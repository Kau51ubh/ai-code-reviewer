import os
import time  
import datetime
import requests
import re
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS 
import vertexai
from vertexai.generative_models import GenerativeModel
from google.cloud import bigquery
from github import Github

# Import our local rule engine
from linter import process_file_locally

app = Flask(__name__)
CORS(app) 

vertexai.init(location="us-central1") 
model = GenerativeModel("gemini-2.5-flash")
bq_client = bigquery.Client()

BQ_ANALYTICS_TABLE = os.environ.get("BQ_ANALYTICS_TABLE", "code_review_analytics.scan_history")
# 10 GB default FinOps ceiling threshold
FINOPS_MAX_BYTES_THRESHOLD = int(os.environ.get("FINOPS_MAX_BYTES_THRESHOLD", 10 * 1024 * 1024 * 1024)) 

def load_rules_from_file(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return ""

def get_changed_files(repo, base_branch, head_branch, token):
    headers = {'Authorization': f'token {token}'} if token else {}
    compare_url = f"https://api.github.com/repos/{repo}/compare/{base_branch}...{head_branch}"
    
    response = requests.get(compare_url, headers=headers)
    response.raise_for_status()
    
    files_data = response.json().get('files', [])
    target_files = []
    
    for file in files_data:
        if file['status'] in ['added', 'modified'] and (file['filename'].endswith(('.sql', '.ksh')) or file['filename'].endswith('.py')):
            raw_url = file['raw_url']
            raw_response = requests.get(raw_url, headers=headers)
            target_files.append({
                "filename": file['filename'],
                "content": raw_response.text
            })
            
    return target_files

def needs_ai_review(filename, content):
    if not filename.endswith('.sql'):
        return False
        
    content_upper = content.upper()
    complex_keywords = ['JOIN ', 'GROUP BY', 'OVER (', 'PARTITION BY', 'UNION']
    return any(keyword in content_upper for keyword in complex_keywords)

class DummyUsage:
    total_token_count = 0

class DummyResponse:
    def __init__(self, text):
        self.text = text
        self.usage_metadata = DummyUsage()

def get_user_identity():
    """Extracts authenticated user email from identity gateway headers (Google IAP / Cloud Run context)."""
    email = request.headers.get('X-Inbound-User-Email') or request.headers.get('X-Goog-Authenticated-User-Email')
    if email:
        return email.replace('accounts.google.com:', '')
    return "local-developer@company.com"

def resolve_dataset_for_metadata(dataset_name):
    """Translates parameter variables like ${AEDW_DB} back to actual DB target schemas."""
    clean = dataset_name.replace('${', '').replace('}', '')
    if clean.upper() in ['AEDW_DB', 'DB_AEDWD2']:
        return 'DB_AEDWD2'
    return clean

def inject_live_schema_context(sql_query):
    """Scans query structure for tables and queries BQ metadata directly to generate live context schemas."""
    schema_context = "--- LIVE BIGQUERY SCHEMA METADATA ---\n"
    # Matches dataset.table and ${var}.table patterns
    table_matches = re.findall(r'\b([A-Za-z0-9_${}]+)\.([A-Za-z0-9_]+)\b', sql_query)
    
    processed_tables = set()
    for dataset, table in table_matches:
        resolved_dataset = resolve_dataset_for_metadata(dataset)
        table_key = f"{resolved_dataset}.{table}"
        
        if table_key in processed_tables:
            continue
            
        try:
            table_ref = bq_client.get_table(f"{bq_client.project}.{resolved_dataset}.{table}")
            fields_desc = [f"  - {f.name} ({f.field_type})" for f in table_ref.schema]
            schema_context += f"Table: {dataset}.{table} structure columns:\n" + "\n".join(fields_desc) + "\n"
            processed_tables.add(table_key)
        except Exception:
            pass # Ignore tables that do not exist or are temporary
            
    return schema_context if len(processed_tables) > 0 else ""

def perform_bq_dry_run(sql_query):
    """Dry run query on actual BQ engine, resolving parameters temporarily to save costs."""
    try:
        executable_query = sql_query.replace('${AEDW_DB}', 'DB_AEDWD2')
        executable_query = executable_query.replace('${ETL_BATCH_SK}', '12345')
        executable_query = executable_query.replace('${env}', 'dev')
        
        job_config = bigquery.QueryJobConfig(dry_run=True, use_query_cache=False)
        query_job = bq_client.query(executable_query, job_config=job_config)
        return {
            "valid": True,
            "bytes_processed": query_job.total_bytes_processed,
            "message": f"Syntax Valid. Will process {query_job.total_bytes_processed / (1024**2):.2f} MB."
        }
    except Exception as e:
        return {"valid": False, "bytes_processed": 0, "message": f"BQ Syntax Error: {str(e)}"}

def log_to_bq_analytics(repo, filename, ext, tokens, cost, bypassed, local_issues, bq_bytes, has_secrets, user_email, finops_status):
    """Persistently logs all scan activity metadata directly to the BigQuery dashboard dataset."""
    try:
        rows_to_insert = [{
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "repo": repo,
            "filename": filename,
            "file_type": ext,
            "tokens_used": tokens,
            "cost": cost,
            "ai_bypassed": bypassed,
            "local_issues_count": local_issues,
            "bq_bytes_processed": bq_bytes,
            "has_secrets": has_secrets,
            "user_email": user_email or "local-developer@company.com", # Fallback ensures no empty DB fields
            "finops_status": finops_status or "PASSED"
        }]
        bq_client.insert_rows_json(BQ_ANALYTICS_TABLE, rows_to_insert)
    except Exception as e:
        print(f"Failed to log to BQ Analytics: {e}")

def extract_refactored_code(markdown_text):
    """Robust extractor that separates refactored SQL strings from markdown wrapping blocks."""
    parts = re.split(r'### 🛠️ Final Refactored Code', markdown_text, flags=re.IGNORECASE)
    code_section = parts[1] if len(parts) > 1 else markdown_text
    match = re.search(r'```[a-z]*\n(.*?)```', code_section, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return code_section.replace('```', '').strip()

def review_code_with_gemini(filename, pre_cleaned_code, repo_context="", live_schema=""):
    if not needs_ai_review(filename, pre_cleaned_code):
        ext = filename.split('.')[-1]
        dummy_text = f"### 💡 Advanced Optimizations\nNo advanced architectural bottlenecks detected. AI review bypassed to save tokens (Simple code structure).\n\n### 🛠️ Final Refactored Code\n```{ext}\n{pre_cleaned_code}\n```"
        return DummyResponse(dummy_text)

    code_lines = pre_cleaned_code.split('\n')
    numbered_code = '\n'.join([f"{i+1:03d} | {line}" for i, line in enumerate(code_lines)])
    
    base_instructions = f"""
    You are a Senior Data Architect specializing in Google BigQuery. 
    All SQL syntax, recommendations, and optimizations MUST strictly adhere to BigQuery Standard SQL.
    
    CRITICAL RULES:
    1. Ensure `etl_batch_sk` is ALWAYS parameterized as `${{ETL_BATCH_SK}}` in all INSERT, UPDATE, SELECT, and DELETE statements you generate.
    
    LIVE PRODUCTION SCHEMA DATA CONTEXT (Use this to verify column names and references):
    {live_schema}
    
    REPO CONTEXT (Cross-file dependencies modified in this PR):
    {repo_context}
    
    The code below has ALREADY been pre-processed locally to fix basic syntax, parameterization, and timestamp functions. 
    DO NOT mention basic syntax fixes.
    
    ONLY look for:
    1. Architectural bottlenecks specific to BigQuery (e.g., poor JOIN strategies, cross-joins, inefficient window functions, failing to filter early, or bad scaling patterns).
    2. Suggest optimizations for BigQuery query execution plans, slot utilization, and performance.
    
    If no severe bottlenecks exist, output EXACTLY: "No advanced architectural bottlenecks detected."

    Format your output strictly with these two headings:
    
    ### 💡 Advanced Optimizations
    (Place ALL your explanations, reasoning, and context here.)

    ### 🛠️ Final Refactored Code
    (Output ONLY the raw markdown code block here. Do NOT place any conversational text under this heading. Start immediately with ```)
    """
    
    specific_instructions = ""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    if filename.endswith('.sql'):
        specific_instructions = load_rules_from_file(os.path.join(base_dir, 'rules_sql.txt'))
    elif filename.endswith('.py'):
        specific_instructions = load_rules_from_file(os.path.join(base_dir, 'rules_py.txt'))
    elif filename.endswith('.ksh'):
        specific_instructions = load_rules_from_file(os.path.join(base_dir, 'rules_ksh.txt'))

    prompt = f"{base_instructions}\n\n{specific_instructions}\n\nCode to review:\n```\n{numbered_code}\n```"
    return model.generate_content(prompt)

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/prepare', methods=['POST'])
def prepare_review():
    data = request.get_json()
    repo = data.get('repo')
    head_branch = data.get('branch')
    base_branch = data.get('base_branch', 'main')
    github_token = os.environ.get("GITHUB_TOKEN")
    
    if not repo or not head_branch:
        return jsonify({"error": "Missing parameters."}), 400

    try:
        files_to_review = get_changed_files(repo, base_branch, head_branch, github_token)
        file_count = len(files_to_review)
        
        if file_count == 0:
            return jsonify({"files": [], "estimates": {"file_count": 0, "estimated_time": 0, "estimated_tokens": 0, "estimated_cost": 0}}), 200
        
        ai_files = 0
        total_ai_chars = 0
        
        for f in files_to_review:
            if needs_ai_review(f['filename'], f['content']):
                ai_files += 1
                total_ai_chars += len(f['content'])
                
        estimated_time = 2.0 + (ai_files * 10.0) + ((file_count - ai_files) * 0.2)
        estimated_tokens = int(total_ai_chars * 0.3) + (ai_files * 1600)
        estimated_cost = (estimated_tokens / 1000000) * 0.15
        
        return jsonify({
            "files": files_to_review,
            "estimates": {
                "file_count": file_count,
                "estimated_time": round(estimated_time, 1),
                "estimated_tokens": estimated_tokens,
                "estimated_cost": estimated_cost
            }
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/process_file', methods=['POST'])
def process_single_file():
    data = request.get_json()
    filename = data.get('filename')
    content = data.get('content')
    repo_context = data.get('repo_context', 'No additional context.')
    repo_name = data.get('repo_name', 'unknown')
    user_email = get_user_identity()
    
    if not filename or not content:
        return jsonify({"error": "Missing file data."}), 400

    try:
        start_time = time.time()
        
        pre_cleaned_code, local_linter_issues = process_file_locally(filename, content)
        has_secrets = any("SECURITY ALERT" in issue for issue in local_linter_issues)
        
        bq_metrics = None
        bq_bytes = 0
        ai_review_markdown = ""
        tokens_used = 0
        is_bypassed = False
        finops_status = "PASSED"

        if has_secrets:
            ai_review_markdown = f"### 💡 Advanced Optimizations\nSecurity breach detected. AI review aborted.\n\n### 🛠️ Final Refactored Code\n```\n{content}\n```"
            is_bypassed = True
            finops_status = "SECURITY_HALT"
        else:
            # 1. Gather schema definitions dynamically from BigQuery metadata
            live_schema = inject_live_schema_context(pre_cleaned_code) if filename.endswith('.sql') else ""
            
            # 2. Get recommendations from AI Architect
            ai_response_obj = review_code_with_gemini(filename, pre_cleaned_code, repo_context, live_schema)
            ai_review_markdown = ai_response_obj.text
            try:
                tokens_used = ai_response_obj.usage_metadata.total_token_count
            except AttributeError:
                is_bypassed = True
            
            # 3. Dry run validation over AI-constructed queries
            if filename.endswith('.sql'):
                refactored_code = extract_refactored_code(ai_review_markdown)
                has_placeholders = any(x in refactored_code for x in ["<MISSING_FILTER_REQUIRED>", "(col1, col2, col3)", "TODO"])
                
                if has_placeholders:
                    bq_metrics = {
                        "valid": False,
                        "message": "Dry Run Bypassed: Code contains active structural placeholders requiring manual update."
                    }
                    finops_status = "CONTAIN_PLACEHOLDERS"
                else:
                    bq_metrics = perform_bq_dry_run(refactored_code)
                    bq_bytes = bq_metrics.get("bytes_processed", 0)
                    
                    if not bq_metrics.get("valid"):
                        local_linter_issues.append(f"BigQuery Engine Error: {bq_metrics.get('message')}")
                        finops_status = "SYNTAX_ERROR"
                    elif bq_bytes > FINOPS_MAX_BYTES_THRESHOLD:
                        # Cost Control block trigger
                        finops_status = "FAILED_COST_GUARDRAIL"
                        bq_metrics["valid"] = False
                        bq_metrics["message"] = f"⚠️ FINOPS BLOCKED: Query structural plan consumes {bq_bytes / (1024**3):.2f} GB, exceeding environment maximum limit ({FINOPS_MAX_BYTES_THRESHOLD / (1024**3):.2f} GB)."
                        local_linter_issues.append("FinOps Exception: Execution plan exceeds maximum organizational compute thresholds.")

        time_taken = round(time.time() - start_time, 2)
        estimated_cost = (tokens_used / 1000000) * 0.15

        # Record audit telemetry into DB
        log_to_bq_analytics(repo_name, filename, filename.split('.')[-1], tokens_used, estimated_cost, is_bypassed, len(local_linter_issues), bq_bytes, has_secrets, user_email, finops_status)
        
        return jsonify({
            "filename": filename,
            "unit_test_fixes": local_linter_issues,
            "ai_review": ai_review_markdown,
            "bq_metrics": bq_metrics,
            "tokens": tokens_used,
            "time_taken": time_taken,
            "original_code": content 
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/validate_bq', methods=['POST'])
def validate_bq_route():
    """Manual trigger route used to validate updated SQL strings coming out of interactive chats."""
    data = request.get_json()
    code = data.get('code')
    if not code:
        return jsonify({"error": "No code provided."}), 400
    try:
        if any(x in code for x in ["<MISSING_FILTER_REQUIRED>", "(col1, col2, col3)", "TODO"]):
            return jsonify({
                "valid": False, 
                "message": "Dry Run Bypassed: Code contains active structural placeholders."
            }), 200

        bq_metrics = perform_bq_dry_run(code)
        bq_bytes = bq_metrics.get("bytes_processed", 0)
        
        if bq_metrics.get("valid") and bq_bytes > FINOPS_MAX_BYTES_THRESHOLD:
            bq_metrics["valid"] = False
            bq_metrics["message"] = f"⚠️ FINOPS BLOCKED: Query structural plan consumes {bq_bytes / (1024**3):.2f} GB, exceeding organizational maximum limit."
            
        return jsonify(bq_metrics), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/commit', methods=['POST'])
def commit_to_github():
    """Pushes the accepted modifications directly to the specified branch branch."""
    data = request.get_json()
    repo_name = data.get('repo')
    branch = data.get('branch')
    filename = data.get('filename')
    new_content = data.get('code')
    token = os.environ.get("GITHUB_TOKEN")

    if not all([repo_name, branch, filename, new_content, token]):
        return jsonify({"error": "Missing parameters or GITHUB_TOKEN."}), 400

    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        file_contents = repo.get_contents(filename, ref=branch)
        
        repo.update_file(
            path=file_contents.path,
            message=f"Auto-refactor: Optimized {filename} via AI Architect",
            content=new_content,
            sha=file_contents.sha,
            branch=branch
        )
        return jsonify({"success": True, "message": f"Successfully pushed {filename} to {branch}!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat_with_code():
    data = request.get_json()
    filename = data.get('filename')
    code_context = data.get('code')
    user_message = data.get('message')
    
    if not filename or not user_message:
        return jsonify({"error": "Missing chat data."}), 400

    prompt = f"""
    You are a Senior Data Architect specializing in Google BigQuery.
    The user is asking a follow-up question regarding the file: {filename}.

    Current Refactored Code Context:
    ```
    {code_context}
    ```

    User Request: "{user_message}"

    Address the user's request. If the code needs to be updated based on their request, provide the entirely updated code block.
    Format your response strictly with these two headings:

    ### 💡 AI Reply
    (Your explanation and response here)

    ### 🛠️ Final Refactored Code
    (Output the raw markdown code block here. If no code changes are needed, output the original code block provided above. Start immediately with ```)
    """

    try:
        response = model.generate_content(prompt)
        return jsonify({"reply": response.text}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
