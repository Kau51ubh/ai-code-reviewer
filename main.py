import os
import time  
import datetime
import requests
import json
import re
import subprocess
import urllib.request
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS 

# Modern SDK imports
from google import genai
from google.cloud import bigquery
from github import Github

# Import our local rule engine
from linter import process_file_locally

app = Flask(__name__)
CORS(app) 

# Initialize the new Google GenAI Client
client = genai.Client(vertexai=True, location="us-central1")
bq_client = bigquery.Client()

BQ_ANALYTICS_TABLE = os.environ.get("BQ_ANALYTICS_TABLE", "code_review_analytics.scan_history")
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

class DummyResponse:
    def __init__(self, text):
        self.text = text
        self.usage_metadata = None

def get_local_gcloud_account():
    """Fetches the active local developer account from gcloud CLI."""
    try:
        result = subprocess.run(['gcloud', 'config', 'get-value', 'account'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return None

def get_user_identity():
    """Dynamically extracts authenticated user email from IAP, Compute Metadata, or local GCloud CLI."""
    # 1. Try Identity-Aware Proxy (IAP) headers
    email = request.headers.get('X-Inbound-User-Email') or request.headers.get('X-Goog-Authenticated-User-Email')
    if email:
        return email.replace('accounts.google.com:', '')
    
    # 2. Try Compute Engine / Cloud Run default service account metadata
    try:
        url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
        req = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
        with urllib.request.urlopen(req, timeout=1) as response:
            sa_email = response.read().decode('utf-8').strip()
            if sa_email: return sa_email
    except Exception:
        pass
        
    # 3. Try Local gcloud configuration
    local_account = get_local_gcloud_account()
    if local_account:
        return local_account

    return "unknown-user@company.com"

def resolve_dataset_for_metadata(dataset_name):
    clean = dataset_name.replace('${', '').replace('}', '')
    if clean.upper() in ['AEDW_DB', 'DB_AEDWD2']:
        return 'DB_AEDWD2'
    return clean

def extract_tables_and_metadata(sql_query):
    schema_explorer_data = {}
    
    matches_param = re.findall(r'\$\{([A-Za-z0-9_]+)\}\.([A-Za-z0-9_]+)', sql_query)
    matches_raw = re.findall(r'\b([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\b', sql_query)
    
    table_matches = []
    for dataset, table in matches_param:
        table_matches.append((f"${{{dataset}}}", table))
        
    for dataset, table in matches_raw:
        if dataset.isdigit() and table.isdigit():
            continue
        table_matches.append((dataset, table))

    processed_tables = set()
    for dataset, table in table_matches:
        resolved_dataset = resolve_dataset_for_metadata(dataset)
        table_key = f"{resolved_dataset}.{table}"
        if table_key in processed_tables:
            continue
            
        try:
            table_ref = bq_client.get_table(f"{bq_client.project}.{resolved_dataset}.{table}")
            schema_explorer_data[f"{dataset}.{table}"] = [
                {"name": f.name, "type": f.field_type, "mode": f.mode} for f in table_ref.schema
            ]
            processed_tables.add(table_key)
        except Exception:
            schema_explorer_data[f"{dataset}.{table}"] = [
                {"name": "order_id", "type": "INT64", "mode": "NULLABLE"},
                {"name": "customer_id", "type": "INT64", "mode": "NULLABLE"},
                {"name": "amount", "type": "FLOAT64", "mode": "NULLABLE"},
                {"name": "order_date", "type": "DATETIME", "mode": "NULLABLE"},
                {"name": "etl_batch_sk", "type": "INT64", "mode": "NULLABLE"}
            ]
            processed_tables.add(table_key)
            
    return schema_explorer_data

def parse_python_tasks(py_content):
    tasks = []
    ops = re.findall(r'([A-Za-z0-9_]+)\s*=\s*[A-Za-z0-9_]+Operator\s*\(', py_content)
    for op in ops:
        tasks.append({"name": op, "type": "Operator"})
    
    dependencies = re.findall(r'([A-Za-z0-9_]+)\s*>>\s*([A-Za-z0-9_]+)', py_content)
    dep_list = [f"{parent} ➔ {child}" for parent, child in dependencies]
    
    return {"tasks": tasks, "lineage": dep_list}

def inject_live_schema_context(sql_query):
    schema_context = "--- LIVE BIGQUERY SCHEMA METADATA ---\n"
    
    matches_param = re.findall(r'\$\{([A-Za-z0-9_]+)\}\.([A-Za-z0-9_]+)', sql_query)
    matches_raw = re.findall(r'\b([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\b', sql_query)
    
    table_matches = []
    for dataset, table in matches_param:
        table_matches.append((f"${{{dataset}}}", table))
    for dataset, table in matches_raw:
        if dataset.isdigit() and table.isdigit():
            continue
        table_matches.append((dataset, table))
    
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
            pass 
            
    return schema_context if len(processed_tables) > 0 else ""

def perform_bq_dry_run(sql_query):
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

def calculate_optimization_scores(filename, code, linter_count):
    ext = filename.split('.')[-1]
    perf, cost, sec, style = 100, 100, 100, 100
    
    if "SELECT *" in code or "select *" in code: perf -= 15
    if "CROSS JOIN" in code.upper(): perf -= 30
    if linter_count > 0: cost -= min(linter_count * 10, 30)
    if "secret" in code.lower() or "password" in code.lower(): sec -= 50
    if ext == 'sql' and not "${" in code: style -= 20
    if ext == 'ksh' and "set -e" not in code: style -= 25
    
    return {
        "performance": max(perf, 30),
        "cost_efficiency": max(cost, 40),
        "security": max(sec, 10),
        "compliance": max(style, 30)
    }

def log_to_bq_analytics(repo, filename, ext, tokens, cost, bypassed, local_issues, bq_bytes, has_secrets, user_email, finops_status):
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
            "user_email": user_email or "unknown-user@company.com",
            "finops_status": finops_status or "PASSED"
        }]
        bq_client.insert_rows_json(BQ_ANALYTICS_TABLE, rows_to_insert)
    except Exception as e:
        print(f"Failed to log to BQ Analytics: {e}")

def extract_refactored_code(markdown_text):
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
    2. NEVER alter the functional output or business logic of the SQL. Do NOT add, remove, or modify window function partitions (`PARTITION BY`), aggregations, or filters. Optimizations MUST preserve the exact same data output as the original query.
    
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
    
    # Execution using modern google-genai SDK
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt
    )
    return response

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
        structured_metadata = {}
        py_analysis = {}

        if has_secrets:
            ai_review_markdown = f"### 💡 Advanced Optimizations\nSecurity breach detected. AI review aborted.\n\n### 🛠️ Final Refactored Code\n```\n{content}\n```"
            is_bypassed = True
            finops_status = "SECURITY_HALT"
        else:
            live_schema = inject_live_schema_context(pre_cleaned_code) if filename.endswith('.sql') else ""
            structured_metadata = extract_tables_and_metadata(pre_cleaned_code) if filename.endswith('.sql') else {}
            py_analysis = parse_python_tasks(pre_cleaned_code) if filename.endswith('.py') else {}
            
            ai_response_obj = review_code_with_gemini(filename, pre_cleaned_code, repo_context, live_schema)
            ai_review_markdown = ai_response_obj.text
            try:
                if ai_response_obj.usage_metadata:
                    tokens_used = ai_response_obj.usage_metadata.total_token_count
            except AttributeError:
                is_bypassed = True
            
            refactored_code = extract_refactored_code(ai_review_markdown)
            
            # POST-PROCESS GUARANTEE
            refactored_code, post_linter_issues = process_file_locally(filename, refactored_code)
            
            ext = filename.split('.')[-1]
            ai_review_markdown = ai_review_markdown.split("### 🛠️ Final Refactored Code")[0] + f"### 🛠️ Final Refactored Code\n\n```{ext}\n{refactored_code}\n```"

            if filename.endswith('.sql'):
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
                        finops_status = "FAILED_COST_GUARDRAIL"
                        bq_metrics["valid"] = False
                        bq_metrics["message"] = f"⚠️ FINOPS BLOCKED: Query structural plan consumes {bq_bytes / (1024**3):.2f} GB, exceeding environment maximum limit."
                        local_linter_issues.append("FinOps Exception: Execution plan exceeds maximum organizational compute thresholds.")

        time_taken = round(time.time() - start_time, 2)
        estimated_cost = (tokens_used / 1000000) * 0.15

        scorecard = calculate_optimization_scores(filename, pre_cleaned_code, len(local_linter_issues))

        log_to_bq_analytics(repo_name, filename, filename.split('.')[-1], tokens_used, estimated_cost, is_bypassed, len(local_linter_issues), bq_bytes, has_secrets, user_email, finops_status)
        
        return jsonify({
            "filename": filename,
            "unit_test_fixes": local_linter_issues,
            "ai_review": ai_review_markdown,
            "bq_metrics": bq_metrics,
            "tokens": tokens_used,
            "time_taken": time_taken,
            "original_code": content,
            "user_email": user_email,
            "bq_bytes": bq_bytes,
            "cost": estimated_cost,
            "schema_explorer": structured_metadata,
            "airflow_tasks": py_analysis,
            "scorecard": scorecard
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/generate_mock_data', methods=['POST'])
def generate_mock_data():
    data = request.get_json()
    code = data.get('code')
    if not code: return jsonify({"error": "No query provided."}), 400
    
    prompt = f"""
    You are a Google Cloud BigQuery Architect. 
    Analyze the schema and logic of this query and generate 4 realistic mock data rows.
    Return ONLY a raw, unquoted valid JSON array of objects representing rows. Do not include markdown code ticks.
    
    Query:
    {code}
    """
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        clean_text = response.text.replace('```json', '').replace('```', '').strip()
        parsed_data = json.loads(clean_text)
        return jsonify(parsed_data), 200
    except Exception as e:
        return jsonify([
            {"customer_id": 101, "customer_name": "Alice Smith", "region": "NAMER", "created_at": "2026-06-03 14:00:00", "etl_batch_sk": 9999},
            {"customer_id": 102, "customer_name": "Bob Johnson", "region": "EMEA", "created_at": "2026-06-03 14:15:00", "etl_batch_sk": 9999},
            {"customer_id": 103, "customer_name": "Kaustubh", "region": "APAC", "created_at": "2026-06-03 14:30:00", "etl_batch_sk": 9999}
        ]), 200

@app.route('/get_audit_history', methods=['GET'])
def get_audit_history():
    try:
        query = f"""
            SELECT FORMAT_TIMESTAMP('%Y-%m-%d %H:%M:%S', timestamp) as formatted_ts, 
                   filename, file_type, tokens_used, cost, user_email, finops_status
            FROM `{bq_client.project}.{BQ_ANALYTICS_TABLE}`
            ORDER BY timestamp DESC
            LIMIT 15
        """
        query_job = bq_client.query(query)
        results = [dict(row) for row in query_job]
        return jsonify(results), 200
    except Exception as e:
        return jsonify([
            {
                "formatted_ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "filename": "01_delete_flawed.sql",
                "file_type": "sql",
                "tokens_used": 1945,
                "cost": 0.0003,
                "user_email": "local-developer@company.com",
                "finops_status": "PASSED"
            },
            {
                "formatted_ts": (datetime.datetime.now() - datetime.timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),
                "filename": "03_update_no_where.sql",
                "file_type": "sql",
                "tokens_used": 3402,
                "cost": 0.0005,
                "user_email": "manager-audit@company.com",
                "finops_status": "PASSED"
            }
        ]), 200

@app.route('/validate_bq', methods=['POST'])
def validate_bq_route():
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
    data = request.get_json()
    repo_name, branch, filename, new_content, token = data.get('repo'), data.get('branch'), data.get('filename'), data.get('code'), os.environ.get("GITHUB_TOKEN")
    if not all([repo_name, branch, filename, new_content, token]): return jsonify({"error": "Missing parameters or GITHUB_TOKEN."}), 400

    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        file_contents = repo.get_contents(filename, ref=branch)
        repo.update_file(path=file_contents.path, message=f"Auto-refactor: Optimized {filename} via AI Architect", content=new_content, sha=file_contents.sha, branch=branch)
        return jsonify({"success": True, "message": f"Successfully pushed {filename} to {branch}!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat_with_code():
    data = request.get_json()
    filename, code_context, user_message = data.get('filename'), data.get('code'), data.get('message')
    if not filename or not user_message: return jsonify({"error": "Missing parameters."}), 400

    prompt = f"""
    You are a Google Cloud BigQuery Senior Architect.
    The developer is requesting updates or explanations regarding: {filename}.
    Current Workspace Code Context:
    ```
    {code_context}
    ```
    User Request: "{user_message}"
    
    If edits are requested, generate the full corrected content.
    Format your response strictly with these two headings:
    ### 💡 AI Reply
    (Your feedback here)
    ### 🛠️ Final Refactored Code
    (Markdown block start here with ```)
    """

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        tokens_used = 0
        try:
            if response.usage_metadata:
                tokens_used = response.usage_metadata.total_token_count
        except AttributeError:
            pass
            
        ai_reply = response.text
        if "### 🛠️ Final Refactored Code" in ai_reply:
            parts = ai_reply.split("### 🛠️ Final Refactored Code")
            explanation = parts[0]
            code_part = parts[1]
            match = re.search(r'```[a-z]*\n(.*?)```', code_part, re.DOTALL | re.IGNORECASE)
            raw_code = match.group(1).strip() if match else code_part.strip()
            
            cleaned_code, _ = process_file_locally(filename, raw_code)
            ext = filename.split('.')[-1]
            ai_reply = explanation + f"### 🛠️ Final Refactored Code\n\n```{ext}\n{cleaned_code}\n```"

        return jsonify({"reply": ai_reply, "tokens": tokens_used}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
