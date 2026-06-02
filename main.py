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

from linter import process_file_locally

app = Flask(__name__)
CORS(app) 

vertexai.init(location="us-central1") 
model = GenerativeModel("gemini-2.5-flash")
bq_client = bigquery.Client()

BQ_ANALYTICS_TABLE = os.environ.get("BQ_ANALYTICS_TABLE", "code_review_analytics.scan_history")

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

def perform_bq_dry_run(sql_query):
    """
    Executes a $0 Dry Run against BigQuery. 
    Temporarily unparameterizes variables so the BQ engine can validate physical tables.
    """
    try:
        # --- 1. UNPARAMETERIZE STRICTLY FOR VALIDATION ---
        executable_query = sql_query.replace('${AEDW_DB}', 'DB_AEDWD2')
        executable_query = executable_query.replace('${ETL_BATCH_SK}', '12345')
        executable_query = executable_query.replace('${env}', 'dev')
        
        # --- 2. EXECUTE DRY RUN ---
        job_config = bigquery.QueryJobConfig(dry_run=True, use_query_cache=False)
        query_job = bq_client.query(executable_query, job_config=job_config)
        
        return {
            "valid": True,
            "bytes_processed": query_job.total_bytes_processed,
            "message": f"Syntax Valid. Will process {query_job.total_bytes_processed / (1024**2):.2f} MB."
        }
    except Exception as e:
        return {"valid": False, "bytes_processed": 0, "message": f"BQ Syntax Error: {str(e)}"}

def log_to_bq_analytics(repo, filename, ext, tokens, cost, bypassed, local_issues, bq_bytes, has_secrets):
    """Asynchronously logs scan metadata to the BigQuery Analytics Dashboard."""
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
            "has_secrets": has_secrets
        }]
        bq_client.insert_rows_json(BQ_ANALYTICS_TABLE, rows_to_insert)
    except Exception as e:
        print(f"Failed to log to BQ Analytics: {e}")

def extract_refactored_code(markdown_text):
    """Extracts just the raw code block from the AI's Markdown response for BQ validation."""
    parts = re.split(r'### 🛠️ Final Refactored Code', markdown_text, flags=re.IGNORECASE)
    if len(parts) > 1:
        code_section = parts[1]
        match = re.search(r'```[a-z]*\n(.*?)```', code_section, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return code_section.replace('```', '').strip()
        
    match = re.search(r'```[a-z]*\n(.*?)```', markdown_text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
        
    return markdown_text.strip()

def review_code_with_gemini(filename, pre_cleaned_code, repo_context=""):
    if not needs_ai_review(filename, pre_cleaned_code):
        dummy_text = f"### 💡 Advanced Optimizations\nNo advanced architectural bottlenecks detected. AI review bypassed to save tokens (Simple code structure).\n\n### 🛠️ Final Refactored Code\n```sql\n{pre_cleaned_code}\n```"
        return DummyResponse(dummy_text)

    code_lines = pre_cleaned_code.split('\n')
    numbered_code = '\n'.join([f"{i+1:03d} | {line}" for i, line in enumerate(code_lines)])
    
    base_instructions = f"""
    You are a Senior Data Architect specializing in Google BigQuery. 
    All SQL syntax, recommendations, and optimizations MUST strictly adhere to BigQuery Standard SQL.
    
    REPO CONTEXT (Cross-file dependencies modified in this PR):
    {repo_context}
    
    ONLY look for:
    1. Architectural bottlenecks specific to BigQuery (poor JOINs, cross-joins, inefficient scaling).
    2. Cross-file dependency issues based on the Repo Context provided above.
    
    If no severe bottlenecks exist, output EXACTLY: "No advanced architectural bottlenecks detected."

    Format your output strictly with these two headings:
    ### 💡 Advanced Optimizations
    (Place ALL explanations here)

    ### 🛠️ Final Refactored Code
    (Output ONLY the raw markdown code block here. Start immediately with ```)
    """
    
    specific_instructions = ""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    if filename.endswith('.sql'): specific_instructions = load_rules_from_file(os.path.join(base_dir, 'rules_sql.txt'))
    elif filename.endswith('.py'): specific_instructions = load_rules_from_file(os.path.join(base_dir, 'rules_py.txt'))
    elif filename.endswith('.ksh'): specific_instructions = load_rules_from_file(os.path.join(base_dir, 'rules_ksh.txt'))

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

        if has_secrets:
            ai_review_markdown = f"### 💡 Advanced Optimizations\nSecurity breach detected. AI review aborted.\n\n### 🛠️ Final Refactored Code\n```\n{content}\n```"
            is_bypassed = True
        else:
            # 1. AI Architect Review (Execute BEFORE BigQuery Dry Run)
            ai_response_obj = review_code_with_gemini(filename, pre_cleaned_code, repo_context)
            ai_review_markdown = ai_response_obj.text
            try:
                tokens_used = ai_response_obj.usage_metadata.total_token_count
            except AttributeError:
                is_bypassed = True # Bypassed via DummyResponse

            # 2. BigQuery Validation (On the NEW Refactored Code)
            if filename.endswith('.sql'):
                refactored_code = extract_refactored_code(ai_review_markdown)
                
                # Check for unresolved placeholders in the new code
                has_placeholders = "<MISSING_FILTER_REQUIRED>" in refactored_code or "(col1, col2, col3)" in refactored_code or "TODO" in refactored_code
                
                if has_placeholders:
                    bq_metrics = {
                        "valid": False,
                        "message": "Dry Run Bypassed: Refactored code contains mandatory placeholders or TODOs that require manual developer input."
                    }
                else:
                    # Validate the AI's output against the actual BQ Engine
                    bq_metrics = perform_bq_dry_run(refactored_code)
                    bq_bytes = bq_metrics.get("bytes_processed", 0)
                    
                    if not bq_metrics.get("valid"):
                        # If the AI hallucinated bad SQL, we flag it in the UI
                        local_linter_issues.append(f"BigQuery Engine Error: {bq_metrics.get('message')}")
            
        time_taken = round(time.time() - start_time, 2)
        estimated_cost = (tokens_used / 1000000) * 0.15

        log_to_bq_analytics(repo_name, filename, filename.split('.')[-1], tokens_used, estimated_cost, is_bypassed, len(local_linter_issues), bq_bytes, has_secrets)
        
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

@app.route('/commit', methods=['POST'])
def commit_to_github():
    """Push to Branch functionality."""
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

@app.route('/validate_bq', methods=['POST'])
def validate_bq_route():
    """On-demand endpoint to run a BQ Dry Run after a user modifies code via chat."""
    data = request.get_json()
    code = data.get('code')
    
    if not code:
        return jsonify({"error": "No code provided."}), 400

    try:
        # Check for placeholders first
        has_placeholders = "<MISSING_FILTER_REQUIRED>" in code or "(col1, col2, col3)" in code or "TODO" in code
        if has_placeholders:
            return jsonify({
                "valid": False,
                "message": "Dry Run Bypassed: Code contains mandatory placeholders or TODOs that require manual developer input."
            }), 200

        # Execute the dry run
        bq_metrics = perform_bq_dry_run(code)
        return jsonify(bq_metrics), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
