import os
import time  # <--- ADDED THIS for execution tracking
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS # <--- ADD THIS
import vertexai
from vertexai.generative_models import GenerativeModel

app = Flask(__name__)
CORS(app) # <--- ADD THIS to enable browser requests

# Ensure Vertex AI is initialized using the environment's project context
# Cloud Run automatically provides default credentials
vertexai.init(location="us-central1") 
model = GenerativeModel("gemini-2.5-flash") # Current stable, cost-effective model

def get_changed_files(repo, base_branch, head_branch, token):
    """Uses GitHub API to compare branches and get changed .sql/.ksh files."""
    headers = {'Authorization': f'token {token}'} if token else {}
    compare_url = f"https://api.github.com/repos/{repo}/compare/{base_branch}...{head_branch}"
    
    response = requests.get(compare_url, headers=headers)
    response.raise_for_status()
    
    files_data = response.json().get('files', [])
    target_files = []
    
    for file in files_data:
        # Only process added or modified files that are SQL, KSH, or INTERFACE_VM.py
        if file['status'] in ['added', 'modified'] and (file['filename'].endswith(('.sql', '.ksh')) or file['filename'].endswith('_INTERFACE_VM.py')):
            # Fetch the raw content of the new file
            raw_url = file['raw_url']
            raw_response = requests.get(raw_url, headers=headers)
            target_files.append({
                "filename": file['filename'],
                "content": raw_response.text
            })
            
    return target_files

def review_code_with_gemini(filename, code):
    """Sends the code to Gemini for review with strict conditional rules and line number tracking."""
    
    # Pre-process code to add line numbers (e.g., "001 | SELECT *")
    code_lines = code.split('\n')
    numbered_code = '\n'.join([f"{i+1:03d} | {line}" for i, line in enumerate(code_lines)])
    
    # 1. Base instructions that apply to EVERY file
    base_instructions = f"""
    You are an expert Senior Data Engineer and Code Reviewer. 
    Please review the following file: `{filename}`.
    
    General Tasks:
    1. Check for syntax errors.
    2. Identify bad practices and suggest best practices.
    3. Suggest optimizations for performance and easier ways to write this.
    4. Provide the fully refactored and updated code (Provide the updated code clean, WITHOUT line numbers).
    
    CRITICAL REPORTING INSTRUCTIONS:
    - LINE NUMBERS: The code provided below is prefixed with line numbers (e.g., `001 | `). Whenever you report an issue, syntax error, or violation, you MUST cite the exact line number(s) where the issue occurs (e.g., "Line 004", "Lines 012-015").
    - If a specific rule or check is NOT applicable to the provided code, YOU MUST NOT mention it. Never write "Not applicable".
    - DO NOT invent or inject new columns (like ETL_BATCH_SK), new tables, or new business logic that do not exist in the original code. Only fix and refactor what is already there.

    CRITICAL FORMATTING INSTRUCTION:
    You MUST format the "Review Comments" section using structured Markdown. 
    Group your findings under appropriate H3 subheadings (e.g., `### 🚨 Rule Violations`, `### ❌ Syntax Errors`, `### 💡 Optimizations`).
    Use bullet points (`*`) for every individual comment.
    Use **bold text** to highlight the specific issue name and line number citation. Example: "* **Hardcoded Dataset (Line 003):** ..."
    """
    
    #  2. Dynamic specific rules based on file name
    specific_instructions = ""
    
    if filename.endswith('_BQ_INSERTS.sql'):
        specific_instructions = """
    Specific Rules for _BQ_INSERTS.sql Files:
    - Target Column List: ALL `INSERT` statements (both VALUES and SELECT types) MUST explicitly define the target column list (e.g., `INSERT INTO table_name (col1, col2)`). Implicit column ordering is strictly forbidden. Report this if missing and add placeholders/derived columns in the updated code.
    - BigQuery Datasets: IF a dataset name is hardcoded (e.g., DB_AEDWD2), it MUST be parameterized (e.g., ${AEDW_DB}).
    - DATETIME vs TIMESTAMP: IF `TIMESTAMP` functions are used, replace them with `DATETIME` functions.
    - ETL_BATCH_SK: IF the `ETL_BATCH_SK` column is already present in the original query, it MUST be parameterized as `${ETL_BATCH_SK}`. DO NOT add this column if it is missing from the original code.
    - Environments: IF environment paths are present in the code, they MUST be parameterized (e.g., /load/dev2/ becomes /load/${env}/).
    - Multiple INSERTs: Multiple `INSERT` statements for a single table are NOT allowed. Consolidate into one `INSERT` statement followed by multiple `VALUES` rows.
    """
    
    elif filename.endswith('.sql'):
        specific_instructions = """
    Specific Rules for standard .sql Files:
    - Target Column List: IF the file contains `INSERT` statements, they MUST explicitly define the target column list (e.g., `INSERT INTO table_name (col1, col2)`). Implicit column ordering is strictly forbidden.
    - BigQuery Datasets: IF a dataset name is hardcoded, it MUST be parameterized (e.g., ${AEDW_DB}).
    - DATETIME vs TIMESTAMP: IF `TIMESTAMP` functions are used, replace them with `DATETIME` functions.
    - ETL_BATCH_SK: IF the `ETL_BATCH_SK` column is already present in the original query, it MUST be parameterized as `${ETL_BATCH_SK}`. DO NOT add this column if it is missing from the original code.
    - Optimization: Ensure thorough checks for query optimization, join performance, and general SQL best practices.
    """
    
    elif filename.endswith('_INTERFACE_VM.py'):
        specific_instructions = """
    Specific Rules for _INTERFACE_VM.py DAG Files:
    - The DAG ID MUST end with 'INTERFACE_VM'.
    - Ensure `catchup=False` is explicitly set.
    - Ensure `max_active_runs=1` is set, or ensure it is completely omitted to fall back to the default.
    - Ensure these DAGs strictly use `gcloud ssh` commands along with appropriate user/host/other variables.
    """
    
    elif filename.endswith('.ksh'):
        specific_instructions = """
    Specific Rules for .ksh Shell Scripts:
    - IF SQL datasets are referenced, ensure they are parameterized.
    - ALL commands must have valid Return Code (RC) checks (e.g., checking `$?`) to capture errors immediately.
    - Robust error handling and exiting must be present.
    - Direct `bq query` commands MUST NOT be used. They should be refactored to use designated wrapper functions instead.
    - Ensure the script avoids huge local/unix file processing (advise offloading to the database or cloud storage).
    - Ensure files are being actively archived wherever applicable in the flow.
    - STRICT SECURITY CHECK: Ensure that passwords or secrets are not printed or echo'd anywhere in the code.
    """

    # 3. Assemble the final prompt
    prompt = f"""
    {base_instructions}
    
    {specific_instructions}
    
    Format your response clearly with headings for "Review Comments" and "Updated Code".
    
    Code to review (with original line numbers):
    ```
    {numbered_code}
    ```
    """
    
    # Return the entire response object so we can read the token metadata
    response = model.generate_content(prompt)
    return response

@app.route('/review', methods=['POST'])
def run_review():
    data = request.get_json()
    
    repo = data.get('repo')                 # e.g., "your-username/sql-ksh-reviewer"
    head_branch = data.get('branch')        # e.g., "release-v1"
    base_branch = data.get('base_branch', 'master') # defaults to master
    
    github_token = os.environ.get("GITHUB_TOKEN")
    
    if not repo or not head_branch:
        return jsonify({"error": "Missing 'repo' or 'branch' in payload."}), 400

    try:
        start_time = time.time()  # <--- START THE CLOCK
        total_tokens = 0          # <--- INITIALIZE TOKEN COUNTER
        
        # 1. Fetch changed files from GitHub
        files_to_review = get_changed_files(repo, base_branch, head_branch, github_token)
        
        if not files_to_review:
            return jsonify({"message": "No .sql, .ksh, or _INTERFACE_VM.py files were added or modified."}), 200
            
        results = {}
        
        # 2. Process each file with Gemini
        for file_obj in files_to_review:
            filename = file_obj['filename']
            code = file_obj['content']
            
            # Fetch the full response object
            response_obj = review_code_with_gemini(filename, code)
            
            # Store the text for the frontend
            results[filename] = response_obj.text
            
            # Safely extract token counts
            try:
                total_tokens += response_obj.usage_metadata.total_token_count
            except AttributeError:
                pass
                
        end_time = time.time()  # <--- STOP THE CLOCK
        time_taken = round(end_time - start_time, 2)
            
        return jsonify({
            "status": "success",
            "repository": repo,
            "branch": head_branch,
            "reviews": results,
            "stats": {            # <--- ADD STATS PAYLOAD
                "time_taken": time_taken,
                "total_tokens": total_tokens
            }
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
