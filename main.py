import os
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
        # Only process added or modified files that are SQL or KSH
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
    """Sends the code to Gemini for review with dynamic, file-specific rules."""
    
    # 1. Base instructions that apply to EVERY file
    base_instructions = f"""
    You are an expert Senior Data Engineer and Code Reviewer. 
    Please review the following file: `{filename}`.
    
    General Tasks:
    1. Check for syntax errors.
    2. Identify bad practices and suggest best practices.
    3. Suggest optimizations for performance and easier ways to write this.
    4. Provide the fully refactored and updated code.
    """
    
    # 2. Dynamic specific rules based on file name
    specific_instructions = ""
    
    if filename.endswith('_BQ_INSERTS.sql'):
        specific_instructions = """
    Specific Rules for _BQ_INSERTS.sql Files:
    - BigQuery datasets MUST be parameterized (e.g., hardcoded DB_AEDWD2 must become ${AEDW_DB}).
    - Ensure DATETIME functions are used instead of TIMESTAMP to avoid timezone conflicts.
    - Ensure the SQL has the ETL_BATCH_SK column parameterized (e.g., ${ETL_BATCH_SK}).
    - Environments MUST NOT be hardcoded in any file paths (e.g., /load/dev2/subjectarea must become /load/${env}/subjectarea).
    - Multiple INSERT statements for a single table are NOT allowed. It must be refactored to one INSERT statement followed by multiple VALUES.
    """
    
    elif filename.endswith('.sql'):
        specific_instructions = """
    Specific Rules for standard .sql Files:
    - BigQuery datasets MUST be parameterized (e.g., hardcoded DB_AEDWD2 must become ${AEDW_DB}).
    - Ensure DATETIME functions are used instead of TIMESTAMP to avoid timezone conflicts.
    - Ensure the SQL has the ETL_BATCH_SK column parameterized (e.g., ${ETL_BATCH_SK}).
    - Ensure thorough checks for query optimization, join performance, and general SQL best practices.
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
    - Ensure any SQL datasets referenced in the script are properly parameterized.
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
    
    Code to review:
    ```
    {code}
    ```
    """
    
    response = model.generate_content(prompt)
    return response.text

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
        # 1. Fetch changed files from GitHub
        files_to_review = get_changed_files(repo, base_branch, head_branch, github_token)
        
        if not files_to_review:
            return jsonify({"message": "No .sql or .ksh files were added or modified."}), 200
            
        results = {}
        
        # 2. Process each file with Gemini
        for file_obj in files_to_review:
            filename = file_obj['filename']
            code = file_obj['content']
            review_feedback = review_code_with_gemini(filename, code)
            results[filename] = review_feedback
            
        return jsonify({
            "status": "success",
            "repository": repo,
            "branch": head_branch,
            "reviews": results
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

