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
        if file['status'] in ['added', 'modified'] and file['filename'].endswith(('.sql', '.ksh')):
            # Fetch the raw content of the new file
            raw_url = file['raw_url']
            raw_response = requests.get(raw_url, headers=headers)
            target_files.append({
                "filename": file['filename'],
                "content": raw_response.text
            })
            
    return target_files

def review_code_with_gemini(filename, code):
    """Sends the code to Gemini for review."""
    prompt = f"""
    You are an expert Senior Developer and Code Reviewer. 
    Please review the following file: `{filename}`.
    
    Tasks:
    1. Check for syntax errors.
    2. Identify bad practices and suggest best practices.
    3. Suggest optimizations for performance and easier ways to write this.
    4. Provide the fully refactored and updated code.
    
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

