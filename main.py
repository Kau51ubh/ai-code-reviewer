import os
import time  
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS 
import vertexai
from vertexai.generative_models import GenerativeModel

app = Flask(__name__)
CORS(app) 

# Ensure Vertex AI is initialized using the environment's project context
vertexai.init(location="us-central1") 
model = GenerativeModel("gemini-2.5-flash")

def load_rules_from_file(filepath):
    """Helper function to read external rule files gracefully."""
    try:
        with open(filepath, 'r') as file:
            return file.read()
    except FileNotFoundError:
        print(f"Warning: Configuration file {filepath} not found. Skipping those specific rules.")
        return ""

def get_changed_files(repo, base_branch, head_branch, token):
    """Uses GitHub API to compare branches and get changed files."""
    headers = {'Authorization': f'token {token}'} if token else {}
    compare_url = f"https://api.github.com/repos/{repo}/compare/{base_branch}...{head_branch}"
    
    response = requests.get(compare_url, headers=headers)
    response.raise_for_status()
    
    files_data = response.json().get('files', [])
    target_files = []
    
    for file in files_data:
        if file['status'] in ['added', 'modified'] and (file['filename'].endswith(('.sql', '.ksh')) or file['filename'].endswith('_INTERFACE_VM.py')):
            raw_url = file['raw_url']
            raw_response = requests.get(raw_url, headers=headers)
            target_files.append({
                "filename": file['filename'],
                "content": raw_response.text
            })
            
    return target_files

def review_code_with_gemini(filename, code):
    """Sends the code to Gemini for review using externally loaded rules."""
    
    code_lines = code.split('\n')
    numbered_code = '\n'.join([f"{i+1:03d} | {line}" for i, line in enumerate(code_lines)])
    
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
    
    # Dynamically load specific instructions from external text files
    specific_instructions = ""
    
    if filename.endswith('.sql'):
        specific_instructions = load_rules_from_file('rules_sql.txt')
    elif filename.endswith('_INTERFACE_VM.py'):
        specific_instructions = load_rules_from_file('rules_py.txt')
    elif filename.endswith('.ksh'):
        specific_instructions = load_rules_from_file('rules_ksh.txt')

    prompt = f"""
    {base_instructions}
    
    {specific_instructions}
    
    Format your response clearly with headings for "Review Comments" and "Updated Code".
    
    Code to review (with original line numbers):
    ```
    {numbered_code}
    ```
    """
    
    response = model.generate_content(prompt)
    return response

@app.route('/review', methods=['POST'])
def run_review():
    data = request.get_json()
    
    repo = data.get('repo')
    head_branch = data.get('branch')
    base_branch = data.get('base_branch', 'main')
    
    github_token = os.environ.get("GITHUB_TOKEN")
    
    if not repo or not head_branch:
        return jsonify({"error": "Missing 'repo' or 'branch' in payload."}), 400

    try:
        start_time = time.time()
        total_tokens = 0
        
        files_to_review = get_changed_files(repo, base_branch, head_branch, github_token)
        
        if not files_to_review:
            return jsonify({"message": "No .sql, .ksh, or _INTERFACE_VM.py files were added or modified."}), 200
            
        results = {}
        
        for file_obj in files_to_review:
            filename = file_obj['filename']
            code = file_obj['content']
            
            response_obj = review_code_with_gemini(filename, code)
            results[filename] = response_obj.text
            
            try:
                total_tokens += response_obj.usage_metadata.total_token_count
            except AttributeError:
                pass
                
        end_time = time.time()
        time_taken = round(end_time - start_time, 2)
            
        return jsonify({
            "status": "success",
            "repository": repo,
            "branch": head_branch,
            "reviews": results,
            "stats": {
                "time_taken": time_taken,
                "total_tokens": total_tokens
            }
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
