import os
import time  
import requests
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS 
import vertexai
from vertexai.generative_models import GenerativeModel

# Import our local rule engine
from linter import process_file_locally

app = Flask(__name__)
CORS(app) 

vertexai.init(location="us-central1") 
model = GenerativeModel("gemini-2.5-flash")

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
    """
    STRICT GATEWAY: 
    - .ksh and .py files NEVER go to AI (100% handled by local linter).
    - .sql files ONLY go to AI if they have JOINs or complex aggregations.
    """
    if not filename.endswith('.sql'):
        return False # Hard cutoff for KSH and PY
        
    content_upper = content.upper()
    complex_keywords = ['JOIN ', 'GROUP BY', 'OVER (', 'PARTITION BY', 'UNION']
    
    if any(keyword in content_upper for keyword in complex_keywords):
        return True
        
    return False

class DummyUsage:
    total_token_count = 0

class DummyResponse:
    def __init__(self, text):
        self.text = text
        self.usage_metadata = DummyUsage()

def review_code_with_gemini(filename, pre_cleaned_code):
    if not needs_ai_review(filename, pre_cleaned_code):
        dummy_text = f"### 💡 Advanced Optimizations\nNo advanced architectural bottlenecks detected. AI review bypassed to save tokens (Simple code structure).\n\n### 🛠️ Final Refactored Code\n```\n{pre_cleaned_code}\n```"
        return DummyResponse(dummy_text)

    code_lines = pre_cleaned_code.split('\n')
    numbered_code = '\n'.join([f"{i+1:03d} | {line}" for i, line in enumerate(code_lines)])
    
    base_instructions = f"""
    You are a Senior Architect. The code below has ALREADY been pre-processed locally to fix basic syntax, parameterization, and timestamp functions. 
    DO NOT mention basic syntax fixes.
    
    ONLY look for:
    1. Architectural bottlenecks (e.g., poor JOIN strategies, cross-joins, inefficient loops).
    2. Suggest optimizations for query execution plans or scaling.
    
    If no severe bottlenecks exist, output EXACTLY: "No advanced architectural bottlenecks detected."

    Format your output strictly with these two headings:
    ### 💡 Advanced Optimizations
    ### 🛠️ Final Refactored Code
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
    
    response = model.generate_content(prompt)
    return response

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/estimate', methods=['POST'])
def estimate_review():
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
            return jsonify({"file_count": 0, "estimated_time": 0, "estimated_tokens": 0, "estimated_cost": 0}), 200
        
        ai_files = 0
        total_ai_chars = 0
        
        for f in files_to_review:
            # We must check the same logic to accurately predict AI bypasses
            if needs_ai_review(f['filename'], f['content']):
                ai_files += 1
                total_ai_chars += len(f['content'])
                
        # HIGH-ACCURACY TIME CALCULATION
        # Gemini takes ~10s per file. Local lint takes ~0.2s. Base network overhead ~2s.
        estimated_time = 2.0 + (ai_files * 10.0) + ((file_count - ai_files) * 0.2)
        
        # HIGH-ACCURACY TOKEN CALCULATION
        # System instructions + rules alone cost ~1,200 tokens.
        # AI Output usually costs ~400 tokens. Code chars = ~0.3 tokens each.
        estimated_tokens = int(total_ai_chars * 0.3) + (ai_files * 1600)
        
        # Cost is roughly $0.15 per 1 Million tokens
        estimated_cost = (estimated_tokens / 1000000) * 0.15
        
        return jsonify({
            "file_count": file_count,
            "estimated_time": round(estimated_time, 1),
            "estimated_tokens": estimated_tokens,
            "estimated_cost": estimated_cost
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/review', methods=['POST'])
def run_review():
    data = request.get_json()
    repo = data.get('repo')
    head_branch = data.get('branch')
    base_branch = data.get('base_branch', 'main')
    github_token = os.environ.get("GITHUB_TOKEN")
    
    if not repo or not head_branch:
        return jsonify({"error": "Missing parameters."}), 400

    try:
        start_time = time.time()
        total_tokens = 0
        
        files_to_review = get_changed_files(repo, base_branch, head_branch, github_token)
        if not files_to_review:
            return jsonify({"message": "No reviewable files found."}), 200
            
        results = {}
        
        for file_obj in files_to_review:
            filename = file_obj['filename']
            raw_content = file_obj['content']
            
            pre_cleaned_code, local_linter_issues = process_file_locally(filename, raw_content)
            
            ai_response_obj = review_code_with_gemini(filename, pre_cleaned_code)
            ai_review_markdown = ai_response_obj.text
            
            try:
                total_tokens += ai_response_obj.usage_metadata.total_token_count
            except AttributeError:
                pass
            
            results[filename] = {
                "unit_test_fixes": local_linter_issues,
                "ai_review": ai_review_markdown
            }
            
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
