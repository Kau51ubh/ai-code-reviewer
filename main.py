import os
import time  
import datetime
import requests
import json
import re
import subprocess
import urllib.request
from flask import Flask, request, jsonify
from flask_cors import CORS

# Modern SDK imports
from google import genai
from google.cloud import bigquery
from github import Github

try:
    from google.genai import types as genai_types
except Exception:
    genai_types = None

# Import our local rule engine
from linter import process_file_locally

app = Flask(__name__)
CORS(app)

# Initialize the new Google GenAI Client
client = genai.Client(vertexai=True, location="us-central1")
bq_client = bigquery.Client()

BQ_ANALYTICS_TABLE = os.environ.get("BQ_ANALYTICS_TABLE", "code_review_analytics.scan_history")
FINOPS_MAX_BYTES_THRESHOLD = int(os.environ.get("FINOPS_MAX_BYTES_THRESHOLD", 10 * 1024 * 1024 * 1024))
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")


def _parse_kv(raw):
    """Parse 'A=1,B=2' into {'A':'1','B':'2'} — used for generic, deployment-driven config."""
    out = {}
    for pair in (raw or '').split(','):
        pair = pair.strip()
        if '=' in pair:
            k, v = pair.split('=', 1)
            k, v = k.strip(), v.strip()
            if k:
                out[k] = v
    return out


# --- Generic, deployment-configured conventions (NO hardcoded business names) ---
# ${TEMPLATE_VAR} dataset references -> the real BigQuery dataset they resolve to.
# Used to fetch the LIVE schema and to make dry-runs parseable. Override per deployment.
SQL_DATASET_MAP = _parse_kv(os.environ.get("SQL_DATASET_MAP", "AEDW_DB=DB_AEDWD2"))
# Other ${TEMPLATE_VAR} placeholders -> concrete values, used only so a dry-run can parse.
SQL_RUNTIME_VARS = _parse_kv(os.environ.get("SQL_RUNTIME_VARS", "ETL_BATCH_SK=12345,env=dev"))


def clean_bq_error(msg):
    """Strip the API URL / Job-ID noise from a BigQuery error, keeping the human part."""
    if not msg:
        return msg
    core = msg
    m = re.search(r'prettyPrint=false:\s*(.*)', core, re.DOTALL)
    if m:
        core = m.group(1)
    # Drop trailing location / job metadata.
    core = re.split(r'\s*(?:Location:|Job ID:)', core, maxsplit=1)[0]
    core = core.strip().strip(':').strip()
    return core or msg


def generate_ai(prompt, max_output_tokens=2048):
    """Single entry point for all Gemini calls — token-frugal by default.

    Key savings on Gemini 2.5 Flash:
      - thinking_budget=0  -> disables the model's internal "thinking" tokens
                              (the largest hidden cost), restoring fast/cheap calls.
      - low temperature    -> deterministic, no wasted re-sampling.
      - capped output      -> bounded response size.
    Falls back to a plain call if the installed SDK predates these config options.
    """
    if genai_types is not None:
        try:
            config = genai_types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=max_output_tokens,
                thinking_config=genai_types.ThinkingConfig(thinking_budget=0),
            )
            return client.models.generate_content(model=GEMINI_MODEL, contents=prompt, config=config)
        except Exception:
            pass
    return client.models.generate_content(model=GEMINI_MODEL, contents=prompt)

def load_rules_from_file(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return ""

def _changed_new_lines(patch):
    """Return the set of NEW-file line numbers that were added/modified in a unified diff."""
    changed = set()
    new_lineno = None
    for line in patch.split('\n'):
        if line.startswith('@@'):
            m = re.search(r'\+(\d+)', line)        # @@ -a,b +c,d @@  -> new side starts at c
            new_lineno = int(m.group(1)) if m else None
            continue
        if new_lineno is None or line.startswith('+++') or line.startswith('---') or line.startswith('\\'):
            continue
        if line.startswith('+'):                    # added/modified line on the new side
            changed.add(new_lineno)
            new_lineno += 1
        elif line.startswith('-'):                  # removed line — does NOT advance new-file counter
            continue
        else:                                       # unchanged context line
            new_lineno += 1
    return changed


def _hunk_newside(patch):
    """Fallback: the raw new-side of each hunk (added + context), regions separated by blanks."""
    regions, current = [], []
    for line in patch.split('\n'):
        if line.startswith('@@'):
            if current:
                regions.append('\n'.join(current)); current = []
            continue
        if line.startswith('+++') or line.startswith('---') or line.startswith('\\') or line.startswith('-'):
            continue
        current.append(line[1:] if (line.startswith('+') or line.startswith(' ')) else line)
    if current:
        regions.append('\n'.join(current))
    return '\n\n'.join(r for r in regions if r.strip()).strip('\n')


def _sql_statements_covering(full_content, changed_lines):
    """Return the COMPLETE SQL statement(s) (`;`-delimited) that contain any changed line,
    so a change anywhere in a statement yields the whole statement — never a truncated fragment."""
    lines = full_content.split('\n')
    # Map each line to a statement id (a statement ends on the line where its ';' appears).
    line_stmt, stmt_id = [], 0
    for ln in lines:
        line_stmt.append(stmt_id)
        if ';' in ln:
            stmt_id += 1
    changed_stmts = {line_stmt[cl - 1] for cl in changed_lines if 1 <= cl <= len(lines)}
    if not changed_stmts:
        return ""
    kept = [lines[i] for i in range(len(lines)) if line_stmt[i] in changed_stmts]
    return '\n'.join(kept).strip('\n')


def extract_changed_content(patch, full_content="", filename=""):
    """Content reviewed in 'Diff Only' mode: only what changed on the feature branch —
    but never a half-statement. For SQL we expand each change to the FULL statement(s) it
    touches (so the INSERT/SELECT header is always included); for other files we return the
    changed hunks (added + context). Falls back to the full content when no patch is available."""
    if not patch:
        return full_content

    changed_lines = _changed_new_lines(patch)

    if filename.lower().endswith('.sql') and full_content and changed_lines:
        snippet = _sql_statements_covering(full_content, changed_lines)
        if snippet:
            return snippet

    return _hunk_newside(patch) or full_content


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
            patch = file.get('patch', '') or ''
            target_files.append({
                "filename": file['filename'],
                "content": raw_response.text,
                # Blob SHA at HEAD — changes only when a new commit modifies the file.
                # Used by the client to skip re-checking files with no new commits.
                "sha": file.get('sha', ''),
                # Unified diff vs the base branch, plus the changed-lines-only snippet
                # (added + context) used by the "Diff Only" review mode.
                "patch": patch,
                "diff_content": extract_changed_content(patch, raw_response.text, file['filename']),
            })

    return target_files

def needs_ai_review(filename, content):
    """Decide whether a file has genuine ENHANCEMENT scope worth spending AI tokens on.

    The deterministic linter already handles syntax, parameterization, datatype and
    compliance fixes for SQL/Python/KSH. The AI is invoked ONLY when a file is complex
    enough that a human expert reviewer would still find optimization opportunities —
    so simple files skip the AI entirely (fewer tokens).
    """
    fn = (filename or '').lower()
    text = content or ''

    if fn.endswith('.sql'):
        up = text.upper()
        # Set-based / multi-table / windowed / CTE SQL has real optimization scope.
        signals = ['JOIN ', 'GROUP BY', 'OVER (', 'OVER(', 'PARTITION BY', 'UNION', 'WITH ', '(SELECT']
        return any(s in up for s in signals)

    if fn.endswith('.py'):
        # Only sizeable Airflow DAGs (real task graphs) have structural optimization scope.
        return content.count('Operator(') >= 3 or content.count('>>') >= 3

    if fn.endswith('.ksh'):
        # Only shell scripts with real control-flow / pipelines may be optimizable beyond linting.
        return any(s in text for s in ['\nfor ', '\nwhile ', '\ncase ', ' | ', '&&'])

    return False

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
    """Resolve a (possibly ${templated}) dataset name to its real BigQuery dataset,
    using the configured SQL_DATASET_MAP. Fully generic — no hardcoded dataset names."""
    clean = dataset_name.replace('${', '').replace('}', '')
    if clean in SQL_DATASET_MAP:
        return SQL_DATASET_MAP[clean]
    for var, real in SQL_DATASET_MAP.items():
        if var.lower() == clean.lower():
            return real
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
            # Generic: NO hardcoded fallback schema. If the table can't be read live,
            # record it with no columns so downstream steps simply skip schema-based fixes
            # for it (rather than guessing fake columns).
            schema_explorer_data[f"{dataset}.{table}"] = []
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
            # Generic: no live schema available for this table → skip it (no fake columns).
            processed_tables.add(table_key)

    return schema_context if "  - " in schema_context else ""

def perform_bq_dry_run(sql_query):
    try:
        # Generic: substitute every configured ${TEMPLATE_VAR} so BigQuery can parse the query.
        executable_query = sql_query
        for var, real in SQL_DATASET_MAP.items():
            executable_query = executable_query.replace('${' + var + '}', real)
        for var, val in SQL_RUNTIME_VARS.items():
            executable_query = executable_query.replace('${' + var + '}', val)

        job_config = bigquery.QueryJobConfig(dry_run=True, use_query_cache=False)
        query_job = bq_client.query(executable_query, job_config=job_config)
        return {
            "valid": True,
            "bytes_processed": query_job.total_bytes_processed,
            "message": f"Syntax Valid. Will process {query_job.total_bytes_processed / (1024**2):.2f} MB."
        }
    except Exception as e:
        return {"valid": False, "bytes_processed": 0, "message": f"BigQuery validation error — {clean_bq_error(str(e))}"}

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

def review_code_with_gemini(filename, pre_cleaned_code, repo_context="", live_schema="", bq_error=""):
    # NOTE: the decision to call this function (optimization vs. skip) is made by the caller
    # (/process_file). This function always performs a real AI call.
    code_lines = pre_cleaned_code.split('\n')
    numbered_code = '\n'.join([f"{i+1:03d} | {line}" for i, line in enumerate(code_lines)])

    fn = (filename or '').lower()
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Generic, language-agnostic expert-reviewer framing (used for SQL, Python and KSH).
    common_header = (
        "You are an expert software code reviewer.\n"
        "The code below has ALREADY been pre-processed by a deterministic linter that fixed every\n"
        "mechanical issue it could (syntax, parameterization, naming/compliance, datatype/quoting).\n"
        "Those are SOLVED — do NOT re-report them. Act like a senior reviewer and ONLY surface genuine\n"
        "ENHANCEMENT opportunities (correctness risks, performance, scalability, maintainability).\n"
        "Be concise to conserve tokens. NEVER invent table or column names — rely only on the code and\n"
        "any schema/context provided. If there is genuinely nothing worth changing, output EXACTLY:\n"
        "\"No advanced architectural bottlenecks detected.\"\n"
    )

    if fn.endswith('.sql'):
        syntax_fix_directive = ""
        if bq_error:
            syntax_fix_directive = f"""
    ⚠️ HIGHEST PRIORITY — THE CODE CURRENTLY FAILS BIGQUERY VALIDATION:
    {bq_error}
    Your PRIMARY task is to FIX this error so the query is valid BigQuery Standard SQL, while preserving the original intent.
    Common causes: a stray semicolon splitting one statement into two, an invalid identifier (e.g. an unquoted column name with a space), or a dangling `AND`/`OR`.
    In the "Advanced Optimizations" section, explain the root cause and your fix. Then output the corrected, valid query under "Final Refactored Code".
    Do NOT output "No advanced architectural bottlenecks detected." — there is a real error that must be fixed.
    """
        domain_rules = f"""
    SQL DIALECT: Google BigQuery Standard SQL. All recommendations MUST be valid BigQuery SQL.
    {syntax_fix_directive}
    CRITICAL RULES:
    1. Preserve any parameterized placeholders (e.g. `${{...}}`) the linter produced — keep them parameterized.
    2. NEVER alter the functional output or business logic. Do NOT add, remove, or modify window partitions
       (`PARTITION BY`), aggregations, or filters. Optimizations MUST preserve the exact same data output.
    3. CARTESIAN PRODUCT / MISSING JOIN CONDITION (correctness exception to Rule 2): if an `INNER JOIN`,
       comma-join, or implicit `JOIN` has NO `ON`/`USING` clause, treat it as a LIKELY BUG (accidental
       Cartesian product), NOT an intentional cross join. Flag it prominently. In the refactored code do NOT
       rewrite to `CROSS JOIN`; add an explicit join condition using a key that BOTH tables share according to
       the LIVE SCHEMA below, and note it must be confirmed. If no shared key is evident, insert the literal
       placeholder `ON <JOIN_CONDITION_REQUIRED>`. Only keep `CROSS JOIN` if the original already says so.
    4. MISSING PARTITION BY (flag, do not silently rewrite): if a window `... OVER (...)` has `ORDER BY` but no
       `PARTITION BY`, flag that the frame spans the ENTIRE table (full scan) instead of per group. If the LIVE
       SCHEMA shows a natural grouping key, recommend `PARTITION BY <key>` and say it must be confirmed. Never
       silently modify an EXISTING `PARTITION BY`.

    LIVE PRODUCTION SCHEMA (use ONLY these real columns to verify references — do not invent any):
    {live_schema or '(no live schema available — do not guess column names)'}

    REPO CONTEXT (other files in this PR):
    {repo_context}

    ONLY look for: correctness risks (esp. missing JOIN conditions), BigQuery bottlenecks (poor join strategy,
    cross joins, inefficient window functions, scanning too much, not filtering early), and execution-plan/cost wins.
    """
        rules_file = 'rules_sql.txt'
    elif fn.endswith('.py'):
        domain_rules = """
    LANGUAGE: Python (typically Apache Airflow DAGs / data-pipeline code).
    Preserve behavior. ONLY look for: DAG structure & scheduling, idempotency, task dependency/parallelism,
    error handling/retries, resource use, and readability/maintainability. Do not restate linter fixes.
    """
        rules_file = 'rules_py.txt'
    elif fn.endswith('.ksh'):
        domain_rules = """
    LANGUAGE: Korn/Bash shell script. Preserve behavior. ONLY look for: robustness (error handling, quoting,
    safe deletes), efficiency (avoiding needless subprocesses/pipes), portability, and maintainability.
    Do not restate linter fixes.
    """
        rules_file = 'rules_ksh.txt'
    else:
        domain_rules = "\n    Review for correctness, performance and maintainability. Preserve behavior.\n"
        rules_file = None

    specific_instructions = load_rules_from_file(os.path.join(base_dir, rules_file)) if rules_file else ""

    output_format = """
    Format your output strictly with these two headings:

    ### 💡 Advanced Optimizations
    (Place ALL your explanations, reasoning, and context here.)

    ### 🛠️ Final Refactored Code
    (Output ONLY the raw code block here. Do NOT place any conversational text under this heading. Start immediately with ```)
    """

    prompt = (f"{common_header}\n{domain_rules}\n{specific_instructions}\n{output_format}\n"
              f"Code to review:\n```\n{numbered_code}\n```")

    # Token-frugal call (thinking disabled, low temperature, capped output).
    return generate_ai(prompt)

@app.route('/', methods=['GET'])
def home():
    # Serve index.html whether it sits next to this module or inside templates/.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(base_dir, 'index.html'),
        os.path.join(base_dir, 'templates', 'index.html'),
    ):
        if os.path.exists(candidate):
            with open(candidate, 'r', encoding='utf-8') as f:
                return f.read()
    return "index.html not found on server.", 500

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
    # 'full' = review the whole file; 'diff' = review only the changed lines (feature vs main).
    scope = (data.get('scope') or 'full').lower()

    user_email = get_user_identity()
    
    if not filename or not content:
        return jsonify({"error": "Missing file data."}), 400

    try:
        start_time = time.time()

        # Fetch the live schema up front so the deterministic linter can resolve small issues
        # (column-name typos, unquoted string literals) WITHOUT spending AI tokens.
        schema_meta = extract_tables_and_metadata(content) if filename.endswith('.sql') else {}

        pre_cleaned_code, local_linter_issues = process_file_locally(filename, content, schema_meta)
        has_secrets = any("SECURITY ALERT" in issue for issue in local_linter_issues)
        
        bq_metrics = None
        bq_bytes = 0
        ai_review_markdown = ""
        ai_optimized_code = ""   # AI suggestion shown in its own tab; never auto-applied.
        tokens_used = 0
        is_bypassed = False
        finops_status = "PASSED"
        structured_metadata = {}
        py_analysis = {}

        # The deterministic linter (pre_cleaned_code) is ALWAYS the committed baseline.
        # The AI is only an advisory optimizer that runs "if needed".
        if has_secrets:
            ai_review_markdown = "### 💡 Advanced Optimizations\n🔒 Security breach detected. Optimization review aborted until secrets are removed."
            is_bypassed = True
            finops_status = "SECURITY_HALT"
        else:
            live_schema = inject_live_schema_context(pre_cleaned_code) if filename.endswith('.sql') else ""
            structured_metadata = schema_meta  # reuse the schema already fetched for the linter
            py_analysis = parse_python_tasks(pre_cleaned_code) if filename.endswith('.py') else {}

            # Deterministically detect a window function that has ORDER BY but no PARTITION BY,
            # so the optimization section ALWAYS calls it out (regardless of what the AI returns).
            window_advisory = ""
            if filename.endswith('.sql'):
                for over_inner in re.findall(r'OVER\s*\(([^)]*)\)', pre_cleaned_code, re.IGNORECASE):
                    up = over_inner.upper()
                    if 'ORDER BY' in up and 'PARTITION BY' not in up:
                        window_advisory = ("⚠️ **Missing `PARTITION BY`:** a window function uses `OVER (... ORDER BY ...)` "
                            "with **no `PARTITION BY`**, so the window spans the **entire table as a single frame** "
                            "(a full scan) instead of being scoped per group. Add `PARTITION BY <key>` "
                            "using the appropriate grouping column if per-group framing was intended.")
                        break

            # Step 2a: validate the LINTER-FIXED code first (for SQL), so we can detect syntax errors
            # before deciding whether the AI is needed.
            sql_syntax_error_msg = ""
            if filename.endswith('.sql') and scope == 'diff':
                # Diff Only: we're reviewing a changed-lines fragment, which is usually not a
                # complete, runnable statement — skip the dry-run instead of failing on a fragment.
                bq_metrics = {
                    "valid": None,
                    "message": "Dry run skipped — reviewing only the lines changed on the feature branch (Diff Only mode)."
                }
                finops_status = "DIFF_SCOPE"
            elif filename.endswith('.sql'):
                has_placeholders = any(x in pre_cleaned_code for x in ["<MISSING_FILTER_REQUIRED>", "<JOIN_CONDITION_REQUIRED>", "(col1, col2, col3)", "TODO"])

                if has_placeholders:
                    bq_metrics = {
                        "valid": False,
                        "message": "Dry Run Bypassed: Code contains active structural placeholders requiring manual update."
                    }
                    finops_status = "CONTAIN_PLACEHOLDERS"
                else:
                    bq_metrics = perform_bq_dry_run(pre_cleaned_code)
                    bq_bytes = bq_metrics.get("bytes_processed", 0)

                    if not bq_metrics.get("valid"):
                        # Already human-readable + cleaned (URL/Job-ID stripped) by perform_bq_dry_run.
                        local_linter_issues.append(bq_metrics.get('message'))
                        finops_status = "SYNTAX_ERROR"
                        sql_syntax_error_msg = bq_metrics.get("message", "")
                    elif bq_bytes > FINOPS_MAX_BYTES_THRESHOLD:
                        finops_status = "FAILED_COST_GUARDRAIL"
                        bq_metrics["valid"] = False
                        bq_metrics["message"] = f"⚠️ FINOPS BLOCKED: Query structural plan consumes {bq_bytes / (1024**3):.2f} GB, exceeding environment maximum limit."
                        local_linter_issues.append("FinOps Exception: Execution plan exceeds maximum organizational compute thresholds.")

            # Step 2b: the deterministic linter + schema pass + BQ dry-run have already CAPTURED
            # every issue that can be found mechanically (parameterization, datatype/quoting,
            # placeholders, and any remaining syntax error reported by the dry-run). The AI is now
            # reserved EXCLUSIVELY for genuine optimization of complex SQL — it is no longer spent
            # trying to fix syntax errors, which saves a large number of tokens.
            if needs_ai_review(filename, pre_cleaned_code):
                ai_response_obj = review_code_with_gemini(filename, pre_cleaned_code, repo_context, live_schema, sql_syntax_error_msg)
                raw_ai_markdown = ai_response_obj.text or ""
                try:
                    if ai_response_obj.usage_metadata:
                        tokens_used = ai_response_obj.usage_metadata.total_token_count
                except AttributeError:
                    pass

                # Advisory notes only — do NOT fold the rewrite back into the working code.
                notes_part = raw_ai_markdown.split("### 🛠️ Final Refactored Code")[0].strip()
                ai_review_markdown = notes_part or "### 💡 Advanced Optimizations\nSee the AI Optimized tab for the suggested rewrite."

                # Extract the AI's suggested code and guarantee it still passes the linter.
                suggested_code = extract_refactored_code(raw_ai_markdown)
                suggested_code, _ = process_file_locally(filename, suggested_code, schema_meta)

                # Surface an AI version only when it actually differs from the linter baseline.
                if suggested_code.strip() and suggested_code.strip() != pre_cleaned_code.strip():
                    ai_optimized_code = suggested_code

                    # If the AI was fixing a syntax error, re-validate its suggestion so the
                    # user can see whether the fix actually passes BigQuery.
                    if sql_syntax_error_msg and not any(x in suggested_code for x in ["<MISSING_FILTER_REQUIRED>", "<JOIN_CONDITION_REQUIRED>", "(col1, col2, col3)", "TODO"]):
                        fixed_metrics = perform_bq_dry_run(suggested_code)
                        if fixed_metrics.get("valid"):
                            local_linter_issues.append("AI Fix Available: A corrected, BigQuery-valid version is ready in the ✨ AI Optimized tab.")
            else:
                is_bypassed = True
                if sql_syntax_error_msg:
                    # A real validation error was captured deterministically by the BigQuery dry-run.
                    # It is shown as an issue in the linter panel; the AI was NOT spent on it.
                    ai_review_markdown = ("### 💡 Advanced Optimizations\n"
                        "⚠️ The BigQuery dry-run flagged a validation error (see the Deterministic Linter panel). "
                        "Resolve it before committing — or ask the Architect in the chat below to rewrite it. "
                        "The AI optimizer was not spent automatically, to conserve tokens.")
                else:
                    ai_review_markdown = ("### 💡 Advanced Optimizations\n"
                        "✓ No advanced optimization required. The deterministic linter applied all parameterization, "
                        "datatype, and compliance fixes; the AI optimizer was skipped to save time and tokens.")

            # Guarantee the missing-PARTITION-BY call-out is in the optimization section.
            if window_advisory:
                heading = "### 💡 Advanced Optimizations"
                if heading in ai_review_markdown:
                    ai_review_markdown = ai_review_markdown.replace(heading, f"{heading}\n\n{window_advisory}\n", 1)
                else:
                    ai_review_markdown = f"{heading}\n\n{window_advisory}\n\n{ai_review_markdown}"

        time_taken = round(time.time() - start_time, 2)
        estimated_cost = (tokens_used / 1000000) * 0.15

        scorecard = calculate_optimization_scores(filename, pre_cleaned_code, len(local_linter_issues))

        log_to_bq_analytics(repo_name, filename, filename.split('.')[-1], tokens_used, estimated_cost, is_bypassed, len(local_linter_issues), bq_bytes, has_secrets, user_email, finops_status)
        
        return jsonify({
            "filename": filename,
            "unit_test_fixes": local_linter_issues,
            "ai_review": ai_review_markdown,
            "linter_code": pre_cleaned_code,
            "ai_optimized_code": ai_optimized_code,
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
        response = generate_ai(prompt, max_output_tokens=1024)
        clean_text = response.text.replace('```json', '').replace('```', '').strip()
        parsed_data = json.loads(clean_text)
        return jsonify(parsed_data), 200
    except Exception as e:
        # Generic, schema-agnostic placeholder preview when AI generation is unavailable
        # (no hardcoded business/domain data).
        return jsonify([
            {"column_1": "sample_value", "column_2": 123, "column_3": "2026-01-01"},
            {"column_1": "sample_value", "column_2": 456, "column_3": "2026-01-02"},
            {"column_1": "sample_value", "column_2": 789, "column_3": "2026-01-03"}
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
        if any(x in code for x in ["<MISSING_FILTER_REQUIRED>", "<JOIN_CONDITION_REQUIRED>", "(col1, col2, col3)", "TODO"]):
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
        response = generate_ai(prompt)
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
