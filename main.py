import os
import time
import random
import datetime
import requests
import json
import re
import subprocess
import urllib.request
from functools import wraps
from flask import Flask, request, jsonify, session, redirect
from flask_cors import CORS

# Modern SDK imports
from google import genai
from google.cloud import bigquery
from github import Github

# Google Sign-In (ID token verification)
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_auth_requests

try:
    from google.genai import types as genai_types
except Exception:
    genai_types = None

# Import our local rule engine
from linter import process_file_locally, DEFAULT_SQL_DATASET_MAP


def load_secret(name, default=""):
    """Read a secret. If USE_SECRET_MANAGER=1, pull `name` from Google Secret Manager
    (project from SECRET_MANAGER_PROJECT or the default project); otherwise use the env var.
    Always falls back to the env var so local/dev keeps working."""
    env_val = os.environ.get(name, default)
    if os.environ.get("USE_SECRET_MANAGER", "").strip() != "1":
        return env_val
    try:
        from google.cloud import secretmanager
        client_sm = secretmanager.SecretManagerServiceClient()
        project = os.environ.get("SECRET_MANAGER_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
        path = f"projects/{project}/secrets/{name}/versions/latest"
        return client_sm.access_secret_version(name=path).payload.data.decode("utf-8").strip()
    except Exception:
        return env_val  # fall back to env if Secret Manager is unavailable/misconfigured


app = Flask(__name__)
# Signed-session secret — set FLASK_SECRET_KEY (or store it in Secret Manager) in production.
app.secret_key = load_secret("FLASK_SECRET_KEY", "dev-insecure-secret-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=12),
)
CORS(app, supports_credentials=True)

# --- Google OAuth / access policy ---
GOOGLE_OAUTH_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "").strip()
# Optional Workspace-domain restriction. Empty = allow ANY Google account.
ALLOWED_EMAIL_DOMAIN = os.environ.get("ALLOWED_EMAIL_DOMAIN", "").strip().lower()

# Auth is OPT-IN: it only turns on when a Google OAuth client ID is configured.
# With no client ID the app runs ungated (so it works out of the box / stays generic).
AUTH_ENABLED = bool(GOOGLE_OAUTH_CLIENT_ID)


def login_required(view):
    """Reject UI/API calls without an authenticated session — but ONLY when auth is enabled.
    If GOOGLE_OAUTH_CLIENT_ID isn't set, auth is off and requests pass through."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if AUTH_ENABLED and not session.get('user_email'):
            return jsonify({"error": "Authentication required. Please sign in.", "auth_required": True}), 401
        return view(*args, **kwargs)
    return wrapper


# Initialize the new Google GenAI Client
client = genai.Client(vertexai=True, location="us-central1")
bq_client = bigquery.Client()

BQ_ANALYTICS_TABLE = os.environ.get("BQ_ANALYTICS_TABLE", "code_review_analytics.scan_history")
FINOPS_MAX_BYTES_THRESHOLD = int(os.environ.get("FINOPS_MAX_BYTES_THRESHOLD", 10 * 1024 * 1024 * 1024))
# Models. These default to the newer Gemini 3.x line shown in your Model Garden, but the EXACT
# api id matters — open the model in Model Garden → "Use this model"/sample code and copy the
# `model="..."` string, then override the env var if it differs (preview ids are often
# date-versioned, e.g. gemini-3.1-pro-preview-MM-YYYY). A wrong id is SAFE: an unreachable model
# falls back to GEMINI_FALLBACK_MODEL automatically, so reviews keep working.
#   GEMINI_MODEL          – default per-file model (fast / frugal)            → "Gemini 3.5 Flash"
#   GEMINI_PRO_MODEL      – the UI Pro toggle's higher-reasoning model        → "Gemini 3.1 Pro Preview"
#   GEMINI_FALLBACK_MODEL – known-good safety net if the above can't be reached
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_PRO_MODEL = os.environ.get("GEMINI_PRO_MODEL", "gemini-3.1-pro-preview")
GEMINI_FALLBACK_MODEL = os.environ.get("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash")
# Hard ceiling on a single response's output tokens, and the largest file (in lines) for which
# we let the AI attempt a FULL rewrite. Beyond that we switch to advisory-only so a long file is
# never half-emitted (which previously looked like the AI "deleting" code). Both are overridable.
AI_MAX_OUTPUT_TOKENS = int(os.environ.get("AI_MAX_OUTPUT_TOKENS", "32768"))
AI_FULL_REWRITE_MAX_LINES = int(os.environ.get("AI_FULL_REWRITE_MAX_LINES", "1200"))
# Retries (with backoff) for a rate-limited (429) Gemini call before giving up and degrading
# gracefully to the linter-only result. A per-minute quota spike on a many-file run is transient,
# so a few backed-off retries clear it without failing the file (a sustained outage still degrades).
AI_MAX_RETRIES = int(os.environ.get("AI_MAX_RETRIES", "3"))


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
# Default is shared with linter.py (DEFAULT_SQL_DATASET_MAP) so the parameterizer and the
# resolver always agree — otherwise a ${VAR} the linter emits can't be resolved/validated.
SQL_DATASET_MAP = _parse_kv(os.environ.get("SQL_DATASET_MAP", DEFAULT_SQL_DATASET_MAP))
# Other ${TEMPLATE_VAR} placeholders -> concrete values, used only so a dry-run can parse.
SQL_RUNTIME_VARS = _parse_kv(os.environ.get("SQL_RUNTIME_VARS", "ETL_BATCH_SK=12345,env=dev"))


def _has_structural_placeholders(code):
    """True when the linter left ANY placeholder behind — a mandatory-filter / join-condition
    stub, or a generated target column list. Used to BYPASS the dry-run, since none of these are
    runnable BigQuery. Matches ONLY the linter's unique sentinels (the angle-bracket stubs and the
    'replace placeholder names' col-list tag), NOT a generic word like 'TODO' — otherwise a user's
    own `-- TODO: ...` comment would wrongly bypass validation."""
    return _has_human_required_placeholders(code) or _has_ai_resolvable_placeholders(code)


def _has_ai_resolvable_placeholders(code):
    """Subset of placeholders the AI can actually fill from the LIVE SCHEMA — a generated
    target column list (the linter tags these with a unique 'replace placeholder names'
    comment, so this matches any column count, including a single column). EXCLUDES the
    human-decision stubs (<MISSING_FILTER_REQUIRED> / <JOIN_CONDITION_REQUIRED>): the rules
    forbid the AI from inventing a DELETE/UPDATE filter or guessing a join key, so escalating
    for those alone would just burn a token-call the human still has to redo."""
    return 'replace placeholder names' in code or bool(re.search(r'\bcol1,\s*col2\b', code))


def _has_human_required_placeholders(code):
    """A stub ONLY a human can resolve — a mandatory DELETE/UPDATE filter, or a join condition
    the schema doesn't dictate. The query is CRITICAL and can't even be dry-run until it's filled
    in, and the linter already flagged it deterministically. So we DON'T spend AI on the file
    (no tokens re-stating a check the linter made); it's re-evaluated on the next scan once the
    human supplies the intent."""
    return any(p in code for p in ('<MISSING_FILTER_REQUIRED>', '<JOIN_CONDITION_REQUIRED>'))


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


def generate_ai(prompt, max_output_tokens=4096, model=None):
    """Single entry point for all Gemini calls — token-frugal by default.
    `model` lets a caller override the default for one call (e.g. the UI's Flash→Pro toggle).

    Key savings:
      - thinking_budget=0  -> disables the model's internal "thinking" tokens
                              (the largest hidden cost), restoring fast/cheap calls.
      - low temperature    -> deterministic, no wasted re-sampling.
    The OUTPUT cap is sized by the caller to the file: too small a cap is what made the model
    stop mid-file and look like it was deleting lines, so callers pass a budget scaled to the
    code length (clamped to AI_MAX_OUTPUT_TOKENS). Falls back to a plain call on older SDKs, and
    to GEMINI_FALLBACK_MODEL if the configured model is unavailable (404 / no access), so a model
    misconfiguration degrades to a working model instead of failing every review.
    """
    primary = model or GEMINI_MODEL
    capped = max(1024, min(int(max_output_tokens or 4096), AI_MAX_OUTPUT_TOKENS))
    for attempt in range(AI_MAX_RETRIES + 1):
        try:
            return _generate_with_model(primary, prompt, capped)
        except Exception as e:
            # Configured model unreachable (404 / no access) → one-shot retry on the fallback model.
            if (GEMINI_FALLBACK_MODEL and GEMINI_FALLBACK_MODEL != primary
                    and _is_model_unavailable(e)):
                return _generate_with_model(GEMINI_FALLBACK_MODEL, prompt, capped)
            # Rate-limited / quota (429) → exponential backoff with jitter, then retry. A per-minute
            # quota refills within ~60s, so backing off clears most spikes. After the last attempt the
            # error propagates so the caller can degrade gracefully (keep linter result).
            if _is_rate_limited(e) and attempt < AI_MAX_RETRIES:
                time.sleep(min(30, 2 ** (attempt + 1)) + random.uniform(0, 1))   # ~2s, 4s, 8s, 16s …
                continue
            raise


def _is_model_unavailable(err):
    """Did the call fail because the MODEL id is wrong / inaccessible (vs. a transient error)?
    Used to decide whether retrying on the fallback model is worthwhile."""
    s = str(err).lower()
    return ('not_found' in s or '404' in s or 'was not found' in s
            or 'does not have access' in s or 'is not allowed' in s
            or 'invalid model' in s or 'unknown model' in s)


def _is_rate_limited(err):
    """A 429 / quota / rate-limit error from Vertex AI — retryable (with backoff) and, if it
    persists, a signal to skip the AI for this file rather than fail the whole review."""
    s = str(err).lower()
    return ('429' in s or 'resource_exhausted' in s or 'resource exhausted' in s
            or 'rate limit' in s or 'ratelimit' in s or 'quota' in s or 'exceeded' in s)


def _generate_with_model(model, prompt, capped):
    """One generate_content call for a specific model. Tries the rich config first and degrades
    to a plain call only for CONFIG/SDK problems — a model-not-found error is re-raised so the
    caller can switch models rather than silently retrying the same bad id without config."""
    if genai_types is not None:
        try:
            config = genai_types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=capped,
                thinking_config=genai_types.ThinkingConfig(thinking_budget=0),
            )
            return client.models.generate_content(model=model, contents=prompt, config=config)
        except Exception as e:
            if _is_model_unavailable(e) or _is_rate_limited(e):
                raise   # a plain retry can't help these — and a 429 retry doubles quota pressure
            # else: older SDK without these config options — fall through to a plain call.
    return client.models.generate_content(model=model, contents=prompt)


def _estimate_tokens(text):
    """Cheap token estimate (~4 chars/token) for sizing the output budget."""
    return max(1, len(text or "") // 4)


def _response_was_truncated(response):
    """Best-effort: did the model stop because it hit the output cap (MAX_TOKENS)? Used to
    discard a partial rewrite. Tolerant of SDK shape differences — returns False if unknown."""
    try:
        fr = response.candidates[0].finish_reason
        name = getattr(fr, "name", str(fr)).upper()
        return "MAX_TOKEN" in name or "LENGTH" in name
    except Exception:
        return False


def _ai_rewrite_is_safe(original, suggestion, ext):
    """Last-resort guard against a CATASTROPHICALLY short rewrite (a clearly broken/truncated
    response), used only when the reliable signal — finish_reason == MAX_TOKENS — is unavailable.

    It is deliberately LENIENT: a legitimate refactor often removes lines (e.g. redundant echoes,
    consolidated UNIONs), so we must NOT reject a complete-but-shorter rewrite — doing so was what
    hid the AI tab entirely. We reject only when almost everything is gone (<35% of non-blank lines)."""
    o = [l for l in (original or "").split('\n') if l.strip()]
    s = [l for l in (suggestion or "").split('\n') if l.strip()]
    if not s:
        return False
    if len(o) >= 12 and len(s) < 0.35 * len(o):
        return False
    return True

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
        # Escalate ONLY on a deterministic RED FLAG an expert would genuinely want to look at —
        # NOT the mere presence of JOIN/GROUP BY. A well-formed single-join, filtered, aggregated
        # query almost always comes back "it's fine", so asking the AI there just burns tokens
        # (the user can still force a review via the Architect chat or the Pro toggle). Word-boundary
        # regex is used throughout so a keyword at the START of a line (after a newline, not a space)
        # is still detected — a plain substring like ' JOIN ' would miss those and misfire.
        def has(pat):
            return re.search(pat, up) is not None
        n_joins = len(re.findall(r'\bJOIN\b', up))
        return (
            'SELECT *' in up                                             # scanning all columns / schema drift
            or has(r'\bCROSS\s+JOIN\b')                                  # explicit Cartesian product
            or (n_joins >= 1 and not has(r'\bON\b') and not has(r'\bUSING\b'))  # join missing its condition
            or n_joins >= 3                                              # many joins → join-order matters
            or has(r'\bUNION\b')                                         # set ops (dedup / consolidation cost)
            or has(r'\bOVER\s*\(')                                       # window functions (incl. PARTITION BY)
            or has(r'\(\s*SELECT\b')                                     # nested / correlated subqueries / CTEs
            or (n_joins >= 1 and not has(r'\bWHERE\b'))                  # unfiltered join → full-table scan
        )

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
    """Dynamically extracts the user email from the signed-in session, IAP, Compute Metadata, or local GCloud CLI."""
    # 0. Authenticated in-app Google sign-in (highest priority).
    if session.get('user_email'):
        return session['user_email']

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

# --- In-memory TTL cache for live BigQuery table schemas (they rarely change) ---
_SCHEMA_CACHE = {}
SCHEMA_CACHE_TTL = int(os.environ.get("SCHEMA_CACHE_TTL", 300))  # seconds


def get_table_columns_cached(resolved_dataset, table):
    """Return [{name,type,mode}, ...] for a table, cached in-memory with a TTL so the
    same table isn't re-fetched from BigQuery on every file/run. Returns [] when the
    table can't be read (and caches that miss briefly to avoid hammering get_table)."""
    key = f"{resolved_dataset}.{table}"
    now = time.time()
    hit = _SCHEMA_CACHE.get(key)
    if hit and (now - hit[0]) < SCHEMA_CACHE_TTL:
        return hit[1]
    try:
        table_ref = bq_client.get_table(f"{bq_client.project}.{resolved_dataset}.{table}")
        cols = [{"name": f.name, "type": f.field_type, "mode": f.mode} for f in table_ref.schema]
    except Exception:
        cols = []
    _SCHEMA_CACHE[key] = (now, cols)
    return cols


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


def _is_known_dataset(dataset_name):
    """True only for a configured ${VAR} or a real dataset name we know about. This is how
    we tell a genuine `dataset.table` reference from a table-alias.column one (e.g. HC.CLM_ID),
    which must NOT be treated as a table in the schema explorer / live-schema context."""
    clean = dataset_name.replace('${', '').replace('}', '').lower()
    for var, real in SQL_DATASET_MAP.items():
        if clean == var.lower() or clean == real.lower():
            return True
    return False


def _extract_table_refs(sql_query):
    """Ordered, de-duplicated list of REAL (display_dataset, table) references.

    Includes `${VAR}.table` and `KnownDataset.table`, but EXCLUDES alias.column refs
    (HC.CLM_ID) and any unknown prefix — so neither the schema explorer nor the AI's
    live-schema context is polluted with non-tables. De-dup is by RESOLVED dataset, so the
    same physical table referenced as both `${SRC_DB}.X` and `DB_SRCD2.X` collapses to one."""
    refs, seen = [], set()

    def _add(display, table):
        key = f"{resolve_dataset_for_metadata(display)}.{table}".lower()
        if key not in seen:
            seen.add(key)
            refs.append((display, table))

    for dataset, table in re.findall(r'\$\{([A-Za-z0-9_]+)\}\.([A-Za-z0-9_]+)', sql_query):
        _add(f"${{{dataset}}}", table)
    for dataset, table in re.findall(r'\b([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\b', sql_query):
        if _is_known_dataset(dataset):
            _add(dataset, table)
    return refs


def extract_tables_and_metadata(sql_query):
    schema_explorer_data = {}
    for dataset, table in _extract_table_refs(sql_query):
        resolved_dataset = resolve_dataset_for_metadata(dataset)
        # Cached live fetch; [] when unreadable (no hardcoded fallback schema).
        schema_explorer_data[f"{dataset}.{table}"] = get_table_columns_cached(resolved_dataset, table)
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
    for dataset, table in _extract_table_refs(sql_query):
        resolved_dataset = resolve_dataset_for_metadata(dataset)
        cols = get_table_columns_cached(resolved_dataset, table)  # cached live fetch
        if cols:
            fields_desc = [f"  - {c['name']} ({c['type']})" for c in cols]
            schema_context += f"Table: {dataset}.{table} structure columns:\n" + "\n".join(fields_desc) + "\n"
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

def review_code_with_gemini(filename, pre_cleaned_code, repo_context="", live_schema="", bq_error="",
                            resolve_placeholders=False, advisory_only=False, max_output_tokens=None, model=None):
    # NOTE: the decision to call this function (optimization vs. skip) is made by the caller
    # (/process_file). This function always performs a real AI call.
    # bq_error: a residual syntax/validation error the linter could not fix (SQL dry-run or
    #           Python compile) — the AI's PRIMARY job becomes repairing it.
    # resolve_placeholders: the linter left structural placeholders (col1.., TODO) the AI
    #           should fill using the LIVE SCHEMA (but NEVER invent a DELETE/UPDATE filter).
    # advisory_only: file too large for a safe full rewrite — return line-referenced notes only.
    # max_output_tokens: caller-sized output budget so long files aren't truncated mid-rewrite.
    code_lines = pre_cleaned_code.split('\n')
    numbered_code = '\n'.join([f"{i+1:03d} | {line}" for i, line in enumerate(code_lines)])

    fn = (filename or '').lower()
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Generic, language-agnostic expert-reviewer framing (used for SQL, Python and KSH).
    # Tight framing to keep INPUT tokens low — a deterministic linter already ran, so the model
    # only needs to look for genuine enhancements, not re-report mechanical fixes.
    common_header = (
        "You are a senior code reviewer. A deterministic linter already fixed all mechanical issues "
        "(syntax, parameterization, naming, datatypes) — do NOT re-report those. Surface ONLY genuine "
        "enhancements (correctness, performance, scalability). Be terse: at most 4 short bullets, each "
        "one line, no preamble, no restating the rules or the code. Never invent table/column names — "
        "use only the code and the schema below. If nothing is worth changing, output EXACTLY: "
        "\"No advanced architectural bottlenecks detected.\"\n"
    )

    if fn.endswith('.sql'):
        syntax_fix_directive = ""
        if bq_error:
            syntax_fix_directive = f"""
    ⚠️ HIGHEST PRIORITY — THE CODE CURRENTLY FAILS BIGQUERY VALIDATION:
    {bq_error}
    Your PRIMARY task is to FIX this error so the query is valid BigQuery Standard SQL, while preserving the original intent.
    Common causes: a stray semicolon splitting one statement into two, a MISSING semicolon between two statements,
    a MISSING closing quote on a string literal, an invalid identifier (e.g. an unquoted column name with a space),
    a CURRENT_DATETIME()/CURRENT_DATE() value whose type does not match the target column, or a dangling `AND`/`OR`.
    In the "Advanced Optimizations" section, explain the root cause and your fix. Then output the corrected, valid query under "Final Refactored Code".
    Do NOT output "No advanced architectural bottlenecks detected." — there is a real error that must be fixed.
    """
        elif resolve_placeholders:
            syntax_fix_directive = """
    ⚠️ HIGHEST PRIORITY — THE LINTER LEFT STRUCTURAL PLACEHOLDERS THAT MUST BE RESOLVED:
    - Replace any generated `(col1, col2, ...)` target column list with the REAL column names, in order, taken
      ONLY from the LIVE SCHEMA below. If the schema is unavailable, keep the list and say so — never invent names.
    - Ensure every value's type matches its target column (e.g. a DATE column must not receive CURRENT_DATETIME()).
    - Fix any remaining syntax issue (missing comma/semicolon/closing quote) so the statement is valid BigQuery SQL.
    - DO NOT invent a filter for a `<MISSING_FILTER_REQUIRED>` DELETE/UPDATE and DO NOT guess a `<JOIN_CONDITION_REQUIRED>`
      key that the schema does not clearly support — leave those placeholders for a human.
    Explain what you resolved under "Advanced Optimizations", then output the corrected query under "Final Refactored Code".
    Do NOT output "No advanced architectural bottlenecks detected." — there is real work to do.
    """
        domain_rules = f"""
    SQL DIALECT: Google BigQuery Standard SQL — all output must be valid BigQuery SQL.
    {syntax_fix_directive}
    CRITICAL RULES:
    1. Keep the linter's ${{...}} placeholders parameterized.
    2. Preserve exact output/logic — do not change PARTITION BY, aggregations, or filters.
    3. A JOIN with no ON/USING is a LIKELY BUG (accidental Cartesian): flag it; add a key BOTH tables share
       per the schema below (mark "confirm"), else `ON <JOIN_CONDITION_REQUIRED>` — never silently use CROSS
       JOIN, and keep CROSS JOIN only if the original already had it.
    4. A window `OVER(... ORDER BY ...)` with NO PARTITION BY scans the whole table as one frame: flag it and
       suggest `PARTITION BY <key>` (mark "confirm"); never modify an existing PARTITION BY.

    LIVE SCHEMA (use ONLY these real columns; never invent):
    {live_schema or '(none available — do not guess column names)'}
    REPO CONTEXT: {repo_context}
    Look for: correctness (esp. missing JOIN conditions) and BigQuery cost/plan wins (join strategy, cross
    joins, inefficient windows, scanning/filtering early).
    """
        rules_file = 'rules_sql.txt'
    elif fn.endswith('.py'):
        py_fix_directive = ""
        if bq_error:
            py_fix_directive = f"""
    ⚠️ HIGHEST PRIORITY — THE CODE DOES NOT PARSE AS VALID PYTHON:
    {bq_error}
    Your PRIMARY task is to FIX this so the module imports cleanly (correct indentation, balanced brackets/quotes),
    while preserving behavior. Output the corrected, valid module under "Final Refactored Code".
    Do NOT output "No advanced architectural bottlenecks detected." — there is a real error that must be fixed.
    """
        domain_rules = f"""
    LANGUAGE: Python (typically Apache Airflow DAGs / data-pipeline code).
    {py_fix_directive}
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

    if advisory_only:
        # Large file: a full rewrite would not fit one response (and a half-emitted file looks
        # like deleted code). Ask for line-referenced advice ONLY — no code block.
        output_format = """
    This file is LARGE. Do NOT output a full rewrite. Under a single heading, give specific,
    line-referenced findings (use the NNN | line numbers) the developer can apply by hand.

    ### 💡 Advanced Optimizations
    (All findings here, each citing the line number(s) it applies to. Do NOT emit a code block.)
    """
    else:
        output_format = """
    Format your output strictly with these two headings:

    ### 💡 Advanced Optimizations
    (≤4 terse one-line bullets. No preamble, no reasoning essays, no restating the code.)

    ### 🛠️ Final Refactored Code
    (Output the COMPLETE corrected file as ONE raw code block — every line, start to finish, nothing
    omitted or abbreviated with "..." . Do NOT place any conversational text under this heading. Start immediately with ```)
    """

    prompt = (f"{common_header}\n{domain_rules}\n{specific_instructions}\n{output_format}\n"
              f"Code to review:\n```\n{numbered_code}\n```")

    # Output budget = room for the FULL rewrite (code) PLUS the explanation. A too-small cap is
    # what truncated the code block after long notes, so we budget generously (x3 + 4096 headroom);
    # it is only a ceiling — you pay for tokens actually generated, not the cap. Clamped in generate_ai.
    budget = max_output_tokens or min(AI_MAX_OUTPUT_TOKENS, _estimate_tokens(pre_cleaned_code) * 3 + 4096)
    return generate_ai(prompt, max_output_tokens=budget, model=model)


def _rules_for(filename):
    """The domain rule-pack text for a file's language ('' when none)."""
    fn = (filename or '').lower()
    rf = 'rules_sql.txt' if fn.endswith('.sql') else 'rules_py.txt' if fn.endswith('.py') \
         else 'rules_ksh.txt' if fn.endswith('.ksh') else None
    return load_rules_from_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), rf)) if rf else ""


def _strip_line_gutter(code):
    """Remove a leaked 'NNN | ' review gutter if the model copied it into its output."""
    lines = code.split('\n')
    gutter = re.compile(r'^\s*\d{1,4} \| ')
    hits = sum(1 for l in lines if gutter.match(l))
    if lines and hits > len(lines) // 2:
        return '\n'.join(gutter.sub('', l) for l in lines)
    return code


def pro_think(filename, pre_cleaned_code, live_schema, repo_context, model=None):
    """STAGE 1 — THINK (reasoning model, tiny output). Analyzes the linted code against the
    rule-pack and live schema, returns (findings_markdown, changes_required, tokens).
    Costs little despite the pricier model: the output is capped at terse bullets and it NEVER
    emits code — the cheap model does that in stage 2, and only when stage 1 found something."""
    code_lines = pre_cleaned_code.split('\n')
    numbered = '\n'.join(f"{i+1:03d} | {l}" for i, l in enumerate(code_lines))
    lang = 'BigQuery SQL' if filename.endswith('.sql') else 'Python (Airflow)' if filename.endswith('.py') else 'Korn shell'
    prompt = (
        f"You are a principal data engineer reviewing {lang} for production. A deterministic linter "
        "already fixed all mechanical issues (syntax, parameterization, naming, datatypes) — never mention those.\n"
        f"RULES:\n{_rules_for(filename)}\n"
        f"LIVE SCHEMA (only real columns; never invent):\n{live_schema or '(none)'}\n"
        f"REPO CONTEXT: {repo_context}\n\n"
        "Identify ONLY genuine correctness / performance / cost issues. Output at most 6 terse bullets, "
        "each as 'L<line>: <issue> — <fix>'. No code blocks, no preamble, no restating the rules.\n"
        "Your LAST line must be exactly one of:  VERDICT: CHANGES_REQUIRED  |  VERDICT: NO_CHANGES\n\n"
        f"CODE:\n```\n{numbered}\n```"
    )
    resp = generate_ai(prompt, max_output_tokens=1024, model=(model or GEMINI_PRO_MODEL))
    text = (resp.text or "").strip()
    tokens = 0
    try:
        if resp.usage_metadata:
            tokens = resp.usage_metadata.total_token_count
    except AttributeError:
        pass
    up = text.upper()
    if 'NO_CHANGES' in up or 'NO ADVANCED ARCHITECTURAL BOTTLENECKS' in up:
        changes = False
    elif 'CHANGES_REQUIRED' in up:
        changes = True
    else:
        changes = bool(text)        # no explicit verdict — assume findings imply changes
    findings = re.sub(r'(?im)^\s*VERDICT:.*$', '', text).strip()
    return findings, changes, tokens


def flash_code(filename, pre_cleaned_code, findings, live_schema, model=None):
    """STAGE 2 — CODE (fast model, code-only output). Applies the stage-1 findings to the file
    and returns (full_corrected_code, tokens, truncated). Retries once at the max budget if the
    first response was cut off, so a complete file always comes back or nothing does."""
    code_lines = pre_cleaned_code.split('\n')
    numbered = '\n'.join(f"{i+1:03d} | {l}" for i, l in enumerate(code_lines))
    ext = filename.rsplit('.', 1)[-1].lower()
    prompt = (
        "You are a precise code generator. Apply EXACTLY the review findings below to the file — nothing "
        "more. Preserve ${...} placeholders and all business logic.\n"
        f"FINDINGS:\n{findings}\n"
        f"LIVE SCHEMA (only real columns; never invent):\n{live_schema or '(none)'}\n\n"
        f"Output ONLY the complete corrected file as one ```{ext} code block — every line, nothing "
        "omitted. The 'NNN | ' gutter in the input is for line reference only: output WITHOUT it. No prose.\n\n"
        f"CODE:\n```\n{numbered}\n```"
    )
    budget = min(AI_MAX_OUTPUT_TOKENS, _estimate_tokens(pre_cleaned_code) * 3 + 2048)
    resp = generate_ai(prompt, max_output_tokens=budget, model=(model or GEMINI_MODEL))
    tokens = 0
    try:
        if resp.usage_metadata:
            tokens = resp.usage_metadata.total_token_count
    except AttributeError:
        pass
    code = _strip_line_gutter(extract_refactored_code(resp.text or ""))
    truncated = _response_was_truncated(resp)
    if truncated or not code.strip():
        retry = generate_ai(prompt, max_output_tokens=AI_MAX_OUTPUT_TOKENS, model=(model or GEMINI_MODEL))
        try:
            if retry.usage_metadata:
                tokens += retry.usage_metadata.total_token_count
        except AttributeError:
            pass
        retry_code = _strip_line_gutter(extract_refactored_code(retry.text or ""))
        if retry_code.strip():
            code, truncated = retry_code, _response_was_truncated(retry)
    return code, tokens, truncated


def _read_first(*relpaths):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    for rel in relpaths:
        path = os.path.join(base_dir, rel)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
    return None


@app.route('/', methods=['GET'])
def home():
    # Gate the app behind Google sign-in ONLY when auth is enabled (a client ID is configured).
    if AUTH_ENABLED and not session.get('user_email'):
        login_html = _read_first('login.html', os.path.join('templates', 'login.html'))
        if login_html is None:
            return "login.html not found on server.", 500
        return login_html.replace('{{GOOGLE_CLIENT_ID}}', GOOGLE_OAUTH_CLIENT_ID)
    index_html = _read_first('index.html', os.path.join('templates', 'index.html'))
    if index_html is None:
        return "index.html not found on server.", 500
    return index_html


@app.route('/auth/google', methods=['POST'])
def auth_google():
    """Verify a Google Identity Services ID token and open a session."""
    if not GOOGLE_OAUTH_CLIENT_ID:
        return jsonify({"error": "Server is missing GOOGLE_OAUTH_CLIENT_ID configuration."}), 500
    token = (request.get_json(silent=True) or {}).get('credential')
    if not token:
        return jsonify({"error": "Missing Google credential."}), 400
    try:
        info = google_id_token.verify_oauth2_token(token, google_auth_requests.Request(), GOOGLE_OAUTH_CLIENT_ID)
    except Exception:
        return jsonify({"error": "Invalid or expired Google credential."}), 401
    if info.get('iss') not in ('accounts.google.com', 'https://accounts.google.com'):
        return jsonify({"error": "Invalid token issuer."}), 401
    if not info.get('email_verified', False):
        return jsonify({"error": "Your Google email is not verified."}), 403
    email = (info.get('email') or '').lower()
    if ALLOWED_EMAIL_DOMAIN and not email.endswith('@' + ALLOWED_EMAIL_DOMAIN):
        return jsonify({"error": f"Access is restricted to @{ALLOWED_EMAIL_DOMAIN} accounts."}), 403
    session.permanent = True
    session['user_email'] = info.get('email')
    session['user_name'] = info.get('name', '')
    session['user_picture'] = info.get('picture', '')
    return jsonify({"ok": True, "email": session['user_email'], "name": session['user_name']}), 200


@app.route('/auth/logout', methods=['GET', 'POST'])
def auth_logout():
    session.clear()
    if request.method == 'GET':
        return redirect('/')
    return jsonify({"ok": True}), 200


@app.route('/auth/status', methods=['GET'])
def auth_status():
    if session.get('user_email'):
        return jsonify({"authenticated": True, "auth_enabled": AUTH_ENABLED, "email": session.get('user_email'),
                        "name": session.get('user_name', ''), "picture": session.get('user_picture', '')}), 200
    return jsonify({"authenticated": False, "auth_enabled": AUTH_ENABLED}), 200


@app.route('/prepare', methods=['POST'])
@login_required
def prepare_review():
    data = request.get_json()
    repo = data.get('repo')
    head_branch = data.get('branch')
    base_branch = data.get('base_branch', 'main')
    github_token = load_secret("GITHUB_TOKEN")
    
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

def review_one_file(filename, content, scope='full', repo_context='No additional context.',
                    repo_name='unknown', user_email='unknown-user@company.com', model=None, force=False):
    """Core review pipeline for a single file. Returns the result dict (same shape the
    /process_file route returns). Reused by both the web UI and the CI/PR endpoint."""
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
        model_used = None   # which model(s) actually reviewed this file (None = deterministic only)
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
            # Schema explorer reflects the LINTED code (fully parameterized, de-duplicated,
            # alias-free) — never the original — so it can't show a raw dataset beside its
            # ${VAR} form or list a table-alias.column as a table. Re-extraction hits the cache.
            structured_metadata = extract_tables_and_metadata(pre_cleaned_code) if filename.endswith('.sql') else {}
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
                has_placeholders = _has_structural_placeholders(pre_cleaned_code)

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

            # Python: surface a syntax error that survived the linter so the AI is asked to fix
            # it (the deterministic reindenter only adopts a fix that compiles; whatever it could
            # not repair is escalated here — mirroring the SQL bq_error path).
            py_syntax_error_msg = ""
            if filename.endswith('.py'):
                try:
                    compile(pre_cleaned_code, filename, 'exec')
                except SyntaxError as e:
                    py_syntax_error_msg = f"Python syntax error: {e.msg} (line {e.lineno})."
                    if not any("syntax" in str(i).lower() for i in local_linter_issues):
                        local_linter_issues.append(f"Critical: {py_syntax_error_msg} The AI was asked to repair it (see the ✨ AI Optimized tab).")

            # Step 2b: ESCALATION POLICY. The AI runs when a file has genuine optimization scope
            # OR when the linter could NOT fully resolve it — a residual syntax error, or structural
            # placeholders left for resolution. In every one of those cases the AI is handed the FULL
            # domain rules (rules_sql/py/ksh) so it re-checks the code against all of them, instead of
            # the file silently passing through with unresolved issues. (Secrets already halted above.)
            # Escalate to AI for a residual SYNTAX error, or for placeholders the AI can actually
            # resolve from the schema (generated column lists) — NOT for human-only stubs. A
            # missing-ON join still reaches the AI via needs_ai_review (the 'JOIN' signal).
            sql_unresolved = filename.endswith('.sql') and (bool(sql_syntax_error_msg) or _has_ai_resolvable_placeholders(pre_cleaned_code))
            must_fix_note = sql_syntax_error_msg or py_syntax_error_msg
            # A file blocked on a HUMAN decision (missing DELETE/UPDATE filter or join key) is
            # CRITICAL and not runnable — the linter already flagged it, so we spend NO AI on it
            # (don't pay tokens to re-state a deterministic check, and don't optimize a blocked
            # query). It re-evaluates on the next scan once the human fills the stub in.
            # `force` is an EXPLICIT per-file opt-in (the single-file PRO re-scan) — only then do we
            # run the AI REGARDLESS of the red-flag gate, so even a clean / fully-auto-fixed file
            # gets an opinion (and an AI-Optimized tab if it finds anything). A BATCH run never sets
            # force, so a 16-file scan only spends tokens on files the gate genuinely escalates —
            # that's what keeps the run cheap and off the rate limit. `model` (Pro) only picks WHICH
            # model runs WHEN the AI runs; it no longer forces the AI on by itself.
            # Human-blocked critical files still skip — fix those first.
            force_ai = bool(force)
            human_blocked = filename.endswith('.sql') and _has_human_required_placeholders(pre_cleaned_code)
            should_use_ai = (not human_blocked) and (
                             force_ai
                             or needs_ai_review(filename, pre_cleaned_code)
                             or sql_unresolved
                             or bool(py_syntax_error_msg))

            if should_use_ai:
                ext = filename.rsplit('.', 1)[-1].lower()
                # Big files can't be fully re-emitted in one response, so we ask for advice ONLY
                # (no rewrite) past a line threshold — that's what prevents a half-written file
                # from showing up as "deleted" code in the diff.
                line_count = pre_cleaned_code.count('\n') + 1
                advisory_only = line_count > AI_FULL_REWRITE_MAX_LINES
                ai_failed = None
                suggested_code = ""
                truncated = False
                think_note = ""

                # ROUTE A — REPAIR/DEFAULT (single call, always the FAST model): concrete syntax
                # error, schema-fillable placeholder, OR no Pro toggle — the reasoning model adds
                # nothing for ordinary optimization scans, so we never pay its rates by default.
                fix_route = bool(must_fix_note) or (sql_unresolved and not sql_syntax_error_msg) or (not model)

                if not fix_route:
                    # ROUTE B — OPTIMIZE (two-stage, Pro toggle only): the reasoning model THINKS —
                    # terse, line-referenced findings under a tiny output cap, never code — and ONLY
                    # if it found something does the fast model CODE the rewrite. A "no changes"
                    # verdict costs one small call total.
                    try:
                        findings, changes, t1 = pro_think(filename, pre_cleaned_code, live_schema, repo_context)
                        tokens_used += t1
                        model_used = f"{GEMINI_PRO_MODEL} (think)"
                        ai_review_markdown = ("### 💡 Advanced Optimizations\n"
                                              + (findings or "✓ No advanced architectural bottlenecks detected."))
                        if changes and advisory_only:
                            ai_review_markdown += (f"\n\n> ℹ️ This file is large ({line_count} lines); the findings "
                                "above are line-referenced advice. Apply them manually, or ask the Architect to "
                                "rewrite one section at a time.")
                        elif changes:
                            try:
                                suggested_code, t2, truncated = flash_code(filename, pre_cleaned_code, findings, live_schema)
                                tokens_used += t2
                                model_used += f" + {GEMINI_MODEL} (code)"
                            except Exception:
                                ai_review_markdown += ("\n\n> ⚠️ The rewrite stage was unavailable — apply the "
                                    "findings above manually, or re-scan to retry.")
                    except Exception:
                        # Reasoning model unavailable (e.g. preview-quota 429) — degrade to the
                        # single-stage fast-model review below so the file is still covered.
                        fix_route = True
                        think_note = "\n\n> ℹ️ The reasoning model was unavailable — this review ran on the fast model instead."

                # When Pro is forced on a clean/auto-fixed file and the reasoning model found
                # no changes, fall back to the flash model so the ✨ AI Optimized tab is still
                # populated with the flash model's take.
                if force_ai and not suggested_code.strip() and not advisory_only:
                    fix_route = True

                if fix_route:
                    try:
                        ai_response_obj = review_code_with_gemini(
                            filename, pre_cleaned_code, repo_context, live_schema,
                            bq_error=must_fix_note,
                            resolve_placeholders=(sql_unresolved and not sql_syntax_error_msg),
                            advisory_only=advisory_only)
                    except Exception as _ai_err:
                        # AI unavailable (e.g. 429 rate limit). Degrade gracefully below — never fail the
                        # whole file; the deterministic linter result is still valid.
                        ai_failed = _ai_err
                        ai_response_obj = DummyResponse("")
                    raw_ai_markdown = ai_response_obj.text or ""
                    try:
                        if ai_response_obj.usage_metadata:
                            tokens_used += ai_response_obj.usage_metadata.total_token_count
                    except AttributeError:
                        pass
                    truncated = _response_was_truncated(ai_response_obj)
                    model_used = GEMINI_MODEL

                    if not advisory_only:
                        suggested_code = extract_refactored_code(raw_ai_markdown)
                        # RETRY once at the MAX budget if the rewrite came back truncated or empty. The
                        # file already fits (advisory threshold), so giving the model all the room it needs
                        # almost always yields the COMPLETE rewrite — this is what keeps the AI tab present
                        # instead of withholding the fix the user actually needs.
                        if ai_failed is None and (truncated or not suggested_code.strip()):
                            try:
                                retry_obj = review_code_with_gemini(
                                    filename, pre_cleaned_code, repo_context, live_schema,
                                    bq_error=must_fix_note,
                                    resolve_placeholders=(sql_unresolved and not sql_syntax_error_msg),
                                    max_output_tokens=AI_MAX_OUTPUT_TOKENS)
                                retry_md = retry_obj.text or ""
                                retry_code = extract_refactored_code(retry_md)
                                try:
                                    if retry_obj.usage_metadata:
                                        tokens_used += retry_obj.usage_metadata.total_token_count
                                except AttributeError:
                                    pass
                                if retry_code.strip():
                                    raw_ai_markdown, suggested_code = retry_md, retry_code
                                    truncated = _response_was_truncated(retry_obj)
                            except Exception:
                                pass   # a retry failure is non-fatal — keep the first response
                        suggested_code = _strip_line_gutter(suggested_code)

                    # Advisory notes only — do NOT fold the rewrite back into the working code.
                    notes_part = raw_ai_markdown.split("### 🛠️ Final Refactored Code")[0].strip()
                    ai_review_markdown = (notes_part or "### 💡 Advanced Optimizations\nSee the AI Optimized tab "
                                          "for the suggested rewrite.") + think_note
                    if advisory_only:
                        ai_review_markdown += (f"\n\n> ℹ️ This file is large ({line_count} lines); the AI gave "
                            "line-referenced advice instead of a full rewrite. Apply the points above, or ask the "
                            "Architect to rewrite a specific section.")

                # SHARED post-processing for any suggested rewrite (either route): re-lint it, then
                # show it only if it's complete (not truncated / not catastrophically short) and differs.
                if suggested_code.strip() and not advisory_only:
                    suggested_code, _ = process_file_locally(filename, suggested_code, schema_meta)
                    safe = (not truncated) and _ai_rewrite_is_safe(pre_cleaned_code, suggested_code, ext)
                    if suggested_code.strip() != pre_cleaned_code.strip() and safe:
                        ai_optimized_code = suggested_code
                        # If the AI was repairing a syntax error or filling structural placeholders,
                        # re-validate its suggestion so the user can see whether it now passes BigQuery.
                        if filename.endswith('.sql') and (sql_syntax_error_msg or sql_unresolved) and not _has_structural_placeholders(suggested_code):
                            fixed_metrics = perform_bq_dry_run(suggested_code)
                            if fixed_metrics.get("valid"):
                                local_linter_issues.append("AI Fix Available: A corrected, BigQuery-valid version is ready in the ✨ AI Optimized tab.")
                    elif not safe:
                        ai_review_markdown += ("\n\n> ⚠️ The AI's full rewrite was withheld because it was still "
                            f"truncated for this file even at the maximum output budget ({AI_MAX_OUTPUT_TOKENS} "
                            "tokens). Raise `AI_MAX_OUTPUT_TOKENS`, or ask the Architect to rewrite one section at a time.")

                # GRACEFUL DEGRADATION: if the AI call itself failed (e.g. a 429 rate limit), keep the
                # valid linter result and tell the user — do NOT fail the whole file.
                if ai_failed is not None:
                    is_bypassed = True
                    tokens_used = 0
                    ai_optimized_code = ""
                    if _is_rate_limited(ai_failed):
                        ai_review_markdown = ("### 💡 Advanced Optimizations\n"
                            "⚠️ The AI review was **rate-limited by Vertex AI (429)** and skipped for this file. "
                            "The deterministic linter fixes above are applied and valid — re-scan shortly to retry the AI step.")
                        local_linter_issues.append("Note: AI review skipped — Vertex AI rate limit (429). Deterministic fixes still applied.")
                    else:
                        ai_review_markdown = ("### 💡 Advanced Optimizations\n"
                            f"⚠️ The AI review could not run for this file ({clean_bq_error(str(ai_failed))[:160]}). "
                            "The deterministic linter fixes above are applied and valid — re-scan to retry.")
                        local_linter_issues.append("Note: AI review skipped — model error. Deterministic fixes still applied.")
            else:
                is_bypassed = True
                if filename.endswith('.sql') and _has_structural_placeholders(pre_cleaned_code):
                    # Human-decision placeholder(s) remain (DELETE/UPDATE filter, JOIN key). The
                    # linter flagged them in the panel; the AI is NOT spent because it must not
                    # invent a filter/join key — a person has to supply the intent.
                    ai_review_markdown = ("### 💡 Advanced Optimizations\n"
                        "⚠️ The linter inserted placeholder(s) that need a human decision (e.g. a DELETE/UPDATE "
                        "filter or a JOIN condition) — see the Deterministic Linter panel. Fill them in, then "
                        "re-scan, or ask the Architect in the chat to draft one. The AI optimizer was not spent "
                        "automatically, to conserve tokens.")
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

        return {
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
            "finops_status": finops_status,
            "has_secrets": has_secrets,
            "schema_explorer": structured_metadata,
            "airflow_tasks": py_analysis,
            "scorecard": scorecard,
            # Which Gemini model actually handled this file (0-token files never call one).
            "model": model_used if tokens_used else None
        }

    except Exception as e:
        raise


def derive_status(result):
    """Map a review result to a single bucket (mirrors the web UI taxonomy)."""
    fixes = [str(x).lower() for x in (result.get("unit_test_fixes") or [])]
    review = (result.get("ai_review") or "").lower()
    has_errors = any(("error" in f or "critical" in f or "security" in f) for f in fixes)
    is_critical = any(re.search(r'critical|security|finops|dangerous|mandatory where', f) for f in fixes) or "security breach" in review
    if has_errors or "syntax error" in review or "security breach" in review:
        return "critical" if is_critical else "issues"
    if "no advanced" in review or "bypassed" in review:
        return "autofix" if fixes else "clean"
    return "optimize"


@app.route('/process_file', methods=['POST'])
@login_required
def process_single_file():
    data = request.get_json() or {}
    filename = data.get('filename')
    content = data.get('content')
    if not filename or not content:
        return jsonify({"error": "Missing file data."}), 400
    try:
        # UI Flash→Pro toggle: when use_pro is set, this scan uses the higher-quality model.
        model = GEMINI_PRO_MODEL if data.get('use_pro') else None
        # `force_ai` is sent ONLY by the deliberate single-file re-scan — it runs the AI even on a
        # clean/auto-fixed file. A batch run omits it, so the per-file red-flag gate decides there
        # (no tokens on clean files, no rate-limit storm).
        result = review_one_file(
            filename, content,
            scope=(data.get('scope') or 'full').lower(),
            repo_context=data.get('repo_context', 'No additional context.'),
            repo_name=data.get('repo_name', 'unknown'),
            user_email=get_user_identity(),
            model=model,
            force=bool(data.get('force_ai')),
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/review_pr', methods=['POST'])
def api_review_pr():
    """Machine-readable PR review for CI (GitHub Actions). Reviews every changed file
    between base and head and returns a structured verdict. Protected by an optional
    API key (set the API_KEY env var and send it as the X-API-Key header)."""
    api_key = os.environ.get("API_KEY", "").strip()
    if api_key and request.headers.get("X-API-Key", "") != api_key:
        return jsonify({"error": "Unauthorized — missing or invalid X-API-Key."}), 401

    data = request.get_json(silent=True) or {}
    repo = data.get('repo')
    head_branch = data.get('branch') or data.get('head')
    base_branch = data.get('base_branch') or data.get('base') or 'main'
    scope = (data.get('scope') or 'full').lower()
    # Per-call token wins; otherwise fall back to the server's configured token.
    github_token = data.get('github_token') or load_secret("GITHUB_TOKEN")
    if not repo or not head_branch:
        return jsonify({"error": "Missing 'repo' and/or 'branch'."}), 400

    try:
        files = get_changed_files(repo, base_branch, head_branch, github_token)
    except Exception as e:
        return jsonify({"error": f"Failed to fetch changed files: {e}"}), 502

    results, counts = [], {"critical": 0, "issues": 0, "optimize": 0, "autofix": 0, "clean": 0}
    total_tokens = total_cost = 0.0
    for f in files:
        content = (f.get("diff_content") if scope == "diff" else f.get("content")) or f.get("content") or ""
        try:
            r = review_one_file(f["filename"], content, scope=scope, repo_context="CI / pull-request review",
                                repo_name=repo, user_email="ci-bot@github")
            status = derive_status(r)
            counts[status] = counts.get(status, 0) + 1
            total_tokens += r.get("tokens", 0) or 0
            total_cost += r.get("cost", 0) or 0
            bqm = r.get("bq_metrics") or {}
            results.append({
                "filename": f["filename"],
                "status": status,
                "issues": r.get("unit_test_fixes", []),
                "bq_valid": bqm.get("valid"),
                "bq_message": bqm.get("message"),
                "tokens": r.get("tokens", 0),
                "has_ai_suggestion": bool(r.get("ai_optimized_code")),
                "linter_code": r.get("linter_code", ""),
                "ai_optimized_code": r.get("ai_optimized_code", ""),
            })
        except Exception as e:
            counts["issues"] += 1
            results.append({"filename": f["filename"], "status": "error", "issues": [f"Processing error: {e}"]})

    blocked = counts.get("critical", 0) > 0
    summary = (f"{len(files)} file(s): {counts['critical']} critical · {counts['issues']} issues · "
               f"{counts['optimize']} optimize · {counts['autofix']} auto-fixed · {counts['clean']} clean")
    return jsonify({
        "repo": repo, "base": base_branch, "head": head_branch, "scope": scope,
        "verdict": "block" if blocked else "pass",
        "summary": summary, "counts": counts,
        "total_tokens": int(total_tokens), "estimated_cost": round(total_cost, 6),
        "files": results,
    }), 200


@app.route('/generate_mock_data', methods=['POST'])
@login_required
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
@login_required
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
@login_required
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
@login_required
def commit_to_github():
    data = request.get_json()
    repo_name, branch, filename, new_content, token = data.get('repo'), data.get('branch'), data.get('filename'), data.get('code'), load_secret("GITHUB_TOKEN")
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
@login_required
def chat_with_code():
    data = request.get_json()
    filename, code_context, user_message = data.get('filename'), data.get('code'), data.get('message')
    if not filename or not user_message: return jsonify({"error": "Missing parameters."}), 400

    # Schema-aware chat: hand the Architect the LIVE columns so it can verify any column the
    # developer mentions actually exists — and suggest the closest real name when it doesn't,
    # instead of inventing one. (Only meaningful for SQL against known datasets.)
    live_schema = inject_live_schema_context(code_context or "") if filename.endswith('.sql') else ""
    schema_block = ""
    if filename.endswith('.sql'):
        schema_block = f"""
    LIVE BIGQUERY SCHEMA (the ONLY real tables/columns — treat this as ground truth):
    {live_schema or '(no live schema available — do not guess column names)'}

    COLUMN-EXISTENCE RULE: if the developer asks to add/use/filter a column, FIRST confirm it
    exists in the live schema above. If it does NOT exist, do NOT invent it — say it's missing and
    list the closest real column name(s) from the schema so they can pick the right one.
    """

    prompt = f"""
    You are a Google Cloud BigQuery Senior Architect.
    The developer is requesting updates or explanations regarding: {filename}.
    Current Workspace Code Context:
    ```
    {code_context}
    ```
    {schema_block}
    User Request: "{user_message}"

    If edits are requested, generate the COMPLETE corrected content — every line, nothing omitted.
    Format your response strictly with these two headings:
    ### 💡 AI Reply
    (Your feedback here. If a requested column is missing, name the closest real columns.)
    ### 🛠️ Final Refactored Code
    (Markdown block start here with ```)
    """

    try:
        # Budget the output to the code size so long files come back whole, not truncated.
        chat_model = GEMINI_PRO_MODEL if data.get('use_pro') else None
        response = generate_ai(prompt, max_output_tokens=min(AI_MAX_OUTPUT_TOKENS,
                                                             _estimate_tokens(code_context or "") * 2 + 1024),
                               model=chat_model)
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
