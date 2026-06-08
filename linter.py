import os
import re


def _parse_kv(raw):
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
# Real BigQuery dataset name -> ${TEMPLATE_VAR} it should be parameterized to.
# Derived (reversed) from the same SQL_DATASET_MAP the backend uses. Empty disables.
_DATASET_VARS = _parse_kv(os.environ.get("SQL_DATASET_MAP", "AEDW_DB=DB_AEDWD2"))
DATASET_PARAM_MAP = {real: '${' + var + '}' for var, real in _DATASET_VARS.items() if real}
# Audit / batch columns that must always be parameterized to ${UPPER(name)}. Empty disables.
PARAM_COLUMNS = [c.strip() for c in os.environ.get("SQL_PARAM_COLUMNS", "etl_batch_sk").split(',') if c.strip()]


def scan_for_secrets(content):
    """Shift-Left Security: Hardcoded Secrets Scanner."""
    logs = []
    # Key patterns for GCP, AWS, and generic configuration strings
    patterns = {
        "GCP API Key": r'(?i)AIza[0-9A-Za-z-_]{35}',
        "AWS Access Key": r'(?i)AKIA[0-9A-Z]{16}',
        "Generic Password/Secret": r'(?i)(password|secret|token)[\s=:]+[\'"][^\'"]{6,}[\'"]'
    }
    
    for name, pattern in patterns.items():
        if re.search(pattern, content):
            logs.append(f"CRITICAL SECURITY ALERT: Found potential {name} in code. File processing halted.")
            
    return logs

_NUMERIC_TYPES = {'INT64', 'INTEGER', 'INT', 'SMALLINT', 'BIGINT', 'TINYINT', 'BYTEINT',
                  'FLOAT64', 'FLOAT', 'NUMERIC', 'BIGNUMERIC', 'DECIMAL'}
_DATE_TYPES = {'DATE', 'DATETIME', 'TIMESTAMP'}
_KEYWORD_VALS = {'TRUE', 'FALSE', 'NULL', 'CURRENT_DATE', 'CURRENT_TIMESTAMP', 'CURRENT_DATETIME'}
# Words that can appear left of an operator but are NOT column names.
_RESERVED_IDENTS = {
    'and', 'or', 'not', 'true', 'false', 'null', 'between', 'in', 'like', 'is', 'as',
    'case', 'when', 'then', 'else', 'end', 'exists', 'on', 'using', 'where', 'select',
    'from', 'group', 'order', 'by', 'having', 'limit', 'union', 'all', 'distinct',
    'current_date', 'current_timestamp', 'current_datetime', 'extract', 'cast', 'date',
    'datetime', 'timestamp', 'count', 'sum', 'avg', 'min', 'max',
}

_LIT_RE = r"'[^']*'|\"[^\"]*\"|-?\d+(?:\.\d+)?"   # quoted string OR number literal


def _is_number(s):
    return bool(re.fullmatch(r"-?\d+(?:\.\d+)?", s.strip()))


def _is_quoted(v):
    return len(v) >= 2 and v[0] in "'\"" and v[-1] == v[0]


def apply_schema_fixes(content, schema, logs):
    """Deterministic, schema-driven fixes — no AI/tokens needed.

    schema: { 'dataset.table': [ {'name':..., 'type':..., 'mode':...}, ... ] }

    Using the LIVE column datatypes, this normalises comparison literals so the
    query passes BigQuery validation WITHOUT spending any AI tokens:
      - spaced column identifiers      (`customer name`  -> `customer_name`)
      - STRING column vs bare literal  (`name = kaustubh`-> `name = 'kaustubh'`)
      - NUMERIC column vs quoted number(`amount = '100'` -> `amount = 100`)
      - DATE/TIME column vs bare date  (`dt = 2024-01-01`-> `dt = '2024-01-01'`)
    """
    if not schema:
        return content

    col_types = {}            # lower_name -> TYPE
    for cols in schema.values():
        for f in cols:
            name = (f.get('name') or '')
            if name and name.lower() not in col_types:
                col_types[name.lower()] = (f.get('type') or '').upper()
    all_cols = set(col_types.keys())

    # B. Correct spaced column identifiers to the schema's underscored name.
    fixed_names = set()
    for cols in schema.values():
        for f in cols:
            col = (f.get('name') or '')
            if '_' not in col or col.lower() in fixed_names:
                continue
            # `customer_name` -> regex `\bcustomer\s+name\b` (matches a space, never an underscore)
            pat = re.compile(r'\b' + r'\s+'.join(re.escape(p) for p in col.split('_')) + r'\b', re.IGNORECASE)
            content, n = pat.subn(col, content)
            if n:
                logs.append(f"Fix: Corrected column name spacing to '{col}' using live schema.")
                fixed_names.add(col.lower())

    # C. Datatype-aware literal normalisation for `col <op> <value>` comparisons.
    seen_fix = set()

    def _log_once(msg):
        if msg not in seen_fix:
            logs.append(msg)
            seen_fix.add(msg)

    def _fix(m):
        col, op, val = m.group('col'), m.group('op'), m.group('val')
        ctype = col_types.get(col.lower())
        if not ctype:
            return m.group(0)

        quoted = len(val) >= 2 and val[0] in "'\"" and val[-1] == val[0]
        inner = val[1:-1] if quoted else val

        # STRING column: ensure the literal is quoted (skip columns, keywords, numbers).
        if ctype == 'STRING':
            if (not quoted and val.lower() not in all_cols
                    and val.upper() not in _KEYWORD_VALS and not _is_number(val)):
                _log_once(f"Fix: Quoted string literal for STRING column '{col}' using live schema datatype.")
                return f"{col} {op} '{val}'"

        # NUMERIC column: drop quotes around a numeric literal.
        elif ctype in _NUMERIC_TYPES:
            if quoted and _is_number(inner):
                _log_once(f"Fix: Removed quotes around numeric literal for {ctype} column '{col}' using live schema datatype.")
                return f"{col} {op} {inner}"

        # DATE/DATETIME/TIMESTAMP column: quote a bare date literal so it isn't read as arithmetic.
        elif ctype in _DATE_TYPES:
            if not quoted and re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[ T][\d:.+-]+)?", val):
                _log_once(f"Fix: Quoted date literal for {ctype} column '{col}' using live schema datatype.")
                return f"{col} {op} '{val}'"

        return m.group(0)

    # B2. Collapse an accidental space inside a column identifier when it sits directly
    #     before a comparison operator (e.g. `customer name = ...` -> `customer_name = ...`).
    #     Schema-INDEPENDENT: handles the typo even when the column isn't in the live schema,
    #     so the value-quoting / unknown-column passes below can then act on a single identifier.
    #     String literals are masked first so text like `'foo bar = baz'` is never touched.
    def _collapse_spaced(m):
        w1, w2 = m.group(1), m.group(2)
        if w1.lower() in _RESERVED_IDENTS or w2.lower() in _RESERVED_IDENTS:
            return m.group(0)
        _log_once(f"Fix: Collapsed an accidental space inside the column identifier '{w1} {w2}' -> '{w1}_{w2}'.")
        return f"{w1}_{w2}{m.group(3)}"

    _masked = []
    def _mask(m):
        _masked.append(m.group(0))
        return f"\x00{len(_masked) - 1}\x00"
    tmp = re.sub(r"'[^']*'|\"[^\"]*\"", _mask, content)
    tmp = re.sub(r"\b([A-Za-z]+)\s+([A-Za-z]+)(\s*(?:=|!=|<>|>=|<=|>|<))", _collapse_spaced, tmp)
    content = re.sub(r"\x00(\d+)\x00", lambda m: _masked[int(m.group(1))], tmp)

    comparison_re = re.compile(
        r"\b(?P<col>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"(?P<op>=|!=|<>|>=|<=|>|<)\s*"
        r"(?P<val>'[^']*'|\"[^\"]*\"|[A-Za-z0-9_.\-]+)"
    )
    content = comparison_re.sub(_fix, content)

    # D. Datatype normalisation inside `col BETWEEN <v1> AND <v2>` ranges.
    def _fix_between(m):
        col, v1, v2 = m.group('col'), m.group('v1'), m.group('v2')
        ctype = col_types.get(col.lower())
        if not ctype:
            return m.group(0)
        if ctype in _NUMERIC_TYPES:
            i1 = v1[1:-1] if _is_quoted(v1) else v1
            i2 = v2[1:-1] if _is_quoted(v2) else v2
            if (_is_quoted(v1) or _is_quoted(v2)) and _is_number(i1) and _is_number(i2):
                _log_once(f"Fix: Removed quotes around BETWEEN bounds for {ctype} column '{col}' using live schema datatype.")
                return f"{col} BETWEEN {i1} AND {i2}"
        elif ctype in _DATE_TYPES:
            dpat = r"\d{4}-\d{2}-\d{2}(?:[ T][\d:.+-]+)?"
            if (not _is_quoted(v1) and re.fullmatch(dpat, v1)) or (not _is_quoted(v2) and re.fullmatch(dpat, v2)):
                q1 = v1 if _is_quoted(v1) else f"'{v1}'"
                q2 = v2 if _is_quoted(v2) else f"'{v2}'"
                _log_once(f"Fix: Quoted BETWEEN date bounds for {ctype} column '{col}' using live schema datatype.")
                return f"{col} BETWEEN {q1} AND {q2}"
        return m.group(0)

    between_re = re.compile(
        r"\b(?P<col>[A-Za-z_][A-Za-z0-9_]*)\s+BETWEEN\s+"
        r"(?P<v1>'[^']*'|\"[^\"]*\"|[A-Za-z0-9_.\-]+)\s+AND\s+"
        r"(?P<v2>'[^']*'|\"[^\"]*\"|[A-Za-z0-9_.\-]+)",
        re.IGNORECASE,
    )
    content = between_re.sub(_fix_between, content)

    # E. Unknown-column guard (WHERE clause only): a column compared to a literal that
    #    is NOT in the live schema is almost certainly a typo / removed column. Neutralise
    #    the predicate with TRUE (keeps the query valid) and flag it for a human — so the
    #    BigQuery dry-run does not have to fail on an "Unrecognized name" error.
    #    CRITICAL: only run this when we actually fetched real columns. With no live schema
    #    (all_cols empty) we must NOT guess — otherwise every predicate would be neutralised.
    if not all_cols:
        return content

    def _neutralize_unknown(where_body):
        def repl(m):
            col, val = m.group('col'), m.group('val')
            cl = col.lower()
            if cl in all_cols or cl in _RESERVED_IDENTS:
                return m.group(0)
            _log_once(f"Warning: Column '{col}' is not in the live schema for this table — its filter was neutralized (TRUE). Verify the column name.")
            return f"TRUE /* '{col}' not in live schema - verify column name */"
        pred_re = re.compile(
            r"\b(?P<col>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|!=|<>|>=|<=|>|<)\s*(?P<val>" + _LIT_RE + r")"
        )
        return pred_re.sub(repl, where_body)

    where_re = re.compile(
        r"(?is)(\bWHERE\b)(?P<body>.*?)(?=\bGROUP\s+BY\b|\bORDER\s+BY\b|\bHAVING\b|\bLIMIT\b|\bWINDOW\b|\bUNION\b|;|$)"
    )
    content = where_re.sub(lambda m: m.group(1) + _neutralize_unknown(m.group('body')), content)

    return content

def pre_process_sql(filename, content, schema=None):
    logs = []

    # 1. Parameterize hardcoded BigQuery datasets (config-driven, generic — no hardcoded names).
    for real_ds, template in DATASET_PARAM_MAP.items():
        pat = re.compile(r'\b' + re.escape(real_ds) + r'\b', re.IGNORECASE)
        if pat.search(content):
            content = pat.sub(template, content)
            logs.append(f"Fix: Parameterized hardcoded dataset '{real_ds}' to '{template}'.")

    # 2. Convert TIMESTAMP functions to DATETIME functions
    timestamp_pattern = re.compile(r'\bTIMESTAMP\b\s*\(', re.IGNORECASE)
    if timestamp_pattern.search(content):
        content = timestamp_pattern.sub('DATETIME(', content)
        logs.append("Fix: Replaced 'TIMESTAMP()' with 'DATETIME()'.")

    # 3. Parameterize configured audit/batch columns (config-driven, generic).
    for col in PARAM_COLUMNS:
        param = '${' + col.upper() + '}'
        # Assignment form:  <col> = <value>   ->   <col> = ${COL}
        assign_re = re.compile(r'(\b' + re.escape(col) + r'\b\s*=\s*)[^\s,;)]+', re.IGNORECASE)
        content, n1 = assign_re.subn(lambda m: m.group(1) + param, content)
        # SELECT-alias form:  <number> AS <col>   ->   ${COL} AS <col>
        alias_re = re.compile(r'\b\d+\s+AS\s+' + re.escape(col) + r'\b', re.IGNORECASE)
        content, n2 = alias_re.subn(param + ' AS ' + col, content)
        if (n1 + n2) > 0:
            logs.append(f"Fix: Parameterized hardcoded '{col}' occurrences to '{param}'.")
        
    # 4. Merge Multiple INSERTs for VALUES
    merge_pattern = re.compile(r"(INSERT\s+INTO\s+([A-Za-z0-9_$.{}]+)(?:\s*\([^)]+\))?\s+VALUES\s*[\s\S]*?);\s*INSERT\s+INTO\s+\2(?:\s*\([^)]+\))?\s+VALUES", re.IGNORECASE)
    while merge_pattern.search(content):
        content = merge_pattern.sub(r"\1,", content)
        if "Fix: Merged multiple INSERT VALUES statements into a single batch statement." not in logs:
            logs.append("Fix: Merged multiple INSERT VALUES statements into a single batch statement.")

    # 4b. Remove a stray semicolon that splits one statement (a fragment starting with AND/OR).
    content, n_semi = re.subn(r';(\s*)\b(AND|OR)\b', r'\1\2', content, flags=re.IGNORECASE)
    if n_semi:
        logs.append("Fix: Removed a stray semicolon that incorrectly split a boolean/WHERE clause.")

    # 4c. Schema-driven deterministic fixes (column spacing, string-literal quoting).
    content = apply_schema_fixes(content, schema, logs)

    # 5. Process Statement by Statement
    statements = content.split(';')
    new_statements = []
    
    for stmt in statements:
        if not stmt.strip():
            continue
            
        stmt_upper = stmt.upper()
        bypass_pattern = re.compile(r'\bWHERE\s+(TRUE|1\s*=\s*1)\b', re.IGNORECASE)

        # Catch 'SELECT *'
        if re.search(r'\bSELECT\s+\*', stmt_upper):
            logs.append("Warning: 'SELECT *' detected. Columns should be explicitly listed to prevent schema-drift errors.")

        # Catch missing ON in JOINs
        if ' JOIN ' in stmt_upper and ' ON ' not in stmt_upper and 'CROSS JOIN' not in stmt_upper:
            logs.append("Warning: JOIN detected without an 'ON' condition. Verify this is not an accidental Cartesian product.")

        # Missing or Bypassed WHERE in DELETE
        if 'DELETE FROM' in stmt_upper:
            if 'WHERE' not in stmt_upper:
                stmt = stmt + "\nWHERE <MISSING_FILTER_REQUIRED> /* TODO: Add specific condition */"
                logs.append("Critical Fix: Appended mandatory WHERE clause placeholder to a DELETE statement.")
            elif bypass_pattern.search(stmt):
                stmt = bypass_pattern.sub('WHERE <MISSING_FILTER_REQUIRED> /* TODO: Replace global bypass with condition */', stmt)
                logs.append("Critical Fix: Overwrote dangerous global bypass in DELETE statement with safe placeholder.")

        # Missing or Bypassed WHERE in UPDATE
        elif 'UPDATE ' in stmt_upper and 'SET ' in stmt_upper:
            if 'WHERE' not in stmt_upper:
                stmt = stmt + "\nWHERE <MISSING_FILTER_REQUIRED> /* TODO: Add specific condition */"
                logs.append("Critical Fix: Appended mandatory WHERE clause placeholder to an UPDATE statement.")
            elif bypass_pattern.search(stmt):
                stmt = bypass_pattern.sub('WHERE <MISSING_FILTER_REQUIRED> /* TODO: Replace global bypass with condition */', stmt)
                logs.append("Critical Fix: Overwrote dangerous global bypass in UPDATE statement with safe placeholder.")

        # Missing Target Column List in INSERT
        insert_match = re.search(r'(INSERT\s+INTO\s+[A-Za-z0-9_$.{}]+)\s+(SELECT|VALUES)', stmt, re.IGNORECASE)
        if insert_match:
            table_part = insert_match.group(1)
            action_part = insert_match.group(2)
            
            if action_part.upper() == 'SELECT':
                select_to_from = re.search(r'SELECT(.*?)FROM', stmt, re.IGNORECASE | re.DOTALL)
                if select_to_from:
                    cols_raw = select_to_from.group(1)
                    cols = []
                    for col in cols_raw.split(','):
                        col = col.strip()
                        if not col: continue
                        if ' AS ' in col.upper(): col = col.upper().split(' AS ')[-1].strip()
                        else: col = col.split('.')[-1].strip() 
                        col = col.split()[0] 
                        if not col.startswith("'") and not col.isnumeric(): cols.append(col)
                            
                    if cols:
                        col_list_str = " (" + ", ".join(cols) + ")"
                        stmt = stmt[:insert_match.start()] + table_part + col_list_str + " \n" + stmt[insert_match.start() + len(table_part):]
                        if "Fix: Extracted columns from SELECT" not in logs:
                            logs.append("Fix: Extracted columns from SELECT and injected explicit Target Column List.")
                        
            elif action_part.upper() == 'VALUES':
                stmt = stmt[:insert_match.start()] + table_part + " (col1, col2, col3) \n" + stmt[insert_match.start() + len(table_part):]
                logs.append("Fix: Injected placeholder Target Column List (col1, col2...) into INSERT VALUES statement.")

        new_statements.append(stmt)

    content = ';\n'.join(new_statements) + (';' if content.strip().endswith(';') else '')
    return content, logs

def pre_process_ksh(filename, content):
    logs = []
    fixed_lines = []
    lines = content.split('\n')
    
    needs_set_e = "set -e" not in content and "set -o pipefail" not in content

    for idx, line in enumerate(lines, start=1):
        # Apply physical fixes to KSH so the Diff view populates correctly
        if "bq query" in line:
            logs.append(f"Line {idx:03d}: Forbidden raw 'bq query' invocation found. Refactored to wrapper.")
            line = re.sub(r'bq\s+query\s+--nouse_legacy_sql', 'execute_bq_wrapper', line)
            line = re.sub(r'bq\s+query', 'execute_bq_wrapper', line)
            
        if "echo " in line.lower() and any(secret in line.lower() for secret in ["pass", "pwd", "secret", "token"]):
            logs.append(f"Line {idx:03d}: Severe Security Breach. Masked explicit secret.")
            line = re.sub(r'(?i)(password|secret|token|pass|pwd)[\s=:]+[\'"][^\'"]+[\'"]', r'\1="********"', line)
            
        if re.search(r'rm\s+-r[fF]?\s+\$[A-Za-z0-9_]+/?\s*$', line):
            logs.append(f"Line {idx:03d}: Dangerous deletion pattern detected. Wrapped in safety check.")
            var_name = re.search(r'\$([A-Za-z0-9_]+)', line).group(1)
            line = f"if [[ -n \"${var_name}\" ]]; then {line}; fi"

        fixed_lines.append(line)

    if needs_set_e:
        logs.append("Warning: Script lacks strict error handling. Injected 'set -e' and 'set -o pipefail'.")
        # Ensure it is placed directly after the shebang if it exists
        if fixed_lines and fixed_lines[0].startswith("#!"):
            fixed_lines.insert(1, "set -e")
            fixed_lines.insert(2, "set -o pipefail")
        else:
            fixed_lines.insert(0, "set -e")
            fixed_lines.insert(1, "set -o pipefail")

    return '\n'.join(fixed_lines), logs

def pre_process_py(filename, content):
    logs = []
    
    # 1. Fix DAG_NAME suffix if missing
    dag_name_match = re.search(r'DAG_NAME\s*=\s*["\'](.*?)["\']', content)
    if dag_name_match:
        dag_name = dag_name_match.group(1)
        if not dag_name.endswith('_VM'):
            content = re.sub(r'(DAG_NAME\s*=\s*["\'])(.*?)(["\'])', r'\1\2_VM\3', content)
            logs.append("Fix: Automatically appended mandatory '_VM' suffix to DAG_NAME.")

    # 2. Fix 'timedelta' import if missing
    if "timedelta" in content and "import timedelta" not in content and "datetime, timedelta" not in content:
        content = re.sub(r'from datetime import datetime', r'from datetime import datetime, timedelta', content)
        logs.append("Fix: Injected missing 'timedelta' import into datetime module.")

    # 3. Remove 'catchup' from default_args if it exists
    if re.search(r'[\'"]catchup[\'"]\s*:\s*(True|False)\s*,?', content, re.IGNORECASE):
        content = re.sub(r'[ \t]*[\'"]catchup[\'"]\s*:\s*(True|False)\s*,?\n?', '', content, flags=re.IGNORECASE)
        logs.append("Fix: Removed 'catchup' from default_args (parameter belongs in DAG definition, not args).")

    # 4. Inject missing Airflow parameters directly into the DAG() instantiation
    missing_dag_params = []
    
    if "catchup=" not in content.replace(" ", ""):
        missing_dag_params.append("catchup=False")
        logs.append("Fix: Injected 'catchup=False' into DAG definition.")
        
    if "max_active_runs" not in content:
        missing_dag_params.append("max_active_runs=1")
        logs.append("Fix: Injected 'max_active_runs=1' concurrency limit into DAG definition.")
        
    if "tags=" not in content.replace(" ", ""):
        missing_dag_params.append('tags=["interface"]')
        logs.append("Fix: Injected 'tags=[\"interface\"]' array for workspace categorization.")
        
    if missing_dag_params:
        injection_string = ",\n\t\t".join(missing_dag_params) + ",\n\t\t"
        content = re.sub(r'(dag\s*=\s*DAG\s*\()', fr'\1\n\t\t{injection_string}', content, flags=re.IGNORECASE)

    return content, logs

def process_file_locally(filename, content, schema=None):
    security_logs = scan_for_secrets(content)
    if security_logs:
        return content, security_logs

    if filename.endswith('.sql'):
        return pre_process_sql(filename, content, schema)
    elif filename.endswith('.ksh'):
        return pre_process_ksh(filename, content)
    elif filename.endswith('_INTERFACE_VM.py') or filename.endswith('.py'):
        return pre_process_py(filename, content)
    
    return content, ["Unsupported extension file passed into deterministic parsing module."]
