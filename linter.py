import os
import re

# Editable rule registry (linter_rules.json). Drives every finding's message text,
# its on/off toggle, and the shared settings below — so rules can be edited/added
# from the JSON without touching this file. The detection/transform LOGIC stays here.
from rules_engine import RULES

# Optional: use the sqlglot parser for robust, comment/string-aware SQL handling.
# Everything degrades gracefully to regex if sqlglot isn't installed.
try:
    import sqlglot
    from sqlglot.tokens import TokenType as _SgTokenType
    _HAS_SQLGLOT = True
except Exception:
    _HAS_SQLGLOT = False


def split_sql_statements(content):
    """Split SQL into statements on TOP-LEVEL semicolons, ignoring any ';' that sits
    inside a string literal or a comment — and preserving each statement's ORIGINAL text.
    Uses the sqlglot tokenizer when available; falls back to a naive split otherwise."""
    if _HAS_SQLGLOT and content:
        try:
            parts, start = [], 0
            for tok in sqlglot.tokenize(content):
                if tok.token_type == _SgTokenType.SEMICOLON:
                    parts.append(content[start:tok.start])
                    start = tok.end + 1
            parts.append(content[start:])
            return parts
        except Exception:
            pass
    return content.split(';')


def validate_sql_syntax(sql, template_vars=None):
    """Best-effort, FREE syntax pre-check via sqlglot (no BigQuery round-trip).
    Returns '' if it looks fine (or can't be checked confidently), else a short error.
    Skips anything still containing template placeholders so we never false-flag them."""
    if not (_HAS_SQLGLOT and sql and sql.strip()):
        return ""
    probe = sql
    for k, v in (template_vars or {}).items():
        probe = probe.replace('${' + k + '}', str(v))
    # Don't try to parse code that still has unresolved placeholders.
    if '${' in probe or '<' in probe and '>' in probe:
        return ""
    try:
        sqlglot.parse(probe, read='bigquery')
        return ""
    except Exception as e:
        return str(e).splitlines()[0] if str(e) else ""


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
# Single source of truth for the ${TEMPLATE_VAR}=RealDataset convention. main.py imports
# this same default so the parameterizer (linter) and the resolver (backend) can NEVER drift
# — drift is what makes a ${VAR} the linter produced fail to resolve to a real BQ dataset.
DEFAULT_SQL_DATASET_MAP = "AEDW_DB=DB_AEDWD2,STGPARTN_DB=DB_STG2PARTND2,SRC_DB=DB_SRCD2"
# Real BigQuery dataset name -> ${TEMPLATE_VAR} it should be parameterized to.
# Derived (reversed) from the same SQL_DATASET_MAP the backend uses. Empty disables.
# Precedence (handled by RULES.setting): env var SQL_DATASET_MAP > registry value > default above.
_DATASET_VARS = _parse_kv(RULES.setting("sql_dataset_map", DEFAULT_SQL_DATASET_MAP))
DATASET_PARAM_MAP = {real: '${' + var + '}' for var, real in _DATASET_VARS.items() if real}
# Audit / batch columns that must always be parameterized to ${UPPER(name)}. Empty disables.
PARAM_COLUMNS = [c.strip() for c in RULES.setting("sql_param_columns", "etl_batch_sk").split(',') if c.strip()]


def scan_for_secrets(content):
    """Shift-Left Security: Hardcoded Secrets Scanner.
    Patterns and the alert message are editable in linter_rules.json
    (secret_patterns block + the 'secret-found' rule)."""
    logs = []
    if not RULES.on("secret-found"):
        return logs
    # Key patterns for GCP, AWS, and generic configuration strings (registry-driven,
    # with a hardcoded fallback in rules_engine so security never silently disappears).
    for name, pattern in RULES.secret_patterns().items():
        if re.search(pattern, content):
            logs.append(RULES.msg("secret-found", name=name))

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
    # clause/statement keywords that can sit directly left of a `<col> <op>` and must never be
    # glued onto the column (e.g. `SET status =` must NOT become `SET_status =`).
    'set', 'update', 'qualify', 'values', 'into', 'join', 'inner', 'left', 'right',
    'outer', 'full', 'cross', 'partition', 'over', 'asc', 'desc', 'insert', 'delete',
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
            if not RULES.on("schema-col-spacing"):
                continue
            # `customer_name` -> regex `\bcustomer\s+name\b` (matches a space, never an underscore)
            pat = re.compile(r'\b' + r'\s+'.join(re.escape(p) for p in col.split('_')) + r'\b', re.IGNORECASE)
            content, n = pat.subn(col, content)
            if n:
                logs.append(RULES.msg("schema-col-spacing", col=col))
                fixed_names.add(col.lower())

    # C. Datatype-aware literal normalisation for `col <op> <value>` comparisons.
    seen_fix = set()

    def _log_once(msg):
        if msg not in seen_fix:
            logs.append(msg)
            seen_fix.add(msg)

    def _fix(m):
        # `ref` preserves an optional table-alias prefix (HC.CLM_TYPE); `col` is the bare
        # name used for the schema datatype lookup. ALL rewrites keep `ref` so we never drop
        # the alias (e.g. `a.amount = '100'` must stay `a.amount = 100`, not `amount = 100`).
        ref, col, op, val = m.group('ref'), m.group('col'), m.group('op'), m.group('val')
        ctype = col_types.get(col.lower())
        if not ctype:
            return m.group(0)

        quoted = len(val) >= 2 and val[0] in "'\"" and val[-1] == val[0]
        inner = val[1:-1] if quoted else val

        # Skip values that look like qualified column refs (TABLE.COLUMN) — not literals.
        if not quoted and '.' in val:
            return m.group(0)

        # STRING column: ensure a bare literal is quoted (skip columns, keywords, numbers).
        # NOTE: case-insensitive UPPER(TRIM()) wrapping is a SEPARATE, filter-scoped pass
        # (_wrap_string_filters) so we never wrap a SET/SELECT/INSERT target by mistake.
        if ctype == 'STRING':
            if (RULES.on("schema-string-quote") and not quoted and val.lower() not in all_cols
                    and val.upper() not in _KEYWORD_VALS and not _is_number(val)):
                _log_once(RULES.msg("schema-string-quote", col=col))
                return f"{ref} {op} '{val}'"

        # NUMERIC column: drop quotes around a numeric literal.
        elif ctype in _NUMERIC_TYPES:
            if RULES.on("schema-numeric-unquote") and quoted and _is_number(inner):
                _log_once(RULES.msg("schema-numeric-unquote", ctype=ctype, col=col))
                return f"{ref} {op} {inner}"

        # DATE/DATETIME/TIMESTAMP column: quote a bare date literal so it isn't read as arithmetic.
        elif ctype in _DATE_TYPES:
            if RULES.on("schema-date-quote") and not quoted and re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[ T][\d:.+-]+)?", val):
                _log_once(RULES.msg("schema-date-quote", ctype=ctype, col=col))
                return f"{ref} {op} '{val}'"

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
        if not RULES.on("schema-collapse-spaced"):
            return m.group(0)
        _log_once(RULES.msg("schema-collapse-spaced", w1=w1, w2=w2))
        return f"{w1}_{w2}{m.group(3)}"

    _masked = []
    def _mask(m):
        _masked.append(m.group(0))
        return f"\x00{len(_masked) - 1}\x00"
    tmp = re.sub(r"'[^']*'|\"[^\"]*\"", _mask, content)
    tmp = re.sub(r"\b([A-Za-z]+)\s+([A-Za-z]+)(\s*(?:=|!=|<>|>=|<=|>|<))", _collapse_spaced, tmp)
    content = re.sub(r"\x00(\d+)\x00", lambda m: _masked[int(m.group(1))], tmp)

    comparison_re = re.compile(
        r"\b(?P<ref>(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?P<col>[A-Za-z_][A-Za-z0-9_]*))\s*"
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
            if (RULES.on("schema-between-numeric") and (_is_quoted(v1) or _is_quoted(v2))
                    and _is_number(i1) and _is_number(i2)):
                _log_once(RULES.msg("schema-between-numeric", ctype=ctype, col=col))
                return f"{col} BETWEEN {i1} AND {i2}"
        elif ctype in _DATE_TYPES:
            dpat = r"\d{4}-\d{2}-\d{2}(?:[ T][\d:.+-]+)?"
            if RULES.on("schema-between-date") and ((not _is_quoted(v1) and re.fullmatch(dpat, v1)) or (not _is_quoted(v2) and re.fullmatch(dpat, v2))):
                q1 = v1 if _is_quoted(v1) else f"'{v1}'"
                q2 = v2 if _is_quoted(v2) else f"'{v2}'"
                _log_once(RULES.msg("schema-between-date", ctype=ctype, col=col))
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
            if not RULES.on("schema-unknown-col"):
                return m.group(0)
            _log_once(RULES.msg("schema-unknown-col", col=col))
            return f"TRUE /* '{col}' not in live schema - verify column name */"
        pred_re = re.compile(
            r"\b(?P<col>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|!=|<>|>=|<=|>|<)\s*(?P<val>" + _LIT_RE + r")"
        )
        return pred_re.sub(repl, where_body)

    where_re = re.compile(
        r"(?is)(\bWHERE\b)(?P<body>.*?)(?=\bGROUP\s+BY\b|\bORDER\s+BY\b|\bHAVING\b|\bLIMIT\b|\bWINDOW\b|\bUNION\b|;|$)"
    )
    content = where_re.sub(lambda m: m.group(1) + _neutralize_unknown(m.group('body')), content)

    # F. Case-insensitive STRING filters. Wrap a STRING column that is compared to a quoted
    #    literal as `UPPER(TRIM(<ref>)) <op> UPPER(<lit>)` — but ONLY when the predicate follows
    #    a FILTER keyword (WHERE/AND/OR/ON/HAVING/QUALIFY). That guard keeps us out of SET/SELECT/
    #    INSERT targets (where `SET UPPER(TRIM(col)) = ...` would be invalid), and the table alias
    #    is kept INSIDE the wrap (UPPER(TRIM(HC.CLM_TYPE)), never HC.UPPER(TRIM(CLM_TYPE))).
    def _wrap_string_filter(m):
        kw, ref, op, val = m.group('kw'), m.group('ref'), m.group('op'), m.group('val')
        if col_types.get(ref.split('.')[-1].lower()) != 'STRING':
            return m.group(0)
        if not RULES.on("schema-string-filter-wrap"):
            return m.group(0)
        _log_once(RULES.msg("schema-string-filter-wrap", ref=ref))
        return f"{kw}UPPER(TRIM({ref})) {op} UPPER({val})"

    filter_pred_re = re.compile(
        r"(?P<kw>\b(?:WHERE|AND|OR|ON|HAVING|QUALIFY)\s+)"
        r"(?P<ref>(?:[A-Za-z_][A-Za-z0-9_]*\.)?[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"(?P<op>=|!=|<>)\s*"
        r"(?P<val>'[^']*'|\"[^\"]*\")",
        re.IGNORECASE,
    )
    content = filter_pred_re.sub(_wrap_string_filter, content)

    return content

# Environment path segments that should never be hardcoded (rules_sql.txt: "/load/dev2/" ->
# "/load/${env}/"). Config-driven; matched only as a COMPLETE path segment (slash on both sides),
# so '/product/' or '/devops/' are never touched.
ENV_PATH_SEGMENTS = [s.strip() for s in RULES.setting(
    "env_path_segments", "dev,dev1,dev2,qa,uat,stg,stage,prd,prod").split(',') if s.strip()]
_ENV_PATH_RE = re.compile(r'/(' + '|'.join(re.escape(s) for s in ENV_PATH_SEGMENTS) + r')(?=/)',
                          re.IGNORECASE)


def _mask_sql_strings(content):
    """Mask quoted literals so structural fixes can never touch text inside strings.
    Returns (masked_content, restore_fn)."""
    masked = []
    def _m(m):
        masked.append(m.group(0))
        return f"\x00{len(masked) - 1}\x00"
    tmp = re.sub(r"'[^']*'|\"[^\"]*\"", _m, content)
    return tmp, lambda s: re.sub(r"\x00(\d+)\x00", lambda m: masked[int(m.group(1))], s)


def expand_select_star(content, schema, logs):
    """Replace `SELECT *` with the explicit column list from the LIVE schema — but ONLY for a
    single-table SELECT (the FROM is one known table, no JOIN or comma-list). Multi-table
    `SELECT *` is left alone (and still flagged) because the column origin is ambiguous.
    Deterministic, no AI/tokens.

    schema: { 'dataset.table': [ {'name':..., 'type':..., 'mode':...}, ... ] }
    """
    if not schema:
        return content

    def _norm(s):
        return s.replace('${', '').replace('}', '').strip().lower()

    tbl_cols = {}   # normalized 'dataset.table' -> ordered [column names]
    for key, cols in schema.items():
        names = [c.get('name') for c in cols if c.get('name')]
        if names:
            tbl_cols[_norm(key)] = names
    if not tbl_cols:
        return content

    # Match `SELECT * FROM <table> [alias]` where what follows the table is a clause boundary
    # (a JOIN or a comma would mean multiple tables → the lookahead deliberately excludes them).
    star_re = re.compile(
        r'\bSELECT\s+\*\s+FROM\s+'
        r'(?P<table>\$\{?\w+\}?\.\w+|\w+\.\w+|\w+)'
        r'(?:\s+(?:AS\s+)?(?P<alias>\w+))?'
        r'(?=\s*(?:\)|;|WHERE\b|QUALIFY\b|GROUP\b|ORDER\b|LIMIT\b|HAVING\b|UNION\b|EXCEPT\b|INTERSECT\b|ON\b|\Z))',
        re.IGNORECASE)
    _KW = {'where', 'qualify', 'group', 'order', 'limit', 'having', 'union', 'except',
           'intersect', 'on', 'join', 'inner', 'left', 'right', 'full', 'cross', 'using'}

    def _repl(m):
        table, alias = m.group('table'), m.group('alias')
        if alias and alias.lower() in _KW:
            alias = None
        cols = tbl_cols.get(_norm(table))
        if not cols:
            return m.group(0)   # table not in live schema → leave '*' (warning still fires)
        prefix = (alias + '.') if alias else ''
        col_list = ', '.join(prefix + c for c in cols)
        logs.append(f"Fix: Expanded 'SELECT *' to {len(cols)} explicit column(s) from live schema for {table}.")
        return f'SELECT {col_list} FROM {table}' + (f' {alias}' if alias else '')

    return star_re.sub(_repl, content)


def pre_process_sql(filename, content, schema=None):
    logs = []

    # 0. Structural typo fixes that need string-masking so literals are never altered.
    tmp, _restore = _mask_sql_strings(content)

    # 0a. NULL comparisons: `col = NULL` is always-false in SQL — the intent is IS NULL.
    def _null_cmp(m):
        ref, op = m.group(1), m.group(2)
        return f"{ref} IS NULL" if op == '=' else f"{ref} IS NOT NULL"
    if RULES.on("sql-null-cmp"):
        tmp, n_null = re.subn(r'\b([A-Za-z_][\w.]*)\s*(!=|<>|(?<![<>!=])=)\s*NULL\b', _null_cmp, tmp, flags=re.IGNORECASE)
        if n_null:
            logs.append(RULES.msg("sql-null-cmp", n=n_null))

    # 0b. Doubled commas (`a,, b`) and trailing commas before FROM / a closing paren.
    if RULES.on("sql-doubled-comma"):
        tmp, n_dc = re.subn(r',\s*,', ',', tmp)
        if n_dc:
            logs.append(RULES.msg("sql-doubled-comma"))
    if RULES.on("sql-trailing-comma-from"):
        tmp, n_tf = re.subn(r',(\s*)(FROM\b)', r'\1\2', tmp, flags=re.IGNORECASE)
        if n_tf:
            logs.append(RULES.msg("sql-trailing-comma-from"))
    if RULES.on("sql-trailing-comma-paren"):
        tmp, n_tp = re.subn(r',(\s*)\)', r'\1)', tmp)
        if n_tp:
            logs.append(RULES.msg("sql-trailing-comma-paren"))

    content = _restore(tmp)

    # 0c. Hardcoded environment path segments -> ${env} (rules_sql convention). Runs on the
    #     RESTORED content because in SQL these paths live INSIDE string literals.
    if RULES.on("sql-env-path"):
        content, n_env = _ENV_PATH_RE.subn('/${env}', content)
        if n_env:
            logs.append(RULES.msg("sql-env-path"))

    # 0d. Unbalanced single quote — unfixable deterministically, but flag it up front so the
    #     user sees the cause even when the BQ dry-run is unavailable. ('' escapes masked first.)
    if RULES.on("sql-unbalanced-quote") and content.replace("''", "").count("'") % 2 == 1:
        logs.append(RULES.msg("sql-unbalanced-quote"))

    # 1. Parameterize hardcoded BigQuery datasets (config-driven, generic — no hardcoded names).
    if RULES.on("sql-dataset-param"):
        for real_ds, template in DATASET_PARAM_MAP.items():
            pat = re.compile(r'\b' + re.escape(real_ds) + r'\b', re.IGNORECASE)
            if pat.search(content):
                content = pat.sub(template, content)
                logs.append(RULES.msg("sql-dataset-param", real_ds=real_ds, template=template))

    # 2. Convert TIMESTAMP functions to DATETIME functions
    if RULES.on("sql-timestamp-to-datetime"):
        timestamp_pattern = re.compile(r'\bTIMESTAMP\b\s*\(', re.IGNORECASE)
        if timestamp_pattern.search(content):
            content = timestamp_pattern.sub('DATETIME(', content)
            logs.append(RULES.msg("sql-timestamp-to-datetime"))

    # 3. Parameterize configured audit/batch columns (config-driven, generic).
    #    IMPORTANT: only count/log a change when the value is NOT ALREADY the parameter — otherwise
    #    a script that already uses ${COL} would be reported as "fixed" when nothing actually changed.
    for col in PARAM_COLUMNS:
        param = '${' + col.upper() + '}'
        # Fix typo: col-<number> (minus used instead of equals) -> col = ${COL}
        if RULES.on("sql-minus-typo"):
            minus_typo_re = re.compile(r'\b' + re.escape(col) + r'\s*-\s*\d+', re.IGNORECASE)
            content, n_minus = minus_typo_re.subn(col + ' = ' + param, content)
            if n_minus:
                logs.append(RULES.msg("sql-minus-typo", col=col, param=param))

        if RULES.on("sql-param-columns"):
            real_changes = [0]
            # Assignment form:  <col> = <value>  ->  <col> = ${COL}  (skip if <value> is already ${COL})
            def _assign(m, _p=param, _r=real_changes):
                prefix, value = m.group(1), m.group(2)
                if value == _p:
                    return m.group(0)            # already parameterized — leave it, don't count
                _r[0] += 1
                return prefix + _p
            assign_re = re.compile(r'(\b' + re.escape(col) + r'\b\s*=\s*)([^\s,;)]+)', re.IGNORECASE)
            content = assign_re.sub(_assign, content)
            # SELECT-alias form:  <number> AS <col>  ->  ${COL} AS <col>
            def _alias(m, _p=param, _col=col, _r=real_changes):
                _r[0] += 1
                return _p + ' AS ' + _col
            alias_re = re.compile(r'\b\d+\s+AS\s+' + re.escape(col) + r'\b', re.IGNORECASE)
            content = alias_re.sub(_alias, content)

            if real_changes[0] > 0:
                logs.append(RULES.msg("sql-param-columns", col=col, param=param))
        
    # 4. Merge Multiple INSERTs for VALUES — into the same table. The separating ';' is
    #    OPTIONAL ([;\s]*): a user who forgot the semicolon between two same-table INSERTs
    #    still gets them collapsed into one valid batch statement (a row-comma) instead of
    #    leaving an unparseable `...) INSERT INTO ...` boundary behind.
    if RULES.on("sql-merge-inserts"):
        merge_pattern = re.compile(r"(INSERT\s+INTO\s+([A-Za-z0-9_$.{}]+)(?:\s*\([^)]+\))?\s+VALUES\s*[\s\S]*?\))[;\s]*INSERT\s+INTO\s+\2(?:\s*\([^)]+\))?\s+VALUES", re.IGNORECASE)
        _merge_msg = RULES.msg("sql-merge-inserts")
        while merge_pattern.search(content):
            content = merge_pattern.sub(r"\1,", content)
            if _merge_msg not in logs:
                logs.append(_merge_msg)

    # 4b. Remove a stray semicolon that splits one statement (a fragment starting with AND/OR).
    if RULES.on("sql-stray-semicolon"):
        content, n_semi = re.subn(r';(\s*)\b(AND|OR)\b', r'\1\2', content, flags=re.IGNORECASE)
        if n_semi:
            logs.append(RULES.msg("sql-stray-semicolon"))

    # 4c. Schema-driven deterministic fixes (column spacing, string-literal quoting).
    content = apply_schema_fixes(content, schema, logs)
    # Expand single-table `SELECT *` into explicit columns from the live schema (before the
    # per-statement warning below — a successful expansion leaves no '*' to flag).
    if RULES.on("sql-select-star"):
        content = expand_select_star(content, schema, logs)

    # 5. Process Statement by Statement (parser-based split: ignores ';' in strings/comments)
    statements = split_sql_statements(content)
    new_statements = []
    
    for stmt in statements:
        if not stmt.strip():
            continue
            
        stmt_upper = stmt.upper()
        bypass_pattern = re.compile(r'\bWHERE\s+(TRUE|1\s*=\s*1)\b', re.IGNORECASE)

        # Catch 'SELECT *'
        if RULES.on("sql-select-star") and re.search(r'\bSELECT\s+\*', stmt_upper):
            logs.append(RULES.msg("sql-select-star"))

        # Catch missing ON/USING in JOINs — use word-boundary regex so ON on its own line
        # (e.g. after a closing paren) or USING keyword are both recognised correctly.
        if (RULES.on("sql-join-no-on") and ' JOIN ' in stmt_upper
                and not re.search(r'\b(?:ON|USING)\b', stmt_upper) and 'CROSS JOIN' not in stmt_upper):
            logs.append(RULES.msg("sql-join-no-on"))

        # Missing or Bypassed WHERE in DELETE
        if 'DELETE FROM' in stmt_upper:
            if 'WHERE' not in stmt_upper and RULES.on("sql-delete-no-where"):
                stmt = stmt + "\nWHERE <MISSING_FILTER_REQUIRED> /* TODO: Add specific condition */"
                logs.append(RULES.msg("sql-delete-no-where"))
            elif bypass_pattern.search(stmt) and RULES.on("sql-delete-bypass"):
                stmt = bypass_pattern.sub('WHERE <MISSING_FILTER_REQUIRED> /* TODO: Replace global bypass with condition */', stmt)
                logs.append(RULES.msg("sql-delete-bypass"))

        # Missing or Bypassed WHERE in UPDATE
        elif 'UPDATE ' in stmt_upper and 'SET ' in stmt_upper:
            if 'WHERE' not in stmt_upper and RULES.on("sql-update-no-where"):
                stmt = stmt + "\nWHERE <MISSING_FILTER_REQUIRED> /* TODO: Add specific condition */"
                logs.append(RULES.msg("sql-update-no-where"))
            elif bypass_pattern.search(stmt) and RULES.on("sql-update-bypass"):
                stmt = bypass_pattern.sub('WHERE <MISSING_FILTER_REQUIRED> /* TODO: Replace global bypass with condition */', stmt)
                logs.append(RULES.msg("sql-update-bypass"))

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
                            
                    if cols and RULES.on("sql-insert-select-cols"):
                        col_list_str = " (" + ", ".join(cols) + ")"
                        stmt = stmt[:insert_match.start()] + table_part + col_list_str + " \n" + stmt[insert_match.start() + len(table_part):]
                        # NOTE: this membership check compares against a SHORTER substring than the
                        # full appended message, so it never matches — kept verbatim to preserve behavior.
                        if "Fix: Extracted columns from SELECT" not in logs:
                            logs.append(RULES.msg("sql-insert-select-cols"))
                        
            elif action_part.upper() == 'VALUES':
                # Count columns from the first VALUES row — handles nested parens like CURRENT_DATE().
                val_count = 0
                vm = re.search(r'VALUES\s*\(', stmt, re.IGNORECASE)
                if vm:
                    depth, i, top_commas = 0, vm.end() - 1, 0
                    while i < len(stmt):
                        c = stmt[i]
                        if c == '(':
                            depth += 1
                        elif c == ')':
                            depth -= 1
                            if depth == 0:
                                break
                        elif c == ',' and depth == 1:
                            top_commas += 1
                        i += 1
                    val_count = top_commas + 1
                if RULES.on("sql-insert-values-cols"):
                    col_list = ', '.join(f'col{i+1}' for i in range(val_count)) if val_count else 'col1, col2, col3'
                    stmt = stmt[:insert_match.start()] + table_part + f" ({col_list}) /* TODO: replace placeholder names — list the {val_count or 3} real target columns in order */ \n" + stmt[insert_match.start() + len(table_part):]
                    # Name the target table so multiple INSERTs in one file produce DISTINCT messages
                    # (instead of the same "Injected placeholder…" line repeated for each statement).
                    table_name = re.sub(r'(?i)^\s*INSERT\s+INTO\s+', '', table_part).strip()
                    logs.append(RULES.msg("sql-insert-values-cols", val_count=(val_count or 3), table_name=table_name))

        new_statements.append(stmt)

    content = ';\n'.join(new_statements) + (';' if content.strip().endswith(';') else '')

    # 6. Terminate the final statement. Find the last CODE line (skip blank/comment-only lines);
    #    if it doesn't end with ';', append one — a missing terminator is the most common reason a
    #    multi-statement script fails to parse when another statement is added later.
    def _code_only(line):
        # Strip a trailing '-- comment', but only when the '--' is OUTSIDE a string literal.
        idx = 0
        while True:
            pos = line.find('--', idx)
            if pos == -1:
                return line.rstrip()
            if line[:pos].count("'") % 2 == 0:
                return line[:pos].rstrip()
            idx = pos + 2

    lines = content.split('\n')
    for i in range(len(lines) - 1, -1, -1):
        code_part = _code_only(lines[i])
        if code_part.strip():
            if not code_part.endswith(';') and RULES.on("sql-final-semicolon"):
                lines[i] = code_part + ';' + lines[i][len(code_part):]
                content = '\n'.join(lines)
                logs.append(RULES.msg("sql-final-semicolon"))
            break

    # User-defined pattern rules from linter_rules.json (custom_rules, lang "sql").
    content = RULES.run_custom("sql", content, logs)

    return content, logs

def pre_process_ksh(filename, content):
    logs = []
    fixed_lines = []
    lines = content.split('\n')

    needs_set_e = "set -e" not in content and "set -o pipefail" not in content

    # Missing shebang: insert the standard interpreter line so the script is directly executable
    # (and so the strict-mode injection below lands right after it).
    if lines and not lines[0].startswith("#!") and RULES.on("ksh-shebang"):
        lines.insert(0, "#!/bin/ksh")
        logs.append(RULES.msg("ksh-shebang"))

    env_path_fixed = False
    for idx, line in enumerate(lines, start=1):
        # Hardcoded environment path segments (e.g. /load/dev2/) -> parameterized /${env}/ ,
        # matching the SQL convention from rules_sql.txt. Skipped on comment lines.
        if RULES.on("ksh-env-path") and not line.lstrip().startswith('#') and _ENV_PATH_RE.search(line):
            line = _ENV_PATH_RE.sub('/${env}', line)
            if not env_path_fixed:
                logs.append(RULES.msg("ksh-env-path"))
                env_path_fixed = True

        # Apply physical fixes to KSH so the Diff view populates correctly
        if RULES.on("ksh-raw-bq-query") and "bq query" in line:
            logs.append(RULES.msg("ksh-raw-bq-query", line=idx))
            line = re.sub(r'bq\s+query\s+--nouse_legacy_sql', 'execute_bq_wrapper', line)
            line = re.sub(r'bq\s+query', 'execute_bq_wrapper', line)

        if (RULES.on("ksh-secret-echo") and "echo " in line.lower()
                and any(secret in line.lower() for secret in ["pass", "pwd", "secret", "token"])):
            logs.append(RULES.msg("ksh-secret-echo", line=idx))
            line = re.sub(r'(?i)(password|secret|token|pass|pwd)[\s=:]+[\'"][^\'"]+[\'"]', r'\1="********"', line)

        if RULES.on("ksh-dangerous-rm") and re.search(r'rm\s+-r[fF]?\s+\$[A-Za-z0-9_]+/?\s*$', line):
            logs.append(RULES.msg("ksh-dangerous-rm", line=idx))
            var_name = re.search(r'\$([A-Za-z0-9_]+)', line).group(1)
            line = f"if [[ -n \"${var_name}\" ]]; then {line}; fi"

        fixed_lines.append(line)

    if needs_set_e and RULES.on("ksh-strict-mode"):
        logs.append(RULES.msg("ksh-strict-mode"))
        # Ensure it is placed directly after the shebang if it exists
        if fixed_lines and fixed_lines[0].startswith("#!"):
            fixed_lines.insert(1, "set -e")
            fixed_lines.insert(2, "set -o pipefail")
        else:
            fixed_lines.insert(0, "set -e")
            fixed_lines.insert(1, "set -o pipefail")

    result = '\n'.join(fixed_lines)

    # Rules gap (rules_ksh.txt): every BQ execution should be followed by a Return-Code check.
    # Deterministically verifiable: the wrapper is called but '$?' / RC= is never inspected.
    if RULES.on("ksh-rc-check") and 'execute_bq_wrapper' in result and not re.search(r'\$\?|RC\s*=', result):
        logs.append(RULES.msg("ksh-rc-check"))

    # User-defined pattern rules from linter_rules.json (custom_rules, lang "ksh").
    result = RULES.run_custom("ksh", result, logs)

    return result, logs

def _scan_py_line(line, in_triple, paren):
    """Advance the (in_triple_delimiter, paren_depth) state across ONE physical line,
    ignoring '#' comments and the contents of '...'/\"...\" and triple-quoted strings.
    Returns the state AFTER the line so callers know whether the next line begins inside
    a string / bracketed continuation (i.e. is NOT a new logical statement)."""
    i, n = 0, len(line)
    while i < n:
        if in_triple:
            idx = line.find(in_triple, i)
            if idx == -1:
                return in_triple, paren            # rest of line is still inside the string
            i, in_triple = idx + 3, None
            continue
        c = line[i]
        if c == '#':
            break                                  # comment runs to end of line
        if c in ('"', "'"):
            if line[i:i + 3] in ('"""', "'''"):
                in_triple = line[i:i + 3]
                i += 3
                continue
            q, i = c, i + 1                         # single-line quoted string
            while i < n:
                if line[i] == '\\':
                    i += 2
                    continue
                if line[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c in '([{':
            paren += 1
        elif c in ')]}':
            paren = max(0, paren - 1)
        i += 1
    return in_triple, paren


def _strip_inline_comment(s):
    """Drop a trailing '# ...' comment that sits OUTSIDE any string, so a compound-header
    check (does the line end with ':'?) isn't fooled by a '#' inside a literal."""
    in_triple, i, n = None, 0, len(s)
    while i < n:
        if in_triple:
            idx = s.find(in_triple, i)
            if idx == -1:
                return s
            i, in_triple = idx + 3, None
            continue
        c = s[i]
        if c == '#':
            return s[:i]
        if c in ('"', "'"):
            if s[i:i + 3] in ('"""', "'''"):
                in_triple = s[i:i + 3]
                i += 3
                continue
            q, i = c, i + 1
            while i < n:
                if s[i] == '\\':
                    i += 2
                    continue
                if s[i] == q:
                    i += 1
                    break
                i += 1
            continue
        i += 1
    return s


def _normalize_py_indentation(content):
    """Re-align the indentation of STATEMENT-START lines to their block depth.

    Only the first physical line of each logical statement is touched; continuation
    lines (inside parens/brackets or a triple-quoted string) are left BYTE-for-BYTE
    intact — so a `script_path=\"\"\"...ksh...\"\"\"` body or bracketed argument list is
    never corrupted. Block depth is tracked from ':'-terminated headers, and dedents are
    inferred from the ORIGINAL relative indentation (internally consistent even when the
    whole file is shifted). The caller only KEEPS this output if it actually compiles."""
    lines = content.split('\n')
    states, in_triple, paren = [], None, 0
    for ln in lines:
        states.append((in_triple, paren))
        in_triple, paren = _scan_py_line(ln, in_triple, paren)

    stmt_idxs = [i for i, ln in enumerate(lines)
                 if states[i] == (None, 0) and ln.strip() and not ln.lstrip().startswith('#')]

    INDENT = 4
    stack = [{"body": 0, "opener_orig": -1}]       # module level
    out = list(lines)
    for k, idx in enumerate(stmt_idxs):
        ln = lines[idx]
        stripped = ln.lstrip(' \t')
        orig_indent = len(ln) - len(stripped)
        while len(stack) > 1 and orig_indent <= stack[-1]["opener_orig"]:
            stack.pop()
        corrected = stack[-1]["body"]
        out[idx] = (' ' * corrected) + stripped
        end = stmt_idxs[k + 1] if k + 1 < len(stmt_idxs) else len(lines)
        logical = ' '.join(l.strip() for l in lines[idx:end])
        if _strip_inline_comment(logical).rstrip().endswith(':'):
            stack.append({"body": corrected + INDENT, "opener_orig": orig_indent})
    return '\n'.join(out)


def pre_process_py(filename, content):
    logs = []

    # 0. If the file does not parse, attempt a string/paren-aware reindent — but ONLY adopt
    #    it when the result actually compiles, so a valid file is never reformatted and a
    #    broken one is never made worse (anything still unparseable is left for the AI).
    try:
        compile(content, filename or '<dag>', 'exec')
    except SyntaxError:
        if RULES.on("py-reindent"):
            candidate = _normalize_py_indentation(content)
            try:
                compile(candidate, filename or '<dag>', 'exec')
                content = candidate
                logs.append(RULES.msg("py-reindent"))
            except SyntaxError:
                pass

    # 1. Fix DAG_NAME suffix if missing
    dag_name_match = re.search(r'DAG_NAME\s*=\s*["\'](.*?)["\']', content)
    if dag_name_match:
        dag_name = dag_name_match.group(1)
        if not dag_name.endswith('_VM') and RULES.on("py-dag-name-suffix"):
            content = re.sub(r'(DAG_NAME\s*=\s*["\'])(.*?)(["\'])', r'\1\2_VM\3', content)
            logs.append(RULES.msg("py-dag-name-suffix"))

    # 2. Fix 'timedelta' import if missing
    already_imported = ("import timedelta" in content
                        or "datetime, timedelta" in content
                        or "datetime,timedelta" in content)
    if "timedelta" in content and not already_imported and RULES.on("py-timedelta-import"):
        content = re.sub(r'from datetime import datetime\b', r'from datetime import datetime, timedelta', content)
        logs.append(RULES.msg("py-timedelta-import"))

    # 3. Remove 'catchup' from default_args if it exists
    if RULES.on("py-remove-catchup-args") and re.search(r'[\'"]catchup[\'"]\s*:\s*(True|False)\s*,?', content, re.IGNORECASE):
        content = re.sub(r'[ \t]*[\'"]catchup[\'"]\s*:\s*(True|False)\s*,?\n?', '', content, flags=re.IGNORECASE)
        logs.append(RULES.msg("py-remove-catchup-args"))

    # 4. Inject missing Airflow parameters into the DAG() instantiation. Handles BOTH the
    #    `dag = DAG(` and the `with DAG(` (context-manager) forms. CRITICAL: only LOG a parameter
    #    we ACTUALLY injected — if no DAG() opening is found, the regex matches nothing, so we must
    #    not claim a fix that never happened (which left the diff unchanged but the log saying "fixed").
    missing_dag_params = []
    if "catchup=" not in content.replace(" ", "") and RULES.on("py-inject-catchup"):
        missing_dag_params.append(("catchup=False", RULES.msg("py-inject-catchup")))
    if "max_active_runs" not in content and RULES.on("py-inject-max-active"):
        missing_dag_params.append(("max_active_runs=1", RULES.msg("py-inject-max-active")))
    if "tags=" not in content.replace(" ", "") and RULES.on("py-inject-tags"):
        missing_dag_params.append(('tags=["interface"]', RULES.msg("py-inject-tags")))

    if missing_dag_params:
        dag_open_re = re.compile(r'((?:dag\s*=\s*DAG|with\s+DAG)\s*\()', re.IGNORECASE)
        # Detect indent style from the existing DAG() body; default to 8 spaces.
        indent_match = re.search(r'(?:dag\s*=\s*DAG|with\s+DAG)\s*\(\s*\n([ \t]+)', content, re.IGNORECASE)
        indent = indent_match.group(1) if indent_match else "        "
        injection_string = ("," + "\n" + indent).join(p for p, _ in missing_dag_params) + ","
        content, n_inj = dag_open_re.subn(lambda m: m.group(1) + "\n" + indent + injection_string, content, count=1)
        if n_inj:                                  # only record fixes that were actually applied
            for _, msg in missing_dag_params:
                logs.append(msg)

    # 5. Normalize stale job-ID prefix in variable names and task_id strings to match DAG_NAME.
    # E.g. if DAG_NAME = "SRCMC11111_INTERFACE_VM", any SRCMC10435 prefix should become SRCMC11111.
    dag_prefix_match = re.search(r'DAG_NAME\s*=\s*["\']([A-Z]+\d+)(?:_[A-Z_]+)?["\']', content)
    if dag_prefix_match and RULES.on("py-stale-jobid"):
        correct_id = dag_prefix_match.group(1)
        stale_re = re.compile(r'\b([A-Z]{2,8}\d{3,8})(_\d+)\b')
        replaced_ids = set()
        def _replace_stale_var(m):
            found_id, suffix = m.group(1), m.group(2)
            if found_id != correct_id and found_id.startswith(correct_id[:2]):
                replaced_ids.add(found_id)
                return correct_id + suffix
            return m.group(0)
        content = stale_re.sub(_replace_stale_var, content)
        if replaced_ids:
            logs.append(RULES.msg("py-stale-jobid", ids=sorted(replaced_ids), correct_id=correct_id))

    # 6. Deterministic advisories (no auto-fix — these need a human value/decision).
    if re.search(r'\bDAG\s*\(', content):
        if 'start_date' not in content and RULES.on("py-no-start-date"):
            logs.append(RULES.msg("py-no-start-date"))
        if ('schedule_interval' not in content and 'schedule=' not in content.replace(' ', '')
                and RULES.on("py-no-schedule")):
            logs.append(RULES.msg("py-no-schedule"))
    if RULES.on("py-bare-except") and re.search(r'\bexcept\s*:', content):
        logs.append(RULES.msg("py-bare-except"))

    # User-defined pattern rules from linter_rules.json (custom_rules, lang "py").
    content = RULES.run_custom("py", content, logs)

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
