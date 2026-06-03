import re

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

def pre_process_sql(filename, content):
    logs = []
    
    # 1. Parameterize Hardcoded BigQuery Datasets
    dataset_pattern = re.compile(r'\bDB_AEDWD2\b', re.IGNORECASE)
    if dataset_pattern.search(content):
        content = dataset_pattern.sub('${AEDW_DB}', content)
        logs.append("Fix: Automatically parameterized hardcoded dataset 'DB_AEDWD2' to '${AEDW_DB}'.")
        
    # 2. Convert TIMESTAMP functions to DATETIME functions
    timestamp_pattern = re.compile(r'\bTIMESTAMP\b\s*\(', re.IGNORECASE)
    if timestamp_pattern.search(content):
        content = timestamp_pattern.sub('DATETIME(', content)
        logs.append("Fix: Replaced 'TIMESTAMP()' with 'DATETIME()'.")

    # 3. Universal ETL_BATCH_SK Parameterization
    # Matches UPDATE/DELETE assignments: etl_batch_sk = 12345
    content, n1 = re.subn(r'(\betl_batch_sk\b\s*=\s*)[^\s,;)]+', r'\1${ETL_BATCH_SK}', content, flags=re.IGNORECASE)
    # Matches SELECT aliases: 12345 AS etl_batch_sk
    content, n2 = re.subn(r'\b\d+\s+AS\s+etl_batch_sk\b', '${ETL_BATCH_SK} AS etl_batch_sk', content, flags=re.IGNORECASE)
    
    if (n1 + n2) > 0:
        logs.append("Fix: Parameterized hardcoded 'ETL_BATCH_SK' occurrences to '${ETL_BATCH_SK}'.")
        
    # 4. Merge Multiple INSERTs for VALUES
    merge_pattern = re.compile(r"(INSERT\s+INTO\s+([A-Za-z0-9_$.{}]+)(?:\s*\([^)]+\))?\s+VALUES\s*[\s\S]*?);\s*INSERT\s+INTO\s+\2(?:\s*\([^)]+\))?\s+VALUES", re.IGNORECASE)
    while merge_pattern.search(content):
        content = merge_pattern.sub(r"\1,", content)
        if "Fix: Merged multiple INSERT VALUES statements into a single batch statement." not in logs:
            logs.append("Fix: Merged multiple INSERT VALUES statements into a single batch statement.")

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


def process_file_locally(filename, content):
    security_logs = scan_for_secrets(content)
    if security_logs:
        return content, security_logs

    if filename.endswith('.sql'):
        return pre_process_sql(filename, content)
    elif filename.endswith('.ksh'):
        return pre_process_ksh(filename, content)
    elif filename.endswith('_INTERFACE_VM.py') or filename.endswith('.py'):
        return pre_process_py(filename, content)
    
    return content, ["Unsupported extension file passed into deterministic parsing module."]
