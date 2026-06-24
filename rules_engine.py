"""rules_engine.py — the bridge between the editable rule registry (``linter_rules.json``)
and the deterministic linter (``linter.py``).

WHY THIS EXISTS
---------------
Every check the linter performs used to live as a hardcoded string / constant inside
``linter.py``.  This module externalizes the *editable surface* of those checks into
``linter_rules.json`` so a non-developer can:

  * edit any rule's message text,
  * turn a rule on/off  (``"enabled": false``),
  * tune the shared settings (dataset map, env-path segments, secret patterns, …),
  * add brand-new pattern rules under ``custom_rules`` WITHOUT touching Python.

The complex *structural* transforms (schema-aware column fixes, INSERT column
injection, SQL statement splitting, Python re-indentation) keep their LOGIC in
``linter.py`` — they cannot be expressed as a simple pattern — but their message,
severity and on/off toggle are still driven from the JSON.  Each such rule's JSON
entry has ``"type": "builtin"`` and a ``"code_ref"`` pointing at the function that
implements it.

ROBUSTNESS
----------
Reads must never crash the linter.  If ``linter_rules.json`` is missing or invalid we
fall back to: messages = the rule id, every rule enabled, and a hardcoded built-in
set of secret patterns (security must never silently disappear).  The shipped JSON is
the source of truth in normal operation.
"""
import json
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
_RULES_PATH = os.environ.get("LINTER_RULES_FILE", os.path.join(_HERE, "linter_rules.json"))

# Security net: if the registry can't be read, secret scanning must still work.
_FALLBACK_SECRET_PATTERNS = {
    "GCP API Key": r'(?i)AIza[0-9A-Za-z-_]{35}',
    "AWS Access Key": r'(?i)AKIA[0-9A-Z]{16}',
    "Generic Password/Secret": r'(?i)(password|secret|token)[\s=:]+[\'"][^\'"]{6,}[\'"]',
}

_FLAG_MAP = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE, "x": re.VERBOSE}


def _compile_flags(flags):
    out = 0
    for f in (flags or []):
        out |= _FLAG_MAP.get(str(f).lower().strip(), 0)
    return out


class _Registry:
    def __init__(self, path):
        self._path = path
        self._raw = {}
        self._by_id = {}
        self.load()

    def load(self):
        """(Re)load the registry from disk. Never raises."""
        self._raw, self._by_id = {}, {}
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                self._raw = json.load(f) or {}
        except Exception:
            self._raw = {}
        # Index every rule by id across all language buckets + custom rules.
        for bucket in (self._raw.get("rules") or {}).values():
            for rule in (bucket or []):
                rid = rule.get("id")
                if rid:
                    self._by_id[rid] = rule
        for rule in (self._raw.get("custom_rules") or []):
            rid = rule.get("id")
            if rid:
                self._by_id[rid] = rule

    # --- per-rule accessors -------------------------------------------------
    def msg(self, rule_id, **kw):
        """Return rule_id's (possibly user-edited) message, formatted with kw.
        Falls back to the rule id if the registry has no text for it."""
        entry = self._by_id.get(rule_id)
        template = entry.get("message") if entry else None
        if not template:
            template = rule_id
        if not kw:
            return template
        try:
            return template.format(**kw)
        except (KeyError, IndexError, ValueError):
            return template

    def on(self, rule_id):
        """True unless the rule is explicitly disabled in the registry."""
        entry = self._by_id.get(rule_id)
        if entry is None:
            return True
        return bool(entry.get("enabled", True))

    # --- shared settings ----------------------------------------------------
    def setting(self, key, default=None):
        """A tunable constant from the ``settings`` block. Each entry may declare an
        ``env`` var that overrides it, so precedence is: env var > registry > default."""
        node = (self._raw.get("settings") or {}).get(key)
        if not isinstance(node, dict):
            return default
        env_name = node.get("env")
        if env_name and os.environ.get(env_name) is not None:
            return os.environ.get(env_name)
        val = node.get("value")
        return val if val is not None else default

    def secret_patterns(self):
        """name -> regex for the shift-left secret scanner."""
        node = self._raw.get("secret_patterns")
        if isinstance(node, dict) and node:
            return {k: v for k, v in node.items() if v}
        return dict(_FALLBACK_SECRET_PATTERNS)

    # --- generic pattern engine (powers user-added custom_rules) ------------
    def run_custom(self, lang, content, logs):
        """Apply every enabled ``custom_rules`` entry for this language.

        Each rule may carry an ordered ``fix`` list (regex search/replace applied to
        the content) and/or a detection ``pattern`` that appends ``message`` to logs.
        Scope ``"line"`` reports once per matching line (exposing {line} and {text});
        scope ``"file"`` reports once if the pattern is found anywhere.
        Returns the (possibly fixed) content. Never raises on a single bad rule."""
        for rule in (self._raw.get("custom_rules") or []):
            try:
                if not rule.get("enabled", False):
                    continue
                if rule.get("lang") not in (lang, "any", None):
                    continue
                content = self._apply_one(rule, content, logs)
            except Exception:
                # A malformed custom rule must never break the linter for a file.
                continue
        return content

    def _apply_one(self, rule, content, logs):
        flags = _compile_flags(rule.get("flags"))
        message = rule.get("message") or rule.get("id")
        # 1. Optional ordered fixes (search/replace) on the content.
        fix_changed = False
        for fix in (rule.get("fix") or []):
            find = fix.get("find")
            if find is None:
                continue
            new_content = re.sub(find, fix.get("replace", ""),
                                 content, flags=_compile_flags(fix.get("flags")) or flags)
            if new_content != content:
                fix_changed = True
            content = new_content
        # 2. Detection -> log message. With no detection pattern, a fix-only rule logs
        #    its message once if (and only if) one of its fixes actually changed the code.
        pattern = rule.get("pattern")
        if not pattern:
            if fix_changed and rule.get("message"):
                logs.append(message)
            return content
        rx = re.compile(pattern, flags)
        if rule.get("scope") == "line":
            for idx, line in enumerate(content.split("\n"), start=1):
                if rx.search(line):
                    try:
                        logs.append(message.format(line=idx, text=line.strip()))
                    except (KeyError, IndexError, ValueError):
                        logs.append(message)
        else:  # file scope
            if rx.search(content):
                logs.append(message)
        return content


# Singleton imported by linter.py
RULES = _Registry(_RULES_PATH)
