"""Default configuration shared by discovery and the rules.

This holds plain data: folder names to skip, name patterns that look
like secrets, weak hash names, names that produce weak randomness,
subprocess function names, and the CWE/severity table for each rule.
"""

SKIPPED_FOLDERS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    "build",
    "dist",
}

# Substrings (lowercase) that mark a name as holding a secret value.
SECRET_NAME_PATTERNS = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
)

# Substrings (lowercase) that mark a name as password-like, for the
# hashlib rule. Narrower than SECRET_NAME_PATTERNS on purpose.
PASSWORD_LIKE_PATTERNS = (
    "pass",
    "pwd",
    "secret",
)

# Substrings (lowercase) that mark a name as holding a security token,
# used by the weak-randomness rule.
TOKEN_LIKE_PATTERNS = (
    "token",
    "session",
    "otp",
    "reset",
    "csrf",
)

# hashlib constructor names considered weak.
WEAK_HASH_NAMES = ("md5", "sha1")

# Dotted suffixes (last attribute) that come from the random module and
# should not be used for security-sensitive values.
RANDOM_FUNCTION_NAMES = (
    "random",
    "randint",
    "randrange",
    "choice",
    "choices",
    "getrandbits",
    "shuffle",
    "sample",
    "uniform",
)

# subprocess functions that accept shell=True.
SUBPROCESS_FUNCTION_NAMES = (
    "run",
    "call",
    "Popen",
    "check_call",
    "check_output",
)

# execute-like sqlite3 / DB-API cursor methods.
SQL_EXEC_METHODS = ("execute", "executemany", "executescript")


_VALID_SEVERITIES = ("high", "medium", "low")


class RuleInfo:
    def __init__(self, rule, cwe, severity):
        if severity not in _VALID_SEVERITIES:
            raise ValueError("invalid severity for " + rule + ": " + str(severity))
        if not isinstance(cwe, int) or cwe <= 0:
            raise ValueError("invalid CWE number for " + rule)
        self.rule = rule
        self.cwe = cwe
        self.severity = severity


RULES_TABLE = {
    "PY-SQL": RuleInfo("PY-SQL", 89, "high"),
    "PY-SECRET": RuleInfo("PY-SECRET", 798, "high"),
    "PY-HASH": RuleInfo("PY-HASH", 328, "medium"),
    "PY-RANDOM": RuleInfo("PY-RANDOM", 330, "low"),
    "PY-EVAL": RuleInfo("PY-EVAL", 95, "high"),
    "PY-SHELL": RuleInfo("PY-SHELL", 78, "high"),
    "PY-PICKLE": RuleInfo("PY-PICKLE", 502, "high"),
    "PY-DEBUG": RuleInfo("PY-DEBUG", 489, "medium"),
    "PY-CORS": RuleInfo("PY-CORS", 942, "medium"),
    "PY-COOKIE": RuleInfo("PY-COOKIE", 614, "low"),
}


def rule_info(rule_name):
    """Look up a rule's CWE and severity by its rule code."""
    try:
        return RULES_TABLE[rule_name]
    except KeyError:
        raise KeyError("no such rule: " + str(rule_name))


def rule_names():
    """Return the known rule codes, sorted for stable output."""
    return sorted(RULES_TABLE)
