"""
Known-pattern secret signatures: regexes that match the distinctive
shape of real credential formats (cloud provider keys, API tokens,
private key headers, connection strings with embedded passwords).

Each entry: (name, compiled regex, severity)
Severity guides how loudly a finding should be flagged; it is not a
guarantee the match is a live, exploitable credential.
"""

import re

# Values that look like secrets by shape but are actually placeholders -
# skip these so templated/example config doesn't get flagged.
_PLACEHOLDER_VALUE = re.compile(
    r"(?i)^(\$\{.*\}|%\(.*\)s|<.*>|your[-_]?|my[-_]?|insert|replace|change|"
    r"example|sample|test|dummy|fake|placeholder|xxxx|0000|1234|changeme|todo|fixme|none|null)"
)


def _is_placeholder(value):
    return bool(_PLACEHOLDER_VALUE.search(value.strip()))

# (name, regex, severity)
PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("AWS Secret Access Key (assignment)", re.compile(
        r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"), "critical"),

    ("GitHub Personal Access Token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "critical"),
    ("GitHub Fine-Grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "critical"),
    ("GitHub OAuth Token", re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "critical"),

    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"), "high"),

    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "critical"),
    ("Google OAuth Client Secret", re.compile(r"(?i)client_secret\s*[=:]\s*['\"]?GOCSPX-[A-Za-z0-9_-]{20,}['\"]?"), "critical"),

    ("Stripe Secret Key (live)", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), "critical"),
    ("Stripe Secret Key (test)", re.compile(r"\bsk_test_[0-9A-Za-z]{24,}\b"), "medium"),

    ("OpenAI API Key", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"), "critical"),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "critical"),

    ("Private Key Header", re.compile(
        r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"), "critical"),

    ("JWT (JSON Web Token)", re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), "medium"),

    ("Generic DB connection string with password", re.compile(
        r"(?i)(postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s$]+@[^\s'\"]+"), "high"),

    ("Hardcoded password assignment", re.compile(
        r"(?i)[a-z0-9_]*(password|passwd|pwd)[a-z0-9_]*\s*[=:]\s*['\"][^'\"\s]{6,}['\"]"), "medium"),

    ("Generic API key/secret assignment", re.compile(
        r"(?i)[a-z0-9_]*(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)[a-z0-9_]*\s*[=:]\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]"), "medium"),
]

# Rule names whose match target is a user-named variable (not a fixed
# vendor key format), so the matched value needs placeholder filtering
# before being reported - a vendor-shaped key like "AKIA..." can't be a
# placeholder, but a password/API key assignment often legitimately is.
GENERIC_RULE_NAMES = {
    "Generic DB connection string with password",
    "Hardcoded password assignment",
    "Generic API key/secret assignment",
}


def is_generic_match_placeholder(rule_name, matched_text):
    """For the generic/variable-named rules, re-checks whether the actual
    secret VALUE inside the match is a placeholder, so templated config
    (${DB_PASSWORD}, "your_api_key_here", etc.) isn't flagged."""
    if rule_name not in GENERIC_RULE_NAMES:
        return False

    if rule_name == "Generic DB connection string with password":
        # value is the password between ':' and '@'
        m = re.search(r":([^:@]+)@", matched_text)
    else:
        m = re.search(r"['\"]([^'\"]+)['\"]\s*$", matched_text)

    if not m:
        return False
    return _is_placeholder(m.group(1))

# File extensions never worth scanning (binary / generated / vendored)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".so", ".dll", ".exe", ".bin", ".dat",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".lock",
}

# Directories never worth walking into
SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "vendor", "target",
}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # skip files over 5MB - unlikely to be source
