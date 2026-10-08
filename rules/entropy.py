"""
Entropy-based generic secret detection.

Known-pattern regexes (patterns.py) only catch vendor formats we've
specifically written a rule for. This module catches the rest: any
quoted string assigned to a key/secret/token-ish variable name whose
Shannon entropy is high enough to look like random key material
rather than a real word, sentence, or placeholder.
"""

import math
import re

# Variable name hints that suggest the assigned value might be a secret
SUSPICIOUS_VAR_HINTS = re.compile(
    r"(?i)\b([a-z0-9_]*(secret|token|key|credential|passwd|password|apikey)[a-z0-9_]*)\s*[=:]\s*['\"]([^'\"]{12,})['\"]"
)

# Strings that look like secrets but are actually common placeholders -
# these should never be flagged even if their entropy happens to be high
PLACEHOLDER_PATTERNS = [
    re.compile(r"(?i)^(your|my|insert|replace|change|example|sample|test|dummy|fake|placeholder)[-_]?"),
    re.compile(r"(?i)(xxxx|0000|1234|changeme|todo|fixme)"),
    re.compile(r"^\$\{.*\}$"),       # template interpolation, e.g. ${SECRET_KEY}
    re.compile(r"^%\(.*\)s$"),       # Python % formatting placeholder
    re.compile(r"^<.*>$"),           # <YOUR_API_KEY>
    re.compile(r"(?i)^(none|null|undefined|n/?a)$"),
]

ENTROPY_THRESHOLD = 3.5  # bits/char; real key material is usually well above this


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder(value):
    return any(pattern.search(value) for pattern in PLACEHOLDER_PATTERNS)


def find_high_entropy_secrets(line):
    """Returns a list of (matched_snippet, entropy) for suspicious
    variable assignments in a line of text that look like real secret
    material rather than a placeholder or ordinary string."""
    findings = []
    for match in SUSPICIOUS_VAR_HINTS.finditer(line):
        var_name, _, value = match.groups()
        if is_placeholder(value):
            continue
        entropy = shannon_entropy(value)
        if entropy >= ENTROPY_THRESHOLD and len(value) >= 12:
            findings.append((f"{var_name} = \"{value}\"", round(entropy, 2)))
    return findings
