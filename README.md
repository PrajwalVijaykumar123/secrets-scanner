# Secrets Scanner

A static analysis tool that scans a codebase for hardcoded credentials — cloud provider keys, API tokens, private keys, and generic high-entropy secrets — before they get committed or shipped. Think of it as a small, from-scratch version of tools like TruffleHog or gitleaks.

## What This Project Does

- **Known-pattern detection** — regex signatures for the distinctive shape of real credential formats: AWS access keys, GitHub/Slack/Stripe/OpenAI/Anthropic tokens, Google API keys, private key headers, JWTs, and DB connection strings with embedded passwords
- **Entropy-based generic detection** — catches secrets that don't match any known vendor format, by flagging high-Shannon-entropy values assigned to suspiciously-named variables (`*_secret`, `*_token`, `*_key`, `*_password`, …)
- **Placeholder-aware** — recognizes templated/example values (`${DB_PASSWORD}`, `your_api_key_here`, `<YOUR_TOKEN>`, AWS's own documented example key) and does not flag them, so clean config doesn't drown in false positives
- **Allowlist system** — exclude specific paths (test fixtures, vendored code) or specific known-safe strings from every run
- **Redacted output** — findings show only the first/last few characters of a match, never the full secret, so running the scanner doesn't itself leak anything into logs or CI output
- **CI-friendly** — exits non-zero when critical/high findings are present, and can write a full JSON report

## Example Output

```
3 potential secret(s) found:

  [CRITICAL] config.py:12
             AWS Access Key ID
             -> AKIA************ZZZZ

  [HIGH    ] config.py:27
             Generic DB connection string with password
             -> post***********************************************************/app

  [MEDIUM  ] config.py:30
             High-entropy generic secret (entropy=5.0)
             -> INTE****************************************************U0y"

Summary — critical: 1, high: 1, medium: 1
```

## Tech Stack

- Python 3.11, standard library only (`re`, `math`, `os`, `json`, `argparse`) — no dependencies to install

## Setup

No dependencies required — just Python 3.

```bash
python3 scanner.py /path/to/codebase
```

Options:

```bash
python3 scanner.py /path/to/codebase --json report.json       # write a full JSON report
python3 scanner.py /path/to/codebase --allowlist custom.json   # use a different allowlist
```

### Testing it against the included fixtures

`test_fixtures/bad_config.py` has synthetic (non-functional) secrets planted in every supported format; `test_fixtures/clean_config.py` has only placeholders and environment-variable reads, and should produce zero findings — it's the false-positive regression check.

The default allowlist excludes `test_fixtures/` (the right behavior when scanning a real project, so its own fixtures aren't reported as findings every run). To scan the fixtures directly and see detection in action, point at an allowlist that doesn't exclude them:

```bash
echo '{"paths": [], "substrings": ["AKIAIOSFODNN7EXAMPLE"]}' > /tmp/fixtures_allowlist.json
python3 scanner.py test_fixtures --allowlist /tmp/fixtures_allowlist.json
```

## Tuning the allowlist

Edit `allowlist/allowlist.json` to exclude paths (test directories, vendored dependencies) or specific strings (a key you know is already revoked, or a documented vendor example key) from future scans.

## Architecture

```
Directory walk (skips .git, node_modules, venv, binaries, files >5MB)
        |
        v
Per-line matching:
  - Known vendor-format regexes (AWS, GitHub, Slack, Stripe, Google, OpenAI, Anthropic, private keys, JWTs)
  - Generic high-entropy secret detection for anything else
        |
        v
Placeholder filtering (templates, "your_api_key_here", example keys) + allowlist filtering
        |
        v
Redacted console report + optional JSON report, severity-sorted
        |
        v
Non-zero exit code on critical/high findings (CI gate)
```

## Project Structure

```
secrets-scanner/
├── scanner.py              # Main CLI: directory walk, matching, reporting
├── rules/
│   ├── patterns.py         # Known vendor-format regex signatures
│   └── entropy.py          # Generic high-entropy secret detection
├── allowlist/
│   └── allowlist.json      # Paths/substrings excluded from findings
├── test_fixtures/
│   ├── bad_config.py       # Synthetic secrets in every supported format
│   └── clean_config.py     # Placeholders only — false-positive check
└── README.md
```

## What I Learned

- Writing regex signatures that match a credential format's real shape rather than a flat keyword list, which is what lets this catch new instances of a known vendor's key format reliably
- Using Shannon entropy as a general-purpose "does this look like random key material" signal, as a fallback for secret formats with no dedicated pattern — and discovering it over-fires on templated values and placeholders unless you explicitly filter those first
- The redaction tradeoff: a security tool that reports findings has to avoid becoming a second place the secret leaks to (terminal scrollback, CI logs, a committed JSON report)
- Designing a tool to fail loudly in CI (non-zero exit code) while staying quiet on legitimate placeholder/template config — false positives are what get a scanner disabled

## Next Steps

- Git history scanning (catch secrets committed in the past, not just the current working tree, à la gitleaks/TruffleHog)
- Pre-commit hook integration so secrets are blocked before they're ever committed
- Verify findings against live APIs where safe (e.g. confirm an AWS key is actually active) rather than just pattern-matching
- HTML dashboard report, consistent with the other projects in this portfolio
