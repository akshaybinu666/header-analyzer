# header-analyzer

[![CI](https://github.com/akshaybinu666/header-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/akshaybinu666/header-analyzer/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A fast command-line tool that audits a website's **HTTP security headers**, flags anything
**missing or misconfigured**, and tells you **exactly how to fix it**. Reports can be exported
as **JSON** or **CSV**, and a CI-friendly exit code lets you fail a build on serious findings.

## Features

- Checks 10+ security headers: `Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
  `Cross-Origin-Opener/Resource/Embedder-Policy`, and deprecated `X-XSS-Protection`.
- Goes beyond presence checks: detects a short HSTS `max-age`, CSP with `unsafe-inline` /
  `unsafe-eval` / wildcards, unsafe referrer policies, and more.
- Flags information leakage (`Server`, `X-Powered-By` exposing versions).
- Audits `Set-Cookie` flags (`Secure`, `HttpOnly`, `SameSite`).
- Severity ratings, a 0-100 score and an A-F grade.
- Remediation advice with a copy-paste fix for every finding.
- Scan multiple URLs in one run; JSON and CSV export; `--fail-on` for CI pipelines.

## Install

```bash
git clone https://github.com/akshaybinu666/header-analyzer.git
cd header-analyzer
pip install .
```

## Usage

```bash
header-analyzer example.com
header-analyzer https://site-a.com https://site-b.com --json report.json --csv report.csv
header-analyzer example.com --fail-on high      # exit code 1 if any high-severity issue
header-analyzer example.com -v                  # also show details for passing headers
python -m header_analyzer example.com           # without installing the script
```

| Option | Description |
|---|---|
| `--json FILE` / `--csv FILE` | Write a report to a file |
| `--fail-on {low,medium,high}` | Exit with code 1 if an issue at or above that severity is found |
| `--timeout SECONDS` | Request timeout (default 10) |
| `--insecure` | Skip TLS certificate verification |
| `--no-redirects` | Do not follow redirects |
| `--user-agent STR` | Custom User-Agent |
| `--no-color` | Disable colored output |
| `-v, --verbose` | Show details for passing headers |

**Exit codes:** `0` success, `1` issues at/above `--fail-on` severity found, `2` no URL could be scanned.

### Try it safely

A deliberately misconfigured demo server is included:

```bash
python examples/demo_server.py &
header-analyzer http://127.0.0.1:8099
```

## Example output

```text
Security Header Report: http://127.0.0.1:8099/
HTTP 200  |  Scanned 2026-10-26T14:49:34+00:00
Score: 29/100  Grade: F
----------------------------------------------------------------------
[WARN   ] Content-Security-Policy (high)
    Value:  default-src 'self'; script-src 'self' 'unsafe-inline'
    Issue:  script policy allows 'unsafe-inline'; no frame-ancestors ...; no base-uri directive.
    Fix:    Define a policy, e.g.: Content-Security-Policy: default-src 'self'; object-src 'none'; ...
[WARN   ] Set-Cookie (sid) (medium)
    Issue:  Cookie missing HttpOnly, missing SameSite.
    Fix:    Set cookies with: Secure; HttpOnly; SameSite=Lax (or Strict).
[PASS   ] X-Content-Type-Options
```

See [`examples/sample_report.json`](examples/sample_report.json) and
[`examples/sample_report.csv`](examples/sample_report.csv) for full reports.

## Use as a library

```python
from header_analyzer import analyse

result = analyse("https://example.com")
print(result["grade"], result["score"])
for f in result["findings"]:
    print(f["header"], f["status"], f["remediation"])
```

## CI usage

```yaml
- run: pip install .
- run: header-analyzer https://staging.example.com --fail-on high
```

## How scoring works

Start at 100. Each missing or misconfigured header subtracts points by severity
(high 20, medium 10, low 3). Grades: A >= 90, B >= 80, C >= 65, D >= 50, else F.
The score is a quick heuristic for comparing changes over time, not a formal security rating.

## Limitations

- Analyses the headers of a **single GET response** (the final URL after redirects). Headers can
  differ per path, status code or content type, so scan important endpoints separately.
- CSP analysis checks common weaknesses; it is not a full CSP evaluator.
- Header checks do not replace a full security assessment.
- When a site sends multiple CSP headers, directives are merged and the first occurrence wins.
  Browsers enforce all policies together, so this is an approximation.
- Cookie findings are heuristics and cannot tell session cookies from analytics cookies.

## Development

```bash
pip install -e ".[dev]"
pytest
```

```text
src/header_analyzer/
  checks.py    # one function per header check
  scanner.py   # fetch + run checks + score
  report.py    # terminal / JSON / CSV output
  cli.py       # argparse entry point
tests/         # unit + local-server integration tests
```

To add a check, write a `check_*` function in `checks.py` that returns a `Finding`, append it
to `CHECKS`, and add a test.

## Responsible use

Only scan websites you own or have explicit permission to test. This tool sends a single
standard GET request per URL, but you are responsible for how you use it.

## License

[MIT](LICENSE)
