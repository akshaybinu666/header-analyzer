"""Command-line interface."""

import argparse
import sys

import requests

from . import __version__
from .models import SEVERITY_ORDER, STATUS_WARN, STATUS_MISSING
from .report import print_report, write_json, write_csv
from .scanner import analyse


def main(argv=None):
    p = argparse.ArgumentParser(description="Check a website for missing or misconfigured security headers.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("urls", nargs="+", help="One or more URLs or domains to scan")
    p.add_argument("--json", metavar="FILE", help="Write JSON report to FILE")
    p.add_argument("--csv", metavar="FILE", help="Write CSV report to FILE")
    p.add_argument("--timeout", type=float, default=10, help="Request timeout in seconds (default 10)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    p.add_argument("--no-redirects", action="store_true", help="Do not follow redirects")
    p.add_argument("--user-agent", help="Custom User-Agent string")
    p.add_argument("--no-color", action="store_true", help="Disable coloured output")
    p.add_argument("-v", "--verbose", action="store_true", help="Show details for passing headers too")
    p.add_argument("--fail-on", choices=["low", "medium", "high"],
                   help="Exit with code 1 if any issue at or above this severity is found (useful for CI)")
    args = p.parse_args(argv)

    use_color = not args.no_color and sys.stdout.isatty()
    results, errors = [], 0

    for url in args.urls:
        try:
            result = analyse(url, timeout=args.timeout, verify=not args.insecure,
                             user_agent=args.user_agent, follow_redirects=not args.no_redirects)
        except requests.exceptions.SSLError as e:
            print(f"[error] {url}: TLS error ({e}). Use --insecure to skip verification.", file=sys.stderr)
            errors += 1
            continue
        except requests.exceptions.RequestException as e:
            print(f"[error] {url}: {e}", file=sys.stderr)
            errors += 1
            continue
        results.append(result)
        print_report(result, color=use_color, verbose=args.verbose)

    if not results:
        return 2
    if args.json:
        write_json(results, args.json)
        print(f"JSON report written to {args.json}")
    if args.csv:
        write_csv(results, args.csv)
        print(f"CSV report written to {args.csv}")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        for r in results:
            for f in r["findings"]:
                if f["status"] in (STATUS_MISSING, STATUS_WARN) and SEVERITY_ORDER[f["severity"]] >= threshold:
                    return 1
    return 2 if errors and not results else 0
