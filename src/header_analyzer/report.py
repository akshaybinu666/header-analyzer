"""Terminal, JSON and CSV output."""

import csv
import json

from .models import SEVERITY_ORDER, STATUS_PASS, STATUS_WARN, STATUS_MISSING, STATUS_INFO


class C:
    RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    RED, GREEN, YELLOW, BLUE, CYAN = "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[36m"


def print_report(result, color=True, verbose=False):
    def c(code, text):
        return f"{code}{text}{C.RESET}" if color else text

    status_style = {STATUS_PASS: C.GREEN, STATUS_WARN: C.YELLOW,
                    STATUS_MISSING: C.RED, STATUS_INFO: C.BLUE}
    grade_style = {"A": C.GREEN, "B": C.GREEN, "C": C.YELLOW, "D": C.YELLOW, "F": C.RED}

    print()
    print(c(C.BOLD, f"Security Header Report: {result['final_url']}"))
    print(f"HTTP {result['status_code']}  |  Scanned {result['scanned_at']}")
    print(f"Score: {result['score']}/100  Grade: " +
          c(C.BOLD + grade_style[result['grade']], result['grade']))
    print("-" * 70)

    findings = sorted(result["findings"],
                      key=lambda f: (f["status"] == STATUS_PASS, -SEVERITY_ORDER[f["severity"]]))
    for f in findings:
        tag = c(status_style[f["status"]] + C.BOLD, f"[{f['status']:<7}]")
        sev = "" if f["status"] == STATUS_PASS else c(C.DIM, f" ({f['severity']})")
        print(f"{tag} {f['header']}{sev}")
        if f["status"] == STATUS_PASS and not verbose:
            continue
        if f["value"]:
            print(f"    Value:  {c(C.DIM, f['value'][:100])}")
        if f["issue"]:
            print(f"    Issue:  {f['issue']}")
        if f["remediation"]:
            print(f"    Fix:    {c(C.CYAN, f['remediation'])}")
    print()

    counts = {s: sum(1 for f in findings if f["status"] == s)
              for s in (STATUS_PASS, STATUS_WARN, STATUS_MISSING, STATUS_INFO)}
    print("Summary: " + ", ".join(f"{n} {s.lower()}" for s, n in counts.items()))
    print()


def write_json(results, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results if len(results) > 1 else results[0], fh, indent=2)


def write_csv(results, path):
    cols = ["url", "score", "grade", "header", "status", "severity", "value", "issue", "remediation"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in results:
            for f in r["findings"]:
                w.writerow({"url": r["final_url"], "score": r["score"], "grade": r["grade"], **f})
