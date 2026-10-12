"""Build the capstone report and validate it.

  python run.py           regenerate docs/ and run all checks
  python run.py --check   verify docs/ are up to date and all checks pass (used in CI)
"""
import sys
from pathlib import Path

from capstone import report, validate

ROOT = Path(__file__).parent


def main():
    files, summary = report.build()
    checks = validate.run(executive_summary_text=summary)

    print("=== Capstone validation ===")
    for name, ok, detail in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name} - {detail}")
    ok = validate.all_passed(checks)

    if "--check" in sys.argv:
        stale = [p for p, text in files.items()
                 if not (ROOT / p).exists() or (ROOT / p).read_text(encoding="utf-8") != text]
        if stale:
            print("\nOut of date (run `python run.py`): " + ", ".join(stale))
            ok = False
    else:
        for p, text in files.items():
            (ROOT / p).parent.mkdir(exist_ok=True)
            (ROOT / p).write_text(text, encoding="utf-8")
            print(f"wrote {p}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
