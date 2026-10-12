"""Run every exercise in order:  python appendix/run_days.py   (or: python appendix/run_days.py 03 07)"""
import runpy
import sys
from pathlib import Path

SRC = Path(__file__).parent / "days"


def main():
    wanted = set(sys.argv[1:])
    for path in sorted(SRC.glob("ex0*.py")):
        num = path.stem[2:4]
        if wanted and num not in wanted:
            continue
        print("\n" + "#" * 78 + f"\n# {path.stem}\n" + "#" * 78)
        try:
            runpy.run_path(str(path), run_name="__main__")
        except SystemExit as e:
            if e.code not in (0, None):
                print(f"{path.stem} exited with code {e.code}")


if __name__ == "__main__":
    main()
