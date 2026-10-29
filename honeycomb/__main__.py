"""Entry point for the whole pipeline: python -m honeycomb run

Empty for now. Each step will be wired in by its owner in later stages.
"""
import argparse

# Pipeline steps 3-10 from the project plan (steps 1-2 run on the server).
STEPS = [
    "normalize",
    "extract_iocs",
    "enrich",
    "behavior",
    "correlate",
    "score",
    "decide",
    "report",
]


def main() -> int:
    parser = argparse.ArgumentParser(prog="honeycomb")
    parser.add_argument("command", choices=["run"], help="run the pipeline")
    parser.parse_args()
    for number, step in enumerate(STEPS, start=3):
        print(f"[{number}] {step}: not implemented yet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
