"""Entry point for the whole pipeline.

    python -m honeycomb run                              (steps listed, none run)
    python -m honeycomb run --input LOG.jsonl --db X.db  (steps 3-8 on real data)
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
    parser.add_argument("--input", help="Cowrie JSON-lines log file to process")
    parser.add_argument("--db", default="data/honeycomb.db",
                        help="SQLite database path (default: data/honeycomb.db)")
    parser.add_argument("--no-enrich", action="store_true",
                        help="skip AbuseIPDB / VirusTotal lookups")
    args = parser.parse_args()

    if not args.input:
        for number, step in enumerate(STEPS, start=3):
            print(f"[{number}] {step}: not implemented yet")
        return 0

    from pathlib import Path

    from honeycomb.src.pipeline import run_pipeline

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    run_pipeline(args.input, args.db, enrich=not args.no_enrich)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
