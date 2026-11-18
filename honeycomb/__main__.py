"""Honeycomb command-line entry point."""
import argparse

from honeycomb.src.analysis.ioc_export import export_iocs_csv

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
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="run the pipeline")

    export_parser = subparsers.add_parser(
        "export-iocs", help="export IOCs from SQLite to CSV"
    )
    export_parser.add_argument("--db", required=True, help="SQLite database path")
    export_parser.add_argument("--output", required=True, help="CSV output path")

    args = parser.parse_args()

    if args.command == "run":
        for number, step in enumerate(STEPS, start=3):
            print(f"[{number}] {step}: not implemented yet")
        return 0

    if args.command == "export-iocs":
        count = export_iocs_csv(args.db, args.output)
        print(f"Exported {count} IOCs to {args.output}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
