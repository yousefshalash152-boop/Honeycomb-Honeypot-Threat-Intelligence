"""Entry point for the Honeycomb pipeline and CLI commands."""
import argparse
import os

from honeycomb.src.analysis.ioc_export import export_iocs_csv

# Pipeline steps 3-10 from the project plan.
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


def _duration(seconds):
    days, rest = divmod(int(seconds), 86400)
    return f"{days}d {rest // 3600}h"


def _verify(args) -> int:
    from honeycomb.src.blocking import BlockingError, verify_ip

    if not args.ip:
        print("verify needs an IP:  python -m honeycomb verify <IP>")
        return 2

    try:
        result = verify_ip(
            args.ip,
            host=args.host,
            key=args.key,
            user=args.user,
            port=args.port,
        )
    except (ValueError, BlockingError) as exc:
        print(f"ERROR: {exc}")
        return 2

    if not result["blocked"]:
        print(f"{result['ip']}  NOT BLOCKED")
        return 1

    print(
        f"{result['ip']}  BLOCKED  packets={result['packets']} "
        f"bytes={result['bytes']}  expires in {_duration(result['expires_in'])}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="honeycomb")

    parser.add_argument(
        "command",
        choices=["run", "verify", "export-iocs"],
        help="run the pipeline, verify a blocked IP, or export IOCs",
    )
    parser.add_argument("ip", nargs="?", help="IP to check (verify only)")

    parser.add_argument("--input", help="Cowrie JSON-lines log file to process")
    parser.add_argument(
        "--db",
        help="SQLite database path",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="skip AbuseIPDB / VirusTotal lookups",
    )

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--user", default="honeycomb-blocker")
    parser.add_argument(
        "--key",
        default=os.path.expanduser("~/.ssh/honeycomb_blocker"),
    )
    parser.add_argument("--port", type=int, default=22)

    parser.add_argument(
        "--output",
        help="CSV output path (required for export-iocs)",
    )

    args = parser.parse_args()

    if args.command == "verify":
        return _verify(args)

    if args.command == "export-iocs":
        if not args.db:
            parser.error("export-iocs requires --db")
        if not args.output:
            parser.error("export-iocs requires --output")

        count = export_iocs_csv(args.db, args.output)
        print(f"Exported {count} IOCs to {args.output}")
        return 0

    # Run command
    db_path = args.db or "data/honeycomb.db"

    if not args.input:
        for number, step in enumerate(STEPS, start=3):
            print(f"[{number}] {step}: not implemented yet")
        return 0

    from pathlib import Path
    from honeycomb.src.pipeline import run_pipeline

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    run_pipeline(args.input, db_path, enrich=not args.no_enrich)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
