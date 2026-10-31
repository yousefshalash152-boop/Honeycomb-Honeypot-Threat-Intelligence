"""Entry point for the whole pipeline.

    python -m honeycomb run                              (steps listed, none run)
    python -m honeycomb run --input LOG.jsonl --db X.db  (steps 3-8 on real data)
    python -m honeycomb verify 203.0.113.45              (is this IP really blocked?)
"""
import argparse
import os

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


def _duration(seconds):
    days, rest = divmod(int(seconds), 86400)
    return f"{days}d {rest // 3600}h"


def _verify(args) -> int:
    from honeycomb.src.blocking import BlockingError, verify_ip

    if not args.ip:
        print("verify needs an IP:  python -m honeycomb verify <IP>")
        return 2
    try:
        result = verify_ip(args.ip, host=args.host, key=args.key,
                           user=args.user, port=args.port)
    except (ValueError, BlockingError) as exc:
        print(f"ERROR: {exc}")
        return 2
    if not result["blocked"]:
        print(f"{result['ip']}  NOT BLOCKED")
        return 1
    print(f"{result['ip']}  BLOCKED  packets={result['packets']} "
          f"bytes={result['bytes']}  expires in {_duration(result['expires_in'])}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="honeycomb")
    parser.add_argument("command", choices=["run", "verify"],
                        help="run the pipeline, or verify that an IP is blocked")
    parser.add_argument("ip", nargs="?", help="IP to check (verify only)")
    parser.add_argument("--input", help="Cowrie JSON-lines log file to process")
    parser.add_argument("--db", default="data/honeycomb.db",
                        help="SQLite database path (default: data/honeycomb.db)")
    parser.add_argument("--no-enrich", action="store_true",
                        help="skip AbuseIPDB / VirusTotal lookups")
    parser.add_argument("--host", default="127.0.0.1",
                        help="blocking host for verify (default: 127.0.0.1)")
    parser.add_argument("--user", default="honeycomb-blocker",
                        help="restricted ssh user for verify")
    parser.add_argument("--key", default=os.path.expanduser("~/.ssh/honeycomb_blocker"),
                        help="restricted ssh private key for verify")
    parser.add_argument("--port", type=int, default=22,
                        help="ssh port of the blocking host for verify")
    args = parser.parse_args()

    if args.command == "verify":
        return _verify(args)

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
