import csv
import ipaddress
import json
import sqlite3
from pathlib import Path

from honeycomb.src.analysis.ioc_extractor import extract_iocs
from honeycomb.src.scoring import load_whitelist


FIELDS = ["type", "value", "first_seen", "last_seen", "sources", "confidence"]


def _team_networks():
    nets = []
    for entry in load_whitelist():
        try:
            nets.append(
                ipaddress.ip_network(str(entry).strip(), strict=False)
            )
        except ValueError:
            continue
    return nets


def _is_team_ip(value, nets):
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False

    return any(addr in network for network in nets)


def _hash_status(response):
    if not isinstance(response, dict) or response.get("error"):
        return "unknown"

    if response.get("status") == "unknown" or response.get("found") is False:
        return "unknown"

    stats = response.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return "unknown"

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)
    failure = stats.get("failure", 0)

    counts = (
        malicious, suspicious, harmless,
        undetected, timeout, failure
    )

    if any(
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        for value in counts
    ):
        return "unknown"

    if malicious > 0:
        return "malicious"

    if suspicious > 0 or timeout > 0 or failure > 0:
        return "unknown"

    if harmless + undetected > 0:
        return "clean"

    return "unknown"


def export_iocs_csv(db_path: str, output_path: str) -> int:
    indicators = extract_iocs(db_path)
    team_networks = _team_networks()

    with sqlite3.connect(db_path) as conn:
        timestamps = {}
        for event_id, ts in conn.execute(
            "SELECT event_id, ts_utc FROM events"
        ):
            timestamps[event_id] = ts

        cache = conn.execute(
            "SELECT indicator, source, response FROM intel_cache"
        ).fetchall()

    cache_by_indicator = {}
    for indicator, source, response_text in cache:
        try:
            response = json.loads(response_text)
        except (ValueError, TypeError):
            response = {}

        cache_by_indicator.setdefault(indicator, []).append(
            (source, response)
        )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()

        for item in indicators:
            kind = item["type"]
            value = item["value"]

            if kind == "ip" and _is_team_ip(value, team_networks):
                continue

            event_times = [
                timestamps[event_id]
                for event_id in item["event_ids"]
                if event_id in timestamps and timestamps[event_id]
            ]

            keys = [value]
            if kind == "ip":
                keys.append(f"ip:{value}")

            records = [
                record
                for key in keys
                for record in cache_by_indicator.get(key, [])
            ]

            sources = {"Cowrie"}
            confidence = "unknown"

            for source, response in records:
                sources.add(source)
                if kind == "ip" and source.lower() == "abuseipdb":
                    score = response.get("abuse_confidence_score")
                    if score is not None:
                        confidence = str(score)
                elif kind == "sha256" and source.lower() == "virustotal":
                    confidence = _hash_status(response)

            writer.writerow({
                "type": kind,
                "value": value,
                "first_seen": min(event_times) if event_times else "",
                "last_seen": max(event_times) if event_times else "",
                "sources": ";".join(sorted(sources)),
                "confidence": confidence,
            })
            count += 1

    return count
