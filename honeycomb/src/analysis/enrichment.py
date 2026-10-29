
from pathlib import Path

from honeycomb.src.analysis.ioc_extractor import extract_iocs
from honeycomb.src.analysis.threat_intel import (
    check_ip_abuseipdb,
    check_virustotal,
)


def enrich_iocs(db_path: str) -> list:
    """Enrich indicators and keep processing when a source is rate limited."""
    db_path = str(Path(db_path).resolve())
    indicators = extract_iocs(db_path)
    results = []

    for indicator in indicators:
        ioc_type = indicator["type"]
        value = indicator["value"]

        result = {
            "type": ioc_type,
            "value": value,
            "event_ids": indicator["event_ids"],
            "threat_intel": {},
        }

        if ioc_type == "ip":
            intel_result = check_ip_abuseipdb(value, db_path=db_path)
            result["threat_intel"]["abuseipdb"] = intel_result

        elif ioc_type == "sha256":
            intel_result = check_virustotal(
                "sha256", value, db_path=db_path
            )
            result["threat_intel"]["virustotal"] = intel_result

        else:
            results.append(result)
            continue

        # Keep the result and continue processing the remaining indicators.
        # A rate-limited result is marked unknown by the API client.
        results.append(result)

    return results
