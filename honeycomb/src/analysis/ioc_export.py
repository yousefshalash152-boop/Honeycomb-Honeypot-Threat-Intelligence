import csv
from pathlib import Path
from honeycomb.src.analysis.ioc_extractor import extract_iocs
def export_iocs_csv(db_path: str, output_path: str) -> int:
    """Export extracted IOCs to a CSV file.
    Returns the number of exported indicators.
    """
    indicators = extract_iocs(db_path)
    output_path = Path(output_path)

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        fieldnames = ["type", "value", "event_ids"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for indicator in indicators:
            writer.writerow(
                {
                    "type": indicator["type"],
                    "value": indicator["value"],
                    "event_ids": ";".join(indicator["event_ids"]),
                }
            )

    return len(indicators)
