
from honeycomb.src.analysis import enrichment

def test_enriches_ip_with_abuseipdb_only(monkeypatch):

    monkeypatch.setattr(
        enrichment,
        "extract_iocs",
        lambda db_path: [
            {
                "type": "ip",
                "value": "8.8.8.8",
                "event_ids": ["event-1"],
            }
        ],
    )

    monkeypatch.setattr(
        enrichment,
        "check_ip_abuseipdb",
        lambda value, db_path=None: {
            "source": "AbuseIPDB",
            "score": 0,
        },
    )

    monkeypatch.setattr(
        enrichment,
        "check_virustotal",
        lambda ioc_type, value, db_path=None: {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
        },
    )

    results = enrichment.enrich_iocs("unused.db")

    assert len(results) == 1
    assert results[0]["event_ids"] == ["event-1"]
    assert "abuseipdb" in results[0]["threat_intel"]
    assert "virustotal" not in results[0]["threat_intel"]

def test_enriches_sha256_with_virustotal_only(monkeypatch):
    monkeypatch.setattr(
        enrichment,
        "extract_iocs",
        lambda db_path: [
            {
                "type": "sha256",
                "value": "a" * 64,
                "event_ids": ["event-2"],
            }
        ],
    )

    monkeypatch.setattr(
        enrichment,
        "check_virustotal",
        lambda ioc_type, value, db_path=None: {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
        },
    )

    results = enrichment.enrich_iocs("unused.db")

    assert results[0]["event_ids"] == ["event-2"]
    assert "virustotal" in results[0]["threat_intel"]
    assert "abuseipdb" not in results[0]["threat_intel"]
