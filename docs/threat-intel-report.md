# Threat Intelligence Report

## 1. Overview

This section summarizes the external threat intelligence enrichment performed by the Honeycomb honeypot pipeline. It describes observed indicators, their reputation status, and the value of correlating locally collected IOCs with external threat intelligence sources.

The current implementation integrates:

- **AbuseIPDB** for public IP reputation checks.
- **VirusTotal** for SHA-256 file hash analysis.
- **Cowrie** as the source of locally observed indicators.

## 2. Threat Intelligence Metrics

The following reusable SQL queries are maintained under `scripts/queries/`:

| Query | Metric |
|---|---|
| `01_total_unique_ips.sql` | Total unique valid observed IP addresses |
| `02_public_unique_ips.sql` | Total unique public IP addresses |
| `03_ips_with_valid_reputation.sql` | Public IPs with valid, fresh AbuseIPDB reputation |
| `04_ips_with_abuse_reports.sql` | Public IPs with actual AbuseIPDB reports |
| `05_malicious_sha256_hashes.sql` | Observed SHA-256 hashes classified as malicious by VirusTotal |

All reputation cache metrics apply a 24-hour freshness window.

The queries can be reproduced using:

`python scripts/run_query.py test_iocs.db 01_total_unique_ips.sql`

Replace the database path and query filename as required.

## 3. Test Database Results

The five queries were previously executed against `test_iocs.db`.

| Metric | Test result |
|---|---:|
| Unique valid IPs | 1 |
| Public unique IPs | 1 |
| IPs with valid reputation | 0 |
| IPs with abuse reports | 0 |
| Malicious SHA-256 hashes | 0 |

**Important:** These values are test database results only. They must not be presented as real-world threat statistics or production measurements.

Production metrics must be recalculated using the actual operational database.

## 4. Final IOC List Review

The exported IOC file is:

`output/iocs.csv`

The reviewed export contains:

| IOC Type | Count |
|---|---:|
| IP | 1 |
| SHA-256 | 1 |
| URL | 1 |
| **Total** | **3** |

The CSV includes the following fields:

- `type`
- `value`
- `first_seen`
- `last_seen`
- `sources`
- `confidence`

All three reviewed indicators currently have `unknown` confidence.

A fresh export from `test_iocs.db` was compared with the existing CSV, and no differences were found.

This confirms export reproducibility for the test database, but does not establish that the indicators are malicious or that the file represents the latest production data.

## 5. Enrichment Limitations

The current AbuseIPDB response mapping extracts:

- Abuse confidence score
- Total reports
- Last reported timestamp
- Tor status

Country and ISP information are not currently extracted by the reviewed implementation. Therefore, country and ISP rankings cannot be reported reliably at this stage.

Missing API responses or unavailable reputation data must not be interpreted as evidence that an indicator is harmless.

## 6. Reproducibility and Validation

The SQL queries are stored independently under `scripts/queries/` so that metrics can be recalculated.

The dedicated tests for `05_malicious_sha256_hashes.sql` passed:

**4 tests passed.**

The tests cover valid malicious hash counting, invalid responses, malformed JSON, expired cache entries, and unobserved hashes.

## 7. Remaining Acceptance Steps

The following steps remain before final acceptance:

1. Recalculate all metrics using the operational database when it becomes available.
2. Confirm the final IOC list against the latest operational dataset.
3. Submit the SQL queries and report metrics to Member 5 for independent verification.
4. Complete the cross-member review of five AI-generated statements after Member 4 provides the validation dataset.

The AI validation review is a coordination task and does not block the completion of Member 3's independent implementation work.