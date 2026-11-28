# Threat Intelligence Limitations

## 1. Overview

This document describes the current limitations of the Honeycomb Threat Intelligence component. These limitations are based on the implemented IOC extraction, enrichment, caching, classification, and export logic.

The system provides useful threat intelligence enrichment, but its results depend on the collected events, external API responses, cache freshness, and the availability of supported indicators.

## 2. IOC Extraction Limitations

The IOC extractor currently supports three indicator types:

- IP addresses
- HTTP/HTTPS URLs
- SHA-256 hashes

### 2.1 IP Address Extraction

IP addresses are extracted from the `src_ip` field of recorded events.

The extractor does not search arbitrary event text for IP addresses.

**Example:** An IP address appearing only inside a command string will not be extracted as an IP indicator unless it is also stored in `src_ip`.

Invalid IP addresses are ignored.

### 2.2 URL Extraction

The extractor identifies HTTP and HTTPS URLs from:

- The event `url` field.
- URLs embedded in the `command` field.

Other URL schemes are not covered by the current URL pattern.

**Example:** An FTP URL is not extracted by the current HTTP/HTTPS URL pattern.

### 2.3 SHA-256 Extraction

The extractor reads hashes from the `sha256` field only.

A valid hash must contain exactly 64 hexadecimal characters. Extracted hashes are normalized to lowercase.

**Example:** A hash with fewer or more than 64 characters is ignored.

## 3. External Threat Intelligence Limitations

The system depends on external threat intelligence providers, including AbuseIPDB and VirusTotal.

### 3.1 Provider and Indicator Coverage

The current integration does not support every indicator type through every provider.

- AbuseIPDB is used for public IP reputation.
- VirusTotal supports the implemented IP and SHA-256 lookup paths.
- Unsupported indicator types cannot be enriched through these lookup paths.

**Example:** A URL extracted from a Cowrie event does not automatically receive the same reputation lookup as a supported IP or SHA-256 indicator.

### 3.2 API Dependency

External enrichment depends on valid API credentials and successful provider communication.

Missing credentials, provider errors, timeouts, and rate limits can prevent an indicator from receiving a usable reputation result.

**Example:** If a provider request times out, the system may return an unknown result instead of a reputation classification.

### 3.3 Provider Response Limitations

The system can only classify information that is available in the provider response and supported by the current response parsing logic.

An unknown result does not prove that an indicator is harmless.

**Example:** A hash that is not found by VirusTotal is classified as unknown, not clean.

## 4. Cache and Retry Limitations

### 4.1 Cache Expiration

Cached threat intelligence responses have a 24-hour validity period.

Responses that are expired or have timestamps in the future are not returned as valid cached results.

**Example:** A cached AbuseIPDB response that is 25 hours old is ignored and requires a new lookup.

### 4.2 Missing Cache Entries

If no cache entry exists for an indicator and provider, the cache lookup returns `None`.

The system therefore needs a provider lookup to obtain new enrichment data.

### 4.3 Retry Handling

The system has retry-queue handling for deferred provider requests.

A queued request is not equivalent to a successful enrichment result. Retry processing depends on the implemented retry execution path.

**Example:** A rate-limited request may remain deferred until its retry time instead of immediately generating a new provider request.

## 5. Hash Classification Limitations

VirusTotal hash classification uses the available analysis statistics.

The exporter can produce the following classifications:

- `malicious`: at least one malicious detection.
- `clean`: no malicious or suspicious detections, with harmless or undetected results available.
- `unknown`: missing, invalid, incomplete, suspicious, or inconclusive response data.

**Example:** A hash with suspicious detections but no malicious detections is classified as unknown.

These classifications represent the provider response available to the system and should not be treated as a guarantee that a file is safe or malicious.

## 6. IOC Export Limitations

The IOC exporter generates a CSV file with the following fields:

- `type`
- `value`
- `first_seen`
- `last_seen`
- `sources`
- `confidence`

### 6.1 Confidence Representation

Confidence values are not a single normalized score across all indicator types.

- IP confidence uses the AbuseIPDB confidence score when available.
- SHA-256 confidence uses the VirusTotal classification.
- Other indicator types may have an unknown confidence value.

**Example:** An IP confidence value such as `80` cannot be directly compared numerically with a SHA-256 value such as `malicious`.

### 6.2 Whitelist Exclusion

Indicators matching the configured team whitelist are excluded from the exported IOC list.

The whitelist supports individual IP addresses and CIDR ranges.

**Example:** If `10.9.0.0/24` is whitelisted, an IP such as `10.9.0.25` is excluded from the export.

### 6.3 Event Timestamp Dependency

The exporter's first-seen and last-seen values depend on timestamps available in the collected events.

If usable event timestamps are unavailable, these fields may be empty.

## 7. Testing and Evaluation Limitations

Automated tests verify implemented behavior using test databases, mocked HTTP responses, and controlled input data.

These tests do not prove that external providers are always available, that provider reputation data is always accurate, or that test results represent the production environment.

**Example:** A successful mocked VirusTotal response verifies the application's response handling, but does not guarantee that a real VirusTotal request will succeed.

Production metrics must be calculated from the operational database and should not be inferred from test databases.

## 8. Conclusion

The current Threat Intelligence component provides IOC extraction, external reputation enrichment, caching, retry handling, hash classification, and CSV export.

Its main limitations are restricted indicator coverage, dependence on external providers, time-limited cached data, provider-dependent classifications, and the quality and completeness of locally collected events.

These limitations should be considered when interpreting threat intelligence results and preparing the final project evaluation.