
import os
import ipaddress
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

from honeycomb.src.storage.intel_cache import (
    get_cached_response,
    save_cached_response,
    enqueue_retry,
    get_pending_retries,
    remove_retry,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"


def _get_with_rate_limit(url, **kwargs):
    """Retry once after a short numeric Retry-After delay."""
    response = requests.get(url, **kwargs)

    if response.status_code != 429:
        return response

    retry_after = response.headers.get("Retry-After")

    try:
        delay = float(retry_after)
    except (TypeError, ValueError):
        return response

    if delay < 0 or delay > 60:
        return response

    time.sleep(delay)
    return requests.get(url, **kwargs)


def check_api_keys():
    """Check whether the required API keys are configured."""
    return {
        "abuseipdb_configured": bool(ABUSEIPDB_API_KEY),
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
    }


def _get_cached(db_path, indicator, source):
    """Return a valid cached response, if available."""
    if not db_path:
        return None

    try:
        return get_cached_response(db_path, indicator, source)
    except Exception:
        return None


def _save_cached(db_path, indicator, source, response):
    """Save a response without interrupting enrichment."""
    if not db_path:
        return

    try:
        save_cached_response(db_path, indicator, source, response)
    except Exception:
        pass


def _retry_is_deferred(db_path, indicator, source):
    """Check whether a queued request must wait before being retried."""
    if not db_path:
        return False

    try:
        pending = get_pending_retries(db_path)
    except Exception:
        return False

    for item in pending:
        if (
            item.get("indicator") != indicator
            or item.get("source") != source
        ):
            continue

        retry_after = item.get("retry_after")
        updated_at = item.get("updated_at")

        try:
            now = datetime.now(timezone.utc)
            retry_text = str(retry_after or "").strip()

            try:
                delay = float(retry_text)
                if delay < 0:
                    delay = 60

                updated = datetime.fromisoformat(updated_at)
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)

                elapsed = (now - updated).total_seconds()
                return elapsed < delay

            except ValueError:
                try:
                    retry_time = parsedate_to_datetime(retry_text)
                    if retry_time.tzinfo is None:
                        retry_time = retry_time.replace(
                            tzinfo=timezone.utc
                        )
                    return now < retry_time

                except (TypeError, ValueError, OverflowError):
                    updated = datetime.fromisoformat(updated_at)
                    if updated.tzinfo is None:
                        updated = updated.replace(tzinfo=timezone.utc)
                    return (
                        now - updated
                    ).total_seconds() < 60

        except (TypeError, ValueError, KeyError, OverflowError):
            return True

    return False


def _queue_rate_limit(
    db_path, indicator, source, ioc_type, response
):
    """Queue an indicator when the API rate limit is reached."""
    if not db_path:
        return

    retry_after = response.headers.get("Retry-After", "60")

    try:
        enqueue_retry(
            db_path,
            indicator,
            source,
            ioc_type,
            retry_after=retry_after,
            last_error="HTTP 429",
        )
    except Exception:
        pass


def _clear_retry(db_path, indicator, source):
    """Remove a queued request after a successful lookup."""
    if not db_path:
        return

    try:
        remove_retry(db_path, indicator, source)
    except Exception:
        pass


def check_ip_abuseipdb(
    ip_address: str,
    db_path: str = None,
) -> dict:
    """Check a public IP using AbuseIPDB and a 24-hour cache."""
    try:
        parsed_ip = ipaddress.ip_address(ip_address.strip())
    except (ValueError, AttributeError):
        return {
            "source": "AbuseIPDB",
            "error": "Invalid IP address",
        }

    if not parsed_ip.is_global:
        return {
            "source": "AbuseIPDB",
            "ip": str(parsed_ip),
            "error": "IP is not a public global address",
        }

    indicator = str(parsed_ip)

    cached = _get_cached(db_path, indicator, "AbuseIPDB")
    if cached is not None:
        return cached

    if _retry_is_deferred(db_path, indicator, "AbuseIPDB"):
        return {
            "source": "AbuseIPDB",
            "ip": indicator,
            "error": "Retry deferred",
            "status": "unknown",
        }

    if not ABUSEIPDB_API_KEY:
        return {
            "source": "AbuseIPDB",
            "error": "API key is not configured",
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": indicator,
        "maxAgeInDays": 90,
    }

    try:
        response = _get_with_rate_limit(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=15,
        )

        if response.status_code == 429:
            _queue_rate_limit(
                db_path, indicator, "AbuseIPDB", "ip", response
            )
            return {
                "source": "AbuseIPDB",
                "ip": indicator,
                "error": "Rate limited (HTTP 429)",
                "status": "unknown",
                "retry_after": response.headers.get("Retry-After"),
            }

        response.raise_for_status()
        data = response.json()["data"]

        result = {
            "source": "AbuseIPDB",
            "ip": indicator,
            "abuse_confidence_score": data.get(
                "abuseConfidenceScore"
            ),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "is_tor": data.get("isTor"),
        }

        _clear_retry(db_path, indicator, "AbuseIPDB")
        _save_cached(db_path, indicator, "AbuseIPDB", result)
        return result

    except requests.Timeout:
        return {
            "source": "AbuseIPDB",
            "ip": indicator,
            "error": "Request timed out",
            "status": "unknown",
        }
    except requests.RequestException:
        return {
            "source": "AbuseIPDB",
            "ip": indicator,
            "error": "AbuseIPDB request failed",
            "status": "unknown",
        }
    except (ValueError, KeyError, TypeError):
        return {
            "source": "AbuseIPDB",
            "ip": indicator,
            "error": "Unexpected AbuseIPDB response",
            "status": "unknown",
        }


def check_virustotal(
    ioc_type: str,
    value: str,
    db_path: str = None,
) -> dict:
    """Look up an indicator in VirusTotal with caching."""
    if not isinstance(value, str):
        return {
            "source": "VirusTotal",
            "error": "Invalid indicator value",
        }

    value = value.strip()

    if ioc_type == "ip":
        try:
            parsed_ip = ipaddress.ip_address(value)
        except ValueError:
            return {
                "source": "VirusTotal",
                "error": "Invalid IP address",
            }

        if not parsed_ip.is_global:
            return {
                "source": "VirusTotal",
                "error": "IP is not a public global address",
            }

        value = str(parsed_ip)
        endpoint = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{value}"
        cache_indicator = f"ip:{value}"

    elif ioc_type == "sha256":
        if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            return {
                "source": "VirusTotal",
                "error": "Invalid SHA-256 hash",
            }

        value = value.lower()
        endpoint = f"{VIRUSTOTAL_BASE_URL}/files/{value}"
        cache_indicator = value

    else:
        return {
            "source": "VirusTotal",
            "error": "Unsupported IOC type; use ip or sha256",
        }

    cached = _get_cached(
        db_path,
        cache_indicator,
        "VirusTotal",
    )
    if cached is not None:
        return cached

    if _retry_is_deferred(
        db_path, cache_indicator, "VirusTotal"
    ):
        return {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
            "value": value,
            "error": "Retry deferred",
            "status": "unknown",
        }

    if not VIRUSTOTAL_API_KEY:
        return {
            "source": "VirusTotal",
            "error": "API key is not configured",
        }

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = _get_with_rate_limit(
            endpoint,
            headers=headers,
            timeout=15,
        )

        if response.status_code == 429:
            _queue_rate_limit(
                db_path,
                cache_indicator,
                "VirusTotal",
                ioc_type,
                response,
            )
            return {
                "source": "VirusTotal",
                "ioc_type": ioc_type,
                "value": value,
                "error": "Rate limited (HTTP 429)",
                "status": "unknown",
                "retry_after": response.headers.get("Retry-After"),
            }

        if response.status_code == 404:
            result = {
                "source": "VirusTotal",
                "ioc_type": ioc_type,
                "value": value,
                "found": False,
            }
            _clear_retry(
                db_path, cache_indicator, "VirusTotal"
            )
            _save_cached(
                db_path,
                cache_indicator,
                "VirusTotal",
                result,
            )
            return result

        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})

        result = {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
            "value": value,
            "found": True,
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }

        _clear_retry(
            db_path, cache_indicator, "VirusTotal"
        )
        _save_cached(
            db_path,
            cache_indicator,
            "VirusTotal",
            result,
        )
        return result

    except requests.Timeout:
        return {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
            "value": value,
            "error": "Request timed out",
            "status": "unknown",
        }
    except requests.RequestException:
        return {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
            "value": value,
            "error": "VirusTotal request failed",
            "status": "unknown",
        }
    except (ValueError, KeyError, TypeError):
        return {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
            "value": value,
            "error": "Unexpected VirusTotal response",
            "status": "unknown",
        }
