
import csv
import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path

from honeycomb.src.analysis.threat_intel import check_virustotal


SHA256_LENGTH = 64


def _valid_sha256(value):
    if not isinstance(value, str):
        return False

    value = value.strip().lower()

    return (
        len(value) == SHA256_LENGTH
        and all(char in "0123456789abcdef" for char in value)
    )


def _detect_file_type(header):
    """Identify common file types using content signatures."""
    signatures = [
        (b"\x7fELF", "ELF executable"),
        (b"MZ", "Windows executable"),
        (b"%PDF-", "PDF document"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"\x1f\x8b", "GZIP archive"),
    ]

    for signature, file_type in signatures:
        if header.startswith(signature):
            return file_type

    if header.startswith(b"#!"):
        return "Script"

    if b"\x00" not in header:
        try:
            header.decode("utf-8")
            return "Text file"
        except UnicodeDecodeError:
            pass

    return "Unknown binary file"


def _inspect_file(file_path):
    """Inspect a regular file without executing it."""
    before = file_path.lstat()

    if stat.S_ISLNK(before.st_mode):
        raise ValueError("Symbolic links are not allowed")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)

    fd = os.open(file_path, flags)

    with os.fdopen(fd, "rb") as file:
        opened = os.fstat(file.fileno())

        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("Not a regular file")

        if (
            before.st_ino != opened.st_ino
            or before.st_dev != opened.st_dev
        ):
            raise ValueError("File changed before inspection")

        digest = hashlib.sha256()

        header = file.read(8192)
        digest.update(header)

        for chunk in iter(
            lambda: file.read(1024 * 1024), b""
        ):
            digest.update(chunk)

        after = os.fstat(file.fileno())

        if (
            opened.st_size != after.st_size
            or opened.st_mtime_ns != after.st_mtime_ns
            or opened.st_ctime_ns != after.st_ctime_ns
            or opened.st_ino != after.st_ino
        ):
            raise OSError("File changed during inspection")

        return {
            "file_size": after.st_size,
            "file_type": _detect_file_type(header),
            "actual_sha256": digest.hexdigest(),
        }


def _add_virustotal_result(result, db_path):
    """Add VirusTotal information using the existing cached API client."""
    hash_to_check = (
        result["actual_sha256"] or result["logged_sha256"]
    )

    if not hash_to_check:
        return

    result["vt_hash"] = hash_to_check

    vt_result = check_virustotal(
        "sha256",
        hash_to_check,
        db_path=str(Path(db_path).resolve()),
    )

    if vt_result.get("found") is True:
        result["vt_status"] = "found"
        result["vt_found"] = True
        result["vt_malicious"] = vt_result.get("malicious", 0)
        result["vt_suspicious"] = vt_result.get("suspicious", 0)
        result["vt_harmless"] = vt_result.get("harmless", 0)

    elif vt_result.get("found") is False:
        result["vt_status"] = "not_found"
        result["vt_found"] = False

    else:
        result["vt_status"] = "unknown"
        result["vt_error"] = vt_result.get(
            "error", "VirusTotal result unavailable"
        )


def inspect_downloads(db_path, files_dir=None):
    """
    Extract Cowrie file-download events and inspect matching files.

    files_dir must be a dedicated directory containing files
    that are safe to inspect. Files are never executed.
    """
    results = []

    root = Path(files_dir).resolve() if files_dir else None

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT event_id, event_type, session_id,
                   url, sha256, raw_json
            FROM events
            WHERE event_type = 'cowrie.session.file_download'
            ORDER BY ts_utc
            """
        ).fetchall()

    for row in rows:
        try:
            event = json.loads(row["raw_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            event = {}

        raw_filename = event.get("outfile")

        filename = (
            Path(raw_filename.replace("\\", "/")).name
            if isinstance(raw_filename, str) and raw_filename.strip()
            else None
        )

        logged_hash = row["sha256"]

        if not _valid_sha256(logged_hash):
            logged_hash = None
        else:
            logged_hash = logged_hash.strip().lower()

        result = {
            "event_id": row["event_id"],
            "session_id": row["session_id"],
            "filename": filename,
            "url": row["url"],
            "logged_sha256": logged_hash,
            "file_status": "not_checked",
            "file_size": None,
            "file_type": None,
            "actual_sha256": None,
            "hash_matches": None,
            "vt_hash": None,
            "vt_status": "not_checked",
            "vt_found": None,
            "vt_malicious": None,
            "vt_suspicious": None,
            "vt_harmless": None,
            "vt_error": None,
        }

        if root is not None:
            if not filename:
                result["file_status"] = "invalid_filename"
            else:
                candidate = root / filename

                try:
                    if candidate.is_symlink():
                        result["file_status"] = "unsafe_path"
                    else:
                        resolved = candidate.resolve(strict=True)

                        if not resolved.is_relative_to(root):
                            result["file_status"] = "unsafe_path"

                        elif not resolved.is_file():
                            result["file_status"] = "not_a_file"

                        else:
                            metadata = _inspect_file(resolved)

                            result.update(metadata)
                            result["file_status"] = "available"

                            if logged_hash:
                                result["hash_matches"] = (
                                    result["actual_sha256"] == logged_hash
                                )

                except FileNotFoundError:
                    result["file_status"] = "missing"

                except ValueError:
                    result["file_status"] = "unsafe_file"

                except OSError:
                    result["file_status"] = "inspection_error"

        _add_virustotal_result(result, db_path)
        results.append(result)

    return results


def export_file_report_csv(results, output_path):
    """Export file inspection and VirusTotal results to CSV."""
    fieldnames = [
        "event_id",
        "session_id",
        "filename",
        "url",
        "logged_sha256",
        "file_status",
        "file_size",
        "file_type",
        "actual_sha256",
        "hash_matches",
        "vt_hash",
        "vt_status",
        "vt_found",
        "vt_malicious",
        "vt_suspicious",
        "vt_harmless",
        "vt_error",
    ]

    with Path(output_path).open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    return len(results)
