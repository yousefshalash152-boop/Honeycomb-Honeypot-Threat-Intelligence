
import argparse
import ipaddress
import sqlite3
import sys
from pathlib import Path
from contextlib import closing


PROJECT_ROOT = Path(__file__).resolve().parent.parent
QUERIES_DIR = PROJECT_ROOT / "scripts" / "queries"


def is_valid_ip(value):
    """Return 1 if value is a valid IP address, otherwise 0."""
    if not isinstance(value, str):
        return 0

    try:
        ipaddress.ip_address(value.strip())
        return 1
    except ValueError:
        return 0
def normalize_ip(value):
    """Return the canonical IP address, or None if invalid."""
    if not isinstance(value, str):
        return None

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None

def is_global_ip(value):
    """Return 1 if value is a valid global IP address, otherwise 0."""
    if not isinstance(value, str):
        return 0

    try:
        return int(ipaddress.ip_address(value.strip()).is_global)
    except ValueError:
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Run a saved Honeycomb SQL query."
    )
    parser.add_argument("db", help="Path to SQLite database")
    parser.add_argument("query", help="SQL filename inside scripts/queries")
    args = parser.parse_args()

    db_path = Path(args.db).resolve()
    query_path = (QUERIES_DIR / args.query).resolve()

    if not db_path.is_file():
        parser.error(f"Database file not found: {db_path}")

    if query_path.parent != QUERIES_DIR.resolve():
        parser.error("Query must be a file directly inside scripts/queries")

    if not query_path.is_file() or query_path.suffix.lower() != ".sql":
        parser.error(f"SQL query file not found: {query_path}")

    try:
        sql = query_path.read_text(encoding="utf-8")

        with closing(sqlite3.connect(str(db_path))) as conn:
            conn.create_function("is_valid_ip", 1, is_valid_ip)
            conn.create_function("normalize_ip", 1, normalize_ip)
            conn.create_function("is_global_ip", 1, is_global_ip)

            cursor = conn.execute(sql)
            rows = cursor.fetchall()

            print(f"Query: {query_path.name}")
            for row in rows:
                print(row)

    except (sqlite3.Error, OSError) as exc:
        print(f"Query execution failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
