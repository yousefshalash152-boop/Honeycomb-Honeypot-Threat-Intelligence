-- Query 01: Total unique valid observed IP addresses
-- IPs are normalized to canonical form before counting.

SELECT COUNT(DISTINCT normalize_ip(src_ip)) AS total_unique_ips
FROM events
WHERE normalize_ip(src_ip) IS NOT NULL;