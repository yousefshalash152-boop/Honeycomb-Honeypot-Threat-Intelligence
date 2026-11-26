-- Query 02: Total unique public global IP addresses
-- IPs are normalized to canonical form before counting.
-- Global classification follows Python ipaddress.ip_address(value).is_global.

SELECT COUNT(DISTINCT normalize_ip(src_ip)) AS public_unique_ips
FROM events
WHERE is_global_ip(src_ip) = 1;