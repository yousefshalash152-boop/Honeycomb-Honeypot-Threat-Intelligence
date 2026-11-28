-- Query 04: Public IPs with actual AbuseIPDB reports
-- Cache validity: 24 hours
-- Malformed JSON responses are safely excluded.

SELECT COUNT(DISTINCT normalize_ip(indicator))
       AS ips_with_abuse_reports
FROM intel_cache
WHERE source = 'AbuseIPDB'
  AND is_global_ip(indicator) = 1
  AND julianday(queried_at) >= julianday('now', '-24 hours')
  AND julianday(queried_at) <= julianday('now')
  AND CASE
      WHEN json_valid(response) = 1 THEN
          CASE
              WHEN json_type(response, '$.error') IS NULL
               AND json_type(response, '$.abuse_confidence_score')
                   IN ('integer', 'real')
               AND json_extract(response, '$.abuse_confidence_score')
                   BETWEEN 0 AND 100
               AND json_type(response, '$.total_reports') = 'integer'
               AND json_extract(response, '$.total_reports') > 0
              THEN 1
              ELSE 0
          END
      ELSE 0
  END = 1;