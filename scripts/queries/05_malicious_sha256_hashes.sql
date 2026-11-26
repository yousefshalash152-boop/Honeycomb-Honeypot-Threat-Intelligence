-- Query 05: Count unique malicious SHA-256 hashes
-- Source: VirusTotal
-- Cache validity: 24 hours
-- A one-second tolerance handles timestamp precision differences.
-- Only observed hashes with valid, fresh VirusTotal results are counted.
-- Malformed JSON and unknown statuses are excluded.
-- Classification follows honeycomb/src/analysis/ioc_export.py::_hash_status.

WITH observed_hashes AS (
    SELECT DISTINCT LOWER(TRIM(sha256)) AS hash
    FROM events
    WHERE sha256 IS NOT NULL
      AND LENGTH(TRIM(sha256)) = 64
      AND LOWER(TRIM(sha256)) NOT GLOB '*[^0-9a-f]*'
),
valid_cache AS (
    SELECT indicator, response, queried_at
    FROM intel_cache
    WHERE source = 'VirusTotal'
      AND julianday(queried_at) >= julianday('now', '-24 hours')
      AND julianday(queried_at) <= julianday('now', '+1 second')
      AND CASE
          WHEN json_valid(response) = 1 THEN
              CASE
                  WHEN json_type(response, '$') = 'object'
                   AND json_extract(response, '$.ioc_type') = 'sha256'
                   AND (
                       json_type(response, '$.found') IS NULL
                       OR json_type(response, '$.found') != 'false'
                   )
                   AND (
                       json_type(response, '$.status') IS NULL
                       OR json_type(response, '$.status') != 'text'
                       OR json_extract(response, '$.status') != 'unknown'
                   )
                   AND json_type(response, '$.last_analysis_stats') = 'object'
                   AND CASE
                       WHEN json_type(response, '$.error') IS NULL
                         OR json_type(response, '$.error') IN ('null', 'false')
                       THEN 1
                       WHEN json_type(response, '$.error') IN ('integer', 'real')
                        AND json_extract(response, '$.error') = 0
                       THEN 1
                       WHEN json_type(response, '$.error') = 'text'
                        AND json_extract(response, '$.error') = ''
                       THEN 1
                       WHEN json_type(response, '$.error') = 'array'
                        AND json_array_length(response, '$.error') = 0
                       THEN 1
                       WHEN json_type(response, '$.error') = 'object'
                        AND NOT EXISTS (
                            SELECT 1
                            FROM json_each(response, '$.error')
                        )
                       THEN 1
                       ELSE 0
                   END = 1
                  THEN 1
                  ELSE 0
              END
          ELSE 0
      END = 1
)
SELECT COUNT(DISTINCT c.indicator) AS malicious_sha256_hashes
FROM valid_cache c
JOIN observed_hashes e
  ON e.hash = c.indicator
WHERE json_valid(c.response) = 1
  AND json_type(
      c.response, '$.last_analysis_stats.malicious'
  ) = 'integer'
  AND json_extract(
      c.response, '$.last_analysis_stats.malicious'
  ) > 0
  AND (
      json_type(c.response, '$.last_analysis_stats.suspicious') IS NULL
      OR (
          json_type(c.response, '$.last_analysis_stats.suspicious') = 'integer'
          AND json_extract(c.response, '$.last_analysis_stats.suspicious') >= 0
      )
  )
  AND (
      json_type(c.response, '$.last_analysis_stats.harmless') IS NULL
      OR (
          json_type(c.response, '$.last_analysis_stats.harmless') = 'integer'
          AND json_extract(c.response, '$.last_analysis_stats.harmless') >= 0
      )
  )
  AND (
      json_type(c.response, '$.last_analysis_stats.undetected') IS NULL
      OR (
          json_type(c.response, '$.last_analysis_stats.undetected') = 'integer'
          AND json_extract(c.response, '$.last_analysis_stats.undetected') >= 0
      )
  )
  AND (
      json_type(c.response, '$.last_analysis_stats.timeout') IS NULL
      OR (
          json_type(c.response, '$.last_analysis_stats.timeout') = 'integer'
          AND json_extract(c.response, '$.last_analysis_stats.timeout') >= 0
      )
  )
  AND (
      json_type(c.response, '$.last_analysis_stats.failure') IS NULL
      OR (
          json_type(c.response, '$.last_analysis_stats.failure') = 'integer'
          AND json_extract(c.response, '$.last_analysis_stats.failure') >= 0
      )
  );
