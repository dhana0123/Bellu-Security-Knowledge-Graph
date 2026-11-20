// Category 8: filter by publishedDate range (inclusive). Params: from, to (ISO dates).
MATCH (v:Vulnerability)
WHERE v.publishedDate >= date($from) AND v.publishedDate <= date($to)
RETURN v.cveID AS cveID, toString(v.publishedDate) AS publishedDate
ORDER BY v.publishedDate, cveID
LIMIT 100
