// Category 9: filter by CVSS v3 version. Params: v3version (float).
MATCH (v:Vulnerability)
WHERE v.v3version = $v3version
RETURN v.cveID AS cveID
ORDER BY cveID
LIMIT 100
