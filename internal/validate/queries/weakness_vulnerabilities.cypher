// Category 2: vulnerabilities of a Weakness. Params: cweID.
MATCH (v:Vulnerability)-[:EXAMPLE_OF]->(:Weakness {cweID: $cweID})
RETURN DISTINCT v.cveID AS cveID
ORDER BY cveID
LIMIT 100
