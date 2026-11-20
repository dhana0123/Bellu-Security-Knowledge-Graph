// Category 1: lookup by cveID. Params: cveID.
MATCH (v:Vulnerability {cveID: $cveID})
RETURN v.cveID AS cveID, toString(v.publishedDate) AS publishedDate, v.numOfReference AS numOfReference,
       v.v3version AS v3version, v.v3baseScore AS v3baseScore, v.exploitability AS exploitability
ORDER BY cveID
LIMIT 10
