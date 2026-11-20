// Category 3: vulnerabilities affecting a Product. Params: productName.
MATCH (v:Vulnerability)-[r:AFFECTS]->(:Product {productName: $productName})
RETURN v.cveID AS cveID, r.numOfVersion AS numOfVersion, r.affectedVersion AS affectedVersion
ORDER BY cveID
LIMIT 100
