// Category 7: full-text search on description. Params: query (Lucene text).
CALL db.index.fulltext.queryNodes("VulnerabilityDescriptionFullTextSchema", $query) YIELD node, score
RETURN node.cveID AS cveID
ORDER BY score DESC, cveID
LIMIT 20
