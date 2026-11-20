// Category 4: products of a Vendor. Params: vendorName.
MATCH (p:Product)-[:BELONGS_TO]->(:Vendor {vendorName: $vendorName})
RETURN p.productName AS productName, p.productType AS productType
ORDER BY productName
LIMIT 100
