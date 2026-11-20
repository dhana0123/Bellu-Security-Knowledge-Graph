CREATE CONSTRAINT UniqueCveID IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cveID IS UNIQUE
;
CREATE CONSTRAINT UniqueEID IF NOT EXISTS FOR (e:Exploit) REQUIRE e.eid IS UNIQUE
;
CREATE CONSTRAINT UniqueAuthorName IF NOT EXISTS FOR (a:Author) REQUIRE a.authorName IS UNIQUE
;
CREATE CONSTRAINT UniquecweID IF NOT EXISTS FOR (w:Weakness) REQUIRE w.cweID IS UNIQUE
;
CREATE CONSTRAINT UniqueDomainName IF NOT EXISTS FOR (d:Domain) REQUIRE d.domainName IS UNIQUE
;
CREATE CONSTRAINT UniqueProductName IF NOT EXISTS FOR (p:Product) REQUIRE p.productName IS UNIQUE
;
CREATE CONSTRAINT UniqueVendorName IF NOT EXISTS FOR (vd:Vendor) REQUIRE vd.vendorName IS UNIQUE
;
CREATE INDEX VulnerabilityV2Version IF NOT EXISTS FOR (v:Vulnerability) ON (v.v2version)
;
CREATE INDEX VulnerabilityV3Version IF NOT EXISTS FOR (v:Vulnerability) ON (v.v3version)
;
CREATE INDEX VulnerabilityPublishedDate IF NOT EXISTS FOR (v:Vulnerability) ON (v.publishedDate)
;
CREATE INDEX ExploitPublishDate IF NOT EXISTS FOR (e:Exploit) ON (e.exploitPublishDate)
;
CREATE FULLTEXT INDEX VulnerabilityDescriptionFullTextSchema IF NOT EXISTS FOR (v:Vulnerability) ON EACH [v.description]
