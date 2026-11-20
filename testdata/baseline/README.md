# Baseline fixture CSVs

Small synthetic VulKG-shaped import files for loader tests (Requirement 22.2). Values are invented. Column headers follow the VulKG deployment script. Files are named by the manifest `scriptName` (the spelling `Vulnerability_`, not the upstream typo `Vulnerabiliy_`), which is also the cache and local-directory name (see `docs/vulkg-notes.md`). Empty fields mean an absent property.

| File (logical name) | Data rows |
| --- | --- |
| `VulnerabilityNodes.csv` | 41 (40 unique cveID) |
| `ExploitNodes.csv` | 15 |
| `Vulnerability_HAS_EXPLOIT_Exploit_relationship.csv` | 18 |
| `WeaknessNodes.csv` | 12 |
| `VulnerabilityNodesAddProperties.csv` | 34 |
| `DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv` | 41 |
| `ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv` | 45 |
| `AffectsAddProperty.csv` | 77 |

## Edge cases

1. **REJECT**: CVE-2019-1007, -1019, -1033 have descriptions starting `** REJECT **`. Step 13 deletes them with their relationships. 1007 and 1019 also carry EXAMPLE_OF, REFERS_TO and AFFECTS (1007: mysql and tomcat; 1019: mysql), and 1007 has an EXPLOITS relationship. 1033 has no relationships.
2. **Duplicate vulnerability row**: CVE-2019-1005 appears twice. `MERGE ... ON CREATE` keeps the first row (`num_reference` 6, not 99, and the "Synthetic flaw 5" description).
3. **Empty fields**: CVE-2019-1001..1004 have no v3 fields. CVE-2019-1031..1040 have no v2 fields. Scores are decimals (for example 9.8, 4.3).
4. **Bare nodes**: CVE-2018-9001, CVE-2018-9002 and CVE-2019-2500 appear only in `VulnerabilityNodesAddProperties.csv`. Step 8 uses `MERGE ... ON MATCH SET` only, so it creates them with `cveID` (plus provenance) and nothing else: no `gainedAccess`, `vulnerabilityType` or `description`. They do not exist yet at steps 5 and 7, so they get no EXPLOITS (40010 -> CVE-2018-9001) and no EXAMPLE_OF. They exist at steps 9 to 12, so CVE-2018-9001 gets a REFERS_TO and CVE-2018-9002 gets an AFFECTS (nginx).
5. **Missing endpoints**:
   - HAS_EXPLOIT: `40008 -> CVE-2019-2999` (no Vulnerability), `49999 -> CVE-2019-1011` (no Exploit), `40010 -> CVE-2018-9001` (not yet created at step 5).
   - AddProperties CWE ids not in `WeaknessNodes.csv`: `CWE-502`, `NVD-CWE-Other`, `NVD-CWE-noinfo`, and the three bare-node rows (CVE-2018-9001, CVE-2018-9002, CVE-2019-2500), whose CWE ids exist but whose Vulnerability does not exist yet at step 7.
   - Domain rows for CVE-2019-7777 and CVE-2019-7778 (no Vulnerability). Their Domain nodes are still created.
   - Product rows for CVE-2019-6666 and CVE-2019-6667. Their Product and Vendor nodes are still created. `orphan_product`/`orphan_vendor` exist only through the first.
   - AffectsAddProperty rows for pair `(CVE-2019-5555, openssl)` and `(CVE-2019-1001, no_such_product)`.
6. **Duplicate product rows**: pair `(CVE-2019-1001, openssl)` appears twice, first `Application`/3, then `Operating System`/5. First row wins, so AFFECTS `numOfVersion` = 3. Pair `(CVE-2019-1002, openssl)` has `Hardware`/2: a new AFFECTS with `numOfVersion` 2, while Product `openssl` keeps `productType` `Application` (set by its first row).
7. **Shared product, two vendors**: `linux_kernel` belongs to `linux` and `debian` (two BELONGS_TO).
8. **Multi-version AffectsAddProperty**: versions per pair run from 1 to 4 and are interleaved with other pairs in the file. Pair `(CVE-2019-1001, http_server)` repeats version `1.0.1` (kept as a duplicate: `["1.0.1","1.0.1"]`). Pair `(CVE-2019-1004, firefox)` gets `["1.0.1","1.0.2","1.0.3","1.0.4"]`. AFFECTS pairs with no rows (for example `(CVE-2019-1001, openssl)`) get `[]` after step 12.
9. **Duplicates deduplicated by MERGE**: HAS_EXPLOIT `(40007, CVE-2019-1010)` twice; CVE-2019-1008 twice in the add-properties file (CWE-287 then CWE-89, so two EXAMPLE_OF edges, and `gainedAccess`/`vulnerabilityType` come from the last row: `Gain Privileges`, `["Bypass"]`).
10. **Author reuse**: 15 exploits, 10 authors. Exploit 40002 (2019-09-20) and 40003 (2019-02-11) both exploit CVE-2019-1002, so `exploitDate` is `[2019-02-11, 2019-09-20]` (ascending). Exploit 40015 exploits two CVEs (1022, 1023).

## Expected counts after a faithful load (all 14 steps)

Counts below were computed by a model of the VulKG MERGE semantics in the design, not by running Neo4j. Verify them against the first real fixture load.

### Final graph

| Item | Count |
| --- | --- |
| Vulnerability | 40 (43 after step 8, minus 3 REJECT) |
| Exploit | 15 |
| Author | 10 |
| Weakness | 12 |
| Domain | 9 (includes `orphan-domain.example.com`) |
| Product | 14 |
| Vendor | 13 |
| WRITES | 15 |
| EXPLOITS | 13 (14 at step 5; the one on REJECT CVE-2019-1007 is deleted) |
| EXAMPLE_OF | 26 (28 at step 7) |
| REFERS_TO | 37 (39 at step 9) |
| AFFECTS | 37 (40 at step 10; 3 on REJECT CVEs deleted) |
| BELONGS_TO | 15 |
| `exploitability = 1` | 12 (CVE-2019-1001, 1002, 1003, 1005, 1006, 1010, 1012, 1015, 1020, 1021, 1022, 1023) |
| `exploitability = 0` | 28 |
| AFFECTS with non-empty / empty `affectedVersion` | 28 / 9 (of 37) |

Bare Vulnerability nodes created by step 8: **3**. REJECT nodes deleted by step 13: **3**.

### Missing-endpoint row counts (rows whose MATCH failed)

| Step | Rows |
| --- | --- |
| 5 `exploits_rel` | 3 |
| 7 `example_of` | 6 |
| 9 `domain_refers` | 2 |
| 10 `product_affects` | 2 |
| 11 `vendor_belongs` | 0 |
| 12 `affected_version` | 2 |

### Exact property expectations

- `Product.productType`: `openssl`, `http_server`, `chrome`, `firefox`, `flash_player`, `jenkins`, `mysql`, `tomcat`, `wordpress`, `nginx`, `orphan_product` = `Application`; `linux_kernel`, `windows_10` = `Operating System`; `big-ip` = `Hardware`.
- AFFECTS `numOfVersion`: `(1001, openssl)` = 3, `(1002, openssl)` = 2, `(1002, linux_kernel)` = 3, `(2018-9002, nginx)` = 1.
- `exploitDate`: CVE-2019-1002 = `[2019-02-11, 2019-09-20]`, CVE-2019-1022 = CVE-2019-1023 = `[2019-05-14]`; vulnerabilities without exploits have `[]`.

These fixtures were produced by a one-off generator. Do not edit them by hand without recomputing the counts above.
