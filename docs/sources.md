# Data sources

Each enabled adapter needs a complete row. Fields: name, URL, license or
terms, attribution text, permitted use, verification date (YYYY-MM-DD). The
verification date is the day the terms were read from the source itself
(Requirement 29.6). VulKG is a model credit (see `NOTICE`), not a data source.

| Name | URL | License | Attribution | Permitted use | Verified on |
| --- | --- | --- | --- | --- | --- |
| MITRE CWE | https://cwe.mitre.org/data/ | CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html): non-exclusive, royalty-free license for research, development, and commercial purposes, on the condition that MITRE's copyright designation and the license are reproduced in any copy | TODO (the exact MITRE copyright designation is not on the terms page; read it from the catalog download page before filling) | Research, development, and commercial use, with the license and copyright designation reproduced | 2026-11-21 |
| NVD | https://services.nvd.nist.gov/rest/json/cves/2.0 | TODO | TODO | TODO | TODO |
| Exploit-DB | https://gitlab.com/exploit-database/exploitdb (file `files_exploits.csv` only) | GNU General Public License v2.0 (README and LICENSE.md of the repository) | Exploit Database, Offensive Security, https://www.exploit-db.com | metadata only: id, date published, author, type, platform, CVE codes; no description text, no exploit code, no file paths; source URL built from the id and kept in Provenance only | 2026-11-21 |
