package api

import "net/http"

// sourceInfo is one row of GET /v1/sources.
type sourceInfo struct {
	Name        string `json:"name"`
	License     string `json:"license"`
	Attribution string `json:"attribution"`
}

// sourceList is a constant copy of the License and Attribution columns of
// docs/sources.md. Name is the source id used in the "sources" arrays of the
// entity routes. Update both places together. "TODO" cells in the document
// are sent as "Not recorded yet".
var sourceList = []sourceInfo{
	{
		Name: "cwe",
		License: "CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html): non-exclusive, royalty-free license for research, " +
			"development, and commercial purposes, on the condition that MITRE's copyright designation and the license are reproduced in any copy",
		Attribution: "Not recorded yet",
	},
	{Name: "nvd", License: "NVD API Terms of Use (https://nvd.nist.gov/developers/terms-of-use)", Attribution: "This product uses the NVD API but is not endorsed or certified by the NVD."},
	{
		Name:        "exploitdb",
		License:     "GNU General Public License v2.0 (README and LICENSE.md of the repository)",
		Attribution: "Exploit Database, Offensive Security, https://www.exploit-db.com",
	},
	{Name: "attack", License: "ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/): non-exclusive, royalty-free license for research, development, and commercial purposes, provided MITRE's copyright designation and the license are reproduced", Attribution: "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."},
	{Name: "atlas", License: "Apache License 2.0 (LICENSE of the atlas-data repository, Copyright 2021-2026 MITRE)", Attribution: "MITRE ATLAS, Copyright 2021-2026 MITRE, licensed under the Apache License 2.0"},
	{Name: "capec", License: "CAPEC Terms of Use (https://capec.mitre.org/about/termsofuse.html): non-exclusive, royalty-free license for research, development, and commercial purposes, provided MITRE's copyright designation and the license are reproduced", Attribution: "CAPEC™, The MITRE Corporation (https://capec.mitre.org), reproduced under the CAPEC Terms of Use"},
	{Name: "kev", License: "CC0 1.0 Universal (https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)", Attribution: "Source: CISA Known Exploited Vulnerabilities Catalog. Use does not imply CISA endorsement; the CISA logo and DHS seal are not used."},
	{Name: "epss", License: "Published free of charge without registration; no formal licence text found. The FIRST EPSS FAQ states the data is free to use and asks for attribution", Attribution: "EPSS scores are provided by the EPSS Special Interest Group at FIRST (https://www.first.org/epss)."},
	{Name: "osv", License: "Per source database: CC-BY-4.0 (GHSA, PyPI PYSEC, Go GO, Erlang EEF, OSS-Fuzz OSV); CC0-1.0 (RustSec, GSD); Apache-2.0 (OpenSSF Malicious Packages MAL)", Attribution: "Contains data from OSV.dev (https://osv.dev) and its source databases, under their licences (CC BY 4.0, CC0 1.0, Apache 2.0); records were transformed into the BSKG graph."},
	{Name: "ghsa", License: "CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/), per the advisory-database README and LICENSE.md", Attribution: "Contains data from the GitHub Advisory Database (https://github.com/advisories), CC BY 4.0, GitHub, Inc.; records were transformed into the BSKG graph."},
}

func (e *Entities) sourcesHandler(w http.ResponseWriter, r *http.Request) {
	e.s.WriteJSON(w, r, http.StatusOK, map[string]any{"sources": sourceList})
}
