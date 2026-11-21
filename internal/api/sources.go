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
	{Name: "nvd", License: "Not recorded yet", Attribution: "Not recorded yet"},
	{
		Name:        "exploitdb",
		License:     "GNU General Public License v2.0 (README and LICENSE.md of the repository)",
		Attribution: "Exploit Database, Offensive Security, https://www.exploit-db.com",
	},
}

func (e *Entities) sourcesHandler(w http.ResponseWriter, r *http.Request) {
	e.s.WriteJSON(w, r, http.StatusOK, map[string]any{"sources": sourceList})
}
