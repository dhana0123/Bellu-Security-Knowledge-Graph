package osv

// Licenses is the licence and attribution of the data OSV.dev serves per
// ecosystem, taken on 2026-11-21 from https://google.github.io/osv.dev/data/
// (the page lists the licence of each source database). OSV.dev has no single
// licence for the aggregate and a record carries no licence field; the licence
// follows the id prefix of the record (see PrefixLicenses). The value is kept
// in the Checkpoint after the first complete run of the ecosystem
// (Requirement 14.5).
var Licenses = map[string]string{
	"npm":            "CC-BY-4.0 (GHSA-* from GitHub Advisory Database); Apache-2.0 (MAL-* from OpenSSF Malicious Packages)",
	"PyPI":           "CC-BY-4.0 (PYSEC-* from PyPI Advisory Database, GHSA-* from GitHub Advisory Database); Apache-2.0 (MAL-* from OpenSSF Malicious Packages)",
	"Go":             "CC-BY-4.0 (GO-* from Go Vulnerability Database, GHSA-* from GitHub Advisory Database)",
	"Maven":          "CC-BY-4.0 (GHSA-* from GitHub Advisory Database)",
	"crates.io":      "CC0-1.0 (RUSTSEC-* from Rust Advisory Database); CC-BY-4.0 (GHSA-* from GitHub Advisory Database); Apache-2.0 (MAL-*)",
	"RubyGems":       "CC-BY-4.0 (GHSA-* from GitHub Advisory Database); Apache-2.0 (MAL-*)",
	"NuGet":          "CC-BY-4.0 (GHSA-* from GitHub Advisory Database); Apache-2.0 (MAL-*)",
	"Packagist":      "CC-BY-4.0 (GHSA-* from GitHub Advisory Database); Apache-2.0 (MAL-*)",
	"Pub":            "CC-BY-4.0 (GHSA-* from GitHub Advisory Database)",
	"Hex":            "CC-BY-4.0 (EEF-* from Erlang Ecosystem Foundation CNA, GHSA-* from GitHub Advisory Database)",
	"GitHub Actions": "CC-BY-4.0 (GHSA-* from GitHub Advisory Database)",
	"SwiftURL":       "CC-BY-4.0 (GHSA-* from GitHub Advisory Database)",
}

// PrefixLicenses maps the id prefix of an OSV record to the licence of its
// source database, as listed on the OSV.dev data sources page.
var PrefixLicenses = map[string]string{
	"GHSA":    "CC-BY-4.0",
	"PYSEC":   "CC-BY-4.0",
	"GO":      "CC-BY-4.0",
	"RUSTSEC": "CC0-1.0",
	"MAL":     "Apache-2.0",
	"EEF":     "CC-BY-4.0",
	"OSV":     "CC-BY-4.0",
	"GSD":     "CC0-1.0",
}
