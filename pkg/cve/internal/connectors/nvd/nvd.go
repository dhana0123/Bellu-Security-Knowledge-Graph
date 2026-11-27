// Package nvd parses NVD API 2.0 / JSON feed 2.0 CVE items.
package nvd

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/cvss"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/normalize"
)

const Source = "nvd"

// Response is the envelope returned by the API and feed files.
type Response struct {
	ResultsPerPage  int               `json:"resultsPerPage"`
	StartIndex      int               `json:"startIndex"`
	TotalResults    int               `json:"totalResults"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type metric struct {
	Source   string `json:"source"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type item struct {
	CVE struct {
		ID           string `json:"id"`
		Published    string `json:"published"`
		LastModified string `json:"lastModified"`
		VulnStatus   string `json:"vulnStatus"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			V40 []metric `json:"cvssMetricV40"`
			V31 []metric `json:"cvssMetricV31"`
			V30 []metric `json:"cvssMetricV30"`
			V2  []metric `json:"cvssMetricV2"`
		} `json:"metrics"`
		Weaknesses []struct {
			Description []struct{ Value string } `json:"description"`
		} `json:"weaknesses"`
		Configurations []struct {
			Nodes []struct {
				CPEMatch []cpeMatch `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
		References []struct {
			URL  string   `json:"url"`
			Tags []string `json:"tags"`
		} `json:"references"`
	} `json:"cve"`
}

var cweRe = regexp.MustCompile(`^CWE-\d+$`)

// Parse converts one vulnerabilities[] item ({"cve":{...}}) into a record. A malformed
// item yields normalize.ErrFormat; an invalid record yields its first normalize.Rejection.
func Parse(data []byte) (*model.Record, error) {
	rec, rej, err := ParseAt(data, time.Time{})
	if err != nil {
		return nil, err
	}
	if len(rej) > 0 {
		return nil, rej[0]
	}
	return rec, nil
}

// ParseResponse parses a whole API/feed envelope. Invalid items are rejected alone;
// a malformed envelope yields normalize.ErrFormat and no records.
func ParseResponse(data []byte, retrieved time.Time) ([]*model.Record, []normalize.Rejection, error) {
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, nil, normalize.Format(Source, err)
	}
	var recs []*model.Record
	var rejs []normalize.Rejection
	for _, raw := range resp.Vulnerabilities {
		rec, rej, err := ParseAt(raw, retrieved)
		if err != nil {
			rejs = append(rejs, normalize.Rejection{Field: "item", Rule: "malformed JSON"})
			continue
		}
		rejs = append(rejs, rej...)
		if rec != nil {
			recs = append(recs, rec)
		}
	}
	return recs, rejs, nil
}

// ParseAt is Parse with the retrieval time, used as the withdrawal time of a rejected CVE
// that has no modification time. On rejection the record is nil.
func ParseAt(data []byte, retrieved time.Time) (*model.Record, []normalize.Rejection, error) {
	var it item
	if err := json.Unmarshal(data, &it); err != nil {
		return nil, nil, normalize.Format(Source, err)
	}
	c := it.CVE
	rec := &model.Record{
		Source: Source, ID: model.NormID(c.ID),
		Published: model.ParseTime(c.Published), Modified: model.ParseTime(c.LastModified),
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			rec.Details = d.Value
			break
		}
	}
	if strings.EqualFold(c.VulnStatus, "Rejected") {
		rec.Withdrawn = normalize.WithdrawnAt(rec.Modified, retrieved)
	}
	add := func(typ string, ms []metric) {
		for _, m := range ms {
			score := m.CVSSData.BaseScore
			sev := model.Severity{Source: Source + ":" + m.Source, Type: typ, Version: m.CVSSData.Version, Vector: m.CVSSData.VectorString}
			sev.Score, sev.Validation, sev.Reason = cvss.Assess(m.CVSSData.VectorString, &score)
			rec.Severities = append(rec.Severities, sev)
		}
	}
	add("CVSS_V4", c.Metrics.V40)
	add("CVSS_V3", c.Metrics.V31)
	add("CVSS_V3", c.Metrics.V30)
	add("CVSS_V2", c.Metrics.V2)

	seen := map[string]bool{}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if cweRe.MatchString(d.Value) && !seen[d.Value] {
				seen[d.Value] = true
				rec.Weaknesses = append(rec.Weaknesses, d.Value)
			}
		}
	}
	for _, ref := range c.References {
		typ := "WEB"
		for _, t := range ref.Tags {
			switch t {
			case "Patch":
				typ = "FIX"
			case "Exploit":
				if typ != "FIX" {
					typ = "EXPLOIT"
				}
			}
		}
		rec.References = append(rec.References, model.Reference{Type: typ, URL: ref.URL})
	}

	idx := map[string]int{}
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				parts := strings.Split(m.Criteria, ":")
				if len(parts) < 6 || parts[0] != "cpe" {
					continue
				}
				vendor, product, ver := parts[3], parts[4], parts[5]
				key := model.ProductID(vendor, product)
				i, ok := idx[key]
				if !ok {
					rec.Affected = append(rec.Affected, model.Affected{Kind: "product", Ecosystem: "cpe", Name: product, Vendor: vendor})
					i = len(rec.Affected) - 1
					idx[key] = i
				}
				a := &rec.Affected[i]
				switch {
				case ver == "-":
				case ver == "*":
					a.Bounds = append(a.Bounds, model.Bound{StartIncl: m.VersionStartIncluding, StartExcl: m.VersionStartExcluding, EndIncl: m.VersionEndIncluding, EndExcl: m.VersionEndExcluding})
				default:
					a.Versions = append(a.Versions, ver)
				}
			}
		}
	}
	if rej := normalize.Apply(rec); len(rej) > 0 {
		return nil, rej, nil
	}
	return rec, nil, nil
}
