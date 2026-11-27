// Package osv parses OSV-schema records. GitHub Advisories (GHSA) are published in the
// same schema, so the same parser is used with a different source name.
package osv

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/cvss"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/normalize"
)

type rawRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Purl      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string        `json:"type"`
			Repo   string        `json:"repo"`
			Events []model.Event `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		CWEIDs []string `json:"cwe_ids"`
	} `json:"database_specific"`
}

// Parse converts one OSV JSON document into a normalized record. A malformed document
// yields normalize.ErrFormat; an invalid record yields its first normalize.Rejection.
func Parse(source string, data []byte) (*model.Record, error) {
	rec, rej, err := ParseAt(source, data, time.Time{})
	if err != nil {
		return nil, err
	}
	if len(rej) > 0 {
		return nil, rej[0]
	}
	return rec, nil
}

// ParseAt is Parse with the retrieval time, used as the withdrawal time when the
// document is marked withdrawn without a usable timestamp. On rejection the record is nil.
func ParseAt(source string, data []byte, retrieved time.Time) (*model.Record, []normalize.Rejection, error) {
	var r rawRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, nil, normalize.Format(source, err)
	}
	rec := &model.Record{
		Source:    source,
		ID:        model.NormID(r.ID),
		Summary:   r.Summary,
		Details:   r.Details,
		Published: model.ParseTime(r.Published),
		Modified:  model.ParseTime(r.Modified),
		Withdrawn: model.ParseTime(r.Withdrawn),
	}
	if strings.TrimSpace(r.Withdrawn) != "" {
		rec.Withdrawn = normalize.WithdrawnAt(rec.Withdrawn, retrieved)
	}
	for _, a := range r.Aliases {
		if a = model.NormID(a); a != "" && a != rec.ID {
			rec.Aliases = append(rec.Aliases, a)
		}
	}
	sort.Strings(rec.Aliases)

	for _, w := range r.DatabaseSpecific.CWEIDs {
		rec.Weaknesses = append(rec.Weaknesses, strings.ToUpper(strings.TrimSpace(w)))
	}
	for _, s := range r.Severity {
		sev := model.Severity{Source: source, Type: s.Type, Vector: s.Score, Version: cvss.Version(s.Score)}
		sev.Score, sev.Validation, sev.Reason = cvss.Assess(s.Score, nil)
		rec.Severities = append(rec.Severities, sev)
	}
	for _, a := range r.Affected {
		if a.Package.Name == "" {
			continue
		}
		af := model.Affected{Kind: "package", Ecosystem: a.Package.Ecosystem, Name: a.Package.Name, Purl: a.Package.Purl, Versions: a.Versions}
		for _, rg := range a.Ranges {
			af.Ranges = append(af.Ranges, model.Range{Type: rg.Type, Repo: rg.Repo, Events: rg.Events})
			if rg.Type == "GIT" {
				for _, e := range rg.Events {
					if e.Fixed != "" && rg.Repo != "" {
						rec.Fixes = append(rec.Fixes, model.Fix{Repo: rg.Repo, Commit: e.Fixed})
					}
				}
			}
		}
		rec.Affected = append(rec.Affected, af)
	}
	for _, ref := range r.References {
		if ref.URL != "" {
			rec.References = append(rec.References, model.Reference{Type: strings.ToUpper(ref.Type), URL: ref.URL})
		}
	}
	if rej := normalize.Apply(rec); len(rej) > 0 {
		return nil, rej, nil
	}
	return rec, nil, nil
}
