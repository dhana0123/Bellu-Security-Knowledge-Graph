// Package enrich parses the CISA KEV catalogue and EPSS score files.
package enrich

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/normalize"
)

// ParseKEV returns the valid KEV entries; invalid entries are dropped and a malformed
// payload yields normalize.ErrFormat.
func ParseKEV(r io.Reader) ([]model.KEV, error) {
	out, _, err := ParseKEVReport(r)
	return out, err
}

// ParseKEVReport is ParseKEV that also reports the rejected entries.
func ParseKEVReport(r io.Reader) ([]model.KEV, []normalize.Rejection, error) {
	var doc struct {
		Vulns []struct {
			CVE        string `json:"cveID"`
			Vendor     string `json:"vendorProject"`
			Product    string `json:"product"`
			Name       string `json:"vulnerabilityName"`
			DateAdded  string `json:"dateAdded"`
			DueDate    string `json:"dueDate"`
			Action     string `json:"requiredAction"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, nil, normalize.Format("kev", err)
	}
	var rejs []normalize.Rejection
	out := make([]model.KEV, 0, len(doc.Vulns))
	for _, v := range doc.Vulns {
		cve, err := normalize.CanonicalCVE(v.CVE)
		if err != nil {
			rejs = append(rejs, normalize.Rejection{RecordID: v.CVE, Field: "cveID", Rule: "must match CVE-YYYY-NNNN+"})
			continue
		}
		out = append(out, model.KEV{CVE: cve, Vendor: v.Vendor, Product: v.Product, Name: v.Name,
			DateAdded: v.DateAdded, DueDate: v.DueDate, Action: v.Action, Ransomware: model.NormalizeRansomware(v.Ransomware)})
	}
	return out, rejs, nil
}

// ParseEPSS reads the EPSS CSV (optional "#model_version:...,score_date:..." first line).
func ParseEPSS(r io.Reader) ([]model.EPSS, error) {
	out, _, err := ParseEPSSReport(r)
	return out, err
}

// ParseEPSSReport is ParseEPSS that also reports rejected rows. A malformed header or
// CSV structure yields normalize.ErrFormat and no rows.
func ParseEPSSReport(r io.Reader) ([]model.EPSS, []normalize.Rejection, error) {
	br := bufio.NewReader(r)
	date := ""
	if b, err := br.Peek(1); err == nil && b[0] == '#' {
		line, _ := br.ReadString('\n')
		for _, p := range strings.Split(strings.TrimPrefix(strings.TrimSpace(line), "#"), ",") {
			if k, v, ok := strings.Cut(p, ":"); ok && strings.TrimSpace(k) == "score_date" {
				date = strings.TrimSpace(v)
				if len(date) >= 10 {
					date = date[:10]
				}
			}
		}
	}
	cr := csv.NewReader(br)
	header, err := cr.Read()
	if err != nil {
		return nil, nil, normalize.Format("epss", err)
	}
	if len(header) < 3 || header[0] != "cve" {
		return nil, nil, normalize.Format("epss", fmt.Errorf("unexpected EPSS header %v", header))
	}
	var out []model.EPSS
	var rejs []normalize.Rejection
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, normalize.Format("epss", err)
		}
		cve, cerr := normalize.CanonicalCVE(row[0])
		s, e1 := strconv.ParseFloat(row[1], 64)
		p, e2 := strconv.ParseFloat(row[2], 64)
		switch {
		case cerr != nil:
			rejs = append(rejs, normalize.Rejection{RecordID: row[0], Field: "cve", Rule: "must match CVE-YYYY-NNNN+"})
			continue
		case e1 != nil || e2 != nil || s < 0 || s > 1 || p < 0 || p > 1:
			rejs = append(rejs, normalize.Rejection{RecordID: cve, Field: "score/percentile", Rule: "must be numbers in [0,1]"})
			continue
		}
		out = append(out, model.EPSS{CVE: cve, Score: s, Percentile: p, Date: date})
	}
	return out, rejs, nil
}
