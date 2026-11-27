package ghsa

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

func fixtures(t *testing.T) []json.RawMessage {
	t.Helper()
	b, err := os.ReadFile("testdata/advisories.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []json.RawMessage
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func norm(t *testing.T, i int) source.Normalized {
	t.Helper()
	raw := fixtures(t)[i]
	n, err := New(Options{}).Normalize(source.Record{ID: "r", Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func entity(n source.Normalized, kind source.RefKind, raw string) *source.Entity {
	for i := range n.Entities {
		if n.Entities[i].Ref.Kind == kind && n.Entities[i].Ref.Raw == raw {
			return &n.Entities[i]
		}
	}
	return nil
}

func rels(n source.Normalized, typ string) []source.Rel {
	var out []source.Rel
	for _, r := range n.Rels {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

func TestName(t *testing.T) {
	if a := New(Options{}); a.Name() != "ghsa" || !source.ValidName(a.Name()) {
		t.Fatalf("name %q", a.Name())
	}
}

func TestNormalizeNoCVE(t *testing.T) {
	n := norm(t, 0)
	if n.Advisory == nil || n.Advisory.ID != "GHSA-v853-p72q-4cfw" || len(n.Advisory.CVEs) != 0 || len(n.Advisory.OtherAliases) != 0 {
		t.Fatalf("advisory %+v", n.Advisory)
	}
	if n.Missing {
		t.Error("Missing set")
	}
	v := entity(n, source.RefAdvisory, "GHSA-v853-p72q-4cfw")
	if v == nil {
		t.Fatal("no advisory entity")
	}
	want := map[string]any{
		"ghsaSummary":    "Quart leaks raw request body to stdout",
		"ghsaSeverity":   "high",
		"ghsaCvssScore":  7.5,
		"ghsaCvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		"ghsaPublished":  time.Date(2026, 10, 5, 22, 49, 44, 0, time.UTC),
		"ghsaUpdated":    time.Date(2026, 11, 2, 13, 39, 16, 0, time.UTC),
	}
	if !reflect.DeepEqual(v.Props, want) {
		t.Errorf("props\n got %v\nwant %v", v.Props, want)
	}
	if !reflect.DeepEqual(v.Clear, []string{"ghsaWithdrawn"}) {
		t.Errorf("clear %v", v.Clear)
	}
	for k := range v.Props { // never an NVD property
		if !strings.HasPrefix(k, "ghsa") {
			t.Errorf("foreign property %s", k)
		}
	}
	if n.Anchor == nil || *n.Anchor != (source.Ref{Kind: source.RefAdvisory, Raw: "GHSA-v853-p72q-4cfw"}) {
		t.Errorf("anchor %+v", n.Anchor)
	}
	if !reflect.DeepEqual(n.Owned, []source.OwnedRel{{Type: "AFFECTS_PACKAGE"}, {Type: "REFERS_TO_REPOSITORY"}}) {
		t.Errorf("owned %v", n.Owned)
	}
	// CWE, never created.
	ex := rels(n, "EXAMPLE_OF")
	if len(ex) != 1 || ex[0].To != (source.Ref{Kind: source.RefCWE, Raw: "CWE-532", MustExist: true}) {
		t.Errorf("EXAMPLE_OF %+v", ex)
	}
	// Package.
	pk := "pkg:pypi/quart"
	if entity(n, source.RefPackage, pk) == nil {
		t.Fatalf("no package %s in %+v", pk, n.Entities)
	}
	ap := rels(n, "AFFECTS_PACKAGE")
	if len(ap) != 1 || ap[0].To.Raw != pk {
		t.Fatalf("AFFECTS_PACKAGE %+v", ap)
	}
	wantP := map[string]any{"affectedRanges": []string{"= 0.23.0"}, "fixed": "0.23.1", "introduced": "0.23.0", "lastAffected": "0.23.0"}
	if !reflect.DeepEqual(ap[0].Props, wantP) {
		t.Errorf("AFFECTS_PACKAGE props %v, want %v", ap[0].Props, wantP)
	}
	// Repository, HOSTED_IN and the fix commit.
	repo := "https://github.com/pallets/quart"
	hi := rels(n, "HOSTED_IN")
	if len(hi) != 1 || hi[0].From.Raw != pk || hi[0].To.Raw != repo {
		t.Errorf("HOSTED_IN %+v", hi)
	}
	rr := rels(n, "REFERS_TO_REPOSITORY")
	if len(rr) != 1 || rr[0].To.Raw != repo {
		t.Errorf("REFERS_TO_REPOSITORY %+v", rr)
	}
	if len(rels(n, "FIXES")) != 1 || len(rels(n, "HAS_FIX_COMMIT")) != 1 {
		t.Errorf("fix commit rels: %+v", n.Rels)
	}
	var sawBad bool
	for _, nt := range n.Notes {
		if strings.Contains(nt.Text, "abc123") {
			sawBad = true
		}
	}
	if !sawBad {
		t.Errorf("short commit sha not reported: %+v", n.Notes)
	}
	checkRefs(t, n)
}

func TestNormalizeOneCVEAndV4(t *testing.T) {
	n := norm(t, 1)
	if !reflect.DeepEqual(n.Advisory, &source.Advisory{ID: "GHSA-f9j6-8p6x-r9j6", CVEs: []string{"CVE-2026-62374"}}) {
		t.Fatalf("advisory %+v", n.Advisory)
	}
	v := entity(n, source.RefAdvisory, "GHSA-f9j6-8p6x-r9j6")
	if v.Props["ghsaCvssScore"] != 7.1 || !strings.HasPrefix(v.Props["ghsaCvssVector"].(string), "CVSS:4.0/") {
		t.Errorf("v4 score not used: %v", v.Props)
	}
	ap := rels(n, "AFFECTS_PACKAGE")
	if len(ap) != 2 {
		t.Fatalf("AFFECTS_PACKAGE %+v", ap)
	}
	if ap[0].To.Raw != "pkg:npm/%40sd-jwt/decode" {
		t.Errorf("scoped npm purl %s", ap[0].To.Raw)
	}
	// No fixed version: the property is absent, not empty.
	if _, ok := ap[0].Props["fixed"]; ok {
		t.Errorf("fixed present: %v", ap[0].Props)
	}
	if ap[0].Props["lastAffected"] != "0.19.0" || ap[0].Props["introduced"] != nil {
		t.Errorf("props %v", ap[0].Props)
	}
	if ap[1].Props["fixed"] != "0.20.0" || ap[1].Props["introduced"] != "0.10.0" {
		t.Errorf("props %v", ap[1].Props)
	}
	if len(rels(n, "EXAMPLE_OF")) != 1 { // CWE-176 listed twice
		t.Errorf("EXAMPLE_OF %+v", rels(n, "EXAMPLE_OF"))
	}
	if len(rels(n, "HOSTED_IN")) != 2 {
		t.Errorf("HOSTED_IN %+v", rels(n, "HOSTED_IN"))
	}
	checkRefs(t, n)
}

func TestNormalizeTwoCVEsWithdrawn(t *testing.T) {
	n := norm(t, 2)
	want := &source.Advisory{ID: "GHSA-pppp-qqqq-rrrr", CVEs: []string{"CVE-2025-0001", "CVE-2025-0002"}, OtherAliases: []string{"PYSEC-2025-1"}}
	if !reflect.DeepEqual(n.Advisory, want) {
		t.Fatalf("advisory %+v", n.Advisory)
	}
	v := entity(n, source.RefAdvisory, "GHSA-pppp-qqqq-rrrr")
	if got := v.Props["ghsaWithdrawn"]; got != time.Date(2025, 3, 1, 10, 0, 0, 0, time.UTC) {
		t.Errorf("ghsaWithdrawn %v", got)
	}
	if len(v.Clear) != 0 {
		t.Errorf("clear %v with a withdrawn advisory", v.Clear)
	}
	// Legacy cvss object when cvss_severities is empty.
	if v.Props["ghsaCvssScore"] != 5.3 || v.Props["ghsaSeverity"] != "low" {
		t.Errorf("props %v", v.Props)
	}
	// Two maven entries for one package give one relationship.
	ap := rels(n, "AFFECTS_PACKAGE")
	if len(ap) != 1 || ap[0].To.Raw != "pkg:maven/org.example/lib" {
		t.Fatalf("AFFECTS_PACKAGE %+v", ap)
	}
	if !reflect.DeepEqual(ap[0].Props["affectedRanges"], []string{"< 1.2.3", ">= 2.0.0, < 2.0.5"}) || ap[0].Props["fixed"] != "1.2.3, 2.0.5" {
		t.Errorf("props %v", ap[0].Props)
	}
	if _, ok := ap[0].Props["introduced"]; ok {
		t.Errorf("introduced derived from several ranges: %v", ap[0].Props)
	}
	// Unsupported ecosystem: warning, no package.
	var warned bool
	for _, nt := range n.Notes {
		if nt.Kind == "warning" && strings.Contains(nt.Text, "other") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no warning for the unsupported ecosystem: %+v", n.Notes)
	}
	// A GitLab source location still gives the Repository and HOSTED_IN.
	rr := rels(n, "REFERS_TO_REPOSITORY")
	if len(rr) != 1 || rr[0].To.Raw != "https://gitlab.com/group/sub/proj" {
		t.Errorf("REFERS_TO_REPOSITORY %+v", rr)
	}
	if len(rels(n, "HOSTED_IN")) != 1 {
		t.Errorf("HOSTED_IN %+v", rels(n, "HOSTED_IN"))
	}
	checkRefs(t, n)
}

func TestNormalizeSkipsRecordsWithoutIDOrUpdated(t *testing.T) {
	for _, i := range []int{3, 4} {
		n := norm(t, i)
		if len(n.Entities) != 0 || len(n.Rels) != 0 || n.Advisory != nil || n.Anchor != nil || !n.Missing || len(n.Notes) != 1 {
			t.Errorf("fixture %d: %+v", i, n)
		}
	}
}

func TestNormalizeErrors(t *testing.T) {
	a := New(Options{})
	if _, err := a.Normalize(source.Record{ID: "GHSA-bad", Payload: []byte(`{`)}); err == nil || !strings.Contains(err.Error(), "GHSA-bad") {
		t.Errorf("malformed JSON: %v", err)
	}
	bad := `{"ghsa_id":"GHSA-zz","updated_at":"2026-01-01T00:00:00Z"}`
	if _, err := a.Normalize(source.Record{ID: "x", Payload: []byte(bad)}); err == nil || !strings.Contains(err.Error(), "GHSA-zz") {
		t.Errorf("invalid id: %v", err)
	}
	if n, err := a.Normalize(source.Record{}); err != nil || len(n.Entities) != 0 {
		t.Errorf("cursor marker: %+v %v", n, err)
	}
}

func TestNormalizeEdgeCases(t *testing.T) {
	a := New(Options{})
	norm1 := func(js string) source.Normalized {
		t.Helper()
		n, err := a.Normalize(source.Record{ID: "r", Payload: []byte(js)})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	long := strings.Repeat("é", SummaryMax+50)
	n := norm1(`{"ghsa_id":"GHSA-pppp-qqqq-rrrr","updated_at":"2026-01-01T00:00:00Z","summary":"` + long + `"}`)
	s := n.Entities[0].Props["ghsaSummary"].(string)
	if len([]rune(s)) != SummaryMax {
		t.Errorf("summary %d characters", len([]rune(s)))
	}
	if !n.Missing { // no published_at
		t.Error("Missing not set without published_at")
	}
	// An invalid CVE id is a warning, not an alias.
	n = norm1(`{"ghsa_id":"GHSA-pppp-qqqq-rrrr","cve_id":"CVE-xx","updated_at":"2026-01-01T00:00:00Z","summary":"s","published_at":"2026-01-01T00:00:00Z"}`)
	if len(n.Advisory.CVEs) != 0 || len(n.Notes) == 0 {
		t.Errorf("advisory %+v notes %v", n.Advisory, n.Notes)
	}
	// first_patched_version as an object.
	n = norm1(`{"ghsa_id":"GHSA-pppp-qqqq-rrrr","updated_at":"2026-01-01T00:00:00Z","vulnerabilities":[{"package":{"ecosystem":"go","name":"github.com/a/b"},"vulnerable_version_range":"< 2","first_patched_version":{"identifier":"2.0.0"}}]}`)
	if ap := rels(n, "AFFECTS_PACKAGE"); len(ap) != 1 || ap[0].Props["fixed"] != "2.0.0" || ap[0].To.Raw != "pkg:golang/github.com/a/b" {
		t.Errorf("%+v", ap)
	}
	// A host the resolver does not know: a warning, no repository, no HOSTED_IN.
	n = norm1(`{"ghsa_id":"GHSA-pppp-qqqq-rrrr","updated_at":"2026-01-01T00:00:00Z","source_code_location":"https://codeberg.org/o/r","vulnerabilities":[{"package":{"ecosystem":"npm","name":"x"}}]}`)
	if len(rels(n, "HOSTED_IN")) != 0 || len(rels(n, "REFERS_TO_REPOSITORY")) != 0 || len(n.Notes) == 0 {
		t.Errorf("%+v", n)
	}
	if ap := rels(n, "AFFECTS_PACKAGE"); len(ap) != 1 || len(ap[0].Props) != 0 {
		t.Errorf("AFFECTS_PACKAGE without ranges: %+v", ap)
	}
}

func TestEveryEcosystemResolves(t *testing.T) {
	names := map[string]string{
		"npm": "left-pad", "pip": "Django_Foo", "maven": "g:a", "nuget": "Newtonsoft.Json", "go": "github.com/o/r",
		"rubygems": "rails", "rust": "serde", "composer": "vendor/pkg", "erlang": "cowboy", "actions": "o/r",
		"pub": "http", "swift": "github.com/o/r",
	}
	for ghsaName, osvName := range ecosystems {
		name, ok := names[ghsaName]
		if !ok {
			t.Errorf("no sample name for %s", ghsaName)
			continue
		}
		purl, err := resolve.PurlFromOSV(osvName, name)
		if err != nil {
			t.Errorf("%s: %v", ghsaName, err)
			continue
		}
		if _, err := resolve.Package(purl); err != nil {
			t.Errorf("%s: %v", ghsaName, err)
		}
	}
	if len(ecosystems) != 12 {
		t.Errorf("%d ecosystems mapped", len(ecosystems))
	}
}

func TestNormalizeIsDeterministic(t *testing.T) {
	for i := 0; i < 3; i++ {
		raw := fixtures(t)[i]
		a, _ := New(Options{}).Normalize(source.Record{ID: "r", Payload: raw})
		b, _ := New(Options{}).Normalize(source.Record{ID: "r", Payload: raw})
		if !reflect.DeepEqual(a, b) {
			t.Errorf("fixture %d differs between runs", i)
		}
	}
}

// checkRefs resolves every ref of n, checks relationship endpoints against
// the schema and that the Advisory ref is the one of Normalized.Advisory.
func checkRefs(t *testing.T, n source.Normalized) {
	t.Helper()
	for _, e := range n.Entities {
		if _, err := resolve.Resolve(e.Ref); err != nil {
			t.Errorf("entity ref %+v: %v", e.Ref, err)
		}
	}
	for _, r := range n.Rels {
		rt, ok := model.RelByName(r.Type)
		if !ok {
			t.Errorf("unknown relationship type %s", r.Type)
			continue
		}
		from, err1 := resolve.Resolve(r.From)
		to, err2 := resolve.Resolve(r.To)
		if err1 != nil || err2 != nil {
			t.Errorf("%s: %v %v", r.Type, err1, err2)
			continue
		}
		if from.Label != rt.From || to.Label != rt.To {
			t.Errorf("%s: %s -> %s, schema %s -> %s", r.Type, from.Label, to.Label, rt.From, rt.To)
		}
		// Every endpoint of the advisory must use the id of Normalized.Advisory.
		for _, ref := range []source.Ref{r.From, r.To} {
			if ref.Kind == source.RefAdvisory && ref.Raw != n.Advisory.ID {
				t.Errorf("advisory ref %s differs from %s", ref.Raw, n.Advisory.ID)
			}
		}
	}
}
