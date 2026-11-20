package baseline

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func validManifest() *Manifest {
	m := &Manifest{
		Upstream: Upstream{Repo: "https://github.com/happyResearcher/VulKG", Commit: strings.Repeat("ab", 20), CopiedOn: "2025-01-31"},
		Bucket:   BucketRef{Name: "bkt", Prefix: "vulkg/x/"},
	}
	for i, l := range RequiredLogicalFiles {
		repo := fmt.Sprintf("import/File%d.csv", i)
		if l == LogicalHasExploit {
			repo = "import/Vulnerabiliy_HAS_EXPLOIT_Exploit_relationship.csv"
		}
		m.Files = append(m.Files, ManifestFile{Logical: l, RepoName: repo, ScriptName: ScriptNameFor(repo),
			Key: "vulkg/x/" + ScriptNameFor(repo), SHA256: strings.Repeat("1f", 32), Size: 100})
	}
	return m
}

func TestValidManifestAccepted(t *testing.T) {
	if err := validManifest().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTypoMapping(t *testing.T) {
	got := ScriptNameFor("import/DomainNodes_Vulnerabiliy_HAS_REFERENCE_Domain_relationship.csv")
	if got != "DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv" {
		t.Fatal(got)
	}
	m := validManifest()
	m.Files[3].ScriptName = "Vulnerabiliy_HAS_EXPLOIT_Exploit_relationship.csv"
	if m.Validate() == nil {
		t.Fatal("typo script name accepted")
	}
}

func TestRejections(t *testing.T) {
	cases := map[string]func(*Manifest){
		"short sha":      func(m *Manifest) { m.Files[0].SHA256 = "abc" },
		"non-hex sha":    func(m *Manifest) { m.Files[0].SHA256 = strings.Repeat("g", 64) },
		"size zero":      func(m *Manifest) { m.Files[0].Size = 0 },
		"size too big":   func(m *Manifest) { m.Files[0].Size = MaxFileSize + 1 },
		"empty key":      func(m *Manifest) { m.Files[0].Key = "" },
		"long key":       func(m *Manifest) { m.Files[0].Key = strings.Repeat("k", 1025) },
		"short commit":   func(m *Manifest) { m.Upstream.Commit = "abc" },
		"bad date":       func(m *Manifest) { m.Upstream.CopiedOn = "2025-13-01" },
		"unpadded date":  func(m *Manifest) { m.Upstream.CopiedOn = "2025-1-1" },
		"missing file":   func(m *Manifest) { m.Files = m.Files[1:] },
		"duplicate file": func(m *Manifest) { m.Files = append(m.Files, m.Files[0]) },
		"unknown file":   func(m *Manifest) { m.Files[0].Logical = "Nope" },
		"path in script": func(m *Manifest) { m.Files[0].ScriptName = "a/b.csv" },
	}
	for name, mut := range cases {
		m := validManifest()
		mut(m)
		if err := m.Validate(); err == nil || errors.Is(err, ErrPlaceholder) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestPlaceholderTemplateRejected(t *testing.T) {
	_, err := LoadManifest("../../baseline/manifest.json")
	if !errors.Is(err, ErrPlaceholder) {
		t.Fatalf("want ErrPlaceholder, got %v", err)
	}
}

func TestParseUnknownFieldAndRoundTrip(t *testing.T) {
	if _, err := ParseManifest([]byte(`{"bogus":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := ParseManifest([]byte(`not json`)); err == nil {
		t.Fatal("bad json accepted")
	}
}

// Feature: bellu-security-knowledge-graph, Property 26: Manifest validation
// **Validates: Requirements 3.1, 24.6**
func TestPropertyManifestValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := validManifest()
		hex := func(n int) string { return rapid.StringMatching(fmt.Sprintf(`[0-9a-f]{%d}`, n)).Draw(t, "hex") }
		m.Upstream.Commit = rapid.OneOf(rapid.Just(hex(40)), rapid.StringMatching(`[0-9a-fg]{0,45}`)).Draw(t, "commit")
		m.Upstream.CopiedOn = rapid.OneOf(rapid.Just("2024-02-29"), rapid.StringMatching(`[0-9]{4}-[0-9]{2}-[0-9]{2}`)).Draw(t, "date")
		for i := range m.Files {
			m.Files[i].SHA256 = rapid.OneOf(rapid.Just(hex(64)), rapid.StringMatching(`[0-9a-f]{60,66}`)).Draw(t, "sha")
			m.Files[i].Size = rapid.Int64Range(-5, MaxFileSize+5).Draw(t, "size")
			m.Files[i].Key = rapid.String().Draw(t, "key")
		}
		expectOK := commitRe.MatchString(m.Upstream.Commit)
		if expectOK {
			_, err := timeParse(m.Upstream.CopiedOn)
			expectOK = err == nil
		}
		for _, f := range m.Files {
			expectOK = expectOK && sha256Re.MatchString(f.SHA256) && f.Size >= 1 && f.Size <= MaxFileSize && len(f.Key) >= 1 && len(f.Key) <= 1024
		}
		err := m.Validate()
		if expectOK && err != nil && !errors.Is(err, ErrPlaceholder) {
			t.Fatalf("valid rejected: %v", err)
		}
		if !expectOK && err == nil {
			t.Fatalf("invalid accepted: %+v", m)
		}
	})
}

func timeParse(s string) (struct{}, error) {
	if len(s) != len(dateLayout) {
		return struct{}{}, errors.New("len")
	}
	_, err := parseDate(s)
	return struct{}{}, err
}
