package canonical

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// loadSnapshot parses a graph fixture snapshot (a JSON array of OSV documents).
func loadSnapshot(t *testing.T, name string) []*model.Record {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "graph", name))
	if err != nil {
		t.Fatal(err)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal(data, &docs); err != nil {
		t.Fatal(err)
	}
	var out []*model.Record
	for _, d := range docs {
		rec, err := osv.Parse("osv", d)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		out = append(out, rec)
	}
	return out
}

func fixtureStore(t *testing.T, snapshots ...string) (*Store, []*model.Record) {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var all []*model.Record
	for _, name := range snapshots {
		for _, rec := range loadSnapshot(t, name) {
			if _, err := s.UpsertRecord(context.Background(), rec); err != nil {
				t.Fatalf("upsert %s: %v", rec.ID, err)
			}
			all = append(all, rec)
		}
	}
	return s, all
}

func identifierTarget(t *testing.T, s *Store, value string) []string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT vulnerability_id FROM vulnerability_identifier WHERE value=? ORDER BY 1`, value)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

func cvesOf(rec *model.Record) []string {
	var out []string
	for _, x := range append([]string{rec.ID}, rec.Aliases...) {
		if model.IsCVE(x) {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// R23.1: every alias of a single-CVE record resolves to the same canonical id.
func TestResolveFixtureAliasesShareCanonicalID(t *testing.T) {
	s, recs := fixtureStore(t, "snapshot_T.json", "snapshot_U.json")
	if _, err := s.Resolve(context.Background(), ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, rec := range recs {
		cves := cvesOf(rec)
		if len(cves) != 1 {
			continue // multi-CVE records are attached to each CVE, never merged
		}
		for _, x := range append([]string{rec.ID}, rec.Aliases...) {
			got := identifierTarget(t, s, x)
			if !reflect.DeepEqual(got, []string{cves[0]}) {
				t.Errorf("record %s: identifier %s resolves to %v, want [%s]", rec.ID, x, got, cves[0])
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no identifiers checked")
	}
	// Two sources of the same CVE share one group.
	m := membership(t, s)
	if want := []string{"osv:GHSA-FIX-0001", "osv:NVD-DISAGREE-1000"}; !reflect.DeepEqual(m["CVE-2024-1000"], want) {
		t.Fatalf("CVE-2024-1000 members %v, want %v", m["CVE-2024-1000"], want)
	}
}

// R23.1: advisories that list two CVEs do not merge those CVEs; both stay separate groups.
func TestResolveFixtureBridgingAndMultiCVEKeepGroupsSeparate(t *testing.T) {
	s, _ := fixtureStore(t, "snapshot_T.json", "snapshot_U.json")
	rep, err := s.Resolve(context.Background(), ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m := membership(t, s)
	for _, pair := range [][2]string{{"CVE-2024-3000", "CVE-2024-3001"}, {"CVE-2024-4000", "CVE-2024-4001"}} {
		a, b := pair[0], pair[1]
		if len(m[a]) == 0 || len(m[b]) == 0 {
			t.Fatalf("missing groups %s/%s: %v", a, b, m)
		}
		if got := identifierTarget(t, s, a); !reflect.DeepEqual(got, []string{a}) {
			t.Errorf("%s resolves to %v", a, got)
		}
		if got := identifierTarget(t, s, b); !reflect.DeepEqual(got, []string{b}) {
			t.Errorf("%s resolves to %v", b, got)
		}
	}
	has := func(list []string, x string) bool {
		for _, v := range list {
			if v == x {
				return true
			}
		}
		return false
	}
	for _, c := range []string{"CVE-2024-3000", "CVE-2024-3001"} {
		if !has(m[c], "osv:GHSA-BRIDGE-0003") {
			t.Errorf("%s lacks bridging advisory: %v", c, m[c])
		}
	}
	for _, c := range []string{"CVE-2024-4000", "CVE-2024-4001"} {
		if !has(m[c], "osv:GHSA-MULTI-0004") {
			t.Errorf("%s lacks multi-CVE advisory: %v", c, m[c])
		}
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM record_vulnerability WHERE method='multi-cve'`); n != 4 {
		t.Fatalf("multi-cve memberships = %d, want 4", n)
	}
	// Two CVEs in one record is a multi-CVE attachment, not an identifier collision.
	if rep.Collisions != 0 {
		t.Fatalf("collisions = %d, want 0", rep.Collisions)
	}
}

// R23.1: a non-CVE alias shared by records of two distinct CVEs yields a stored
// collision decision and two separate groups.
func TestResolveFixtureSharedAliasCollision(t *testing.T) {
	s, _ := fixtureStore(t, "snapshot_T.json")
	ctx := context.Background()
	for _, r := range []*model.Record{
		{Source: "osv", ID: "GHSA-LINK-a", Aliases: []string{"CVE-2024-3000", "PYSEC-BRIDGE"}, Modified: time.Unix(1700000000, 0)},
		{Source: "osv", ID: "GHSA-LINK-b", Aliases: []string{"CVE-2024-3001", "PYSEC-BRIDGE"}, Modified: time.Unix(1700000000, 0)},
	} {
		if _, err := s.UpsertRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := s.Resolve(ctx, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Collisions != 1 {
		t.Fatalf("collisions = %d, want 1", rep.Collisions)
	}
	var left, right, body string
	if err := s.DB.QueryRow(`SELECT left_id, right_id, decision FROM entity_resolution WHERE method=?`, RuleIdentifierCollision).Scan(&left, &right, &body); err != nil {
		t.Fatalf("collision decision not stored: %v", err)
	}
	if left != "CVE-2024-3000" || right != "CVE-2024-3001" {
		t.Fatalf("collision between %s and %s", left, right)
	}
	if !contains(body, "osv:GHSA-LINK-b") && !contains(body, "osv:GHSA-LINK-a") {
		t.Fatalf("decision lacks source records: %s", body)
	}
	m := membership(t, s)
	if len(m["CVE-2024-3000"]) == 0 || len(m["CVE-2024-3001"]) == 0 {
		t.Fatalf("groups merged: %v", m)
	}
	for v, list := range m {
		for _, r := range list {
			if r == "osv:GHSA-LINK-a" && v == "CVE-2024-3001" || r == "osv:GHSA-LINK-b" && v == "CVE-2024-3000" {
				t.Fatalf("record %s attached to wrong group %s", r, v)
			}
		}
	}
	if got := identifierTarget(t, s, "CVE-2024-3000"); !reflect.DeepEqual(got, []string{"CVE-2024-3000"}) {
		t.Fatalf("CVE-2024-3000 -> %v", got)
	}
	if got := identifierTarget(t, s, "CVE-2024-3001"); !reflect.DeepEqual(got, []string{"CVE-2024-3001"}) {
		t.Fatalf("CVE-2024-3001 -> %v", got)
	}
}
