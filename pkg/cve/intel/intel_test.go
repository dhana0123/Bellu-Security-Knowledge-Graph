package intel

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func buildGraphDB(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	st, err := canonical.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	data, err := os.ReadFile(filepath.Join("..", "tests", "fixtures", "graph", "snapshot_U.json"))
	if err != nil {
		t.Fatal(err)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal(data, &docs); err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		rec, err := osv.Parse("osv", d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-1000", DateAdded: "2024-03-01", DueDate: "2024-03-22", Ransomware: "known"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []model.EPSS{
		{CVE: "CVE-2024-1000", Score: 0.5, Percentile: 0.9, Date: "2024-03-01"},
		{CVE: "CVE-2024-1000", Score: 0.6, Percentile: 0.95, Date: "2024-03-02"},
	} {
		if _, err := st.UpsertEPSS(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "graph.db")
	sink := graph.NewSQLiteSink(path)
	if err := sink.Begin(ctx, graph.SinkMeta{CreatedAt: "2024-05-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if _, err := graph.Build(ctx, st, graph.Policy{}, sink.WriteNode, sink.WriteEdge); err != nil {
		_ = sink.Abort()
		t.Fatal(err)
	}
	if err := sink.Commit(); err != nil {
		t.Fatal(err)
	}
	return path
}

func openClient(t *testing.T, path string) Client {
	t.Helper()
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func fileHash(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func checkNonNil(t *testing.T, v *Vulnerability) {
	t.Helper()
	if v.Aliases == nil || v.Severities == nil || v.Weaknesses == nil || v.Sources == nil {
		t.Errorf("nil collection in %+v", v)
	}
}

func TestGetVulnerabilityLookups(t *testing.T) {
	path := buildGraphDB(t)
	before := fileHash(t, path)
	c := openClient(t, path)
	ctx := context.Background()

	byCVE, err := c.GetVulnerability(ctx, "CVE-2024-1000")
	if err != nil {
		t.Fatal(err)
	}
	checkNonNil(t, byCVE)
	if byCVE.ID != "CVE-2024-1000" {
		t.Fatalf("id = %q", byCVE.ID)
	}
	if byCVE.KEV == nil || byCVE.KEV.DateAdded != "2024-03-01" {
		t.Errorf("KEV = %+v", byCVE.KEV)
	}
	if byCVE.EPSS == nil || byCVE.EPSS.Date != "2024-03-02" || byCVE.EPSS.Score != 0.6 {
		t.Errorf("EPSS = %+v", byCVE.EPSS)
	}
	if len(byCVE.Sources) == 0 || byCVE.TrustState == "" {
		t.Errorf("sources/trust missing: %+v", byCVE)
	}
	hasGHSA := false
	for _, a := range byCVE.Aliases {
		if a == "GHSA-FIX-0001" {
			hasGHSA = true
		}
		if a == byCVE.ID {
			t.Errorf("alias list contains own id")
		}
	}
	if !hasGHSA {
		t.Errorf("aliases = %v", byCVE.Aliases)
	}

	for _, in := range []string{"GHSA-FIX-0001", "vuln:CVE-2024-1000", "ghsa-fix-0001", "src:osv:GHSA-FIX-0001", " CVE-2024-1000 "} {
		got, err := c.GetVulnerability(ctx, in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got.ID != byCVE.ID {
			t.Errorf("%q resolved to %q", in, got.ID)
		}
		checkNonNil(t, got)
	}

	// A vulnerability without enrichment still has non-nil collections.
	plain, err := c.GetVulnerability(ctx, "CVE-2024-2000")
	if err != nil {
		t.Fatal(err)
	}
	checkNonNil(t, plain)
	if plain.KEV != nil || plain.EPSS != nil {
		t.Errorf("unexpected enrichment: %+v", plain)
	}

	if after := fileHash(t, path); after != before {
		t.Error("graph.db changed after queries")
	}
}

func TestGetVulnerabilityErrors(t *testing.T) {
	c := openClient(t, buildGraphDB(t))
	ctx := context.Background()
	for _, id := range []string{"CVE-1999-0000", "vuln:nope", "src:osv:nope", "alias:nope"} {
		v, err := c.GetVulnerability(ctx, id)
		if !errors.Is(err, ErrNotFound) || v != nil {
			t.Errorf("%q: got (%v, %v)", id, v, err)
		}
	}
	if _, err := c.GetVulnerability(ctx, "  "); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("empty id: %v", err)
	}
	if _, err := c.GetVulnerability(ctx, "CVE-2024-1000", WithAsOf(time.Now())); !errors.Is(err, ErrHistoryUnavailable) {
		t.Errorf("as-of without history: %v", err)
	}
}

func TestAttackPathsAlwaysNotImplemented(t *testing.T) {
	c := openClient(t, buildGraphDB(t))
	c.(*sqliteClient).db.Close() // proves the DB is not touched
	p, err := c.GetAttackPaths(context.Background(), "CVE-2024-1000")
	if p != nil || !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("got (%v, %v)", p, err)
	}
}

func TestOpenReadOnly(t *testing.T) {
	path := buildGraphDB(t)
	c := openClient(t, path)
	db := c.(*sqliteClient).db
	if _, err := db.Exec(`INSERT INTO meta(key,value) VALUES('x','y')`); err == nil {
		t.Fatal("write succeeded on read-only handle")
	}
	if _, err := db.Exec(`DELETE FROM nodes`); err == nil {
		t.Fatal("delete succeeded on read-only handle")
	}
}

func TestOpenSchemaVersion(t *testing.T) {
	path := buildGraphDB(t)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE meta SET value=? WHERE key='schema_version'`, "99"); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	_, err = Open(path)
	var sv *SchemaVersionError
	if !errors.As(err, &sv) || sv.File != 99 || sv.Supported != MaxSchemaVersion {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenMissingFile(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope.db")); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestAliasPrefixLookup(t *testing.T) {
	path := buildGraphDB(t)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	err = raw.QueryRow(`SELECT id FROM nodes WHERE id LIKE 'alias:%' ORDER BY id LIMIT 1`).Scan(&id)
	raw.Close()
	if err != nil {
		t.Fatalf("fixture has no alias-only node: %v", err)
	}
	c := openClient(t, path)
	for _, in := range []string{id, strings.TrimPrefix(id, "alias:")} {
		if _, err := c.GetVulnerability(context.Background(), in); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
}
