package intel

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/version"
)

// ---------------------------------------------------------------------------
// fixture: one seeded random canonical store, projected once into a graph.db

type oracleEntry struct {
	vuln     string
	scheme   string
	bySource map[string]*model.Affected
}

type ident struct{ in, vuln string }

type propFixture struct {
	path    string
	oracle  map[string][]*oracleEntry // package node id -> entries
	vulns   []string
	idents  []ident // inputs (record ids, aliases, CVE, case variants) -> vulnerability id
	edgeIDs []ident // src:/alias: node ids -> vulnerability id (from ALIAS_OF edges)
	known   map[string]bool
	pairs   [][2]string // (ecosystem, name) probes, including absent packages
	vers    []string
}

var (
	propEcosystems = []string{"PyPI", "npm", "Maven", "Go", "crates.io", "NuGet"}
	propVersions   = []string{"0.1", "1.0", "1.0.0", "1.2.3", "1.10.0", "2.0", "2.1.0", "3.0.0", "1.0.0-rc1", "10.0", "4.5.6"}
	propSources    = []string{"osv", "github", "ghsa"}
)

func propPackageNames(eco string) []string {
	if eco == "Maven" {
		return []string{"org.a:alpha", "org.b:beta", "org.c:gamma"}
	}
	if eco == "PyPI" {
		return []string{"Foo_Bar", "foo-bar", "baz", "Qux.Lib"}
	}
	return []string{"alpha", "Beta", "gamma", "delta"}
}

func buildPropFixture(t testing.TB, history bool) *propFixture {
	t.Helper()
	ctx := context.Background()
	rng := rand.New(rand.NewSource(20240501))
	pickVer := func() string {
		if rng.Intn(12) == 0 {
			return "zz!!" // not a valid version under any scheme
		}
		return propVersions[rng.Intn(len(propVersions))]
	}
	genAffected := func() model.Affected {
		eco := propEcosystems[rng.Intn(len(propEcosystems))]
		names := propPackageNames(eco)
		a := model.Affected{Kind: "package", Ecosystem: eco, Name: names[rng.Intn(len(names))]}
		for i, n := 0, rng.Intn(3); i < n; i++ {
			var evs []model.Event
			if rng.Intn(3) == 0 {
				evs = append(evs, model.Event{Introduced: "0"})
			} else {
				evs = append(evs, model.Event{Introduced: pickVer()})
			}
			switch rng.Intn(3) {
			case 0:
				evs = append(evs, model.Event{Fixed: pickVer()})
			case 1:
				evs = append(evs, model.Event{LastAffected: pickVer()})
			}
			typ := []string{"ECOSYSTEM", "SEMVER", "GIT"}[rng.Intn(3)]
			a.Ranges = append(a.Ranges, model.Range{Type: typ, Events: evs})
		}
		if rng.Intn(3) == 0 {
			b := model.Bound{}
			if rng.Intn(2) == 0 {
				b.StartIncl = pickVer()
			}
			if rng.Intn(2) == 0 {
				b.EndExcl = pickVer()
			}
			a.Bounds = append(a.Bounds, b)
		}
		for i, n := 0, rng.Intn(3); i < n; i++ {
			a.Versions = append(a.Versions, pickVer())
		}
		return a
	}

	dir := t.TempDir()
	canon := filepath.Join(dir, "canonical.db")
	st, err := canonical.Open(canon)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 40; i++ {
		cve := fmt.Sprintf("CVE-2024-%04d", 1000+i)
		perm := rng.Perm(len(propSources))
		for j, n := 0, 1+rng.Intn(3); j < n; j++ {
			rec := &model.Record{
				Source: propSources[perm[j]], ID: fmt.Sprintf("GHSA-G%03d-%c", i, 'A'+j),
				Aliases: []string{cve}, Summary: fmt.Sprintf("generated vulnerability %d", i),
				Published: base, Modified: base.Add(time.Duration(i+j) * time.Hour),
			}
			if rng.Intn(10) == 0 {
				rec.Withdrawn = base.Add(time.Duration(i+j+100) * time.Hour)
			}
			for k, m := 0, 1+rng.Intn(3); k < m; k++ {
				rec.Affected = append(rec.Affected, genAffected())
			}
			rec.Normalize()
			if _, err := st.UpsertRecord(ctx, rec); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}

	fx := &propFixture{path: filepath.Join(dir, "graph.db"), oracle: map[string][]*oracleEntry{}, known: map[string]bool{}, vers: propVersions}
	rows, err := st.DB.QueryContext(ctx, `SELECT DISTINCT vulnerability_id FROM record_vulnerability ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		fx.vulns = append(fx.vulns, v)
	}
	rows.Close()
	if len(fx.vulns) == 0 {
		t.Fatal("fixture resolved no vulnerabilities")
	}
	for _, v := range fx.vulns {
		recs, err := st.SourceRecords(ctx, v)
		if err != nil {
			t.Fatal(err)
		}
		fx.addIdent(v, v)
		byPkg := map[string]*oracleEntry{}
		for _, r := range recs {
			fx.addIdent(r.ID, v)
			for _, a := range r.Aliases {
				fx.addIdent(a, v)
			}
			if !r.Withdrawn.IsZero() {
				continue
			}
			for _, a := range r.Affected {
				if a.Kind == "product" || strings.TrimSpace(a.Name) == "" {
					continue
				}
				id := model.PackageID(a.Ecosystem, a.Name)
				e := byPkg[id]
				if e == nil {
					scheme := version.SchemeFor(a.Ecosystem)
					if scheme == "" {
						scheme = "generic"
					}
					e = &oracleEntry{vuln: v, scheme: scheme, bySource: map[string]*model.Affected{}}
					byPkg[id] = e
					fx.oracle[id] = append(fx.oracle[id], e)
				}
				m := e.bySource[r.Source]
				if m == nil {
					m = &model.Affected{}
					e.bySource[r.Source] = m
				}
				m.Ranges = append(m.Ranges, a.Ranges...)
				m.Bounds = append(m.Bounds, a.Bounds...)
				m.Versions = append(m.Versions, a.Versions...)
			}
		}
	}
	for _, eco := range propEcosystems {
		for _, n := range propPackageNames(eco) {
			fx.pairs = append(fx.pairs, [2]string{eco, n})
		}
	}
	fx.pairs = append(fx.pairs, [2]string{"pypi", "FOO-bar"}, [2]string{"PyPI", "absent-pkg"}, [2]string{"Debian", "openssl"})

	sink := graph.NewSQLiteSink(fx.path)
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
	st.Close()

	raw, err := sql.Open("sqlite", fx.path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	er, err := raw.Query(`SELECT src, dst FROM edges WHERE type='ALIAS_OF' ORDER BY src, dst`)
	if err != nil {
		t.Fatal(err)
	}
	defer er.Close()
	for er.Next() {
		var s, d string
		if err := er.Scan(&s, &d); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(d, "vuln:") && (strings.HasPrefix(s, "src:") || strings.HasPrefix(s, "alias:")) {
			fx.edgeIDs = append(fx.edgeIDs, ident{s, strings.TrimPrefix(d, "vuln:")})
		}
	}
	if len(fx.edgeIDs) == 0 {
		t.Fatal("fixture has no ALIAS_OF edges")
	}
	return fx
}

func (fx *propFixture) addIdent(in, vuln string) {
	in = model.NormID(in)
	if in == "" || fx.known[in] {
		return
	}
	fx.known[in] = true
	fx.idents = append(fx.idents, ident{in, vuln})
	fx.idents = append(fx.idents, ident{"vuln:" + in, vuln}) // only valid for vuln ids, filtered below
	fx.idents = append(fx.idents, ident{strings.ToLower(in), vuln})
}

// ---------------------------------------------------------------------------
// oracle

type expected struct {
	state  MatchState
	source string
	fixed  string
}

func firstFixed(a *model.Affected) string {
	for _, rg := range a.Ranges {
		if strings.EqualFold(rg.Type, "GIT") {
			continue
		}
		for _, ev := range rg.Events {
			if ev.Fixed != "" {
				return ev.Fixed
			}
		}
	}
	for _, b := range a.Bounds {
		if b.EndExcl != "" {
			return b.EndExcl
		}
	}
	return ""
}

func (fx *propFixture) expect(eco, name, ver string) map[string]expected {
	out := map[string]expected{}
	for _, e := range fx.oracle[model.PackageID(eco, name)] {
		srcs := make([]string, 0, len(e.bySource))
		for s := range e.bySource {
			srcs = append(srcs, s)
		}
		sort.Strings(srcs)
		unknown, matched := false, false
		for _, s := range srcs {
			r, _ := e.bySource[s].MatchVersion(e.scheme, ver)
			if r == model.Match {
				out[e.vuln] = expected{MatchAffected, s, firstFixed(e.bySource[s])}
				matched = true
				break
			}
			if r == model.Unknown {
				unknown = true
			}
		}
		if !matched && unknown {
			out[e.vuln] = expected{state: MatchUnknown}
		}
	}
	return out
}

func checkMatches(t *rapid.T, fx *propFixture, eco, name, ver string, got []PackageMatch, stats map[MatchState]int) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s/%s@%s: nil result", eco, name, ver)
	}
	want := fx.expect(eco, name, ver)
	if len(got) != len(want) {
		t.Fatalf("%s/%s@%s: got %d matches, oracle %d (%v)", eco, name, ver, len(got), len(want), want)
	}
	for _, m := range got {
		w, ok := want[m.Vulnerability.ID]
		if !ok {
			t.Fatalf("%s/%s@%s: unexpected vulnerability %s", eco, name, ver, m.Vulnerability.ID)
		}
		if m.State != w.state || m.Level != LevelAffectedPackage {
			t.Fatalf("%s %s/%s@%s: state/level = %s/%s, want %s/affected-package", m.Vulnerability.ID, eco, name, ver, m.State, m.Level, w.state)
		}
		if w.state == MatchAffected {
			if m.Range == nil || m.Range.Source != w.source || m.FixedVersion != w.fixed || m.Range.Fixed != w.fixed {
				t.Fatalf("%s %s/%s@%s: range/fixed = %+v/%q, want source %s fixed %q", m.Vulnerability.ID, eco, name, ver, m.Range, m.FixedVersion, w.source, w.fixed)
			}
		} else if m.Range != nil || m.FixedVersion != "" {
			t.Fatalf("%s: unknown match carries range %+v fixed %q", m.Vulnerability.ID, m.Range, m.FixedVersion)
		}
		stats[m.State]++
	}
}

func genVersion() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.SampledFrom(propVersions),
		rapid.SampledFrom([]string{"not-a-version!!", "zz!!"}),
		rapid.Custom(func(t *rapid.T) string {
			return fmt.Sprintf("%d.%d.%d", rapid.IntRange(0, 11).Draw(t, "maj"), rapid.IntRange(0, 11).Draw(t, "min"), rapid.IntRange(0, 11).Draw(t, "pat"))
		}),
	)
}

// Feature: bellu-security-knowledge-graph, Property 34: SDK package matching equals the reference oracle
// **Validates: Requirements 12.5, 12.6, 18.1, 18.2, 18.5, 18.6**
func TestProperty34PackageMatchingEqualsOracle(t *testing.T) {
	fx := buildPropFixture(t, false)
	c := openClient(t, fx.path)
	ctx := context.Background()
	stats := map[MatchState]int{}
	empty := 0
	rapid.Check(t, func(t *rapid.T) {
		p := rapid.SampledFrom(fx.pairs).Draw(t, "pkg")
		ver := genVersion().Draw(t, "version")
		got, err := c.GetPackageVulnerabilities(ctx, p[0], p[1], ver)
		if err != nil {
			t.Fatalf("%v: %v", p, err)
		}
		if len(got) == 0 {
			empty++
		}
		checkMatches(t, fx, p[0], p[1], ver, got, stats)

		// AnalyzeDependencies: one entry per input, in input order.
		deps := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Dependency {
			q := rapid.SampledFrom(fx.pairs).Draw(t, "pkg")
			return Dependency{Ecosystem: q[0], Name: q[1], Version: genVersion().Draw(t, "version")}
		}), 1, 12).Draw(t, "deps")
		res, err := c.AnalyzeDependencies(ctx, deps)
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != len(deps) {
			t.Fatalf("got %d results for %d deps", len(res), len(deps))
		}
		for i, d := range deps {
			if res[i].Dependency != d {
				t.Fatalf("result %d is for %+v, want %+v", i, res[i].Dependency, d)
			}
			checkMatches(t, fx, d.Ecosystem, d.Name, d.Version, res[i].Vulnerabilities, stats)
		}
	})
	if stats[MatchAffected] == 0 || stats[MatchUnknown] == 0 || empty == 0 {
		t.Errorf("generator did not cover all outcomes: %v, empty=%d", stats, empty)
	}
}

func (fx *propFixture) validIdents() []ident {
	var out []ident
	for _, x := range fx.idents {
		// "vuln:<id>" only resolves when <id> is itself a vulnerability id.
		if strings.HasPrefix(x.in, "vuln:") && "vuln:"+x.vuln != x.in {
			continue
		}
		out = append(out, x)
	}
	return out
}

func (fx *propFixture) genAbsent() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.StringMatching(`CVE-19[0-9]{2}-[0-9]{4,7}`),
		rapid.StringMatching(`GHSA-[A-Z]{4}-[0-9]{4}`),
		rapid.StringMatching(`(vuln|src:osv|alias):[A-Z]{3,5}-[0-9]{4,6}`),
		rapid.StringMatching(`[A-Za-z0-9]{3,12}`),
	).Filter(func(s string) bool { return !fx.known[model.NormID(s)] && strings.TrimSpace(s) != "" })
}

// Feature: bellu-security-knowledge-graph, Property 35: SDK identifier resolution and errors
// **Validates: Requirements 12.4, 12.7, 12.8, 12.13**
func TestProperty35IdentifierResolutionAndErrors(t *testing.T) {
	fx := buildPropFixture(t, false)
	c := openClient(t, fx.path)
	ctx := context.Background()
	valid := fx.validIdents()
	absent := fx.genAbsent()
	rapid.Check(t, func(t *rapid.T) {
		x := rapid.SampledFrom(valid).Draw(t, "ident")
		v, err := c.GetVulnerability(ctx, x.in)
		if err != nil || v == nil || v.ID != x.vuln {
			t.Fatalf("%q: got (%+v, %v), want %s", x.in, v, err, x.vuln)
		}
		if v.Aliases == nil || v.Severities == nil || v.Weaknesses == nil || v.Sources == nil {
			t.Fatalf("%q: nil collection", x.in)
		}
		e := rapid.SampledFrom(fx.edgeIDs).Draw(t, "nodeID")
		if v, err := c.GetVulnerability(ctx, e.in); err != nil || v.ID != e.vuln {
			t.Fatalf("%q: got (%v, %v), want %s", e.in, v, err, e.vuln)
		}

		id := absent.Draw(t, "absent")
		if v, err := c.GetVulnerability(ctx, id); !errors.Is(err, ErrNotFound) || v != nil {
			t.Fatalf("GetVulnerability(%q) = (%v, %v)", id, v, err)
		}
		if ps, err := c.GetAffectedProducts(ctx, id); !errors.Is(err, ErrNotFound) || ps != nil {
			t.Fatalf("GetAffectedProducts(%q) = (%v, %v)", id, ps, err)
		}
		if ps, err := c.GetPatches(ctx, id); !errors.Is(err, ErrNotFound) || ps != nil {
			t.Fatalf("GetPatches(%q) = (%v, %v)", id, ps, err)
		}
		// GetAttackPaths is not implemented for any id, present or absent.
		for _, q := range []string{id, x.in} {
			if ap, err := c.GetAttackPaths(ctx, q); ap != nil || !errors.Is(err, ErrNotImplemented) {
				t.Fatalf("GetAttackPaths(%q) = (%v, %v)", q, ap, err)
			}
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 35 (schema version): Open rejects newer schemas
// **Validates: Requirements 12.13**
func TestProperty35NewerSchemaVersion(t *testing.T) {
	fx := buildPropFixture(t, false)
	data, err := os.ReadFile(fx.path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	n := 0
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.IntRange(MaxSchemaVersion+1, 100000).Draw(t, "schema")
		n++
		p := filepath.Join(dir, fmt.Sprintf("g%d.db", n))
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		raw, err := sql.Open("sqlite", p)
		if err != nil {
			t.Fatal(err)
		}
		_, err = raw.Exec(`UPDATE meta SET value=? WHERE key='schema_version'`, fmt.Sprint(v))
		raw.Close()
		if err != nil {
			t.Fatal(err)
		}
		c, err := Open(p)
		var sv *SchemaVersionError
		if err == nil {
			c.Close()
			t.Fatalf("Open accepted schema version %d", v)
		}
		if !errors.As(err, &sv) || sv.File != v || sv.Supported != MaxSchemaVersion {
			t.Fatalf("schema %d: err = %v", v, err)
		}
		_ = os.Remove(p)
	})
}

// Feature: bellu-security-knowledge-graph, Property 36: SDK queries do not modify the database
// **Validates: Requirements 12.12**
func TestProperty36QueriesDoNotModifyDatabase(t *testing.T) {
	fx := buildPropFixture(t, false)
	ctx := context.Background()
	valid := fx.validIdents()
	absent := fx.genAbsent()
	before := fileHash(t, fx.path)
	rapid.Check(t, func(t *rapid.T) {
		c, err := Open(fx.path)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		ops := rapid.SliceOfN(rapid.IntRange(0, 9), 1, 15).Draw(t, "ops")
		for _, op := range ops {
			id := rapid.SampledFrom(valid).Draw(t, "ident").in
			bad := absent.Draw(t, "absent")
			p := rapid.SampledFrom(fx.pairs).Draw(t, "pkg")
			ver := genVersion().Draw(t, "ver")
			switch op {
			case 0:
				_, _ = c.GetVulnerability(ctx, id)
			case 1:
				_, _ = c.GetVulnerability(ctx, bad)
			case 2:
				_, _ = c.GetPackageVulnerabilities(ctx, p[0], p[1], ver)
			case 3:
				_, _ = c.GetPackageVulnerabilities(ctx, "", p[1], ver)
			case 4:
				_, _ = c.GetAffectedProducts(ctx, id)
			case 5:
				_, _ = c.GetPatches(ctx, bad)
			case 6:
				_, _ = c.GetAttackPaths(ctx, id)
			case 7:
				_, _ = c.AnalyzeDependencies(ctx, []Dependency{{p[0], p[1], ver}, {p[0], p[1], id}})
			case 8:
				_, _ = c.AnalyzeDependencies(ctx, nil)
			case 9:
				_, _ = c.GetVulnerability(ctx, id, WithAsOf(time.Now().Add(-time.Hour)))
			}
		}
		if after := hashFile(t, fx.path); after != before {
			t.Fatalf("graph.db changed after ops %v", ops)
		}
	})
	if matches, _ := filepath.Glob(fx.path + "-*"); len(matches) > 0 {
		t.Errorf("queries created side files: %v", matches)
	}
}

// Feature: bellu-security-knowledge-graph, Property 37: Batch validation rejects without partial results
// **Validates: Requirements 12.10, 18.3**
func TestProperty37BatchValidationRejects(t *testing.T) {
	fx := buildPropFixture(t, false)
	c := openClient(t, fx.path)
	ctx := context.Background()
	genDep := rapid.Custom(func(t *rapid.T) Dependency {
		q := rapid.SampledFrom(fx.pairs).Draw(t, "pkg")
		return Dependency{Ecosystem: q[0], Name: q[1], Version: genVersion().Draw(t, "version")}
	})
	rapid.Check(t, func(t *rapid.T) {
		switch kind := rapid.IntRange(0, 2).Draw(t, "kind"); kind {
		case 0: // empty
			var deps []Dependency
			if rapid.Bool().Draw(t, "nilList") {
				deps = []Dependency{}
			}
			res, err := c.AnalyzeDependencies(ctx, deps)
			if !errors.Is(err, ErrInvalidRequest) || res != nil {
				t.Fatalf("empty: (%v, %v)", res, err)
			}
		case 1: // too many
			n := MaxDependencies + rapid.IntRange(1, 300).Draw(t, "extra")
			d := genDep.Draw(t, "dep")
			deps := make([]Dependency, n)
			for i := range deps {
				deps[i] = d
			}
			res, err := c.AnalyzeDependencies(ctx, deps)
			if !errors.Is(err, ErrInvalidRequest) || res != nil || !strings.Contains(err.Error(), fmt.Sprint(MaxDependencies)) {
				t.Fatalf("%d deps: (%d results, %v)", n, len(res), err)
			}
		default: // one invalid element
			deps := rapid.SliceOfN(genDep, 1, 30).Draw(t, "deps")
			i := rapid.IntRange(0, len(deps)-1).Draw(t, "index")
			field := rapid.SampledFrom([]string{"ecosystem", "name", "version"}).Draw(t, "field")
			blank := rapid.SampledFrom([]string{"", " ", "\t", "  \n"}).Draw(t, "blank")
			switch field {
			case "ecosystem":
				deps[i].Ecosystem = blank
			case "name":
				deps[i].Name = blank
			default:
				deps[i].Version = blank
			}
			res, err := c.AnalyzeDependencies(ctx, deps)
			if !errors.Is(err, ErrInvalidRequest) || res != nil {
				t.Fatalf("invalid deps[%d].%s: (%v, %v)", i, field, res, err)
			}
			// The first invalid entry is reported; earlier ones are valid.
			if want := fmt.Sprintf("deps[%d].%s", i, field); !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not name %s", err, want)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// unit tests

// The SDK sources must not import net/http (R12.12 / R23.5). Checked on the
// parsed imports, so it needs no toolchain subprocess.
func TestSDKSourcesDoNotImportNetHTTP(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v %v", files, err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			if p := strings.Trim(im.Path.Value, `"`); p == "net/http" || strings.HasPrefix(p, "net/http/") {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}

func TestIDMethodsNotFoundOnMissingID(t *testing.T) {
	c := openClient(t, buildPyGraph(t, false))
	ctx := context.Background()
	if v, err := c.GetVulnerability(ctx, "CVE-1999-0001"); !errors.Is(err, ErrNotFound) || v != nil {
		t.Errorf("GetVulnerability: (%v, %v)", v, err)
	}
	if ps, err := c.GetAffectedProducts(ctx, "CVE-1999-0001"); !errors.Is(err, ErrNotFound) || ps != nil {
		t.Errorf("GetAffectedProducts: (%v, %v)", ps, err)
	}
	if ps, err := c.GetPatches(ctx, "CVE-1999-0001"); !errors.Is(err, ErrNotFound) || ps != nil {
		t.Errorf("GetPatches: (%v, %v)", ps, err)
	}
}

func hashFile(t *rapid.T, p string) [32]byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}
