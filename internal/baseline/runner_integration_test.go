//go:build integration

package baseline_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bellu/bskg/internal/baseline"
	"github.com/bellu/bskg/internal/change"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/graph/graphtest"
)

const fixtureDir = "../../testdata/baseline"

var fixtureScriptNames = map[string]string{
	baseline.LogicalVulnerabilityNodes:         "VulnerabilityNodes.csv",
	baseline.LogicalVulnerabilityAddProperties: "VulnerabilityNodesAddProperties.csv",
	baseline.LogicalExploitNodes:               "ExploitNodes.csv",
	baseline.LogicalHasExploit:                 "Vulnerability_HAS_EXPLOIT_Exploit_relationship.csv",
	baseline.LogicalWeaknessNodes:              "WeaknessNodes.csv",
	baseline.LogicalDomainRelationship:         "DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv",
	baseline.LogicalProductVendorAffects:       "ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv",
	baseline.LogicalAffectsAddProperty:         "AffectsAddProperty.csv",
}

// fixtureManifest builds a manifest for the fixture CSVs with checksums computed here.
func fixtureManifest(t *testing.T) *baseline.Manifest {
	t.Helper()
	m := &baseline.Manifest{
		Upstream: baseline.Upstream{Repo: "https://example.test/VulKG", Commit: strings.Repeat("ab", 20), CopiedOn: "2024-01-02"},
		Bucket:   baseline.BucketRef{Name: "fixture-bucket", Prefix: "vulkg/x/"},
	}
	for _, logical := range baseline.RequiredLogicalFiles {
		script := fixtureScriptNames[logical]
		data, err := os.ReadFile(filepath.Join(fixtureDir, script))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		repo := "import/" + script
		if logical == baseline.LogicalHasExploit || logical == baseline.LogicalDomainRelationship {
			repo = "import/" + strings.Replace(script, "Vulnerability_", "Vulnerabiliy_", 1)
		}
		m.Files = append(m.Files, baseline.ManifestFile{
			Logical: logical, RepoName: repo, ScriptName: script, Key: "vulkg/x/" + script,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)),
		})
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m
}

func loadOpts(t *testing.T, c *graph.Client) baseline.LoadOptions {
	return baseline.LoadOptions{
		Manifest: fixtureManifest(t), Fetcher: &baseline.Fetcher{LocalDir: fixtureDir},
		Client: c, BatchSize: 7,
	}
}

func checkFixtureGraph(t *testing.T, c *graph.Client) {
	t.Helper()
	for q, want := range map[string]int64{
		`MATCH (n:Vulnerability) RETURN count(n)`:                                               40,
		`MATCH (n:Domain) RETURN count(n)`:                                                      9,
		`MATCH ()-[r:AFFECTS]->() RETURN count(r)`:                                              37,
		`MATCH (v:Vulnerability) WHERE v.exploitability = 1 RETURN count(v)`:                    12,
		`MATCH (j:Job {name:'baseline-load'}) RETURN j.bareNodes`:                               3,
		`MATCH (j:Job {name:'baseline-load'}) RETURN j.rejectDeleted`:                           3,
		`MATCH (j:Job {name:'baseline-load'}) RETURN j.missing_exploits_rel`:                    3,
		`MATCH (b:BuildMeta {id:'build'}) WHERE b.baselineLoadedAt IS NOT NULL RETURN count(b)`: 1,
	} {
		if got := count(t, c, q); got != want {
			t.Errorf("%s: got %d want %d", q, got, want)
		}
	}
}

func TestLoadFixtureEndToEnd(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	st, err := baseline.Load(ctx, loadOpts(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if st.LastCompleted != baseline.StepFinalize || st.RunID == "" {
		t.Fatalf("state %+v", st)
	}
	checkFixtureGraph(t, c)
	if n := count(t, c, `MATCH (c:Change {type:'baselineLoad'}) RETURN count(c)`); n != 1 {
		t.Fatalf("baselineLoad records = %d, want 1", n)
	}
	if n := count(t, c, `MATCH (c:Change {type:'baselineLoad', source:'vulkg'}) WHERE c.runId = '`+st.RunID+`' AND c.newValue CONTAINS '"nodes":' RETURN count(c)`); n != 1 {
		t.Fatalf("summary record not tied to run %s", st.RunID)
	}
	if n := count(t, c, `MATCH (v:Vulnerability {cveID:'CVE-2019-1001'}) WHERE v.p_vulkg_run = '`+st.RunID+`' RETURN count(v)`); n != 1 {
		t.Fatal("provenance run id differs from the load's run id")
	}

	// A second load of a finished baseline is a new load with identical counts.
	st2, err := baseline.Load(ctx, loadOpts(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if st2.RunID == st.RunID {
		t.Fatal("finished load must not be resumed")
	}
	checkFixtureGraph(t, c)
	if n := count(t, c, `MATCH (c:Change {type:'baselineLoad'}) RETURN count(c)`); n != 2 {
		t.Fatalf("baselineLoad records = %d, want 2", n)
	}
}

func TestLoadResumesAfterInterruption(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	m := fixtureManifest(t)
	files := map[string]string{}
	for l, s := range fixtureScriptNames {
		files[l] = filepath.Join(fixtureDir, s)
	}
	calls := map[string]int{}
	failOnce := true
	build := func(st baseline.RunState) []baseline.Step {
		l := baseline.Loader{
			W: baseline.Writer{C: c, BatchSize: 7}, Files: files,
			RunID: st.RunID, Ref: m.Upstream.Commit, At: st.StartedAt,
		}
		steps := l.StepList()
		for i := range steps {
			s := steps[i]
			steps[i].Run = func(ctx context.Context) error {
				calls[s.Name]++
				if s.Name == baseline.StepProductAffects && failOnce {
					failOnce = false
					return errors.New("injected interruption")
				}
				return s.Run(ctx)
			}
		}
		return steps
	}
	r := baseline.Runner{
		Store: baseline.GraphJobStore{C: c}, Commit: m.Upstream.Commit, Build: build, NewRunID: change.NewID,
	}
	st1, err := r.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), baseline.StepProductAffects) {
		t.Fatalf("want failure naming %s, got %v", baseline.StepProductAffects, err)
	}
	if st1.LastCompleted != baseline.StepDomainRefers {
		t.Fatalf("last completed = %q", st1.LastCompleted)
	}
	if count(t, c, `MATCH (j:Job {name:'baseline-load'}) RETURN j.bareNodes`) != 3 {
		t.Fatal("bareNodes should be set after step 8")
	}

	st2, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st2.RunID != st1.RunID {
		t.Fatalf("resume changed run id: %s -> %s", st1.RunID, st2.RunID)
	}
	if calls[baseline.StepVulnNodes] != 1 || calls[baseline.StepDomainRefers] != 1 {
		t.Fatalf("completed steps reran: %v", calls)
	}
	if calls[baseline.StepProductAffects] != 2 {
		t.Fatalf("interrupted step runs = %d, want 2", calls[baseline.StepProductAffects])
	}
	checkFixtureGraph(t, c)
	if n := count(t, c, `MATCH (c:Change {type:'baselineLoad'}) RETURN count(c)`); n != 1 {
		t.Fatalf("baselineLoad records = %d, want 1", n)
	}
}
