//go:build integration

package baseline_test

import (
	"context"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/baseline"
	"github.com/bellu/bskg/internal/change"
	"github.com/bellu/bskg/internal/graph/graphtest"
	"github.com/bellu/bskg/internal/provenance"
)

func TestMain(m *testing.M) { graphtest.Main(m) }

func TestWriterBatchesProgressAndProvenance(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	const file = "../../testdata/baseline/WeaknessNodes.csv"
	total, err := baseline.CountRows(file)
	if err != nil {
		t.Fatal(err)
	}
	set, err := provenance.SetClause("w", provenance.SourceVulKG)
	if err != nil {
		t.Fatal(err)
	}
	spec := baseline.StepSpec{
		Name: "weakness_nodes",
		Cypher: `UNWIND $rows AS row
MERGE (w:Weakness {cweID: row.cweID})
ON CREATE SET w.cweName = row.cweName, w.cweView = row.cweView, ` + set + `
RETURN count(w) AS matched`,
		Params: map[string]any{"runID": "RUN1", "at": time.Now().UTC(), "ref": "deadbeef"},
		Map: func(r baseline.Row) (map[string]any, error) {
			return r.Props([]baseline.Field{
				{Column: "cweID", Prop: "cweID", Type: baseline.TString},
				{Column: "cweName", Prop: "cweName", Type: baseline.TString},
				{Column: "cweView", Prop: "cweView", Type: baseline.TStringList},
			})
		},
	}
	w := baseline.Writer{C: c, BatchSize: 5}
	res, err := w.RunStep(ctx, file, total, spec, "cweID")
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != total || res.Sent != total {
		t.Fatalf("result %+v, total %d", res, total)
	}
	jobs := baseline.Jobs{C: c}
	p, err := jobs.Read(ctx)
	if err != nil || p.CurrentStep != "weakness_nodes" || p.RowsDone != total || p.RowsTotal != total {
		t.Fatalf("progress %+v %v", p, err)
	}
	if err := jobs.Complete(ctx, "weakness_nodes"); err != nil {
		t.Fatal(err)
	}
	if p, _ = jobs.Read(ctx); p.LastCompletedStep != "weakness_nodes" || p.CurrentStep != "" {
		t.Fatalf("after complete %+v", p)
	}

	// Rerun is idempotent: same node count.
	if _, err := w.RunStep(ctx, file, total, spec, "cweID"); err != nil {
		t.Fatal(err)
	}
	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, `MATCH (w:Weakness) WHERE w.sources = ['vulkg'] AND w.p_vulkg_run = 'RUN1' RETURN count(w)`, nil)
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		return rec.Values[0], nil
	})
	if err != nil || v.(int64) != 12 {
		t.Fatalf("weakness count %v %v", v, err)
	}

	// One baselineLoad Change record.
	rec, err := change.NewBaselineLoad("RUN1", "vulkg", change.BaselineSummary{Commit: "deadbeef", Nodes: 12}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, change.Write(ctx, tx, rec)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWriterRejectsBadBatchSize(t *testing.T) {
	c := graphtest.New(t)
	for _, n := range []int{0, 10001} {
		_, err := baseline.Writer{C: c, BatchSize: n}.RunStep(context.Background(), "x", 0, baseline.StepSpec{})
		if err == nil {
			t.Fatalf("batch size %d accepted", n)
		}
	}
}
