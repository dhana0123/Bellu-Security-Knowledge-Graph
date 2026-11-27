package canonical

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

type asofClock struct{ t time.Time }

func (c *asofClock) Now() time.Time { return c.t }

func asofIDs(t *testing.T, v View) map[string]string {
	t.Helper()
	out := map[string]string{}
	for r, err := range v.Records(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		out[r.Source+":"+r.ID] = r.Summary
	}
	return out
}

func TestAsOfTemporalViews(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := &asofClock{base}
	st.SetClock(clk)

	up := func(r *model.Record) {
		if _, err := st.UpsertRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	up(&model.Record{Source: "osv", ID: "A", Summary: "v1"})
	up(&model.Record{Source: "osv", ID: "B", Summary: "b1"})
	t1 := base
	clk.t = base.Add(time.Hour)
	up(&model.Record{Source: "osv", ID: "A", Summary: "v2", Modified: base.Add(time.Hour)})
	t2 := clk.t
	clk.t = base.Add(2 * time.Hour)
	up(&model.Record{Source: "osv", ID: "B", Summary: "b1", Modified: clk.t, Withdrawn: clk.t})
	t3 := clk.t
	clk.t = base.Add(3 * time.Hour)

	cur := asofIDs(t, st.Current())
	if len(cur) != 1 || cur["osv:A"] != "v2" {
		t.Fatalf("current = %v", cur)
	}

	v, err := st.AsOf(t2)
	if err != nil {
		t.Fatal(err)
	}
	got := asofIDs(t, v)
	if len(got) != 2 || got["osv:A"] != "v2" || got["osv:B"] != "b1" {
		t.Fatalf("as-of before withdrawal = %v", got)
	}
	v, _ = st.AsOf(t1)
	if got := asofIDs(t, v); got["osv:A"] != "v1" || len(got) != 2 {
		t.Fatalf("as-of t1 = %v", got)
	}
	// As-of the withdrawal instant includes the withdrawn version (only Current filters).
	v, _ = st.AsOf(t3)
	if got := asofIDs(t, v); len(got) != 2 {
		t.Fatalf("as-of t3 = %v", got)
	}
	// Before anything was recorded.
	v, _ = st.AsOf(base.Add(-time.Hour))
	if got := asofIDs(t, v); len(got) != 0 {
		t.Fatalf("pre-history = %v", got)
	}
}

func TestAsOfInvalid(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Date(2024, 5, 5, 0, 0, 0, 0, time.UTC)
	st.SetClock(&asofClock{now})
	for _, bad := range []time.Time{{}, now.Add(time.Second)} {
		if _, err := st.AsOf(bad); !errors.Is(err, ErrInvalidAsOf) {
			t.Fatalf("AsOf(%v) err = %v", bad, err)
		}
	}
	if _, err := st.AsOf(now); err != nil {
		t.Fatal(err)
	}
}

func TestAsOfNowEqualsCurrentWhenNoWithdrawn(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Date(2024, 5, 5, 0, 0, 0, 0, time.UTC)
	clk := &asofClock{now}
	st.SetClock(clk)
	for _, id := range []string{"A", "B"} {
		if _, err := st.UpsertRecord(ctx, &model.Record{Source: "osv", ID: id, Summary: id}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.DB.ExecContext(ctx, `INSERT INTO record_vulnerability VALUES('osv','A','CVE-2024-0001','alias')`); err != nil {
		t.Fatal(err)
	}
	v, err := st.AsOf(clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, c := asofIDs(t, v), asofIDs(t, st.Current())
	if len(a) != 2 || len(c) != 2 || a["osv:A"] != c["osv:A"] || a["osv:B"] != c["osv:B"] {
		t.Fatalf("asof=%v current=%v", a, c)
	}
	vv, err := v.Vulnerability(ctx, "CVE-2024-0001")
	if err != nil || vv == nil || len(vv.Records) != 1 || vv.Records[0].ID != "A" {
		t.Fatalf("vuln view = %+v err=%v", vv, err)
	}
	if vv, _ := v.Vulnerability(ctx, "CVE-0"); vv != nil {
		t.Fatal("expected nil for unknown vulnerability")
	}
}
