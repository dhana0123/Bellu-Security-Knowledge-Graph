package canonical

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Feature: bellu-security-knowledge-graph, Property 2: Ingestion idempotence
// Feature: bellu-security-knowledge-graph, Property 13: Change history is complete and append-only

var ingestEpoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// drawIngestRecord draws a record for a fixed key with a strictly increasing Modified time
// (step is the 1-based position in the sequence) so no upsert is dropped as stale.
func drawIngestRecord(t *rapid.T, source, id string, step int) *model.Record {
	r := &model.Record{
		Source:   source,
		ID:       id,
		Summary:  rapid.SampledFrom([]string{"", "a", "b", "c"}).Draw(t, "summary"),
		Modified: ingestEpoch.Add(time.Duration(step) * time.Hour),
	}
	r.Weaknesses = rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"CWE-79", "CWE-89", "CWE-20"}),
		0, 3, func(s string) string { return s }).Draw(t, "weaknesses")
	if rapid.Bool().Draw(t, "withdrawn") {
		r.Withdrawn = ingestEpoch.Add(time.Duration(1000+rapid.IntRange(0, 2).Draw(t, "wd")) * time.Hour)
	}
	for _, u := range rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"u1", "u2", "u3"}),
		0, 3, func(s string) string { return s }).Draw(t, "refs") {
		r.References = append(r.References, model.Reference{Type: "WEB", URL: "https://x/" + u})
	}
	return r
}

func ingestCount(t *rapid.T, s *Store, table string) int {
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// canonicalCounts is the canonical-level stand-in for "no graph nodes or edges added".
// The projection-level check (node/edge sets unchanged after a duplicate ingestion) lives in
// internal/graph (TestDuplicateIngestionProjectionUnchanged) to avoid an import cycle.
func canonicalCounts(t *rapid.T, s *Store) map[string]int {
	m := map[string]int{}
	for _, tb := range []string{"source_record", "source_record_version", "change_history", "graph_event"} {
		m[tb] = ingestCount(t, s, tb)
	}
	return m
}

func dumpTable(t *rapid.T, s *Store, q string) []string {
	rows, err := s.DB.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%q", vals))
	}
	return out
}

func newIngestStore(t *rapid.T) *Store {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(&fakeClock{t: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)})
	return s
}

// Validates: Requirements 1.13, 23.1
func TestPropertyIngestionIdempotence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := newIngestStore(t)
		defer s.Close()
		ctx := context.Background()
		n := rapid.IntRange(1, 6).Draw(t, "n")
		var recs []*model.Record
		for i := 0; i < n; i++ {
			recs = append(recs, drawIngestRecord(t, "osv", fmt.Sprintf("ID-%d", i), 1))
		}
		for _, r := range recs {
			if ch, err := s.UpsertRecord(ctx, r); err != nil || !ch {
				t.Fatalf("first ingest: changed=%v err=%v", ch, err)
			}
		}
		before := canonicalCounts(t, s)
		rows := dumpTable(t, s, `SELECT * FROM source_record ORDER BY source, external_id`)
		vers := dumpTable(t, s, `SELECT * FROM source_record_version ORDER BY source, external_id, version`)
		hist := dumpTable(t, s, `SELECT * FROM change_history ORDER BY rowid`)

		for _, i := range rapid.SliceOfN(rapid.IntRange(0, n-1), 1, 3*n).Draw(t, "replay") {
			if ch, err := s.UpsertRecord(ctx, recs[i]); err != nil || ch {
				t.Fatalf("re-ingest reported changed=%v err=%v", ch, err)
			}
		}
		if after := canonicalCounts(t, s); !reflect.DeepEqual(before, after) {
			t.Fatalf("counts changed: %v -> %v", before, after)
		}
		if !reflect.DeepEqual(rows, dumpTable(t, s, `SELECT * FROM source_record ORDER BY source, external_id`)) ||
			!reflect.DeepEqual(vers, dumpTable(t, s, `SELECT * FROM source_record_version ORDER BY source, external_id, version`)) ||
			!reflect.DeepEqual(hist, dumpTable(t, s, `SELECT * FROM change_history ORDER BY rowid`)) {
			t.Fatal("table contents changed on re-ingestion")
		}
	})
}

// expectedChange is one fact kind that differs between two consecutive record versions.
type expectedChange struct{ fact, old, new string }

func simpleFacts(r *model.Record) map[string]string {
	f := map[string]string{}
	if r.Summary != "" {
		f["summary"] = r.Summary
	}
	if len(r.Weaknesses) > 0 {
		w := append([]string(nil), r.Weaknesses...)
		sort.Strings(w)
		b, _ := json.Marshal(w)
		f["weakness"] = string(b)
	}
	if !r.Withdrawn.IsZero() {
		f["withdrawn"] = r.Withdrawn.UTC().Format(time.RFC3339)
	}
	if len(r.References) > 0 {
		var refs []string
		for _, x := range r.References {
			refs = append(refs, x.Type+"|"+x.URL)
		}
		sort.Strings(refs)
		b, _ := json.Marshal(refs)
		f["reference"] = string(b)
	}
	return f
}

// Validates: Requirements 4.8, 7.10
func TestPropertyChangeHistoryCompleteAppendOnly(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := newIngestStore(t)
		defer s.Close()
		ctx := context.Background()
		const src, id = "osv", "GHSA-1"
		n := rapid.IntRange(1, 8).Draw(t, "n")

		var recs []*model.Record
		var bodies []string
		var snapshots [][]string
		var expected []expectedChange
		for i := 0; i < n; i++ {
			r := drawIngestRecord(t, src, id, i+1)
			if i > 0 {
				of, nf := simpleFacts(recs[i-1]), simpleFacts(r)
				keys := map[string]bool{}
				for k := range of {
					keys[k] = true
				}
				for k := range nf {
					keys[k] = true
				}
				var ks []string
				for k := range keys {
					if of[k] != nf[k] || (of[k] == "") != (nf[k] == "") {
						ks = append(ks, k)
					}
				}
				sort.Strings(ks)
				for _, k := range ks {
					expected = append(expected, expectedChange{src + ":" + id + "#" + k, of[k], nf[k]})
				}
			}
			if ch, err := s.UpsertRecord(ctx, r); err != nil || !ch {
				t.Fatalf("step %d: changed=%v err=%v", i, ch, err)
			}
			b, _ := json.Marshal(r)
			recs, bodies = append(recs, r), append(bodies, string(b))

			// earlier history entries are byte-identical after later writes
			cur := dumpTable(t, s, `SELECT * FROM change_history ORDER BY rowid`)
			if len(snapshots) > 0 {
				prev := snapshots[len(snapshots)-1]
				if len(cur) < len(prev) || strings.Join(prev, "\n") != strings.Join(cur[:len(prev)], "\n") {
					t.Fatalf("earlier history entries changed at step %d", i)
				}
			}
			snapshots = append(snapshots, cur)
		}

		// exactly one entry per changed fact, with old/new values and cause
		rows, err := s.DB.Query(`SELECT fact, old_value, new_value, cause FROM change_history ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		var got []expectedChange
		for rows.Next() {
			var f, cause string
			var ov, nv *string
			if err := rows.Scan(&f, &ov, &nv, &cause); err != nil {
				t.Fatal(err)
			}
			if cause != SourceRecordCause(src, id) {
				t.Fatalf("cause = %q", cause)
			}
			e := expectedChange{fact: f}
			if ov != nil {
				e.old = *ov
			}
			if nv != nil {
				e.new = *nv
			}
			got = append(got, e)
		}
		rows.Close()
		if !reflect.DeepEqual(got, append([]expectedChange(nil), expected...)) && !(len(got) == 0 && len(expected) == 0) {
			t.Fatalf("history mismatch\n got: %v\nwant: %v", got, expected)
		}

		// every previous version remains retrievable, in order
		for i, want := range bodies {
			var js string
			if err := s.DB.QueryRow(`SELECT json FROM source_record_version WHERE source=? AND external_id=? AND version=?`,
				src, id, i+1).Scan(&js); err != nil || js != want {
				t.Fatalf("version %d not retrievable: err=%v", i+1, err)
			}
		}
		if c := ingestCount(t, s, "source_record_version"); c != n {
			t.Fatalf("versions = %d, want %d", c, n)
		}

		// append-only: UPDATE and DELETE always fail and change nothing
		before := dumpTable(t, s, `SELECT * FROM change_history ORDER BY rowid`)
		if len(before) > 0 {
			if _, err := s.DB.Exec(`UPDATE change_history SET new_value='x'`); err == nil {
				t.Fatal("UPDATE on change_history succeeded")
			}
			if _, err := s.DB.Exec(`DELETE FROM change_history`); err == nil {
				t.Fatal("DELETE on change_history succeeded")
			}
		} else {
			// triggers fire per row; with no rows, force one so the guard is exercised
			if _, err := s.DB.Exec(`INSERT INTO change_history(fact,old_value,new_value,cause,changed_at) VALUES('f',NULL,'v','c','2024-01-01T00:00:00.000Z')`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(`UPDATE change_history SET new_value='x'`); err == nil {
				t.Fatal("UPDATE on change_history succeeded")
			}
			if _, err := s.DB.Exec(`DELETE FROM change_history`); err == nil {
				t.Fatal("DELETE on change_history succeeded")
			}
			before = dumpTable(t, s, `SELECT * FROM change_history ORDER BY rowid`)
		}
		if !reflect.DeepEqual(before, dumpTable(t, s, `SELECT * FROM change_history ORDER BY rowid`)) {
			t.Fatal("change_history modified despite guard")
		}
	})
}

// R23.1: ingesting the same record twice adds no rows (canonical level).
// Projection level: see internal/graph TestDuplicateIngestionProjectionUnchanged.
func TestDuplicateIngestionAddsNothing(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetClock(&fakeClock{t: ingestEpoch})
	ctx := context.Background()
	rec := &model.Record{Source: "osv", ID: "GHSA-9", Summary: "s", Modified: ingestEpoch,
		Weaknesses: []string{"CWE-79"}}
	if ch, err := s.UpsertRecord(ctx, rec); err != nil || !ch {
		t.Fatalf("first: %v %v", ch, err)
	}
	count := func() string {
		var parts []string
		for _, tb := range []string{"source_record", "source_record_version", "change_history", "graph_event"} {
			var n int
			if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ` + tb).Scan(&n); err != nil {
				t.Fatal(err)
			}
			parts = append(parts, fmt.Sprintf("%s=%d", tb, n))
		}
		return strings.Join(parts, ",")
	}
	before := count()
	if ch, err := s.UpsertRecord(ctx, rec); err != nil || ch {
		t.Fatalf("second: changed=%v err=%v", ch, err)
	}
	if after := count(); after != before {
		t.Fatalf("rows added by duplicate ingestion: %s -> %s", before, after)
	}
}
