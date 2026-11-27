package model_test

import (
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func genTime() *rapid.Generator[time.Time] {
	return rapid.Custom(func(t *rapid.T) time.Time {
		if rapid.Bool().Draw(t, "zero") {
			return time.Time{}
		}
		ms := rapid.Int64Range(0, 4102444800000).Draw(t, "ms")
		return time.UnixMilli(ms).UTC()
	})
}

// slice draws a slice that is nil when empty (the canonical form).
func slice[T any](g *rapid.Generator[T], max int) *rapid.Generator[[]T] {
	return rapid.Custom(func(t *rapid.T) []T {
		s := rapid.SliceOfN(g, 0, max).Draw(t, "s")
		if len(s) == 0 {
			return nil
		}
		return s
	})
}

func genRecord() *rapid.Generator[model.Record] {
	str := rapid.String()
	strs := slice(str, 3)
	sev := rapid.Custom(func(t *rapid.T) model.Severity {
		s := model.Severity{Source: str.Draw(t, "src"), Type: str.Draw(t, "type"), Version: str.Draw(t, "ver"),
			Vector: str.Draw(t, "vec"), Validation: str.Draw(t, "val"), Reason: str.Draw(t, "reason")}
		if rapid.Bool().Draw(t, "hasScore") {
			f := rapid.Float64Range(0, 10).Draw(t, "score")
			s.Score = &f
		}
		return s
	})
	ev := rapid.Custom(func(t *rapid.T) model.Event {
		return model.Event{Introduced: str.Draw(t, "i"), Fixed: str.Draw(t, "f"), LastAffected: str.Draw(t, "l"), Limit: str.Draw(t, "lim")}
	})
	rng := rapid.Custom(func(t *rapid.T) model.Range {
		return model.Range{Type: str.Draw(t, "t"), Repo: str.Draw(t, "r"), Events: slice(ev, 3).Draw(t, "events")}
	})
	bound := rapid.Custom(func(t *rapid.T) model.Bound {
		return model.Bound{StartIncl: str.Draw(t, "a"), StartExcl: str.Draw(t, "b"), EndIncl: str.Draw(t, "c"), EndExcl: str.Draw(t, "d")}
	})
	aff := rapid.Custom(func(t *rapid.T) model.Affected {
		return model.Affected{Kind: str.Draw(t, "kind"), Ecosystem: str.Draw(t, "eco"), Name: str.Draw(t, "name"),
			Vendor: str.Draw(t, "vendor"), Purl: str.Draw(t, "purl"), Ranges: slice(rng, 2).Draw(t, "ranges"),
			Bounds: slice(bound, 2).Draw(t, "bounds"), Versions: strs.Draw(t, "versions"), Unmapped: rapid.Bool().Draw(t, "unm")}
	})
	ref := rapid.Custom(func(t *rapid.T) model.Reference {
		return model.Reference{Type: str.Draw(t, "t"), URL: str.Draw(t, "u")}
	})
	fix := rapid.Custom(func(t *rapid.T) model.Fix {
		return model.Fix{Repo: str.Draw(t, "r"), Commit: str.Draw(t, "c")}
	})
	return rapid.Custom(func(t *rapid.T) model.Record {
		return model.Record{
			Source: str.Draw(t, "source"), ID: str.Draw(t, "id"), Aliases: strs.Draw(t, "aliases"),
			Summary: str.Draw(t, "summary"), Details: str.Draw(t, "details"),
			Published: genTime().Draw(t, "pub"), Modified: genTime().Draw(t, "mod"), Withdrawn: genTime().Draw(t, "wd"),
			Weaknesses: strs.Draw(t, "cwe"), Severities: slice(sev, 3).Draw(t, "sevs"),
			Affected: slice(aff, 3).Draw(t, "aff"), References: slice(ref, 3).Draw(t, "refs"), Fixes: slice(fix, 3).Draw(t, "fixes"),
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 6: Source record serialization round trip
// **Validates: Requirements 2.12**
func TestPropertyRecordRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		r := genRecord().Draw(t, "record")
		r.Normalize()
		data, err := model.Marshal(r)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got model.Record
		if err := model.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, p := range [][2]time.Time{{r.Published, got.Published}, {r.Modified, got.Modified}, {r.Withdrawn, got.Withdrawn}} {
			if !p[0].Equal(p[1]) {
				t.Fatalf("time mismatch: %v vs %v", p[0], p[1])
			}
		}
		if !reflect.DeepEqual(r, got) {
			t.Fatalf("round trip mismatch:\n want %+v\n got  %+v", r, got)
		}
	})
}
