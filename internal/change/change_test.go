package change

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewBaselineLoad(t *testing.T) {
	at := time.Date(2024, 5, 6, 7, 8, 9, 123456789, time.UTC)
	r, err := NewBaselineLoad("RUN1", "vulkg", BaselineSummary{Commit: "abc", Nodes: 3, Relationships: 2}, at)
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != TypeBaselineLoad || r.EntityKey != "BaselineLoad:RUN1" || r.At.Nanosecond() != 123000000 {
		t.Fatalf("%+v", r)
	}
	var s BaselineSummary
	if err := json.Unmarshal([]byte(r.NewValue), &s); err != nil || s.Commit != "abc" || s.Nodes != 3 || s.Relationships != 2 {
		t.Fatalf("%v %+v", err, s)
	}
}

func TestNewIDMonotonic(t *testing.T) {
	at := time.Now()
	prev := ""
	for i := 0; i < 1000; i++ {
		id, err := NewID(at)
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 26 || id <= prev {
			t.Fatalf("id %q not after %q", id, prev)
		}
		prev = id
	}
}
