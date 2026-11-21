package change

import (
	"testing"
	"time"
)

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

func TestEncodeTyped(t *testing.T) {
	d := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	if got := EncodeValue(d); got != `{"$date":"2024-01-02"}` {
		t.Fatal(got)
	}
	dt := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := EncodeValue(dt); got != `{"$datetime":"2024-01-02T03:04:05Z"}` {
		t.Fatal(got)
	}
	if got := EncodeProps(map[string]any{"n": 3, "l": []time.Time{d}}); got != `{"l":[{"$date":"2024-01-02"}],"n":3}` {
		t.Fatal(got)
	}
	if EncodeValue(nil) != "null" {
		t.Fatal("nil")
	}
	r := Builder{Source: "nvd", RunID: "r"}.PropertyChanged("k", "f", 1, nil)
	if r.Type != TypePropertyChanged || r.OldValue != "1" || r.NewValue != "null" {
		t.Fatal(r)
	}
}
