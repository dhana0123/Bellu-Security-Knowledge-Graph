package source

import (
	"testing"
	"time"
)

func TestValidName(t *testing.T) {
	for _, ok := range []string{"nvd", "cwe", "exploitdb", "a", "osv2"} {
		if !ValidName(ok) {
			t.Errorf("%q must be valid", ok)
		}
	}
	for _, bad := range []string{"", "NVD", "1nvd", "a-b", "x'y", "abcdefghijklmnopq"} {
		if ValidName(bad) {
			t.Errorf("%q must be invalid", bad)
		}
	}
}

func TestCheckpointIsZero(t *testing.T) {
	if !(Checkpoint{}).IsZero() {
		t.Fatal("zero checkpoint")
	}
	for _, c := range []Checkpoint{{Watermark: time.Now()}, {Resume: "x"}, {Version: "v"}} {
		if c.IsZero() {
			t.Errorf("%+v is not zero", c)
		}
	}
}
