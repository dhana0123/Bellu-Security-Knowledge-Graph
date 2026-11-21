package checkpoint

import (
	"errors"
	"testing"
)

func TestDecideBuildMode(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		gl, el    int
		want      Decision
		wantError bool
	}{
		{"unset unset", "", 0, 0, Decision{ModeFull, 0}, false},
		{"unset N", "", 0, 1000, Decision{ModeSample, 1000}, false},
		{"sample N same", ModeSample, 1000, 1000, Decision{ModeSample, 1000}, false},
		{"sample N changed", ModeSample, 1000, 50, Decision{ModeSample, 50}, false},
		{"sample unset continues as full", ModeSample, 1000, 0, Decision{ModeFull, 0}, false},
		{"full unset", ModeFull, 0, 0, Decision{ModeFull, 0}, false},
		{"full N refused", ModeFull, 0, 10, Decision{}, true},
	}
	for _, c := range cases {
		got, err := DecideBuildMode(c.mode, c.gl, c.el)
		if c.wantError {
			if !errors.Is(err, ErrFullGraphSample) {
				t.Errorf("%s: err=%v", c.name, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got %+v err=%v, want %+v", c.name, got, err, c.want)
		}
	}
}
