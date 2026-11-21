package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{nil, 2},
		{[]string{"bogus"}, 2},
		{[]string{"baseline"}, 2},
		{[]string{"baseline", "x"}, 2},
		{[]string{"migrate"}, 1},
		{[]string{"baseline", "load"}, 2},
		{[]string{"apikey", "create", "n"}, 1},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.want {
			t.Errorf("run(%v) = %d, want %d", c.args, got, c.want)
		}
	}
}

func TestUnknownPrintsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{"bogus"}, &out, &errb)
	if !strings.Contains(errb.String(), "usage: bskg") {
		t.Errorf("usage missing: %q", errb.String())
	}
}
