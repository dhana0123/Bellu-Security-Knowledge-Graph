package main

import (
	"bytes"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-security-knowledge-graph, Property 45: Unknown subcommands
// For any argument that is not a defined subcommand, the binary prints usage
// and exits non-zero.
// **Validates: Requirements 19.8**
func TestPropertyUnknownSubcommands(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		arg := rapid.String().Draw(t, "arg")
		if commands[arg] {
			t.Skip()
		}
		extra := rapid.SliceOfN(rapid.String(), 0, 3).Draw(t, "extra")

		var stdout, stderr bytes.Buffer
		code := run(append([]string{arg}, extra...), &stdout, &stderr)

		if code == 0 {
			t.Fatalf("exit code 0 for unknown subcommand %q", arg)
		}
		if !strings.Contains(stderr.String(), "usage: bskg") {
			t.Fatalf("usage not printed for %q: %q", arg, stderr.String())
		}
	})
}
