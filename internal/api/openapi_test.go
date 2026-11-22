package api

import (
	"context"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"gopkg.in/yaml.v3"
)

type oaSpec struct {
	OpenAPI string                     `yaml:"openapi"`
	Paths   map[string]map[string]oaOp `yaml:"paths"`
	Comp    struct {
		Parameters map[string]oaParam        `yaml:"parameters"`
		Responses  map[string]map[string]any `yaml:"responses"`
	} `yaml:"components"`
}

type oaOp struct {
	Parameters []oaParam                 `yaml:"parameters"`
	Responses  map[string]map[string]any `yaml:"responses"`
}

type oaParam struct {
	Ref  string `yaml:"$ref"`
	Name string `yaml:"name"`
	In   string `yaml:"in"`
}

var pathVarRe = regexp.MustCompile(`\{([^}]+)\}`)

// fullServer builds a server with every phase applied and co-exploitation on.
func fullServer() *Server {
	s := New(Config{
		MaxPhase: 3, Logger: slog.New(slog.DiscardHandler),
		UI: fstest.MapFS{"index.html": {Data: []byte("<html></html>")}},
	})
	q := func(context.Context, string, map[string]any) ([]Row, error) { return nil, nil }
	Routes(s, q, []byte("secret"))
	CoExploitRoutes(s, q, true, 0)
	OpsRoutes(s, OpsConfig{Q: q})
	return s
}

func TestOpenAPIMatchesRoutes(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec oaSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.0") {
		t.Fatalf("openapi = %q, want 3.0.x", spec.OpenAPI)
	}
	documented := map[string]bool{}
	for path, ops := range spec.Paths {
		for method, op := range ops {
			m := strings.ToUpper(method)
			documented[m+" "+path] = true
			if len(op.Responses) == 0 {
				t.Errorf("%s %s has no responses", m, path)
			}
			checkPathParams(t, spec, m, path, op)
		}
	}
	registered := map[string]bool{}
	for _, r := range fullServer().Routes() {
		if registered[r] {
			t.Errorf("route %q registered twice", r)
		}
		registered[r] = true
	}
	for r := range registered {
		if !documented[r] {
			t.Errorf("route %q is registered but not in api/openapi.yaml", r)
		}
	}
	for d := range documented {
		if !registered[d] {
			t.Errorf("%q is in api/openapi.yaml but no route is registered", d)
		}
	}
}

// checkPathParams requires every {var} of the path to be declared as a path
// parameter, and every declared path parameter to appear in the path.
func checkPathParams(t *testing.T, spec oaSpec, method, path string, op oaOp) {
	t.Helper()
	declared := map[string]bool{}
	for _, p := range op.Parameters {
		if p.Ref != "" {
			name := strings.TrimPrefix(p.Ref, "#/components/parameters/")
			var ok bool
			if p, ok = spec.Comp.Parameters[name]; !ok {
				t.Errorf("%s %s: unknown parameter ref %q", method, path, name)
				continue
			}
		}
		if p.In == "path" {
			declared[p.Name] = true
		}
	}
	want := map[string]bool{}
	for _, m := range pathVarRe.FindAllStringSubmatch(path, -1) {
		want[m[1]] = true
	}
	if !sameSet(want, declared) {
		t.Errorf("%s %s: path variables %v, declared path parameters %v", method, path, keys(want), keys(declared))
	}
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
