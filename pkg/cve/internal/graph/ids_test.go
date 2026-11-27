package graph

import "testing"

func TestHashFromPropsMatchesNodeAndEdgeHash(t *testing.T) {
	props := []map[string]any{
		nil, {}, {"a": 1, "b": []any{"x<y>&z", 2.5, nil, true}, "c": map[string]any{"z": "é\u2028", "a": 10000000000.0}},
		{"summary": "<script>alert(1)</script> & \"quoted\" \\ back", "n": 0.1},
	}
	for i, p := range props {
		raw, err := CanonicalProps(p)
		if err != nil {
			t.Fatal(err)
		}
		n := Node{ID: "vuln:CVE-<1>&\"x\"", Type: "Vulnerability", Props: p}
		want, err := NodeHash(n)
		if err != nil {
			t.Fatal(err)
		}
		if got := nodeHashFromProps(n.Type, n.ID, raw); got != want {
			t.Errorf("node case %d: %s != %s", i, got, want)
		}
		e := Edge{ID: EdgeID("AFFECTS", "a<", "b&"), Type: "AFFECTS", Src: "a<", Dst: "b&", Props: p}
		wantE, err := EdgeHash(e)
		if err != nil {
			t.Fatal(err)
		}
		if got := edgeHashFromProps(e, raw); got != wantE {
			t.Errorf("edge case %d: %s != %s", i, got, wantE)
		}
	}
}
