package cvss

import "testing"

func fp(f float64) *float64 { return &f }

func TestScore3Known(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
	}
	for v, want := range cases {
		got, ok := Score3(v)
		if !ok || got != want {
			t.Errorf("%s: got %v ok=%v want %v", v, got, ok, want)
		}
	}
}

func TestAssess(t *testing.T) {
	v := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
	tests := []struct {
		name, vec, status, reason string
		rep                       *float64
		score                     *float64
	}{
		{"valid", v, "valid", "", fp(10.0), fp(10.0)},
		{"mismatch", v, "mismatch", "", fp(9.0), fp(9.0)},
		{"computed", v, "computed", "", nil, fp(10.0)},
		{"v4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "unverified", "unsupported-version:4.0", fp(9.3), fp(9.3)},
		{"v2", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "unverified", "unsupported-version:2.0", fp(7.5), fp(7.5)},
		{"malformed", "CVSS:3.1/AV:X", "unverified", "malformed-vector", nil, nil},
	}
	for _, tc := range tests {
		s, st, r := Assess(tc.vec, tc.rep)
		if st != tc.status || r != tc.reason {
			t.Errorf("%s: got %s/%s", tc.name, st, r)
		}
		if (s == nil) != (tc.score == nil) || (s != nil && *s != *tc.score) {
			t.Errorf("%s: score %v want %v", tc.name, s, tc.score)
		}
	}
}
