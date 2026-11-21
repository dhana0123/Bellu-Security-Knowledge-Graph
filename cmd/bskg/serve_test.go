package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyUsageAndNameChecks(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"apikey"}, 2},
		{[]string{"apikey", "create"}, 2},
		{[]string{"apikey", "rotate", "x"}, 2},
		{[]string{"apikey", "create", "a", "b"}, 2},
		{[]string{"apikey", "create", "bad name!"}, 1},
		{[]string{"apikey", "revoke", ""}, 1},
		{[]string{"serve", "extra"}, 2},
		{[]string{"serve", "--bogus"}, 2},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.want {
			t.Errorf("run(%v) = %d, want %d (%s)", c.args, got, c.want, errb.String())
		}
		if out.Len() != 0 {
			t.Errorf("run(%v) wrote to stdout: %q", c.args, out.String())
		}
	}
}

func TestHealthcheckURL(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		env  map[string]string
		want string
	}{
		{nil, "http://127.0.0.1:8080/healthz"},
		{map[string]string{"BSKG_API_ADDR": ":9000"}, "http://127.0.0.1:9000/healthz"},
		{map[string]string{"BSKG_API_ADDR": "0.0.0.0:9001"}, "http://127.0.0.1:9001/healthz"},
		{map[string]string{"BSKG_API_ADDR": "10.0.0.5:9002", "BSKG_API_TLS_CERT_FILE": "/c"}, "https://10.0.0.5:9002/healthz"},
	}
	for _, c := range cases {
		if got := healthcheckURL(env(c.env)); got != c.want {
			t.Errorf("%v: %s, want %s", c.env, got, c.want)
		}
	}
}

func TestHealthcheckAgainstServer(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	env := func(k string) string {
		if k == "BSKG_API_ADDR" {
			return "127.0.0.1:" + port
		}
		return ""
	}
	if err := healthcheck(env); err != nil {
		t.Fatalf("ok: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := healthcheck(env); err == nil {
		t.Fatal("503 must fail")
	}
}
