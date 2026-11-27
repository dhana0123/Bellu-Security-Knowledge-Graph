package nettest

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBlockFailsDials(t *testing.T) {
	// httptest servers are created before blocking so loopback still works for injected tests.
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	restore := Block()
	defer restore()
	before := Dials()
	_, err := http.Get("http://example.invalid/")
	if err == nil || !errors.Is(err, ErrNetworkBlocked) {
		t.Fatalf("expected blocked error, got %v", err)
	}
	if _, err := net.DefaultResolver.LookupHost(t.Context(), "example.invalid"); err == nil {
		t.Fatal("expected lookup failure")
	}
	if Dials() <= before {
		t.Fatal("dial counter not incremented")
	}
}
