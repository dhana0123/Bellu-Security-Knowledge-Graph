//go:build integration

package apikey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/apikey"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph/graphtest"
)

func TestMain(m *testing.M) { graphtest.Main(m) }

func TestStoreLifecycle(t *testing.T) {
	g := graphtest.New(t)
	ctx := context.Background()
	for _, q := range []string{
		"CREATE CONSTRAINT bskg_apikey_id IF NOT EXISTS FOR (n:ApiKey) REQUIRE n.id IS UNIQUE",
		"CREATE CONSTRAINT bskg_apikey_name IF NOT EXISTS FOR (n:ApiKey) REQUIRE n.name IS UNIQUE",
	} {
		if _, err := g.Auto(ctx, q, nil); err != nil {
			t.Fatal(err)
		}
	}
	s := apikey.NewStore(g, nil)
	key, err := s.Create(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "agent"); !errors.Is(err, apikey.ErrDuplicateName) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.Create(ctx, "bad name"); !errors.Is(err, apikey.ErrInvalidName) {
		t.Fatalf("invalid: %v", err)
	}
	v := apikey.NewVerifier(s, nil)
	if n, err := v.Verify(ctx, key); err != nil || n != "agent" {
		t.Fatalf("verify: %q %v", n, err)
	}
	if err := s.Revoke(ctx, "nobody"); !errors.Is(err, apikey.ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
	if err := s.Revoke(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "agent"); !errors.Is(err, apikey.ErrNotFound) {
		t.Fatalf("revoke twice: %v", err)
	}
	time.Sleep(apikey.CacheTTL + 100*time.Millisecond)
	if _, err := v.Verify(ctx, key); !errors.Is(err, apikey.ErrUnauthorized) {
		t.Fatalf("revoked verify: %v", err)
	}
	rec, err := s.Lookup(ctx, "0000000000000000")
	if err != nil || rec != nil {
		t.Fatalf("unknown lookup: %v %v", rec, err)
	}
}
