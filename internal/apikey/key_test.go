package apikey

import (
	"context"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: bellu-security-knowledge-graph, Property 38: API key lifecycle
// **Validates: Requirements 18.1, 18.2, 18.3, 18.4**
func TestProperty38KeyLifecycle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`[A-Za-z0-9._-]{1,64}`).Draw(t, "name")
		key, rec, err := Generate(nil, name, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		id, secret, ok := Parse(key)
		if !ok || id != rec.ID {
			t.Fatalf("parse failed for %q", key)
		}
		if len(secret) < 43 { // 32 bytes base64url, no padding
			t.Fatalf("secret too short: %d", len(secret))
		}
		for _, field := range []string{string(rec.Hash), string(rec.Salt), rec.Name + rec.ID} {
			if strings.Contains(field, secret) {
				t.Fatal("record contains secret")
			}
		}
		if !Check(&rec, secret) {
			t.Fatal("valid key rejected")
		}
		// any modified secret fails
		i := rapid.IntRange(0, len(secret)-1).Draw(t, "i")
		b := []byte(secret)
		b[i] ^= 1
		if Check(&rec, string(b)) {
			t.Fatal("modified key accepted")
		}
		// revoked fails
		now := time.Now()
		rec.RevokedAt = &now
		if Check(&rec, secret) {
			t.Fatal("revoked key accepted")
		}
		if Check(nil, secret) {
			t.Fatal("unknown key accepted")
		}
	})
}

// idSrc returns its record only for the matching key id, like the real store.
type idSrc struct{ rec *Record }

func (f *idSrc) Lookup(_ context.Context, id string) (*Record, error) {
	if f.rec != nil && f.rec.ID == id {
		return f.rec, nil
	}
	return nil, nil
}

// Feature: bellu-security-knowledge-graph, Property 38: API key lifecycle (verification outcomes)
// **Validates: Requirements 18.2, 18.3, 18.4**
func TestProperty38VerifierOutcomes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`[A-Za-z0-9._-]{1,64}`).Draw(t, "name")
		key, rec, err := Generate(nil, name, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		v := NewVerifier(&idSrc{rec: &rec}, nil)
		ctx := context.Background()
		if got, err := v.Verify(ctx, key); err != nil || got != name {
			t.Fatalf("valid key: %q %v", got, err)
		}
		// arbitrary strings, modified keys and revoked keys all give the same error
		i := rapid.IntRange(0, len(key)-1).Draw(t, "i")
		b := []byte(key)
		b[i] ^= 1
		other := rapid.String().Draw(t, "other")
		for _, k := range []string{string(b), other, key + "x"} {
			if k == key {
				continue
			}
			if _, err := v.Verify(ctx, k); err != ErrUnauthorized {
				t.Fatalf("%q: %v", k, err)
			}
		}
		now := time.Now()
		rev := rec
		rev.RevokedAt = &now
		v2 := NewVerifier(&idSrc{rec: &rev}, nil)
		if _, err := v2.Verify(ctx, key); err != ErrUnauthorized {
			t.Fatalf("revoked: %v", err)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 38: API key lifecycle (invalid names)
// **Validates: Requirements 18.1**
func TestProperty38InvalidNames(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.String().Draw(t, "name")
		valid := len(name) >= 1 && len(name) <= 64
		for _, r := range name {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
				valid = false
			}
		}
		_, _, err := Generate(nil, name, time.Now())
		if valid != (err == nil) {
			t.Fatalf("name %q valid=%v err=%v", name, valid, err)
		}
	})
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, k := range []string{"", "bskg", "bskg_zz_x", "bskg_0011223344556677_", "x_0011223344556677_s", "bskg_001122_s"} {
		if _, _, ok := Parse(k); ok {
			t.Errorf("accepted %q", k)
		}
	}
	if _, s, ok := Parse("bskg_0011223344556677_a_b-c"); !ok || s != "a_b-c" {
		t.Errorf("secret with underscore: %q %v", s, ok)
	}
}

func TestValidateName(t *testing.T) {
	for _, n := range []string{"", strings.Repeat("a", 65), "a b", "a/b", "é"} {
		if ValidateName(n) == nil {
			t.Errorf("accepted %q", n)
		}
		if _, _, err := Generate(nil, n, time.Now()); err == nil {
			t.Errorf("generated for %q", n)
		}
	}
	for _, n := range []string{"a", strings.Repeat("a", 64), "ci.agent_1-x"} {
		if err := ValidateName(n); err != nil {
			t.Errorf("rejected %q", n)
		}
	}
}

type fakeSrc struct {
	rec   *Record
	calls int
}

func (f *fakeSrc) Lookup(context.Context, string) (*Record, error) { f.calls++; return f.rec, nil }

func TestVerifierCacheAndRevocation(t *testing.T) {
	key, rec, _ := Generate(nil, "agent", time.Now())
	src := &fakeSrc{rec: &rec}
	clock := time.Unix(1000, 0)
	v := NewVerifier(src, func() time.Time { return clock })
	ctx := context.Background()

	if n, err := v.Verify(ctx, key); err != nil || n != "agent" {
		t.Fatalf("verify: %q %v", n, err)
	}
	if _, err := v.Verify(ctx, key); err != nil || src.calls != 1 {
		t.Fatalf("expected cache hit, calls=%d err=%v", src.calls, err)
	}
	// revoke in the store; cached entry still serves for under 2 s, not after
	revoked := rec
	at := clock
	revoked.RevokedAt = &at
	src.rec = &revoked
	clock = clock.Add(CacheTTL)
	if _, err := v.Verify(ctx, key); err != ErrUnauthorized {
		t.Fatalf("revoked key after TTL: %v", err)
	}
	if CacheTTL >= 5*time.Second {
		t.Fatal("TTL too long for 18.7")
	}
}

func TestVerifierIdenticalFailures(t *testing.T) {
	key, rec, _ := Generate(nil, "agent", time.Now())
	v := NewVerifier(&fakeSrc{rec: nil}, nil)
	for _, k := range []string{"", "garbage", key} {
		if _, err := v.Verify(context.Background(), k); err != ErrUnauthorized {
			t.Errorf("%q: %v", k, err)
		}
	}
	v = NewVerifier(&fakeSrc{rec: &rec}, nil)
	if _, err := v.Verify(context.Background(), key+"x"); err != ErrUnauthorized {
		t.Errorf("wrong secret: %v", err)
	}
}
