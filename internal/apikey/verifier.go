package apikey

import (
	"context"
	"sync"
	"time"
)

// CacheTTL bounds how stale a cached record can be; it keeps revocation
// effective within the 5 s required by Requirement 18.7.
const CacheTTL = 2 * time.Second

// Lookup finds a record by key id. It returns (nil, nil) when none exists.
type Lookup interface {
	Lookup(ctx context.Context, id string) (*Record, error)
}

type cacheEntry struct {
	rec     *Record
	expires time.Time
}

// Verifier authenticates keys against a Lookup with a short in-memory cache.
type Verifier struct {
	src Lookup
	now func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// NewVerifier returns a Verifier. now may be nil (time.Now).
func NewVerifier(src Lookup, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{src: src, now: now, cache: map[string]cacheEntry{}}
}

// Verify returns the key name for a valid, active key. Every failure caused
// by the key (malformed, unknown, wrong secret, revoked) returns
// ErrUnauthorized. Lookup failures return that error unchanged.
func (v *Verifier) Verify(ctx context.Context, key string) (string, error) {
	id, secret, ok := Parse(key)
	if !ok {
		Check(nil, key)
		return "", ErrUnauthorized
	}
	rec, err := v.get(ctx, id)
	if err != nil {
		return "", err
	}
	if !Check(rec, secret) {
		return "", ErrUnauthorized
	}
	return rec.Name, nil
}

func (v *Verifier) get(ctx context.Context, id string) (*Record, error) {
	now := v.now()
	v.mu.Lock()
	e, hit := v.cache[id]
	v.mu.Unlock()
	if hit && now.Before(e.expires) {
		return e.rec, nil
	}
	rec, err := v.src.Lookup(ctx, id)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	if len(v.cache) > 1024 { // bound memory against random-id probing
		for k, c := range v.cache {
			if !now.Before(c.expires) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) > 1024 {
			v.cache = map[string]cacheEntry{}
		}
	}
	v.cache[id] = cacheEntry{rec: rec, expires: now.Add(CacheTTL)}
	v.mu.Unlock()
	return rec, nil
}
