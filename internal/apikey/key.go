// Package apikey implements API key generation, hashing, verification, and
// storage in (:ApiKey) nodes. The crypto and verification logic is pure; only
// store.go touches the graph.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	prefix     = "bskg"
	idBytes    = 8
	saltBytes  = 16
	secretByte = 32 // 256-bit secret
)

var (
	// ErrInvalidName is returned for names outside 1..64 chars of [A-Za-z0-9._-].
	ErrInvalidName = errors.New("apikey: invalid name (1 to 64 characters of A-Z a-z 0-9 . _ -)")
	// ErrDuplicateName is returned when a key with the name already exists.
	ErrDuplicateName = errors.New("apikey: name already exists")
	// ErrNotFound is returned by Revoke for an unknown or already revoked key.
	ErrNotFound = errors.New("apikey: no active key with that name")
	// ErrUnauthorized is the single error for missing, malformed, unknown, and
	// revoked keys, so callers cannot tell the cases apart.
	ErrUnauthorized = errors.New("apikey: unauthorized")

	nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// ValidateName checks a key name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return ErrInvalidName
	}
	return nil
}

// Record is the stored form of a key. It holds no part of the secret except
// the salted SHA-256 hash.
type Record struct {
	ID        string
	Name      string
	Salt      []byte
	Hash      []byte
	CreatedAt time.Time
	RevokedAt *time.Time
}

// Revoked reports whether the key has been revoked.
func (r *Record) Revoked() bool { return r.RevokedAt != nil }

// HashSecret returns SHA-256(salt || secret).
func HashSecret(salt []byte, secret string) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(secret))
	return h.Sum(nil)
}

// Generate makes a new key "bskg_<id>_<secret>" and its stored Record. rnd is
// normally crypto/rand.Reader (nil selects it).
func Generate(rnd io.Reader, name string, now time.Time) (key string, rec Record, err error) {
	if err := ValidateName(name); err != nil {
		return "", Record{}, err
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	buf := make([]byte, idBytes+saltBytes+secretByte)
	if _, err := io.ReadFull(rnd, buf); err != nil {
		return "", Record{}, fmt.Errorf("apikey: random source: %w", err)
	}
	id := hex.EncodeToString(buf[:idBytes])
	salt := buf[idBytes : idBytes+saltBytes]
	secret := base64.RawURLEncoding.EncodeToString(buf[idBytes+saltBytes:])
	rec = Record{
		ID: id, Name: name, Salt: append([]byte(nil), salt...),
		Hash: HashSecret(salt, secret), CreatedAt: now.UTC(),
	}
	return prefix + "_" + id + "_" + secret, rec, nil
}

// Parse splits a key into id and secret. The id is hex and never contains an
// underscore, so the secret (which may contain '_') is everything after the
// second underscore.
func Parse(key string) (id, secret string, ok bool) {
	parts := strings.SplitN(key, "_", 3)
	if len(parts) != 3 || parts[0] != prefix || len(parts[1]) != idBytes*2 || parts[2] == "" {
		return "", "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// dummy is compared against when the id is unknown, to keep timing similar.
var (
	dummySalt = make([]byte, saltBytes)
	dummyHash = HashSecret(dummySalt, "dummy")
)

// Check verifies secret against rec in constant time. A nil rec runs a dummy
// comparison and returns false. A revoked record never verifies.
func Check(rec *Record, secret string) bool {
	if rec == nil {
		got := HashSecret(dummySalt, secret)
		subtle.ConstantTimeCompare(got, dummyHash)
		return false
	}
	got := HashSecret(rec.Salt, secret)
	eq := subtle.ConstantTimeCompare(got, rec.Hash) == 1
	return eq && !rec.Revoked()
}
