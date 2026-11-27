// Package sign implements the detached Ed25519 signatures that protect
// index.json and the snapshot and delta packages. It is a public package so
// that other Go modules (for example bellucode) can verify what the publisher
// signs.
//
// A signature file is one text line:
//
//	bellu-sig-v1 ed25519 <key id> <base64 signature>
//
// The key id is the first 8 bytes of SHA-256 of the public key, in hex. A
// verifier tries every pinned key whose id matches, so several keys can be
// pinned at once during a key rotation.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const sigPrefix = "bellu-sig-v1 ed25519 "

// ErrInvalidSignature is returned when no pinned key verifies the data.
var ErrInvalidSignature = errors.New("sign: signature verification failed")

// ErrMalformed is returned when a signature or key file cannot be parsed.
var ErrMalformed = errors.New("sign: malformed input")

// KeyID returns the short identifier of a public key.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// GenerateKey returns a new key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodePrivateKey returns the key file text for priv: the base64 of the
// 32-byte seed, and a newline.
func EncodePrivateKey(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"
}

// EncodePublicKey returns the key file text for pub: base64 and a newline.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub) + "\n"
}

// ParsePrivateKey parses the output of EncodePrivateKey.
func ParsePrivateKey(text string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: private key must be the base64 of a %d-byte seed", ErrMalformed, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// ParsePublicKey parses the output of EncodePublicKey.
func ParsePublicKey(text string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key must be the base64 of %d bytes", ErrMalformed, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// Sign returns the detached signature file content for data.
func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, data)
	return []byte(sigPrefix + KeyID(pub) + " " + base64.StdEncoding.EncodeToString(sig) + "\n")
}

// Verify checks that sigFile is a valid signature of data by one of keys. It
// returns the id of the key that verified. A signature made by a key that is
// not pinned gives ErrInvalidSignature.
func Verify(keys []ed25519.PublicKey, data, sigFile []byte) (string, error) {
	line := strings.TrimSuffix(string(sigFile), "\n")
	if !strings.HasPrefix(line, sigPrefix) {
		return "", fmt.Errorf("%w: bad signature header", ErrMalformed)
	}
	fields := strings.Split(strings.TrimPrefix(line, sigPrefix), " ")
	if len(fields) != 2 {
		return "", fmt.Errorf("%w: expected key id and signature", ErrMalformed)
	}
	sig, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w: bad signature encoding", ErrMalformed)
	}
	for _, k := range keys {
		if len(k) != ed25519.PublicKeySize || KeyID(k) != fields[0] {
			continue
		}
		if ed25519.Verify(k, data, sig) {
			return fields[0], nil
		}
	}
	return "", ErrInvalidSignature
}

// ErrChecksum is returned by VerifyPack when the SHA-256 of the data differs
// from the value in the signed index.
var ErrChecksum = errors.New("sign: sha256 mismatch")

// VerifyPack checks data against wantSHA256 (lower-case hex, taken from the
// signed index) and then against its detached signature. The checksum is
// tested first so that a corrupt download is reported as such.
func VerifyPack(keys []ed25519.PublicKey, data []byte, wantSHA256 string, sigFile []byte) error {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(wantSHA256) {
		return ErrChecksum
	}
	_, err := Verify(keys, data, sigFile)
	return err
}
