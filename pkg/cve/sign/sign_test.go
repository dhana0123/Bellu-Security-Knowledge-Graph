package sign

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"testing/quick"
)

// Validates: Requirements 19.10
func TestRoundTripProperty(t *testing.T) {
	pub, priv, _ := GenerateKey()
	keys := []ed25519.PublicKey{pub}
	f := func(data []byte, bit uint) bool {
		sig := Sign(priv, data)
		if _, err := Verify(keys, data, sig); err != nil {
			return false
		}
		if len(data) == 0 {
			return true
		}
		bad := append([]byte{}, data...)
		bad[bit%uint(len(bad))] ^= 1
		_, err := Verify(keys, bad, sig)
		return errors.Is(err, ErrInvalidSignature)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

func TestKeyFilesAndMalformed(t *testing.T) {
	pub, priv, _ := GenerateKey()
	p2, err := ParsePrivateKey(EncodePrivateKey(priv))
	if err != nil || !p2.Equal(priv) {
		t.Fatalf("private key round trip: %v", err)
	}
	k2, err := ParsePublicKey(EncodePublicKey(pub))
	if err != nil || !k2.Equal(pub) {
		t.Fatalf("public key round trip: %v", err)
	}
	if _, err := Verify([]ed25519.PublicKey{pub}, []byte("x"), []byte("garbage")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
	if err := VerifyPack([]ed25519.PublicKey{pub}, []byte("x"), "00", Sign(priv, []byte("x"))); !errors.Is(err, ErrChecksum) {
		t.Fatalf("got %v", err)
	}
}
