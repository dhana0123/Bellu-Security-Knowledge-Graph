package install

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/sign"
)

// Validates: Requirements 19.10
func signedDir(t *testing.T) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	canon := canonFile(t)
	p, _ := build(t, canon, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	dir := t.TempDir()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snap.tar.gz"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignDir(dir, "", priv); err != nil {
		t.Fatal(err)
	}
	return dir, pub, priv
}

func flip(t *testing.T, p string) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyRoundTripAndDeterminism(t *testing.T) {
	dir, pub, priv := signedDir(t)
	idx, err := VerifyDir(dir, "", []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if idx.Latest.SigURL != "snap.tar.gz.sig" || idx.Snapshots[0].SigURL != "snap.tar.gz.sig" || idx.Snapshots[0].SHA256 == "" {
		t.Fatalf("index lacks signature references: %+v", idx)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	sigBefore, _ := os.ReadFile(filepath.Join(dir, IndexSigName))
	if _, err := SignDir(dir, "", priv); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	sigAfter, _ := os.ReadFile(filepath.Join(dir, IndexSigName))
	if string(before) != string(after) || string(sigBefore) != string(sigAfter) {
		t.Fatal("signing twice changed the output")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	for _, name := range []string{"snap.tar.gz", "snap.tar.gz.sig", "index.json", IndexSigName} {
		dir, pub, _ := signedDir(t)
		flip(t, filepath.Join(dir, name))
		if _, err := VerifyDir(dir, "", []ed25519.PublicKey{pub}); err == nil {
			t.Fatalf("flipped byte in %s was not detected", name)
		}
	}
}

func TestVerifyRejectsUnpinnedKeyAndAcceptsRotation(t *testing.T) {
	dir, pub, _ := signedDir(t)
	other, _, _ := sign.GenerateKey()
	if _, err := VerifyDir(dir, "", []ed25519.PublicKey{other}); err == nil {
		t.Fatal("unpinned key accepted")
	}
	if _, err := VerifyDir(dir, "", []ed25519.PublicKey{other, pub}); err != nil {
		t.Fatalf("rotation with two pinned keys: %v", err)
	}
}
