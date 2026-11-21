package infratest

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoVulKGLoaderCode fails when code of the removed VulKG baseline loader
// returns to the repository (Requirements 1.6, 26.4).
func TestNoVulKGLoaderCode(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, p := range []string{"internal/baseline", "baseline/manifest.json", "scripts/baseline-publish.sh", "testdata/baseline", "cmd/bskg/baseline.go"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("removed VulKG loader path exists: %s", p)
		}
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), "s3store") {
			t.Errorf("removed S3 baseline client exists: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"go.mod", "go.sum"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "aws-sdk-go-v2") {
			t.Errorf("%s still references aws-sdk-go-v2", f)
		}
	}
}
