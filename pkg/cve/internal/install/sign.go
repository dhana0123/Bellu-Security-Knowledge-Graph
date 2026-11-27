package install

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/sign"
)

// SigSuffix is appended to a package URL to form its detached signature URL.
const SigSuffix = ".sig"

// IndexSigName is the file name of the detached signature of index.json.
const IndexSigName = "index.json.sig"

// localPath maps a package or signature URL from an index to a slash-separated
// path under the publish directory. Absolute URLs need baseURL as their prefix.
func localPath(url, baseURL string) (string, error) {
	rel := url
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		prefix := strings.TrimRight(baseURL, "/") + "/"
		if baseURL == "" || !strings.HasPrefix(url, prefix) {
			return "", fmt.Errorf("install: url %q is not under the base url", url)
		}
		rel = strings.TrimPrefix(url, prefix)
	}
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return "", fmt.Errorf("install: unsafe url %q", url)
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == ".." || part == "." {
			return "", fmt.Errorf("install: unsafe url %q", url)
		}
	}
	return filepath.FromSlash(rel), nil
}

// SignDir rebuilds the index of dir, adds the signature URL of every package,
// and writes dir/index.json, a detached <package>.sig for every package, and
// dir/index.json.sig. The output is deterministic: the same packages and key
// give the same bytes (Ed25519 signatures are deterministic).
//
// Packages and their signatures are written before index.json, and
// index.json.sig is written last.
func SignDir(dir, baseURL string, priv ed25519.PrivateKey) (Index, error) {
	idx, err := BuildIndex(dir, baseURL)
	if err != nil {
		return Index{}, err
	}
	for i := range idx.Snapshots {
		idx.Snapshots[i].SigURL = idx.Snapshots[i].URL + SigSuffix
		if idx.Snapshots[i].ID == idx.Latest.ID {
			idx.Latest.SigURL = idx.Snapshots[i].SigURL
		}
	}
	for i := range idx.Deltas {
		idx.Deltas[i].SigURL = idx.Deltas[i].URL + SigSuffix
	}
	var urls []string
	for _, s := range idx.Snapshots {
		urls = append(urls, s.URL)
	}
	for _, d := range idx.Deltas {
		urls = append(urls, d.URL)
	}
	for _, u := range urls {
		rel, err := localPath(u, baseURL)
		if err != nil {
			return Index{}, err
		}
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return Index{}, err
		}
		if err := os.WriteFile(filepath.Join(dir, rel+SigSuffix), sign.Sign(priv, data), 0o644); err != nil {
			return Index{}, err
		}
	}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return Index{}, err
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(dir, "index.json"), b, 0o644); err != nil {
		return Index{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, IndexSigName), sign.Sign(priv, b), 0o644); err != nil {
		return Index{}, err
	}
	return idx, nil
}

// VerifyDir checks a signed publish directory against the pinned keys: the
// signature of index.json, then for every snapshot and delta the size, the
// SHA-256 recorded in the index, and the detached signature. The first
// failure is returned and names the package. It returns the verified index.
func VerifyDir(dir, baseURL string, keys []ed25519.PublicKey) (Index, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return Index{}, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, IndexSigName))
	if err != nil {
		return Index{}, err
	}
	if _, err := sign.Verify(keys, raw, sig); err != nil {
		return Index{}, fmt.Errorf("install: index.json: %w", err)
	}
	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return Index{}, fmt.Errorf("install: index.json: %w", err)
	}
	type entry struct {
		url, sigURL, sum string
		size             int64
	}
	var entries []entry
	for _, s := range idx.Snapshots {
		entries = append(entries, entry{s.URL, s.SigURL, s.SHA256, s.Size})
	}
	for _, d := range idx.Deltas {
		entries = append(entries, entry{d.URL, d.SigURL, d.SHA256, d.Size})
	}
	if idx.Latest.SigURL == "" {
		return Index{}, fmt.Errorf("install: index.json: latest has no sig_url")
	}
	for _, e := range entries {
		if e.sigURL == "" {
			return Index{}, fmt.Errorf("install: %s: index has no sig_url", e.url)
		}
		rel, err := localPath(e.url, baseURL)
		if err != nil {
			return Index{}, err
		}
		srel, err := localPath(e.sigURL, baseURL)
		if err != nil {
			return Index{}, err
		}
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return Index{}, fmt.Errorf("install: %s: %w", e.url, err)
		}
		if int64(len(data)) != e.size {
			return Index{}, fmt.Errorf("install: %s: size differs from index", e.url)
		}
		psig, err := os.ReadFile(filepath.Join(dir, srel))
		if err != nil {
			return Index{}, fmt.Errorf("install: %s: %w", e.url, err)
		}
		if err := sign.VerifyPack(keys, data, e.sum, psig); err != nil {
			return Index{}, fmt.Errorf("install: %s: %w", e.url, err)
		}
	}
	return idx, nil
}
