package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/pack"
)

// IndexSchemaVersion is the index.json format version.
const IndexSchemaVersion = "1"

// Index is the content of index.json, the catalogue that Sync reads.
//
//	{
//	  "product": "Bellu Global Intelligence",
//	  "schema_version": "1",
//	  "latest":    {"id","level","ecosystems","url","sha256","size","created_at"},
//	  "snapshots": [{same fields as latest}],
//	  "deltas":    [{"base","target","url","sha256","size","changed_records",
//	                 "level","ecosystems"}]
//	}
//
// sig_url (set by "bellu-intel sign", empty otherwise) names the detached
// signature of the package.
//
// url is absolute (http, https) or relative to the location of index.json.
// sha256 is the lower-case hex digest of the package file. size is in bytes.
// level and ecosystems on a delta are optional; when present Sync only uses
// the delta for an installation with the same level and ecosystems.
// Snapshots and deltas are sorted (snapshots by id, deltas by base then
// target) so that the file is deterministic.
type Index struct {
	Product       string          `json:"product"`
	SchemaVersion string          `json:"schema_version"`
	Latest        IndexSnapshot   `json:"latest"`
	Snapshots     []IndexSnapshot `json:"snapshots"`
	Deltas        []IndexDelta    `json:"deltas"`
}

// IndexSnapshot describes one full snapshot package.
type IndexSnapshot struct {
	ID         string      `json:"id"`
	Level      graph.Level `json:"level"`
	Ecosystems []string    `json:"ecosystems"`
	URL        string      `json:"url"`
	SHA256     string      `json:"sha256"`
	Size       int64       `json:"size"`
	CreatedAt  time.Time   `json:"created_at"`
	SigURL     string      `json:"sig_url,omitempty"`
}

// IndexDelta describes one delta package.
type IndexDelta struct {
	Base           string      `json:"base"`
	Target         string      `json:"target"`
	URL            string      `json:"url"`
	SHA256         string      `json:"sha256"`
	Size           int64       `json:"size"`
	ChangedRecords int64       `json:"changed_records"`
	Level          graph.Level `json:"level,omitempty"`
	Ecosystems     []string    `json:"ecosystems,omitempty"`
	SigURL         string      `json:"sig_url,omitempty"`
}

// BuildIndex scans dir recursively for *.tar.gz packages, verifies each with
// pack.VerifyPackage or pack.VerifyDelta, and returns the index. The latest
// snapshot is the one with the newest created_at (ties: greatest id). baseURL
// is prefixed to each package's slash-separated path relative to dir; an empty
// baseURL gives relative URLs.
func BuildIndex(dir, baseURL string) (Index, error) {
	idx := Index{Product: pack.Product, SchemaVersion: IndexSchemaVersion,
		Snapshots: []IndexSnapshot{}, Deltas: []IndexDelta{}}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".tar.gz") {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		url := filepath.ToSlash(rel)
		if baseURL != "" {
			url = strings.TrimRight(baseURL, "/") + "/" + url
		}
		sum, err := hashFile(p)
		if err != nil {
			return err
		}
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		if m, err := pack.VerifyPackage(p); err == nil {
			idx.Snapshots = append(idx.Snapshots, IndexSnapshot{ID: m.SnapshotID, Level: m.DistributionLevel,
				Ecosystems: append([]string{}, m.Ecosystems...), URL: url, SHA256: sum, Size: fi.Size(), CreatedAt: m.CreatedAt})
			return nil
		}
		dm, derr := pack.VerifyDelta(p)
		if derr != nil {
			return fmt.Errorf("install: %s is neither a valid snapshot nor a valid delta: %w", rel, derr)
		}
		idx.Deltas = append(idx.Deltas, IndexDelta{Base: dm.BaseSnapshotID, Target: dm.TargetSnapshotID, URL: url,
			SHA256: sum, Size: fi.Size(), ChangedRecords: dm.Counts.ChangedRecords,
			Level: dm.DistributionLevel, Ecosystems: append([]string{}, dm.Ecosystems...)})
		return nil
	})
	if err != nil {
		return Index{}, err
	}
	sort.Slice(idx.Snapshots, func(i, j int) bool { return idx.Snapshots[i].ID < idx.Snapshots[j].ID })
	sort.Slice(idx.Deltas, func(i, j int) bool {
		a, b := idx.Deltas[i], idx.Deltas[j]
		if a.Base != b.Base {
			return a.Base < b.Base
		}
		return a.Target < b.Target
	})
	if len(idx.Snapshots) == 0 {
		return Index{}, errors.New("install: no snapshot packages found")
	}
	idx.Latest = idx.Snapshots[0]
	for _, s := range idx.Snapshots[1:] {
		if s.CreatedAt.After(idx.Latest.CreatedAt) || (s.CreatedAt.Equal(idx.Latest.CreatedAt) && s.ID > idx.Latest.ID) {
			idx.Latest = s
		}
	}
	return idx, nil
}

// WriteIndex builds the index of dir and writes it to dir/index.json.
func WriteIndex(dir, baseURL string) (Index, error) {
	idx, err := BuildIndex(dir, baseURL)
	if err != nil {
		return Index{}, err
	}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return Index{}, err
	}
	return idx, os.WriteFile(filepath.Join(dir, "index.json"), append(b, '\n'), 0o644)
}
