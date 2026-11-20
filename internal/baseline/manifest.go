// Package baseline fetches, verifies, and loads the pinned VulKG baseline.
package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

// Logical file names. The loader addresses files by these names only, so the
// upstream typo "Vulnerabiliy_" never reaches the load code.
const (
	LogicalVulnerabilityNodes         = "VulnerabilityNodes"
	LogicalVulnerabilityAddProperties = "VulnerabilityNodesAddProperties"
	LogicalExploitNodes               = "ExploitNodes"
	LogicalHasExploit                 = "HasExploit"
	LogicalWeaknessNodes              = "WeaknessNodes"
	LogicalDomainRelationship         = "DomainRefers"
	LogicalProductVendorAffects       = "ProductAffects"
	LogicalAffectsAddProperty         = "AffectsAddProperty"
)

// RequiredLogicalFiles lists the eight files every manifest must contain once.
var RequiredLogicalFiles = []string{
	LogicalVulnerabilityNodes,
	LogicalVulnerabilityAddProperties,
	LogicalExploitNodes,
	LogicalHasExploit,
	LogicalWeaknessNodes,
	LogicalDomainRelationship,
	LogicalProductVendorAffects,
	LogicalAffectsAddProperty,
}

const (
	MinFileSize       int64 = 1
	MaxFileSize       int64 = 10737418240
	MaxKeyLength            = 1024
	upstreamTypo            = "Vulnerabiliy_"
	upstreamFixed           = "Vulnerability_"
	dateLayout              = "2006-01-02"
	placeholderBucket       = "REPLACE_WITH_BASELINE_BUCKET"
)

var (
	sha256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	commitRe = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

	// ErrPlaceholder is returned for a manifest that still holds template values.
	ErrPlaceholder = errors.New("manifest is an unpublished placeholder (zeroed checksum or commit); run scripts/baseline-publish.sh")
)

// Manifest is the Baseline_Manifest.
type Manifest struct {
	Upstream Upstream       `json:"upstream"`
	Bucket   BucketRef      `json:"bucket"`
	Files    []ManifestFile `json:"files"`
}

// Upstream identifies the pinned VulKG commit.
type Upstream struct {
	Repo     string `json:"repo"`
	Commit   string `json:"commit"`
	CopiedOn string `json:"copiedOn"`
}

// BucketRef names the S3 bucket and key prefix that hold the files.
type BucketRef struct {
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
}

// ManifestFile is one baseline import file.
type ManifestFile struct {
	Logical    string `json:"logical"`
	RepoName   string `json:"repoName"`
	ScriptName string `json:"scriptName"`
	Key        string `json:"key"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
}

// ParseManifest decodes and validates a manifest. Unknown JSON fields are rejected.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: invalid JSON: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// LoadManifest reads and validates a manifest file.
func LoadManifest(p string) (*Manifest, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return ParseManifest(data)
}

// File returns the entry for a logical name.
func (m *Manifest) File(logical string) (ManifestFile, bool) {
	for _, f := range m.Files {
		if f.Logical == logical {
			return f, true
		}
	}
	return ManifestFile{}, false
}

// IsPlaceholder reports whether the manifest still carries template values.
func (m *Manifest) IsPlaceholder() bool {
	if isAllZero(m.Upstream.Commit) || m.Bucket.Name == placeholderBucket {
		return true
	}
	for _, f := range m.Files {
		if isAllZero(f.SHA256) {
			return true
		}
	}
	return false
}

// Validate checks every field range and returns all violations joined.
// A placeholder manifest with otherwise valid fields returns ErrPlaceholder.
func (m *Manifest) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf("manifest: "+format, a...)) }

	if !commitRe.MatchString(m.Upstream.Commit) {
		add("upstream.commit must be 40 hexadecimal characters")
	}
	if m.Upstream.Repo == "" {
		add("upstream.repo must not be empty")
	}
	if _, err := time.Parse(dateLayout, m.Upstream.CopiedOn); err != nil || len(m.Upstream.CopiedOn) != len(dateLayout) {
		add("upstream.copiedOn must be a YYYY-MM-DD date")
	}
	if m.Bucket.Name == "" {
		add("bucket.name must not be empty")
	}

	seen := map[string]int{}
	required := map[string]bool{}
	for _, l := range RequiredLogicalFiles {
		required[l] = true
	}
	for i, f := range m.Files {
		seen[f.Logical]++
		label := fmt.Sprintf("files[%d] (%q)", i, f.Logical)
		if !required[f.Logical] {
			add("%s: unknown logical name", label)
		}
		if !sha256Re.MatchString(f.SHA256) {
			add("%s: sha256 must be 64 hexadecimal characters", label)
		}
		if f.Size < MinFileSize || f.Size > MaxFileSize {
			add("%s: size must be from %d to %d bytes", label, MinFileSize, MaxFileSize)
		}
		if n := len(f.Key); n < 1 || n > MaxKeyLength {
			add("%s: key must be 1 to %d characters", label, MaxKeyLength)
		}
		if f.RepoName == "" {
			add("%s: repoName must not be empty", label)
		}
		if f.ScriptName == "" || strings.ContainsAny(f.ScriptName, `/\`) || f.ScriptName == "." || f.ScriptName == ".." {
			add("%s: scriptName must be a plain file name", label)
		} else if f.RepoName != "" {
			if want := ScriptNameFor(f.RepoName); f.ScriptName != want {
				add("%s: scriptName %q must equal the repoName base with %q replaced by %q (%q)",
					label, f.ScriptName, upstreamTypo, upstreamFixed, want)
			}
		}
	}
	for _, l := range RequiredLogicalFiles {
		switch seen[l] {
		case 1:
		case 0:
			add("missing entry for logical file %q", l)
		default:
			add("logical file %q listed %d times, want exactly once", l, seen[l])
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if m.IsPlaceholder() {
		return ErrPlaceholder
	}
	return nil
}

// ScriptNameFor maps an upstream repository file name to the name the VulKG
// deployment script loads, fixing the "Vulnerabiliy_" typo.
func ScriptNameFor(repoName string) string {
	return strings.ReplaceAll(path.Base(repoName), upstreamTypo, upstreamFixed)
}

func isAllZero(s string) bool {
	return s != "" && strings.Trim(s, "0") == ""
}

func parseDate(s string) (time.Time, error) { return time.Parse(dateLayout, s) }
