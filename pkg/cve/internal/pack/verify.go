package pack

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
)

// MaxPackageSize bounds the total uncompressed size of a package.
var MaxPackageSize int64 = 256 << 30

const maxMetaSize = 64 << 20 // per small file held in memory

// PackageError attributes a verification failure to a package entry.
type PackageError struct {
	File   string
	Reason string
	Err    error
}

func (e *PackageError) Unwrap() error { return e.Err }

func (e *PackageError) Error() string {
	if e.File == "" {
		return "pack: " + e.Reason
	}
	return fmt.Sprintf("pack: %s: %s", e.File, e.Reason)
}

func perr(file, format string, a ...any) error {
	return &PackageError{File: file, Reason: fmt.Sprintf(format, a...)}
}

// ErrChecksum is wrapped by checksum mismatches.
var ErrChecksum = errors.New("checksum mismatch")

func validEntryName(n string) error {
	if n == "" || strings.HasPrefix(n, "/") || strings.Contains(n, "\\") || strings.ContainsRune(n, 0) {
		return errors.New("invalid path")
	}
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return errors.New("invalid path")
		}
	}
	if path.Clean(n) != n {
		return errors.New("invalid path")
	}
	return nil
}

// VerifyPackage checks a snapshot package: exact file set, safe entries,
// checksums and manifest, and returns the manifest.
func VerifyPackage(p string) (Manifest, error) {
	f, err := os.Open(p)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return Manifest{}, perr("", "not a gzip archive: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	want := map[string]bool{}
	for _, n := range SnapshotFiles {
		want[n] = true
	}
	sums := map[string]string{}
	small := map[string][]byte{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Manifest{}, perr("", "reading archive: %v", err)
		}
		if err := validEntryName(h.Name); err != nil {
			return Manifest{}, perr(h.Name, "%v", err)
		}
		if h.Typeflag != tar.TypeReg {
			return Manifest{}, perr(h.Name, "not a regular file")
		}
		if !want[h.Name] {
			return Manifest{}, perr(h.Name, "unexpected file")
		}
		if _, dup := sums[h.Name]; dup {
			return Manifest{}, perr(h.Name, "duplicate entry")
		}
		if h.Size < 0 {
			return Manifest{}, perr(h.Name, "negative size")
		}
		total += h.Size
		if total > MaxPackageSize {
			return Manifest{}, perr(h.Name, "package exceeds size limit of %d bytes", MaxPackageSize)
		}
		hash := sha256.New()
		var dst io.Writer = hash
		var buf *bytes.Buffer
		if h.Name != FileGraphDB {
			if h.Size > maxMetaSize {
				return Manifest{}, perr(h.Name, "file too large")
			}
			buf = &bytes.Buffer{}
			dst = io.MultiWriter(hash, buf)
		}
		n, err := io.Copy(dst, io.LimitReader(tr, h.Size+1))
		if err != nil {
			return Manifest{}, perr(h.Name, "reading: %v", err)
		}
		if n != h.Size {
			return Manifest{}, perr(h.Name, "size mismatch")
		}
		sums[h.Name] = hex.EncodeToString(hash.Sum(nil))
		if buf != nil {
			small[h.Name] = buf.Bytes()
		}
	}
	// drain trailing gzip data to detect corruption
	if _, err := io.Copy(io.Discard, zr); err != nil {
		return Manifest{}, perr("", "reading archive: %v", err)
	}
	for _, n := range SnapshotFiles {
		if _, ok := sums[n]; !ok {
			return Manifest{}, perr(n, "missing file")
		}
	}

	listed, err := parseChecksums(small[FileChecksums])
	if err != nil {
		return Manifest{}, err
	}
	for _, n := range SnapshotFiles {
		if n == FileChecksums {
			continue
		}
		exp, ok := listed[n]
		if !ok {
			return Manifest{}, perr(n, "missing from %s", FileChecksums)
		}
		if exp != sums[n] {
			return Manifest{}, &PackageError{File: n, Reason: "checksum mismatch", Err: ErrChecksum}
		}
	}
	for n := range listed {
		if _, ok := sums[n]; !ok || n == FileChecksums {
			return Manifest{}, perr(n, "listed in %s but not a covered package file", FileChecksums)
		}
	}

	var m Manifest
	if err := strictJSON(small[FileManifest], &m); err != nil {
		return Manifest{}, perr(FileManifest, "%v", err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, perr(FileManifest, "%v", err)
	}
	var sv struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(small[FileSchemaVer], &sv); err != nil || sv.SchemaVersion != m.SchemaVersion {
		return Manifest{}, perr(FileSchemaVer, "invalid or does not match manifest schema_version")
	}
	for _, n := range []string{FileSources, FileStatistics} {
		if !json.Valid(small[n]) {
			return Manifest{}, perr(n, "invalid JSON")
		}
	}
	return m, nil
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func parseChecksums(b []byte) (map[string]string, error) {
	out := map[string]string{}
	var prev string
	for i, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if len(line) < 67 || line[64:66] != "  " || !digestRe.MatchString(line[:64]) {
			return nil, perr(FileChecksums, "malformed line %d", i+1)
		}
		name := line[66:]
		if err := validEntryName(name); err != nil {
			return nil, perr(FileChecksums, "line %d: %v", i+1, err)
		}
		if _, dup := out[name]; dup {
			return nil, perr(FileChecksums, "duplicate entry for %s", name)
		}
		if prev != "" && name <= prev {
			return nil, perr(FileChecksums, "entries not sorted at line %d", i+1)
		}
		prev = name
		out[name] = line[:64]
	}
	return out, nil
}

func formatChecksums(sums map[string]string) []byte {
	names := make([]string, 0, len(sums))
	for n := range sums {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", sums[n], n)
	}
	return b.Bytes()
}
