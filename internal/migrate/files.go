// Package migrate applies the embedded, versioned Cypher migrations to the
// graph. Parsing, ordering, and checksum logic is pure; the Runner talks to
// Neo4j through the Store interface.
package migrate

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed files/*.cypher
var embedded embed.FS

// Migration is one parsed migration file.
type Migration struct {
	Version    int
	Name       string
	Checksum   string // lowercase hex SHA-256 of the raw file bytes
	Statements []string
}

var fileName = regexp.MustCompile(`^V(\d+)__([A-Za-z0-9_]+)\.cypher$`)

// Embedded returns the migrations compiled into the binary, ascending by version.
func Embedded() ([]Migration, error) {
	sub, err := fs.Sub(embedded, "files")
	if err != nil {
		return nil, err
	}
	return Load(sub)
}

// Load parses every V<version>__<name>.cypher file at the root of fsys and
// returns them in ascending version order. Duplicate versions and
// malformed names are errors.
func Load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []Migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cypher") {
			continue
		}
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migrate: file %q does not match V<version>__<name>.cypher", e.Name())
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("migrate: file %q: bad version", e.Name())
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("migrate: version %d used by both %q and %q", v, prev, e.Name())
		}
		seen[v] = e.Name()
		raw, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		out = append(out, Migration{
			Version:    v,
			Name:       m[2],
			Checksum:   hex.EncodeToString(sum[:]),
			Statements: SplitStatements(string(raw)),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// SplitStatements splits text on lines that contain only ";" (surrounding
// whitespace ignored). Statements are trimmed; blank and comment-only
// statements are dropped.
func SplitStatements(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	var out []string
	var cur []string
	flush := func() {
		s := strings.TrimSpace(strings.Join(cur, "\n"))
		cur = cur[:0]
		if hasCode(s) {
			out = append(out, s)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == ";" {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return out
}

func hasCode(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "//") {
			return true
		}
	}
	return false
}

// Applied is a stored Migration record.
type Applied struct {
	Version  int
	Checksum string
}

// Plan verifies the applied records against the files and returns the
// pending migrations in ascending order. An applied version with no file, or
// whose checksum differs from the file, is an error.
func Plan(files []Migration, applied []Applied) ([]Migration, error) {
	byVersion := make(map[int]Migration, len(files))
	for _, f := range files {
		byVersion[f.Version] = f
	}
	done := map[int]bool{}
	for _, a := range applied {
		f, ok := byVersion[a.Version]
		if !ok {
			return nil, fmt.Errorf("migrate: applied migration V%03d has no embedded file", a.Version)
		}
		if f.Checksum != a.Checksum {
			return nil, fmt.Errorf("migrate: applied migration V%03d (%s) was edited: checksum differs from the stored one", f.Version, f.Name)
		}
		done[a.Version] = true
	}
	var pending []Migration
	for _, f := range files {
		if !done[f.Version] {
			pending = append(pending, f)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Version < pending[j].Version })
	return pending, nil
}
