package graph

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadError reports the file and 1-based line at which a JSONL load failed.
// Line is 0 when the error concerns the file or directory as a whole.
type LoadError struct {
	File string
	Line int
	Err  error
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("graph: load %s:%d: %v", e.File, e.Line, e.Err)
}

func (e *LoadError) Unwrap() error { return e.Err }

// ErrUnsupportedSchema is returned (wrapped) for a header with an unknown schema version.
var ErrUnsupportedSchema = errors.New("unsupported schema version")

// ErrMissingNode is returned (wrapped) for an edge whose endpoint node does not exist.
var ErrMissingNode = errors.New("edge references missing node")

type loadFile struct {
	name string
	kind string // "nodes" or "edges"
	typ  string
}

// LoadJSONL loads a JSONL export directory into a new graph.db at targetDBPath.
// Node files are read before edge files. On any error a *LoadError is returned
// and no file is created at targetDBPath.
func LoadJSONL(ctx context.Context, dir, targetDBPath string, meta SinkMeta) (err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return &LoadError{File: dir, Err: err}
	}
	nodeSet, edgeSet := toSet(AllNodeTypes), toSet(AllEdgeTypes)
	var nodeFiles, edgeFiles []loadFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".jsonl") {
			return &LoadError{File: name, Err: errors.New("unexpected entry in export directory")}
		}
		base := strings.TrimSuffix(name, ".jsonl")
		switch {
		case strings.HasPrefix(base, "nodes-"):
			t := strings.TrimPrefix(base, "nodes-")
			if _, ok := nodeSet[t]; !ok {
				return &LoadError{File: name, Err: fmt.Errorf("unknown node type %q", t)}
			}
			nodeFiles = append(nodeFiles, loadFile{name, "nodes", t})
		case strings.HasPrefix(base, "edges-"):
			t := strings.TrimPrefix(base, "edges-")
			if _, ok := edgeSet[t]; !ok {
				return &LoadError{File: name, Err: fmt.Errorf("unknown edge type %q", t)}
			}
			edgeFiles = append(edgeFiles, loadFile{name, "edges", t})
		default:
			return &LoadError{File: name, Err: errors.New("unrecognised file name")}
		}
	}
	sort.Slice(nodeFiles, func(i, j int) bool { return nodeFiles[i].name < nodeFiles[j].name })
	sort.Slice(edgeFiles, func(i, j int) bool { return edgeFiles[i].name < edgeFiles[j].name })

	sink := NewSQLiteSink(targetDBPath)
	if err := sink.Begin(ctx, meta); err != nil {
		return &LoadError{File: targetDBPath, Err: err}
	}
	defer func() {
		if err != nil {
			_ = sink.Abort()
		}
	}()
	nodeIDs := NewIDSet()
	for _, f := range nodeFiles {
		if err = loadFileLines(ctx, dir, f, func(line int, raw []byte) error {
			var r jsonlNodeRec2
			if err := decodeStrict(raw, &r); err != nil {
				return err
			}
			if r.Type != f.typ {
				return fmt.Errorf("record type %q does not match file type %q", r.Type, f.typ)
			}
			if err := nodeIDs.Add(r.ID); err != nil {
				return err
			}
			return sink.WriteNode(Node{ID: r.ID, Type: r.Type, Props: r.Props})
		}); err != nil {
			return err
		}
	}
	for _, f := range edgeFiles {
		if err = loadFileLines(ctx, dir, f, func(line int, raw []byte) error {
			var r jsonlEdgeRec2
			if err := decodeStrict(raw, &r); err != nil {
				return err
			}
			if r.Type != f.typ {
				return fmt.Errorf("record type %q does not match file type %q", r.Type, f.typ)
			}
			if !nodeIDs.Seen(r.Src) {
				return fmt.Errorf("%w: src %q", ErrMissingNode, r.Src)
			}
			if !nodeIDs.Seen(r.Dst) {
				return fmt.Errorf("%w: dst %q", ErrMissingNode, r.Dst)
			}
			return sink.WriteEdge(Edge{ID: r.ID, Type: r.Type, Src: r.Src, Dst: r.Dst, Props: r.Props})
		}); err != nil {
			return err
		}
	}
	if err = sink.Commit(); err != nil {
		return &LoadError{File: targetDBPath, Err: err}
	}
	return nil
}

type jsonlNodeRec2 struct {
	ID    string         `json:"id"`
	Type  string         `json:"type"`
	Props map[string]any `json:"props"`
}

type jsonlEdgeRec2 struct {
	ID    string         `json:"id"`
	Type  string         `json:"type"`
	Src   string         `json:"src"`
	Dst   string         `json:"dst"`
	Props map[string]any `json:"props"`
}

// decodeStrict decodes exactly one JSON value, keeping numbers verbatim and
// rejecting unknown fields and trailing data.
func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func loadFileLines(ctx context.Context, dir string, f loadFile, rec func(line int, raw []byte) error) error {
	fh, err := os.Open(filepath.Join(dir, f.name))
	if err != nil {
		return &LoadError{File: f.name, Err: err}
	}
	defer fh.Close()
	r := bufio.NewReaderSize(fh, 1<<16)
	line := 0
	for {
		if err := ctx.Err(); err != nil {
			return &LoadError{File: f.name, Line: line, Err: err}
		}
		b, rerr := r.ReadBytes('\n')
		if len(b) == 0 && rerr == io.EOF {
			break
		}
		if rerr != nil && rerr != io.EOF {
			return &LoadError{File: f.name, Line: line + 1, Err: rerr}
		}
		line++
		b = bytes.TrimRight(b, "\r\n")
		if line == 1 {
			if err := checkHeader(b, f); err != nil {
				return &LoadError{File: f.name, Line: 1, Err: err}
			}
		} else if err := rec(line, b); err != nil {
			return &LoadError{File: f.name, Line: line, Err: err}
		}
		if rerr == io.EOF {
			break
		}
	}
	if line == 0 {
		return &LoadError{File: f.name, Line: 0, Err: errors.New("missing header line")}
	}
	return nil
}

func checkHeader(b []byte, f loadFile) error {
	var raw struct {
		SchemaVersion json.RawMessage `json:"schema_version"`
		Kind          string          `json:"kind"`
		Type          string          `json:"type"`
	}
	if err := decodeStrict(b, &raw); err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}
	ver := strings.Trim(string(raw.SchemaVersion), `"`)
	if ver != SchemaVersion {
		return fmt.Errorf("%w: %q", ErrUnsupportedSchema, ver)
	}
	if raw.Kind != f.kind || raw.Type != f.typ {
		return fmt.Errorf("header kind/type %q/%q does not match file %s", raw.Kind, raw.Type, f.name)
	}
	return nil
}
