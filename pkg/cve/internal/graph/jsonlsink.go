package graph

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// jsonlHeader is the first line of every JSONL export file.
type jsonlHeader struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	Type          string `json:"type"`
}

type jsonlNodeRec struct {
	ID    string          `json:"id"`
	Type  string          `json:"type"`
	Props json.RawMessage `json:"props"`
}

type jsonlEdgeRec struct {
	ID    string          `json:"id"`
	Type  string          `json:"type"`
	Src   string          `json:"src"`
	Dst   string          `json:"dst"`
	Props json.RawMessage `json:"props"`
}

func jsonlNodeFile(t string) string { return "nodes-" + t + ".jsonl" }
func jsonlEdgeFile(t string) string { return "edges-" + t + ".jsonl" }

type jsonlOut struct {
	f *os.File
	w *bufio.Writer
}

// JSONLSink writes one JSONL file per node type and per edge type into a
// temporary directory (<dir>.tmp) that is renamed to dir on Commit. Files for
// types without records contain only the header, so the file set is stable.
type JSONLSink struct {
	dir, tmp string
	nodes    map[string]*jsonlOut
	edges    map[string]*jsonlOut
	nodeIDs  *IDSet
	edgeIDs  *IDSet
	active   bool
	trust    bool
}

// TrustUniqueIDs turns off the in-memory duplicate id check. Projector calls it because Build
// already guarantees unique ids; without it the check holds every id of the export in memory.
func (s *JSONLSink) TrustUniqueIDs() { s.trust = true }

var _ Sink = (*JSONLSink)(nil)

// NewJSONLSink returns a sink that will produce the export directory dir.
func NewJSONLSink(dir string) *JSONLSink {
	dir = filepath.Clean(dir)
	return &JSONLSink{dir: dir, tmp: dir + ".tmp"}
}

// Begin creates the temp directory and all header lines.
func (s *JSONLSink) Begin(_ context.Context, meta SinkMeta) (err error) {
	if s.active {
		return errors.New("jsonlsink: already begun")
	}
	version := meta.SchemaVersion
	if version == "" {
		version = SchemaVersion
	}
	if err := os.RemoveAll(s.tmp); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.dir), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(s.tmp, 0o755); err != nil {
		return err
	}
	s.nodes, s.edges = map[string]*jsonlOut{}, map[string]*jsonlOut{}
	s.nodeIDs, s.edgeIDs = NewIDSet(), NewIDSet()
	if s.trust {
		s.nodeIDs, s.edgeIDs = nil, nil
	}
	s.active = true
	defer func() {
		if err != nil {
			_ = s.Abort()
		}
	}()
	open := func(name, kind, typ string) (*jsonlOut, error) {
		f, err := os.Create(filepath.Join(s.tmp, name))
		if err != nil {
			return nil, err
		}
		o := &jsonlOut{f: f, w: bufio.NewWriter(f)}
		h, err := json.Marshal(jsonlHeader{SchemaVersion: version, Kind: kind, Type: typ})
		if err != nil {
			return o, err
		}
		_, err = o.w.Write(append(h, '\n'))
		return o, err
	}
	for _, t := range AllNodeTypes {
		o, err := open(jsonlNodeFile(t), "nodes", t)
		if o != nil {
			s.nodes[t] = o
		}
		if err != nil {
			return err
		}
	}
	for _, t := range AllEdgeTypes {
		o, err := open(jsonlEdgeFile(t), "edges", t)
		if o != nil {
			s.edges[t] = o
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func writeLine(o *jsonlOut, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := o.w.Write(b); err != nil {
		return err
	}
	return o.w.WriteByte('\n')
}

// WriteNode appends the node to the file of its type.
func (s *JSONLSink) WriteNode(n Node) error {
	if !s.active {
		return errors.New("jsonlsink: not active")
	}
	o, ok := s.nodes[n.Type]
	if !ok {
		return fmt.Errorf("jsonlsink: unknown node type %q", n.Type)
	}
	if err := s.checkID(s.nodeIDs, n.ID); err != nil {
		return err
	}
	props, err := CanonicalProps(n.Props)
	if err != nil {
		return fmt.Errorf("graph: node %s props: %w", n.ID, err)
	}
	return writeLine(o, jsonlNodeRec{ID: n.ID, Type: n.Type, Props: props})
}

// WriteEdge appends the edge to the file of its type.
func (s *JSONLSink) WriteEdge(e Edge) error {
	if !s.active {
		return errors.New("jsonlsink: not active")
	}
	o, ok := s.edges[e.Type]
	if !ok {
		return fmt.Errorf("jsonlsink: unknown edge type %q", e.Type)
	}
	if err := s.checkID(s.edgeIDs, e.ID); err != nil {
		return err
	}
	props, err := CanonicalProps(e.Props)
	if err != nil {
		return fmt.Errorf("graph: edge %s props: %w", e.ID, err)
	}
	return writeLine(o, jsonlEdgeRec{ID: e.ID, Type: e.Type, Src: e.Src, Dst: e.Dst, Props: props})
}

func (s *JSONLSink) checkID(set *IDSet, id string) error {
	if set == nil {
		return CheckID(id)
	}
	return set.Add(id)
}

func (s *JSONLSink) closeAll(sync bool) error {
	var first error
	for _, m := range []map[string]*jsonlOut{s.nodes, s.edges} {
		for _, o := range m {
			if err := o.w.Flush(); err != nil && first == nil {
				first = err
			}
			if sync {
				if err := o.f.Sync(); err != nil && first == nil {
					first = err
				}
			}
			if err := o.f.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	s.nodes, s.edges = nil, nil
	return first
}

// Commit flushes all files and renames the temp directory to the target.
// An existing target directory is replaced; it is restored if the rename fails.
func (s *JSONLSink) Commit() error {
	if !s.active {
		return errors.New("jsonlsink: not active")
	}
	if err := s.closeAll(true); err != nil {
		_ = s.Abort()
		return err
	}
	old := s.dir + ".old"
	hadOld := false
	if _, err := os.Stat(s.dir); err == nil {
		_ = os.RemoveAll(old)
		if err := os.Rename(s.dir, old); err != nil {
			_ = s.Abort()
			return err
		}
		hadOld = true
	}
	if err := os.Rename(s.tmp, s.dir); err != nil {
		if hadOld {
			_ = os.Rename(old, s.dir)
		}
		_ = s.Abort()
		return err
	}
	if hadOld {
		_ = os.RemoveAll(old)
	}
	s.active = false
	if d, err := os.Open(filepath.Dir(s.dir)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Abort removes the temp directory; the export location is left untouched.
func (s *JSONLSink) Abort() error {
	_ = s.closeAll(false)
	s.active = false
	return os.RemoveAll(s.tmp)
}
