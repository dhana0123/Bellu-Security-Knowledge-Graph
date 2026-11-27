package graph

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// CypherSink writes Memgraph-compatible Cypher text, one statement per line.
//
// Layout of the output file: index statements, then all node MERGEs, then all
// edge MATCH...MERGE statements (edges are buffered in a side file so nodes
// always precede them, whatever the write order).
//
// Property values: scalars become Cypher literals; arrays and maps become
// native Cypher lists and maps (Memgraph supports both as property values).
// Null properties are omitted (null inside a list is kept as null). Map keys
// are sorted at every depth, so output is deterministic.
type CypherSink struct {
	finalPath string
	tmpPath   string
	edgePath  string

	f      *os.File
	w      *bufio.Writer
	ef     *os.File
	ew     *bufio.Writer
	active bool
}

// NewCypherSink creates a sink that will produce finalPath on Commit.
func NewCypherSink(finalPath string) *CypherSink {
	return &CypherSink{finalPath: finalPath, tmpPath: finalPath + ".tmp", edgePath: finalPath + ".edges.tmp"}
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Begin opens the temp files and writes the index statements.
func (s *CypherSink) Begin(_ context.Context, meta SinkMeta) error {
	if s.active {
		return errors.New("cyphersink: already begun")
	}
	f, err := os.Create(s.tmpPath)
	if err != nil {
		return err
	}
	ef, err := os.Create(s.edgePath)
	if err != nil {
		f.Close()
		os.Remove(s.tmpPath)
		return err
	}
	s.f, s.w, s.ef, s.ew, s.active = f, bufio.NewWriter(f), ef, bufio.NewWriter(ef), true
	for _, t := range AllNodeTypes {
		if _, err := fmt.Fprintf(s.w, "CREATE INDEX ON :%s(id);\n", t); err != nil {
			_ = s.Abort()
			return err
		}
	}
	return nil
}

// WriteNode emits a MERGE statement for the node.
func (s *CypherSink) WriteNode(n Node) error {
	if !s.active {
		return errors.New("cyphersink: not begun")
	}
	if !identRe.MatchString(n.Type) {
		return fmt.Errorf("cyphersink: invalid label %q", n.Type)
	}
	if err := CheckID(n.ID); err != nil {
		return err
	}
	props, err := propsLiteral(n.Props)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(s.w, "MERGE (n:%s {id: %s}) SET n += %s;\n", n.Type, EscapeCypherString(n.ID), props)
	return err
}

// WriteEdge emits a MATCH ... MERGE statement for the edge.
func (s *CypherSink) WriteEdge(e Edge) error {
	if !s.active {
		return errors.New("cyphersink: not begun")
	}
	if !identRe.MatchString(e.Type) {
		return fmt.Errorf("cyphersink: invalid relationship type %q", e.Type)
	}
	if err := CheckID(e.ID); err != nil {
		return err
	}
	props, err := propsLiteral(e.Props)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(s.ew, "MATCH (a {id: %s}), (b {id: %s}) MERGE (a)-[r:%s {id: %s}]->(b) SET r += %s;\n",
		EscapeCypherString(e.Src), EscapeCypherString(e.Dst), e.Type, EscapeCypherString(e.ID), props)
	return err
}

// Commit appends the edge statements and atomically renames the temp file.
func (s *CypherSink) Commit() error {
	if !s.active {
		return errors.New("cyphersink: not begun")
	}
	if err := s.ew.Flush(); err != nil {
		_ = s.Abort()
		return err
	}
	if _, err := s.ef.Seek(0, io.SeekStart); err != nil {
		_ = s.Abort()
		return err
	}
	if _, err := io.Copy(s.w, s.ef); err != nil {
		_ = s.Abort()
		return err
	}
	if err := s.w.Flush(); err != nil {
		_ = s.Abort()
		return err
	}
	if err := s.f.Sync(); err != nil {
		_ = s.Abort()
		return err
	}
	if err := s.f.Close(); err != nil {
		s.f = nil
		_ = s.Abort()
		return err
	}
	s.f = nil
	_ = s.ef.Close()
	s.ef = nil
	_ = os.Remove(s.edgePath)
	s.active = false
	if err := os.Rename(s.tmpPath, s.finalPath); err != nil {
		_ = os.Remove(s.tmpPath)
		return err
	}
	return nil
}

// Abort removes temp files and leaves any existing final file untouched.
func (s *CypherSink) Abort() error {
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
	if s.ef != nil {
		_ = s.ef.Close()
		s.ef = nil
	}
	s.active = false
	var first error
	for _, p := range []string{s.tmpPath, s.edgePath} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}

// EscapeCypherString returns s as a double-quoted Cypher string literal.
// Backslash, double quote and all control characters are escaped, so a value
// can never terminate the literal.
func EscapeCypherString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case 0x2028, 0x2029, 0x7f:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else if r == 0xFFFD {
				b.WriteString("\uFFFD")
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func keyLiteral(k string) string {
	if identRe.MatchString(k) {
		return k
	}
	// Control characters cannot be escaped inside backticks; replace them with "_".
	k = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return '_'
		}
		return r
	}, k)
	return "`" + strings.ReplaceAll(k, "`", "``") + "`"
}

// propsLiteral renders a sorted map literal, omitting null values and the
// reserved key "id" (set separately).
func propsLiteral(props map[string]any) (string, error) {
	keys := make([]string, 0, len(props))
	for k := range props {
		if k == "id" || props[k] == nil {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	first := true
	for _, k := range keys {
		v, ok, err := valueLiteral(props[k])
		if err != nil {
			return "", fmt.Errorf("property %q: %w", k, err)
		}
		if !ok {
			continue
		}
		if !first {
			b.WriteString(", ")
		}
		first = false
		b.WriteString(keyLiteral(k))
		b.WriteString(": ")
		b.WriteString(v)
	}
	b.WriteByte('}')
	return b.String(), nil
}

// valueLiteral renders v; ok=false means the value is null and must be omitted.
func valueLiteral(v any) (string, bool, error) {
	switch x := v.(type) {
	case nil:
		return "", false, nil
	case string:
		return EscapeCypherString(x), true, nil
	case bool:
		return strconv.FormatBool(x), true, nil
	case int:
		return strconv.FormatInt(int64(x), 10), true, nil
	case int32:
		return strconv.FormatInt(int64(x), 10), true, nil
	case int64:
		return strconv.FormatInt(x, 10), true, nil
	case uint64:
		return strconv.FormatUint(x, 10), true, nil
	case float32:
		return floatLiteral(float64(x))
	case float64:
		return floatLiteral(x)
	case json.Number:
		return x.String(), true, nil
	case []string:
		a := make([]any, len(x))
		for i := range x {
			a[i] = x[i]
		}
		return listLiteral(a)
	case []any:
		return listLiteral(x)
	case map[string]any:
		s, err := propsMapLiteral(x)
		return s, err == nil, err
	}
	// Fallback: normalise through JSON.
	raw, err := json.Marshal(v)
	if err != nil {
		return "", false, err
	}
	var g any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&g); err != nil {
		return "", false, err
	}
	if _, isStr := g.(string); isStr {
		return EscapeCypherString(g.(string)), true, nil
	}
	return valueLiteral(g)
}

func floatLiteral(f float64) (string, bool, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", false, nil
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return s, true, nil
}

func listLiteral(a []any) (string, bool, error) {
	parts := make([]string, len(a))
	for i, e := range a {
		s, ok, err := valueLiteral(e)
		if err != nil {
			return "", false, err
		}
		if !ok {
			s = "null"
		}
		parts[i] = s
	}
	return "[" + strings.Join(parts, ", ") + "]", true, nil
}

// propsMapLiteral renders a nested map (including an "id" key, unlike top level).
func propsMapLiteral(m map[string]any) (string, error) {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v != nil {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, ok, err := valueLiteral(m[k])
		if err != nil {
			return "", err
		}
		if ok {
			parts = append(parts, keyLiteral(k)+": "+v)
		}
	}
	return "{" + strings.Join(parts, ", ") + "}", nil
}

var _ Sink = (*CypherSink)(nil)
