package pack

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
)

// Delta package entry names.
const FileDelta = "delta.jsonl"

// DeltaFiles lists the exact entries of a delta package, sorted.
var DeltaFiles = []string{FileChecksums, FileDelta, FileManifest}

// DeltaKind is the manifest kind of a delta package.
const DeltaKind = "delta"

// Op names in delta.jsonl, in the order they must appear.
const (
	OpDeleteEdge = "delete_edge"
	OpDeleteNode = "delete_node"
	OpUpsertNode = "upsert_node"
	OpUpsertEdge = "upsert_edge"
)

var opRank = map[string]int{OpDeleteEdge: 0, OpDeleteNode: 1, OpUpsertNode: 2, OpUpsertEdge: 3}

// maxOpLine bounds one delta.jsonl line.
const maxOpLine = 64 << 20

// DeltaCounts holds the operation counts of a delta.
type DeltaCounts struct {
	UpsertNodes    int64 `json:"upsert_nodes"`
	DeleteNodes    int64 `json:"delete_nodes"`
	UpsertEdges    int64 `json:"upsert_edges"`
	DeleteEdges    int64 `json:"delete_edges"`
	ChangedRecords int64 `json:"changed_records"`
}

// DeltaManifest is the content of a delta package's manifest.json. RecordCounts
// and LogicalDigest describe the target snapshot, so an installer can verify
// the result of applying the delta.
type DeltaManifest struct {
	Kind              string       `json:"kind"`
	Product           string       `json:"product"`
	BaseSnapshotID    string       `json:"base_snapshot_id"`
	TargetSnapshotID  string       `json:"target_snapshot_id"`
	SchemaVersion     string       `json:"schema_version"`
	DistributionLevel graph.Level  `json:"distribution_level"`
	Ecosystems        []string     `json:"ecosystems"`
	CreatedAt         time.Time    `json:"created_at"`
	Counts            DeltaCounts  `json:"counts"`
	RecordCounts      RecordCounts `json:"record_counts"`
	LogicalDigest     string       `json:"logical_digest"`
	Files             []string     `json:"files"`
}

// Validate checks the manifest fields.
func (m DeltaManifest) Validate() error {
	if m.Kind != DeltaKind {
		return fmt.Errorf("manifest: kind %q, want %q", m.Kind, DeltaKind)
	}
	if m.Product != Product {
		return fmt.Errorf("manifest: product %q, want %q", m.Product, Product)
	}
	for _, id := range []string{m.BaseSnapshotID, m.TargetSnapshotID} {
		if !snapshotIDRe.MatchString(id) {
			return fmt.Errorf("manifest: malformed snapshot id %q", id)
		}
	}
	if !digestRe.MatchString(m.LogicalDigest) {
		return fmt.Errorf("manifest: malformed logical_digest %q", m.LogicalDigest)
	}
	switch m.DistributionLevel {
	case graph.LevelCore, graph.LevelEcosystem, graph.LevelComplete:
	default:
		return fmt.Errorf("manifest: unsupported distribution_level %q", string(m.DistributionLevel))
	}
	if m.SchemaVersion == "" {
		return errors.New("manifest: schema_version is required")
	}
	if m.CreatedAt.IsZero() || m.CreatedAt.Location() != time.UTC {
		return errors.New("manifest: created_at must be a UTC time")
	}
	if len(m.Ecosystems) > MaxEcosystems {
		return fmt.Errorf("manifest: %d ecosystems exceeds %d", len(m.Ecosystems), MaxEcosystems)
	}
	if m.RecordCounts.Nodes == nil || m.RecordCounts.Edges == nil {
		return errors.New("manifest: record_counts.nodes and record_counts.edges are required")
	}
	c := m.Counts
	if c.UpsertNodes < 0 || c.DeleteNodes < 0 || c.UpsertEdges < 0 || c.DeleteEdges < 0 {
		return errors.New("manifest: negative delta count")
	}
	if c.ChangedRecords != c.UpsertNodes+c.DeleteNodes+c.UpsertEdges+c.DeleteEdges {
		return errors.New("manifest: changed_records is not the sum of the operation counts")
	}
	if !reflect.DeepEqual(m.Files, DeltaFiles) {
		return fmt.Errorf("manifest: files %v, want %v", m.Files, DeltaFiles)
	}
	return nil
}

// DeltaOptions configures BuildDelta.
type DeltaOptions struct {
	BasePackage   string // snapshot package of the base
	TargetPackage string // snapshot package of the target
	OutDir        string
}

// Op is one parsed line of delta.jsonl.
type Op struct {
	Op    string
	ID    string
	Type  string
	Src   string
	Dst   string
	Props json.RawMessage
	H     string
}

// BuildDelta computes the delta from the base to the target snapshot package
// and writes bellu-delta-<base>-to-<target>.tar.gz into OutDir.
func BuildDelta(ctx context.Context, opts DeltaOptions) (string, DeltaManifest, error) {
	if opts.BasePackage == "" || opts.TargetPackage == "" || opts.OutDir == "" {
		return "", DeltaManifest{}, errors.New("pack: BasePackage, TargetPackage and OutDir are required")
	}
	bm, err := VerifyPackage(opts.BasePackage)
	if err != nil {
		return "", DeltaManifest{}, fmt.Errorf("pack: base package: %w", err)
	}
	tm, err := VerifyPackage(opts.TargetPackage)
	if err != nil {
		return "", DeltaManifest{}, fmt.Errorf("pack: target package: %w", err)
	}
	if bm.SchemaVersion != tm.SchemaVersion {
		return "", DeltaManifest{}, fmt.Errorf("pack: schema_version differs: base %q, target %q", bm.SchemaVersion, tm.SchemaVersion)
	}
	if bm.DistributionLevel != tm.DistributionLevel {
		return "", DeltaManifest{}, fmt.Errorf("pack: distribution_level differs: base %q, target %q", bm.DistributionLevel, tm.DistributionLevel)
	}
	if !reflect.DeepEqual(nonNil(bm.Ecosystems), nonNil(tm.Ecosystems)) {
		return "", DeltaManifest{}, fmt.Errorf("pack: ecosystems differ: base %v, target %v", bm.Ecosystems, tm.Ecosystems)
	}
	work, err := os.MkdirTemp("", "bellu-delta-*")
	if err != nil {
		return "", DeltaManifest{}, err
	}
	defer os.RemoveAll(work)
	baseDB := filepath.Join(work, "base.db")
	targetDB := filepath.Join(work, "target.db")
	if err := extractEntry(opts.BasePackage, FileGraphDB, baseDB); err != nil {
		return "", DeltaManifest{}, err
	}
	if err := extractEntry(opts.TargetPackage, FileGraphDB, targetDB); err != nil {
		return "", DeltaManifest{}, err
	}
	opsPath := filepath.Join(work, FileDelta)
	counts, opsSum, err := writeOps(ctx, baseDB, targetDB, opsPath)
	if err != nil {
		return "", DeltaManifest{}, err
	}
	m := DeltaManifest{
		Kind: DeltaKind, Product: Product,
		BaseSnapshotID: bm.SnapshotID, TargetSnapshotID: tm.SnapshotID,
		SchemaVersion: tm.SchemaVersion, DistributionLevel: tm.DistributionLevel,
		Ecosystems: nonNil(tm.Ecosystems), CreatedAt: tm.CreatedAt.UTC(),
		Counts: counts, RecordCounts: tm.RecordCounts, LogicalDigest: tm.LogicalDigest,
		Files: append([]string(nil), DeltaFiles...),
	}
	mb, err := marshal(m)
	if err != nil {
		return "", DeltaManifest{}, err
	}
	ms := sha256.Sum256(mb)
	cks := formatChecksums(map[string]string{FileManifest: hex.EncodeToString(ms[:]), FileDelta: opsSum})
	if err := ctx.Err(); err != nil {
		return "", DeltaManifest{}, err
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return "", DeltaManifest{}, err
	}
	final := filepath.Join(opts.OutDir, fmt.Sprintf("bellu-delta-%s-to-%s.tar.gz", bm.SnapshotID, tm.SnapshotID))
	partial := final + ".partial"
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(partial)
		}
	}()
	if err := writeDeltaTarGz(partial, map[string][]byte{FileManifest: mb, FileChecksums: cks}, opsPath, m.CreatedAt); err != nil {
		return "", DeltaManifest{}, err
	}
	got, err := VerifyDelta(partial)
	if err != nil {
		return "", DeltaManifest{}, fmt.Errorf("pack: verifying built delta: %w", err)
	}
	if !reflect.DeepEqual(got, m) {
		return "", DeltaManifest{}, errors.New("pack: built delta manifest differs from expected")
	}
	if err := os.Rename(partial, final); err != nil {
		return "", DeltaManifest{}, err
	}
	ok = true
	if d, err := os.Open(opts.OutDir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return final, got, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// extractEntry copies one regular entry of a (verified) package to dest.
func extractEntry(pkg, name, dest string) error {
	f, err := os.Open(pkg)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return perr(name, "missing file")
		}
		if err != nil {
			return err
		}
		if h.Name != name || h.Typeflag != tar.TypeReg {
			continue
		}
		out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
}

type opWriter struct {
	w    *bufio.Writer
	hash io.Writer
}

func (o *opWriter) line(op, id, typ, src, dst, props, h string, withBody, edge bool) error {
	var b bytes.Buffer
	q := func(s string) []byte { x, _ := json.Marshal(s); return x }
	b.WriteString(`{"op":`)
	b.Write(q(op))
	b.WriteString(`,"id":`)
	b.Write(q(id))
	if withBody {
		b.WriteString(`,"type":`)
		b.Write(q(typ))
		if edge {
			b.WriteString(`,"src":`)
			b.Write(q(src))
			b.WriteString(`,"dst":`)
			b.Write(q(dst))
		}
		if !json.Valid([]byte(props)) || bytes.ContainsAny([]byte(props), "\r\n") {
			return fmt.Errorf("pack: record %q has non-canonical props", id)
		}
		b.WriteString(`,"props":`)
		b.WriteString(props)
		b.WriteString(`,"h":`)
		b.Write(q(h))
	}
	b.WriteString("}\n")
	_, err := o.w.Write(b.Bytes())
	return err
}

// writeOps computes the diff and writes delta.jsonl, returning counts and the file sha256.
func writeOps(ctx context.Context, baseDB, targetDB, out string) (DeltaCounts, string, error) {
	var c DeltaCounts
	db, err := sql.Open("sqlite", roURI(targetDB))
	if err != nil {
		return c, "", err
	}
	defer db.Close()
	conn, err := db.Conn(ctx) // ATTACH is per connection
	if err != nil {
		return c, "", err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `ATTACH DATABASE ? AS base`, baseDB); err != nil {
		return c, "", err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return c, "", err
	}
	defer f.Close()
	h := sha256.New()
	bw := bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20)
	ow := &opWriter{w: bw}
	type step struct {
		op    string
		query string
		edge  bool
		body  bool
		n     *int64
	}
	steps := []step{
		{OpDeleteEdge, `SELECT b.id FROM base.edges b LEFT JOIN main.edges t ON t.id=b.id WHERE t.id IS NULL ORDER BY b.id`, true, false, &c.DeleteEdges},
		{OpDeleteNode, `SELECT b.id FROM base.nodes b LEFT JOIN main.nodes t ON t.id=b.id WHERE t.id IS NULL ORDER BY b.id`, false, false, &c.DeleteNodes},
		{OpUpsertNode, `SELECT t.id, t.type, t.props, t.h FROM main.nodes t LEFT JOIN base.nodes b ON b.id=t.id WHERE b.id IS NULL OR b.h<>t.h ORDER BY t.id`, false, true, &c.UpsertNodes},
		{OpUpsertEdge, `SELECT t.id, t.type, t.src, t.dst, t.props, t.h FROM main.edges t LEFT JOIN base.edges b ON b.id=t.id WHERE b.id IS NULL OR b.h<>t.h ORDER BY t.id`, true, true, &c.UpsertEdges},
	}
	for _, s := range steps {
		rows, err := conn.QueryContext(ctx, s.query)
		if err != nil {
			return c, "", err
		}
		for rows.Next() {
			var id, typ, src, dst, props, hh string
			switch {
			case !s.body:
				err = rows.Scan(&id)
			case s.edge:
				err = rows.Scan(&id, &typ, &src, &dst, &props, &hh)
			default:
				err = rows.Scan(&id, &typ, &props, &hh)
			}
			if err == nil {
				err = ow.line(s.op, id, typ, src, dst, props, hh, s.body, s.edge)
			}
			if err != nil {
				rows.Close()
				return c, "", err
			}
			*s.n++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return c, "", err
		}
		rows.Close()
	}
	if err := bw.Flush(); err != nil {
		return c, "", err
	}
	if err := f.Sync(); err != nil {
		return c, "", err
	}
	c.ChangedRecords = c.UpsertNodes + c.DeleteNodes + c.UpsertEdges + c.DeleteEdges
	return c, hex.EncodeToString(h.Sum(nil)), nil
}

func writeDeltaTarGz(dest string, files map[string][]byte, opsPath string, mtime time.Time) (err error) {
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
		}
	}()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, n := range DeltaFiles {
		var size int64
		var src io.Reader
		if n == FileDelta {
			g, err := os.Open(opsPath)
			if err != nil {
				return err
			}
			defer g.Close()
			fi, err := g.Stat()
			if err != nil {
				return err
			}
			size, src = fi.Size(), g
		} else {
			size, src = int64(len(files[n])), bytes.NewReader(files[n])
		}
		hdr := &tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: size, ModTime: mtime, Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, src); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// VerifyDelta checks a delta package: exact file set, safe entries, checksums,
// manifest, and that delta.jsonl is well formed, ordered, and matches the counts.
func VerifyDelta(p string) (DeltaManifest, error) {
	f, err := os.Open(p)
	if err != nil {
		return DeltaManifest{}, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return DeltaManifest{}, perr("", "not a gzip archive: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	want := map[string]bool{}
	for _, n := range DeltaFiles {
		want[n] = true
	}
	sums := map[string]string{}
	small := map[string][]byte{}
	var total int64
	var got DeltaCounts
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return DeltaManifest{}, perr("", "reading archive: %v", err)
		}
		if err := validEntryName(h.Name); err != nil {
			return DeltaManifest{}, perr(h.Name, "%v", err)
		}
		if h.Typeflag != tar.TypeReg {
			return DeltaManifest{}, perr(h.Name, "not a regular file")
		}
		if !want[h.Name] {
			return DeltaManifest{}, perr(h.Name, "unexpected file")
		}
		if _, dup := sums[h.Name]; dup {
			return DeltaManifest{}, perr(h.Name, "duplicate entry")
		}
		if h.Size < 0 {
			return DeltaManifest{}, perr(h.Name, "negative size")
		}
		total += h.Size
		if total > MaxPackageSize {
			return DeltaManifest{}, perr(h.Name, "package exceeds size limit of %d bytes", MaxPackageSize)
		}
		hash := sha256.New()
		src := io.LimitReader(tr, h.Size+1)
		if h.Name == FileDelta {
			// stream: hash while validating
			pr, pw := io.Pipe()
			done := make(chan error, 1)
			go func() {
				c, e := scanOps(pr, nil)
				got = c
				_, _ = io.Copy(io.Discard, pr)
				done <- e
			}()
			n, cerr := io.Copy(io.MultiWriter(hash, pw), src)
			if cerr != nil {
				pw.CloseWithError(cerr)
			} else {
				pw.Close()
			}
			if e := <-done; e != nil {
				return DeltaManifest{}, perr(h.Name, "%v", e)
			}
			if cerr != nil {
				return DeltaManifest{}, perr(h.Name, "reading: %v", cerr)
			}
			if n != h.Size {
				return DeltaManifest{}, perr(h.Name, "size mismatch")
			}
		} else {
			if h.Size > maxMetaSize {
				return DeltaManifest{}, perr(h.Name, "file too large")
			}
			var buf bytes.Buffer
			n, err := io.Copy(io.MultiWriter(hash, &buf), src)
			if err != nil {
				return DeltaManifest{}, perr(h.Name, "reading: %v", err)
			}
			if n != h.Size {
				return DeltaManifest{}, perr(h.Name, "size mismatch")
			}
			small[h.Name] = buf.Bytes()
		}
		sums[h.Name] = hex.EncodeToString(hash.Sum(nil))
	}
	if _, err := io.Copy(io.Discard, zr); err != nil {
		return DeltaManifest{}, perr("", "reading archive: %v", err)
	}
	for _, n := range DeltaFiles {
		if _, ok := sums[n]; !ok {
			return DeltaManifest{}, perr(n, "missing file")
		}
	}
	listed, err := parseChecksums(small[FileChecksums])
	if err != nil {
		return DeltaManifest{}, err
	}
	for _, n := range []string{FileDelta, FileManifest} {
		exp, ok := listed[n]
		if !ok {
			return DeltaManifest{}, perr(n, "missing from %s", FileChecksums)
		}
		if exp != sums[n] {
			return DeltaManifest{}, &PackageError{File: n, Reason: "checksum mismatch", Err: ErrChecksum}
		}
	}
	if len(listed) != 2 {
		return DeltaManifest{}, perr(FileChecksums, "lists files other than %s and %s", FileDelta, FileManifest)
	}
	var m DeltaManifest
	if err := strictJSON(small[FileManifest], &m); err != nil {
		return DeltaManifest{}, perr(FileManifest, "%v", err)
	}
	if err := m.Validate(); err != nil {
		return DeltaManifest{}, perr(FileManifest, "%v", err)
	}
	if got != m.Counts {
		return DeltaManifest{}, perr(FileDelta, "operation counts %+v do not match manifest %+v", got, m.Counts)
	}
	return m, nil
}

// scanOps parses and validates a delta.jsonl stream (well-formed ops, required
// order, ids strictly increasing within each op kind), calling fn per op when
// fn is not nil. It returns the op counts.
func scanOps(r io.Reader, fn func(Op) error) (DeltaCounts, error) {
	var c DeltaCounts
	br := bufio.NewReaderSize(r, 1<<20)
	lastRank, lastID := -1, ""
	for ln := 1; ; ln++ {
		line, err := readLine(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			return c, err
		}
		op, err := parseOp(line)
		if err != nil {
			return c, fmt.Errorf("line %d: %v", ln, err)
		}
		rank := opRank[op.Op]
		switch {
		case rank < lastRank:
			return c, fmt.Errorf("line %d: %s out of order", ln, op.Op)
		case rank == lastRank && op.ID <= lastID:
			return c, fmt.Errorf("line %d: ids not strictly increasing within %s", ln, op.Op)
		}
		lastRank, lastID = rank, op.ID
		switch op.Op {
		case OpDeleteEdge:
			c.DeleteEdges++
		case OpDeleteNode:
			c.DeleteNodes++
		case OpUpsertNode:
			c.UpsertNodes++
		case OpUpsertEdge:
			c.UpsertEdges++
		}
		if fn != nil {
			if err := fn(op); err != nil {
				return c, err
			}
		}
	}
	c.ChangedRecords = c.UpsertNodes + c.DeleteNodes + c.UpsertEdges + c.DeleteEdges
	return c, nil
}

// readLine returns the next newline-terminated line; io.EOF only at clean end.
func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxOpLine {
			return nil, errors.New("line too long")
		}
		switch err {
		case nil:
			return line[:len(line)-1], nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if len(line) == 0 {
				return nil, io.EOF
			}
			return nil, errors.New("missing trailing newline")
		default:
			return nil, err
		}
	}
}

func parseOp(line []byte) (Op, error) {
	var raw struct {
		Op    *string          `json:"op"`
		ID    *string          `json:"id"`
		Type  *string          `json:"type"`
		Src   *string          `json:"src"`
		Dst   *string          `json:"dst"`
		Props *json.RawMessage `json:"props"`
		H     *string          `json:"h"`
	}
	if err := strictJSON(line, &raw); err != nil {
		return Op{}, err
	}
	if raw.Op == nil || raw.ID == nil || *raw.ID == "" {
		return Op{}, errors.New("op and id are required")
	}
	op := Op{Op: *raw.Op, ID: *raw.ID}
	str := func(name string, p *string, need bool) (string, error) {
		if p == nil {
			if need {
				return "", fmt.Errorf("%s is required for %s", name, op.Op)
			}
			return "", nil
		}
		if !need {
			return "", fmt.Errorf("%s not allowed for %s", name, op.Op)
		}
		if *p == "" {
			return "", fmt.Errorf("%s must not be empty", name)
		}
		return *p, nil
	}
	var needBody, needEdge bool
	switch op.Op {
	case OpDeleteEdge, OpDeleteNode:
	case OpUpsertNode:
		needBody = true
	case OpUpsertEdge:
		needBody, needEdge = true, true
	default:
		return Op{}, fmt.Errorf("unknown op %q", op.Op)
	}
	var err error
	if op.Type, err = str("type", raw.Type, needBody); err != nil {
		return Op{}, err
	}
	if op.H, err = str("h", raw.H, needBody); err != nil {
		return Op{}, err
	}
	if op.Src, err = str("src", raw.Src, needEdge); err != nil {
		return Op{}, err
	}
	if op.Dst, err = str("dst", raw.Dst, needEdge); err != nil {
		return Op{}, err
	}
	if needBody {
		if raw.Props == nil || len(*raw.Props) == 0 {
			return Op{}, errors.New("props is required")
		}
		op.Props = *raw.Props
	} else if raw.Props != nil {
		return Op{}, fmt.Errorf("props not allowed for %s", op.Op)
	}
	return op, nil
}

// ApplyOps validates and applies a delta.jsonl stream inside the caller's
// transaction. The caller commits or rolls back, and verifies the result
// (counts, LogicalDigest).
func ApplyOps(ctx context.Context, tx *sql.Tx, ops io.Reader) error {
	stmts := map[string]*sql.Stmt{}
	for k, q := range map[string]string{
		OpDeleteEdge: `DELETE FROM edges WHERE id=?`,
		OpDeleteNode: `DELETE FROM nodes WHERE id=?`,
		OpUpsertNode: `INSERT INTO nodes(id,type,props,h) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET type=excluded.type, props=excluded.props, h=excluded.h`,
		OpUpsertEdge: `INSERT INTO edges(id,type,src,dst,props,h) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET type=excluded.type, src=excluded.src, dst=excluded.dst, props=excluded.props, h=excluded.h`,
	} {
		s, err := tx.PrepareContext(ctx, q)
		if err != nil {
			return err
		}
		defer s.Close()
		stmts[k] = s
	}
	_, err := scanOps(ops, func(o Op) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		switch o.Op {
		case OpDeleteEdge, OpDeleteNode:
			_, err = stmts[o.Op].ExecContext(ctx, o.ID)
		case OpUpsertNode:
			_, err = stmts[o.Op].ExecContext(ctx, o.ID, o.Type, string(o.Props), o.H)
		case OpUpsertEdge:
			_, err = stmts[o.Op].ExecContext(ctx, o.ID, o.Type, o.Src, o.Dst, string(o.Props), o.H)
		}
		return err
	})
	return err
}

// LogicalDigest returns the logical digest (SHA-256 over sorted kind/h pairs)
// of a graph.db file.
func LogicalDigest(dbPath string) (string, error) {
	m, _, err := inspectGraphDB(context.Background(), dbPath, graph.LevelComplete)
	if err != nil {
		return "", err
	}
	return m.LogicalDigest, nil
}
