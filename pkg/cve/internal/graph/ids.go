package graph

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // id suffix only, not security relevant
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func VulnerabilityID(vulnID string) string { return "vuln:" + vulnID }
func AliasID(identifier string) string     { return "alias:" + identifier }
func SourceRecordID(source, externalID string) string {
	return "src:" + source + ":" + externalID
}
func PackageID(ecosystem, name string) string { return model.PackageID(ecosystem, name) }
func ProductID(vendor, product string) string { return model.ProductID(vendor, product) }
func VendorID(vendor string) string           { return "vendor:" + vendor }

// VersionID: targetID is a package or product id.
func VersionID(scheme, targetID, version string) string {
	return "ver:" + scheme + ":" + targetID + "@" + version
}
func WeaknessID(n string) string { return "cwe:" + n }

func SeverityID(source, sourceRecordID, typ, vector string) string {
	sum := sha1.Sum([]byte(vector)) //nolint:gosec
	return "sev:" + source + ":" + sourceRecordID + ":" + typ + ":" + hex.EncodeToString(sum[:])[:12]
}
func EPSSID(cve, date string) string { return "epss:" + cve + ":" + date }
func KEVID(cve string) string        { return "kev:" + cve }

func hash16(vuln, url, source string) string {
	sum := sha256.Sum256([]byte(vuln + "|" + url + "|" + source))
	return hex.EncodeToString(sum[:])[:16]
}
func ExploitID(vuln, url, source string) string { return "exp:" + hash16(vuln, url, source) }
func PatchID(vuln, url, source string) string   { return "patch:" + hash16(vuln, url, source) }

// EdgeID is the hex sha256 of "type|src|dst".
func EdgeID(typ, src, dst string) string {
	sum := sha256.Sum256([]byte(typ + "|" + src + "|" + dst))
	return hex.EncodeToString(sum[:])
}

// CanonicalJSON encodes v deterministically: object keys sorted at every
// depth, no HTML escaping, no trailing newline.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil { // maps are emitted with sorted keys
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// CanonicalProps returns the canonical JSON of props; nil is "{}".
func CanonicalProps(props map[string]any) ([]byte, error) {
	if props == nil {
		props = map[string]any{}
	}
	return CanonicalJSON(props)
}

func contentHash(m map[string]any) (string, error) {
	b, err := CanonicalJSON(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func quoteJSON(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return string(bytes.TrimRight(buf.Bytes(), "\n"))
}

// nodeHashFromProps is NodeHash for props that are already canonical JSON (CanonicalProps).
// The canonical form of the hashed object has sorted keys, so it is assembled directly instead
// of canonicalizing the props a second time.
func nodeHashFromProps(typ, id string, props []byte) string {
	h := sha256.New()
	h.Write([]byte(`{"id":` + quoteJSON(id) + `,"props":`))
	h.Write(props)
	h.Write([]byte(`,"type":` + quoteJSON(typ) + `}`))
	return hex.EncodeToString(h.Sum(nil))
}

// edgeHashFromProps is EdgeHash for props that are already canonical JSON.
func edgeHashFromProps(e Edge, props []byte) string {
	h := sha256.New()
	h.Write([]byte(`{"dst":` + quoteJSON(e.Dst) + `,"id":` + quoteJSON(e.ID) + `,"props":`))
	h.Write(props)
	h.Write([]byte(`,"src":` + quoteJSON(e.Src) + `,"type":` + quoteJSON(e.Type) + `}`))
	return hex.EncodeToString(h.Sum(nil))
}

// NodeHash is the content hash h of a node: sha256 over the canonical JSON of type, id, props.
func NodeHash(n Node) (string, error) {
	props := n.Props
	if props == nil {
		props = map[string]any{}
	}
	return contentHash(map[string]any{"type": n.Type, "id": n.ID, "props": props})
}

// EdgeHash is the content hash h of an edge: type, id, src, dst, props.
func EdgeHash(e Edge) (string, error) {
	props := e.Props
	if props == nil {
		props = map[string]any{}
	}
	return contentHash(map[string]any{"type": e.Type, "id": e.ID, "src": e.Src, "dst": e.Dst, "props": props})
}

// ErrEmptyID and ErrDuplicateID are returned by IDSet.
var (
	ErrEmptyID     = errors.New("graph: empty id")
	ErrDuplicateID = errors.New("graph: duplicate id")
)

// CheckID rejects empty ids.
func CheckID(id string) error {
	if id == "" {
		return ErrEmptyID
	}
	return nil
}

// IDSet enforces non-empty, unique ids within one projection.
type IDSet struct{ seen map[string]struct{} }

func NewIDSet() *IDSet { return &IDSet{seen: map[string]struct{}{}} }

// Add records id, failing on empty or already-present ids.
func (s *IDSet) Add(id string) error {
	if err := CheckID(id); err != nil {
		return err
	}
	if _, ok := s.seen[id]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicateID, id)
	}
	s.seen[id] = struct{}{}
	return nil
}

// Seen reports whether id was added. Useful for shared nodes emitted once.
func (s *IDSet) Seen(id string) bool { _, ok := s.seen[id]; return ok }

// Len returns the number of ids.
func (s *IDSet) Len() int { return len(s.seen) }

// NewEdge builds an edge with the stable id derived from type, src and dst.
func NewEdge(typ, src, dst string, props map[string]any) Edge {
	return Edge{ID: EdgeID(typ, src, dst), Type: typ, Src: src, Dst: dst, Props: props}
}
