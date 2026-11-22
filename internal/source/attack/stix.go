package attack

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// technique is one ATT&CK technique or sub-technique, merged over the
// domains that contain it.
type technique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	Tactics     []string `json:"tactics,omitempty"`
	Deprecated  bool     `json:"deprecated"`
	Revoked     bool     `json:"revoked"`
	URL         string   `json:"url,omitempty"`
}

var idRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// attackSources are the external_references source names that carry the
// ATT&CK id. Current objects use "mitre-attack"; some old mobile and ICS
// objects use a domain-specific name.
var attackSources = map[string]bool{
	"mitre-attack":        true,
	"mitre-mobile-attack": true,
	"mitre-ics-attack":    true,
}

// stixObject holds the fields of a STIX object this adapter reads. Every
// other field is skipped by the JSON decoder.
type stixObject struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Revoked     bool     `json:"revoked"`
	Deprecated  bool     `json:"x_mitre_deprecated"`
	Version     string   `json:"x_mitre_version"`
	Domains     []string `json:"x_mitre_domains"`
	ExternalRef []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
		URL        string `json:"url"`
	} `json:"external_references"`
	KillChain []struct {
		PhaseName string `json:"phase_name"`
	} `json:"kill_chain_phases"`
}

// bundle is the result of parsing one STIX bundle file.
type bundle struct {
	Release    string // x_mitre_version of the x-mitre-collection object
	Techniques []technique
}

// parseBundle streams the bundle at path. The file is never loaded as a
// whole: json.Decoder reads the objects array one object at a time.
// domain is the domain name of the file (enterprise-attack, ...); it is the
// domain of a technique that has no x_mitre_domains.
func parseBundle(path, domain string) (b bundle, err error) {
	f, oerr := os.Open(path)
	if oerr != nil {
		return b, oerr
	}
	defer f.Close()
	dec := json.NewDecoder(bufio.NewReaderSize(f, 1<<20))
	if err := expectDelim(dec, '{'); err != nil {
		return b, err
	}
	sawObjects := false
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return b, fmt.Errorf("invalid JSON: %w", err)
		}
		key, _ := kt.(string)
		switch key {
		case "type":
			var v string
			if err := dec.Decode(&v); err != nil {
				return b, fmt.Errorf("invalid JSON: %w", err)
			}
			if v != "bundle" {
				return b, fmt.Errorf("not a STIX bundle (type %q)", v)
			}
		case "objects":
			if sawObjects {
				return b, errors.New("bundle has two objects arrays")
			}
			sawObjects = true
			if err := readObjects(dec, domain, &b); err != nil {
				return b, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return b, fmt.Errorf("invalid JSON: %w", err)
			}
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return b, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return b, errors.New("invalid JSON: data after the bundle")
	}
	if !sawObjects {
		return b, errors.New("bundle has no objects array")
	}
	if b.Release == "" {
		return b, errors.New("bundle has no x-mitre-collection object with an x_mitre_version")
	}
	return b, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("invalid JSON: expected %q", string(want))
	}
	return nil
}

func readObjects(dec *json.Decoder, domain string, b *bundle) error {
	if err := expectDelim(dec, '['); err != nil {
		return err
	}
	seen := map[string]bool{}
	for dec.More() {
		var o stixObject
		if err := dec.Decode(&o); err != nil {
			return fmt.Errorf("invalid JSON object: %w", err)
		}
		switch o.Type {
		case "x-mitre-collection":
			if b.Release != "" {
				return errors.New("bundle has more than one x-mitre-collection object")
			}
			b.Release = strings.TrimSpace(o.Version)
		case "attack-pattern":
			t, err := toTechnique(o, domain)
			if err != nil {
				return err
			}
			if seen[t.ID] {
				return fmt.Errorf("technique %s appears twice in the bundle", t.ID)
			}
			seen[t.ID] = true
			b.Techniques = append(b.Techniques, t)
		}
	}
	return expectDelim(dec, ']')
}

func toTechnique(o stixObject, domain string) (technique, error) {
	t := technique{Name: o.Name, Description: o.Description, Deprecated: o.Deprecated, Revoked: o.Revoked}
	for _, r := range o.ExternalRef {
		if attackSources[r.SourceName] && r.ExternalID != "" {
			t.ID = strings.TrimSpace(r.ExternalID)
			t.URL = r.URL
			break
		}
	}
	if t.ID == "" {
		return t, fmt.Errorf("attack-pattern %s (%q) has no ATT&CK external_id", o.ID, o.Name)
	}
	if !idRe.MatchString(t.ID) {
		return t, fmt.Errorf("attack-pattern %s has invalid ATT&CK id %q", o.ID, t.ID)
	}
	if t.Name == "" {
		return t, fmt.Errorf("technique %s has no name", t.ID)
	}
	t.Domains = addAll(nil, o.Domains)
	if len(t.Domains) == 0 {
		t.Domains = []string{domain}
	}
	for _, k := range o.KillChain {
		t.Tactics = addAll(t.Tactics, []string{k.PhaseName})
	}
	return t, nil
}

// addAll appends the non-empty values of add that are not in dst.
func addAll(dst, add []string) []string {
	for _, v := range add {
		if v == "" {
			continue
		}
		dup := false
		for _, d := range dst {
			if d == v {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, v)
		}
	}
	return dst
}
