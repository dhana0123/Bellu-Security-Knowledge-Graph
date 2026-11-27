package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// NormalizeRansomware maps a KEV ransomware value to "known" or "unknown".
func NormalizeRansomware(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "known") {
		return "known"
	}
	return "unknown"
}

// Normalize returns k with Ransomware limited to known|unknown.
func (k KEV) Normalize() KEV {
	k.Ransomware = NormalizeRansomware(k.Ransomware)
	return k
}

// TruncateTime converts t to UTC at millisecond precision; zero stays zero.
func TruncateTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC().Truncate(time.Millisecond)
}

// Normalize truncates all timestamps to millisecond UTC.
func (r *Record) Normalize() {
	r.Published = TruncateTime(r.Published)
	r.Modified = TruncateTime(r.Modified)
	r.Withdrawn = TruncateTime(r.Withdrawn)
}

// Patch is a fix reference derived from a record. URL length is validated by the store.
type Patch struct {
	URL          string
	Source       string
	FixedVersion string
}

// Exploit is an exploit reference derived from a record.
type Exploit struct {
	URL    string
	Source string
}

// Patches derives patches from FIX references and commit fixes, deduplicated by URL.
func (r Record) Patches() []Patch {
	var out []Patch
	seen := map[string]bool{}
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, Patch{URL: u, Source: r.Source})
		}
	}
	for _, ref := range r.References {
		if strings.EqualFold(ref.Type, "FIX") {
			add(ref.URL)
		}
	}
	for _, f := range r.Fixes {
		if f.Repo == "" || f.Commit == "" {
			continue
		}
		add(strings.TrimSuffix(f.Repo, "/") + "/commit/" + f.Commit)
	}
	return out
}

// Exploits derives exploit references from EXPLOIT references, deduplicated by URL.
func (r Record) Exploits() []Exploit {
	var out []Exploit
	seen := map[string]bool{}
	for _, ref := range r.References {
		if strings.EqualFold(ref.Type, "EXPLOIT") && ref.URL != "" && !seen[ref.URL] {
			seen[ref.URL] = true
			out = append(out, Exploit{URL: ref.URL, Source: r.Source})
		}
	}
	return out
}

type recordAlias Record

type recordJSON struct {
	recordAlias
	Published *time.Time `json:"published"`
	Modified  *time.Time `json:"modified"`
	Withdrawn *time.Time `json:"withdrawn"`
}

func tp(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func tv(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
}

// Marshal is the canonical JSON encoding of a record: zero timestamps are null.
func Marshal(r Record) ([]byte, error) {
	return json.Marshal(recordJSON{recordAlias: recordAlias(r), Published: tp(r.Published), Modified: tp(r.Modified), Withdrawn: tp(r.Withdrawn)})
}

// Unmarshal decodes canonical JSON; null timestamps become the zero time.
func Unmarshal(data []byte, r *Record) error {
	var j recordJSON
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&j); err != nil {
		return err
	}
	*r = Record(j.recordAlias)
	r.Published, r.Modified, r.Withdrawn = tv(j.Published), tv(j.Modified), tv(j.Withdrawn)
	return nil
}
