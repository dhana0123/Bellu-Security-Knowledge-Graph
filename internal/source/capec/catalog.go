package capec

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// MaxXMLBytes is the limit on the catalog file. The live file is about 4 MB.
const MaxXMLBytes = 100 << 20

var errTooLarge = errors.New("catalog exceeds 100 MB")

// pattern is one Attack_Pattern of the catalog.
type pattern struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Abstraction string   `json:"abstraction,omitempty"`
	Status      string   `json:"status,omitempty"`
	Description string   `json:"description,omitempty"`
	Likelihood  string   `json:"likelihood,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`       // Related_Weakness CWE_ID values, in document order
	Techniques  []string `json:"techniques,omitempty"` // Taxonomy_Name="ATTACK" Entry_ID values, in document order
}

// limitedReader returns errTooLarge once more than n bytes were read.
type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n < 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > l.n+1 {
		p = p[:l.n+1]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	if l.n < 0 {
		return n, errTooLarge
	}
	return n, err
}

// catalogReader streams the Attack_Pattern elements of the catalog XML.
type catalogReader struct {
	dec     *xml.Decoder
	closer  io.Closer
	names   []string
	Version string
	Date    string
}

// openCatalog opens the XML file and reads the root element, so Version and
// Date are set when it returns. DOCTYPE declarations (and with them entity
// declarations) are rejected while reading.
func openCatalog(path string) (*catalogReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	dec := xml.NewDecoder(bufio.NewReaderSize(&limitedReader{r: f, n: MaxXMLBytes}, 1<<20))
	dec.Strict = true
	dec.Entity = nil // no entity map; external entities are never resolved
	c := &catalogReader{dec: dec, closer: f}
	if err := c.readRoot(); err != nil {
		f.Close()
		return nil, err
	}
	return c, nil
}

func (c *catalogReader) Close() error { return c.closer.Close() }

func (c *catalogReader) token() (xml.Token, error) {
	t, err := c.dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(xml.Directive); ok && strings.HasPrefix(strings.TrimSpace(strings.ToUpper(string(d))), "DOCTYPE") {
		return nil, errors.New("DOCTYPE declarations are not allowed")
	}
	return t, nil
}

func (c *catalogReader) readRoot() error {
	for {
		t, err := c.token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("catalog has no root element")
			}
			return fmt.Errorf("parse catalog: %w", err)
		}
		if se, ok := t.(xml.StartElement); ok {
			if se.Name.Local != "Attack_Pattern_Catalog" {
				return fmt.Errorf("unexpected root element %q", se.Name.Local)
			}
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "Version":
					c.Version = strings.TrimSpace(a.Value)
				case "Date":
					c.Date = strings.TrimSpace(a.Value)
				}
			}
			if c.Version == "" {
				return errors.New("catalog has no Version attribute")
			}
			c.names = []string{se.Name.Local}
			return nil
		}
	}
}

// Next returns the next Attack_Pattern, or io.EOF.
func (c *catalogReader) Next() (pattern, error) {
	for {
		t, err := c.token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(c.names) > 0 {
					return pattern{}, errors.New("parse catalog: unexpected end of file")
				}
				return pattern{}, io.EOF
			}
			return pattern{}, fmt.Errorf("parse catalog: %w", err)
		}
		switch t := t.(type) {
		case xml.StartElement:
			n := t.Name.Local
			if len(c.names) == 2 && n == "Attack_Pattern" && c.names[1] == "Attack_Patterns" {
				p, err := c.decodePattern(t)
				if err != nil {
					return pattern{}, fmt.Errorf("parse catalog: %w", err)
				}
				return p, nil
			}
			c.names = append(c.names, n)
		case xml.EndElement:
			c.names = c.names[:len(c.names)-1]
			if len(c.names) == 0 {
				return pattern{}, io.EOF
			}
		}
	}
}

// blockElements separate paragraphs inside a Description.
var blockElements = map[string]bool{"p": true, "br": true, "li": true, "ul": true, "ol": true, "div": true, "tr": true}

// decodePattern reads one Attack_Pattern through its end tag.
func (c *catalogReader) decodePattern(start xml.StartElement) (pattern, error) {
	var p pattern
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "ID":
			p.ID = strings.TrimSpace(a.Value)
		case "Name":
			p.Name = strings.TrimSpace(a.Value)
		case "Abstraction":
			p.Abstraction = strings.TrimSpace(a.Value)
		case "Status":
			p.Status = strings.TrimSpace(a.Value)
		}
	}
	var path []string
	var text *strings.Builder
	var desc, like, sev, entry strings.Builder
	var taxName string
	for {
		t, err := c.token()
		if err != nil {
			return p, err
		}
		switch t := t.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			n := t.Name.Local
			switch {
			case len(path) == 1 && n == "Description":
				text = &desc
			case len(path) == 1 && n == "Likelihood_Of_Attack":
				text = &like
			case len(path) == 1 && n == "Typical_Severity":
				text = &sev
			case len(path) == 2 && path[0] == "Related_Weaknesses" && n == "Related_Weakness":
				for _, a := range t.Attr {
					if a.Name.Local == "CWE_ID" {
						p.CWEs = append(p.CWEs, strings.TrimSpace(a.Value))
					}
				}
			case len(path) == 2 && path[0] == "Taxonomy_Mappings" && n == "Taxonomy_Mapping":
				taxName = ""
				entry.Reset()
				for _, a := range t.Attr {
					if a.Name.Local == "Taxonomy_Name" {
						taxName = strings.TrimSpace(a.Value)
					}
				}
			case len(path) == 3 && path[0] == "Taxonomy_Mappings" && n == "Entry_ID":
				text = &entry
			default:
				if text == &desc && blockElements[n] {
					desc.WriteByte('\n')
				}
			}
		case xml.CharData:
			if text != nil {
				text.Write(t)
			}
		case xml.EndElement:
			if len(path) == 0 {
				p.Description = clean(desc.String())
				p.Likelihood = clean(like.String())
				p.Severity = clean(sev.String())
				return p, nil
			}
			n := path[len(path)-1]
			switch {
			case len(path) == 1:
				text = nil
			case len(path) == 3 && n == "Entry_ID":
				text = nil
				if taxName == "ATTACK" {
					if e := strings.TrimSpace(entry.String()); e != "" {
						p.Techniques = append(p.Techniques, e)
					}
				}
			case text == &desc && blockElements[n]:
				desc.WriteByte('\n')
			}
			path = path[:len(path)-1]
		}
	}
}

// clean collapses runs of white space to one space inside a line and drops
// empty lines.
func clean(s string) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			lines = append(lines, strings.Join(f, " "))
		}
	}
	return strings.Join(lines, "\n")
}
