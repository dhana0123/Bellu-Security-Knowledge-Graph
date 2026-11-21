package cwe

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxUnzippedBytes is the limit on the unzipped catalog (Requirement 4.10).
const MaxUnzippedBytes = 209_715_200

// maxZipBytes caps the compressed download held in memory.
const maxZipBytes = 64 << 20

var errTooLarge = errors.New("unzipped catalog exceeds 200 MB")

// parent is one ChildOf entry of an element.
type parent struct {
	ID   string `json:"id"`
	View string `json:"view"`
}

// element is one Weakness or Category of the catalog.
type element struct {
	Kind        string   `json:"kind"` // Weakness or Category
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Abstraction string   `json:"abstraction"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
	Extended    string   `json:"extended"`
	Parents     []parent `json:"parents"`
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

// catalogReader streams the elements of the catalog XML.
type catalogReader struct {
	dec     *xml.Decoder
	closer  io.Closer
	names   []string
	Version string
	Date    string
}

// openCatalog opens the single .xml entry of the zip archive and reads the
// root element, so Version and Date are set when it returns.
func openCatalog(zipData []byte, limit int64) (*catalogReader, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	var f *zip.File
	for _, e := range zr.File {
		if strings.HasSuffix(strings.ToLower(e.Name), ".xml") {
			if f != nil {
				return nil, errors.New("archive holds more than one .xml entry")
			}
			f = e
		}
	}
	if f == nil {
		return nil, errors.New("archive holds no .xml entry")
	}
	if f.UncompressedSize64 > uint64(limit) {
		return nil, errTooLarge
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", f.Name, err)
	}
	dec := xml.NewDecoder(&limitedReader{r: rc, n: limit})
	dec.Strict = true
	dec.Entity = nil // no entity map; external entities are never resolved
	c := &catalogReader{dec: dec, closer: rc}
	if err := c.readRoot(); err != nil {
		rc.Close()
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
			if se.Name.Local != "Weakness_Catalog" {
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

// Next returns the next Weakness or Category, or io.EOF.
func (c *catalogReader) Next() (element, error) {
	for {
		t, err := c.token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(c.names) > 0 {
					return element{}, errors.New("parse catalog: unexpected end of file")
				}
				return element{}, io.EOF
			}
			return element{}, fmt.Errorf("parse catalog: %w", err)
		}
		switch t := t.(type) {
		case xml.StartElement:
			n := t.Name.Local
			if len(c.names) == 2 && (n == "Weakness" || n == "Category") &&
				(c.names[1] == "Weaknesses" || c.names[1] == "Categories") {
				el, err := c.decodeElement(t)
				if err != nil {
					return element{}, fmt.Errorf("parse catalog: %w", err)
				}
				return el, nil
			}
			c.names = append(c.names, n)
		case xml.EndElement:
			c.names = c.names[:len(c.names)-1]
			if len(c.names) == 0 {
				return element{}, io.EOF
			}
		}
	}
}

// decodeElement reads one Weakness or Category through its end tag.
func (c *catalogReader) decodeElement(start xml.StartElement) (element, error) {
	el := element{Kind: start.Name.Local}
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "ID":
			el.ID = strings.TrimSpace(a.Value)
		case "Name":
			el.Name = a.Value
		case "Abstraction":
			el.Abstraction = a.Value
		case "Status":
			el.Status = a.Value
		}
	}
	descName := "Description"
	if el.Kind == "Category" {
		descName = "Summary"
	}
	var path []string
	var text *strings.Builder
	var descB, extB strings.Builder
	for {
		t, err := c.token()
		if err != nil {
			return el, err
		}
		switch t := t.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			switch {
			case len(path) == 1 && t.Name.Local == descName:
				text = &descB
			case len(path) == 1 && t.Name.Local == "Extended_Description":
				text = &extB
			case len(path) == 2 && path[0] == "Related_Weaknesses" && t.Name.Local == "Related_Weakness":
				var nature, id, view string
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "Nature":
						nature = a.Value
					case "CWE_ID":
						id = strings.TrimSpace(a.Value)
					case "View_ID":
						view = strings.TrimSpace(a.Value)
					}
				}
				if nature == "ChildOf" {
					el.Parents = append(el.Parents, parent{ID: id, View: view})
				}
			}
		case xml.CharData:
			if text != nil {
				text.Write(t)
			}
		case xml.EndElement:
			if len(path) == 0 {
				el.Description = strings.TrimSpace(descB.String())
				el.Extended = strings.TrimSpace(extB.String())
				return el, nil
			}
			if len(path) == 1 {
				text = nil
			}
			path = path[:len(path)-1]
		}
	}
}
