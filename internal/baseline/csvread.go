package baseline

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// CSVReader streams one CSV file row by row. It never holds more than the
// rows the caller asks for.
type CSVReader struct {
	f      *os.File
	r      *csv.Reader
	header map[string]int
	line   int
	name   string
}

// Row is one CSV data row.
type Row struct {
	fields []string
	header map[string]int
	Line   int
}

// OpenCSV opens path and reads the header. Every column in required must be
// present, or the error names the file and the column.
func OpenCSV(path string, required ...string) (*CSVReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open baseline file %s: %w", path, err)
	}
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.ReuseRecord = false
	hdr, err := r.Read()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read header of %s: %w", path, err)
	}
	h := make(map[string]int, len(hdr))
	for i, c := range hdr {
		c = strings.TrimPrefix(strings.TrimSpace(c), "\ufeff")
		if _, dup := h[c]; !dup {
			h[c] = i
		}
	}
	for _, c := range required {
		if _, ok := h[c]; !ok {
			f.Close()
			return nil, fmt.Errorf("baseline file %s: missing column %q", path, c)
		}
	}
	return &CSVReader{f: f, r: r, header: h, line: 1, name: path}, nil
}

// Next returns the next row, or io.EOF at the end.
func (c *CSVReader) Next() (Row, error) {
	rec, err := c.r.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return Row{}, io.EOF
		}
		return Row{}, fmt.Errorf("read %s after line %d: %w", c.name, c.line, err)
	}
	c.line++
	return Row{fields: rec, header: c.header, Line: c.line}, nil
}

// NextBatch returns up to n rows. It returns an empty slice and io.EOF when no
// rows remain; a final partial batch is returned with a nil error.
func (c *CSVReader) NextBatch(n int) ([]Row, error) {
	out := make([]Row, 0, n)
	for len(out) < n {
		row, err := c.Next()
		if err != nil {
			if errors.Is(err, io.EOF) && len(out) > 0 {
				return out, nil
			}
			return out, err
		}
		out = append(out, row)
	}
	return out, nil
}

// Close releases the file.
func (c *CSVReader) Close() error { return c.f.Close() }

// CountRows counts the data rows in a CSV file by streaming it.
func CountRows(path string) (int64, error) {
	r, err := OpenCSV(path)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	var n int64
	for {
		if _, err := r.Next(); err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
		n++
	}
}

// Get returns the trimmed value of column col. present is false when the
// column is missing from the file or the field is empty (empty means absent).
func (r Row) Get(col string) (string, bool) {
	i, ok := r.header[col]
	if !ok || i >= len(r.fields) {
		return "", false
	}
	v := strings.TrimSpace(r.fields[i])
	return v, v != ""
}
