// Package fetch resolves a location (local path or http(s) URL) and iterates JSON documents in it.
package fetch

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxDoc = 256 << 20 // 256 MiB per document

var client = &http.Client{Timeout: 30 * time.Minute}

// Local returns a local path for loc, downloading http(s) URLs to a temp file.
func Local(ctx context.Context, loc string) (string, func(), error) {
	return LocalWith(ctx, nil, loc)
}

// LocalWith is Local, but downloads through the retrying, rate-limited c when c is not nil.
func LocalWith(ctx context.Context, c *Client, loc string) (string, func(), error) {
	if !strings.HasPrefix(loc, "http://") && !strings.HasPrefix(loc, "https://") {
		return loc, func() {}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "bellu-global-intel/1.0")
	var resp *http.Response
	if c != nil {
		resp, err = c.Do(ctx, req)
	} else {
		resp, err = client.Do(req)
	}
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("GET %s: %s", loc, resp.Status)
	}
	ext := filepath.Ext(strings.SplitN(loc, "?", 2)[0])
	f, err := os.CreateTemp("", "bellu-fetch-*"+ext)
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, err
	}
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

// ReadFile reads a file, transparently gunzipping *.gz.
func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	return readCapped(r)
}

func readCapped(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxDoc+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDoc {
		return nil, fmt.Errorf("document exceeds %d bytes", maxDoc)
	}
	return b, nil
}

// WalkJSON calls fn for every JSON document under path: a directory (recursive *.json[.gz]),
// a .zip archive (*.json entries), or a single .json/.json.gz file.
func WalkJSON(path string, fn func(name string, data []byte) error) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	switch {
	case st.IsDir():
		var files []string
		err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && (strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".json.gz")) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return err
		}
		sort.Strings(files)
		for _, p := range files {
			b, err := ReadFile(p)
			if err != nil {
				return err
			}
			if err := fn(p, b); err != nil {
				return err
			}
		}
		return nil
	case strings.HasSuffix(path, ".zip"):
		zr, err := zip.OpenReader(path)
		if err != nil {
			return err
		}
		defer zr.Close()
		for _, zf := range zr.File {
			if !strings.HasSuffix(zf.Name, ".json") {
				continue
			}
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			b, err := readCapped(rc)
			rc.Close()
			if err != nil {
				return err
			}
			if err := fn(zf.Name, b); err != nil {
				return err
			}
		}
		return nil
	default:
		b, err := ReadFile(path)
		if err != nil {
			return err
		}
		return fn(path, b)
	}
}

// Reader returns the (gunzipped if needed) content of loc as a reader.
func Reader(path string) (io.Reader, error) {
	b, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}
