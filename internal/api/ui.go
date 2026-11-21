package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
)

const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// hashedAsset matches Vite's content-hashed names, such as assets/index-DiwrgTda.js.
var hashedAsset = regexp.MustCompile(`^assets/.+-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$`)

// uiHandler serves the embedded Client_UI with SPA fallback (Requirement 23).
type uiHandler struct {
	files fs.FS
	etags map[string]string // file path -> ETag, computed once
}

func newUIHandler(files fs.FS) *uiHandler {
	h := &uiHandler{files: files, etags: map[string]string{}}
	_ = fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, rerr := fs.ReadFile(files, p); rerr == nil {
			sum := sha256.Sum256(b)
			h.etags[p] = `"` + hex.EncodeToString(sum[:8]) + `"`
		}
		return nil
	})
	return h
}

func (s *Server) mountUI(files fs.FS) {
	h := newUIHandler(files)
	s.mux.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
	})
	s.mux.Handle("/ui/", h)
}

func (h *uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", uiCSP)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hd.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/ui/")
	if name == "" {
		name = "index.html"
	}
	if _, ok := h.etags[name]; !ok || !fs.ValidPath(name) {
		if strings.HasPrefix(name, "assets/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		name = "index.html" // client-side route
	}
	etag, ok := h.etags[name]
	if !ok {
		http.Error(w, "UI not built", http.StatusNotFound)
		return
	}
	b, err := fs.ReadFile(h.files, name)
	if err != nil {
		http.Error(w, "UI not built", http.StatusNotFound)
		return
	}
	if hashedAsset.MatchString(name) {
		hd.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		hd.Set("Cache-Control", "no-cache")
	}
	hd.Set("ETag", etag)
	http.ServeContent(w, r, path.Base(name), time.Time{}, bytes.NewReader(b))
}
