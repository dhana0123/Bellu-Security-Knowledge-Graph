// Package fetch holds the download helper shared by the source adapters.
//
// Adapters write large downloads (OSV ecosystem archives, EPSS and KEV
// snapshots, ATT&CK and CAPEC bundles) under the cache directory
// (BSKG_CACHE_DIR, a writable volume; the worker root file system is
// read-only and /tmp is RAM). DownloadToCache streams the body to disk, so a
// large file never sits in memory.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/httpx"
)

// PartSuffix is appended to the file name while a download is running.
const PartSuffix = ".part"

// Result describes a completed download.
type Result struct {
	// Path is cacheDir/name. The file is complete: it was renamed from the
	// .part file only after the whole body was read.
	Path string
	// Size is the number of bytes written.
	Size int64
	// SHA256 is the lowercase hex SHA-256 of the file content. Adapters use it
	// as the snapshot version (source.Cursor.Version) to skip unchanged files.
	SHA256 string
	// ETag and LastModified are the response headers, empty when absent.
	ETag         string
	LastModified string
}

// Options are optional request settings.
type Options struct {
	// Header is added to the request (for example Authorization for GHSA).
	// Never log it.
	Header http.Header
	// MaxBytes, when positive, fails a download whose body is larger. The
	// failure is not retried.
	MaxBytes int64
}

// DownloadToCache GETs url and stores the body as cacheDir/name.
//
// The body is streamed to cacheDir/name.part and renamed to cacheDir/name
// after the last byte arrived and the file was synced, so a reader never sees
// a partial file and a failed download leaves an existing cacheDir/name
// untouched. The .part file is removed on every failure.
//
// Retries follow policy with clock (nil means httpx.RealClock): network
// errors, truncated bodies, and the statuses httpx.IsRetryableStatus
// accepts (403, 429, 5xx) are retried, honouring Retry-After. Other statuses
// and httpx.HostNotAllowedError fail at once. client is usually
// httpx.AllowList.NewClient(...). cacheDir is created when missing. name is a
// plain file name without a path.
func DownloadToCache(ctx context.Context, client *http.Client, url, cacheDir, name string, policy httpx.Policy, clock httpx.Clock) (Result, error) {
	return DownloadWith(ctx, client, url, cacheDir, name, policy, clock, Options{})
}

// DownloadWith is DownloadToCache with request options.
func DownloadWith(ctx context.Context, client *http.Client, url, cacheDir, name string, policy httpx.Policy, clock httpx.Clock, opts Options) (Result, error) {
	if err := checkName(name); err != nil {
		return Result{}, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	if clock == nil {
		clock = httpx.RealClock{}
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("fetch: create cache directory: %w", err)
	}
	final := filepath.Join(cacheDir, name)
	part := final + PartSuffix
	var res Result
	err := httpx.Do(ctx, policy, clock, func(int) error {
		r, err := once(ctx, client, url, part, opts, clock)
		if err != nil {
			_ = os.Remove(part)
			return err
		}
		if err := os.Rename(part, final); err != nil {
			_ = os.Remove(part)
			return fmt.Errorf("fetch: publish %s: %w", name, err)
		}
		r.Path = final
		res = r
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("fetch %s: %w", redact(url), err)
	}
	return res, nil
}

func checkName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || strings.HasSuffix(name, PartSuffix) {
		return fmt.Errorf("fetch: invalid cache file name %q", name)
	}
	return nil
}

// redact drops the query and user info of a URL for error messages (tokens
// are sometimes passed there).
func redact(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "://"); i >= 0 {
		if j := strings.Index(u[i+3:], "@"); j >= 0 && !strings.Contains(u[i+3:i+3+j], "/") {
			u = u[:i+3] + u[i+3+j+1:]
		}
	}
	return u
}

// once runs one attempt into part. Errors that a new attempt may fix are
// wrapped with httpx.Retryable.
func once(ctx context.Context, client *http.Client, url, part string, opts Options, clock httpx.Clock) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	for k, vs := range opts.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		var uerr *neturl.Error
		if errors.As(err, &uerr) {
			uerr.URL = redact(uerr.URL) // the URL may carry a token in its query
		}
		var denied *httpx.HostNotAllowedError
		if ctx.Err() != nil || errors.As(err, &denied) {
			return Result{}, err
		}
		return Result{}, httpx.Retryable(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
		if httpx.IsRetryableStatus(resp.StatusCode) {
			return Result{}, &httpx.RetryableError{Err: err, RetryAfter: httpx.ParseRetryAfter(resp.Header.Get("Retry-After"), clock.Now())}
		}
		return Result{}, err
	}
	if opts.MaxBytes > 0 && resp.ContentLength > opts.MaxBytes {
		return Result{}, fmt.Errorf("download is %d bytes, over the limit of %d", resp.ContentLength, opts.MaxBytes)
	}
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return Result{}, fmt.Errorf("create %s: %w", filepath.Base(part), err)
	}
	h := sha256.New()
	var src io.Reader = resp.Body
	if opts.MaxBytes > 0 {
		src = io.LimitReader(resp.Body, opts.MaxBytes+1)
	}
	n, err := io.Copy(io.MultiWriter(f, h), src)
	if err != nil {
		_ = f.Close()
		return Result{}, httpx.Retryable(fmt.Errorf("read body: %w", err))
	}
	if opts.MaxBytes > 0 && n > opts.MaxBytes {
		_ = f.Close()
		return Result{}, fmt.Errorf("download is over the limit of %d bytes", opts.MaxBytes)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		_ = f.Close()
		return Result{}, httpx.Retryable(fmt.Errorf("body has %d bytes, expected %d", n, resp.ContentLength))
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return Result{}, fmt.Errorf("sync %s: %w", filepath.Base(part), err)
	}
	if err := f.Close(); err != nil {
		return Result{}, fmt.Errorf("close %s: %w", filepath.Base(part), err)
	}
	return Result{
		Size: n, SHA256: hex.EncodeToString(h.Sum(nil)),
		ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}
