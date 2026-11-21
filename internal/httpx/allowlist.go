package httpx

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AllowList is the set of hosts outbound requests may reach (Requirements
// 25.8, 25.9). Hosts are compared in lower case without port.
type AllowList map[string]struct{}

// NewAllowList returns a list of the given hosts.
func NewAllowList(hosts ...string) AllowList {
	a := AllowList{}
	for _, h := range hosts {
		a[strings.ToLower(strings.TrimSuffix(h, "."))] = struct{}{}
	}
	return a
}

// HostNotAllowedError reports a host outside the allow-list. It is never
// retried.
type HostNotAllowedError struct{ Host string }

func (e *HostNotAllowedError) Error() string {
	return fmt.Sprintf("httpx: host %q is not on the outbound allow-list", e.Host)
}

// Check returns a *HostNotAllowedError naming host when it is not on the list.
func (a AllowList) Check(host string) error {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if _, ok := a[h]; !ok {
		return &HostNotAllowedError{Host: host}
	}
	return nil
}

type allowTransport struct {
	list AllowList
	next http.RoundTripper
}

func (t allowTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.list.Check(req.URL.Hostname()); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return t.next.RoundTrip(req)
}

// RoundTripper wraps next (http.DefaultTransport when nil) so that a request
// to a host outside the list fails before anything is sent.
func (a AllowList) RoundTripper(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return allowTransport{list: a, next: next}
}

// CheckRedirect blocks a redirect to a host outside the list and stops after
// 10 redirects. It is an http.Client.CheckRedirect function.
func (a AllowList) CheckRedirect(req *http.Request, via []*http.Request) error {
	if err := a.Check(req.URL.Hostname()); err != nil {
		return fmt.Errorf("redirect blocked: %w", err)
	}
	if len(via) >= 10 {
		return fmt.Errorf("httpx: stopped after 10 redirects")
	}
	return nil
}

// NewClient returns a client that enforces the list on requests and redirects.
// TLS verification stays at the Go default. timeout 0 means no client timeout.
func (a AllowList) NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport:     a.RoundTripper(nil),
		CheckRedirect: a.CheckRedirect,
		Timeout:       timeout,
	}
}
