// Package nettest blocks all network access in tests (R23.2, R23.3).
package nettest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
)

// ErrNetworkBlocked is returned by every blocked dial.
var ErrNetworkBlocked = errors.New("nettest: network access is blocked in tests")

var dials atomic.Int64

// Dials returns the number of blocked dial attempts so far.
func Dials() int64 { return dials.Load() }

func blockedDial(_ context.Context, network, addr string) (net.Conn, error) {
	dials.Add(1)
	fmt.Fprintf(os.Stderr, "nettest: blocked dial %s %s\n", network, addr)
	return nil, fmt.Errorf("%w: %s %s", ErrNetworkBlocked, network, addr)
}

// Block replaces http.DefaultTransport and the default resolver dialer so any
// dial fails. It returns a function that restores the previous values.
func Block() (restore func()) {
	oldT := http.DefaultTransport
	oldDial := net.DefaultResolver.Dial
	oldPrefer := net.DefaultResolver.PreferGo
	http.DefaultTransport = &http.Transport{DialContext: blockedDial, DialTLSContext: blockedDial}
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = blockedDial
	return func() {
		http.DefaultTransport = oldT
		net.DefaultResolver.Dial = oldDial
		net.DefaultResolver.PreferGo = oldPrefer
	}
}

// Main is for use in TestMain: it blocks the network, runs the tests and
// fails the run if any dial was attempted.
//
//	func TestMain(m *testing.M) { os.Exit(nettest.Main(m)) }
func Main(m interface{ Run() int }) int {
	restore := Block()
	defer restore()
	code := m.Run()
	if code == 0 && Dials() > 0 {
		fmt.Fprintf(os.Stderr, "nettest: %d blocked dial attempt(s)\n", Dials())
		return 1
	}
	return code
}
