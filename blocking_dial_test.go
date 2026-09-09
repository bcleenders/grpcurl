package grpcurl_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	. "github.com/fullstorydev/grpcurl"
	grpcurl_testing "github.com/fullstorydev/grpcurl/internal/testing"
	"google.golang.org/grpc"
)

// dialTimeout is the context timeout used by the dial tests. It is
// deliberately generous: a dial that is expected to fail should fail long
// before this deadline, so that an assertion on the error message is not
// racing the deadline. A dial that only fails once this deadline expires is
// itself the bug these tests guard against (see assertFailsFast).
const dialTimeout = 10 * time.Second

// maxFastFailure bounds how long an expected-to-fail dial may take before we
// consider it "hanging" rather than failing fast. Connection refused and
// missing-socket errors are reported by the kernel essentially immediately,
// so anything beyond this means the error is being swallowed and retried
// internally until the context deadline.
const maxFastFailure = 3 * time.Second

// startTCPServer starts a gRPC server on a loopback TCP port and returns its
// host:port address. The server is stopped when the test finishes.
func startTCPServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	serveOn(t, l)
	return l.Addr().String()
}

// serveOn registers the test service on a gRPC server serving the given
// listener, and arranges for it to be stopped when the test finishes.
func serveOn(t *testing.T, l net.Listener) {
	t.Helper()
	svr := grpc.NewServer()
	grpcurl_testing.RegisterTestServiceServer(svr, grpcurl_testing.TestServer{})
	go svr.Serve(l)
	t.Cleanup(svr.Stop)
}

// unusedTCPPort returns a loopback address that nothing is listening on, by
// binding a port and immediately releasing it.
func unusedTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}
	return addr
}

// assertDialSucceeds dials the address and verifies the connection works by
// issuing an RPC over it.
func assertDialSucceeds(t *testing.T, network, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	cc, err := BlockingDial(ctx, network, address, nil)
	if err != nil {
		t.Fatalf("BlockingDial(%q, %q) failed: %v", network, address, err)
	}
	defer cc.Close()

	simpleTest(t, cc)
}

// assertFailsFast dials the address expecting failure, and verifies both that
// the error identifies the underlying cause (rather than a context deadline)
// and that it is reported promptly.
//
// Both properties matter. A dial whose connection error is swallowed still
// returns an error eventually -- "context deadline exceeded" -- so asserting
// only that a dial failed would not catch that regression. See
// https://github.com/fullstorydev/grpcurl/issues/387
func assertFailsFast(t *testing.T, network, address, wantErrSubstring string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	start := time.Now()
	cc, err := BlockingDial(ctx, network, address, nil)
	elapsed := time.Since(start)

	if err == nil {
		cc.Close()
		t.Fatalf("BlockingDial(%q, %q) succeeded, expected it to fail", network, address)
	}
	if !strings.Contains(err.Error(), wantErrSubstring) {
		t.Errorf("BlockingDial(%q, %q) error = %q, want it to contain %q",
			network, address, err, wantErrSubstring)
	}
	if elapsed > maxFastFailure {
		t.Errorf("BlockingDial(%q, %q) took %v to fail, want less than %v; "+
			"the connection error is likely being retried internally instead of propagated",
			network, address, elapsed, maxFastFailure)
	}
}

func TestBlockingDialTCP(t *testing.T) {
	addr := startTCPServer(t)

	// The empty network is what the command line uses, so it is the most
	// important case to cover; "tcp" is supported for callers of the library.
	for _, network := range []string{"", "tcp"} {
		t.Run(fmt.Sprintf("network=%q", network), func(t *testing.T) {
			assertDialSucceeds(t, network, addr)
		})
	}
}

func TestBlockingDialTCPConnectionRefused(t *testing.T) {
	addr := unusedTCPPort(t)

	for _, network := range []string{"", "tcp"} {
		t.Run(fmt.Sprintf("network=%q", network), func(t *testing.T) {
			assertFailsFast(t, network, addr, "connection refused")
		})
	}
}

func TestBlockingDialTCPNetworkRejectsUnixAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	_, err := BlockingDial(ctx, "tcp", "unix:///tmp/does-not-exist.sock", nil)
	if err == nil {
		t.Fatal("BlockingDial with tcp network and unix address succeeded, expected it to fail")
	}
	if !strings.Contains(err.Error(), "cannot use unix address") {
		t.Errorf("error = %q, want it to contain %q", err, "cannot use unix address")
	}
}
