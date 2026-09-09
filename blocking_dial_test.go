package grpcurl_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	. "github.com/fullstorydev/grpcurl"
	grpcurl_testing "github.com/fullstorydev/grpcurl/internal/testing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
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
func serveOn(t *testing.T, l net.Listener) *grpc.Server {
	t.Helper()
	svr := grpc.NewServer()
	grpcurl_testing.RegisterTestServiceServer(svr, grpcurl_testing.TestServer{})
	go svr.Serve(l)
	t.Cleanup(svr.Stop)
	return svr
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
func assertFailsFast(t *testing.T, network, address string, wantErr error) {
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
	if !errors.Is(err, wantErr) {
		t.Errorf("BlockingDial(%q, %q) error = %q, want it to wrap %v",
			network, address, err, wantErr)
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
	wantErr := syscall.ECONNREFUSED
	if runtime.GOOS == "windows" {
		// Winsock uses WSAECONNREFUSED, not Go's synthetic ECONNREFUSED.
		wantErr = syscall.Errno(10061)
	}

	for _, network := range []string{"", "tcp"} {
		t.Run(fmt.Sprintf("network=%q", network), func(t *testing.T) {
			assertFailsFast(t, network, addr, wantErr)
		})
	}
}

type dialError struct{ temporary bool }

func (e dialError) Error() string   { return "injected dial failure" }
func (e dialError) Temporary() bool { return e.temporary }

func fastDialBackoff() grpc.DialOption {
	return grpc.WithConnectParams(grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  10 * time.Millisecond,
			Multiplier: 1,
			MaxDelay:   10 * time.Millisecond,
		},
		MinConnectTimeout: time.Second,
	})
}

func TestBlockingDialRetries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		temporary bool
		override  bool
	}{
		{name: "temporary", temporary: true},
		{name: "permanent"},
		{name: "permanent with caller override", override: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			serveOn(t, listener)
			var attempts atomic.Int32
			wantErr := dialError{temporary: tc.temporary}
			opts := []grpc.DialOption{
				fastDialBackoff(),
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					if attempts.Add(1) == 1 {
						return nil, wantErr
					}
					return listener.DialContext(ctx)
				}),
			}
			if tc.override {
				opts = append(opts, grpc.FailOnNonTempDialError(false))
			}
			ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
			defer cancel()
			cc, err := BlockingDial(ctx, "", "passthrough:///retry-test", nil, opts...)
			if !tc.temporary && !tc.override {
				if cc != nil {
					cc.Close()
				}
				if !errors.Is(err, wantErr) || attempts.Load() != 1 {
					t.Fatalf("BlockingDial returned %v after %d attempts, want the permanent error after one attempt", err, attempts.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()
			if attempts.Load() != 2 {
				t.Errorf("dial attempts = %d, want 2", attempts.Load())
			}
			cancel()
			// A successful connection must outlive its dial context.
			simpleTest(t, cc)
		})
	}
}

func TestBlockingDialContextCleanup(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%v", deadline), func(t *testing.T) {
			timeout := dialTimeout
			wantErr := context.Canceled
			if deadline {
				timeout = 100 * time.Millisecond
				wantErr = context.DeadlineExceeded
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			started := make(chan struct{})
			stopped := make(chan struct{})
			result := make(chan error, 1)
			go func() {
				cc, err := BlockingDial(ctx, "", "passthrough:///cancellation-test", nil,
					grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
						close(started)
						<-ctx.Done()
						close(stopped)
						return nil, ctx.Err()
					}))
				if cc != nil {
					cc.Close()
				}
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(dialTimeout):
				t.Fatal("dialer did not start")
			}
			if !deadline {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, wantErr) {
					t.Fatalf("BlockingDial error = %v, want %v", err, wantErr)
				}
			case <-time.After(dialTimeout):
				t.Fatal("BlockingDial did not return after context cancellation")
			}
			select {
			case <-stopped:
			case <-time.After(maxFastFailure):
				t.Fatal("in-flight dial was not canceled")
			}
		})
	}
}

func TestBlockingDialTLSFailureStopsRetrying(t *testing.T) {
	for _, address := range []string{"passthrough:///tls-failure-test", "dns:///127.0.0.1:1"} {
		t.Run(address, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			serveOn(t, listener)
			var attempts atomic.Int32
			ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
			defer cancel()
			cc, err := BlockingDial(ctx, "", address, credentials.NewTLS(&tls.Config{}),
				fastDialBackoff(),
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					attempts.Add(1)
					return listener.DialContext(ctx)
				}))
			if cc != nil {
				cc.Close()
			}
			var tlsErr tls.RecordHeaderError
			if !errors.As(err, &tlsErr) {
				t.Fatalf("BlockingDial error = %v, want TLS record header error from the plaintext server", err)
			}
			if ctx.Err() != nil {
				t.Fatalf("parent context expired before the TLS error was returned: %v", ctx.Err())
			}
			// Keep the parent context alive for several backoff intervals. An early
			// handshake error must stop the connection's background retry loop.
			before := attempts.Load()
			time.Sleep(100 * time.Millisecond)
			if after := attempts.Load(); after != before {
				t.Errorf("dial continued after TLS failure: %d -> %d attempts", before, after)
			}
		})
	}
}

func TestBlockingDialReconnect(t *testing.T) {
	first := bufconn.Listen(1024 * 1024)
	second := bufconn.Listen(1024 * 1024)
	firstServer := serveOn(t, first)
	serveOn(t, second)
	var active atomic.Pointer[bufconn.Listener]
	active.Store(first)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	cc, err := BlockingDial(ctx, "", "passthrough:///reconnect-test", nil,
		fastDialBackoff(),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return active.Load().DialContext(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	cancel()
	simpleTest(t, cc)
	active.Store(second)
	firstServer.Stop()
	simpleTest(t, cc)
}

func TestBlockingDialTCPNetworkRejectsUnixAddress(t *testing.T) {
	for _, address := range []string{"unix:///tmp/does-not-exist.sock", "unix:s.sock"} {
		t.Run(address, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
			defer cancel()

			cc, err := BlockingDial(ctx, "tcp", address, nil)
			if err == nil {
				cc.Close()
				t.Fatal("BlockingDial with tcp network and unix address succeeded, expected it to fail")
			}
			if !strings.Contains(err.Error(), "cannot use unix address") {
				t.Errorf("error = %q, want it to contain %q", err, "cannot use unix address")
			}
		})
	}
}
