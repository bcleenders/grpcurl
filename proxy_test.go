package grpcurl_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/fullstorydev/grpcurl"
	grpcurl_testing "github.com/fullstorydev/grpcurl/internal/testing"
	"google.golang.org/grpc"
)

// proxyChildEnv marks the re-executed child process that runs the body of
// TestProxySupport.
const proxyChildEnv = "GRPCURL_TEST_PROXY_CHILD"

// proxyTarget is the address the client is asked to dial. It must be a name
// rather than an IP, and it must not resolve:
//
//   - A loopback address would never be proxied at all. net/http excludes
//     "localhost" and any loopback IP from proxying, so the proxy would be
//     skipped and the test would pass without proving anything.
//   - Because the name never resolves, the RPC can only succeed by way of the
//     proxy. A regression that bypasses the proxy cannot accidentally pass by
//     connecting directly.
//
// The .invalid TLD is reserved by RFC 2606 and is guaranteed not to resolve.
const proxyTarget = "grpcurl-proxy-test.invalid:443"

// TestProxySupport verifies that a dial honors the HTTPS_PROXY environment
// variable, by routing it through a local HTTP CONNECT proxy.
//
// This guards the fix in https://github.com/fullstorydev/grpcurl/pull/480,
// which removed a custom dialer precisely so that grpc-go's own proxy support
// would be used. grpc-go treats grpc.WithContextDialer as an opt-out of proxy
// support: when a custom dialer is set it skips the delegating resolver that
// implements proxying. Reintroducing a custom dialer therefore silently
// disables proxies, which nothing else in this suite would catch.
//
// The test runs in a re-executed child process. net/http resolves the proxy
// environment once per process and caches it in a sync.Once, so any earlier
// dial in this test binary would fix the cached value to "no proxy" and make
// setting HTTPS_PROXY here have no effect.
func TestProxySupport(t *testing.T) {
	if os.Getenv(proxyChildEnv) != "1" {
		reExecForProxyTest(t)
		return
	}

	// Guard the premise: if this name somehow resolves (e.g. a DNS provider
	// that wildcards NXDOMAIN), a bypassed proxy could connect directly and
	// the test would pass for the wrong reason.
	if addrs, err := net.LookupHost(strings.Split(proxyTarget, ":")[0]); err == nil {
		t.Skipf("%s unexpectedly resolves to %v; cannot prove the proxy was used",
			proxyTarget, addrs)
	}

	backend := startBackendServer(t)
	proxyAddr, connectTargets := startConnectProxy(t, backend)

	// Safe to set here: this is a fresh process and nothing has dialed yet.
	t.Setenv("HTTPS_PROXY", "http://"+proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cc, err := BlockingDial(ctx, "", proxyTarget, nil)
	if err != nil {
		t.Fatalf("BlockingDial(%q) through proxy %s failed: %v\nCONNECT requests seen by proxy: %v",
			proxyTarget, proxyAddr, err, connectTargets())
	}
	defer cc.Close()

	simpleTest(t, cc)

	// The RPC succeeding is strong evidence already, but assert on the proxy's
	// own record so a failure says plainly whether the proxy was involved.
	seen := connectTargets()
	if len(seen) == 0 {
		t.Fatalf("proxy received no CONNECT requests, so the dial did not go through it")
	}
	if seen[0] != proxyTarget {
		t.Errorf("proxy received CONNECT for %q, want %q", seen[0], proxyTarget)
	}
}

// reExecForProxyTest runs this test again in a child process, where the proxy
// environment has not yet been resolved and cached.
func reExecForProxyTest(t *testing.T) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProxySupport$", "-test.v")
	cmd.Env = append(os.Environ(), proxyChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("proxy test child process failed: %v\n%s", err, out)
	}
}

// startBackendServer starts a gRPC server on loopback and returns its address.
func startBackendServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for backend: %v", err)
	}
	svr := grpc.NewServer()
	grpcurl_testing.RegisterTestServiceServer(svr, grpcurl_testing.TestServer{})
	go svr.Serve(l)
	t.Cleanup(svr.Stop)
	return l.Addr().String()
}

// startConnectProxy starts a minimal HTTP CONNECT proxy on loopback. It
// records every target it is asked to connect to, then tunnels to backendAddr
// regardless of what was requested. That indirection is what lets the test use
// an unresolvable target: the client only ever sends the name as text in the
// CONNECT request, and never resolves it itself.
//
// The returned function reports the targets seen so far.
func startConnectProxy(t *testing.T, backendAddr string) (proxyAddr string, connectTargets func() []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for proxy: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	var mu sync.Mutex
	var targets []string

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return // listener closed at test cleanup
			}
			go proxyOneConn(conn, backendAddr, func(target string) {
				mu.Lock()
				defer mu.Unlock()
				targets = append(targets, target)
			})
		}
	}()

	return l.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), targets...)
	}
}

// proxyOneConn handles a single CONNECT request and then bridges the tunnel.
func proxyOneConn(conn net.Conn, backendAddr string, record func(string)) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	requestLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	// e.g. "CONNECT grpcurl-proxy-test.invalid:443 HTTP/1.1"
	fields := strings.Fields(requestLine)
	if len(fields) < 2 || fields[0] != "CONNECT" {
		return
	}
	record(fields[1])

	// Discard the remaining request headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	upstream, err := net.Dial("tcp", backendAddr)
	if err != nil {
		return
	}
	defer upstream.Close()

	// Bridge until either side closes. br may hold buffered bytes already read
	// from conn, so copy from it rather than from conn directly.
	go func() { _, _ = io.Copy(upstream, br) }()
	_, _ = io.Copy(conn, upstream)
}
