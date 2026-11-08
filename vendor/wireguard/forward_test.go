package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"sgwg/internal/testpeer"
)

// dialForward connects to a forwarder the way WGSockets.m does: connect, then
// report the socket's local port.
func dialForward(t *testing.T, e *Engine, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", joinHostPort("127.0.0.1", port), 2*time.Second)
	if err != nil {
		t.Fatalf("loopback connect: %v", err)
	}
	if !e.ExpectPeer(port, c.LocalAddr().(*net.TCPAddr).Port) {
		t.Fatal("forwarder was gone before its connection")
	}
	return c
}

func httpOver(t *testing.T, c net.Conn, host, path string) (string, error) {
	t.Helper()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.WriteString(c, "GET "+path+" HTTP/1.0\r\nHost: "+host+"\r\n\r\n"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(bufio.NewReader(c))
	return string(b), err
}

func TestForwardCarriesSpotifyStyleSocketThroughTunnel(t *testing.T) {
	h := startTunnel(t, nil)
	port, err := h.engine.Forward("media.fixture.test", 80, false)
	if err != nil {
		t.Fatal(err)
	}
	c := dialForward(t, h.engine, port)
	defer c.Close()
	body, err := httpOver(t, c, "media.fixture.test", "/media")
	if err != nil || !strings.Contains(body, string(testpeer.MediaBody)) {
		t.Fatalf("response %q err %v", body, err)
	}
	if h.peer.DNSQueries.Load() == 0 {
		t.Fatal("hostname was not resolved by the tunnel's DNS")
	}
	conns := h.engine.Status()["connections"].(map[string]int64)
	if conns["forward"] != 1 || conns["forwardOpen"] != 0 {
		t.Fatalf("counters %v", conns)
	}
}

func TestForwardTakesOnlyTheExpectedSocket(t *testing.T) {
	h := startTunnel(t, nil)
	port, err := h.engine.Forward(testpeer.ServerAddr.String(), 80, false)
	if err != nil {
		t.Fatal(err)
	}
	intruder, err := net.Dial("tcp4", joinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	defer intruder.Close()
	c := dialForward(t, h.engine, port)
	defer c.Close()
	intruder.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(intruder, "GET /media HTTP/1.0\r\nHost: x\r\n\r\n"); err == nil {
		if b, _ := io.ReadAll(intruder); strings.Contains(string(b), "200") {
			t.Fatal("an unexpected local socket was forwarded")
		}
	}
	body, err := httpOver(t, c, "fixture.test", "/media")
	if err != nil || !strings.Contains(body, "200") {
		t.Fatalf("expected socket: %q %v", body, err)
	}
	if h.engine.forwardRejected.Load() != 1 {
		t.Fatalf("rejected %d", h.engine.forwardRejected.Load())
	}
}

func TestForwardWaitsForUpstreamAttachedLater(t *testing.T) {
	peer, err := testpeer.Start(testpeer.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	e, err := NewEngine(testUser, testPass, EngineOptions{DialTimeout: 6 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	port, err := e.Forward("fixture.test", 80, false)
	if err != nil {
		t.Fatal(err)
	}
	c := dialForward(t, e, port)
	defer c.Close()
	go func() {
		time.Sleep(400 * time.Millisecond)
		p, _ := ParseProfile(peer.ClientConfig)
		if err := e.AttachWireGuard(p, nil); err != nil {
			t.Error(err)
		}
	}()
	body, err := httpOver(t, c, "fixture.test", "/media")
	if err != nil || !strings.Contains(body, "200") {
		t.Fatalf("response %q err %v", body, err)
	}
}

func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || (err != nil && strings.Contains(err.Error(), "reset"))
}

func TestForwardFailsClosedWithReset(t *testing.T) {
	e, err := NewEngine(testUser, testPass, EngineOptions{DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	port, err := e.Forward("fixture.test", 80, false)
	if err != nil {
		t.Fatal(err)
	}
	c := dialForward(t, e, port)
	defer c.Close()
	e.Fail("profile unusable")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "GET / HTTP/1.0\r\n\r\n")
	_, err = io.ReadAll(c)
	if !isReset(err) {
		t.Fatalf("expected a reset, got %v", err)
	}
	if _, err := e.Forward("fixture.test", 80, false); err == nil {
		t.Fatal("a failed engine still opened forwarders")
	}
}

func TestForwardOverIPv6Loopback(t *testing.T) {
	if l, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		l.Close()
	}
	h := startTunnel(t, nil)
	port, err := h.engine.Forward("fixture.test", 80, true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp6", joinHostPort("::1", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h.engine.ExpectPeer(port, c.LocalAddr().(*net.TCPAddr).Port)
	if body, err := httpOver(t, c, "fixture.test", "/media"); err != nil || !strings.Contains(body, "200") {
		t.Fatalf("response %q err %v", body, err)
	}
}

func TestForwarderExpiresUnused(t *testing.T) {
	e, err := NewEngine(testUser, testPass, EngineOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.forwardTimeout = 100 * time.Millisecond // forwardAcceptTimeout, shortened
	e.Forward("fixture.test", 80, false)
	deadline := time.Now().Add(3 * time.Second)
	for e.forwardOpen.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if e.forwardOpen.Load() != 0 || e.forwardExpired.Load() != 1 {
		t.Fatalf("open %d expired %d", e.forwardOpen.Load(), e.forwardExpired.Load())
	}
}

// chained returns an engine whose upstream is `kind` pointed at h's own
// authenticated SOCKS5 / CONNECT server (which reaches the test peer).
func chained(t *testing.T, h *harness, cfg ExternalConfig) *Engine {
	t.Helper()
	e, err := NewEngine("u-front", "p-front", EngineOptions{DialTimeout: 6 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	if cfg.Host == "" {
		cfg.Host, cfg.Port = "127.0.0.1", h.engine.Port()
	}
	if err := e.AttachExternal(cfg); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestExternalSOCKS5AndHTTPConnect(t *testing.T) {
	h := startTunnel(t, nil)
	for _, kind := range []string{"socks5", "http"} {
		e := chained(t, h, ExternalConfig{Kind: kind, Username: testUser, Password: testPass})
		port, err := e.Forward("fixture.test", 80, false)
		if err != nil {
			t.Fatal(err)
		}
		c := dialForward(t, e, port)
		body, err := httpOver(t, c, "fixture.test", "/media")
		c.Close()
		if err != nil || !strings.Contains(body, string(testpeer.MediaBody)) {
			t.Fatalf("%s: %q %v", kind, body, err)
		}
	}
	conns := h.engine.Status()["connections"].(map[string]int64)
	if conns["socks"] != 1 || conns["httpConnect"] != 1 {
		t.Fatalf("upstream proxy counters %v", conns)
	}
}

func TestExternalWrongPasswordResets(t *testing.T) {
	h := startTunnel(t, nil)
	for _, kind := range []string{"socks5", "http"} {
		e := chained(t, h, ExternalConfig{Kind: kind, Username: testUser, Password: "wrong"})
		port, _ := e.Forward("fixture.test", 80, false)
		c := dialForward(t, e, port)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, "GET / HTTP/1.0\r\n\r\n")
		if _, err := io.ReadAll(c); !isReset(err) {
			t.Fatalf("%s: expected reset, got %v", kind, err)
		}
		c.Close()
	}
	if h.engine.authRejected.Load() != 2 {
		t.Fatalf("auth rejected %d", h.engine.authRejected.Load())
	}
}

// tlsFront terminates TLS for an HTTPS proxy and passes the bytes to target.
func tlsFront(t *testing.T, target int) (int, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "proxy"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	l, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var served atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			served.Add(1)
			go func() {
				defer c.Close()
				u, err := net.Dial("tcp4", joinHostPort("127.0.0.1", target))
				if err != nil {
					return
				}
				defer u.Close()
				go io.Copy(u, c)
				io.Copy(c, u)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, pool
}

func TestExternalHTTPSValidatesProxyCertificate(t *testing.T) {
	h := startTunnel(t, nil)
	front, pool := tlsFront(t, h.engine.Port())
	good := chained(t, h, ExternalConfig{Kind: "https", Host: "127.0.0.1", Port: front, Username: testUser, Password: testPass, RootCAs: pool})
	port, _ := good.Forward("fixture.test", 80, false)
	c := dialForward(t, good, port)
	body, err := httpOver(t, c, "fixture.test", "/media")
	c.Close()
	if err != nil || !strings.Contains(body, "200") {
		t.Fatalf("trusted HTTPS proxy: %q %v", body, err)
	}
	// The same server with the system trust store: its self-signed certificate is refused.
	bad := chained(t, h, ExternalConfig{Kind: "https", Host: "127.0.0.1", Port: front, Username: testUser, Password: testPass})
	port, _ = bad.Forward("fixture.test", 80, false)
	c = dialForward(t, bad, port)
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "GET / HTTP/1.0\r\n\r\n")
	if _, err := io.ReadAll(c); !isReset(err) {
		t.Fatalf("untrusted proxy certificate was accepted: %v", err)
	}
}

func TestExternalConfigValidation(t *testing.T) {
	for _, cfg := range []ExternalConfig{
		{Kind: "ftp", Host: "proxy.example", Port: 1080},
		{Kind: "socks5", Host: "http://proxy.example", Port: 1080},
		{Kind: "socks5", Host: "proxy.example/path", Port: 1080},
		{Kind: "http", Host: "proxy.example", Port: 0},
		{Kind: "http", Host: "proxy.example", Port: 70000},
		{Kind: "http", Host: "proxy.example", Port: 8080, Username: "a:b"},
	} {
		if validateExternal(cfg) == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
	for _, cfg := range []ExternalConfig{
		{Kind: "socks5", Host: "proxy.example", Port: 1080},
		{Kind: "https", Host: "[2001:db8::1]", Port: 443, Username: "me", Password: "p:w"},
		{Kind: "http", Host: "203.0.113.5", Port: 3128},
	} {
		if err := validateExternal(cfg); err != nil {
			t.Errorf("rejected %+v: %v", cfg, err)
		}
	}
}

func TestLocalNetworkTargetsGoDirectWithoutUpstream(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			io.WriteString(c, "HTTP/1.0 200 OK\r\n\r\nlan")
			c.Close()
		}
	}()
	e, err := NewEngine(testUser, testPass, EngineOptions{DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	lan := l.Addr().String()
	e.localNet = func(a netip.Addr) bool { return netip.MustParsePrefix("192.168.77.0/24").Contains(a) }
	e.lanDial = func(host string, port int) (net.Conn, error) {
		if host != "192.168.77.7" || port != 8009 {
			t.Errorf("direct dial to %s:%d", host, port)
		}
		return net.Dial("tcp4", lan) // stands in for the speaker on the LAN
	}
	port, _ := e.Forward("192.168.77.7", 8009, false)
	c := dialForward(t, e, port)
	defer c.Close()
	if body, err := httpOver(t, c, "x", "/"); err != nil || !strings.Contains(body, "lan") {
		t.Fatalf("%q %v", body, err)
	}
	if e.lanDirect.Load() != 1 || e.total.Load() != 0 {
		t.Fatalf("lanDirect %d total %d", e.lanDirect.Load(), e.total.Load())
	}
	for host, local := range map[string]bool{"192.168.77.20": true, "::ffff:192.168.77.9": true, "fe80::1": true, "speaker.local": true,
		"10.64.0.1": false, "192.168.1.20": false, "127.0.0.1": false, "localhost": false, "8.8.8.8": false,
		"spclient.wg.spotify.com": false, "100.64.0.1": false, "198.18.0.1": false} {
		if e.isLocalTarget(host) != local {
			t.Errorf("isLocalTarget(%q) = %v", host, !local)
		}
	}
}
