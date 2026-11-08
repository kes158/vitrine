package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Engine runs wireguard-go on a gVisor userspace network stack and exposes an
// authenticated SOCKS5 / HTTP CONNECT proxy on 127.0.0.1 for this process only.
//
// No system TUN, route table, VPN profile or Network Extension is involved: the
// only sockets opened on the device are the WireGuard UDP socket and the local
// loopback listener. Every proxied TCP connection, and every DNS lookup for a
// proxied hostname, goes through the WireGuard tunnel. There is no net.Dial
// fallback anywhere in the data path.
type Engine struct {
	dev   *device.Device
	stack *netstack.Net
	user  []byte
	pass  []byte
	port  int

	mu       sync.Mutex
	listener net.Listener
	clients  map[net.Conn]struct{}

	dialTimeout time.Duration
	stopped     atomic.Bool

	// Counters. Only counts are kept; hostnames, URLs and addresses are not.
	total, active, failed, dnsFailed atomic.Int64
	domainTargets, ipTargets         atomic.Int64
	viaSOCKS, viaCONNECT             atomic.Int64
	authRejected, badRequests        atomic.Int64
	media, api, other                atomic.Int64
	upBytes, downBytes               atomic.Int64
	bindUpdates, bindFailures        atomic.Int64
	relistens                        atomic.Int64
	started                          time.Time
	endpointResolvedLocally          bool
}

type EngineOptions struct {
	// Listener, when non-nil, is used as the local proxy socket. Otherwise the
	// engine listens on 127.0.0.1:Port (Port 0 picks a free port).
	Listener    net.Listener
	Port        int
	DialTimeout time.Duration
	// Resolve resolves a hostname Endpoint. It is the one lookup that cannot go
	// through the tunnel, because it is needed to reach the tunnel.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
}

var (
	errStackInit    = errors.New("userspace network initialization failed")
	errWGConfig     = errors.New("WireGuard configuration failed")
	errWGUp         = errors.New("WireGuard UDP initialization failed")
	errListen       = errors.New("local proxy initialization failed")
	errEndpointDNS  = errors.New("WireGuard endpoint hostname could not be resolved")
	errCredentials  = errors.New("local proxy credentials are required")
	errNoSuitableEP = errors.New("WireGuard endpoint has no usable address")
)

func defaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func StartEngine(p *Profile, user, pass string, opt EngineOptions) (*Engine, error) {
	if len(user) == 0 || len(pass) == 0 || len(user) > 255 || len(pass) > 255 {
		return nil, errCredentials
	}
	endpoint, local, err := resolveEndpoint(p, opt.Resolve)
	if err != nil {
		return nil, err
	}
	tunDev, stack, err := netstack.CreateNetTUN(p.Addresses, p.DNS, p.MTU)
	if err != nil {
		return nil, errStackInit
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(p.uapi(endpoint)); err != nil {
		dev.Close()
		return nil, errWGConfig
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, errWGUp
	}
	listener := opt.Listener
	if listener == nil {
		listener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(opt.Port)))
		if err != nil {
			dev.Close()
			return nil, errListen
		}
	}
	e := &Engine{
		dev: dev, stack: stack, user: []byte(user), pass: []byte(pass),
		listener: listener, clients: map[net.Conn]struct{}{},
		dialTimeout: opt.DialTimeout, started: time.Now(), endpointResolvedLocally: local,
	}
	if e.dialTimeout <= 0 {
		e.dialTimeout = 15 * time.Second
	}
	if addr, ok := listener.Addr().(*net.TCPAddr); ok {
		e.port = addr.Port
	}
	go e.acceptLoop(listener)
	return e, nil
}

func resolveEndpoint(p *Profile, resolve func(context.Context, string) ([]netip.Addr, error)) (netip.AddrPort, bool, error) {
	if addr, err := netip.ParseAddr(p.EndpointHost); err == nil {
		return netip.AddrPortFrom(addr, uint16(p.EndpointPort)), false, nil
	}
	if resolve == nil {
		resolve = defaultResolve
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := resolve(ctx, p.EndpointHost)
	if err != nil || len(addrs) == 0 {
		return netip.AddrPort{}, true, errEndpointDNS
	}
	for _, a := range addrs { // prefer IPv4: it works on every network
		if a.Unmap().Is4() {
			return netip.AddrPortFrom(a.Unmap(), uint16(p.EndpointPort)), true, nil
		}
	}
	for _, a := range addrs {
		if a.Is6() {
			return netip.AddrPortFrom(a, uint16(p.EndpointPort)), true, nil
		}
	}
	return netip.AddrPort{}, true, errNoSuitableEP
}

func (e *Engine) Port() int { return e.port }

func (e *Engine) Close() {
	if e.stopped.Swap(true) {
		return
	}
	e.mu.Lock()
	e.listener.Close()
	for c := range e.clients {
		c.Close()
	}
	e.mu.Unlock()
	e.dev.Close()
}

func (e *Engine) track(c net.Conn) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped.Load() {
		return false
	}
	e.clients[c] = struct{}{}
	return true
}

func (e *Engine) untrack(c net.Conn) {
	e.mu.Lock()
	delete(e.clients, c)
	e.mu.Unlock()
}

func (e *Engine) acceptLoop(l net.Listener) {
	failures := 0
	for {
		c, err := l.Accept()
		if err != nil {
			if e.stopped.Load() {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && failures < 50 {
				failures++
				time.Sleep(20 * time.Millisecond)
				continue
			}
			// iOS can defunct a listening socket while the app is suspended.
			// Bind the same port again so existing URLSession proxy settings,
			// which point at this port, keep working.
			e.relisten(l)
			return
		}
		failures = 0
		if !e.track(c) {
			c.Close()
			return
		}
		go func() {
			defer e.untrack(c)
			defer c.Close()
			e.serve(c)
		}()
	}
}

func (e *Engine) relisten(old net.Listener) {
	for attempt := 0; !e.stopped.Load(); attempt++ {
		e.mu.Lock()
		if e.listener != old || e.stopped.Load() {
			e.mu.Unlock()
			return
		}
		old.Close()
		l, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(e.port)))
		if err == nil {
			e.listener = l
			e.relistens.Add(1)
			e.mu.Unlock()
			go e.acceptLoop(l)
			return
		}
		e.mu.Unlock()
		delay := time.Duration(attempt+1) * 100 * time.Millisecond
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
		time.Sleep(delay)
	}
}

// Rebind reopens the WireGuard UDP socket (network change or return from
// suspension) and re-creates the local listener if it no longer accepts.
func (e *Engine) Rebind() error {
	if e.stopped.Load() {
		return net.ErrClosed
	}
	err := e.dev.BindUpdate()
	if err != nil {
		e.bindFailures.Add(1)
	} else {
		e.bindUpdates.Add(1)
	}
	e.mu.Lock()
	l := e.listener
	e.mu.Unlock()
	probe, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(e.port)), 500*time.Millisecond)
	if dialErr != nil {
		e.relisten(l)
	} else {
		probe.Close()
	}
	return err
}

// classify counts the destination family without storing the hostname.
func (e *Engine) classify(host string) {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	switch {
	case strings.HasPrefix(h, "audio") && (hasSuffix(h, "scdn.co") || hasSuffix(h, "spotifycdn.com") || hasSuffix(h, "akamaized.net")):
		e.media.Add(1)
	case hasSuffix(h, "spotify.com"), hasSuffix(h, "spotify.net"):
		e.api.Add(1)
	default:
		e.other.Add(1)
	}
}

func hasSuffix(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func (e *Engine) dial(host string, port int) (net.Conn, error) {
	e.total.Add(1)
	if _, err := netip.ParseAddr(host); err == nil {
		e.ipTargets.Add(1)
		e.other.Add(1)
	} else {
		e.domainTargets.Add(1)
		e.classify(host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.dialTimeout)
	defer cancel()
	// Hostnames are resolved by netstack's resolver, which queries the
	// profile's DNS servers through the tunnel. There is no direct fallback.
	c, err := e.stack.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		e.failed.Add(1)
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			e.dnsFailed.Add(1)
		}
		return nil, err
	}
	return c, nil
}

func (e *Engine) serve(c net.Conn) {
	c.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReaderSize(c, 4096)
	first, err := r.Peek(1)
	if err != nil {
		return
	}
	switch {
	case first[0] == 5:
		e.serveSOCKS(c, r)
	case first[0] >= 'A' && first[0] <= 'Z':
		e.serveCONNECT(c, r)
	default:
		e.badRequests.Add(1)
	}
}

func (e *Engine) authorized(user, pass []byte) bool {
	u := subtle.ConstantTimeCompare(user, e.user)
	p := subtle.ConstantTimeCompare(pass, e.pass)
	return u&p == 1
}

func (e *Engine) serveSOCKS(c net.Conn, r *bufio.Reader) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}
	userPass := false
	for _, m := range methods {
		if m == 2 {
			userPass = true
		}
	}
	if !userPass { // "no authentication" is never accepted
		e.authRejected.Add(1)
		c.Write([]byte{5, 0xff})
		return
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return
	}
	if _, err := io.ReadFull(r, head); err != nil || head[0] != 1 {
		return
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, user); err != nil {
		return
	}
	if _, err := io.ReadFull(r, head[:1]); err != nil {
		return
	}
	pass := make([]byte, int(head[0]))
	if _, err := io.ReadFull(r, pass); err != nil {
		return
	}
	if !e.authorized(user, pass) {
		e.authRejected.Add(1)
		c.Write([]byte{1, 1})
		return
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(r, req); err != nil || req[0] != 5 {
		return
	}
	if req[1] != 1 { // only CONNECT; UDP ASSOCIATE/BIND are refused (no UDP bypass)
		e.badRequests.Add(1)
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return
		}
		host = netip.AddrFrom4([4]byte(b)).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return
		}
		host = netip.AddrFrom16([16]byte(b)).Unmap().String()
	case 3:
		if _, err := io.ReadFull(r, head[:1]); err != nil || head[0] == 0 {
			return
		}
		b := make([]byte, int(head[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return
		}
		host = string(b)
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := io.ReadFull(r, head); err != nil {
		return
	}
	port := int(head[0])<<8 | int(head[1])
	if port == 0 {
		return
	}
	e.viaSOCKS.Add(1)
	upstream, err := e.dial(host, port)
	if err != nil {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // host unreachable
		return
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		upstream.Close()
		return
	}
	e.pipe(c, r, upstream)
}

const proxyAuthRequired = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
	"Proxy-Authenticate: Basic realm=\"ytmu\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

// serveCONNECT accepts HTTP CONNECT (used by FFmpeg's http_proxy for HTTPS
// downloads). Plain absolute-URI HTTP proxying is refused so that nothing is
// forwarded outside a tunnelled byte stream.
func (e *Engine) serveCONNECT(c net.Conn, r *bufio.Reader) {
	var lines []string
	size := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		size += len(line)
		if size > 16*1024 {
			e.badRequests.Add(1)
			io.WriteString(c, "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n")
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 3 || parts[0] != "CONNECT" || !strings.HasPrefix(parts[2], "HTTP/1.") {
		e.badRequests.Add(1)
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	authorized := false
	for _, h := range lines[1:] {
		name, value, ok := strings.Cut(h, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Proxy-Authorization") {
			continue
		}
		scheme, cred, _ := strings.Cut(strings.TrimSpace(value), " ")
		if !strings.EqualFold(scheme, "Basic") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
		if err != nil {
			continue
		}
		u, p, ok := strings.Cut(string(raw), ":")
		if ok && e.authorized([]byte(u), []byte(p)) {
			authorized = true
		}
	}
	if !authorized {
		e.authRejected.Add(1)
		io.WriteString(c, proxyAuthRequired)
		return
	}
	host, portText, err := net.SplitHostPort(parts[1])
	port, perr := strconv.Atoi(portText)
	if err != nil || perr != nil || host == "" || port < 1 || port > 65535 {
		e.badRequests.Add(1)
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	e.viaCONNECT.Add(1)
	upstream, err := e.dial(host, port)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		upstream.Close()
		return
	}
	e.pipe(c, r, upstream)
}

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (cw countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n.Add(int64(n))
	return n, err
}

func (e *Engine) pipe(c net.Conn, r *bufio.Reader, upstream net.Conn) {
	if !e.track(upstream) {
		upstream.Close()
		return
	}
	defer e.untrack(upstream)
	defer upstream.Close()
	c.SetDeadline(time.Time{})
	e.active.Add(1)
	defer e.active.Add(-1)
	done := make(chan struct{})
	go func() {
		// r may already hold bytes the client sent right after the request.
		io.Copy(countingWriter{upstream, &e.upBytes}, r)
		if half, ok := upstream.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		} else {
			upstream.Close()
		}
		close(done)
	}()
	io.Copy(countingWriter{c, &e.downBytes}, upstream)
	if half, ok := c.(interface{ CloseWrite() error }); ok {
		half.CloseWrite()
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	c.Close()
	upstream.Close()
	<-done
}

// Lookup resolves host through the tunnel's DNS servers (diagnostics only).
func (e *Engine) Lookup(host string, timeout time.Duration) (int, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	addrs, err := e.stack.LookupContextHost(ctx, host)
	return len(addrs), time.Since(start), err
}

// Status reports counters and handshake state. It never includes keys,
// endpoint addresses, hostnames or URLs: IpcGet output is parsed for a fixed
// set of numeric fields only, because it also contains private_key.
func (e *Engine) Status() map[string]any {
	out := map[string]any{"running": !e.stopped.Load()}
	data, err := e.dev.IpcGet()
	if err == nil {
		var last, rx, tx int64
		for _, line := range strings.Split(data, "\n") {
			key, value, _ := strings.Cut(line, "=")
			n, _ := strconv.ParseInt(value, 10, 64)
			switch key {
			case "last_handshake_time_sec":
				last = n
			case "rx_bytes":
				rx = n
			case "tx_bytes":
				tx = n
			}
		}
		out["handshakeAgeSec"] = int64(-1)
		if last > 0 {
			out["handshakeAgeSec"] = int64(time.Since(time.Unix(last, 0)).Seconds())
		}
		out["wgRxBytes"], out["wgTxBytes"] = rx, tx
	}
	out["uptimeSec"] = int64(time.Since(e.started).Seconds())
	out["connections"] = map[string]int64{
		"total": e.total.Load(), "active": e.active.Load(), "failed": e.failed.Load(),
		"dnsFailed": e.dnsFailed.Load(), "domainTargets": e.domainTargets.Load(), "ipTargets": e.ipTargets.Load(),
		"socks": e.viaSOCKS.Load(), "httpConnect": e.viaCONNECT.Load(),
		"authRejected": e.authRejected.Load(), "badRequests": e.badRequests.Load(),
	}
	out["categories"] = map[string]int64{"media": e.media.Load(), "api": e.api.Load(), "other": e.other.Load()}
	out["proxyBytes"] = map[string]int64{"up": e.upBytes.Load(), "down": e.downBytes.Load()}
	out["bind"] = map[string]int64{"updates": e.bindUpdates.Load(), "failures": e.bindFailures.Load(), "relistens": e.relistens.Load()}
	out["endpointResolvedLocally"] = e.endpointResolvedLocally
	return out
}

func (e *Engine) String() string { return fmt.Sprintf("engine(port=%d)", e.port) }
