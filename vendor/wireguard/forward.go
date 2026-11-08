package main

import (
	"bufio"
	"net"
	"strconv"
	"time"
)

// A forwarder carries one TCP connection that Spotify opened with connect()
// to the destination it asked for. Shared/WireGuard/WGSockets.m asks for one
// with the destination, connects Spotify's own socket to the loopback port it
// gets back instead, and then reports the socket's local port (ExpectPeer), so
// the forwarder takes that one connection and nothing else on the device that
// might reach the port first.
//
// Spotify's socket keeps its own non-blocking and kqueue behaviour: the kernel
// completes the loopback handshake, and the upstream connection is made after
// accept. When that fails the loopback side is reset (SO_LINGER 0), so Spotify
// reads ECONNRESET and tries its next access point or host, as it would for a
// refused connection.

// forwardAcceptTimeout is how long a forwarder waits for its one connection.
const forwardAcceptTimeout = 30 * time.Second

// expectTimeout is how long an accepted connection waits for ExpectPeer.
const expectTimeout = 3 * time.Second

type forwarder struct {
	listener *net.TCPListener
	host     string
	port     int
	expect   chan int
}

// Forward opens a one-shot loopback listener for a connection to host:port,
// on ::1 when ipv6 is set and on 127.0.0.1 otherwise, and returns its port.
func (e *Engine) Forward(host string, port int, ipv6 bool) (int, error) {
	if e.stopped.Load() {
		return -1, errStopped
	}
	if e.failed.Load() != nil && e.upstream() == nil {
		return -1, errNotReady
	}
	if port < 1 || port > 65535 || host == "" {
		return -1, errNotReady
	}
	if e.forwardOpen.Add(1) > maxForwarders {
		e.forwardOpen.Add(-1)
		return -1, errTooMany
	}
	network, address := "tcp4", "127.0.0.1:0"
	if ipv6 {
		network, address = "tcp6", "[::1]:0"
	}
	l, err := net.Listen(network, address)
	if err != nil {
		e.forwardOpen.Add(-1)
		return -1, err
	}
	tl := l.(*net.TCPListener)
	f := &forwarder{listener: tl, host: host, port: port, expect: make(chan int, 1)}
	local := tl.Addr().(*net.TCPAddr).Port
	e.mu.Lock()
	if e.forwarders == nil {
		e.forwarders = map[int]*forwarder{}
	}
	e.forwarders[local] = f
	e.mu.Unlock()
	go e.runForwarder(local, f)
	return local, nil
}

// ExpectPeer names the local port of the one socket the forwarder on
// listenPort may accept. Zero accepts the first connection.
func (e *Engine) ExpectPeer(listenPort, clientPort int) bool {
	e.mu.Lock()
	f := e.forwarders[listenPort]
	e.mu.Unlock()
	if f == nil {
		return false
	}
	select {
	case f.expect <- clientPort:
		return true
	default:
		return false
	}
}

func (e *Engine) dropForwarder(local int, f *forwarder) {
	f.listener.Close()
	e.mu.Lock()
	if e.forwarders[local] == f {
		delete(e.forwarders, local)
	}
	e.mu.Unlock()
	e.forwardOpen.Add(-1)
}

func (e *Engine) runForwarder(local int, f *forwarder) {
	timeout := e.forwardTimeout
	if timeout <= 0 {
		timeout = forwardAcceptTimeout
	}
	deadline := time.Now().Add(timeout)
	f.listener.SetDeadline(deadline)
	expected, known := 0, false
	for {
		c, err := f.listener.AcceptTCP()
		if err != nil {
			e.forwardExpired.Add(1)
			e.dropForwarder(local, f)
			return
		}
		if !known {
			select {
			case expected = <-f.expect:
				known = true
			case <-time.After(expectTimeout):
			}
		}
		peer, _ := c.RemoteAddr().(*net.TCPAddr)
		if !known || peer == nil || !peer.IP.IsLoopback() || (expected != 0 && peer.Port != expected) {
			e.forwardRejected.Add(1)
			c.SetLinger(0)
			c.Close()
			if time.Now().After(deadline) {
				e.dropForwarder(local, f)
				return
			}
			continue
		}
		e.dropForwarder(local, f)
		e.serveForward(c, f.host, f.port)
		return
	}
}

func (e *Engine) serveForward(c *net.TCPConn, host string, port int) {
	if !e.track(c) {
		c.Close()
		return
	}
	defer e.untrack(c)
	defer c.Close()
	e.viaForward.Add(1)
	upstream, err := e.dial(host, port)
	if err != nil {
		c.SetLinger(0) // ECONNRESET for Spotify, never a direct connection
		return
	}
	e.pipe(c, bufio.NewReaderSize(c, 32*1024), upstream)
}

func joinHostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }
