package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ExternalConfig is a proxy server the user named instead of a WireGuard profile.
type ExternalConfig struct {
	Kind     string // "http", "https" or "socks5"
	Host     string
	Port     int
	Username string
	Password string
	// RootCAs replaces the system trust store for the HTTPS kind (tests only).
	RootCAs *x509.CertPool
}

var (
	errExternalKind = errors.New("unknown proxy kind")
	errExternalHost = errors.New("proxy server must be a host name or IP address")
	errExternalPort = errors.New("proxy port must be a number from 1 to 65535")
	errExternalUser = errors.New("proxy user name or password is too long")
	errProxyRefused = errors.New("proxy server refused the connection")
	errProxyAuth    = errors.New("proxy server rejected the user name or password")
)

// externalUpstream hands each connection to the proxy server. Hostnames go to
// the server unresolved (SOCKS5 domain addresses, CONNECT authorities), so the
// device never looks them up. The proxy server's own address is the one name
// the device resolves.
type externalUpstream struct {
	cfg    ExternalConfig
	server string
	socks  proxy.ContextDialer
}

func validateExternal(cfg ExternalConfig) error {
	switch cfg.Kind {
	case "http", "https", "socks5":
	default:
		return errExternalKind
	}
	host := strings.TrimSuffix(strings.TrimPrefix(cfg.Host, "["), "]")
	if host == "" || len(host) > 253 || (net.ParseIP(host) == nil && !isHostname(host)) {
		return errExternalHost
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return errExternalPort
	}
	if len(cfg.Username) > 255 || len(cfg.Password) > 255 || strings.ContainsAny(cfg.Username, ":\r\n") {
		return errExternalUser
	}
	return nil
}

func newExternalUpstream(cfg ExternalConfig) (*externalUpstream, error) {
	if err := validateExternal(cfg); err != nil {
		return nil, err
	}
	host := strings.TrimSuffix(strings.TrimPrefix(cfg.Host, "["), "]")
	x := &externalUpstream{cfg: cfg, server: net.JoinHostPort(host, strconv.Itoa(cfg.Port))}
	if cfg.Kind == "socks5" {
		var auth *proxy.Auth
		if cfg.Username != "" {
			auth = &proxy.Auth{User: cfg.Username, Password: cfg.Password}
		}
		d, err := proxy.SOCKS5("tcp", x.server, auth, &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second})
		if err != nil {
			return nil, errExternalHost
		}
		x.socks = d.(proxy.ContextDialer)
	}
	return x, nil
}

func (x *externalUpstream) Kind() string { return x.cfg.Kind }
func (x *externalUpstream) Close()       {}

func (x *externalUpstream) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	target := joinHostPort(host, port)
	if x.socks != nil {
		c, err := x.socks.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, errProxyRefused
		}
		return c, nil
	}
	return x.connect(ctx, target)
}

// bufferedConn returns what the reader already holds before reading the socket.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufferedConn) CloseWrite() error {
	if half, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

// connect opens an HTTP CONNECT tunnel, over TLS to the proxy for the HTTPS kind
// (validated against the system trust store: a self-signed proxy is refused).
func (x *externalUpstream) connect(ctx context.Context, target string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", x.server)
	if err != nil {
		return nil, errProxyRefused
	}
	c := raw
	if x.cfg.Kind == "https" {
		host, _, _ := net.SplitHostPort(x.server)
		t := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: x.cfg.RootCAs, MinVersion: tls.VersionTLS12})
		if err := t.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, errProxyRefused
		}
		c = t
	}
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	var b strings.Builder
	b.WriteString("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n")
	if x.cfg.Username != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(x.cfg.Username + ":" + x.cfg.Password))
		b.WriteString("Proxy-Authorization: Basic " + cred + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := c.Write([]byte(b.String())); err != nil {
		c.Close()
		return nil, errProxyRefused
	}
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, errProxyRefused
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired {
		c.Close()
		return nil, errProxyAuth
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, errProxyRefused
	}
	c.SetDeadline(time.Time{})
	return &bufferedConn{Conn: c, r: r}, nil
}
