// Package testpeer is a WireGuard server for tests. It runs wireguard-go on its
// own gVisor netstack (no TUN, no root) and serves, inside the tunnel only:
//
//   - DNS on 10.66.0.1:53, answering *.fixture.test with 10.66.0.1. These names
//     do not exist in public DNS, so a successful request proves that the
//     lookup went through the tunnel's DNS.
//   - HTTP on :80 and HTTPS on :443 (self-signed certificate for fixture.test),
//     with Range support (HTTP 206) on /media.
//   - /cdn-cgi/trace returning ip= and loc= lines like Cloudflare's endpoint.
package testpeer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	ServerAddr = netip.MustParseAddr("10.66.0.1")
	ClientAddr = netip.MustParseAddr("10.66.0.2")
	// MediaBody is served at /media; tests request byte ranges of it.
	MediaBody = []byte("ytmu-wireguard-range-fixture-0123456789")
)

type Peer struct {
	dev     *device.Device
	net     *netstack.Net
	servers []*http.Server
	dnsConn net.PacketConn

	Port         int    // UDP port on 127.0.0.1
	ClientConfig string // complete client .conf (test keys only)
	CertDER      []byte // HTTPS certificate for fixture.test

	DNSQueries, HTTPHits, HTTPSHits, RangeHits atomic.Int64
}

type Options struct {
	ListenAddr string // UDP listen host; default 127.0.0.1
	MTU        int
	Keepalive  int
}

func newKey() (priv, pub [32]byte) {
	rand.Read(priv[:])
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

func Start(opt Options) (*Peer, error) {
	if opt.ListenAddr == "" {
		opt.ListenAddr = "127.0.0.1"
	}
	if opt.MTU == 0 {
		opt.MTU = 1420
	}
	serverPriv, serverPub := newKey()
	clientPriv, clientPub := newKey()

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{ServerAddr}, nil, opt.MTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	p := &Peer{dev: dev, net: tnet}
	// An explicit port is used because wireguard-go reports port 0 for
	// listen_port=0 on hosts without IPv6 (udp6 EAFNOSUPPORT overwrites it).
	var lastErr error
	for attempt := 0; attempt < 20 && p.Port == 0; attempt++ {
		probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			lastErr = err
			continue
		}
		port := probe.LocalAddr().(*net.UDPAddr).Port
		probe.Close()
		uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\npublic_key=%s\nallowed_ip=%s/32\n",
			hex.EncodeToString(serverPriv[:]), port, hex.EncodeToString(clientPub[:]), ClientAddr)
		if lastErr = dev.IpcSet(uapi); lastErr == nil {
			p.Port = port
		}
	}
	if p.Port == 0 {
		dev.Close()
		return nil, fmt.Errorf("peer UDP port: %v", lastErr)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	keepalive := ""
	if opt.Keepalive > 0 {
		keepalive = fmt.Sprintf("PersistentKeepalive = %d\n", opt.Keepalive)
	}
	p.ClientConfig = fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = %s\nMTU = %d\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s\n%s",
		base64.StdEncoding.EncodeToString(clientPriv[:]), ClientAddr, ServerAddr, opt.MTU,
		base64.StdEncoding.EncodeToString(serverPub[:]), net.JoinHostPort(opt.ListenAddr, fmt.Sprint(p.Port)), keepalive)

	if err := p.startDNS(); err != nil {
		p.Close()
		return nil, err
	}
	if err := p.startHTTP(); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

func (p *Peer) Close() {
	for _, s := range p.servers {
		s.Close()
	}
	if p.dnsConn != nil {
		p.dnsConn.Close()
	}
	p.dev.Close()
}

func (p *Peer) startDNS() error {
	pc, err := p.net.ListenUDPAddrPort(netip.AddrPortFrom(ServerAddr, 53))
	if err != nil {
		return err
	}
	p.dnsConn = pc
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			p.DNSQueries.Add(1)
			if resp := answer(buf[:n]); resp != nil {
				pc.WriteTo(resp, from)
			}
		}
	}()
	return nil
}

func answer(query []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil
	}
	q, err := parser.Question()
	if err != nil {
		return nil
	}
	name := strings.ToLower(q.Name.String())
	known := name == "fixture.test." || strings.HasSuffix(name, ".fixture.test.")
	header.Response, header.Authoritative, header.RecursionAvailable = true, true, true
	header.RCode = dnsmessage.RCodeSuccess
	if !known {
		header.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, header)
	b.EnableCompression()
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	if known && q.Type == dnsmessage.TypeA {
		b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: ServerAddr.As4()})
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

func (p *Peer) handler(secure bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if secure {
			p.HTTPSHits.Add(1)
		} else {
			p.HTTPHits.Add(1)
		}
		w.Write([]byte("through-tunnel"))
	})
	mux.HandleFunc("/media", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			p.RangeHits.Add(1)
		}
		w.Header().Set("Content-Type", "audio/mp4")
		http.ServeContent(w, r, "media", time.Unix(1700000000, 0), bytes.NewReader(MediaBody))
	})
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintf(w, "fl=test\nh=fixture.test\nip=%s\nloc=ZZ\nhttp=http/1.1\n", host)
	})
	return mux
}

func (p *Peer) startHTTP() error {
	plain, err := p.net.ListenTCPAddrPort(netip.AddrPortFrom(ServerAddr, 80))
	if err != nil {
		return err
	}
	secure, err := p.net.ListenTCPAddrPort(netip.AddrPortFrom(ServerAddr, 443))
	if err != nil {
		plain.Close()
		return err
	}
	cert, err := p.certificate()
	if err != nil {
		plain.Close()
		secure.Close()
		return err
	}
	s1 := &http.Server{Handler: p.handler(false), ReadHeaderTimeout: 10 * time.Second}
	s2 := &http.Server{Handler: p.handler(true), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	p.servers = []*http.Server{s1, s2}
	go s1.Serve(plain)
	go s2.ServeTLS(secure, "", "")
	return nil
}

func (p *Peer) certificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "fixture.test"},
		DNSNames:     []string{"fixture.test", "media.fixture.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	p.CertDER = der
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// CertPool returns a pool trusting only the fixture certificate.
func (p *Peer) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if c, err := x509.ParseCertificate(p.CertDER); err == nil {
		pool.AddCert(c)
	}
	return pool
}
