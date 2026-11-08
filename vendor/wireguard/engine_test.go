package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var testKey = base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))

func validProfile() string {
	return "[Interface]\n# Key for test\nPrivateKey = " + testKey + "\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n" +
		"[Peer]\n# US-FREE#34\nPublicKey = " + testKey + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:51820\nPersistentKeepalive = 25\n"
}

func TestParseValidProfiles(t *testing.T) {
	p, err := ParseProfile(validProfile())
	if err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	if len(p.Addresses) != 1 || len(p.DNS) != 1 || p.MTU != 1280 || p.Keepalive != 25 || p.EndpointPort != 51820 {
		t.Fatalf("unexpected parse result: %+v", p)
	}
	// Proton-style dual stack, comments, CRLF line endings, BOM, search domain.
	dual := "\ufeff" + strings.ReplaceAll(strings.NewReplacer(
		"Address = 10.2.0.2/32", "Address = 10.2.0.2/32, 2a07:b944::2:2/128",
		"DNS = 10.2.0.1", "DNS = 10.2.0.1, 2a07:b944::2:1, corp.example",
		"AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0",
	).Replace(validProfile()), "\n", "\r\n")
	p, err = ParseProfile(dual)
	if err != nil || !p.HasIPv6() || len(p.DNS) != 2 {
		t.Fatalf("dual stack profile: %v %+v", err, p)
	}
	host := strings.Replace(validProfile(), "127.0.0.1:51820", "engage.example.com:2408", 1)
	if p, err = ParseProfile(host); err != nil || p.EndpointHost != "engage.example.com" {
		t.Fatalf("hostname endpoint: %v", err)
	}
	psk := strings.Replace(validProfile(), "AllowedIPs", "PresharedKey = "+testKey+"\nAllowedIPs", 1)
	if p, err = ParseProfile(psk); err != nil || !p.HasPSK {
		t.Fatalf("psk: %v", err)
	}
}

func TestParseRejectsUnsafeOrInvalid(t *testing.T) {
	valid := validProfile()
	cases := map[string]string{
		"script":            valid + "PostUp = echo no\n",
		"script-interface":  strings.Replace(valid, "DNS =", "PreUp = curl example\nDNS =", 1),
		"second peer":       valid + "[Peer]\nPublicKey = " + testKey + "\n",
		"split tunnel":      strings.ReplaceAll(valid, "0.0.0.0/0", "10.0.0.0/8"),
		"dns hostname only": strings.ReplaceAll(valid, "DNS = 10.2.0.1", "DNS = resolver.example"),
		"no dns":            strings.ReplaceAll(valid, "DNS = 10.2.0.1\n", ""),
		"bad endpoint":      strings.ReplaceAll(valid, "127.0.0.1:51820", "bad host:51820"),
		"endpoint port":     strings.ReplaceAll(valid, "127.0.0.1:51820", "127.0.0.1:0"),
		"bad key":           strings.Replace(valid, "PrivateKey = ", "PrivateKey = x", 1),
		"mtu":               strings.Replace(valid, "DNS =", "MTU = 1600\nDNS =", 1),
		"unknown field":     strings.Replace(valid, "DNS =", "Table = off\nDNS =", 1),
		"unknown section":   valid + "[Proxy]\n",
		"duplicate":         strings.Replace(valid, "DNS =", "DNS = 1.1.1.1\nDNS =", 1),
		"ipv6 without ::/0": strings.Replace(valid, "Address = 10.2.0.2/32", "Address = 10.2.0.2/32, fd00::2/128", 1),
		"clash yaml":        "proxies:\n  - name: wg\n    type: wireguard\n",
		"too large":         valid + strings.Repeat("#", maxProfileBytes),
	}
	for name, text := range cases {
		if _, err := ParseProfile(text); err == nil {
			t.Errorf("%s: invalid profile accepted", name)
		}
	}
}

func TestErrorsAndSummaryContainNoSecrets(t *testing.T) {
	bad := strings.Replace(validProfile(), "PublicKey = ", "PublicKey = !!", 1)
	_, err := ParseProfile(bad)
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Fatalf("error leaks key or missing: %v", err)
	}
	p, _ := ParseProfile(strings.Replace(validProfile(), "AllowedIPs", "PresharedKey = "+testKey+"\nAllowedIPs", 1))
	b, _ := json.Marshal(p.Summary())
	for _, secret := range []string{testKey, p.privateKeyHex, p.publicKeyHex} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("summary leaks key material: %s", b)
		}
	}
	if !strings.Contains(p.uapi(mustAddrPort("127.0.0.1:1")), "private_key=") {
		t.Fatal("uapi must carry the key to wireguard-go")
	}
}

func socksHandshake(t *testing.T, c net.Conn, methods []byte, user, pass string) []byte {
	t.Helper()
	c.Write(append([]byte{5, byte(len(methods))}, methods...))
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 2 {
		return reply
	}
	msg := append([]byte{1, byte(len(user))}, user...)
	msg = append(append(msg, byte(len(pass))), pass...)
	c.Write(msg)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func pipeEngine() (*Engine, net.Conn, chan struct{}) {
	a, b := net.Pipe()
	e := &Engine{user: []byte("user-0123"), pass: []byte("pass-4567"), clients: map[net.Conn]struct{}{}}
	done := make(chan struct{})
	go func() { e.serve(a); a.Close(); close(done) }()
	b.SetDeadline(time.Now().Add(2 * time.Second))
	return e, b, done
}

func TestSOCKSRejectsNoAuthAndWrongPassword(t *testing.T) {
	e, c, done := pipeEngine()
	if r := socksHandshake(t, c, []byte{0}, "", ""); r[1] != 0xff {
		t.Fatalf("no-auth SOCKS accepted: %v", r)
	}
	c.Close()
	<-done
	if e.authRejected.Load() != 1 {
		t.Fatal("rejection not counted")
	}
	e, c, done = pipeEngine()
	if r := socksHandshake(t, c, []byte{0, 2}, "user-0123", "wrong"); r[1] != 1 {
		t.Fatalf("wrong password accepted: %v", r)
	}
	c.Close()
	<-done
	if e.total.Load() != 0 {
		t.Fatal("a rejected client must not cause any upstream dial")
	}
}

func TestSOCKSRefusesUDPAssociate(t *testing.T) {
	e, c, done := pipeEngine()
	if r := socksHandshake(t, c, []byte{2}, "user-0123", "pass-4567"); r[1] != 0 {
		t.Fatalf("valid credentials rejected: %v", r)
	}
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 7 {
		t.Fatalf("UDP ASSOCIATE must be refused: %v %v", reply, err)
	}
	c.Close()
	<-done
	if e.total.Load() != 0 {
		t.Fatal("UDP associate must not dial")
	}
}

func TestCONNECTRequiresAuthAndRefusesPlainProxying(t *testing.T) {
	e, c, done := pipeEngine()
	go c.Write([]byte("CONNECT fixture.test:443 HTTP/1.1\r\nHost: fixture.test:443\r\n\r\n"))
	reader := bufio.NewReader(c)
	resp, _ := reader.ReadString('\n')
	all, _ := io.ReadAll(reader)
	if !strings.Contains(resp, "407") || !strings.Contains(string(all), "Proxy-Authenticate: Basic") {
		t.Fatalf("missing 407 challenge: %q %q", resp, all)
	}
	<-done
	e, c, done = pipeEngine()
	go c.Write([]byte("GET http://fixture.test/ HTTP/1.1\r\nHost: fixture.test\r\nProxy-Authorization: Basic " +
		base64.StdEncoding.EncodeToString([]byte("user-0123:pass-4567")) + "\r\n\r\n"))
	resp, _ = bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(resp, "405") {
		t.Fatalf("plain HTTP proxying must be refused: %q", resp)
	}
	c.Close()
	<-done
	if e.total.Load() != 0 {
		t.Fatal("refused requests must not dial")
	}
}

func TestRedact(t *testing.T) {
	in := strings.Join([]string{
		"PrivateKey = " + testKey,
		"private_key=" + strings.Repeat("ab", 32),
		"https://audio-ak.spotifycdn.com/audio/abc?__token__=exp=1~hmac=SECRETSIG&ip=1.2.3.4",
		"videoplayback?id=1&signature=XYZ",
		"Authorization: Bearer ya29.a0AfH6SMBlongtoken",
		"exit 203.0.113.77 v6 2001:db8:1234:5678::1",
		"proxy http://user-0123:" + strings.Repeat("f", 32) + "@127.0.0.1:5555",
		"mail someone@example.com",
		"keep: Spotify 9.1.94, NSURLErrorDomain -1005, HTTP 206 x3",
	}, "\n")
	out := Redact(in)
	for _, leak := range []string{testKey, strings.Repeat("ab", 32), "SECRETSIG", "spotifycdn", "signature=XYZ",
		"ya29", "203.0.113.77", "5678::1", strings.Repeat("f", 32), "someone@", "user-0123"} {
		if strings.Contains(out, leak) {
			t.Errorf("redaction leaked %q:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"9.1.94", "NSURLErrorDomain -1005", "HTTP 206 x3", "203.0.113.x"} {
		if !strings.Contains(out, keep) {
			t.Errorf("redaction removed harmless text %q:\n%s", keep, out)
		}
	}
}
