package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Profile is a parsed standard WireGuard .conf with exactly one peer.
//
// Only data needed by an app-local userspace tunnel is accepted. wg-quick
// script hooks (PreUp/PostUp/...) are rejected, and nothing in a profile can
// change system routes, create a TUN interface or run a command.
type Profile struct {
	Addresses    []netip.Addr
	DNS          []netip.Addr
	MTU          int
	EndpointHost string // numeric IP or hostname (hostname is resolved once at start)
	EndpointPort int
	AllowedIPs   []netip.Prefix
	Keepalive    int
	HasPSK       bool

	privateKeyHex string
	publicKeyHex  string
	pskHex        string
}

// Errors are short fixed strings. They never contain profile values, so they
// are safe to show in the UI or diagnostics.
var (
	errFormat        = errors.New("invalid configuration format")
	errSection       = errors.New("unsupported section (only [Interface] and one [Peer])")
	errScript        = errors.New("script fields (PreUp/PostUp/PreDown/PostDown) are not allowed")
	errField         = errors.New("unsupported configuration field")
	errDuplicate     = errors.New("duplicate configuration field")
	errPeerCount     = errors.New("exactly one [Peer] is required")
	errKey           = errors.New("invalid WireGuard key")
	errAddress       = errors.New("invalid Interface Address")
	errNoAddress     = errors.New("Interface Address is required")
	errDNSMissing    = errors.New("DNS with at least one numeric IP is required (DNS is resolved inside the tunnel)")
	errMTU           = errors.New("MTU must be between 1280 and 1500")
	errEndpoint      = errors.New("invalid Peer Endpoint")
	errEndpointPort  = errors.New("invalid Peer Endpoint port")
	errAllowedIPs    = errors.New("invalid AllowedIPs")
	errNoIPv4Default = errors.New("AllowedIPs must include 0.0.0.0/0 (full tunnel)")
	errIPv6Default   = errors.New("an IPv6 Interface Address needs ::/0 in AllowedIPs")
	errKeepalive     = errors.New("invalid PersistentKeepalive")
	errTooLarge      = errors.New("profile is too large")
)

const maxProfileBytes = 64 * 1024

var allowedFields = map[string]bool{
	"[interface]privatekey": true, "[interface]address": true, "[interface]dns": true,
	"[interface]mtu": true, "[interface]listenport": true,
	"[peer]publickey": true, "[peer]presharedkey": true, "[peer]endpoint": true,
	"[peer]allowedips": true, "[peer]persistentkeepalive": true,
}

var scriptFields = map[string]bool{"preup": true, "postup": true, "predown": true, "postdown": true}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func decodeKey(value string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(b) != 32 {
		return "", errKey
	}
	return hex.EncodeToString(b), nil
}

// ParseProfile validates a standard WireGuard configuration.
func ParseProfile(text string) (*Profile, error) {
	if len(text) > maxProfileBytes {
		return nil, errTooLarge
	}
	p := &Profile{MTU: 1280}
	fields := map[string]string{}
	section := ""
	peers := 0
	scanner := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(text, "\ufeff")))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.ReplaceAll(line, " ", ""))
			switch section {
			case "[interface]":
			case "[peer]":
				peers++
			default:
				return nil, errSection
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return nil, errFormat
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if scriptFields[key] {
			return nil, errScript
		}
		full := section + key
		if !allowedFields[full] {
			return nil, errField
		}
		if section == "[peer]" && peers > 1 {
			return nil, errPeerCount
		}
		if _, exists := fields[full]; exists {
			return nil, errDuplicate
		}
		fields[full] = value
	}
	if scanner.Err() != nil {
		return nil, errFormat
	}
	if peers != 1 {
		return nil, errPeerCount
	}

	var err error
	if p.privateKeyHex, err = decodeKey(fields["[interface]privatekey"]); err != nil {
		return nil, err
	}
	if p.publicKeyHex, err = decodeKey(fields["[peer]publickey"]); err != nil {
		return nil, err
	}
	if v := fields["[peer]presharedkey"]; v != "" {
		if p.pskHex, err = decodeKey(v); err != nil {
			return nil, err
		}
		p.HasPSK = true
	}

	for _, part := range splitList(fields["[interface]address"]) {
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			addr, err2 := netip.ParseAddr(part)
			if err2 != nil {
				return nil, errAddress
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		p.Addresses = append(p.Addresses, prefix.Addr().Unmap())
	}
	if len(p.Addresses) == 0 {
		return nil, errNoAddress
	}

	// wg-quick treats non-IP DNS entries as search domains. They are not needed
	// for an app-local resolver, so they are ignored; at least one IP is required
	// because every lookup is sent to these servers through the tunnel.
	for _, part := range splitList(fields["[interface]dns"]) {
		if addr, err := netip.ParseAddr(part); err == nil {
			p.DNS = append(p.DNS, addr.Unmap())
		}
	}
	if len(p.DNS) == 0 {
		return nil, errDNSMissing
	}

	if v := fields["[interface]mtu"]; v != "" {
		mtu, err := strconv.Atoi(v)
		if err != nil || mtu < 1280 || mtu > 1500 {
			return nil, errMTU
		}
		p.MTU = mtu
	}

	host, port, err := net.SplitHostPort(fields["[peer]endpoint"])
	if err != nil || host == "" {
		return nil, errEndpoint
	}
	p.EndpointPort, err = strconv.Atoi(port)
	if err != nil || p.EndpointPort < 1 || p.EndpointPort > 65535 {
		return nil, errEndpointPort
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		p.EndpointHost = addr.Unmap().String()
	} else if isHostname(host) {
		p.EndpointHost = strings.ToLower(host)
	} else {
		return nil, errEndpoint
	}

	ipv4Default, ipv6Default := false, false
	for _, part := range splitList(fields["[peer]allowedips"]) {
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, errAllowedIPs
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			if prefix.Addr().Is4() {
				ipv4Default = true
			} else {
				ipv6Default = true
			}
		}
		p.AllowedIPs = append(p.AllowedIPs, prefix)
	}
	if !ipv4Default {
		return nil, errNoIPv4Default
	}
	for _, addr := range p.Addresses {
		if addr.Is6() && !ipv6Default {
			return nil, errIPv6Default
		}
	}

	if v := fields["[peer]persistentkeepalive"]; v != "" && !strings.EqualFold(v, "off") {
		seconds, err := strconv.Atoi(v)
		if err != nil || seconds < 0 || seconds > 65535 {
			return nil, errKeepalive
		}
		p.Keepalive = seconds
	}
	return p, nil
}

func isHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// HasIPv4/HasIPv6 report the address families configured on the tunnel.
func (p *Profile) HasIPv4() bool {
	for _, a := range p.Addresses {
		if a.Is4() {
			return true
		}
	}
	return false
}

func (p *Profile) HasIPv6() bool {
	for _, a := range p.Addresses {
		if a.Is6() {
			return true
		}
	}
	return false
}

// uapi builds the wireguard-go configuration. endpoint must be numeric.
func (p *Profile) uapi(endpoint netip.AddrPort) string {
	var b strings.Builder
	b.WriteString("private_key=" + p.privateKeyHex + "\n")
	b.WriteString("replace_peers=true\n")
	b.WriteString("public_key=" + p.publicKeyHex + "\n")
	if p.pskHex != "" {
		b.WriteString("preshared_key=" + p.pskHex + "\n")
	}
	b.WriteString("endpoint=" + endpoint.String() + "\n")
	if p.Keepalive > 0 {
		b.WriteString("persistent_keepalive_interval=" + strconv.Itoa(p.Keepalive) + "\n")
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, prefix := range p.AllowedIPs {
		b.WriteString("allowed_ip=" + prefix.String() + "\n")
	}
	return b.String()
}

// Summary returns only non-secret profile facts for the settings screen.
// Keys (private, public, preshared) are never included.
func (p *Profile) Summary() map[string]any {
	addrs := make([]string, 0, len(p.Addresses))
	for _, a := range p.Addresses {
		addrs = append(addrs, a.String())
	}
	dns := make([]string, 0, len(p.DNS))
	for _, a := range p.DNS {
		dns = append(dns, a.String())
	}
	allowed := make([]string, 0, len(p.AllowedIPs))
	for _, a := range p.AllowedIPs {
		allowed = append(allowed, a.String())
	}
	_, numeric := netip.ParseAddr(p.EndpointHost)
	return map[string]any{
		"addresses":        addrs,
		"dns":              dns,
		"mtu":              p.MTU,
		"endpoint":         net.JoinHostPort(p.EndpointHost, strconv.Itoa(p.EndpointPort)),
		"endpointHostname": numeric != nil,
		"allowedIPs":       allowed,
		"keepalive":        p.Keepalive,
		"presharedKey":     p.HasPSK,
		"ipv6":             p.HasIPv6(),
	}
}
