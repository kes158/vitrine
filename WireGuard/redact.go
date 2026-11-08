package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Redact is the last pass over any diagnostics text before it is shown or
// copied. The diagnostics are built from counters and fixed labels, so this is
// defence in depth: it removes anything shaped like a key, credential, token,
// URL (including signed media URLs) or a full IP address.
var redactRules = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,15}://[^\s"'<>]+`), "[URL]"},
	{regexp.MustCompile(`[^\s"'<>]*\?[^\s"'<>]*=[^\s"'<>]*`), "[URL]"},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`), "$1 [REDACTED]"},
	{regexp.MustCompile(`[A-Za-z0-9+/]{43}=`), "[KEY]"},
	{regexp.MustCompile(`\b[0-9A-Fa-f]{64}\b`), "[KEY]"},
	{regexp.MustCompile(`\b[0-9A-Fa-f]{32}\b`), "[SECRET]"},
	{regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`), "[EMAIL]"},
	{regexp.MustCompile(`(?i)\b(private_?key|preshared_?key|password|token|secret|cookie|authorization)\s*[:=]\s*\S+`), "$1=[REDACTED]"},
}

var (
	ipv4Pattern = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	ipv6Pattern = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
)

func Redact(text string) string {
	for _, rule := range redactRules {
		text = rule.re.ReplaceAllString(text, rule.repl)
	}
	text = ipv4Pattern.ReplaceAllStringFunc(text, func(s string) string {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is4() {
			return s
		}
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.x", b[0], b[1], b[2])
	})
	text = ipv6Pattern.ReplaceAllStringFunc(text, func(s string) string {
		if strings.Count(s, ":") < 2 {
			return s
		}
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is6() {
			return s
		}
		b := addr.As16()
		return netip.AddrFrom16([16]byte{b[0], b[1], b[2], b[3]}).String() + "/32(masked)"
	})
	return text
}
