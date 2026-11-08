package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// C ABI used by tweak/Sources/Shared/WireGuard (SGWGBridge.h). Every returned
// string is allocated with malloc and must be released with SGWGFree. Returned
// JSON never contains key material, endpoint addresses, hostnames or URLs
// (except SGWGInspect, which returns the non-secret profile summary for the UI).
//
// None of these may be called from an image constructor: the Go runtime of
// this archive initializes after them and the call would wait for it.

var (
	bridgeMu  sync.Mutex
	current   *Engine
	lastError string
)

func cString(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		return C.CString(`{"ok":false,"error":"internal error"}`)
	}
	return C.CString(string(b))
}

func engine() *Engine {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	return current
}

//export SGWGInspect
func SGWGInspect(text *C.char) *C.char {
	p, err := ParseProfile(C.GoString(text))
	if err != nil {
		return cString(map[string]any{"ok": false, "error": err.Error()})
	}
	summary := p.Summary()
	summary["ok"] = true
	return cString(summary)
}

// SGWGOpen starts the engine's local proxy, with no upstream yet, once per
// process. listenerFD is a listening TCP socket on 127.0.0.1 the tweak made in
// its constructor (so URLSession hooks know the port before Go runs); when it
// is negative the engine listens on 127.0.0.1:port itself. Returns the port,
// or -1.
//
//export SGWGOpen
func SGWGOpen(user, pass *C.char, listenerFD C.int, port C.int) C.int {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	var listener net.Listener
	if listenerFD >= 0 {
		file := os.NewFile(uintptr(listenerFD), "vitrine-wireguard-local-proxy")
		l, err := net.FileListener(file)
		file.Close()
		if err != nil {
			lastError = "local proxy descriptor initialization failed"
			return -1
		}
		listener = l
	}
	if current != nil {
		if listener != nil {
			listener.Close()
		}
		return C.int(current.Port())
	}
	e, err := NewEngine(C.GoString(user), C.GoString(pass), EngineOptions{Listener: listener, Port: int(port)})
	if err != nil {
		if listener != nil {
			listener.Close()
		}
		lastError = err.Error()
		return -1
	}
	current, lastError = e, ""
	return C.int(e.Port())
}

func attachResult(err error) C.int {
	if err != nil {
		bridgeMu.Lock()
		lastError = err.Error()
		bridgeMu.Unlock()
		return -1
	}
	return 0
}

// SGWGAttachWireGuard brings the tunnel up from a .conf and makes it the
// upstream. 0 on success; on failure the engine refuses every connection.
//
//export SGWGAttachWireGuard
func SGWGAttachWireGuard(text *C.char) C.int {
	e := engine()
	if e == nil {
		return -1
	}
	p, err := ParseProfile(C.GoString(text))
	if err != nil {
		e.Fail(err.Error())
		return attachResult(err)
	}
	return attachResult(e.AttachWireGuard(p, nil))
}

// SGWGAttachExternal makes an HTTP, HTTPS or SOCKS5 proxy server the upstream.
//
//export SGWGAttachExternal
func SGWGAttachExternal(kind, host *C.char, port C.int, user, pass *C.char) C.int {
	e := engine()
	if e == nil {
		return -1
	}
	return attachResult(e.AttachExternal(ExternalConfig{
		Kind: C.GoString(kind), Host: C.GoString(host), Port: int(port),
		Username: C.GoString(user), Password: C.GoString(pass),
	}))
}

// SGWGFail refuses every connection from now on (configuration unusable).
//
//export SGWGFail
func SGWGFail(reason *C.char) {
	if e := engine(); e != nil {
		e.Fail(C.GoString(reason))
	}
}

// SGWGForward opens a one-shot loopback forwarder to host:port and returns
// its port, or -1. host is a hostname or a numeric address.
//
//export SGWGForward
func SGWGForward(host *C.char, port C.int, ipv6 C.int) C.int {
	e := engine()
	if e == nil {
		return -1
	}
	p, err := e.Forward(C.GoString(host), int(port), ipv6 != 0)
	if err != nil {
		return -1
	}
	return C.int(p)
}

// SGWGExpectPeer names the local port of the socket the forwarder on
// listenPort accepts. 0 on success.
//
//export SGWGExpectPeer
func SGWGExpectPeer(listenPort, clientPort C.int) C.int {
	if e := engine(); e != nil && e.ExpectPeer(int(listenPort), int(clientPort)) {
		return 0
	}
	return -1
}

//export SGWGStatus
func SGWGStatus() *C.char {
	bridgeMu.Lock()
	e, msg := current, lastError
	bridgeMu.Unlock()
	if e == nil {
		return cString(map[string]any{"running": false, "error": msg})
	}
	st := e.Status()
	if msg != "" {
		st["error"] = msg
	}
	return cString(st)
}

//export SGWGRebind
func SGWGRebind() C.int {
	e := engine()
	if e == nil {
		return -1
	}
	if e.Rebind() != nil {
		return 1
	}
	return 0
}

//export SGWGLookup
func SGWGLookup(host *C.char) *C.char {
	e := engine()
	if e == nil {
		return cString(map[string]any{"ok": false, "error": "engine not running"})
	}
	name := strings.TrimSpace(C.GoString(host))
	if !isHostname(name) {
		return cString(map[string]any{"ok": false, "error": "invalid hostname"})
	}
	count, elapsed, err := e.Lookup(name, 8*time.Second)
	out := map[string]any{"ok": err == nil && count > 0, "count": count, "ms": elapsed.Milliseconds()}
	if err != nil {
		// net.DNSError text contains the name and server; report only its kind.
		kind := "failed"
		if err == errNotReady {
			kind = "not a WireGuard tunnel"
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			kind = "timeout"
		} else if de, ok := err.(*net.DNSError); ok && de.IsNotFound {
			kind = "not found"
		}
		out["error"] = kind
	}
	return cString(out)
}

//export SGWGRedact
func SGWGRedact(text *C.char) *C.char {
	return C.CString(Redact(C.GoString(text)))
}

//export SGWGFree
func SGWGFree(p *C.char) { C.free(unsafe.Pointer(p)) }

// main is required by -buildmode=c-archive and is never called.
func main() {}
