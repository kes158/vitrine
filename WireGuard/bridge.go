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

// C ABI used by Source/WireGuard/SGWGCore.m. Every returned string is
// allocated with malloc and must be released with SGWGFree. Returned JSON
// never contains key material, endpoint addresses, hostnames or URLs (except
// SGWGInspect, which returns the non-secret profile summary for the UI).

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

// SGWGStart starts the engine once per process. listenerFD is a listening
// TCP socket on 127.0.0.1 created synchronously by Objective-C (so the port is
// known before the Go runtime is ready); if it is negative the engine listens
// on 127.0.0.1:port itself. Returns the local port, or -1 on failure.
//
//export SGWGStart
func SGWGStart(text, user, pass *C.char, listenerFD C.int, port C.int) C.int {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	var listener net.Listener
	if listenerFD >= 0 {
		file := os.NewFile(uintptr(listenerFD), "ytmu-wireguard-local-proxy")
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
	p, err := ParseProfile(C.GoString(text))
	if err != nil {
		if listener != nil {
			listener.Close()
		}
		lastError = err.Error()
		return -1
	}
	e, err := StartEngine(p, C.GoString(user), C.GoString(pass), EngineOptions{Listener: listener, Port: int(port)})
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

//export SGWGStatus
func SGWGStatus() *C.char {
	bridgeMu.Lock()
	e, msg := current, lastError
	bridgeMu.Unlock()
	if e == nil {
		return cString(map[string]any{"running": false, "error": msg})
	}
	return cString(e.Status())
}

//export SGWGRebind
func SGWGRebind() C.int {
	bridgeMu.Lock()
	e := current
	bridgeMu.Unlock()
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
	bridgeMu.Lock()
	e := current
	bridgeMu.Unlock()
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
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
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
