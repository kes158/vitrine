#!/usr/bin/env python3
"""Run the app-local WireGuard core against Apple's real NSURLSession on macOS.

Builds the Go engine for macOS, the test WireGuard peer and the Objective-C
harness, then checks (with freshly generated test keys only):

* NSURLSession -> authenticated SOCKS5 (nw_proxy_config, failover disabled)
  -> Go engine -> WireGuard handshake -> peer: HTTPS, HTTP 206, tunnel DNS
* no direct fallback: a host reachable directly but not through the tunnel
  is never contacted, also when the WireGuard peer is dead
* Spotify delegate observers against fixtures matching the 9.1.90 selectors
* diagnostics contain no private key, signed URL, host or address

Usage: python3 harness/wireguard/run_macos.py [--out results.json]
"""
import argparse
import base64
import http.server
import select
import socketserver
import ssl
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
WG = ROOT / "WireGuard"


def sh(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run(cmd, check=True, **kw)


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") else ip
    except OSError:
        return None
    finally:
        s.close()


class DirectHandler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        DirectHandler.hits += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"direct")

    def log_message(self, *args):
        pass


def exact(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise EOFError
        data += part
    return data


class Origin(http.server.BaseHTTPRequestHandler):
    hits = 0
    body = b"external-proxy-range-fixture"

    def do_GET(self):
        Origin.hits += 1
        if self.headers.get("Range") == "bytes=0-9":
            self.send_response(206)
            self.send_header("Content-Range", f"bytes 0-9/{len(self.body)}")
            self.send_header("Content-Length", "10")
            self.end_headers()
            self.wfile.write(self.body[:10])
        else:
            self.send_response(200)
            self.send_header("Content-Length", str(len(self.body)))
            self.end_headers()
            self.wfile.write(self.body)

    def log_message(self, *args):
        pass


class FixtureProxy(socketserver.ThreadingTCPServer):
    """HTTP CONNECT or SOCKS5 proxy that maps fixture.invalid to 127.0.0.1."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, kind, user, password, tls=None):
        super().__init__(("127.0.0.1", 0), ProxyHandler)
        self.kind, self.user, self.password, self.hits = kind, user, password, 0
        if tls:
            self.socket = tls.wrap_socket(self.socket, server_side=True)


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s, srv = self.request, self.server
        s.settimeout(8)
        try:
            if srv.kind == "socks5":
                _, count = exact(s, 2)
                methods = exact(s, count)
                need = 2 if srv.user else 0
                if need not in methods:
                    s.sendall(b"\x05\xff")
                    return
                s.sendall(bytes([5, need]))
                if need:
                    exact(s, 1)
                    user = exact(s, exact(s, 1)[0])
                    password = exact(s, exact(s, 1)[0])
                    ok = user == srv.user.encode() and password == srv.password.encode()
                    s.sendall(bytes([1, 0 if ok else 1]))
                    if not ok:
                        return
                _, cmd, _, atyp = exact(s, 4)
                assert cmd == 1
                if atyp == 3:
                    host = exact(s, exact(s, 1)[0]).decode()
                elif atyp == 1:
                    host = socket.inet_ntoa(exact(s, 4))
                else:
                    host = socket.inet_ntop(socket.AF_INET6, exact(s, 16))
                port = int.from_bytes(exact(s, 2), "big")
                if host != "fixture.invalid":
                    s.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)
                    return
                upstream = socket.create_connection(("127.0.0.1", port), 5)
                s.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            else:
                header = b""
                while not header.endswith(b"\r\n\r\n"):
                    header += exact(s, 1)
                method, target, _ = header.split(b"\r\n")[0].decode().split(" ", 2)
                assert method == "CONNECT"
                if srv.user:
                    token = base64.b64encode(f"{srv.user}:{srv.password}".encode()).decode()
                    if f"proxy-authorization: basic {token}".lower() not in header.decode().lower():
                        s.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="fixture"\r\n'
                                  b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                        return
                host, port = target.rsplit(":", 1)
                if host != "fixture.invalid":
                    s.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    return
                upstream = socket.create_connection(("127.0.0.1", int(port)), 5)
                s.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            srv.hits += 1
            with upstream:
                while True:
                    ready, _, _ = select.select([s, upstream], [], [], 8)
                    if not ready:
                        return
                    for src in ready:
                        data = src.recv(65536)
                        if not data:
                            return
                        (upstream if src is s else s).sendall(data)
        except (OSError, EOFError, AssertionError, ValueError, ssl.SSLError):
            pass


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def external_proxy_tests(harness, tmp, results):
    cert, key, der = tmp / "origin.pem", tmp / "origin.key", tmp / "origin.der"
    sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", str(key), "-out", str(cert),
        "-subj", "/CN=fixture.invalid", "-addext", "subjectAltName=DNS:fixture.invalid",
        "-addext", "extendedKeyUsage=serverAuth", "-addext", "keyUsage=digitalSignature,keyEncipherment", "-sha256"],
       capture_output=True)
    sh(["openssl", "x509", "-in", str(cert), "-outform", "DER", "-out", str(der)])
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin.socket = tls.wrap_socket(origin.socket, server_side=True)
    serve(origin)
    url = f"https://fixture.invalid:{origin.server_port}/media"
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    cases = [
        ("http", "u-fixture", "p-fixture", "p-fixture", None, True, "HTTP CONNECT with Basic auth (407 challenge)"),
        ("http", "", "", "", None, True, "HTTP CONNECT without auth"),
        ("socks5", "u-fixture", "p-fixture", "p-fixture", None, True, "SOCKS5 with user/password"),
        ("socks5", "u-fixture", "p-fixture", "wrong", None, False, "SOCKS5 wrong password"),
        ("https", "", "", "", tls, False, "HTTPS proxy with untrusted certificate"),
        ("http", "", "", "", "closed", False, "unreachable HTTP proxy"),
    ]
    for kind, user, server_pass, client_pass, extra, ok, name in cases:
        proxy = None
        if extra == "closed":
            port = closed_port
        else:
            proxy = serve(FixtureProxy("socks5" if kind == "socks5" else "http", user, server_pass,
                                       tls=extra if kind == "https" else None))
            port = proxy.server_address[1]
        before = Origin.hits
        env = dict(os.environ, SGWG_TEST_ENABLED="1", SGWG_TEST_KIND=kind, SGWG_TEST_HOST="127.0.0.1",
                   SGWG_TEST_PORT=str(port), SGWG_TEST_USER=user, SGWG_TEST_PASS=client_pass,
                   SGWG_TEST_ORIGIN_URL=url, SGWG_TEST_CERT=str(der), SGWG_TEST_TRUST_SUFFIX="fixture.invalid",
                   SGWG_EXPECT_OK="1" if ok else "0")
        proc = subprocess.run([str(harness), "external"], env=env, capture_output=True, text=True, timeout=120)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            raise SystemExit(f"FAILED: external {name} (exit {proc.returncode})")
        if ok:
            assert Origin.hits > before and proxy.hits > 0, (name, Origin.hits, before)
        else:
            assert Origin.hits == before, f"{name}: origin was reached"
        if proxy:
            proxy.shutdown()
            proxy.server_close()
        results.append(f"external {kind}: {name} -> {'206 via proxy' if ok else 'blocked, origin not reached'}")
    origin.shutdown()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=pathlib.Path)
    parser.add_argument("--live-profile", type=pathlib.Path,
                        help="real WireGuard .conf: run only the live checks against that server")
    parser.add_argument("--expect-country", default="", help="expected exit country code for --live-profile")
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix="sgwg-") as tmp:
        tmp = pathlib.Path(tmp)
        env = dict(os.environ, CGO_ENABLED="1")
        sh(["go", "build", "-o", str(tmp / "testpeer"), "./cmd/sgwg-testpeer"], cwd=WG, env=env)
        sh(["go", "build", "-buildmode=c-archive", "-o", str(tmp / "libsgwg-macos.a"), "."], cwd=WG, env=env)
        harness = tmp / "harness"
        sh(["xcrun", "clang", "-fobjc-arc", "-fmodules", "-DSGWG_TESTING", "-mmacosx-version-min=14.0", "-Wall",
            "-I", str(ROOT / "tweak/Sources"),
            str(ROOT / "tweak/Sources/Shared/WireGuard/SGWGCore.m"), str(ROOT / "tweak/Sources/Shared/WireGuard/SGWGTransport.m"),
            str(ROOT / "tweak/Sources/Shared/WireGuard/SGWGNative.m"),
            str(ROOT / "harness/wireguard/harness.m"), str(tmp / "libsgwg-macos.a"),
            "-framework", "Foundation", "-framework", "Network", "-framework", "Security",
            "-framework", "CoreFoundation", "-lresolv", "-o", str(harness)])

        if args.live_profile:
            env_live = dict(os.environ, SGWG_TEST_ENABLED="1", SGWG_TEST_PROFILE=str(args.live_profile),
                            SGWG_EXPECT_COUNTRY=args.expect_country)
            proc = subprocess.run([str(harness), "live"], env=env_live, capture_output=True, text=True, timeout=300)
            sys.stdout.write(proc.stdout)
            sys.stderr.write(proc.stderr)
            if proc.returncode != 0:
                raise SystemExit(f"FAILED: live check (exit {proc.returncode})")
            return

        peer_dir = tmp / "peer"
        peer_dir.mkdir()
        peer = subprocess.Popen([str(tmp / "testpeer"), "-out", str(peer_dir)])
        try:
            for _ in range(100):
                if (peer_dir / "ready.json").exists():
                    break
                time.sleep(0.1)
            ready = json.loads((peer_dir / "ready.json").read_text())
            stats_url = f"http://127.0.0.1:{ready['statsPort']}/"

            def stats():
                with urllib.request.urlopen(stats_url, timeout=5) as r:
                    return json.load(r)

            direct = http.server.ThreadingHTTPServer(("0.0.0.0", 0), DirectHandler)
            threading.Thread(target=direct.serve_forever, daemon=True).start()
            ip = lan_ip()
            direct_url = f"http://{ip}:{direct.server_port}/direct" if ip else ""
            if not ip:
                print("NOTE no non-loopback IPv4 address; direct-fallback probe skipped", flush=True)

            base = dict(os.environ, SGWG_TEST_ENABLED="1", SGWG_TEST_PROFILE=str(peer_dir / "client.conf"),
                        SGWG_TEST_CERT=str(peer_dir / "fixture.der"), SGWG_TEST_DIRECT_URL=direct_url,
                        SGWG_TEST_APP_VERSION="9.1.90", SGWG_EXPECT_ACTIVE="1")

            def run(name, mode, **extra):
                proc = subprocess.run([str(harness), mode], env=dict(base, **extra), capture_output=True, text=True, timeout=180)
                sys.stdout.write(proc.stdout)
                sys.stderr.write(proc.stderr)
                if proc.returncode != 0:
                    raise SystemExit(f"FAILED: {name} (exit {proc.returncode})")
                results.append(name)
                return proc.stdout

            run("unit: Spotify delegates, ABI guards, proxy enforcement and redaction", "unit")
            run("unit: disabled -> no hooks", "unit", SGWG_TEST_ENABLED="0", SGWG_EXPECT_ACTIVE="0")

            before = stats()
            out = run("net: NSURLSession through WireGuard (HTTPS, 206, tunnel DNS, shared session, NSData)", "net")
            after = stats()
            assert after["dns"] > before["dns"], ("tunnel DNS not used", before, after)
            assert after["https"] > before["https"] and after["range"] > before["range"], (before, after)
            assert DirectHandler.hits == 0, "direct server was contacted"
            results.append(f"peer counters: dns +{after['dns'] - before['dns']}, https +{after['https'] - before['https']}, range +{after['range'] - before['range']}; direct hits 0")
            report = out[out.find("Vitrine app-local WireGuard diagnostics"):]

            # Dead peer: profile points at a UDP port nobody serves.
            dead = (peer_dir / "client.conf").read_text()
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.bind(("127.0.0.1", 0))
            dead_port = probe.getsockname()[1]
            probe.close()
            dead = "\n".join(f"Endpoint = 127.0.0.1:{dead_port}" if l.startswith("Endpoint = ") else l for l in dead.split("\n"))
            (tmp / "dead.conf").write_text(dead)
            run("failclosed: unreachable WireGuard peer, no direct fallback", "failclosed", SGWG_TEST_PROFILE=str(tmp / "dead.conf"))
            (tmp / "invalid.conf").write_text("[Interface]\nPrivateKey = invalid\n")
            run("failclosed: invalid profile -> engine failed, traffic blocked", "failclosed",
                SGWG_TEST_PROFILE=str(tmp / "invalid.conf"), SGWG_EXPECT_FAILED="1")
            run("failclosed: unusable external proxy configuration", "failclosed",
                SGWG_TEST_KIND="http", SGWG_TEST_HOST="", SGWG_TEST_PORT="0")
            assert DirectHandler.hits == 0, "direct server was contacted"
            external_proxy_tests(harness, tmp, results)
            direct.shutdown()
        finally:
            peer.terminate()
            peer.wait(timeout=10)

    summary = {
        "platform": f"macOS {subprocess.run(['sw_vers', '-productVersion'], capture_output=True, text=True).stdout.strip()} (Foundation + Network.framework, same proxy API as iOS 17+)",
        "passed": results,
        "diagnostics_sample": report,
        "not_covered": ["iPhone installation and UIKit settings screen", "real Spotify process and servers",
                        "music playback, next track, lock-screen playback", "Wi-Fi/cellular switching", "real WireGuard provider"],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if args.out:
        args.out.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
