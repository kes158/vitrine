// What the files of Shared/WireGuard share and nothing else imports. SGWireGuard.h is the feature's face.
#import <Foundation/Foundation.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import "SGWireGuard.h"

// The launch, from WireGuard.x's %ctor: reads the switch, reserves the loopback port and installs the hooks.
void SGWireGuardLaunch(void);

#if SG_WIREGUARD

// The C ABI of vendor/wireguard/bridge.go (libsgwg.a). Every returned string is malloc'ed by Go and freed
// with SGWGFree. None may be called from a constructor: the Go runtime starts after them.
char *SGWGInspect(char *text);
int SGWGOpen(char *user, char *pass, int listenerFD, int port);
int SGWGAttachWireGuard(char *text);
int SGWGAttachExternal(char *kind, char *host, int port, char *user, char *pass);
void SGWGFail(char *reason);
int SGWGForward(char *host, int port, int ipv6);
int SGWGExpectPeer(int listenPort, int clientPort);
char *SGWGStatus(void);
int SGWGRebind(void);
char *SGWGLookup(char *host);
char *SGWGRedact(char *text);
void SGWGFree(char *p);

// The engine's local proxy for this launch, opened on the first call (from any thread but a constructor).
// NO when it could not be: every connection is then refused.
BOOL SGWGEnsureOpen(void);
// The loopback SOCKS5 server's port and this launch's credentials for it.
int SGWGProxyPort(void);
const char *SGWGProxyUser(void);
const char *SGWGProxyPassword(void);

// An nw_proxy_config_t (iOS 17) for the loopback SOCKS5 server, direct failover off; nil when the
// API is missing, which the callers treat as "refuse".
id SGWGCreateProxyConfig(void);

// Installed once from the launch, before Spotify has run (WGURLSession.x, WGSockets.m).
void SGWGInstallSessionHooks(void);
void SGWGInstallSocketHooks(void);
// Points a configuration at the loopback SOCKS5 server, or makes every request on it fail when that
// cannot be done (WGURLSession.x).
void SGWGApplyProxy(NSURLSessionConfiguration *configuration);

// Destinations that stay on the local network and are connected directly: link-local, multicast,
// broadcast, loopback, and the subnets of the device's own interfaces (never a VPN's). Fake addresses
// (below) are never local.
BOOL SGWGAddressIsLocal(const struct sockaddr *address);
BOOL SGWGHostIsLocal(const char *host);

// The names Spotify looks up are answered with addresses of 198.18.0.0/15 (RFC 2544, never routed), one
// per name, so the name is only ever resolved at the other end: the tunnel's DNS or the proxy server.
// Returns NO when the address is not one handed out; `host` gets the name.
BOOL SGWGFakeAddressHost(const struct sockaddr *address, char *host, size_t size);

// Counters the socket hooks keep for the report.
NSDictionary<NSString *, NSNumber *> *SGWGSocketCounters(void);
NSDictionary<NSString *, NSNumber *> *SGWGSessionCounters(void);

#endif
