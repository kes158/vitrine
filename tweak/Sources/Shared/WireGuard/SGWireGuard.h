// App-local WireGuard and proxy (docs/wireguard.md): Spotify's connections, the core's own sockets
// included, leave through a WireGuard tunnel that runs inside the app, or through an HTTP, HTTPS or SOCKS5
// proxy server, with no system VPN, Network Extension or route change. Built only with WIREGUARD=1
// (tweak/Makefile, SG_WIREGUARD); the default build has no engine and no page for it.
//
//   vendor/wireguard/     the Go engine: wireguard-go on a gVisor netstack, or a proxy client, behind an
//                         authenticated loopback SOCKS5 server and one-shot loopback forwarders
//   SGWGCore.m            settings, the profile in the Keychain, the engine's start and its diagnostics
//   WGURLSession.x        every NSURLSession configuration pointed at the loopback SOCKS5 server with
//                         nw_proxy_config, direct failover off (iOS 17)
//   WGSockets.m           Spotify's own imports of getaddrinfo, connect, getpeername, sendto, sendmsg,
//                         CFStreamCreatePairWithSocketToHost, CFNetwork's proxy lookups and
//                         nw_connection_create, rebound (Core/SGRebind.h) so the core's access point and
//                         HTTP connections and Ably's websocket go the same way
//   WireGuardSettings.m   the page, under Premium, ads & privacy
//
// Read at launch: a change needs a restart. With it on and the tunnel not up, connections fail rather
// than go out directly. Addresses on the local network (Spotify Connect, Cast, AirPlay) stay direct.
#import <UIKit/UIKit.h>

#ifndef SG_WIREGUARD
#define SG_WIREGUARD 0
#endif

#define SGKeyWireGuard @"spotifyglass.wireguard"
#define SGKeyWireGuardKind @"spotifyglass.wireguard.kind"
#define SGKeyWireGuardHost @"spotifyglass.wireguard.host"
#define SGKeyWireGuardPort @"spotifyglass.wireguard.port"
#define SGKeyWireGuardUser @"spotifyglass.wireguard.username"

typedef NS_ENUM(NSInteger, SGWGState) {
    SGWGStateOff = 0,          // switched off, or not in this build
    SGWGStateUnsupported,      // iOS below 17, or the proxy API missing
    SGWGStateWaitingProfile,   // on; the profile is not readable yet (Keychain locked before first unlock)
    SGWGStateStarting,
    SGWGStateRunning,          // WireGuard up, or a proxy server attached
    SGWGStateFailed,           // the engine failed: connections are refused, never sent directly
};

// The connection kinds: WireGuard runs in the app, the others hand connections to a proxy server.
typedef NS_ENUM(NSInteger, SGWGKind) {
    SGWGKindWireGuard = 0,
    SGWGKindHTTP,     // HTTP CONNECT
    SGWGKindHTTPS,    // HTTP CONNECT over TLS to the proxy, checked against the system's trust store
    SGWGKindSOCKS5,
};

// YES when this build carries the engine (WIREGUARD=1).
BOOL SGWireGuardBuilt(void);
// iOS 17 and the nw_proxy_config functions URLSession needs.
BOOL SGWireGuardSupportedOS(void);

// The stored settings, read at the next launch.
BOOL SGWireGuardEnabled(void);
void SGWireGuardSetEnabled(BOOL on);
SGWGKind SGWireGuardKind(void);
NSString *SGWireGuardKindName(SGWGKind kind);
// The proxy server's host, port and user name (the password is in the Keychain).
NSString *SGWireGuardProxyHost(void);
NSString *SGWireGuardProxyPort(void);
NSString *SGWireGuardProxyUser(void);
BOOL SGWireGuardHasProxyPassword(void);
// Checks and stores a connection kind; for a proxy kind its server too. password nil keeps the stored one,
// empty removes it. On failure `reason` says why in words for the page.
BOOL SGWireGuardSaveConnection(SGWGKind kind, NSString *host, NSString *port, NSString *username, NSString *password, NSString **reason);

// The WireGuard profile, kept in the Keychain on this device only. The summary never holds a key.
BOOL SGWireGuardHasProfile(void);
NSDictionary *SGWireGuardInspectProfile(NSString *text, NSString **reason);
BOOL SGWireGuardImportProfile(NSString *text, NSString **reason);
BOOL SGWireGuardDeleteProfile(NSString **reason);
NSDictionary *SGWireGuardProfileSummary(void);

// This launch.
SGWGState SGWireGuardState(void);
BOOL SGWireGuardActive(void);   // the hooks are in place: everything goes through the engine or fails
NSString *SGWireGuardStateText(void);
NSDictionary *SGWireGuardEngineStatus(void);
// Looks a name up through the tunnel's DNS; the result comes back on main.
void SGWireGuardLookup(NSString *host, void (^completion)(NSDictionary *result));
// A session whose requests go through the engine, for the page's checks; nil when inactive.
NSURLSession *SGWireGuardSession(void);
// Counters, redacted text and the report the page copies.
NSString *SGWireGuardReport(NSDictionary<NSString *, NSString *> *checks);

@class SGModSection;
// The row that opens the page, for Premium, ads & privacy; nil in a build without the engine.
SGModSection *SGWireGuardSection(void);
UIViewController *SGWireGuardSettingsPage(void);
