#import <Foundation/Foundation.h>

// App-local WireGuard for Spotify.
//
// No system VPN, Network Extension, TUN interface or route change is used.
// wireguard-go + gVisor netstack run inside this process; an authenticated
// SOCKS5 server on 127.0.0.1 is applied to every NSURLSession configuration via
// nw_proxy_config (iOS 17+) with failover to direct connections disabled.

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SGWGState) {
    SGWGStateOff = 0,          // disabled in settings for this launch
    SGWGStateUnsupported,      // iOS < 17 or proxy API missing
    SGWGStateWaitingProfile,   // enabled; profile not readable yet (Keychain locked)
    SGWGStateStarting,
    SGWGStateRunning,
    SGWGStateFailed,           // engine failed; traffic is blocked, not sent direct
    SGWGStateExternalProxy,    // HTTP / HTTPS / SOCKS5 proxy server applied
    SGWGStateBlocked,          // enabled but the configuration is unusable: traffic blocked
};

// Connection kinds. WireGuard runs in-app; the others use an external proxy server.
FOUNDATION_EXPORT NSString *const SGWGKindWireGuard; // "wireguard"
FOUNDATION_EXPORT NSString *const SGWGKindHTTP;      // "http"   HTTP CONNECT
FOUNDATION_EXPORT NSString *const SGWGKindHTTPS;     // "https"  HTTP CONNECT over TLS to the proxy
FOUNDATION_EXPORT NSString *const SGWGKindSOCKS5;    // "socks5"

FOUNDATION_EXPORT NSString *const SGWGVersion;

// Settings (take effect on next launch).
BOOL SGWGSettingEnabled(void);
void SGWGSetSettingEnabled(BOOL enabled);
NSString *SGWGSettingKind(void);
NSDictionary *SGWGSettingExternalProxy(void); // host, port, username (no password)
BOOL SGWGHasStoredProxyPassword(void);
// Validates and saves the connection kind (and server fields for external
// kinds). password == nil keeps the stored password.
BOOL SGWGSaveConnection(NSString *kind, NSString *_Nullable host, NSString *_Nullable port,
                          NSString *_Nullable username, NSString *_Nullable password, NSString *_Nullable *_Nullable reason);
NSString *SGWGActiveKind(void); // kind applied in this launch, or @"" when inactive

BOOL SGWGIsSupportedOS(void);
SGWGState SGWGCurrentState(void);
BOOL SGWGActiveThisLaunch(void);
NSString *SGWGStateDescription(SGWGState state);

// Profile (Keychain, this device only). Summaries never contain keys.
BOOL SGWGHasProfile(void);
NSDictionary *_Nullable SGWGInspectProfile(NSString *text, NSString *_Nullable *_Nullable reason);
BOOL SGWGImportProfile(NSString *text, NSString *_Nullable *_Nullable reason);
BOOL SGWGDeleteProfile(NSString *_Nullable *_Nullable reason);
NSDictionary *_Nullable SGWGStoredProfileSummary(void);

// Engine.
NSDictionary *SGWGEngineStatus(void);
void SGWGLookupInTunnel(NSString *host, void (^completion)(NSDictionary *result));
void SGWGRequestRebind(NSString *reason);

// A session that goes through the tunnel (used by diagnostics). Returns nil
// when the tunnel is not active in this launch.
NSURLSession *_Nullable SGWGTunnelSession(id<NSURLSessionDelegate> _Nullable delegate);

// Counters of proxy application, for diagnostics.
NSDictionary *SGWGProxyCounters(void);

// Text helpers. Diagnostics are always passed through SGWGRedact.
NSString *SGWGRedactText(NSString *text);
NSString *SGWGDiagnosticsReport(NSDictionary<NSString *, NSString *> *_Nullable checks);

// Implemented in SGWGTransport.m.
void SGWGInstallTransportPatches(void);
NSArray<NSString *> *SGWGTransportReportLines(void);
NSArray<NSString *> *SGWGScanTransportClasses(void);

// Implemented in SGWGCore.m; used by SGWGTransport.m.
NSString *SGWGAppVersion(void);
NSString *SGWGHostCategory(NSString *_Nullable host);

NS_ASSUME_NONNULL_END
