// The feature's settings, the profile and proxy password in the Keychain, and the launch: per-launch
// credentials, the loopback port reserved before any hook can need it, the hooks, then the engine on a
// queue of its own (the Go runtime must not be entered from a constructor). SGWireGuard.h says what it is.
#import <Network/Network.h>
#import <Security/Security.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <os/lock.h>
#import <stdatomic.h>
#import <sys/utsname.h>
#import <unistd.h>
#import "Core/SGCore.h"
#import "SGWGInternal.h"

static NSString *const kKeychainService = @"spotifyglass.wireguard";
static NSString *const kProfileAccount = @"profile";
static NSString *const kProxyAccount = @"proxy-password";

#pragma mark - Settings (every build)

BOOL SGWireGuardBuilt(void) { return SG_WIREGUARD != 0; }

BOOL SGWireGuardEnabled(void) { return SGFlag(SGKeyWireGuard, NO); }
void SGWireGuardSetEnabled(BOOL on) { SGSetEnabled(SGKeyWireGuard, on); }

SGWGKind SGWireGuardKind(void) {
    NSInteger kind = SGInt(SGKeyWireGuardKind, SGWGKindWireGuard);
    return kind >= SGWGKindWireGuard && kind <= SGWGKindSOCKS5 ? (SGWGKind)kind : SGWGKindWireGuard;
}

NSString *SGWireGuardKindName(SGWGKind kind) {
    switch (kind) {
        case SGWGKindWireGuard: return @"WireGuard";
        case SGWGKindHTTP: return @"HTTP";
        case SGWGKindHTTPS: return @"HTTPS";
        case SGWGKindSOCKS5: return @"SOCKS5";
    }
    return @"WireGuard";
}

__attribute__((unused)) static NSString *kindWire(SGWGKind kind) {
    switch (kind) {
        case SGWGKindHTTP: return @"http";
        case SGWGKindHTTPS: return @"https";
        case SGWGKindSOCKS5: return @"socks5";
        default: return @"wireguard";
    }
}

static NSString *storedString(NSString *key) {
    id value = [NSUserDefaults.standardUserDefaults objectForKey:key];
    return [value isKindOfClass:NSString.class] ? value : @"";
}

NSString *SGWireGuardProxyHost(void) { return storedString(SGKeyWireGuardHost); }
NSString *SGWireGuardProxyPort(void) { return storedString(SGKeyWireGuardPort); }
NSString *SGWireGuardProxyUser(void) { return storedString(SGKeyWireGuardUser); }

#pragma mark - Keychain (this device only, never in backups)

static NSMutableDictionary *keychainQuery(NSString *account) {
    return [@{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
              (__bridge id)kSecAttrService: kKeychainService,
              (__bridge id)kSecAttrAccount: account} mutableCopy];
}

static OSStatus keychainWrite(NSString *account, NSData *data) {
    NSMutableDictionary *query = keychainQuery(account);
    NSDictionary *attributes = @{(__bridge id)kSecValueData: data,
                                 (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly};
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
        [query addEntriesFromDictionary:attributes];
        status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    }
    return status;
}

static NSString *keychainRead(NSString *account, OSStatus *outStatus) {
    NSMutableDictionary *query = keychainQuery(account);
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (outStatus) *outStatus = status;
    if (status != errSecSuccess || !result) return nil;
    return [[NSString alloc] initWithData:CFBridgingRelease(result) encoding:NSUTF8StringEncoding];
}

static OSStatus keychainDelete(NSString *account) {
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)keychainQuery(account));
    return status == errSecItemNotFound ? errSecSuccess : status;
}

BOOL SGWireGuardHasProxyPassword(void) { return keychainRead(kProxyAccount, NULL).length > 0; }
BOOL SGWireGuardHasProfile(void) { return keychainRead(kProfileAccount, NULL).length > 0; }

static NSString *keychainFailure(OSStatus status) {
    return [NSString stringWithFormat:SGL(@"settings.wireguard.error.keychain", @"The Keychain refused it (%d)."), (int)status];
}

#pragma mark - The proxy server

static BOOL validProxy(SGWGKind kind, NSString *host, NSString *port, NSString *user, NSString **reason) {
    NSString *failure = nil;
    NSCharacterSet *hostCharacters = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]"];
    if (kind == SGWGKindWireGuard) {
        failure = nil;
    } else if (!host.length || host.length > 253 || [host rangeOfCharacterFromSet:hostCharacters.invertedSet].location != NSNotFound) {
        failure = SGL(@"settings.wireguard.error.host", @"The server is a host name or an IP address alone, without http:// or a path.");
    } else if (!port.length || port.length > 5 || [port rangeOfCharacterFromSet:NSCharacterSet.decimalDigitCharacterSet.invertedSet].location != NSNotFound ||
               port.integerValue < 1 || port.integerValue > 65535) {
        failure = SGL(@"settings.wireguard.error.port", @"The port is a number from 1 to 65535.");
    } else if (user.length > 255 || [user rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@":\r\n"]].location != NSNotFound) {
        failure = SGL(@"settings.wireguard.error.user", @"The user name can't hold a colon or a line break.");
    }
    if (reason) *reason = failure;
    return failure == nil;
}

BOOL SGWireGuardSaveConnection(SGWGKind kind, NSString *host, NSString *port, NSString *username, NSString *password, NSString **reason) {
    if (kind == SGWGKindWireGuard) {
        if (!SGWireGuardHasProfile()) {
            if (reason) *reason = SGL(@"settings.wireguard.error.no_profile", @"Import a WireGuard .conf file first.");
            return NO;
        }
        SGSetInt(SGKeyWireGuardKind, kind);
        return YES;
    }
    NSCharacterSet *space = NSCharacterSet.whitespaceAndNewlineCharacterSet;
    host = [host ?: @"" stringByTrimmingCharactersInSet:space];
    port = [port ?: @"" stringByTrimmingCharactersInSet:space];
    username = username ?: @"";
    if (!validProxy(kind, host, port, username, reason)) return NO;
    if (password) {
        if (password.length > 255) {
            if (reason) *reason = SGL(@"settings.wireguard.error.password", @"The password is longer than 255 characters.");
            return NO;
        }
        OSStatus status = password.length ? keychainWrite(kProxyAccount, [password dataUsingEncoding:NSUTF8StringEncoding]) : keychainDelete(kProxyAccount);
        if (status != errSecSuccess) {
            if (reason) *reason = keychainFailure(status);
            return NO;
        }
    }
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    [defaults setObject:host forKey:SGKeyWireGuardHost];
    [defaults setObject:port forKey:SGKeyWireGuardPort];
    [defaults setObject:username forKey:SGKeyWireGuardUser];
    SGSetInt(SGKeyWireGuardKind, kind);
    return YES;
}

#pragma mark - State

static atomic_int sg_state = SGWGStateOff;
static BOOL sg_active;
static SGWGKind sg_kind;

SGWGState SGWireGuardState(void) { return (SGWGState)atomic_load(&sg_state); }
BOOL SGWireGuardActive(void) { return sg_active; }

NSString *SGWireGuardStateText(void) {
    switch (SGWireGuardState()) {
        case SGWGStateOff: return SGL(@"settings.wireguard.state.off", @"Off");
        case SGWGStateUnsupported: return SGL(@"settings.wireguard.state.unsupported", @"Needs iOS 17");
        case SGWGStateWaitingProfile: return SGL(@"settings.wireguard.state.waiting", @"Waiting for the Keychain");
        case SGWGStateStarting: return SGL(@"settings.wireguard.state.starting", @"Starting");
        case SGWGStateRunning: return sg_kind == SGWGKindWireGuard ? SGL(@"settings.wireguard.state.running", @"Connected")
                                                                   : SGL(@"settings.wireguard.state.proxy", @"Through the proxy");
        case SGWGStateFailed: return SGL(@"settings.wireguard.state.failed", @"Failed, connections blocked");
    }
    return @"";
}

#if SG_WIREGUARD

#pragma mark - The iOS 17 proxy API, looked up at run time

typedef void *(*SGWGCreateSocksFn)(void *endpoint);
typedef void (*SGWGSetUserPassFn)(void *config, const char *user, const char *pass);
typedef void (*SGWGSetFailoverFn)(void *config, bool allowed);
static SGWGCreateSocksFn sg_createSocks;
static SGWGSetUserPassFn sg_setUserPass;
static SGWGSetFailoverFn sg_setFailover;

BOOL SGWireGuardSupportedOS(void) {
    static BOOL supported;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // NSProcessInfo instead of @available: no compiler-rt dependency.
        if (![NSProcessInfo.processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){17, 0, 0}]) return;
        sg_createSocks = (SGWGCreateSocksFn)dlsym(RTLD_DEFAULT, "nw_proxy_config_create_socksv5");
        sg_setUserPass = (SGWGSetUserPassFn)dlsym(RTLD_DEFAULT, "nw_proxy_config_set_username_and_password");
        sg_setFailover = (SGWGSetFailoverFn)dlsym(RTLD_DEFAULT, "nw_proxy_config_set_failover_allowed");
        supported = sg_createSocks && sg_setUserPass && sg_setFailover &&
            [NSURLSessionConfiguration instancesRespondToSelector:NSSelectorFromString(@"setProxyConfigurations:")];
    });
    return supported;
}

static int sg_port = -1;            // the loopback SOCKS5 server, fixed for the launch
static int sg_listener = -1;        // reserved in the constructor, handed to Go on open
static char sg_user[33], sg_pass[33];
static dispatch_queue_t sg_queue;
static atomic_uint sg_rebinds;

int SGWGProxyPort(void) { return sg_port; }
const char *SGWGProxyUser(void) { return sg_user; }
const char *SGWGProxyPassword(void) { return sg_pass; }

id SGWGCreateProxyConfig(void) {
    if (!SGWireGuardSupportedOS() || sg_port <= 0) return nil;
    char port[8];
    snprintf(port, sizeof port, "%d", sg_port);
    nw_endpoint_t endpoint = nw_endpoint_create_host("127.0.0.1", port);
    if (!endpoint) return nil;
    id proxy = (__bridge_transfer id)sg_createSocks((__bridge void *)endpoint);
    if (!proxy) return nil;
    sg_setUserPass((__bridge void *)proxy, sg_user, sg_pass);
    sg_setFailover((__bridge void *)proxy, false);
    return proxy;
}

BOOL SGWGEnsureOpen(void) {
    static BOOL open;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        int fd = sg_listener;
        sg_listener = -1; // Go owns it from here
        open = SGWGOpen(sg_user, sg_pass, fd, sg_port) == sg_port;
        if (!open) SGLog(@"wireguard: the engine's local proxy did not open");
    });
    return open;
}

static NSDictionary *jsonFromGo(char *raw) {
    if (!raw) return nil;
    NSData *data = [NSData dataWithBytes:raw length:strlen(raw)];
    SGWGFree(raw);
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

#pragma mark - The profile

NSDictionary *SGWireGuardInspectProfile(NSString *text, NSString **reason) {
    NSDictionary *summary = jsonFromGo(SGWGInspect((char *)(text ?: @"").UTF8String));
    if (![summary[@"ok"] boolValue]) {
        // The engine's reasons are fixed English sentences that never hold a value of the profile.
        if (reason) *reason = [summary[@"error"] isKindOfClass:NSString.class] ? summary[@"error"]
                                                                              : SGL(@"settings.wireguard.error.profile", @"This is not a WireGuard configuration.");
        return nil;
    }
    return summary;
}

BOOL SGWireGuardImportProfile(NSString *text, NSString **reason) {
    if (!SGWireGuardInspectProfile(text, reason)) return NO;
    OSStatus status = keychainWrite(kProfileAccount, [text dataUsingEncoding:NSUTF8StringEncoding]);
    if (status != errSecSuccess) {
        if (reason) *reason = keychainFailure(status);
        return NO;
    }
    SGSetInt(SGKeyWireGuardKind, SGWGKindWireGuard);
    return YES;
}

NSDictionary *SGWireGuardProfileSummary(void) {
    NSString *text = keychainRead(kProfileAccount, NULL);
    return text ? SGWireGuardInspectProfile(text, NULL) : nil;
}

BOOL SGWireGuardDeleteProfile(NSString **reason) {
    OSStatus status = keychainDelete(kProfileAccount);
    if (status != errSecSuccess) {
        if (reason) *reason = keychainFailure(status);
        return NO;
    }
    if (SGWireGuardKind() == SGWGKindWireGuard) SGWireGuardSetEnabled(NO);
    return YES;
}

#pragma mark - The engine

NSDictionary *SGWireGuardEngineStatus(void) {
    if (!sg_active) return @{@"running": @NO};
    return jsonFromGo(SGWGStatus()) ?: @{@"running": @NO};
}

static void attachUpstream(void) {
    SGWGState state = SGWireGuardState();
    if (state == SGWGStateRunning || state == SGWGStateFailed) return;
    if (!SGWGEnsureOpen()) {
        atomic_store(&sg_state, SGWGStateFailed);
        return;
    }
    OSStatus status = errSecSuccess;
    int result;
    if (sg_kind == SGWGKindWireGuard) {
        NSString *profile = keychainRead(kProfileAccount, &status);
        if (!profile.length) {
            if (status == errSecItemNotFound) {
                SGWGFail("no WireGuard profile");
                atomic_store(&sg_state, SGWGStateFailed);
            } else {
                // A launch in the background before the first unlock: keep refusing and try again once
                // the data is available.
                atomic_store(&sg_state, SGWGStateWaitingProfile);
            }
            return;
        }
        atomic_store(&sg_state, SGWGStateStarting);
        result = SGWGAttachWireGuard((char *)profile.UTF8String);
    } else {
        NSString *host = SGWireGuardProxyHost(), *port = SGWireGuardProxyPort(), *user = SGWireGuardProxyUser();
        NSString *password = @"";
        if (!validProxy(sg_kind, host, port, user, NULL)) {
            SGWGFail("proxy server unusable");
            atomic_store(&sg_state, SGWGStateFailed);
            return;
        }
        if (user.length) {
            password = keychainRead(kProxyAccount, &status);
            if (status != errSecSuccess && status != errSecItemNotFound) {
                atomic_store(&sg_state, SGWGStateWaitingProfile);
                return;
            }
        }
        atomic_store(&sg_state, SGWGStateStarting);
        NSString *bare = [[host stringByReplacingOccurrencesOfString:@"[" withString:@""] stringByReplacingOccurrencesOfString:@"]" withString:@""];
        result = SGWGAttachExternal((char *)kindWire(sg_kind).UTF8String, (char *)bare.UTF8String, (int)port.integerValue,
                                    (char *)user.UTF8String, (char *)(password ?: @"").UTF8String);
    }
    atomic_store(&sg_state, result == 0 ? SGWGStateRunning : SGWGStateFailed);
    SGLog(@"wireguard: %@ %@", kindWire(sg_kind), result == 0 ? @"attached" : @"failed, connections are refused");
}

static void requestRebind(void) {
    if (!sg_active) return;
    dispatch_async(sg_queue, ^{
        SGWGState state = SGWireGuardState();
        if (state == SGWGStateWaitingProfile) {
            attachUpstream();
        } else if (state == SGWGStateRunning) {
            SGWGRebind();
            atomic_fetch_add(&sg_rebinds, 1);
        }
    });
}

void SGWireGuardLookup(NSString *host, void (^completion)(NSDictionary *)) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = sg_active && sg_kind == SGWGKindWireGuard ? jsonFromGo(SGWGLookup((char *)host.UTF8String)) : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(result ?: @{@"ok": @NO, @"error": @"tunnel not active"});
        });
    });
}

NSURLSession *SGWireGuardSession(void) {
    if (!sg_active) return nil;
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.timeoutIntervalForRequest = 15;
    configuration.timeoutIntervalForResource = 25;
    configuration.URLCache = nil;
    configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    SGWGApplyProxy(configuration); // explicit, whatever the class-method hooks did
    return [NSURLSession sessionWithConfiguration:configuration];
}

static BOOL reserveListener(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NO;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in address = {.sin_len = sizeof address, .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof address;
    if (bind(fd, (struct sockaddr *)&address, sizeof address) || listen(fd, 256) ||
        getsockname(fd, (struct sockaddr *)&address, &length)) {
        close(fd);
        return NO;
    }
    sg_listener = fd;
    sg_port = ntohs(address.sin_port);
    return YES;
}

static void randomHex(char out[33]) {
    uint8_t bytes[16];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof bytes, bytes) != errSecSuccess) arc4random_buf(bytes, sizeof bytes);
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", bytes[i]);
}

static void observeLifecycle(void) {
    // queue:nil throughout: UIKit posts these on main, and a main-queue observer of a notification posted
    // elsewhere would leave the poster waiting (AGENTS.md). Rebind only after real backgrounding (iOS may
    // have defuncted the sockets), not after Control Center, so a playing stream is not interrupted.
    static CFAbsoluteTime backgroundSince;
    NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
    [center addObserverForName:@"UIApplicationDidEnterBackgroundNotification" object:nil queue:nil usingBlock:^(NSNotification *note) {
        backgroundSince = CFAbsoluteTimeGetCurrent();
    }];
    [center addObserverForName:@"UIApplicationWillEnterForegroundNotification" object:nil queue:nil usingBlock:^(NSNotification *note) {
        if (backgroundSince > 0 && CFAbsoluteTimeGetCurrent() - backgroundSince > 15) requestRebind();
        backgroundSince = 0;
    }];
    for (NSString *name in @[@"UIApplicationDidBecomeActiveNotification", @"UIApplicationProtectedDataDidBecomeAvailable"]) {
        [center addObserverForName:name object:nil queue:nil usingBlock:^(NSNotification *note) {
            if (SGWireGuardState() == SGWGStateWaitingProfile) requestRebind();
        }];
    }
    static nw_path_monitor_t monitor;
    static NSString *lastSignature;
    monitor = nw_path_monitor_create();
    nw_path_monitor_set_queue(monitor, sg_queue);
    nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
        NSString *signature = [NSString stringWithFormat:@"%d%d%d%d", (int)nw_path_get_status(path),
            nw_path_uses_interface_type(path, nw_interface_type_wifi), nw_path_uses_interface_type(path, nw_interface_type_cellular),
            nw_path_uses_interface_type(path, nw_interface_type_wired)];
        // Wi-Fi to cellular and back: the WireGuard UDP socket is opened again on the new path.
        if (lastSignature && ![signature isEqualToString:lastSignature] && nw_path_get_status(path) == nw_path_status_satisfied) requestRebind();
        lastSignature = signature;
    });
    nw_path_monitor_start(monitor);
}

void SGWireGuardLaunch(void) {
    sg_queue = dispatch_queue_create("spotifyglass.wireguard", DISPATCH_QUEUE_SERIAL);
    if (!SGWireGuardEnabled()) return;
    if (!SGWireGuardSupportedOS()) {
        atomic_store(&sg_state, SGWGStateUnsupported);
        SGLog(@"wireguard: switched on, but this iOS has no URLSession proxy API (iOS 17 is needed); left off");
        return;
    }
    sg_kind = SGWireGuardKind();
    randomHex(sg_user);
    randomHex(sg_pass);
    // The port is known before the Go runtime is: the hooks below may run before it.
    if (!reserveListener()) sg_port = 1; // a closed port: refused, never direct
    sg_active = YES;
    atomic_store(&sg_state, SGWGStateStarting);
    SGWGInstallSessionHooks();
    SGWGInstallSocketHooks();
    observeLifecycle();
    dispatch_async(sg_queue, ^{ attachUpstream(); });
}

#pragma mark - The report

static NSString *redact(NSString *text) {
    char *raw = SGWGRedact((char *)(text ?: @"").UTF8String);
    if (!raw) return @"";
    NSString *out = [NSString stringWithUTF8String:raw] ?: @"";
    SGWGFree(raw);
    return out;
}

static NSString *N(id value) { return value ? [NSString stringWithFormat:@"%@", value] : @"-"; }

static NSString *counters(NSDictionary<NSString *, NSNumber *> *values) {
    NSMutableArray *parts = [NSMutableArray array];
    for (NSString *key in [values.allKeys sortedArrayUsingSelector:@selector(compare:)]) [parts addObject:[NSString stringWithFormat:@"%@ %@", key, values[key]]];
    return [parts componentsJoinedByString:@" | "];
}

NSString *SGWireGuardReport(NSDictionary<NSString *, NSString *> *checks) {
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    struct utsname machine;
    uname(&machine);
    id spotify = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    [lines addObject:[NSString stringWithFormat:@"Vitrine %@ app-local WireGuard / proxy", @SG_VERSION]];
    [lines addObject:[NSString stringWithFormat:@"app: Spotify %@ | %@ | %s", N(spotify), NSProcessInfo.processInfo.operatingSystemVersionString, machine.machine]];
    [lines addObject:[NSString stringWithFormat:@"setting: %@ | kind %@ | active this launch %@ | supported OS %@",
        SGWireGuardEnabled() ? @"on" : @"off", kindWire(sg_active ? sg_kind : SGWireGuardKind()), sg_active ? @"yes" : @"no",
        SGWireGuardSupportedOS() ? @"yes" : @"no"]];
    [lines addObject:[NSString stringWithFormat:@"state: %ld", (long)SGWireGuardState()]];
    NSDictionary *status = SGWireGuardEngineStatus();
    if ([status[@"running"] boolValue]) {
        long long age = [status[@"handshakeAgeSec"] longLongValue];
        [lines addObject:[NSString stringWithFormat:@"engine: upstream %@ | handshake %@ | wg rx %@ B tx %@ B | uptime %@ s%@",
            N(status[@"upstream"]), age < 0 ? @"none yet" : [NSString stringWithFormat:@"%lld s ago", age],
            N(status[@"wgRxBytes"]), N(status[@"wgTxBytes"]), N(status[@"uptimeSec"]),
            status[@"error"] ? [@" | error " stringByAppendingString:N(status[@"error"])] : @""]];
        NSDictionary *c = status[@"connections"], *categories = status[@"categories"], *bytes = status[@"proxyBytes"];
        if ([c isKindOfClass:NSDictionary.class]) [lines addObject:[@"connections: " stringByAppendingString:counters(c)]];
        if ([categories isKindOfClass:NSDictionary.class]) [lines addObject:[@"destinations: " stringByAppendingString:counters(categories)]];
        if ([bytes isKindOfClass:NSDictionary.class]) [lines addObject:[NSString stringWithFormat:@"bytes: up %@ down %@", N(bytes[@"up"]), N(bytes[@"down"])]];
        NSDictionary *bind = status[@"bind"];
        if ([bind isKindOfClass:NSDictionary.class]) [lines addObject:[NSString stringWithFormat:@"bind: updates %@ failures %@ | relistens %@ | endpoint resolved by the device %@",
            N(bind[@"updates"]), N(bind[@"failures"]), N(status[@"relistens"]), [status[@"endpointResolvedLocally"] boolValue] ? @"yes" : @"no"]];
    } else {
        [lines addObject:[NSString stringWithFormat:@"engine: not running %@", N(status[@"error"])]];
    }
    [lines addObject:[@"urlsession: " stringByAppendingString:counters(SGWGSessionCounters())]];
    [lines addObject:[@"sockets: " stringByAppendingString:counters(SGWGSocketCounters())]];
    [lines addObject:[NSString stringWithFormat:@"rebinds: %u", atomic_load(&sg_rebinds)]];
    for (NSString *key in [checks.allKeys sortedArrayUsingSelector:@selector(compare:)])
        [lines addObject:[NSString stringWithFormat:@"check.%@: %@", key, checks[key]]];
    [lines addObject:@"note: a country check passing does not prove playback; play a song, skip, and play from the lock screen."];
    return redact([lines componentsJoinedByString:@"\n"]);
}

#else

BOOL SGWireGuardSupportedOS(void) { return NO; }
NSDictionary *SGWireGuardInspectProfile(NSString *text, NSString **reason) { return nil; }
BOOL SGWireGuardImportProfile(NSString *text, NSString **reason) { return NO; }
NSDictionary *SGWireGuardProfileSummary(void) { return nil; }
BOOL SGWireGuardDeleteProfile(NSString **reason) { return keychainDelete(kProfileAccount) == errSecSuccess; }
NSDictionary *SGWireGuardEngineStatus(void) { return @{@"running": @NO}; }
void SGWireGuardLookup(NSString *host, void (^completion)(NSDictionary *)) { completion(@{@"ok": @NO}); }
NSURLSession *SGWireGuardSession(void) { return nil; }
NSString *SGWireGuardReport(NSDictionary<NSString *, NSString *> *checks) { return @""; }
void SGWireGuardLaunch(void) {}

#endif
