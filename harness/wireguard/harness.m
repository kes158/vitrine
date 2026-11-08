// macOS harness for the app-local WireGuard core (Source/WireGuard).
//
// Built by harness/wireguard/run_macos.py together with SGWGCore.m,
// SGWGTransport.m (compiled with -DSGWG_TESTING) and the Go engine built for
// macOS. It runs Apple's real NSURLSession + Network.framework proxy stack:
//
//   NSURLSession -> nw_proxy_config SOCKS5 (auth, no failover) -> Go engine
//   -> gVisor netstack -> WireGuard UDP -> test peer (DNS/HTTP/HTTPS/206)
//
// The Spotify classes below are fixtures; they test observer forwarding and ABI guards only.

#import <Foundation/Foundation.h>
#import <arpa/inet.h>
#import <Network/Network.h>
#import <dlfcn.h>
#import <netdb.h>
#import <fcntl.h>
#import <sys/socket.h>
#import <objc/runtime.h>
#import "../../tweak/Sources/Shared/WireGuard/SGWGCore.h"

int SGWGNativeTestGetaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
int SGWGNativeTestConnect(int, const struct sockaddr *, socklen_t);
ssize_t SGWGNativeTestSendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
nw_connection_t SGWGNativeTestNWCreate(nw_endpoint_t, nw_parameters_t);

#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);            \
            fprintf(stderr, __VA_ARGS__);                                   \
            fprintf(stderr, "\n");                                          \
            exit(1);                                                        \
        }                                                                   \
    } while (0)

static NSString *Env(NSString *name) { return NSProcessInfo.processInfo.environment[name]; }

#pragma mark - Spotify delegate fixtures (not the real Spotify process)
@interface SPTCoreURLSessionDataDelegate : NSObject
@property NSUInteger calls, bytes;
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error;
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)data;
@end
@implementation SPTCoreURLSessionDataDelegate
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error { self.calls++; }
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)data { self.bytes += data.length; }
@end
// Deliberately incompatible ABI: the observer must leave it alone.
@interface SPTDataLoaderService : NSObject
@property NSUInteger calls;
- (NSInteger)URLSession:(id)session task:(id)task didCompleteWithError:(id)error;
@end
@implementation SPTDataLoaderService
- (NSInteger)URLSession:(id)session task:(id)task didCompleteWithError:(id)error { self.calls++; return 73; }
@end
@interface FixtureTask : NSURLSessionDataTask
@property NSHTTPURLResponse *fixtureResponse;
@property NSURLRequest *fixtureRequest;
@end
@implementation FixtureTask
- (NSURLResponse *)response { return self.fixtureResponse; }
- (NSURLRequest *)currentRequest { return self.fixtureRequest; }
- (NSURLRequest *)originalRequest { return self.fixtureRequest; }
@end

#pragma mark - Trust delegate (test only: pins the generated fixture certificate)

@interface FixtureTrust : NSObject <NSURLSessionDelegate>
@end
@implementation FixtureTrust
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completion {
    NSString *host = challenge.protectionSpace.host;
    NSData *der = Env(@"SGWG_TEST_CERT") ? [NSData dataWithContentsOfFile:Env(@"SGWG_TEST_CERT")] : nil;
    NSString *suffix = Env(@"SGWG_TEST_TRUST_SUFFIX") ?: @"fixture.test";
    if (der && [host hasSuffix:suffix] &&
        [challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef trust = challenge.protectionSpace.serverTrust;
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)der);
        SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)@[(__bridge id)cert]);
        SecTrustSetAnchorCertificatesOnly(trust, true);
        CFRelease(cert);
        if (SecTrustEvaluateWithError(trust, NULL)) {
            completion(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:trust]);
            return;
        }
    }
    completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}
@end

#pragma mark - Helpers

typedef struct {
    NSInteger status;
    NSString *body;
    NSError *error;
    NSDictionary *headers;
} Result;

static Result Run(NSURLSessionDataTask * (^make)(void (^)(NSData *, NSURLResponse *, NSError *))) {
    __block Result r = {0};
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    NSURLSessionDataTask *task = make(^(NSData *data, NSURLResponse *response, NSError *error) {
        r.status = [response isKindOfClass:NSHTTPURLResponse.class] ? [(NSHTTPURLResponse *)response statusCode] : 0;
        r.headers = [response isKindOfClass:NSHTTPURLResponse.class] ? [(NSHTTPURLResponse *)response allHeaderFields] : nil;
        r.body = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
        r.error = error;
        dispatch_semaphore_signal(done);
    });
    [task resume];
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC))) {
        [task cancel];
        r.error = [NSError errorWithDomain:@"harness" code:-1 userInfo:nil];
    }
    return r;
}

static Result Get(NSURLSession *session, NSString *url, NSString *range) {
    return Run(^NSURLSessionDataTask *(void (^done)(NSData *, NSURLResponse *, NSError *)) {
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
        request.timeoutInterval = 12;
        if (range) [request setValue:range forHTTPHeaderField:@"Range"];
        return [session dataTaskWithRequest:request completionHandler:done];
    });
}

static NSString *ReportText(void) { return SGWGDiagnosticsReport(@{@"harness": @"run"}); }

static void WaitForEngine(void) {
    for (int i = 0; i < 200 && SGWGCurrentState() != SGWGStateRunning; i++) usleep(50000);
    CHECK(SGWGCurrentState() == SGWGStateRunning, "engine state %s", SGWGStateDescription(SGWGCurrentState()).UTF8String);
}

#pragma mark - Modes

static void UnitChecks(void) {
    BOOL expectActive = [Env(@"SGWG_EXPECT_ACTIVE") boolValue];
    CHECK(SGWGActiveThisLaunch() == expectActive, "active=%d expected %d", SGWGActiveThisLaunch(), expectActive);
    NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    NSArray *proxies = [config valueForKey:@"proxyConfigurations"];
    if (!expectActive) {
        CHECK(proxies.count == 0, "proxy applied while disabled");
        puts("PASS disabled: no proxy, no Spotify hooks");
        return;
    }
    CHECK(proxies.count == 1, "ephemeral configuration has %lu proxies", (unsigned long)proxies.count);
    bool (*getFailover)(void *) = (bool (*)(void *))dlsym(RTLD_DEFAULT, "nw_proxy_config_get_failover_allowed");
    CHECK(getFailover && !getFailover((__bridge void *)proxies.firstObject), "direct failover must be disabled");
    NSURLSessionConfiguration *background = [NSURLSessionConfiguration backgroundSessionConfigurationWithIdentifier:@"sgwg.harness"];
    // Background sessions run out of process; record (do not assert) whether
    // the platform keeps the proxy on such a configuration.
    printf("INFO background configuration proxies: %lu\n", (unsigned long)[[background valueForKey:@"proxyConfigurations"] count]);
    // A session made from a configuration the app later stripped is re-proxied.
    NSURLSessionConfiguration *stripped = NSURLSessionConfiguration.defaultSessionConfiguration;
    [stripped setValue:@[] forKey:@"proxyConfigurations"];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:stripped];
    CHECK([[session.configuration valueForKey:@"proxyConfigurations"] count] == 1, "session constructor did not re-apply proxy");
    [session invalidateAndCancel];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://fixture.test/"]];
    if ([request respondsToSelector:NSSelectorFromString(@"setAssumesHTTP3Capable:")]) {
        [request setValue:@YES forKey:@"assumesHTTP3Capable"];
        CHECK(![[request valueForKey:@"assumesHTTP3Capable"] boolValue], "assumesHTTP3Capable not cleared");
    }

    FixtureTask *task = [FixtureTask new];
    task.fixtureRequest = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://audio-fa.scdn.co/audio/secret?sig=SECRETSIG"]];
    task.fixtureResponse = [[NSHTTPURLResponse alloc] initWithURL:task.fixtureRequest.URL statusCode:403 HTTPVersion:@"HTTP/1.1" headerFields:nil];
    NSError *error = [NSError errorWithDomain:NSURLErrorDomain code:-1005 userInfo:@{NSLocalizedDescriptionKey:@"private-error-text"}];
    SPTCoreURLSessionDataDelegate *events = [SPTCoreURLSessionDataDelegate new];
    [events URLSession:nil dataTask:task didReceiveData:[NSMutableData dataWithLength:12]];
    [events URLSession:nil task:task didCompleteWithError:error];
    CHECK(events.calls == 1 && events.bytes == 12, "Spotify delegate callbacks not preserved");
    SPTDataLoaderService *wrong = [SPTDataLoaderService new];
    CHECK([wrong URLSession:nil task:task didCompleteWithError:nil] == 73 && wrong.calls == 1, "wrong ABI changed");
    CHECK([SGWGHostCategory(@"audio-fa.scdn.co.evil.example") isEqualToString:@"other"], "suffix boundary");
    NSString *report = ReportText();
    for (NSString *expected in @[@"spotify.http-status: 403 x1", @"NSURLErrorDomain -1005 x1", @"media 12 api 0", @"2 installed", @"SPTDataLoaderService URLSession:task:didCompleteWithError:"])
        CHECK([report containsString:expected], "report missing %s: %s", expected.UTF8String, report.UTF8String);
    for (NSString *secret in @[@"SECRETSIG", @"private-error-text", @"scdn.co"])
        CHECK(![report containsString:secret], "report leaks %s", secret.UTF8String);
    puts("PASS Spotify observers: callbacks preserved, incompatible ABI skipped, counters redacted; proxy enforced");

}

static void NetworkChecks(void) {
    WaitForEngine();
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *resolved = NULL;
    CHECK(SGWGNativeTestGetaddrinfo("fixture.test", "80", &hints, &resolved) == 0 && resolved,
          "native getaddrinfo did not use tunnel DNS");
    int nativeFD = socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol);
    CHECK(nativeFD >= 0 && SGWGNativeTestConnect(nativeFD, resolved->ai_addr, resolved->ai_addrlen) == 0,
          "native TCP did not connect through SOCKS: %d", errno);
    freeaddrinfo(resolved);
    const char *request = "GET / HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n";
    CHECK(send(nativeFD, request, strlen(request), 0) == (ssize_t)strlen(request), "native TCP write failed");
    char response[512] = {0};
    ssize_t count = recv(nativeFD, response, sizeof(response) - 1, 0);
    close(nativeFD);
    CHECK(count > 0 && strstr(response, "200 OK"), "native TCP did not reach tunnel origin");
    puts("PASS Spotify-style native getaddrinfo + connect -> SOCKS5 -> WireGuard origin");

    nw_parameters_t tcp = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    nw_endpoint_t endpoint = nw_endpoint_create_host("fixture.test", "80");
    nw_connection_t nw = SGWGNativeTestNWCreate(endpoint, tcp);
    dispatch_semaphore_t nwDone = dispatch_semaphore_create(0);
    __block BOOL nwOK = NO;
    nw_connection_set_queue(nw, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    nw_connection_set_state_changed_handler(nw, ^(nw_connection_state_t state, nw_error_t error) {
        if (state == nw_connection_state_failed) dispatch_semaphore_signal(nwDone);
        if (state != nw_connection_state_ready) return;
        dispatch_data_t data = dispatch_data_create(request, strlen(request), NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        nw_connection_send(nw, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t sendError) {
            if (sendError) { dispatch_semaphore_signal(nwDone); return; }
            nw_connection_receive(nw, 1, 512, ^(dispatch_data_t content, nw_content_context_t context,
                                                   bool complete, nw_error_t receiveError) {
                const void *mapped = NULL;
                size_t mappedSize = 0;
                dispatch_data_t map = content ? dispatch_data_create_map(content, &mapped, &mappedSize) : nil;
                nwOK = !receiveError && mappedSize >= 12 && memmem(mapped, mappedSize, "200 OK", 6);
                (void)map;
                dispatch_semaphore_signal(nwDone);
            });
        });
    });
    nw_connection_start(nw);
    CHECK(dispatch_semaphore_wait(nwDone, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC)) == 0 && nwOK,
          "native Network.framework TCP did not reach tunnel origin");
    nw_connection_cancel(nw);
    puts("PASS Spotify-style nw_connection_create -> proxy context -> WireGuard origin");

    struct addrinfo *blockingAddress = NULL;
    CHECK(SGWGNativeTestGetaddrinfo("fixture.test", "80", &hints, &blockingAddress) == 0 && blockingAddress,
          "nonblocking fixture DNS failed");
    int nonblockingFD = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(nonblockingFD >= 0 && fcntl(nonblockingFD, F_SETFL, O_NONBLOCK) == 0, "nonblocking socket setup failed");
    CHECK(SGWGNativeTestConnect(nonblockingFD, blockingAddress->ai_addr, blockingAddress->ai_addrlen) == 0,
          "nonblocking native TCP did not connect through tunnel: %d", errno);
    CHECK(fcntl(nonblockingFD, F_GETFL) & O_NONBLOCK, "nonblocking flag was not restored");
    close(nonblockingFD);
    freeaddrinfo(blockingAddress);
    puts("PASS native nonblocking TCP proxied and original socket flag restored");

    int udpFD = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in remote = {.sin_len = sizeof(remote), .sin_family = AF_INET,
        .sin_port = htons(443)};
    inet_pton(AF_INET, "203.0.113.2", &remote.sin_addr);
    CHECK(udpFD >= 0 && SGWGNativeTestSendto(udpFD, "x", 1, 0,
          (const struct sockaddr *)&remote, sizeof(remote)) == -1 && errno == ENETUNREACH,
          "remote native UDP was not blocked");
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    remote.sin_port = htons(5353);
    CHECK(SGWGNativeTestSendto(udpFD, "x", 1, 0,
          (const struct sockaddr *)&remote, sizeof(remote)) == 1, "local mDNS was blocked");
    close(udpFD);
    puts("PASS remote native UDP blocked; loopback mDNS left local");
    FixtureTrust *trust = [FixtureTrust new];
    NSURLSession *delegateSession = [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.ephemeralSessionConfiguration
                                                                  delegate:trust delegateQueue:nil];
    Result r = Get(delegateSession, @"https://fixture.test/", nil);
    CHECK(r.status == 200 && [r.body isEqualToString:@"through-tunnel"], "HTTPS via tunnel: %ld %s %s", (long)r.status, r.body.UTF8String, r.error.description.UTF8String);
    puts("PASS NSURLSession HTTPS through SOCKS5 -> WireGuard (name resolved by tunnel DNS)");

    r = Get(delegateSession, @"https://media.fixture.test/media", @"bytes=5-14");
    CHECK(r.status == 206 && r.body.length == 10 && [r.headers[@"Content-Range"] hasPrefix:@"bytes 5-14/"], "range response failed");
    puts("PASS HTTPS byte range (206) through tunnel");

    NSURLSession *shared = NSURLSession.sharedSession;
    CHECK([[shared.configuration valueForKey:@"proxyConfigurations"] count] == 1, "sharedSession not proxied");
    r = Get(shared, @"http://fixture.test/", nil);
    CHECK(r.status == 200 && [r.body isEqualToString:@"through-tunnel"], "sharedSession: %ld %s", (long)r.status, r.error.description.UTF8String);
    r = Get([NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.defaultSessionConfiguration], @"http://fixture.test/", nil);
    CHECK(r.status == 200, "sessionWithConfiguration: %ld %s", (long)r.status, r.error.description.UTF8String);
    puts("PASS sharedSession and sessionWithConfiguration: through tunnel");

    NSData *data = [NSData dataWithContentsOfURL:[NSURL URLWithString:@"http://fixture.test/"]];
    CHECK([[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] isEqualToString:@"through-tunnel"], "NSData URL load not tunnelled");
    puts("PASS +[NSData dataWithContentsOfURL:] through tunnel");

    r = Get(delegateSession, @"https://fixture.test/cdn-cgi/trace", nil);
    CHECK(r.status == 200 && [r.body containsString:@"ip=10.66.0.2"], "trace: %s", r.body.UTF8String);
    puts("PASS origin sees the WireGuard tunnel address as the client");

    NSString *direct = Env(@"SGWG_TEST_DIRECT_URL");
    if (direct.length) {
        r = Get(delegateSession, direct, nil);
        CHECK(r.error != nil, "request outside the tunnel succeeded: %ld (direct body %d, fixture body %d)", (long)r.status, [r.body isEqualToString:@"direct"], [r.body isEqualToString:@"through-tunnel"]);
        puts("PASS host reachable only directly: request fails (no direct fallback)");
    }

    __block NSDictionary *lookup;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    SGWGLookupInTunnel(@"media.fixture.test", ^(NSDictionary *result) {
        lookup = result;
        dispatch_semaphore_signal(done);
    });
    while (dispatch_semaphore_wait(done, DISPATCH_TIME_NOW)) [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    CHECK([lookup[@"ok"] boolValue] && [lookup[@"count"] intValue] == 1, "tunnel lookup %s", lookup.description.UTF8String);

    NSDictionary *status = SGWGEngineStatus();
    CHECK([status[@"handshakeAgeSec"] longLongValue] >= 0, "no handshake: %s", status.description.UTF8String);
    CHECK([status[@"connections"][@"socks"] intValue] >= 5 && [status[@"connections"][@"domainTargets"] intValue] >= 5,
          "SOCKS hostname connections not counted: %s", status.description.UTF8String);
    NSString *report = ReportText();
    CHECK(![report containsString:@"fixture.test"] && ![report containsString:@"127.0.0.1"], "report leaks host or address:\n%s", report.UTF8String);
    SGWGRequestRebind(@"harness");
    usleep(300000);
    r = Get(delegateSession, @"https://fixture.test/", nil);
    CHECK(r.status == 200, "after rebind: %ld %s", (long)r.status, r.error.description.UTF8String);
    puts("PASS diagnostics counters, tunnel DNS lookup, rebind");
    printf("%s\n", report.UTF8String);
}

static void FailClosedChecks(void) {
    for (int i = 0; i < 100 && SGWGCurrentState() == SGWGStateStarting; i++) usleep(50000);
    if ([Env(@"SGWG_EXPECT_FAILED") boolValue])
        CHECK(SGWGCurrentState() == SGWGStateFailed, "invalid profile: state %s", SGWGStateDescription(SGWGCurrentState()).UTF8String);
    NSURLSession *session = [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.ephemeralSessionConfiguration
                                                          delegate:[FixtureTrust new] delegateQueue:nil];
    Result r = Get(session, @"http://fixture.test/", nil);
    CHECK(r.error != nil, "request succeeded although the WireGuard peer is unreachable");
    NSString *direct = Env(@"SGWG_TEST_DIRECT_URL");
    if (direct.length) {
        r = Get(session, direct, nil);
        CHECK(r.error != nil, "direct fallback happened with a dead tunnel");
    }
    puts("PASS dead WireGuard peer: requests fail, nothing sent directly");
}

static NSDictionary *LookupSync(NSString *host) {
    __block NSDictionary *result;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    SGWGLookupInTunnel(host, ^(NSDictionary *r) {
        result = r;
        dispatch_semaphore_signal(done);
    });
    while (dispatch_semaphore_wait(done, DISPATCH_TIME_NOW)) [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    return result;
}

// Live mode: a real WireGuard server from the user's profile (CI secret).
// Same checks as the in-app "connection diagnostics", through the hooked
// NSURLSession path the app uses. Prints no key material, full IP or URL
// query; the exit IP is masked.
static void LiveChecks(void) {
    WaitForEngine();
    NSMutableDictionary *checks = [NSMutableDictionary dictionary];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.ephemeralSessionConfiguration];
    CHECK([[session.configuration valueForKey:@"proxyConfigurations"] count] == 1, "session not proxied");

    for (NSString *host in @[@"apresolve.spotify.com", @"spclient.wg.spotify.com", @"audio-fa.scdn.co"]) {
        NSDictionary *r = LookupSync(host);
        printf("LIVE tunnel DNS %s: %s (%s addr, %s ms)\n", host.UTF8String, [r[@"ok"] boolValue] ? "ok" : "FAILED",
               [[r[@"count"] description] UTF8String], [[r[@"ms"] description] UTF8String]);
        CHECK([r[@"ok"] boolValue], "tunnel DNS failed for %s: %s", host.UTF8String, [[r[@"error"] description] UTF8String]);
        checks[[@"dns." stringByAppendingString:host]] = @"ok";
    }

    Result r = Get(session, @"https://www.cloudflare.com/cdn-cgi/trace", nil);
    NSString *ip = nil, *loc = nil;
    for (NSString *line in [r.body componentsSeparatedByString:@"\n"]) {
        if ([line hasPrefix:@"ip="]) ip = [line substringFromIndex:3];
        if ([line hasPrefix:@"loc="]) loc = [line substringFromIndex:4];
    }
    CHECK(r.status == 200 && loc.length, "country check failed: HTTP %ld %s", (long)r.status, r.error.description.UTF8String);
    printf("LIVE exit country: %s, exit IP: %s\n", loc.UTF8String, SGWGRedactText(ip ?: @"?").UTF8String);
    NSString *expected = Env(@"SGWG_EXPECT_COUNTRY");
    if (expected.length) CHECK([loc isEqualToString:expected], "exit country %s, expected %s", loc.UTF8String, expected.UTF8String);
    checks[@"country"] = [NSString stringWithFormat:@"%@ exit %@", loc, ip];

    r = Get(session, @"https://www.google.com/generate_204", nil);
    printf("LIVE HTTPS www.google.com/generate_204: HTTP %ld %s\n", (long)r.status, r.error ? r.error.domain.UTF8String : "");
    CHECK(r.status == 204, "generate_204 failed");

    BOOL ranged = NO;
    for (NSString *url in @[@"https://www.gstatic.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png",
                            @"https://raw.githubusercontent.com/kes158/vitrine/main/LICENSE"]) {
        r = Get(session, url, @"bytes=0-1023");
        NSString *range = r.headers[@"Content-Range"];
        printf("LIVE Range %s: HTTP %ld, Content-Range %s\n", [NSURL URLWithString:url].host.UTF8String, (long)r.status,
               [range hasPrefix:@"bytes 0-1023/"] ? "ok" : "missing");
        if (r.status == 206 && [range hasPrefix:@"bytes 0-1023/"]) {
            ranged = YES;
            break;
        }
    }
    CHECK(ranged, "no HTTP 206 partial response through the tunnel");
    checks[@"range206"] = @"ok";

    // Informational: the Spotify web origin through the exit.
    r = Get(session, @"https://apresolve.spotify.com/", nil);
    printf("LIVE apresolve.spotify.com: HTTP %ld %s\n", (long)r.status, r.error ? [NSString stringWithFormat:@"%@ %ld", r.error.domain, (long)r.error.code].UTF8String : "");

    NSDictionary *status = SGWGEngineStatus();
    CHECK([status[@"handshakeAgeSec"] longLongValue] >= 0, "no WireGuard handshake");
    printf("PASS live: handshake, tunnel DNS, country, HTTPS, HTTP 206 through the real WireGuard server\n");
    printf("%s\n", SGWGDiagnosticsReport(checks).UTF8String);
}

// External HTTP / HTTPS / SOCKS5 proxy modes against local fixture proxies.
static void ExternalChecks(void) {
    NSString *kind = Env(@"SGWG_TEST_KIND");
    BOOL expectOK = [Env(@"SGWG_EXPECT_OK") boolValue];
    CHECK([SGWGActiveKind() isEqualToString:kind], "active kind %s", SGWGActiveKind().UTF8String);
    CHECK(SGWGCurrentState() == SGWGStateExternalProxy, "state %s", SGWGStateDescription(SGWGCurrentState()).UTF8String);
    NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    NSArray *proxies = [config valueForKey:@"proxyConfigurations"];
    bool (*getFailover)(void *) = (bool (*)(void *))dlsym(RTLD_DEFAULT, "nw_proxy_config_get_failover_allowed");
    CHECK(proxies.count == 1 && !getFailover((__bridge void *)proxies.firstObject), "proxy missing or failover allowed");

    NSURLSession *session = [NSURLSession sessionWithConfiguration:config delegate:[FixtureTrust new] delegateQueue:nil];
    Result r = Get(session, Env(@"SGWG_TEST_ORIGIN_URL"), @"bytes=0-9");
    if (expectOK) {
        CHECK(r.status == 206 && r.body.length == 10, "%s proxy: HTTP %ld %s", kind.UTF8String, (long)r.status, r.error.description.UTF8String);
        CHECK([[NSURLSession.sharedSession.configuration valueForKey:@"proxyConfigurations"] count] == 1, "sharedSession not proxied");
    } else {
        CHECK(r.error != nil, "%s proxy request succeeded although it must fail (HTTP %ld)", kind.UTF8String, (long)r.status);
    }
    NSString *report = ReportText();
    NSString *pass = Env(@"SGWG_TEST_PASS");
    NSString *modeLine = [NSString stringWithFormat:@"mode: %@ (external proxy", kind];
    CHECK([report containsString:modeLine], "report mode line:\n%s", report.UTF8String);
    CHECK(!pass.length || ![report containsString:pass], "report leaks proxy password");
    printf("PASS external %s: %s\n", kind.UTF8String, expectOK ? "HTTPS byte range (206) through proxy, failover disabled" : "request failed, nothing sent directly");
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *mode = argc > 1 ? @(argv[1]) : @"unit";
        if ([mode isEqualToString:@"unit"]) UnitChecks();
        else if ([mode isEqualToString:@"net"]) NetworkChecks();
        else if ([mode isEqualToString:@"failclosed"]) FailClosedChecks();
        else if ([mode isEqualToString:@"live"]) LiveChecks();
        else if ([mode isEqualToString:@"external"]) ExternalChecks();
        else CHECK(NO, "unknown mode %s", mode.UTF8String);
    }
    return 0;
}
