// Every NSURLSession in the process, Spotify's, its SDKs' and the mod's own, is pointed at the engine's
// loopback SOCKS5 server through NSURLSessionConfiguration.proxyConfigurations (iOS 17), with failover to a
// direct connection switched off. A configuration that cannot be given the proxy gets a protocol that fails
// every web request on it instead. The session constructors apply it again to a copy, so a configuration
// changed after it was made cannot drop it; +sharedSession is a session of its own built the same way.
//
// HTTP/3 is never assumed (the proxy carries TCP only), and -[NSData dataWithContentsOfURL:], which loads
// web URLs on a path of Foundation's own, is answered by a tunnelled session. AVURLAsset loads remote media
// outside the process, where no proxy reaches; those are only counted (docs/wireguard.md).
#import <AVFoundation/AVFoundation.h>
#import <objc/message.h>
#import <stdatomic.h>
#import "Core/SGCore.h"
#import "SGWGInternal.h"

#if SG_WIREGUARD

static atomic_uint sg_configs, sg_sessions, sg_background, sg_failures, sg_blocked, sg_http3, sg_dataLoads, sg_avRemote;

NSDictionary<NSString *, NSNumber *> *SGWGSessionCounters(void) {
    return @{@"configs": @(atomic_load(&sg_configs)), @"sessions": @(atomic_load(&sg_sessions)),
             @"background": @(atomic_load(&sg_background)), @"proxyFailures": @(atomic_load(&sg_failures)),
             @"blockedRequests": @(atomic_load(&sg_blocked)), @"http3Cleared": @(atomic_load(&sg_http3)),
             @"dataURLLoads": @(atomic_load(&sg_dataLoads)), @"avAssetRemote(outside)": @(atomic_load(&sg_avRemote))};
}

@interface SGWGBlockedProtocol : NSURLProtocol
@end

@implementation SGWGBlockedProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *scheme = request.URL.scheme.lowercaseString ?: @"";
    return [@[@"http", @"https", @"ws", @"wss"] containsObject:scheme];
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    atomic_fetch_add(&sg_blocked, 1);
    [self.client URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorNotConnectedToInternet userInfo:nil]];
}
- (void)stopLoading {}
@end

static void block(NSURLSessionConfiguration *configuration) {
    atomic_fetch_add(&sg_failures, 1);
    NSArray *classes = configuration.protocolClasses ?: @[];
    if (![classes containsObject:SGWGBlockedProtocol.class])
        configuration.protocolClasses = [@[SGWGBlockedProtocol.class] arrayByAddingObjectsFromArray:classes];
}

void SGWGApplyProxy(NSURLSessionConfiguration *configuration) {
    if (!SGWireGuardActive() || ![configuration isKindOfClass:NSURLSessionConfiguration.class]) return;
    @try {
        id proxy = SGWGCreateProxyConfig();
        if (!proxy) {
            block(configuration);
            return;
        }
        configuration.connectionProxyDictionary = nil;
        ((void (*)(id, SEL, id))objc_msgSend)(configuration, NSSelectorFromString(@"setProxyConfigurations:"), @[proxy]);
        atomic_fetch_add(&sg_configs, 1);
    } @catch (NSException *exception) {
        block(configuration);
    }
}

static BOOL isWebURL(id url) {
    if (![url isKindOfClass:NSURL.class]) return NO;
    NSString *scheme = [url scheme].lowercaseString;
    return [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"];
}

static NSData *tunnelFetch(NSURL *url, NSError **outError) {
    static NSURLSession *session;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
        configuration.timeoutIntervalForRequest = 30;
        configuration.timeoutIntervalForResource = 120;
        NSOperationQueue *queue = [NSOperationQueue new];
        queue.maxConcurrentOperationCount = 4;
        session = [NSURLSession sessionWithConfiguration:configuration delegate:nil delegateQueue:queue];
    });
    atomic_fetch_add(&sg_dataLoads, 1);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSData *result;
    __block NSError *failure;
    [[session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse *)response).statusCode : 0;
        if (!error && status >= 200 && status < 300) result = data ?: [NSData data];
        else failure = error ?: [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil];
        dispatch_semaphore_signal(done);
    }] resume];
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 125 * NSEC_PER_SEC)))
        failure = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorTimedOut userInfo:nil];
    if (!result && outError) *outError = failure;
    return result;
}

static id asClass(Class cls, NSData *data) {
    if (!data) return nil;
    return [cls isSubclassOfClass:NSMutableData.class] ? [data mutableCopy] : data;
}

%group SGWGSession

%hook NSURLSessionConfiguration
+ (NSURLSessionConfiguration *)defaultSessionConfiguration {
    NSURLSessionConfiguration *configuration = %orig;
    SGWGApplyProxy(configuration);
    return configuration;
}
+ (NSURLSessionConfiguration *)ephemeralSessionConfiguration {
    NSURLSessionConfiguration *configuration = %orig;
    SGWGApplyProxy(configuration);
    return configuration;
}
+ (NSURLSessionConfiguration *)backgroundSessionConfigurationWithIdentifier:(NSString *)identifier {
    NSURLSessionConfiguration *configuration = %orig;
    atomic_fetch_add(&sg_background, 1);
    SGWGApplyProxy(configuration);
    return configuration;
}
%end

%hook NSURLSession
+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration {
    NSURLSessionConfiguration *copy = [configuration copy];
    SGWGApplyProxy(copy);
    atomic_fetch_add(&sg_sessions, 1);
    return %orig(copy);
}
+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration delegate:(id)delegate delegateQueue:(NSOperationQueue *)queue {
    NSURLSessionConfiguration *copy = [configuration copy];
    SGWGApplyProxy(copy);
    atomic_fetch_add(&sg_sessions, 1);
    return %orig(copy, delegate, queue);
}
+ (NSURLSession *)sharedSession {
    static NSURLSession *session;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
    });
    return session;
}
%end

// The proxy carries TCP only: never ask URLSession to assume QUIC.
%hook NSMutableURLRequest
- (void)setAssumesHTTP3Capable:(BOOL)value {
    if (value) atomic_fetch_add(&sg_http3, 1);
    %orig(NO);
}
%end

%hook NSURLRequest
- (BOOL)assumesHTTP3Capable {
    return NO;
}
%end

%hook NSData
+ (id)dataWithContentsOfURL:(NSURL *)url {
    if (!isWebURL(url)) return %orig;
    return asClass(self, tunnelFetch(url, NULL));
}
+ (id)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)options error:(NSError **)error {
    if (!isWebURL(url)) return %orig;
    return asClass(self, tunnelFetch(url, error));
}
%end

%hook AVURLAsset
- (instancetype)initWithURL:(NSURL *)url options:(NSDictionary *)options {
    if (isWebURL(url)) atomic_fetch_add(&sg_avRemote, 1);
    return %orig;
}
%end

%end

void SGWGInstallSessionHooks(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ %init(SGWGSession); });
}

#endif
