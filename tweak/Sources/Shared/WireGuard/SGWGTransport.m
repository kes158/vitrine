// Spotify 9.1.90 transport observations. No Google flags, enum guesses or binary patches.
// The session core applies the proxy; these delegates measure what Spotify actually receives.
#import "SGWGCore.h"
#import <objc/runtime.h>
#import <os/lock.h>

static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
static NSMutableDictionary<NSString *, NSNumber *> *completions, *statuses, *errors;
static NSMutableArray<NSString *> *installed, *skipped;
static uint64_t mediaBytes, apiBytes;

static NSArray<NSString *> *Delegates(void) {
    return @[@"SPTCoreURLSessionDataDelegate",
             @"_TtC26Connectivity_HttpClientKit20HttpClientURLSession", @"SPTDataLoaderService"];
}

// Verify the ABI, including every argument, before touching the implementation.
static BOOL Matches(Method method) {
    if (!method || method_getNumberOfArguments(method) != 5) return NO;
    char *type = method_copyReturnType(method);
    BOOL valid = type && !strcmp(type, "v");
    free(type);
    for (unsigned i = 2; valid && i < 5; i++) {
        type = method_copyArgumentType(method, i);
        valid = type && !strcmp(type, "@");
        free(type);
    }
    return valid;
}

static void Increment(NSMutableDictionary *map, NSString *key) {
    map[key] = @([map[key] unsignedLongLongValue] + 1);
}

static void ObserveCompletion(NSString *name, NSURLSessionTask *task, NSError *error) {
    NSInteger status = [task.response isKindOfClass:NSHTTPURLResponse.class] ? [(NSHTTPURLResponse *)task.response statusCode] : 0;
    // Never retain URLs, payloads, headers, or an arbitrary error domain supplied by a server.
    NSString *domain = [@[@"NSURLErrorDomain", @"NSPOSIXErrorDomain", @"kCFErrorDomainCFNetwork"] containsObject:error.domain] ? error.domain : @"other";
    os_unfair_lock_lock(&lock);
    Increment(completions, name);
    if (status) Increment(statuses, [NSString stringWithFormat:@"%ld", (long)status]);
    if (error) Increment(errors, [NSString stringWithFormat:@"%@ %ld", domain, (long)error.code]);
    os_unfair_lock_unlock(&lock);
}

static void ObserveData(NSURLSessionTask *task, NSData *data) {
    NSString *category = SGWGHostCategory(task.currentRequest.URL.host ?: task.originalRequest.URL.host);
    os_unfair_lock_lock(&lock);
    if ([category isEqualToString:@"media"]) mediaBytes += data.length;
    else if ([category isEqualToString:@"api"]) apiBytes += data.length;
    os_unfair_lock_unlock(&lock);
}

static void Hook(NSString *name, BOOL data) {
    Class cls = NSClassFromString(name);
    SEL selector = NSSelectorFromString(data ? @"URLSession:dataTask:didReceiveData:" : @"URLSession:task:didCompleteWithError:");
    Method method = class_getInstanceMethod(cls, selector);
    NSString *label = [NSString stringWithFormat:@"%@ %@", name, NSStringFromSelector(selector)];
    if (!Matches(method)) { [skipped addObject:label]; return; }
    void (*original)(id, SEL, id, id, id) = (void *)method_getImplementation(method);
    IMP replacement;
    if (data) {
        replacement = imp_implementationWithBlock(^(id self, NSURLSession *session, NSURLSessionDataTask *task, NSData *bytes) {
            ObserveData(task, bytes);
            original(self, selector, session, task, bytes);
        });
    } else {
        replacement = imp_implementationWithBlock(^(id self, NSURLSession *session, NSURLSessionTask *task, NSError *error) {
            ObserveCompletion(name, task, error);
            original(self, selector, session, task, error);
        });
    }
    if (!class_addMethod(cls, selector, replacement, method_getTypeEncoding(method)))
        method_setImplementation(class_getInstanceMethod(cls, selector), replacement);
    [installed addObject:label];
}

void SGWGInstallTransportPatches(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        completions = [NSMutableDictionary dictionary];
        statuses = [NSMutableDictionary dictionary];
        errors = [NSMutableDictionary dictionary];
        installed = [NSMutableArray array];
        skipped = [NSMutableArray array];
        for (NSString *name in Delegates()) { Hook(name, NO); Hook(name, YES); }
    });
}

static NSString *Summary(NSDictionary *values) {
    NSMutableArray *parts = [NSMutableArray array];
    for (NSString *key in [values.allKeys sortedArrayUsingSelector:@selector(compare:)])
        [parts addObject:[NSString stringWithFormat:@"%@ x%@", key, values[key]]];
    return parts.count ? [parts componentsJoinedByString:@", "] : @"none";
}

NSArray<NSString *> *SGWGTransportReportLines(void) {
    os_unfair_lock_lock(&lock);
    NSArray *lines = @[
        [NSString stringWithFormat:@"spotify.completions: %@", Summary(completions)],
        [NSString stringWithFormat:@"spotify.http-status: %@", Summary(statuses)],
        [NSString stringWithFormat:@"spotify.errors: %@", Summary(errors)],
        [NSString stringWithFormat:@"spotify.received-bytes: media %llu api %llu", (unsigned long long)mediaBytes, (unsigned long long)apiBytes],
        [NSString stringWithFormat:@"spotify.hooks: %lu installed | skipped: %@", (unsigned long)installed.count, [skipped componentsJoinedByString:@"; "] ?: @"none"],
        @"coverage: URLSession and Spotify main-image native TCP imports; remote UDP is blocked. Background services, remote Connect devices and playback are not device-verified.",
        @"baseline: Spotify 9.1.90; class/selector existence is static evidence, not proof of playback. Destination counters count connection attempts."
    ];
    os_unfair_lock_unlock(&lock);
    return lines;
}

NSArray<NSString *> *SGWGScanTransportClasses(void) {
    NSMutableArray *lines = [NSMutableArray array];
    for (NSString *name in Delegates()) {
        Class cls = NSClassFromString(name);
        [lines addObject:[NSString stringWithFormat:@"%@: %@", name, cls ? @"present" : @"missing"]];
        for (NSString *selector in @[@"URLSession:task:didCompleteWithError:", @"URLSession:dataTask:didReceiveData:"]) {
            Method method = class_getInstanceMethod(cls, NSSelectorFromString(selector));
            [lines addObject:[NSString stringWithFormat:@"  %@: %@", selector, Matches(method) ? @"compatible" : @"missing or incompatible"]];
        }
    }
    return lines;
}
