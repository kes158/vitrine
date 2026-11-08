// Rebind only imports in Spotify's main image. Network.framework, Foundation,
// the Go engine and the Connect mDNS relay keep their own socket calls.
#import "SGWGCore.h"
#import "SGWGBridge.h"
#import "Core/SGRebind.h"
#import <Network/Network.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <netinet/in.h>
#import <netdb.h>
#import <stdatomic.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <unistd.h>

// Raw pointers preserve nw_connection_create's +1 ownership across the import
// slot. ARC must not insert a retain/autorelease around Spotify's C ABI.
static void *(*realNWCreate)(void *, void *);
static int (*realConnect)(int, const struct sockaddr *, socklen_t);
static int (*realGetaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static ssize_t (*realSendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*realSendmsg)(int, const struct msghdr *, int);
static atomic_uint nwProxied, nwBlocked, tcpProxied, tcpFailed, udpBlocked, dnsProxied, dnsFailed;
static BOOL nwHooked, connectHooked, sendtoHooked, sendmsgHooked, dnsHooked;

// Local receivers and the in-app proxy are intentionally outside the tunnel.
static BOOL LocalAddress(const struct sockaddr *address, socklen_t length) {
    if (!address) return NO;
    if (address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        uint32_t ip = ntohl(((const struct sockaddr_in *)address)->sin_addr.s_addr);
        return (ip >> 24) == 127 || (ip >> 16) == 0xA9FE || IN_MULTICAST(ip);
    }
    if (address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        const struct in6_addr *ip = &((const struct sockaddr_in6 *)address)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(ip) || IN6_IS_ADDR_LINKLOCAL(ip) || IN6_IS_ADDR_MULTICAST(ip);
    }
    return NO;
}

static BOOL LocalEndpoint(nw_endpoint_t endpoint) {
    if (!endpoint) return NO;
    nw_endpoint_type_t type = nw_endpoint_get_type(endpoint);
    if (type == nw_endpoint_type_bonjour_service) return YES;
    if (type == nw_endpoint_type_address) {
        const struct sockaddr *address = nw_endpoint_get_address(endpoint);
        return address && LocalAddress(address, address->sa_len);
    }
    if (type != nw_endpoint_type_host) return NO;
    const char *hostname = nw_endpoint_get_hostname(endpoint);
    if (!hostname) return NO;
    if (!strcasecmp(hostname, "localhost")) return YES;
    size_t size = strlen(hostname);
    if (size >= 6 && !strcasecmp(hostname + size - 6, ".local")) return YES;
    if (size >= 10 && !strcasecmp(hostname + size - 10, ".localhost")) return YES;
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, hostname, &v4) == 1) {
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = v4};
        return LocalAddress((const struct sockaddr *)&address, sizeof(address));
    }
    if (inet_pton(AF_INET6, hostname, &v6) == 1) {
        struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_addr = v6};
        return LocalAddress((const struct sockaddr *)&address, sizeof(address));
    }
    return NO;
}

static BOOL LocalName(const char *name) {
    if (!name || !*name || !strcasecmp(name, "localhost")) return YES;
    size_t size = strlen(name);
    if (size >= 6 && !strcasecmp(name + size - 6, ".local")) return YES;
    if (size >= 10 && !strcasecmp(name + size - 10, ".localhost")) return YES;
    struct in_addr v4;
    struct in6_addr v6;
    return inet_pton(AF_INET, name, &v4) == 1 || inet_pton(AF_INET6, name, &v6) == 1;
}

static int HookGetaddrinfo(const char *name, const char *service,
                           const struct addrinfo *hints, struct addrinfo **result) {
    if (LocalName(name) || (hints && (hints->ai_flags & AI_NUMERICHOST)))
        return realGetaddrinfo(name, service, hints, result);
    if (!result) return EAI_FAIL;
    *result = NULL;
    // Do not enter Go before its runtime and tunnel have started. A caller can
    // retry EAI_AGAIN; querying the system resolver here would disclose names.
    if (SGWGCurrentState() != SGWGStateRunning) { atomic_fetch_add(&dnsFailed, 1); return EAI_AGAIN; }
    char *json = SGWGResolve((char *)name);
    NSData *bytes = json ? [NSData dataWithBytes:json length:strlen(json)] : nil;
    if (json) SGWGFree(json);
    NSDictionary *reply = bytes ? [NSJSONSerialization JSONObjectWithData:bytes options:0 error:nil] : nil;
    NSArray *addresses = [reply[@"addresses"] isKindOfClass:NSArray.class] ? reply[@"addresses"] : nil;
    if (![reply[@"ok"] boolValue] || !addresses.count) { atomic_fetch_add(&dnsFailed, 1); return EAI_AGAIN; }
    struct addrinfo numeric = {0};
    if (hints) numeric = *hints;
    numeric.ai_flags = (numeric.ai_flags | AI_NUMERICHOST) & ~AI_CANONNAME;
    numeric.ai_addr = NULL;
    numeric.ai_addrlen = 0;
    numeric.ai_canonname = NULL;
    numeric.ai_next = NULL;
    struct addrinfo *head = NULL, *tail = NULL;
    for (NSString *ip in addresses) {
        if (![ip isKindOfClass:NSString.class]) continue;
        struct in_addr v4;
        struct in6_addr v6;
        if (inet_pton(AF_INET, ip.UTF8String, &v4) != 1 && inet_pton(AF_INET6, ip.UTF8String, &v6) != 1) continue;
        struct addrinfo *next = NULL;
        if (realGetaddrinfo(ip.UTF8String, service, &numeric, &next) || !next) continue;
        if (!head) head = next;
        else tail->ai_next = next;
        tail = next;
        while (tail->ai_next) tail = tail->ai_next;
    }
    if (!head) { atomic_fetch_add(&dnsFailed, 1); return EAI_NONAME; }
    if (hints && (hints->ai_flags & AI_CANONNAME)) head->ai_canonname = strdup(name);
    *result = head;
    atomic_fetch_add(&dnsProxied, 1);
    return 0;
}

static BOOL TCPParameters(nw_parameters_t parameters) {
    if (!parameters) return NO;
    nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(parameters);
    nw_protocol_options_t transport = stack ? nw_protocol_stack_copy_transport_protocol(stack) : nil;
    nw_protocol_definition_t actual = transport ? nw_protocol_options_copy_definition(transport) : nil;
    nw_protocol_definition_t tcp = nw_protocol_copy_tcp_definition();
    return actual && tcp && nw_protocol_definition_is_equal(actual, tcp);
}

static void *HookNWCreate(void *rawEndpoint, void *rawParameters) {
    nw_endpoint_t endpoint = (__bridge nw_endpoint_t)rawEndpoint;
    nw_parameters_t parameters = (__bridge nw_parameters_t)rawParameters;
    if (LocalEndpoint(endpoint)) return realNWCreate(rawEndpoint, rawParameters);
    // A SOCKS/CONNECT proxy carries TCP. Never let a UDP/QUIC connection
    // silently bypass the proxy, including when the proxy is not available.
    if (!TCPParameters(parameters)) {
        atomic_fetch_add(&nwBlocked, 1);
        nw_endpoint_t closed = nw_endpoint_create_host("127.0.0.1", "1");
        return realNWCreate((__bridge void *)closed, rawParameters);
    }
    id proxy = SGWGCreateNativeProxyConfig();
    if (!proxy) {
        atomic_fetch_add(&nwBlocked, 1);
        nw_endpoint_t closed = nw_endpoint_create_host("127.0.0.1", "1");
        return realNWCreate((__bridge void *)closed, rawParameters);
    }
    nw_parameters_t copy = nw_parameters_copy(parameters);
    nw_privacy_context_t context = nw_privacy_context_create("vitrine.spotify.native");
    typedef void (*AddProxy)(nw_privacy_context_t, nw_proxy_config_t);
    AddProxy add = (AddProxy)dlsym(RTLD_DEFAULT, "nw_privacy_context_add_proxy");
    if (!copy || !context || !add) {
        atomic_fetch_add(&nwBlocked, 1);
        nw_endpoint_t closed = nw_endpoint_create_host("127.0.0.1", "1");
        return realNWCreate((__bridge void *)closed, rawParameters);
    }
    add(context, (nw_proxy_config_t)proxy);
    nw_parameters_set_privacy_context(copy, context);
    atomic_fetch_add(&nwProxied, 1);
    return realNWCreate(rawEndpoint, (__bridge void *)copy);
}

static BOOL ExactIO(int fd, void *buffer, size_t size, BOOL sending) {
    uint8_t *bytes = buffer;
    while (size) {
        ssize_t count = sending ? send(fd, bytes, size, 0) : recv(fd, bytes, size, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return NO;
        bytes += count;
        size -= (size_t)count;
    }
    return YES;
}

static BOOL SOCKSConnect(int fd, const struct sockaddr *target) {
    int port;
    const char *user, *password;
    if (!SGWGNativeSOCKSEndpoint(&port, &user, &password) || port <= 0 || port > UINT16_MAX) return NO;
    // The reserved in-app listener is IPv4. An IPv6 socket may use the v4-mapped
    // loopback address; if IPV6_V6ONLY forbids it, this attempt fails closed.
    int family = target->sa_family;
    if (family == AF_INET) {
        struct sockaddr_in local = {.sin_len = sizeof(local), .sin_family = AF_INET,
            .sin_port = htons((uint16_t)port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        if (realConnect(fd, (const struct sockaddr *)&local, sizeof(local))) return NO;
    } else {
        struct sockaddr_in6 local = {.sin6_len = sizeof(local), .sin6_family = AF_INET6,
            .sin6_port = htons((uint16_t)port)};
        static const uint8_t mapped[16] = {0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1};
        memcpy(&local.sin6_addr, mapped, sizeof(mapped));
        if (realConnect(fd, (const struct sockaddr *)&local, sizeof(local))) return NO;
    }
    uint8_t greeting[] = {5, 1, 2}, answer[4];
    if (!ExactIO(fd, greeting, sizeof(greeting), YES) || !ExactIO(fd, answer, 2, NO) ||
        answer[0] != 5 || answer[1] != 2) return NO;
    size_t userLength = strlen(user), passLength = strlen(password);
    if (userLength > 255 || passLength > 255) return NO;
    uint8_t auth[2 + 255 + 1 + 255];
    size_t length = 0;
    auth[length++] = 1; auth[length++] = (uint8_t)userLength;
    memcpy(auth + length, user, userLength); length += userLength;
    auth[length++] = (uint8_t)passLength;
    memcpy(auth + length, password, passLength); length += passLength;
    if (!ExactIO(fd, auth, length, YES) || !ExactIO(fd, answer, 2, NO) ||
        answer[0] != 1 || answer[1] != 0) return NO;
    uint8_t request[4 + 16 + 2] = {5, 1, 0, family == AF_INET ? 1 : 4};
    size_t addressLength = family == AF_INET ? 4 : 16;
    uint16_t destinationPort;
    if (family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)target;
        memcpy(request + 4, &v4->sin_addr, 4);
        destinationPort = v4->sin_port;
    } else {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)target;
        memcpy(request + 4, &v6->sin6_addr, 16);
        destinationPort = v6->sin6_port;
    }
    memcpy(request + 4 + addressLength, &destinationPort, 2);
    if (!ExactIO(fd, request, 4 + addressLength + 2, YES) || !ExactIO(fd, answer, 4, NO) ||
        answer[0] != 5 || answer[1] != 0) return NO;
    size_t replyLength = answer[3] == 1 ? 4 : answer[3] == 4 ? 16 : 0;
    if (!replyLength) return NO;
    uint8_t discard[18];
    return ExactIO(fd, discard, replyLength + 2, NO);
}

static int HookConnect(int fd, const struct sockaddr *target, socklen_t length) {
    if (!target) return realConnect(fd, target, length);
    if (target->sa_family != AF_INET && target->sa_family != AF_INET6) return realConnect(fd, target, length);
    if (LocalAddress(target, length)) return realConnect(fd, target, length);
    int kind = 0;
    socklen_t kindLength = sizeof(kind);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &kindLength)) return -1;
    if (kind != SOCK_STREAM) { errno = ENETUNREACH; return -1; }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    struct timeval priorSend = {0}, priorReceive = {0};
    socklen_t size = sizeof(struct timeval);
    getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &priorSend, &size);
    size = sizeof(struct timeval);
    getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &priorReceive, &size);
    struct timeval timeout = {.tv_sec = 8};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (flags & O_NONBLOCK) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    BOOL connected = SOCKSConnect(fd, target);
    int saved = connected ? 0 : errno;
    if (flags & O_NONBLOCK) fcntl(fd, F_SETFL, flags);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &priorSend, sizeof(priorSend));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &priorReceive, sizeof(priorReceive));
    if (connected) { atomic_fetch_add(&tcpProxied, 1); return 0; }
    atomic_fetch_add(&tcpFailed, 1);
    errno = saved ? saved : ECONNREFUSED;
    return -1;
}

static BOOL RemoteDatagram(int fd, const struct sockaddr *to, socklen_t length) {
    int kind = 0;
    socklen_t size = sizeof(kind);
    return to && !LocalAddress(to, length) &&
        !getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &size) && kind == SOCK_DGRAM;
}
static ssize_t HookSendto(int fd, const void *bytes, size_t length, int flags,
                          const struct sockaddr *to, socklen_t toLength) {
    if (RemoteDatagram(fd, to, toLength)) { atomic_fetch_add(&udpBlocked, 1); errno = ENETUNREACH; return -1; }
    return realSendto(fd, bytes, length, flags, to, toLength);
}
static ssize_t HookSendmsg(int fd, const struct msghdr *message, int flags) {
    if (message && RemoteDatagram(fd, message->msg_name, message->msg_namelen)) {
        atomic_fetch_add(&udpBlocked, 1); errno = ENETUNREACH; return -1;
    }
    return realSendmsg(fd, message, flags);
}

void SGWGInstallNativePatches(void) {
#ifndef SGWG_TESTING
    nwHooked = SGRebindImport("nw_connection_create", HookNWCreate, (void **)&realNWCreate) && realNWCreate;
    connectHooked = SGRebindImport("connect", HookConnect, (void **)&realConnect) && realConnect;
    dnsHooked = SGRebindImport("getaddrinfo", HookGetaddrinfo, (void **)&realGetaddrinfo) && realGetaddrinfo;
    sendtoHooked = SGRebindImport("sendto", HookSendto, (void **)&realSendto) && realSendto;
    sendmsgHooked = SGRebindImport("sendmsg", HookSendmsg, (void **)&realSendmsg) && realSendmsg;
#endif
}

NSArray<NSString *> *SGWGNativeReportLines(void) {
    return @[
        [NSString stringWithFormat:@"native.hooks: nw_connection_create %@, connect %@, getaddrinfo %@, sendto %@, sendmsg %@",
            nwHooked ? @"installed" : @"missing", connectHooked ? @"installed" : @"missing", dnsHooked ? @"installed" : @"missing",
            sendtoHooked ? @"installed" : @"missing", sendmsgHooked ? @"installed" : @"missing"],
        [NSString stringWithFormat:@"native.paths: Network TCP proxied %u blocked %u; BSD TCP proxied %u failed %u; remote UDP blocked %u",
            atomic_load(&nwProxied), atomic_load(&nwBlocked), atomic_load(&tcpProxied),
            atomic_load(&tcpFailed), atomic_load(&udpBlocked)],
        [NSString stringWithFormat:@"native.dns: tunnel %u failed %u", atomic_load(&dnsProxied), atomic_load(&dnsFailed)],
        @"native scope: Spotify main image imports only. TCP SOCKS for WireGuard; remote UDP is blocked; local Connect discovery stays local."
    ];
}

#ifdef SGWG_TESTING
nw_connection_t SGWGNativeTestNWCreate(nw_endpoint_t endpoint, nw_parameters_t parameters) {
    realNWCreate = (void *(*)(void *, void *))(void *)nw_connection_create;
    return (__bridge_transfer nw_connection_t)HookNWCreate((__bridge void *)endpoint, (__bridge void *)parameters);
}
int SGWGNativeTestGetaddrinfo(const char *name, const char *service,
                              const struct addrinfo *hints, struct addrinfo **result) {
    realGetaddrinfo = getaddrinfo;
    return HookGetaddrinfo(name, service, hints, result);
}
int SGWGNativeTestConnect(int fd, const struct sockaddr *target, socklen_t length) {
    realConnect = connect;
    return HookConnect(fd, target, length);
}
ssize_t SGWGNativeTestSendto(int fd, const void *bytes, size_t length, int flags,
                             const struct sockaddr *to, socklen_t toLength) {
    realSendto = sendto;
    return HookSendto(fd, bytes, length, flags, to, toLength);
}
#endif
