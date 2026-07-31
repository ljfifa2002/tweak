#import "SocketReporter.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <unistd.h>
#import <errno.h>

static const NSUInteger kMaxQueue = 2000;

static void DebugLog(const char *fmt, ...) {
    FILE *f = fopen("/tmp/monitortweaks.log", "a");
    if (!f) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fprintf(f, "\n");
    fflush(f);
    fclose(f);
}

@interface SocketReporter ()
@property (nonatomic, assign) int serverFd;
@property (nonatomic, assign) int clientFd;      // -1 = no client
@property (nonatomic, strong) NSMutableArray<NSData *> *queue;
@property (nonatomic, strong) dispatch_queue_t  ioQueue;  // serial queue for all state
@end

@implementation SocketReporter

+ (instancetype)shared {
    static SocketReporter *s;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ s = [SocketReporter new]; });
    return s;
}

- (instancetype)init {
    self = [super init];
    _serverFd = -1;
    _clientFd = -1;
    _queue    = [NSMutableArray array];
    _ioQueue  = dispatch_queue_create("com.pecker.monitor.socket", DISPATCH_QUEUE_SERIAL);
    return self;
}

// ── Public ──────────────────────────────────────────────────────────────────

- (void)sendDict:(NSDictionary *)dict {
    NSError *err;
    NSData  *json = [NSJSONSerialization dataWithJSONObject:dict options:0 error:&err];
    if (!json) return;

    // Append newline delimiter
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];

    dispatch_async(self.ioQueue, ^{
        [self _enqueueAndFlush:line];
    });
}

- (void)startServer {
    DebugLog("[SocketReporter] startServer called");
    NSLog(@"[MonitorTweak] SocketReporter startServer called");
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        DebugLog("[SocketReporter] dispatch block entered");
        NSLog(@"[MonitorTweak] SocketReporter dispatch block entered");
        [self _acceptLoop];
        DebugLog("[SocketReporter] _acceptLoop returned");
        NSLog(@"[MonitorTweak] SocketReporter _acceptLoop returned");
    });
    DebugLog("[SocketReporter] startServer dispatch scheduled");
    NSLog(@"[MonitorTweak] SocketReporter startServer dispatch scheduled");
}

// ── Private ─────────────────────────────────────────────────────────────────

- (void)_enqueueAndFlush:(NSData *)line {
    // Drop oldest if queue too large
    while (self.queue.count >= kMaxQueue) {
        [self.queue removeObjectAtIndex:0];
    }
    [self.queue addObject:line];
    [self _flushToClient];
}

- (void)_flushToClient {
    if (self.clientFd < 0) return;
    NSMutableArray *failed = nil;
    for (NSData *line in self.queue) {
        if (![self _writeData:line toFd:self.clientFd]) {
            // Client disconnected
            close(self.clientFd);
            self.clientFd = -1;
            NSLog(@"[MonitorTweak] client disconnected");
            return;
        }
        if (!failed) failed = [NSMutableArray array];
        [failed addObject:line]; // mark as sent
    }
    // Remove all successfully sent lines
    if (failed) {
        [self.queue removeObjectsInArray:failed];
    } else {
        [self.queue removeAllObjects];
    }
}

- (BOOL)_writeData:(NSData *)data toFd:(int)fd {
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger    total  = data.length;
    NSUInteger    sent   = 0;
    while (sent < total) {
        ssize_t n = write(fd, bytes + sent, total - sent);
        if (n <= 0) return NO;
        sent += n;
    }
    return YES;
}

- (void)_acceptLoop {
    DebugLog("[_acceptLoop] starting");
    NSLog(@"[MonitorTweak] _acceptLoop: starting");
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        DebugLog("[_acceptLoop] socket() failed errno=%d", errno);
        NSLog(@"[MonitorTweak] socket() failed errno=%d", errno);
        return;
    }
    DebugLog("[_acceptLoop] socket created fd=%d", fd);
    NSLog(@"[MonitorTweak] _acceptLoop: socket created fd=%d", fd);
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(MONITOR_SOCKET_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only

    DebugLog("[_acceptLoop] attempting bind on port %d", MONITOR_SOCKET_PORT);
    NSLog(@"[MonitorTweak] _acceptLoop: attempting bind on port %d", MONITOR_SOCKET_PORT);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        DebugLog("[_acceptLoop] bind() failed errno=%d on port %d", errno, MONITOR_SOCKET_PORT);
        NSLog(@"[MonitorTweak] bind() failed errno=%d on port %d", errno, MONITOR_SOCKET_PORT);
        close(fd);
        return;
    }
    listen(fd, 1);
    self.serverFd = fd;
    DebugLog("[_acceptLoop] listening on 127.0.0.1:%d", MONITOR_SOCKET_PORT);
    NSLog(@"[MonitorTweak] listening on 127.0.0.1:%d", MONITOR_SOCKET_PORT);

    while (YES) {
        @autoreleasepool {
            struct sockaddr_in clientAddr;
            socklen_t len = sizeof(clientAddr);
            int clientFd = -1;  // Define before @try

            NSLog(@"[accept] about to call accept");
            DebugLog("[_acceptLoop] about to call accept, fd=%d", fd);

            // Add error handling around accept
            @try {
                clientFd = accept(fd, (struct sockaddr *)&clientAddr, &len);
                NSLog(@"[accept] accept returned, clientFd=%d, errno=%d", clientFd, errno);
                DebugLog("[_acceptLoop] accept returned, clientFd=%d, errno=%d", clientFd, errno);

                if (clientFd < 0) {
                    DebugLog("[_acceptLoop] accept failed, errno=%d, continuing", errno);
                    [NSThread sleepForTimeInterval:0.1];
                    continue;
                }
            }
            @catch (NSException *e) {
                NSLog(@"[accept] exception: %@ - %@", e.name, e.reason);
                DebugLog("[_acceptLoop] exception: %s", e.reason.UTF8String);
                [NSThread sleepForTimeInterval:0.1];
                continue;
            }

            DebugLog("[_acceptLoop] client connected, fd=%d", clientFd);
            NSLog(@"[MonitorTweak] pecker-agent connected fd=%d", clientFd);

            dispatch_sync(self.ioQueue, ^{
                if (self.clientFd >= 0) close(self.clientFd);
                self.clientFd = clientFd;
                DebugLog("[_acceptLoop] calling _flushToClient");
                [self _flushToClient];
                DebugLog("[_acceptLoop] _flushToClient returned");
            });

            DebugLog("[_acceptLoop] waiting for client disconnect, clientFd=%d", self.clientFd);
            while (YES) {
                dispatch_sync(self.ioQueue, ^{});
                if (self.clientFd < 0) {
                    DebugLog("[_acceptLoop] client disconnected");
                    break;
                }
                [NSThread sleepForTimeInterval:0.1];
            }
            DebugLog("[_acceptLoop] ready for next connection");
        }
    }
}

@end
