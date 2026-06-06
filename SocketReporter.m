#import "SocketReporter.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <unistd.h>

static const NSUInteger kMaxQueue = 2000;

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
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        [self _acceptLoop];
    });
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
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        NSLog(@"[MonitorTweak] socket() failed");
        return;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(MONITOR_SOCKET_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        NSLog(@"[MonitorTweak] bind() failed on port %d", MONITOR_SOCKET_PORT);
        close(fd);
        return;
    }
    listen(fd, 1);
    self.serverFd = fd;
    NSLog(@"[MonitorTweak] listening on 127.0.0.1:%d", MONITOR_SOCKET_PORT);

    while (YES) {
        struct sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int clientFd = accept(fd, (struct sockaddr *)&clientAddr, &len);
        if (clientFd < 0) continue;

        NSLog(@"[MonitorTweak] pecker-agent connected");
        dispatch_sync(self.ioQueue, ^{
            if (self.clientFd >= 0) close(self.clientFd);
            self.clientFd = clientFd;
            // Drain queued events to new client immediately
            [self _flushToClient];
        });

        // Wait until this client disconnects (detect via write failure in _flushToClient)
        while (YES) {
            dispatch_sync(self.ioQueue, ^{});  // spin on ioQueue to detect disconnect
            if (self.clientFd < 0) break;
            [NSThread sleepForTimeInterval:0.1];
        }
        NSLog(@"[MonitorTweak] waiting for next connection");
    }
}

@end
