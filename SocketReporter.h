#pragma once
#import <Foundation/Foundation.h>

// SocketReporter — TCP server on the device.
// pecker-agent connects via `ios forward LOCAL 9190 --udid=UDID` then dials localhost:LOCAL.
// Each event is emitted as a single JSON object followed by '\n'.
// Matches the frida.Message JSON shape so pecker-agent can parse without changes.

#define MONITOR_SOCKET_PORT 9190

@interface SocketReporter : NSObject

+ (instancetype)shared;

// Send a pre-built frida.Message-compatible JSON dictionary.
// Thread-safe. Drops oldest entry when queue exceeds 2000.
- (void)sendDict:(NSDictionary *)dict;

// Start the TCP accept loop (called from %ctor).
- (void)startServer;

@end
