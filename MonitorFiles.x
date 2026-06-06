#import "SocketReporter.h"
#import <Foundation/Foundation.h>

// App-container path filter — same as hook_ios.js
static BOOL isAppPath(NSString *path) {
    if (!path) return NO;
    NSArray *prefixes = @[
        @"/var/mobile/Containers/Data/Application/",
        @"/var/mobile/Containers/Shared/AppGroup/",
        @"/private/var/mobile/Containers/Data/Application/",
        @"/private/var/mobile/Containers/Shared/AppGroup/",
    ];
    for (NSString *pfx in prefixes) {
        if ([path hasPrefix:pfx]) return YES;
    }
    return NO;
}

static long long msNow2(void) {
    return (long long)([[NSDate date] timeIntervalSince1970] * 1000);
}

static void reportFile(NSString *method, NSString *path, NSString *flag) {
    if (!isAppPath(path)) return;
    [[SocketReporter shared] sendDict:@{
        @"type":        @"behavior",
        @"method":      method,
        @"data":        path.length > 200 ? [path substringToIndex:200] : path,
        @"stack":       @"",
        @"privacyFlag": @"",
        @"scene":       @"NORMAL",
        @"timestamp":   @(msNow2()),
    }];
}

// ── NSFileHandle ──────────────────────────────────────────────────────────────

%hook NSFileHandle
+ (id)fileHandleForReadingAtPath:(NSString *)path {
    reportFile(@"NSFileHandle.read", path, @"readsdcard");
    return %orig;
}
+ (id)fileHandleForWritingAtPath:(NSString *)path {
    reportFile(@"NSFileHandle.write", path, @"writesdcard");
    return %orig;
}
%end

// ── NSData ────────────────────────────────────────────────────────────────────

%hook NSData
+ (id)dataWithContentsOfFile:(NSString *)path {
    reportFile(@"NSData.read", path, @"readsdcard");
    return %orig;
}
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)a {
    reportFile(@"NSData.write", path, @"writesdcard");
    return %orig;
}
%end

// ── NSFileManager ─────────────────────────────────────────────────────────────

%hook NSFileManager
- (NSData *)contentsAtPath:(NSString *)path {
    reportFile(@"NSFileManager.read", path, @"readsdcard");
    return %orig;
}
- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)d attributes:(NSDictionary *)a {
    reportFile(@"NSFileManager.write", path, @"writesdcard");
    return %orig;
}
- (BOOL)removeItemAtPath:(NSString *)path error:(NSError **)e {
    reportFile(@"NSFileManager.write", path, @"writesdcard");
    return %orig;
}
- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)e {
    reportFile(@"NSFileManager.write", src, @"writesdcard");
    return %orig;
}
- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)e {
    reportFile(@"NSFileManager.write", src, @"writesdcard");
    return %orig;
}
%end
