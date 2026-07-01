#import "SocketReporter.h"
#import "RestoreSymbol.h"
#import <substrate.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <AdSupport/AdSupport.h>
#import <CoreLocation/CoreLocation.h>
#import <Contacts/Contacts.h>
#import <Photos/Photos.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <CommonCrypto/CommonCrypto.h>
#import "SDKRulesData.h"

// ── Helpers ──────────────────────────────────────────────────────────────────

static NSString *captureStack(void) {
    RestoreSymbol *rs = [[RestoreSymbol alloc] init];
    NSMutableArray *frames = [rs outputCallStackSymbol];
    NSMutableArray *filtered = [NSMutableArray array];
    for (id item in frames) {
        if (![item isKindOfClass:[NSString class]]) continue;
        NSString *f = (NSString *)item;
        if ([f isEqualToString:@"null"] || f.length == 0) continue;
        if ([f containsString:@"MonitorTweak"] ||
            [f containsString:@"SocketReporter"] ||
            [f containsString:@"RestoreSymbol"]) continue;
        [filtered addObject:f];
        if (filtered.count >= 15) break;
    }
    return filtered.count > 0 ? [filtered componentsJoinedByString:@"\n"] : @"";
}

static long long msNow(void) {
    return (long long)([[NSDate date] timeIntervalSince1970] * 1000);
}

// Build a behavior message compatible with frida.Message JSON shape.
// Hooks listed here are completely silenced — neither reported nor logged.
// Add a method key (matching behavior_ios.json) to disable a hook without removing its %hook block.
static NSSet *behaviorBlacklist(void) {
    static NSSet *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [NSSet setWithObjects:
            @"CTTelephonyNetworkInfo.subscriberCellularProvider",
            @"CTTelephonyNetworkInfo.serviceSubscriberCellularProviders",
            @"NSFileHandle.write",
            @"NSData.write",
            @"NSFileManager.write",
            nil];
    });
    return s;
}

// method must match a key in behavior_ios.json; lookupBehavior in inspector.go
// resolves privacyFlag and desc from config — no flag needed here.
static void reportBehavior(NSString *method, NSString *data) {
    if ([behaviorBlacklist() containsObject:method]) return;
    [[SocketReporter shared] sendDict:@{
        @"type":        @"behavior",
        @"method":      method ?: @"",
        @"data":        data   ?: @"",
        @"stack":       captureStack(),
        @"privacyFlag": @"",
        @"scene":       @"NORMAL",
        @"timestamp":   @(msNow()),
    }];
}

static void reportNetwork(NSString *method, NSString *url,
                           NSDictionary *headers, NSString *body) {
    [[SocketReporter shared] sendDict:@{
        @"type":           @"network",
        @"method":         method  ?: @"GET",
        @"url":            url     ?: @"",
        @"requestHeaders": headers ?: @{},
        @"requestBody":    body    ?: @"",
        @"responseHeaders":@{},
        @"responseBody":   @"",
        @"statusCode":     @0,
        @"timestamp":      @(msNow()),
    }];
}

// ── Keychain C-function hooks (MSHookFunction) ────────────────────────────────

typedef OSStatus (*SecItemCopyMatchingFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*SecItemAddFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*SecItemUpdateFn)(CFDictionaryRef, CFDictionaryRef);
typedef OSStatus (*SecItemDeleteFn)(CFDictionaryRef);

static SecItemCopyMatchingFn orig_SecItemCopyMatching;
static SecItemAddFn          orig_SecItemAdd;
static SecItemUpdateFn       orig_SecItemUpdate;
static SecItemDeleteFn       orig_SecItemDelete;

static OSStatus new_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *r) {
    reportBehavior(@"SecItemCopyMatching",
        q ? [NSString stringWithFormat:@"%@", (__bridge NSDictionary *)q] : @"");
    return orig_SecItemCopyMatching(q, r);
}
static OSStatus new_SecItemAdd(CFDictionaryRef a, CFTypeRef *r) {
    reportBehavior(@"SecItemAdd",
        a ? [NSString stringWithFormat:@"%@", (__bridge NSDictionary *)a] : @"");
    return orig_SecItemAdd(a, r);
}
static OSStatus new_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef upd) {
    reportBehavior(@"SecItemUpdate", @"");
    return orig_SecItemUpdate(q, upd);
}
static OSStatus new_SecItemDelete(CFDictionaryRef q) {
    reportBehavior(@"SecItemDelete", @"");
    return orig_SecItemDelete(q);
}

// ── ptrace bypass ─────────────────────────────────────────────────────────────

typedef int (*ptrace_fn)(int, pid_t, caddr_t, int);
static ptrace_fn orig_ptrace;
static int new_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == 31) return 0; // PT_DENY_ATTACH → no-op
    return orig_ptrace(req, pid, addr, data);
}

// ── ObjC hooks (behavior) ─────────────────────────────────────────────────────

%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    NSUUID *r = %orig;
    reportBehavior(@"ASIdentifierManager.advertisingIdentifier", r.UUIDString ?: @"");
    return r;
}
%end

%hook UIDevice
- (NSUUID *)identifierForVendor {
    NSUUID *r = %orig;
    reportBehavior(@"UIDevice.identifierForVendor", r.UUIDString ?: @"");
    return r;
}
%end

%hook ATTrackingManager
+ (void)requestTrackingAuthorizationWithCompletionHandler:(void(^)(NSUInteger))handler {
    reportBehavior(@"ATTrackingManager.requestTrackingAuthorization", @"");
    %orig;
}
%end

// ── Location ──────────────────────────────────────────────────────────────────

%hook CLLocationManager
- (void)startUpdatingLocation {
    reportBehavior(@"CLLocationManager.startUpdatingLocation", @""); %orig;
}
- (void)requestWhenInUseAuthorization {
    reportBehavior(@"CLLocationManager.requestWhenInUseAuthorization", @""); %orig;
}
- (void)requestAlwaysAuthorization {
    reportBehavior(@"CLLocationManager.requestAlwaysAuthorization", @""); %orig;
}
- (void)startMonitoringSignificantLocationChanges {
    reportBehavior(@"CLLocationManager.startMonitoringSignificantLocationChanges", @""); %orig;
}
- (void)startMonitoringForRegion:(id)region {
    reportBehavior(@"CLLocationManager.startMonitoringForRegion", @""); %orig;
}
- (void)requestLocation {
    reportBehavior(@"CLLocationManager.requestLocation", @""); %orig;
}
- (void)setAllowsBackgroundLocationUpdates:(BOOL)allow {
    if (allow) reportBehavior(@"CLLocationManager.setAllowsBackgroundLocationUpdates", @"YES");
    %orig;
}
%end

// ── Contacts ──────────────────────────────────────────────────────────────────

%hook CNContactStore
- (void)requestAccessForEntityType:(NSInteger)t completionHandler:(id)h {
    reportBehavior(@"CNContactStore.requestAccessForEntityType", @""); %orig;
}
- (NSArray *)unifiedContactsMatchingPredicate:(id)p keysToFetch:(NSArray *)k error:(NSError **)e {
    reportBehavior(@"CNContactStore.unifiedContactsMatchingPredicate", @"");
    return %orig;
}
- (NSArray *)unifiedContactsWithIdentifiers:(NSArray *)ids keysToFetch:(NSArray *)k error:(NSError **)e {
    reportBehavior(@"CNContactStore.unifiedContactsWithIdentifiers",
                   [NSString stringWithFormat:@"%lu", (unsigned long)ids.count]);
    return %orig;
}
- (NSArray *)groupsMatchingPredicate:(id)p error:(NSError **)e {
    reportBehavior(@"CNContactStore.groupsMatchingPredicate", @""); return %orig;
}
- (NSArray *)containersMatchingPredicate:(id)p error:(NSError **)e {
    reportBehavior(@"CNContactStore.containersMatchingPredicate", @""); return %orig;
}
%end

// ── Camera / Microphone ───────────────────────────────────────────────────────

%hook AVCaptureDevice
+ (void)requestAccessForMediaType:(NSString *)mt completionHandler:(id)h {
    NSString *flag = ([mt containsString:@"vide"]) ? @"vide" : @"soun";
    reportBehavior(@"AVCaptureDevice.requestAccessForMediaType", flag);
    %orig;
}
%end

%hook AVAudioSession
- (void)requestRecordPermission:(id)h {
    reportBehavior(@"AVAudioSession.requestRecordPermission", @""); %orig;
}
%end

// Actual-use hooks: permission requests only fire on first grant; these catch the
// real recording/camera operation on every use (after the permission persists).
%hook AVAudioRecorder
- (BOOL)record {
    reportBehavior(@"AVAudioRecorder.record", @"");
    return %orig;
}
- (BOOL)recordForDuration:(NSTimeInterval)d {
    reportBehavior(@"AVAudioRecorder.record", @"");
    return %orig;
}
%end

%hook AVCaptureSession
- (void)startRunning {
    reportBehavior(@"AVCaptureSession.startRunning", @"");
    %orig;
}
%end

// ── Photos ────────────────────────────────────────────────────────────────────

%hook PHPhotoLibrary
+ (void)requestAuthorization:(id)h {
    reportBehavior(@"PHPhotoLibrary.requestAuthorization", @""); %orig;
}
+ (void)requestAuthorizationForAccessLevel:(NSInteger)l handler:(id)h {
    reportBehavior(@"PHPhotoLibrary.requestAuthorizationForAccessLevel", @""); %orig;
}
- (void)performChanges:(id)block completionHandler:(id)h {
    reportBehavior(@"PHPhotoLibrary.performChanges", @""); %orig;
}
- (void)performChangesAndWait:(id)block error:(NSError **)e {
    reportBehavior(@"PHPhotoLibrary.performChangesAndWait", @""); %orig;
}
%end

// Actual album reads — permission requests moved to the `permissions` flag, so these
// keep `readalbum` covered: enumerating the library + loading a photo's pixels.
%hook PHAsset
+ (PHFetchResult *)fetchAssetsWithMediaType:(PHAssetMediaType)mediaType options:(PHFetchOptions *)options {
    reportBehavior(@"PHAsset.fetchAssets", @"");
    return %orig;
}
%end

%hook PHImageManager
- (PHImageRequestID)requestImageForAsset:(PHAsset *)asset targetSize:(CGSize)targetSize contentMode:(PHImageContentMode)contentMode options:(PHImageRequestOptions *)options resultHandler:(id)resultHandler {
    reportBehavior(@"PHImageManager.requestImageForAsset", @"");
    return %orig;
}
%end

// ── Clipboard ─────────────────────────────────────────────────────────────────

%hook _UIConcretePasteboard
- (NSString *)string {
    NSString *r = %orig;
    if (r) reportBehavior(@"UIPasteboard.string", [r substringToIndex:MIN(200, r.length)]);
    return r;
}
- (void)setString:(NSString *)s {
    if (s) reportBehavior(@"UIPasteboard.setString", [s substringToIndex:MIN(200, s.length)]);
    %orig;
}
- (NSURL *)URL {
    NSURL *r = %orig;
    if (r) reportBehavior(@"UIPasteboard.URL", r.absoluteString ?: @"");
    return r;
}
- (NSArray *)items {
    NSArray *r = %orig;
    if (r) reportBehavior(@"UIPasteboard.items", @"");
    return r;
}
- (void)setItems:(NSArray *)items {
    if (items) reportBehavior(@"UIPasteboard.setItems", @"");
    %orig;
}
%end

// ── SIM ───────────────────────────────────────────────────────────────────────

%hook CTTelephonyNetworkInfo
- (id)subscriberCellularProvider {
    id r = %orig;
    NSString *name = @"";
    if ([r respondsToSelector:@selector(carrierName)]) name = [r carrierName] ?: @"";
    reportBehavior(@"CTTelephonyNetworkInfo.subscriberCellularProvider", name);
    return r;
}
- (id)serviceSubscriberCellularProviders {
    reportBehavior(@"CTTelephonyNetworkInfo.serviceSubscriberCellularProviders", @"");
    return %orig;
}
%end

// ── Network ───────────────────────────────────────────────────────────────────

%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)req {
    // Skip relay socket traffic (no URL filter needed for USB socket mode,
    // but guard against accidental HTTP loopback requests)
    if (req.URL && [req.URL.host isEqualToString:@"127.0.0.1"]) return %orig;
    reportNetwork(req.HTTPMethod, req.URL.absoluteString,
                  req.allHTTPHeaderFields,
                  req.HTTPBody ? [[NSString alloc] initWithData:req.HTTPBody
                                  encoding:NSUTF8StringEncoding] : @"");
    return %orig;
}
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)req
                            completionHandler:(id)h {
    if (req.URL && [req.URL.host isEqualToString:@"127.0.0.1"]) return %orig;
    reportNetwork(req.HTTPMethod, req.URL.absoluteString,
                  req.allHTTPHeaderFields,
                  req.HTTPBody ? [[NSString alloc] initWithData:req.HTTPBody
                                  encoding:NSUTF8StringEncoding] : @"");
    return %orig;
}
- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url {
    if ([url.host isEqualToString:@"127.0.0.1"]) return %orig;
    reportNetwork(@"GET", url.absoluteString, @{}, @"");
    return %orig;
}
- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url completionHandler:(id)h {
    if ([url.host isEqualToString:@"127.0.0.1"]) return %orig;
    reportNetwork(@"GET", url.absoluteString, @{}, @"");
    return %orig;
}
%end

// ── SDK detection (3 s delay; rules embedded in the dylib, AES-256-CTR) ────────

// AES-256-CTR decrypt of a [16-byte IV][ciphertext] blob using CommonCrypto.
// kCCModeOptionCTR_BE = big-endian counter starting at the IV, matching the
// Go cipher.NewCTR used by tools/gen_sdk_header.go.
static NSData *aesCtrDecrypt(const uint8_t *key, const uint8_t *blob, size_t blobLen) {
    if (blobLen <= 16) return nil;
    const uint8_t *iv = blob;
    const uint8_t *ct = blob + 16;
    size_t ctLen = blobLen - 16;

    CCCryptorRef cryptor = NULL;
    if (CCCryptorCreateWithMode(kCCDecrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
                                iv, key, kCCKeySizeAES256, NULL, 0, 0,
                                kCCModeOptionCTR_BE, &cryptor) != kCCSuccess) {
        return nil;
    }
    NSMutableData *out = [NSMutableData dataWithLength:ctLen];
    size_t moved = 0;
    CCCryptorStatus s = CCCryptorUpdate(cryptor, ct, ctLen, out.mutableBytes, ctLen, &moved);
    CCCryptorRelease(cryptor);
    if (s != kCCSuccess) return nil;
    out.length = moved;
    return out;
}

// Returns the SDK-rules JSON. A loose /var/mobile/monitor_sdk_rules.json wins
// when present (dev override: test new rules without rebuilding the dylib);
// production no longer ships that file (the agent stopped pushing it), so the
// AES-encrypted copy embedded in the dylib is used instead.
static NSData *loadSDKRules(void) {
    NSData *f = [NSData dataWithContentsOfFile:@"/var/mobile/monitor_sdk_rules.json"];
    if (f) return f;
    return aesCtrDecrypt(kSDKRulesKey, kSDKRulesBlob, kSDKRulesBlobLen);
}

static void runSDKDetection(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSData *data = loadSDKRules();
        if (!data) { NSLog(@"[MonitorTweak] sdk rules unavailable"); return; }
        NSArray *rules = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (![rules isKindOfClass:[NSArray class]]) return;

        NSMutableArray *results = [NSMutableArray array];
        NSMutableSet   *found   = [NSMutableSet set];

        // Class existence check
        for (NSDictionary *rule in rules) {
            NSString *name = rule[@"name"];
            if (!name || [found containsObject:name]) continue;
            for (NSString *cls in rule[@"class"] ?: @[]) {
                if (NSClassFromString(cls)) {
                    NSString *cat = [rule[@"category"] ?: @[] componentsJoinedByString:@", "];
                    [results addObject:@{@"name":name, @"category":cat,
                                         @"match":[@"Class: " stringByAppendingString:cls]}];
                    [found addObject:name];
                    break;
                }
            }
        }

        // Module path check for unmatched rules
        NSArray *modules = nil;
        for (NSDictionary *rule in rules) {
            NSString *name = rule[@"name"];
            if (!name || [found containsObject:name]) continue;
            NSArray *files = rule[@"file"] ?: @[];
            if (!files.count) continue;
            if (!modules) {
                // enumerate loaded dylibs
                NSMutableArray *m = [NSMutableArray array];
                uint32_t count = _dyld_image_count();
                for (uint32_t i = 0; i < count; i++) {
                    const char *nm = _dyld_get_image_name(i);
                    if (nm) [m addObject:[NSString stringWithUTF8String:nm]];
                }
                modules = m;
            }
            for (NSString *fileKey in files) {
                for (NSString *modPath in modules) {
                    if ([modPath rangeOfString:fileKey].location != NSNotFound) {
                        NSString *cat = [rule[@"category"] ?: @[] componentsJoinedByString:@", "];
                        [results addObject:@{@"name":name, @"category":cat,
                                             @"match":[@"Module: " stringByAppendingString:fileKey]}];
                        [found addObject:name];
                        break;
                    }
                }
                if ([found containsObject:name]) break;
            }
        }

        NSLog(@"[MonitorTweak] sdk detected: %lu", (unsigned long)results.count);
        [[SocketReporter shared] sendDict:@{
            @"type":      @"sdk_list",
            @"sdk_items": results,
            @"timestamp": @(msNow()),
        }];
    });
}

// ── Privacy policy capture (A: WKWebView innerText, B: native view-tree text) ──
// Extracted on-device and pushed as a "privacy_policy" message (frida.Message
// shape); pecker-agent's inspector enqueues it straight to the upload pipeline.
// source distinguishes the two plans: webview_js / native_view.

static const NSUInteger kPrivacyMinChars     = 200;     // ignore short blobs (buttons/toasts)
static const long long  kPrivacyNativeWindow = 120000;  // only walk native views for 120s after launch
static long long        gPrivacyLaunchMs     = 0;
static NSMutableSet     *gPrivacySeen         = nil;     // dedup by content prefix

static BOOL looksLikePrivacy(NSString *s) {
    if (!s.length) return NO;
    static NSArray *kw;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        kw = @[@"隐私", @"隐私政策", @"用户协议", @"服务协议", @"用户服务协议",
               @"privacy", @"agreement", @"policy"];
    });
    for (NSString *k in kw) {
        if ([s rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    }
    return NO;
}

static BOOL privacyAlreadyReported(NSString *content) {
    NSString *key = content.length > 80 ? [content substringToIndex:80] : content;
    @synchronized (gPrivacySeen) {
        if ([gPrivacySeen containsObject:key]) return YES;
        [gPrivacySeen addObject:key];
    }
    return NO;
}

static void reportPrivacy(NSString *source, NSString *url, NSString *text) {
    if (text.length < kPrivacyMinChars) return;
    if (privacyAlreadyReported(text)) return;
    [[SocketReporter shared] sendDict:@{
        @"type":      @"privacy_policy",
        @"method":    source ?: @"",
        @"url":       url ?: @"",
        @"data":      text,
        @"timestamp": @(msNow()),
    }];
}

// Report a privacy-looking page URL (frida.Message "webview_privacy_url") so
// pecker-agent can fetch the text as a fallback (Plan C) when the on-device
// innerText / native-view capture is missing or too short. HTTP(S) only — Plan
// C fetches over the network, so file://about: base URLs are useless.
static void reportPrivacyURL(NSString *url) {
    if (![url hasPrefix:@"http"]) return;
    [[SocketReporter shared] sendDict:@{
        @"type":      @"webview_privacy_url",
        @"url":       url,
        @"timestamp": @(msNow()),
    }];
}

// collectViewText walks a view subtree gathering UILabel / UITextView text.
static void collectViewText(UIView *v, NSMutableString *out, int depth) {
    if (!v || depth > 40 || out.length > 200000) return;
    if ([v isKindOfClass:[UILabel class]]) {
        NSString *t = ((UILabel *)v).text;
        if (t.length) { [out appendString:t]; [out appendString:@"\n"]; }
    } else if ([v isKindOfClass:[UITextView class]]) {
        NSString *t = ((UITextView *)v).text;
        if (t.length) { [out appendString:t]; [out appendString:@"\n"]; }
    }
    for (UIView *sub in v.subviews) collectViewText(sub, out, depth + 1);
}

// A: hook WKWebView; on a privacy-looking load, pull innerText after render settles.
%hook WKWebView
- (WKNavigation *)loadRequest:(NSURLRequest *)request {
    WKNavigation *nav = %orig;
    NSString *url = request.URL.absoluteString ?: @"";
    if (looksLikePrivacy(url)) {
        reportPrivacyURL(url);   // Plan C fallback fuel for pecker-agent
        __weak WKWebView *wself = self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            WKWebView *sv = wself;
            if (!sv) return;
            [sv evaluateJavaScript:@"document.body ? document.body.innerText : ''"
                completionHandler:^(id result, NSError *error) {
                    if ([result isKindOfClass:[NSString class]])
                        reportPrivacy(@"webview_js", url, (NSString *)result);
                }];
        });
    }
    return nav;
}
- (WKNavigation *)loadHTMLString:(NSString *)string baseURL:(NSURL *)baseURL {
    WKNavigation *nav = %orig;
    if (looksLikePrivacy(string)) {
        __weak WKWebView *wself = self;
        NSString *url = baseURL.absoluteString ?: @"";
        reportPrivacyURL(url);   // Plan C fuel (no-op unless baseURL is http(s))
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            WKWebView *sv = wself;
            if (!sv) return;
            [sv evaluateJavaScript:@"document.body ? document.body.innerText : ''"
                completionHandler:^(id result, NSError *error) {
                    if ([result isKindOfClass:[NSString class]])
                        reportPrivacy(@"webview_js", url, (NSString *)result);
                }];
        });
    }
    return nav;
}
%end

// B: hook UIViewController; during the launch window scan native view text for a
// privacy agreement (the common first-launch dialog). Time-boxed + deduped so the
// hot viewDidAppear path stays cheap.
%hook UIViewController
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    if (gPrivacyLaunchMs == 0 || msNow() - gPrivacyLaunchMs > kPrivacyNativeWindow) return;
    UIView *root = self.view;
    if (!root) return;
    NSMutableString *buf = [NSMutableString string];
    collectViewText(root, buf, 0);
    if (buf.length >= kPrivacyMinChars && looksLikePrivacy(buf))
        reportPrivacy(@"native_view", @"", buf);
}
%end

// ── Bootstrap ─────────────────────────────────────────────────────────────────

%ctor {
    NSLog(@"[MonitorTweak] loaded into %@", [[NSBundle mainBundle] bundleIdentifier]);

    // Start TCP server immediately (pure POSIX, no ObjC runtime needed)
    [[SocketReporter shared] startServer];

    // Privacy capture state (A/B): dedup set + launch timestamp for the native window.
    gPrivacySeen     = [NSMutableSet set];
    gPrivacyLaunchMs = msNow();

    // ptrace bypass
    MSHookFunction((void *)MSFindSymbol(NULL, "_ptrace"),
                   (void *)new_ptrace, (void **)&orig_ptrace);

    // Keychain C hooks
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (sec) {
        MSHookFunction((void *)SecItemCopyMatching,
                       (void *)new_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
        MSHookFunction((void *)SecItemAdd,
                       (void *)new_SecItemAdd,          (void **)&orig_SecItemAdd);
        MSHookFunction((void *)SecItemUpdate,
                       (void *)new_SecItemUpdate,       (void **)&orig_SecItemUpdate);
        MSHookFunction((void *)SecItemDelete,
                       (void *)new_SecItemDelete,       (void **)&orig_SecItemDelete);
        dlclose(sec);
    }

    // ObjC hooks
    %init;

    // SDK detection after runtime settles
    runSDKDetection();
}
