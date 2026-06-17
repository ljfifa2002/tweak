#import "RestoreSymbol.h"
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <os/lock.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>

// Scheme A: restore ObjC method symbols for a back-trace by parsing each image's
// __objc_classlist / method lists DIRECTLY from memory — never via the live objc
// runtime (objc_getClass / class_copyMethodList). The runtime path forces
// realization of not-yet-realized Swift classes during early app launch, which
// null-derefs in swift_getSingletonMetadata and crashes the host app. Reading the
// Mach-O metadata only touches already-mapped image memory, never realizes a
// class, and is cached per image so it is built once.
//
// Every dereference is bounds-checked against the image's mapped VA window, so a
// malformed/unexpected layout degrades to "module + offset" instead of crashing.
// Target: arm64, iOS 15 objc4 layout (the device in use). arm64e (PAC-signed
// pointers) is not handled — those frames fall back to module+offset.

#define FAST_DATA_MASK   0x00007ffffffffff8UL // class_data_bits_t -> data() (arm64)
#define RW_REALIZED      0x80000000U          // class_rw_t.flags bit; absent in class_ro_t.flags
#define ML_SMALL_FLAG    0x80000000U          // method_list_t uses relative (small) entries
#define ML_ENTSIZE_MASK  0x0000fffcU
#define MAX_SYM_OFFSET   0x80000UL            // >512KB from nearest IMP => treat as no match
#define MAX_SEL_LEN      255

typedef struct { uintptr_t imp; char *sym; } SymEnt;

typedef struct {
    const void *base;   // image header (dli_fbase) — cache key
    uintptr_t   lo, hi; // readable VA window [lo, hi)
    SymEnt     *ents;   // sorted ascending by imp; process-lifetime (never freed)
    size_t      count;
    BOOL        built;
} ImgCache;

#define MAX_IMAGES 24
static ImgCache gImgs[MAX_IMAGES];
static int gImgN = 0;
static os_unfair_lock gLock = OS_UNFAIR_LOCK_INIT;

// ── bounds-checked reads ───────────────────────────────────────────────────────

static inline BOOL okRange(uintptr_t p, size_t n, uintptr_t lo, uintptr_t hi) {
    return n && p >= lo && hi >= n && p <= hi - n;
}
static inline uint32_t  rdU32(uintptr_t p) { uint32_t v;  memcpy(&v, (void *)p, 4); return v; }
static inline int32_t   rdS32(uintptr_t p) { int32_t  v;  memcpy(&v, (void *)p, 4); return v; }
static inline uintptr_t rdPtr(uintptr_t p) { uintptr_t v; memcpy(&v, (void *)p, sizeof(v)); return v; }

// Fault-safe pointer read for addresses OUTSIDE the image window (a realized
// class's class_rw_t lives on the heap). Returns NO instead of crashing on a bad
// address.
static BOOL safeReadPtr(uintptr_t addr, uintptr_t *out) {
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                         sizeof(uintptr_t), (vm_address_t)out, &got);
    return kr == KERN_SUCCESS && got == sizeof(uintptr_t);
}

// Copy a printable, NUL-terminated C string at p (within [lo,hi)); NULL on failure.
static char *dupCStr(uintptr_t p, uintptr_t lo, uintptr_t hi) {
    if (p < lo || p >= hi) return NULL;
    size_t max = hi - p; if (max > MAX_SEL_LEN + 1) max = MAX_SEL_LEN + 1;
    size_t len = 0;
    while (len < max) {
        unsigned char c = *((unsigned char *)(p + len));
        if (c == 0) break;
        if (c < 0x20 || c >= 0x7f) return NULL; // selector chars are printable ASCII
        len++;
    }
    if (len == 0 || len >= max) return NULL;    // empty, or no NUL within bound
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, (void *)p, len); s[len] = 0;
    return s;
}

// ── ObjC structure walk ────────────────────────────────────────────────────────

// Resolve class_ro_t* from a class_t*. The discriminator is WHERE bits->data
// points: a class_ro_t lives in the image (so it falls inside [lo,hi)); a
// realized class's class_rw_t is malloc'd on the heap (outside [lo,hi)). For the
// heap case we read class_rw_t.ro_or_rw_ext (+8) via the fault-safe reader. This
// never calls the objc runtime, so it never realizes a (Swift) class. 0 = skip.
static uintptr_t roOf(uintptr_t cls, uintptr_t lo, uintptr_t hi) {
    if (!okRange(cls, 40, lo, hi)) return 0;        // need bits at +32
    uintptr_t data = rdPtr(cls + 32) & FAST_DATA_MASK;
    if (okRange(data, 8, lo, hi)) return data;      // in image: class_ro_t (not realized)

    // Out of image: realized class_rw_t on the heap. ro_or_rw_ext is at +8.
    uintptr_t v;
    if (!safeReadPtr(data + 8, &v)) return 0;
    if (v & 1) {                                    // tagged -> class_rw_ext_t*, ro at +0
        uintptr_t ro;
        if (!safeReadPtr(v & ~1UL, &ro)) return 0;
        return ro;
    }
    return v & ~1UL;                                // class_ro_t*
}

static void addEnt(SymEnt **arr, size_t *n, size_t *cap,
                   uintptr_t imp, char type, const char *cls, const char *sel) {
    if (!imp || !cls || !sel) return;
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 512;
        SymEnt *na = (SymEnt *)realloc(*arr, nc * sizeof(SymEnt));
        if (!na) return;
        *arr = na; *cap = nc;
    }
    size_t L = strlen(cls) + strlen(sel) + 8;
    char *s = (char *)malloc(L);
    if (!s) return;
    snprintf(s, L, "%c[%s %s]", type, cls, sel);
    (*arr)[*n].imp = imp; (*arr)[*n].sym = s; (*n)++;
}

// Walk one class_ro_t's baseMethods, appending {imp -> "<type>[cls sel]"}.
static void parseMethods(uintptr_t ro, char type, const char *cls,
                         uintptr_t lo, uintptr_t hi, SymEnt **arr, size_t *n, size_t *cap) {
    if (!okRange(ro, 40, lo, hi)) return;           // need baseMethods at +32
    uintptr_t ml = rdPtr(ro + 32);
    if (!ml || !okRange(ml, 8, lo, hi)) return;
    uint32_t eaf = rdU32(ml);
    uint32_t count = rdU32(ml + 4);
    uint32_t entsize = eaf & ML_ENTSIZE_MASK;
    BOOL small = (eaf & ML_SMALL_FLAG) != 0;
    if (entsize < 12 || count == 0 || count > 200000) return;
    uintptr_t m = ml + 8;
    for (uint32_t i = 0; i < count; i++, m += entsize) {
        if (!okRange(m, entsize, lo, hi)) break;
        uintptr_t imp = 0, selStr = 0, selSlot = 0;
        if (small) {
            int32_t nameOff = rdS32(m);
            int32_t impOff  = rdS32(m + 8);
            selSlot = (uintptr_t)((intptr_t)m + nameOff);          // -> SEL slot (selref)
            imp     = (uintptr_t)((intptr_t)(m + 8) + impOff);     // relative to imp field
            if (okRange(selSlot, sizeof(uintptr_t), lo, hi)) selStr = rdPtr(selSlot);
        } else {
            selStr = rdPtr(m);          // SEL (pointer to name string)
            imp    = rdPtr(m + 16);
        }
        char *sel = dupCStr(selStr, lo, hi);
        if (!sel && small) sel = dupCStr(selSlot, lo, hi); // fallback: direct-string form
        if (sel) { addEnt(arr, n, cap, imp, type, cls, sel); free(sel); }
    }
}

static int cmpEnt(const void *a, const void *b) {
    uintptr_t x = ((const SymEnt *)a)->imp, y = ((const SymEnt *)b)->imp;
    return x < y ? -1 : (x > y ? 1 : 0);
}

// Parse all classes (instance + class methods) of one image into ic->ents.
static void buildImage(ImgCache *ic) {
    ic->built = YES;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)ic->base;
    uintptr_t header = (uintptr_t)mh;

    // Pass 1: slide (from __TEXT) and the mapped VA span (excluding __PAGEZERO).
    uintptr_t textVM = 0, maxEnd = 0; BOOL haveText = NO;
    const uint8_t *p = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__PAGEZERO") != 0) {
                if (strcmp(sg->segname, "__TEXT") == 0) { textVM = sg->vmaddr; haveText = YES; }
                uintptr_t e = (uintptr_t)(sg->vmaddr + sg->vmsize);
                if (e > maxEnd) maxEnd = e;
            }
        }
        p += lc->cmdsize;
    }
    if (!haveText) return;
    uintptr_t slide = header - textVM;
    ic->lo = header;
    ic->hi = maxEnd + slide;

    // Pass 2: every __objc_classlist section, in any segment.
    SymEnt *arr = NULL; size_t n = 0, cap = 0;
    p = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            const struct section_64 *sec = (const struct section_64 *)(sg + 1);
            for (uint32_t s = 0; s < sg->nsects; s++) {
                if (strncmp(sec[s].sectname, "__objc_classlist", 16) != 0) continue;
                uintptr_t list = (uintptr_t)(sec[s].addr + slide);
                size_t cnt = (size_t)(sec[s].size / sizeof(uintptr_t));
                for (size_t k = 0; k < cnt; k++) {
                    uintptr_t slot = list + k * sizeof(uintptr_t);
                    if (!okRange(slot, sizeof(uintptr_t), ic->lo, ic->hi)) break;
                    uintptr_t cls = rdPtr(slot);
                    uintptr_t ro = roOf(cls, ic->lo, ic->hi);
                    if (!ro || !okRange(ro, 32, ic->lo, ic->hi)) continue;
                    char *cname = dupCStr(rdPtr(ro + 24), ic->lo, ic->hi);
                    if (!cname) continue;
                    parseMethods(ro, '-', cname, ic->lo, ic->hi, &arr, &n, &cap);
                    if (okRange(cls, 8, ic->lo, ic->hi)) {           // metaclass -> +methods
                        uintptr_t mro = roOf(rdPtr(cls), ic->lo, ic->hi);
                        if (mro) parseMethods(mro, '+', cname, ic->lo, ic->hi, &arr, &n, &cap);
                    }
                    free(cname);
                }
            }
        }
        p += lc->cmdsize;
    }
    if (n > 1) qsort(arr, n, sizeof(SymEnt), cmpEnt);
    ic->ents = arr; ic->count = n;
}

// ── symbolication ──────────────────────────────────────────────────────────────

static NSString *symbolicate(uintptr_t addr) {
    Dl_info info;
    if (!dladdr((const void *)addr, &info) || !info.dli_fname || !info.dli_fbase) return nil;
    const char *path = info.dli_fname;
    // Skip system images (kept un-symbolicated, matching prior behaviour) and self.
    if (strncmp(path, "/System/Library", 15) == 0) return nil;
    if (strncmp(path, "/usr/lib", 8) == 0) return nil;
    if (strstr(path, "MonitorTweak")) return nil;

    NSString *mod = [[NSString stringWithUTF8String:path] lastPathComponent];

    NSString *result = nil;
    os_unfair_lock_lock(&gLock);
    ImgCache *ic = NULL;
    for (int i = 0; i < gImgN; i++) {
        if (gImgs[i].base == info.dli_fbase) { ic = &gImgs[i]; break; }
    }
    if (!ic && gImgN < MAX_IMAGES) {
        ic = &gImgs[gImgN++];
        memset(ic, 0, sizeof(*ic));
        ic->base = info.dli_fbase;
    }
    if (ic) {
        if (!ic->built) buildImage(ic);
        if (ic->count) {
            size_t lo = 0, hi = ic->count;          // rightmost imp <= addr
            while (lo < hi) { size_t mid = (lo + hi) / 2; if (ic->ents[mid].imp <= addr) lo = mid + 1; else hi = mid; }
            if (lo > 0) {
                SymEnt *e = &ic->ents[lo - 1];
                if (addr - e->imp <= MAX_SYM_OFFSET)
                    result = [NSString stringWithFormat:@"%@`%s + %lu", mod, e->sym, (unsigned long)(addr - e->imp)];
            }
        }
    }
    os_unfair_lock_unlock(&gLock);
    if (result) return result;

    // Fallbacks: nearest exported symbol, else module + offset.
    if (info.dli_sname && info.dli_saddr)
        return [NSString stringWithFormat:@"%@`%s + %lu", mod, info.dli_sname,
                          (unsigned long)(addr - (uintptr_t)info.dli_saddr)];
    return [NSString stringWithFormat:@"%@ + %lu", mod, (unsigned long)(addr - (uintptr_t)info.dli_fbase)];
}

@implementation RestoreSymbol

- (NSMutableArray *)outputCallStackSymbol {
    NSMutableArray *out = [NSMutableArray array];
    NSArray<NSNumber *> *addrs = [NSThread callStackReturnAddresses]; // safe: only walks the stack
    for (NSNumber *na in addrs) {
        NSString *s = symbolicate((uintptr_t)[na unsignedLongLongValue]);
        if (s) [out addObject:s];
    }
    return out;
}

@end
