#include <Windows.h>
#include <Unknwn.h>

#include <algorithm>
#include <initializer_list>
#include <atomic>
#include <cstring>
#include <cwctype>
#include <memory>
#include <unordered_map>
#include <vector>

#include "loose_hook.hpp"

namespace hr {

namespace {
constexpr uint64_t LOOSE_FILE_MARK = 4294967296ull; // Same as REFramework LooseFileLoader

using PathToHashFn = uint64_t (*)(const wchar_t* path);

PathToHashFn g_prev{};
PathToHashFn g_orig{}; // Engine's original function (bypassing REFramework's hook): returns the path hash in the pak
std::atomic<bool> g_installed{false};
std::atomic<uint32_t> g_forced_count{0};
SRWLOCK g_lock = SRWLOCK_INIT;
// Registered path -> decision counters (the core uses them to confirm a reload actually read the loose file). Entries are never removed, so pointers stay stable; counters are atomic
struct LooseStat {
    std::atomic<uint32_t> loose{0};   // Returned the loose marker (REFramework found the file, or forced by the plugin)
    std::atomic<uint32_t> forced{0};  // Of those, forced by the plugin (REFramework decided the file does not exist)
    std::atomic<uint32_t> missing{0}; // File not visible on disk; returned the pak hash
};
std::unordered_map<uint64_t, std::unique_ptr<LooseStat>> g_forced{};

LooseStat* find_stat(uint64_t h) {
    AcquireSRWLockShared(&g_lock);
    const auto it = g_forced.find(h);
    LooseStat* s = it == g_forced.end() ? nullptr : it->second.get();
    ReleaseSRWLockShared(&g_lock);
    return s;
}

// FNV-1a hash starting at "natives/" (case-insensitive, '\\' treated as '/'); returns 0 if there is no "natives/"
uint64_t natives_hash(const wchar_t* path) {
    static const wchar_t k[] = L"natives/";
    const wchar_t* start = nullptr;
    for (const wchar_t* p = path; *p != 0 && start == nullptr; ++p) {
        size_t i = 0;
        for (; k[i] != 0; ++i) {
            wchar_t c = p[i];
            if (c == 0) break;
            if (c == L'\\') c = L'/';
            if ((wchar_t)towlower(c) != k[i]) break;
        }
        if (k[i] == 0) start = p;
    }
    if (start == nullptr) return 0;
    uint64_t h = 1469598103934665603ull;
    for (const wchar_t* p = start; *p != 0; ++p) {
        wchar_t c = *p == L'\\' ? L'/' : (wchar_t)towlower(*p);
        h = (h ^ (uint64_t)c) * 1099511628211ull;
    }
    return h;
}

uint64_t detour(const wchar_t* path) {
    const uint64_t r = g_prev(path);
    if (path == nullptr) return r;
    LooseStat* stat = nullptr;
    if (g_forced_count.load(std::memory_order_relaxed) != 0) {
        if (const auto h = natives_hash(path); h != 0) stat = find_stat(h);
    }
    if (r == LOOSE_FILE_MARK) {
        // REFramework caches "file exists": after the file is deleted or moved it still returns the loose marker, the engine reads a missing file, the load fails and blocks every
        // later resource load (observed three times on 2026-10-29). When the file is no longer on disk, use the engine's original result instead (read from the pak)
        if (g_orig != nullptr && GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
            if (stat != nullptr) stat->missing.fetch_add(1, std::memory_order_relaxed);
            return g_orig(path);
        }
        if (stat != nullptr) stat->loose.fetch_add(1, std::memory_order_relaxed);
        return r;
    }
    // REFramework decided the file does not exist (a file added while the game runs: it caches "missing" per thread): if registered and present on disk, force reading it as a loose file
    if (stat == nullptr) return r;
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        stat->missing.fetch_add(1, std::memory_order_relaxed);
        return r;
    }
    stat->forced.fetch_add(1, std::memory_order_relaxed);
    stat->loose.fetch_add(1, std::memory_order_relaxed);
    return LOOSE_FILE_MARK;
}

// ---- Locating ----

// Instructions of sub_14B042C10 after its first 5 bytes (-1 is a wildcard: call / rip-relative offsets)
const int k_pattern[] = {
    0x57, 0x53, 0xB8, 0x40, 0x10, 0x00, 0x00, 0xE8, -1, -1, -1, -1, 0x48, 0x29, 0xC4, 0x48, 0x89, 0xCE, 0x48, 0x8B, 0x05, -1, -1, -1, -1,
    0x48, 0x31, 0xE0, 0x48, 0x89, 0x84, 0x24, 0x38, 0x10, 0x00, 0x00, 0x48, 0x8D, 0xBC, 0x24, 0x30, 0x08, 0x00, 0x00, 0x41, 0xB8, 0x00,
    0x08, 0x00, 0x00, 0x48, 0x89, 0xF9, 0x31, 0xD2, 0xE8, -1, -1, -1, -1, 0x48, 0x39, 0xF7, 0x74, 0x16, 0x48, 0x8D, 0x8C, 0x24, 0x30,
    0x08, 0x00, 0x00, 0xBA, 0x00, 0x04, 0x00, 0x00, 0x49, 0x89, 0xF0, 0xFF, 0x15,
};
constexpr size_t PATTERN_SKIP = 5; // Offset of the signature from the function start
const uint8_t k_original_head[5] = {0x41, 0x57, 0x41, 0x56, 0x56}; // push r15; push r14; push rsi

// Find a function by signature in the exe's executable sections (the signature starts skip bytes after the function start); returns the function start on a unique match
uintptr_t find_pattern(const int* pattern, size_t n, size_t skip, int& matches) {
    matches = 0;
    const auto base = (uintptr_t)GetModuleHandleW(nullptr);
    const auto nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);
    uintptr_t found = 0;
    for (int s = 0; s < nt->FileHeader.NumberOfSections; ++s, ++section) {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        const auto start = (const uint8_t*)(base + section->VirtualAddress);
        const auto size = (size_t)section->Misc.VirtualSize;
        for (size_t i = skip; i + n <= size; ++i) {
            if (start[i] != pattern[0]) continue;
            size_t k = 1;
            for (; k < n; ++k) {
                if (pattern[k] >= 0 && start[i + k] != (uint8_t)pattern[k]) break;
            }
            if (k == n) {
                ++matches;
                found = (uintptr_t)(start + i - skip);
            }
        }
    }
    return matches == 1 ? found : 0;
}

uintptr_t find_target(int& matches) {
    return find_pattern(k_pattern, sizeof(k_pattern) / sizeof(k_pattern[0]), PATTERN_SKIP, matches);
}

// Allocate executable memory within ±2GB of target (reachable by a rel32 jump): walk free regions with VirtualQuery and take the one closest to target
uint8_t* alloc_near(uintptr_t target, size_t size, DWORD* last_error = nullptr) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const uintptr_t gran = si.dwAllocationGranularity;
    const uintptr_t min_app = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t max_app = (uintptr_t)si.lpMaximumApplicationAddress;
    const uintptr_t reach = 0x7FF00000ull;
    const uintptr_t lo = std::max<uintptr_t>(target > reach ? target - reach : 0, min_app);
    const uintptr_t hi = std::min<uintptr_t>(target + reach, max_app);

    // Collect candidate addresses (in each free region, the allocation-granularity-aligned address closest to target)
    struct Cand {
        uintptr_t addr;
        uintptr_t dist;
    };
    std::vector<Cand> cands{};
    for (uintptr_t a = lo; a < hi;) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery((void*)a, &mbi, sizeof(mbi)) == 0) break;
        const auto rbase = (uintptr_t)mbi.BaseAddress;
        const auto rend = rbase + mbi.RegionSize;
        if (mbi.State == MEM_FREE) {
            const uintptr_t first = (std::max(rbase, lo) + gran - 1) & ~(gran - 1);
            const uintptr_t last = ((std::min(rend, hi) - size) & ~(gran - 1));
            if (first + size <= rend && first <= last) {
                const uintptr_t pick = target < first ? first : (target > last ? last : (target & ~(gran - 1)));
                const uintptr_t dist = pick > target ? pick - target : target - pick;
                cands.push_back({pick, dist});
            }
        }
        if (rend <= a) break;
        a = rend;
    }
    std::sort(cands.begin(), cands.end(), [](const Cand& x, const Cand& y) { return x.dist < y.dist; });
    for (size_t i = 0; i < cands.size(); ++i) {
        if (auto p = VirtualAlloc((void*)cands[i].addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) return (uint8_t*)p;
        if (last_error) *last_error = GetLastError();
    }
    return nullptr;
}

void write_abs_jmp(uint8_t* at, uintptr_t dest) {
    at[0] = 0xFF;
    at[1] = 0x25;
    *(uint32_t*)(at + 2) = 0;
    *(uint64_t*)(at + 6) = dest;
}

// Trampoline layout: +0 jmp [detour]; +16 original function entry when not hooked (original first 5 bytes + jmp target+5)
constexpr size_t STUB_SIZE = 48;
constexpr size_t STUB_TRAMP = 16;
constexpr size_t CAVE_MIN = 96; // Use only 0xCC padding runs that are long enough, and stay away from their ends

// Find the run of 0xCC padding (alignment padding between functions) closest to target in the exe's executable sections; returns a 16-byte-aligned start inside it that fits size bytes
uint8_t* find_cave(uintptr_t target, size_t need = STUB_SIZE) {
    const auto base = (uintptr_t)GetModuleHandleW(nullptr);
    const auto nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);
    uint8_t* best = nullptr;
    uintptr_t best_dist = ~0ull;
    for (int s = 0; s < nt->FileHeader.NumberOfSections; ++s, ++section) {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        const auto start = (uint8_t*)(base + section->VirtualAddress);
        const auto size = (size_t)section->Misc.VirtualSize;
        for (size_t i = 0; i < size;) {
            if (start[i] != 0xCC) {
                ++i;
                continue;
            }
            size_t j = i;
            while (j < size && start[j] == 0xCC) ++j;
            if (j - i >= CAVE_MIN) {
                const auto at = (uintptr_t)(start + i + 32 + 15) & ~(uintptr_t)15;
                if (at + need + 16 <= (uintptr_t)(start + j)) {
                    const auto dist = at > target ? at - target : target - at;
                    if (dist < best_dist && dist < 0x7FF00000ull) {
                        best_dist = dist;
                        best = (uint8_t*)at;
                    }
                }
            }
            i = j;
        }
    }
    return best;
}

bool write_code(uint8_t* dst, const uint8_t* src, size_t n) {
    DWORD old = 0;
    if (!VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(dst, src, n);
    VirtualProtect(dst, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), dst, n);
    return true;
}

// Two-level trampolines: the full trampoline code (position-independent) goes into freshly allocated executable memory; only a 16-byte relay (jmp [rip]) is placed where the hooked site can reach with rel32.
// In the running exe the code section has only one 0xCC padding run long enough, and memory nearby often cannot be allocated (observed 2026-11-03), so all hooks share relay slots in this padding run
constexpr size_t PAD_SIZE = 16;
constexpr size_t PAD_REGION = 96; // Length of a padding run set aside for relay slots (6 of them)
uint8_t* g_far = nullptr;
size_t g_far_used = 0;
uint8_t* g_pad = nullptr;
size_t g_pad_left = 0;
bool g_pad_in_cave = false;

uint8_t* far_alloc(size_t n) {
    n = (n + 15) & ~(size_t)15;
    if (g_far == nullptr) g_far = (uint8_t*)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (g_far == nullptr || g_far_used + n > 0x1000) return nullptr;
    const auto p = g_far + g_far_used;
    g_far_used += n;
    return p;
}

bool in_rel32(uintptr_t from, uintptr_t to) {
    const auto d = (intptr_t)to - (intptr_t)(from + 5);
    return d > -0x7FF00000ll && d < 0x7FF00000ll;
}

uint8_t* pad_alloc(uintptr_t target) {
    if (g_pad_left < PAD_SIZE || !in_rel32(target, (uintptr_t)g_pad)) {
        if (auto c = find_cave(target, PAD_REGION)) {
            g_pad = c;
            g_pad_left = PAD_REGION;
            g_pad_in_cave = true;
        } else if (auto n = alloc_near(target, 0x1000)) {
            g_pad = n;
            g_pad_left = 0x1000;
            g_pad_in_cave = false;
        } else {
            return nullptr;
        }
        if (!in_rel32(target, (uintptr_t)g_pad)) return nullptr;
    }
    const auto p = g_pad;
    g_pad += PAD_SIZE;
    g_pad_left -= PAD_SIZE;
    return p;
}

// Place a trampoline: copy code into newly allocated memory (body) and write a relay jmp body where target can reach it. Returns the relay address (rel32 target) on success
uint8_t* place_stub(uintptr_t target, const uint8_t* code, size_t len, uint8_t** far_out = nullptr) {
    const auto body = far_alloc(len);
    if (body == nullptr) return nullptr;
    memcpy(body, code, len);
    FlushInstructionCache(GetCurrentProcess(), body, len);
    const auto pad = pad_alloc(target);
    if (pad == nullptr) return nullptr;
    uint8_t jmp[PAD_SIZE];
    memset(jmp, 0xCC, sizeof(jmp));
    write_abs_jmp(jmp, (uintptr_t)body);
    if (!write_code(pad, jmp, sizeof(jmp))) return nullptr; // The padding run needs its protection changed temporarily; newly allocated memory is already writable, which works too
    if (far_out) *far_out = body;
    return pad;
}
}

bool loose_hook_install(void (*log_info)(const char*, ...), void (*log_error)(const char*, ...)) {
    if (g_installed.load()) return true;
    int matches = 0;
    const auto target = find_target(matches);
    if (target == 0) {
        log_error("[file_hotreload] Engine path hash function not found (signature matched %d times); loose files added while the game runs take effect only after a restart", matches);
        return false;
    }
    if ((target & 7) != 0) {
        log_error("[file_hotreload] Path hash function %llx is not 8-byte aligned, cannot hook atomically", (unsigned long long)target);
        return false;
    }

    const auto head = *(volatile uint64_t*)target;
    const auto b = (const uint8_t*)&head;
    const bool chained = b[0] == 0xE9;
    if (!chained && memcmp(b, k_original_head, 5) != 0) {
        log_error("[file_hotreload] Path hash function does not start with the expected instructions (%016llx), not hooking", (unsigned long long)head);
        return false;
    }

    uint8_t code[STUB_SIZE];
    memset(code, 0xCC, sizeof(code));
    write_abs_jmp(code, (uintptr_t)&detour);
    // Entry of the engine's original function: the original first 5 bytes (overwritten by REFramework's jmp when it hooks; their content is fixed as k_original_head and the signature confirms the following instructions are unchanged) + jump back to target+5
    memcpy(code + STUB_TRAMP, k_original_head, 5);
    write_abs_jmp(code + STUB_TRAMP + 5, target + 5);
    // Trampoline code goes into newly allocated memory; only the relay goes where it is reachable
    uint8_t* body = nullptr;
    uint8_t* stub = place_stub(target, code, sizeof(code), &body);
    if (stub == nullptr) {
        log_error("[file_hotreload] No usable trampoline location (neither code section padding nor nearby memory is available)");
        return false;
    }
    const bool in_cave = g_pad_in_cave;
    if (chained) {
        // Already hooked by REFramework: its original jump target becomes the previous layer
        const auto rel = *(const int32_t*)(b + 1);
        g_prev = (PathToHashFn)(target + 5 + (intptr_t)rel);
    } else {
        g_prev = (PathToHashFn)(body + STUB_TRAMP);
    }
    g_orig = (PathToHashFn)(body + STUB_TRAMP);

    // Atomically replace the first 8 bytes: E9 rel32(trampoline) + original bytes 5..7
    uint64_t patched = head;
    auto pb = (uint8_t*)&patched;
    pb[0] = 0xE9;
    *(int32_t*)(pb + 1) = (int32_t)((intptr_t)stub - (intptr_t)(target + 5));
    DWORD old = 0;
    if (!VirtualProtect((void*)target, 8, PAGE_EXECUTE_READWRITE, &old)) {
        log_error("[file_hotreload] Failed to change memory protection of the path hash function: %lu", GetLastError());
        return false;
    }
    const auto prev = (uint64_t)InterlockedCompareExchange64((volatile LONG64*)target, (LONG64)patched, (LONG64)head);
    VirtualProtect((void*)target, 8, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void*)target, 8);
    if (prev != head) {
        log_error("[file_hotreload] Path hash function was modified concurrently while hooking, giving up");
        return false;
    }
    g_installed = true;
    log_info("[file_hotreload] Hooked path hash function %llx (%s, trampoline %llx in %s); loose files added while the game runs are read immediately", (unsigned long long)target,
             chained ? "chained after REFramework LooseFileLoader" : "no REFramework hook found, hooked standalone", (unsigned long long)stub,
             in_cave ? "code section padding" : "newly allocated memory");
    return true;
}

// ---- Hook on the ResourceManager::create_resource entry ----
namespace {
using CreateResourceFn = void* (*)(void* manager, void* type, const wchar_t* path);

// Instructions of create_resource after its first 6 bytes (-1 is a wildcard): push r12/rsi/rdi/rbp/rbx; sub rsp,48h; stack guard; check that the path is non-empty and the '@' prefix
const int k_create_pattern[] = {
    0x41, 0x54, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8B, 0x05, -1,   -1,   -1,   -1,   0x48, 0x31, 0xE0,
    0x48, 0x89, 0x44, 0x24, 0x40, 0x4D, 0x85, 0xC0, 0x0F, 0x84, -1,   -1,   -1,   -1,   0x41, 0x0F, 0xB7, 0x28, 0x66, 0x85,
    0xED, 0x0F, 0x84, -1,   -1,   -1,   -1,   0x49, 0x89, 0xD6, 0x48, 0x89, 0xCE, 0x31, 0xC0, 0x66, 0x83, 0xFD, 0x40, 0x0F,
    0x94, 0xC0, 0x49, 0x8D, 0x3C, 0x40, 0x48, 0x89, 0xFA, 0xE8,
};
constexpr size_t CREATE_SKIP = 6;
const uint8_t k_create_head[CREATE_SKIP] = {0x41, 0x57, 0x41, 0x56, 0x41, 0x55}; // push r15; push r14; push r13

CreateResourceFn g_create_prev{};
std::atomic<bool> g_create_installed{false};
SRWLOCK g_filter_lock = SRWLOCK_INIT;
CreateResourceFilter g_filter{};
std::atomic<bool> g_filter_on{false};

void* create_detour(void* manager, void* type, const wchar_t* path) {
    if (g_filter_on.load(std::memory_order_acquire)) {
        void* r = nullptr;
        AcquireSRWLockShared(&g_filter_lock);
        if (g_filter != nullptr) r = g_filter(manager, type, path);
        ReleaseSRWLockShared(&g_filter_lock);
        if (r != nullptr) return r;
    }
    return g_create_prev(manager, type, path);
}

// Install the hook (called on the main thread). If the start is already a jmp written by REFramework (FaultyFileDetector), chain in front of it
bool install_create_hook(void (*log_info)(const char*, ...), void (*log_error)(const char*, ...)) {
    if (g_create_installed.load()) return true;
    int matches = 0;
    const auto target = find_pattern(k_create_pattern, sizeof(k_create_pattern) / sizeof(k_create_pattern[0]), CREATE_SKIP, matches);
    if (target == 0 || (target & 7) != 0) {
        log_error("[file_hotreload] create_resource not found (signature matched %d times, address %llx)", matches, (unsigned long long)target);
        return false;
    }
    const auto head = *(volatile uint64_t*)target;
    const auto b = (const uint8_t*)&head;
    const bool chained = b[0] == 0xE9;
    if (!chained && memcmp(b, k_create_head, CREATE_SKIP) != 0) {
        log_error("[file_hotreload] create_resource does not start with the expected instructions (%016llx), not hooking", (unsigned long long)head);
        return false;
    }
    uint8_t code[STUB_SIZE];
    memset(code, 0xCC, sizeof(code));
    write_abs_jmp(code, (uintptr_t)&create_detour);
    memcpy(code + STUB_TRAMP, k_create_head, CREATE_SKIP);
    write_abs_jmp(code + STUB_TRAMP + CREATE_SKIP, target + CREATE_SKIP);
    uint8_t* body = nullptr;
    uint8_t* stub = place_stub(target, code, sizeof(code), &body);
    if (stub == nullptr) {
        log_error("[file_hotreload] No usable trampoline location for the create_resource hook");
        return false;
    }
    const bool in_cave = g_pad_in_cave;
    if (chained) {
        g_create_prev = (CreateResourceFn)(target + 5 + (intptr_t)*(const int32_t*)(b + 1));
    } else {
        g_create_prev = (CreateResourceFn)(body + STUB_TRAMP);
    }
    // Atomically replace the first 8 bytes: E9 rel32(trampoline) + original bytes 5..7 (instructions after the return point target+6 stay unchanged)
    uint64_t patched = head;
    auto pb = (uint8_t*)&patched;
    pb[0] = 0xE9;
    *(int32_t*)(pb + 1) = (int32_t)((intptr_t)stub - (intptr_t)(target + 5));
    DWORD old = 0;
    if (!VirtualProtect((void*)target, 8, PAGE_EXECUTE_READWRITE, &old)) {
        log_error("[file_hotreload] Failed to change memory protection of create_resource: %lu", GetLastError());
        return false;
    }
    const auto prev = (uint64_t)InterlockedCompareExchange64((volatile LONG64*)target, (LONG64)patched, (LONG64)head);
    VirtualProtect((void*)target, 8, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void*)target, 8);
    if (prev != head) {
        log_error("[file_hotreload] create_resource was modified concurrently while hooking, giving up");
        return false;
    }
    g_create_installed = true;
    log_info("[file_hotreload] Hooked create_resource %llx (%s, trampoline %llx in %s)", (unsigned long long)target,
             chained ? "chained before the REFramework hook" : "hooked standalone", (unsigned long long)stub, in_cave ? "code section padding" : "newly allocated memory");
    return true;
}

void (*g_log_info)(const char*, ...) = nullptr;
void (*g_log_error)(const char*, ...) = nullptr;

// ---- Reference count compensation for closing DirectStorage files ----
// The engine's DirectStorage file close (exe+cf03ac0, 1.42.0.3) only acts when wcsstr(path at extension object+8, L".sub_000.pak") matches; under a lock it looks up in a global std::map
// the node keyed by [extension object] (IDStorageFile*), calls Close -> Release, then erase (which calls Release once more). The map holds only 1 reference,
// so the extra Release drops the count to -1 (observed 2026-11-03: Release inside erase returns 0xFFFFFFFF), and other holders later use a freed object.
// In the vanilla game only sub_000 paks go through here; REFramework LooseTextureLoader routes loose textures whose path contains ".tex." here as well, over-releasing once per close.
// Compensation: at entry, remember whether this close is for a loose texture (same test as LooseTextureLoader); when the node is found and Close is about to run, AddRef once first. Only loose textures are handled; vanilla paks are untouched
const int k_ds_close_pattern[] = {
    0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE, 0x48, 0x83, 0xC1, 0x08, 0x48, 0x8D, 0x15, -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
    -1,   0x48, 0x85, 0xC0, 0x74, 0x42, 0x48, 0x8D, 0x0D, -1,   -1,   -1,   -1,   0xFF, 0x15, -1,   -1,   -1,   -1,   0x48, 0x8B, 0x06, 0x48,
    0x85, 0xC0, 0x74, 0x1A, 0x48, 0x8B, 0x0D, -1,   -1,   -1,   -1,   0x48, 0x8B, 0x51, 0x08, 0x80, 0x7A, 0x19, 0x00, 0x48, 0x89, 0xCE, 0x74,
    0x20, 0x80, 0x7E, 0x19, 0x00, 0x74, 0x38, 0x48, 0x8D, 0x0D, -1,   -1,   -1,   -1,   0x48, 0x83, 0xC4, 0x20, 0x5E, 0x48, 0xFF, 0x25, -1,
    -1,   -1,   -1,   0x90, 0x48, 0x83, 0xC4, 0x20, 0x5E, 0xC3, 0x48, 0x89, 0xCE, 0x4C, 0x8D, 0x42, 0x10, 0x48, 0x39, 0x42, 0x20, 0x48, 0x0F,
    0x43, 0xF2, 0x4C, 0x0F, 0x43, 0xC2, 0x49, 0x8B, 0x10, 0x80, 0x7A, 0x19, 0x00, 0x74, 0xE7, 0xEB, 0xC2, 0x48, 0x3B, 0x46, 0x20, 0x72, 0xC2,
    0x48, 0x39, 0xCE, 0x74, 0xBD, 0x48, 0x8B, 0x4E, 0x28, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x18, 0x48, 0x8B, 0x4E, 0x28, 0x48, 0x8B, 0x01, 0xFF,
    0x50, 0x10, 0x48, 0x8D, 0x0D, -1,   -1,   -1,   -1,   0x48, 0x89, 0xF2, 0xE8, -1,   -1,   -1,   -1,   0xEB, 0x98,
};
constexpr size_t DS_FOUND_OFFSET = 0x8F; // mov rcx,[rsi+28h]; mov rax,[rcx] (rsi is the found node); +0x96 after this is call [rax+18h] (Close)
const uint8_t k_ds_entry_head[8] = {0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE}; // push rsi; sub rsp,20h; mov rsi,rcx
const uint8_t k_ds_found_head[8] = {0x48, 0x8B, 0x4E, 0x28, 0x48, 0x8B, 0x01, 0xFF};
constexpr uintptr_t DS_NODE_KEY = 0x20;
constexpr uintptr_t DS_NODE_FILE = 0x28;

thread_local uintptr_t t_ds_loose_key = 0; // IDStorageFile* of the loose texture this thread is closing
std::atomic<bool> g_ds_installed{false};

bool contains(const wchar_t* s, const wchar_t* sub) {
    return wcsstr(s, sub) != nullptr;
}

void ds_close_entry(uintptr_t ext) {
    t_ds_loose_key = 0;
    if (ext == 0) return;
    __try {
        const auto path = (const wchar_t*)(ext + 8);
        if (contains(path, L".tex.") && !contains(path, L".sub_000.pak")) t_ds_loose_key = *(const uintptr_t*)ext;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        t_ds_loose_key = 0;
    }
}

void ds_close_found(uintptr_t node) {
    const auto key = t_ds_loose_key;
    t_ds_loose_key = 0;
    if (key == 0 || node == 0) return;
    __try {
        if (*(const uintptr_t*)(node + DS_NODE_KEY) != key) return;
        const auto file = *(IUnknown**)(node + DS_NODE_FILE);
        if (file == nullptr) return;
        file->AddRef();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// Save volatile registers and call handler (rcx = rsi when arg_is_rsi, otherwise keep rcx), restore them, run the overwritten original instructions and jump back to back.
// rsp_aligned: rsp is already 16-byte aligned at the hook site (inside a function body); otherwise it is a function entry (rsp ≡ 8)
size_t emit_call_stub(uint8_t* p, void* handler, bool arg_is_rsi, const uint8_t* relocated, size_t relocated_len, uintptr_t back,
                      bool rsp_aligned) {
    size_t n = 0;
    auto put = [&](std::initializer_list<uint8_t> b) {
        for (auto x : b) p[n++] = x;
    };
    // At a function entry rsp ≡ 8 (mod 16): aligned after 7 pushes; inside a body rsp ≡ 0: add pushfq for 8 pushes in total
    if (rsp_aligned) put({0x9C});                                       // pushfq
    put({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53}); // push rax rcx rdx r8 r9 r10 r11
    put({0x48, 0x83, 0xEC, 0x20});                                      // sub rsp,20h
    if (arg_is_rsi) put({0x48, 0x89, 0xF1});                            // mov rcx,rsi
    put({0x48, 0xB8});                                                  // mov rax,imm64
    *(uint64_t*)(p + n) = (uint64_t)handler;
    n += 8;
    put({0xFF, 0xD0});                                                  // call rax
    put({0x48, 0x83, 0xC4, 0x20});                                      // add rsp,20h
    put({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58}); // pop r11 r10 r9 r8 rdx rcx rax
    if (rsp_aligned) put({0x9D});                                       // popfq
    memcpy(p + n, relocated, relocated_len);
    n += relocated_len;
    write_abs_jmp(p + n, back);
    return n + 14;
}

// Atomically rewrite the 8 bytes at at (not crossing a cache line): E9 rel32(stub) + nops up to patch_len, the rest unchanged
bool patch_jmp(uintptr_t at, const uint8_t* expect, size_t patch_len, uint8_t* stub) {
    if (((at & 63) + 8) > 64) return false;
    const auto head = *(volatile uint64_t*)at;
    if (memcmp(&head, expect, 8) != 0) return false;
    uint64_t patched = head;
    auto pb = (uint8_t*)&patched;
    pb[0] = 0xE9;
    *(int32_t*)(pb + 1) = (int32_t)((intptr_t)stub - (intptr_t)(at + 5));
    for (size_t i = 5; i < patch_len; ++i) pb[i] = 0x90;
    DWORD old = 0;
    if (!VirtualProtect((void*)at, 8, PAGE_EXECUTE_READWRITE, &old)) return false;
    const auto prev = (uint64_t)InterlockedCompareExchange64((volatile LONG64*)at, (LONG64)patched, (LONG64)head);
    VirtualProtect((void*)at, 8, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void*)at, 8);
    return prev == head;
}
}

bool dstorage_close_fix_install(void (*log_info)(const char*, ...), void (*log_error)(const char*, ...)) {
    if (g_ds_installed.load()) return true;
    int matches = 0;
    const auto target = find_pattern(k_ds_close_pattern, sizeof(k_ds_close_pattern) / sizeof(k_ds_close_pattern[0]), 0, matches);
    if (target == 0) {
        log_error("[file_hotreload] DirectStorage file close function not found (signature matched %d times); reference counts are not compensated when loose textures are closed", matches);
        return false;
    }
    const auto found = target + DS_FOUND_OFFSET;
    if (memcmp((const void*)target, k_ds_entry_head, 8) != 0 || memcmp((const void*)found, k_ds_found_head, 8) != 0) {
        log_error("[file_hotreload] DirectStorage file close function has already been modified, not compensating");
        return false;
    }
    // Trampolines (position-independent code, generated locally first): entry (original push rsi; sub rsp,20h, 5 bytes, jump back to +5); node-found site (original two movs, 7 bytes, jump back to +7)
    uint8_t entry_code[128], found_code[128];
    memset(entry_code, 0xCC, sizeof(entry_code));
    memset(found_code, 0xCC, sizeof(found_code));
    const auto entry_len = emit_call_stub(entry_code, (void*)&ds_close_entry, false, k_ds_entry_head, 5, target + 5, false);
    const auto found_len = emit_call_stub(found_code, (void*)&ds_close_found, true, k_ds_found_head, 7, found + 7, true);
    // Trampoline code goes into newly allocated memory; only a 16-byte relay goes where it is reachable (code-section padding)
    uint8_t* entry_stub = place_stub(target, entry_code, entry_len);
    uint8_t* found_stub = entry_stub ? place_stub(found, found_code, found_len) : nullptr;
    if (entry_stub == nullptr || found_stub == nullptr) {
        log_error("[file_hotreload] No usable trampoline location for the DirectStorage compensation");
        return false;
    }
    const auto stub = entry_stub;
    // Hook the node-found site first, then the entry: while the entry is not hooked t_ds_loose_key is 0 and the node-found site does nothing
    if (!patch_jmp(found, k_ds_found_head, 7, found_stub)) {
        log_error("[file_hotreload] Failed to patch the DirectStorage file close function (at the node-found site)");
        return false;
    }
    if (!patch_jmp(target, k_ds_entry_head, 5, entry_stub)) {
        log_error("[file_hotreload] Failed to patch the DirectStorage file close function (entry); the hook at the node-found site stays a no-op");
        return false;
    }
    g_ds_installed = true;
    log_info("[file_hotreload] Hooked DirectStorage file close function %llx: one reference is compensated when a loose texture is closed (trampolines %llx, %llx)", (unsigned long long)target,
             (unsigned long long)stub, (unsigned long long)found_stub);
    return true;
}

void loader_hooks_set_log(void (*log_info)(const char*, ...), void (*log_error)(const char*, ...)) {
    g_log_info = log_info;
    g_log_error = log_error;
}

}

extern "C" __declspec(dllexport) bool loader_set_create_filter(hr::CreateResourceFilter filter) {
    using namespace hr;
    if (filter != nullptr && !g_create_installed.load()) {
        if (g_log_info == nullptr || g_log_error == nullptr || !install_create_hook(g_log_info, g_log_error)) return false;
    }
    AcquireSRWLockExclusive(&g_filter_lock);
    g_filter = filter;
    g_filter_on.store(filter != nullptr, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_filter_lock);
    return filter == nullptr || g_create_installed.load();
}

extern "C" __declspec(dllexport) void loader_force_loose(const wchar_t* natives_path) {
    if (natives_path == nullptr) return;
    const auto h = hr::natives_hash(natives_path);
    if (h == 0) return;
    AcquireSRWLockExclusive(&hr::g_lock);
    if (hr::g_forced.try_emplace(h, std::make_unique<hr::LooseStat>()).second) hr::g_forced_count.fetch_add(1);
    ReleaseSRWLockExclusive(&hr::g_lock);
}

extern "C" __declspec(dllexport) bool loader_loose_stats(const wchar_t* natives_path, uint32_t* loose, uint32_t* forced, uint32_t* missing) {
    if (natives_path == nullptr) return false;
    const auto h = hr::natives_hash(natives_path);
    const auto s = h != 0 ? hr::find_stat(h) : nullptr;
    if (s == nullptr) return false;
    if (loose) *loose = s->loose.load();
    if (forced) *forced = s->forced.load();
    if (missing) *missing = s->missing.load();
    return true;
}
