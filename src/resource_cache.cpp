#include <Windows.h>
#include <algorithm>
#include <cstring>
#include <cwctype>
#include <unordered_set>

#include <reframework/API.hpp>

#include "memory_scan.hpp"
#include "resource_cache.hpp"

namespace hr {

namespace {
constexpr uintptr_t RM_LOCK = 0x490;
constexpr uintptr_t RM_BUCKET_COUNT = 0xDF8;
constexpr uintptr_t RM_SIZE = 0xE00;
constexpr uintptr_t RM_BUCKETS = 0xE18;

constexpr uintptr_t NODE_NEXT = 0x0;
constexpr uintptr_t NODE_BUCKET = 0x8;
constexpr uintptr_t NODE_KEY = 0x10;
constexpr uintptr_t NODE_RES = 0x18;

constexpr uintptr_t RES_PATH = 0x8;
constexpr uintptr_t RES_REFCOUNT = 0x28;
constexpr uintptr_t RES_KEY = 0x30;
constexpr uintptr_t RES_READY = 0x38;

constexpr uint64_t BUCKET_MASK = 0x7FFFFFFFFFFFFFFFull;
constexpr size_t MAX_PATH_CHARS = 512;

template <typename T> T rd(uintptr_t a) { return *(T*)a; }

// Raw reads live in functions without C++ objects so SEH can be used
bool safe_read_u64(uintptr_t addr, uint64_t& out) {
    __try {
        out = *(volatile uint64_t*)addr;
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

size_t safe_read_wstr(uintptr_t addr, wchar_t* buf, size_t cap) {
    __try {
        size_t i = 0;
        for (; i + 1 < cap; ++i) {
            wchar_t c = ((volatile wchar_t*)addr)[i];
            if (c == 0) break;
            buf[i] = c;
        }
        buf[i] = 0;
        return i;
    } __except (read_fault_filter(GetExceptionInformation())) {
        buf[0] = 0;
        return 0;
    }
}

size_t safe_read_str(uintptr_t addr, char* buf, size_t cap) {
    __try {
        size_t i = 0;
        for (; i + 1 < cap; ++i) {
            char c = ((volatile char*)addr)[i];
            if (c == 0) break;
            buf[i] = c;
        }
        buf[i] = 0;
        return i;
    } __except (read_fault_filter(GetExceptionInformation())) {
        buf[0] = 0;
        return 0;
    }
}

// Extension -> resource type map (std::map red-black tree node: +0x00 left, +0x08 parent, +0x10 right, +0x19 is-head flag, +0x20 key, +0x28 value)
constexpr uintptr_t RM_TYPE_MAP = 0xE20;
constexpr uintptr_t RM_TYPE_MAP_SIZE = 0xE28;
constexpr uintptr_t MAP_LEFT = 0x00;
constexpr uintptr_t MAP_PARENT = 0x08;
constexpr uintptr_t MAP_RIGHT = 0x10;
constexpr uintptr_t MAP_ISNIL = 0x19;
constexpr uintptr_t MAP_KEY = 0x20;
constexpr uintptr_t MAP_VALUE = 0x28;
constexpr uintptr_t RETYPE_NAME = 0x20;
constexpr uint64_t MAX_TYPE_ENTRIES = 4096;

bool map_isnil(uintptr_t node) {
    uint64_t v = 0;
    return !safe_read_u64(node + MAP_ISNIL - 1, v) || ((v >> 8) & 0xFF) != 0;
}

std::string type_name_of(uintptr_t type) {
    uint64_t name = 0;
    if (type == 0 || !safe_read_u64(type + RETYPE_NAME, name) || name == 0) return {};
    char buf[160];
    safe_read_str((uintptr_t)name, buf, sizeof(buf));
    // Accept only printable type names (guards against reading unrelated memory if the layout does not match)
    for (const char* p = buf; *p; ++p) {
        if (*p < 0x20 || *p > 0x7E) return {};
    }
    return buf;
}

struct SharedLock {
    PSRWLOCK l;
    explicit SharedLock(uintptr_t rm) : l((PSRWLOCK)(rm + RM_LOCK)) { AcquireSRWLockShared(l); }
    ~SharedLock() { ReleaseSRWLockShared(l); }
};

struct ExclusiveLock {
    PSRWLOCK l;
    explicit ExclusiveLock(uintptr_t rm) : l((PSRWLOCK)(rm + RM_LOCK)) { AcquireSRWLockExclusive(l); }
    ~ExclusiveLock() { ReleaseSRWLockExclusive(l); }
};

// Same per-character rule as normalize: '\\' treated as '/', lowercase
inline wchar_t fold_char(wchar_t c) {
    if (c == L'\\') return L'/';
    if (c >= L'A' && c <= L'Z') return (wchar_t)(c + (L'a' - L'A'));
    if (c >= 0x80) return (wchar_t)std::towlower(c);
    return c;
}

// Whether a resource path in engine memory (wchar_t string) equals the normalized path t (strip: like normalize, first skip a leading '/' and one '@').
// Compared in place character by character, returning at the first difference without copying the string: copying and normalizing every path while walking the whole cache table (about 120k entries) takes about 10 ms,
// all while holding the resource table lock (observed 2026-11-08: saving a mesh cost the main thread an extra 10 ms because of it)
bool path_matches_at(uintptr_t str, const wchar_t* t, size_t n, bool strip = false) {
    __try {
        auto p = (const volatile wchar_t*)str;
        if (strip) {
            while (*p == L'/' || *p == L'\\') ++p;
            if (*p == L'@') ++p;
        }
        size_t i = 0;
        for (; i < n; ++i) {
            const wchar_t c = p[i];
            if (c == 0 || fold_char(c) != t[i]) return false;
        }
        return p[i] == 0;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

// Whether the path (same rules, leading characters not skipped) starts with the normalized f
bool path_prefix_at(uintptr_t str, const wchar_t* f, size_t n) {
    __try {
        const auto p = (const volatile wchar_t*)str;
        for (size_t i = 0; i < n; ++i) {
            const wchar_t c = p[i];
            if (c == 0 || fold_char(c) != f[i]) return false;
        }
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

// Whether the path (same rules, leading characters not skipped) contains the normalized fragment f; scanned in place without copying
bool path_contains_at(uintptr_t str, const wchar_t* f, size_t n) {
    if (n == 0) return true;
    __try {
        const auto p = (const volatile wchar_t*)str;
        for (size_t i = 0; i < MAX_PATH_CHARS && p[i] != 0; ++i) {
            size_t k = 0;
            while (k < n && p[i + k] != 0 && fold_char(p[i + k]) == f[k]) ++k;
            if (k == n) return true;
        }
        return false;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

template <typename F> void walk_nodes(uintptr_t rm, F&& fn) {
    const auto bucket_count = rd<uint64_t>(rm + RM_BUCKET_COUNT);
    const auto buckets = rd<uintptr_t>(rm + RM_BUCKETS);
    const auto size = rd<uint64_t>(rm + RM_SIZE);
    uint64_t node = 0;
    if (!safe_read_u64(buckets + 8 * bucket_count, node)) return;

    // Defensive: at most size*2+16 steps, to avoid looping forever if the list is corrupt
    for (uint64_t steps = 0; node != 0 && steps < size * 2 + 16; ++steps) {
        uint64_t bucket = 0, res = 0, next = 0;
        if (!safe_read_u64(node + NODE_BUCKET, bucket) || !safe_read_u64(node + NODE_RES, res) ||
            !safe_read_u64(node + NODE_NEXT, next)) {
            return;
        }
        // Nodes with the top bit set are skipped by the engine's lookup; skip them here too
        if ((int64_t)bucket >= 0 && res != 0) {
            if (!fn((uintptr_t)node, (uintptr_t)res)) return;
        }
        node = next;
    }
}
}

namespace {
// Cache key = XXH64(UTF-16LE bytes of the resource path as is, seed 0xFFFFFFFF): create_resource (1.42.0.3 0x140061578) calls 0x14B00EE80 with wcslen*2 bytes
// and seed 0xFFFFFFFF to get the key, matching XXH64 (verified 2026-11-09 with the key of 11_ring_000_ALBA.tex). Case-sensitive;
// per-material texture copies created by mdf2 and loose textures re-keyed by REFramework do not match, so path lookups fall back to a walk when not found. check_layout samples it at startup
bool g_key_lookup_ok = false;

uint64_t xxh64(const uint8_t* p, size_t len, uint64_t seed) {
    constexpr uint64_t P1 = 11400714785074694791ull, P2 = 14029467366897019727ull, P3 = 1609587929392839161ull,
                       P4 = 9650029242287828579ull, P5 = 2870177450012600261ull;
    const auto rotl = [](uint64_t x, int r) { return (x << r) | (x >> (64 - r)); };
    const auto round = [&](uint64_t acc, uint64_t in) { return rotl(acc + in * P2, 31) * P1; };
    const auto merge = [&](uint64_t h, uint64_t v) { return (h ^ round(0, v)) * P1 + P4; };
    const auto r64 = [](const uint8_t* q) { uint64_t v; memcpy(&v, q, 8); return v; };
    const auto r32 = [](const uint8_t* q) { uint32_t v; memcpy(&v, q, 4); return (uint64_t)v; };
    const uint8_t* const end = p + len;
    uint64_t h = 0;
    if (len >= 32) {
        uint64_t v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1;
        for (; p + 32 <= end; p += 32) {
            v1 = round(v1, r64(p));
            v2 = round(v2, r64(p + 8));
            v3 = round(v3, r64(p + 16));
            v4 = round(v4, r64(p + 24));
        }
        h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
        h = merge(merge(merge(merge(h, v1), v2), v3), v4);
    } else {
        h = seed + P5;
    }
    h += len;
    for (; p + 8 <= end; p += 8) h = rotl(h ^ round(0, r64(p)), 27) * P1 + P4;
    if (p + 4 <= end) {
        h = rotl(h ^ (r32(p) * P1), 23) * P2 + P3;
        p += 4;
    }
    for (; p < end; ++p) h = rotl(h ^ (*p * P5), 11) * P1;
    h ^= h >> 33;
    h *= P2;
    h ^= h >> 29;
    h *= P3;
    h ^= h >> 32;
    return h;
}

uint64_t path_key(const wchar_t* path, size_t n) {
    return xxh64((const uint8_t*)path, n * sizeof(wchar_t), 0xFFFFFFFFull);
}

// Same as the engine lookup: the first node with the same key in the key's bucket (skipping nodes with the top bit set). Caller holds the lock
uintptr_t first_with_key(uintptr_t rm, uint64_t key) {
    const auto bucket_count = rd<uint64_t>(rm + RM_BUCKET_COUNT);
    const auto buckets = rd<uintptr_t>(rm + RM_BUCKETS);
    if (bucket_count == 0 || rd<uint64_t>(rm + RM_SIZE) == 0) return 0;
    const auto b = key % bucket_count;
    uint64_t pred = 0, n = 0;
    if (!safe_read_u64(buckets + 8 * b, pred) || pred == 0 || !safe_read_u64(pred + NODE_NEXT, n)) return 0;
    for (int steps = 0; n != 0 && steps < 100000; ++steps) {
        uint64_t nb = 0, nk = 0, nr = 0, next = 0;
        if (!safe_read_u64(n + NODE_BUCKET, nb) || !safe_read_u64(n + NODE_NEXT, next)) return 0;
        if ((int64_t)nb >= 0) {
            if ((nb & BUCKET_MASK) != b) return 0;
            if (!safe_read_u64(n + NODE_KEY, nk) || !safe_read_u64(n + NODE_RES, nr)) return 0;
            if (nk == key) return (uintptr_t)nr;
        }
        n = next;
    }
    return 0;
}

// Compute the key from the path as is and look up the bucket directly (O(1)); the resource path must equal normalized. Returns 0 if not found (the caller walks the table). Caller holds the lock
uintptr_t find_keyed(uintptr_t rm, const std::wstring& path, const std::wstring& normalized) {
    if (!g_key_lookup_ok || path.empty()) return 0;
    std::wstring k = path;
    for (auto& c : k) {
        if (c == L'\\') c = L'/';
    }
    size_t start = 0;
    while (start < k.size() && k[start] == L'/') ++start;
    if (start < k.size() && k[start] == L'@') ++start;
    const auto res = first_with_key(rm, path_key(k.c_str() + start, k.size() - start));
    uint64_t path_ptr = 0;
    if (res == 0 || !safe_read_u64(res + RES_PATH, path_ptr) || path_ptr == 0 ||
        !path_matches_at((uintptr_t)path_ptr, normalized.c_str(), normalized.size(), true)) {
        return 0;
    }
    return res;
}
}

uintptr_t ResourceCache::manager() {
    return (uintptr_t)reframework::API::get()->get_native_singleton("via.ResourceManager");
}

bool ResourceCache::validate(std::string& err) {
    const auto rm = manager();
    if (rm == 0) {
        err = "via.ResourceManager singleton not found";
        return false;
    }
    uint64_t bc = 0, size = 0, buckets = 0;
    if (!safe_read_u64(rm + RM_BUCKET_COUNT, bc) || !safe_read_u64(rm + RM_SIZE, size) ||
        !safe_read_u64(rm + RM_BUCKETS, buckets)) {
        err = "failed to read resource table";
        return false;
    }
    if (bc == 0 || bc > 100000000ull || buckets == 0 || size > bc * 8) {
        char buf[256];
        sprintf_s(buf, "resource table layout mismatch: bucket_count=%llu size=%llu buckets=%llx", bc, size, buckets);
        err = buf;
        return false;
    }
    return true;
}

std::wstring ResourceCache::normalize(std::wstring path) {
    for (auto& c : path) {
        c = c == L'\\' ? L'/' : (wchar_t)std::towlower(c);
    }
    while (!path.empty() && path.front() == L'/') path.erase(path.begin());
    if (!path.empty() && path.front() == L'@') path.erase(path.begin());
    return path;
}

bool ResourceCache::read_entry(uintptr_t res, ResourceEntry& out) {
    uint64_t path_ptr = 0, key = 0, ready = 0;
    if (!safe_read_u64(res + RES_PATH, path_ptr) ||
        !safe_read_u64(res + RES_KEY, key) || !safe_read_u64(res + RES_READY, ready)) {
        return false;
    }
    wchar_t buf[MAX_PATH_CHARS];
    safe_read_wstr((uintptr_t)path_ptr, buf, MAX_PATH_CHARS);
    out.resource = res;
    out.key = key;
    out.ready = (ready & 0xFF) != 0;
    out.path = buf;
    return true;
}

std::vector<ResourceEntry> ResourceCache::list(const std::wstring& filter, size_t limit, const std::vector<uintptr_t>& vtables) {
    std::vector<ResourceEntry> result{};
    const auto rm = manager();
    if (rm == 0) return result;

    const auto f = normalize(filter);
    SharedLock lock{rm};
    walk_nodes(rm, [&](uintptr_t node, uintptr_t res) {
        // Filter by vtable first, then by path in place; read the entry (copying the path) only for matches
        uint64_t path_ptr = 0, vt = 0;
        if (!vtables.empty() && (!safe_read_u64(res, vt) || std::find(vtables.begin(), vtables.end(), (uintptr_t)vt) == vtables.end())) return true;
        if (!f.empty() && (!safe_read_u64(res + RES_PATH, path_ptr) || path_ptr == 0 || !path_contains_at((uintptr_t)path_ptr, f.c_str(), f.size()))) {
            return true;
        }
        ResourceEntry e{};
        if (read_entry(res, e)) {
            safe_read_u64(node + NODE_KEY, e.node_key);
            result.push_back(std::move(e));
        }
        return result.size() < limit;
    });
    return result;
}

bool ResourceCache::path_matches(uintptr_t str, const std::wstring& normalized) {
    return str != 0 && path_matches_at(str, normalized.c_str(), normalized.size(), true);
}

std::unordered_map<std::wstring, uintptr_t> ResourceCache::find_many(const std::vector<std::wstring>& paths) {
    std::unordered_map<std::wstring, uintptr_t> found{};
    const auto rm = manager();
    if (rm == 0 || paths.empty()) return found;
    std::unordered_set<std::wstring> targets{};
    const auto ext_of = [](const std::wstring& n) {
        const auto dot = n.find_last_of(L'.');
        return dot == std::wstring::npos ? std::wstring{} : n.substr(dot);
    };
    std::unordered_map<std::wstring, uintptr_t> ext_vtable{}; // Resources found by key: extension -> vtable
    SharedLock lock{rm};
    // Look up buckets by key first; the ones not found (not loaded, path case differs from the cache, per-material copies, etc.) are then resolved together in a single walk
    for (const auto& p : paths) {
        auto n = normalize(p);
        if (found.contains(n)) continue;
        if (const auto keyed = find_keyed(rm, p, n); keyed != 0) {
            targets.erase(n);
            if (uint64_t vt = 0; safe_read_u64(keyed, vt) && vt != 0) ext_vtable.try_emplace(ext_of(n), (uintptr_t)vt);
            found.emplace(std::move(n), keyed);
        } else {
            targets.insert(std::move(n));
        }
    }
    if (targets.empty()) return found;
    const auto keyed_found = found.size();
    // Common prefix of all paths: compare the prefix in place first, and copy the whole path for a table lookup only when it matches
    std::wstring prefix = *targets.begin();
    for (const auto& t : targets) {
        size_t i = 0;
        while (i < prefix.size() && i < t.size() && prefix[i] == t[i]) ++i;
        prefix.resize(i);
    }
    // When the vtables of all remaining paths' extensions are already known from resources found by key (resources of the same extension are the same class), compare vtables first while walking
    // without reading paths (a texture cascade looking up 6 uvs with 4 of them not loaded took about 3 ms walking by path)
    std::vector<uintptr_t> vtables{};
    for (const auto& t : targets) {
        const auto it = ext_vtable.find(ext_of(t));
        if (it == ext_vtable.end()) {
            vtables.clear();
            break;
        }
        if (std::find(vtables.begin(), vtables.end(), it->second) == vtables.end()) vtables.push_back(it->second);
    }
    walk_nodes(rm, [&](uintptr_t, uintptr_t res) {
        uint64_t path_ptr = 0, vt = 0;
        if (!vtables.empty() && (!safe_read_u64(res, vt) || std::find(vtables.begin(), vtables.end(), (uintptr_t)vt) == vtables.end())) return true;
        if (!safe_read_u64(res + RES_PATH, path_ptr) || path_ptr == 0) return true;
        if (!prefix.empty() && !path_prefix_at((uintptr_t)path_ptr, prefix.c_str(), prefix.size())) return true;
        wchar_t buf[MAX_PATH_CHARS];
        safe_read_wstr((uintptr_t)path_ptr, buf, MAX_PATH_CHARS);
        std::wstring p{buf};
        for (auto& c : p) c = fold_char(c);
        if (targets.contains(p)) found.try_emplace(std::move(p), res); // Same as find: take the first one encountered while walking
        return found.size() < keyed_found + targets.size();
    });
    return found;
}

uintptr_t ResourceCache::find(const std::wstring& path) {
    const auto rm = manager();
    if (rm == 0) return 0;

    const auto target = normalize(path);
    uintptr_t found = 0;
    SharedLock lock{rm};
    if (const auto keyed = find_keyed(rm, path, target); keyed != 0) return keyed;
    walk_nodes(rm, [&](uintptr_t, uintptr_t res) {
        uint64_t path_ptr = 0;
        if (!safe_read_u64(res + RES_PATH, path_ptr) || path_ptr == 0) return true;
        if (path_matches_at((uintptr_t)path_ptr, target.c_str(), target.size())) {
            found = res;
            return false;
        }
        return true;
    });
    return found;
}

std::vector<uintptr_t> ResourceCache::find_all(const std::wstring& path, uintptr_t vtable) {
    std::vector<uintptr_t> found{};
    const auto rm = manager();
    if (rm == 0) return found;
    const auto target = normalize(path);
    SharedLock lock{rm};
    walk_nodes(rm, [&](uintptr_t, uintptr_t res) {
        uint64_t path_ptr = 0, vt = 0;
        if (vtable != 0 && (!safe_read_u64(res, vt) || vt != vtable)) return true; // All entries of the same path have the same resource type
        if (!safe_read_u64(res + RES_PATH, path_ptr) || path_ptr == 0) return true;
        if (path_matches_at((uintptr_t)path_ptr, target.c_str(), target.size())) found.push_back(res);
        return true;
    });
    return found;
}

bool ResourceCache::evict(uintptr_t resource) {
    const auto rm = manager();
    if (rm == 0 || resource == 0) return false;

    ExclusiveLock lock{rm};

    const auto bucket_count = rd<uint64_t>(rm + RM_BUCKET_COUNT);
    const auto buckets = rd<uintptr_t>(rm + RM_BUCKETS);
    const auto key = rd<uint64_t>(resource + RES_KEY);
    const auto b = key % bucket_count;

    // Locate the node and its predecessor within bucket b (buckets[b] is the predecessor of the first node)
    uintptr_t pred = rd<uintptr_t>(buckets + 8 * b);
    if (pred == 0) return false;

    uintptr_t node = 0;
    for (uintptr_t p = pred, n = rd<uintptr_t>(p); n != 0; p = n, n = rd<uintptr_t>(n)) {
        const auto nb = rd<uint64_t>(n + NODE_BUCKET);
        if ((int64_t)nb >= 0 && (nb & BUCKET_MASK) != b) break; // Walked out of bucket b
        if (rd<uint64_t>(n + NODE_KEY) == key && rd<uintptr_t>(n + NODE_RES) == resource) {
            pred = p;
            node = n;
            break;
        }
    }
    if (node == 0) return false;

    const auto next = rd<uintptr_t>(node + NODE_NEXT);
    *(uintptr_t*)(pred + NODE_NEXT) = next;

    // Same as the bucket fix-up logic in sub_14B0051B0
    if (next != 0) {
        const auto nb = rd<uint64_t>(next + NODE_BUCKET) & BUCKET_MASK;
        if (nb != b) {
            *(uintptr_t*)(buckets + 8 * nb) = pred;
            if (rd<uintptr_t>(buckets + 8 * b) == pred) *(uintptr_t*)(buckets + 8 * b) = 0;
        }
    } else if (rd<uintptr_t>(buckets + 8 * b) == pred) {
        *(uintptr_t*)(buckets + 8 * b) = 0;
    }

    --*(uint64_t*)(rm + RM_SIZE);
    // Node memory (32 bytes) is not returned, to avoid mismatching the engine allocator; each reload leaks only one node
    *(uintptr_t*)(node + NODE_NEXT) = 0;
    *(uintptr_t*)(node + NODE_RES) = 0;
    return true;
}

uint32_t ResourceCache::ext_crc(const std::wstring& ext) {
    static const auto table = [] {
        std::vector<uint32_t> t(256);
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    uint32_t crc = 0xFFFFFFFFu;
    for (const wchar_t ch : ext) {
        for (const uint8_t b : {(uint8_t)(ch & 0xFF), (uint8_t)(ch >> 8)}) crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF];
    }
    return crc;
}

std::string ResourceCache::resource_type_for_ext(const std::wstring& ext) {
    const auto rm = manager();
    if (rm == 0 || ext.empty()) return {};
    std::wstring e = ext;
    for (auto& c : e) c = (wchar_t)std::towlower(c);
    const auto crc = ext_crc(e);
    uint64_t head = 0, node = 0;
    if (!safe_read_u64(rm + RM_TYPE_MAP, head) || head == 0 || !safe_read_u64(head + MAP_PARENT, node)) return {};
    // Same lower_bound as the engine: when key >= crc, remember it and go left, otherwise go right
    uintptr_t best = 0;
    for (uint64_t steps = 0; node != 0 && !map_isnil(node) && steps < 64; ++steps) {
        uint64_t key = 0, next = 0;
        if (!safe_read_u64(node + MAP_KEY, key)) return {};
        if ((uint32_t)key >= crc) {
            best = node;
            if (!safe_read_u64(node + MAP_LEFT, next)) return {};
        } else if (!safe_read_u64(node + MAP_RIGHT, next)) {
            return {};
        }
        node = next;
    }
    uint64_t key = 0, type = 0;
    if (best == 0 || !safe_read_u64(best + MAP_KEY, key) || (uint32_t)key != crc || !safe_read_u64(best + MAP_VALUE, type)) return {};
    return type_name_of((uintptr_t)type);
}

std::vector<std::pair<uint32_t, std::string>> ResourceCache::resource_types() {
    std::vector<std::pair<uint32_t, std::string>> out{};
    const auto rm = manager();
    uint64_t head = 0, root = 0, size = 0;
    if (rm == 0 || !safe_read_u64(rm + RM_TYPE_MAP, head) || head == 0 || !safe_read_u64(head + MAP_PARENT, root) ||
        !safe_read_u64(rm + RM_TYPE_MAP_SIZE, size) || size > MAX_TYPE_ENTRIES) {
        return out;
    }
    // In-order traversal (explicit stack, steps bounded by the table size)
    std::vector<uintptr_t> stack{};
    uintptr_t node = (uintptr_t)root;
    for (uint64_t steps = 0; (node != 0 && !map_isnil(node)) || !stack.empty(); ++steps) {
        if (steps > size * 4 + 16) break;
        if (node != 0 && !map_isnil(node)) {
            stack.push_back(node);
            uint64_t left = 0;
            if (!safe_read_u64(node + MAP_LEFT, left)) break;
            node = (uintptr_t)left;
            continue;
        }
        node = stack.back();
        stack.pop_back();
        uint64_t key = 0, type = 0, right = 0;
        if (!safe_read_u64(node + MAP_KEY, key) || !safe_read_u64(node + MAP_VALUE, type) || !safe_read_u64(node + MAP_RIGHT, right)) break;
        out.emplace_back((uint32_t)key, type_name_of((uintptr_t)type));
        node = (uintptr_t)right;
    }
    return out;
}

bool ResourceCache::listed(uintptr_t resource) {
    const auto rm = manager();
    uint64_t key = 0;
    if (rm == 0 || resource == 0 || !safe_read_u64(resource + RES_KEY, key)) return false;
    SharedLock lock{rm};
    return first_with_key(rm, key) == resource;
}

namespace {
// The part of the engine's release that hands a resource whose count reached zero to the resource thread for destruction (1.42.0.3, 0x14B006090 + 0x321):
//   mov ecx,2; call <thread flag>; lea rcx,[rbx+68h]; mov [rsp+38h],rsi; lea rdx,[rsp+38h]; call <lock-free queue push>; mov ecx,1; xor eax,eax;
//   lock cmpxchg [rbx+5E8h],ecx; jne; mov rcx,[rbx+5E0h]; call [<wake function>]
// rbx is the ResourceManager. Located by a signature at the start of release; offsets and function addresses are read from the machine code
struct DestroyQueue {
    using PushFn = void (*)(uintptr_t queue, uintptr_t* value);
    using WakeFn = void(__stdcall*)(uintptr_t handle);
    PushFn push{};
    WakeFn wake{};
    uint32_t queue{}, flag{}, event{};
    uintptr_t release{}; // Engine release function (check_layout verifies the offset immediates in it)
    std::string error{};
};

// All positions of a wildcard signature (-1 is any byte) within [start, start+size)
std::vector<uintptr_t> scan_pattern(uintptr_t start, size_t size, const std::vector<int>& pat, size_t limit) {
    std::vector<uintptr_t> out{};
    if (size < pat.size()) return out;
    const auto p = (const uint8_t*)start;
    for (size_t i = 0; i + pat.size() <= size && out.size() < limit; ++i) {
        size_t k = 0;
        for (; k < pat.size(); ++k) {
            if (pat[k] >= 0 && p[i + k] != (uint8_t)pat[k]) break;
        }
        if (k == pat.size()) out.push_back(start + i);
    }
    return out;
}

std::vector<int> parse_pattern(const char* text) {
    std::vector<int> pat{};
    for (const char* s = text; *s;) {
        if (*s == ' ') {
            ++s;
        } else if (*s == '?') {
            pat.push_back(-1);
            while (*s == '?') ++s;
        } else {
            pat.push_back((int)strtoul(s, nullptr, 16));
            s += 2;
        }
    }
    return pat;
}

const DestroyQueue& destroy_queue() {
    static const DestroyQueue q = [] {
        DestroyQueue r{};
        const auto base = (uintptr_t)GetModuleHandleW(nullptr);
        const auto nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
        // Start of release: save registers, read the ResourceManager global, copy the key onto the stack, lock dec [rcx+28h]
        const auto head = parse_pattern("41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC 48 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 44 24 40 "
                                        "48 8B 1D ?? ?? ?? ?? 48 8B 41 30 48 89 44 24 38 F0 FF 44 24 34 F0 FF 49 28 0F 85");
        std::vector<uintptr_t> found{};
        auto section = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
            if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
            auto hits = scan_pattern(base + section->VirtualAddress, section->Misc.VirtualSize, head, 4);
            found.insert(found.end(), hits.begin(), hits.end());
        }
        if (found.size() != 1) {
            r.error = "resource release function signature matched " + std::to_string(found.size()) + " times";
            return r;
        }
        const auto fn = found[0];
        r.release = fn;
        const auto push_pat = parse_pattern("48 8D 4B ?? 48 89 74 24 38 48 8D 54 24 38 E8");
        const auto wake_pat = parse_pattern("B9 01 00 00 00 31 C0 F0 0F B1 8B ?? ?? ?? ?? 75 ?? 48 8B 8B ?? ?? ?? ?? FF 15");
        const auto push_at = scan_pattern(fn, 0x600, push_pat, 2);
        const auto wake_at = scan_pattern(fn, 0x600, wake_pat, 2);
        if (push_at.size() != 1 || wake_at.size() != 1 || wake_at[0] < push_at[0] || wake_at[0] - push_at[0] > 0x20) {
            r.error = "enqueue code for the pending-destroy queue not found in the resource release function";
            return r;
        }
        const auto p = push_at[0];
        r.queue = *(const uint8_t*)(p + 3);
        r.push = (DestroyQueue::PushFn)(p + 19 + *(const int32_t*)(p + 15));
        const auto w = wake_at[0];
        r.flag = *(const uint32_t*)(w + 11);
        r.event = *(const uint32_t*)(w + 20);
        const auto import_slot = w + 30 + *(const int32_t*)(w + 26);
        r.wake = *(DestroyQueue::WakeFn*)import_slot;
        if (r.wake == nullptr) r.error = "function that wakes the resource thread is null";
        return r;
    }();
    return q;
}

DWORD call_push(DestroyQueue::PushFn push, uintptr_t queue, uintptr_t* value) {
    __try {
        push(queue, value);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}
}

bool ResourceCache::check_layout(std::string& report) {
    const auto rm = manager();
    if (rm == 0) {
        report = "ResourceManager singleton is null";
        return false;
    }
    std::vector<std::string> problems{};
    // (1) release machine code: the start signature already contains mov rax,[rcx+30h] (key) and lock dec [rcx+28h] (reference count); here the table and state flag immediates are checked as well
    const auto& q = destroy_queue();
    std::string code{};
    if (q.release != 0) {
        const std::pair<const char*, const char*> literals[] = {
            {"48 8D BB 90 04 00 00", "resource table lock +0x490"},     {"4C 8B 83 F8 0D 00 00", "bucket count +0xDF8"},
            {"48 83 BB 00 0E 00 00 00", "element count +0xE00"},    {"48 8B 83 18 0E 00 00", "bucket array +0xE18"},
            {"80 4E 3B 02", "resource state flags +0x3B"},
        };
        for (const auto& [pat, what] : literals) {
            if (scan_pattern(q.release, 0x400, parse_pattern(pat), 1).empty()) problems.push_back(std::string{"release lacks "} + what);
        }
        code = "release machine code checked";
    } else {
        code = "release not located (" + q.error + "), sampling only";
    }
    // (2) Sample the cache table: a node's bucket index matches its key, resource +0x30 key equals the node's, reference count is plausible, path is readable, load flag is 0/1
    uint32_t total = 0, bad_bucket = 0, bad_key = 0, bad_refs = 0, bad_path = 0, bad_ready = 0, key_match = 0;
    {
        SharedLock lock{rm};
        uint64_t bucket_count = 0;
        if (!safe_read_u64(rm + RM_BUCKET_COUNT, bucket_count) || bucket_count == 0) {
            report = "hash table bucket count unreadable";
            return false;
        }
        walk_nodes(rm, [&](uintptr_t node, uintptr_t res) {
            uint64_t bucket = 0, key = 0, rkey = 0, refs = 0, ready = 0, path = 0;
            ++total;
            if (!safe_read_u64(node + NODE_BUCKET, bucket) || !safe_read_u64(node + NODE_KEY, key) || (bucket & BUCKET_MASK) != key % bucket_count) ++bad_bucket;
            if (!safe_read_u64(res + RES_KEY, rkey) || rkey != key) ++bad_key;
            if (!safe_read_u64(res + RES_REFCOUNT, refs) || (int32_t)(uint32_t)refs < 0 || (int32_t)(uint32_t)refs > (1 << 24)) ++bad_refs;
            if (!safe_read_u64(res + RES_READY, ready) || (ready & 0xFF) > 1) ++bad_ready;
            wchar_t buf[MAX_PATH_CHARS];
            const auto len = safe_read_u64(res + RES_PATH, path) && path != 0 ? safe_read_wstr((uintptr_t)path, buf, MAX_PATH_CHARS) : 0;
            bool printable = len >= 3;
            for (size_t i = 0; printable && i < len; ++i) printable = buf[i] >= 0x20;
            if (!printable) ++bad_path;
            if (printable && path_key(buf, len) == key) ++key_match;
            return total < 4096;
        });
    }
    const auto ratio_bad = [&](uint32_t n) { return total == 0 || n * 50 > total; }; // More than 2% inconsistent means failure
    if (total < 32) problems.push_back("cache table has only " + std::to_string(total) + " entries, not enough samples");
    if (ratio_bad(bad_bucket)) problems.push_back("node bucket does not match key " + std::to_string(bad_bucket) + "/" + std::to_string(total));
    if (ratio_bad(bad_key)) problems.push_back("resource +0x30 key does not match node " + std::to_string(bad_key) + "/" + std::to_string(total));
    if (ratio_bad(bad_refs)) problems.push_back("resource +0x28 reference count abnormal " + std::to_string(bad_refs) + "/" + std::to_string(total));
    if (ratio_bad(bad_path)) problems.push_back("resource +0x08 path unreadable " + std::to_string(bad_path) + "/" + std::to_string(total));
    if (ratio_bad(bad_ready)) problems.push_back("resource +0x38 load flag abnormal " + std::to_string(bad_ready) + "/" + std::to_string(total));
    // A failed key algorithm check does not affect the plugin; path lookups just always walk the table
    g_key_lookup_ok = problems.empty() && total > 0 && key_match * 10 >= total * 8;
    const auto key_note = ", keys computed from paths match " + std::to_string(key_match) + "/" + std::to_string(total) + (g_key_lookup_ok ? "" : ", too few: lookups by path fall back to walking the table");
    if (problems.empty()) {
        report = "Resource objects and cache table: passed (" + code + ", sampled " + std::to_string(total) + " entries" + key_note + ")";
        return true;
    }
    report = "Resource objects and cache table: FAILED (" + code + "): ";
    for (size_t i = 0; i < problems.size(); ++i) report += (i ? "; " : "") + problems[i];
    return false;
}

bool ResourceCache::destroy_supported(std::string* err) {
    const auto& q = destroy_queue();
    if (err != nullptr) *err = q.error;
    return q.error.empty();
}

bool ResourceCache::destroy_unlisted(uintptr_t resource) {
    constexpr uintptr_t RES_STATE_FLAGS = 0x3B;
    const auto& q = destroy_queue();
    const auto rm = manager();
    if (!q.error.empty() || rm == 0 || resource == 0) return false;
    if (listed(resource)) return false;
    // Atomically drop to zero only when the caller holds the last reference; if someone adds a reference meanwhile (CAS fails), do not destroy
    if (InterlockedCompareExchange((volatile LONG*)(resource + RES_REFCOUNT), 0, 1) != 1) return false;
    _InterlockedOr8((volatile char*)(resource + RES_STATE_FLAGS), 2);
    uintptr_t value = resource;
    if (call_push(q.push, rm + q.queue, &value) != 0) return true; // Already at zero: the reference cannot be restored even if the enqueue fails
    if (InterlockedCompareExchange((volatile LONG*)(rm + q.flag), 1, 0) == 0) q.wake(*(uintptr_t*)(rm + q.event));
    return true;
}

bool ResourceCache::replace(uintptr_t from, uintptr_t to) {
    const auto rm = manager();
    if (rm == 0 || from == 0 || to == 0) return false;
    if (rd<uint64_t>(from + RES_KEY) != rd<uint64_t>(to + RES_KEY)) return false;
    ExclusiveLock lock{rm};
    bool done = false;
    walk_nodes(rm, [&](uintptr_t node, uintptr_t res) {
        if (res != from) return true;
        *(volatile uintptr_t*)(node + NODE_RES) = to;
        done = true;
        return false;
    });
    return done;
}

}
