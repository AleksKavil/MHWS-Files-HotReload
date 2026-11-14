#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

#include <reframework/API.hpp>

#include "memory_scan.hpp"
#include "core_heap.hpp"

namespace hr {

int read_fault_filter(EXCEPTION_POINTERS* ep) {
    const auto r = ep->ExceptionRecord;
    if (r->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION && r->NumberParameters >= 2) {
        const auto page = (uintptr_t)r->ExceptionInformation[1] & ~(uintptr_t)0xFFF;
        MEMORY_BASIC_INFORMATION mbi{};
        DWORD old = 0;
        if (VirtualQuery((LPCVOID)page, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0) {
            VirtualProtect((LPVOID)page, 0x1000, mbi.Protect | PAGE_GUARD, &old);
        }
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

namespace {
struct Region {
    uintptr_t base;
    size_t size;
};

// A single region is scanned in a function without C++ objects so SEH can be used; hits go into a fixed-size buffer
size_t scan_region_raw(uintptr_t base, size_t size, const uintptr_t* values, size_t value_count, uintptr_t lo,
                       uintptr_t hi, uintptr_t* hits, size_t hit_cap) {
    size_t n = 0;
    __try {
        const auto* p = (const volatile uintptr_t*)base;
        const auto* end = (const volatile uintptr_t*)(base + (size & ~(size_t)7));
        for (; p < end; ++p) {
            const uintptr_t v = *p;
            if (v < lo || v > hi) continue;
            for (size_t i = 0; i < value_count; ++i) {
                if (v == values[i]) {
                    if (n < hit_cap) hits[n++] = (uintptr_t)p;
                    break;
                }
            }
        }
    } __except (read_fault_filter(GetExceptionInformation())) {
    }
    return n;
}

std::vector<Region> collect_regions(uint64_t& total) {
    std::vector<Region> regions{};
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    auto addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const auto max_addr = (uintptr_t)si.lpMaximumApplicationAddress;
    total = 0;

    // Allocations containing guard pages (thread stacks) are skipped entirely: they hold none of the holders we look for, and guard pages move as stacks grow, so they may no longer be where the snapshot says
    std::vector<Region> pending{};
    uint64_t pending_size = 0;
    uintptr_t alloc = 0;
    bool has_guard = false;
    // Memory of the plugin core's private heap (the plugin's own containers) is skipped entirely, see core_heap.cpp
    auto own = core_heap_allocations();
    std::sort(own.begin(), own.end());
    auto is_own = [&](uintptr_t base) { return std::binary_search(own.begin(), own.end(), base); };
    auto flush = [&] {
        if (!has_guard) {
            regions.insert(regions.end(), pending.begin(), pending.end());
            total += pending_size;
        }
        pending.clear();
        pending_size = 0;
        has_guard = false;
    };
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < max_addr && VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const auto base = (uintptr_t)mbi.BaseAddress;
        if ((uintptr_t)mbi.AllocationBase != alloc) {
            flush();
            alloc = (uintptr_t)mbi.AllocationBase;
        }
        const auto prot = mbi.Protect & 0xFF;
        const bool writable = prot == PAGE_READWRITE || prot == PAGE_EXECUTE_READWRITE;
        const bool bad = (mbi.Protect & (PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)) != 0;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) != 0) has_guard = true;
        if (is_own((uintptr_t)mbi.AllocationBase)) has_guard = true; // Likewise skipped entirely
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && writable && !bad) {
            // Split large regions into chunks to balance threads
            constexpr size_t CHUNK = 64ull * 1024 * 1024;
            for (size_t off = 0; off < mbi.RegionSize; off += CHUNK) {
                pending.push_back({base + off, std::min(CHUNK, (size_t)mbi.RegionSize - off)});
            }
            pending_size += mbi.RegionSize;
        }
        addr = base + mbi.RegionSize;
    }
    flush();
    return regions;
}
}

namespace {
thread_local const ReadableMap* t_map = nullptr; // This thread's current snapshot of readable regions (see vq_readable)
}

ReadableMap::ReadableMap() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    auto addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const auto max_addr = (uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < max_addr && VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const auto base = (uintptr_t)mbi.BaseAddress;
        const auto end = base + mbi.RegionSize;
        const auto prot = mbi.Protect & 0xFF;
        const bool readable = prot == PAGE_READONLY || prot == PAGE_READWRITE || prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                              prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
        if (mbi.State == MEM_COMMIT && readable && (mbi.Protect & PAGE_GUARD) == 0) {
            // Merge adjacent readable regions (objects may straddle region boundaries returned by VirtualQuery)
            if (!m_ranges.empty() && m_ranges.back().end == base) {
                m_ranges.back().end = end;
            } else {
                m_ranges.push_back({base, end});
            }
        }
        addr = end;
    }
    if (t_map == nullptr) t_map = this;
}

ReadableMap::~ReadableMap() {
    if (t_map == this) t_map = nullptr;
}

const ReadableMap::Range* ReadableMap::find(uintptr_t addr) const {
    auto it = std::upper_bound(m_ranges.begin(), m_ranges.end(), addr, [](uintptr_t a, const Range& r) { return a < r.base; });
    if (it == m_ranges.begin()) return nullptr;
    --it;
    return addr < it->end ? &*it : nullptr;
}

bool ReadableMap::readable(uintptr_t addr, size_t len) const {
    const auto r = find(addr);
    return r != nullptr && addr + len <= r->end;
}

uintptr_t ReadableMap::region_start(uintptr_t addr) const {
    const auto r = find(addr);
    return r != nullptr ? r->base : 0;
}

// No readability check: an SEH read of a guard page consumes it just the same; callers must confirm unknown addresses are readable first
// (background threads use the ReadableMap snapshot; the main thread checks objects with managed_object_safe)
bool safe_read_ptr(uintptr_t addr, uintptr_t& out) {
    __try {
        out = *(volatile uintptr_t*)addr;
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

bool vq_readable(uintptr_t addr, size_t len) {
    // Each thread caches the 64 readable regions looked up most recently (objects are spread across many heap regions; caching only one meant a VirtualQuery almost every time,
    // which measured as hot-reload main-thread time rising from about 5 ms to about 90 ms and background scans 2-3x slower)
    constexpr size_t N = 64;
    thread_local uintptr_t base[N]{}, end[N]{};
    thread_local size_t next = 0;
    if (addr + len < addr) return false;
    if (t_map != nullptr) return t_map->readable(addr, len); // Background scan threads: decide from the snapshot
    for (size_t i = 0; i < N; ++i) {
        if (addr >= base[i] && addr + len <= end[i]) return true;
    }
    MEMORY_BASIC_INFORMATION mbi{};
    if (addr < 0x10000 || VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 || (mbi.Protect & 0xFF) == 0) return false;
    const auto b = (uintptr_t)mbi.BaseAddress, e = b + mbi.RegionSize;
    if (addr + len > e) return false; // Spans regions: be conservative
    base[next] = b;
    end[next] = e;
    next = (next + 1) % N;
    return true;
}

namespace {
bool is_managed_raw(uintptr_t obj) {
    __try {
        return reframework::API::get()->sdk()->managed_object->is_managed_object((void*)obj);
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}
}

bool managed_object_safe(uintptr_t obj) {
    // Range of the TDB type definition array: object +0x00 is the object info, object info +0x00 is the type definition (an entry of the array)
    static const auto range = [] {
        struct R {
            uintptr_t begin, end, stride;
        } r{};
        const auto tdb = reframework::API::get()->tdb();
        const auto n = tdb->get_num_types();
        if (n >= 2) {
            r.begin = (uintptr_t)tdb->get_type(0);
            r.stride = (uintptr_t)tdb->get_type(1) - r.begin;
            r.end = r.begin + r.stride * n;
        }
        return r;
    }();
    uintptr_t info = 0, td = 0;
    if (obj == 0 || (obj & 7) != 0 || range.stride == 0) return false;
    if (!vq_readable(obj, 0x10) || !safe_read_ptr(obj, info) || !vq_readable(info, 8) || !safe_read_ptr(info, td)) return false;
    if (td < range.begin || td >= range.end || (td - range.begin) % range.stride != 0) return false;
    return is_managed_raw(obj);
}

std::unordered_map<uintptr_t, std::vector<uintptr_t>> scan_pointers(const std::vector<uintptr_t>& values, ScanStats& stats) {
    std::unordered_map<uintptr_t, std::vector<uintptr_t>> result{};
    if (values.empty()) return result;

    const auto start = std::chrono::steady_clock::now();
    const auto regions = collect_regions(stats.bytes_scanned);
    stats.regions = regions.size();

    const auto [lo_it, hi_it] = std::minmax_element(values.begin(), values.end());
    const uintptr_t lo = *lo_it, hi = *hi_it;

    std::atomic<size_t> next{0};
    std::mutex mtx{};
    const auto thread_count = std::max(1u, std::min(16u, std::thread::hardware_concurrency()));
    std::vector<std::thread> threads{};

    for (unsigned t = 0; t < thread_count; ++t) {
        threads.emplace_back([&]() {
            std::vector<uintptr_t> hits(4096);
            // Only scan regions in the snapshot that are committed, private, writable and free of guard pages (collect_regions). No per-chunk VirtualQuery re-check during the scan:
            // 16 threads issuing frequent VirtualQuery calls at once measured as slowing the scan from about 0.4 s to 1-2.6 s
            for (size_t i = next++; i < regions.size(); i = next++) {
                const auto n = scan_region_raw(regions[i].base, regions[i].size, values.data(), values.size(), lo, hi,
                                               hits.data(), hits.size());
                if (n == 0) continue;
                std::scoped_lock _{mtx};
                for (size_t k = 0; k < n; ++k) {
                    uintptr_t v = 0;
                    if (safe_read_ptr(hits[k], v)) result[v].push_back(hits[k]);
                }
            }
        });
    }
    for (auto& th : threads) th.join();

    stats.milliseconds =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    return result;
}

}
