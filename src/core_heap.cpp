// Private heap for the core module: all operator new/delete of this module go through it, and the background memory scan skips its memory entirely.
// Reason: when scanning the whole process for references to old objects, the plugin's own containers (old-object lists, maps, etc.) live in the scanned memory too;
// if a container happens to be allocated on memory of a freed managed object, the leftover object header makes the scan treat the container as an "object holding a reference",
// rewrite it to the new object's address and release the old object on its behalf, causing a double release (observed 2026-10-30: an old component was reclaimed early, then a write to freed memory crashed)
#include "core_heap.hpp"

#include <Windows.h>

#include <cstdlib>
#include <new>

namespace hr {

// All cores (every version across hot swaps) share one heap: its handle is stored in a process environment variable and reused by cores loaded later.
// After an old core unloads its heap still exists (holding stale container data); if each core created its own heap, the new core's scan would not skip the old heap and the stale data would be taken for holders
// (observed 2026-11-08: a reference search hit an address used by the previous scan inside the old core's heap)
HANDLE core_heap() {
    static const HANDLE heap = [] {
        constexpr const wchar_t* VAR = L"FILE_HOTRELOAD_CORE_HEAP";
        wchar_t buf[32]{};
        if (GetEnvironmentVariableW(VAR, buf, 32) > 0) {
            const auto saved = (HANDLE)(uintptr_t)wcstoull(buf, nullptr, 16);
            HANDLE heaps[1024];
            const auto n = GetProcessHeaps(1024, heaps);
            for (DWORD i = 0; i < n && i < 1024; ++i) {
                if (heaps[i] == saved) return saved;
            }
        }
        const auto created = HeapCreate(0, 0, 0);
        if (created != nullptr) {
            swprintf_s(buf, L"%llx", (unsigned long long)(uintptr_t)created);
            SetEnvironmentVariableW(VAR, buf);
        }
        return created;
    }();
    return heap;
}

std::vector<uintptr_t> core_heap_allocations() {
    std::vector<uintptr_t> bases{};
    bases.reserve(16384); // No allocation on this heap while walking it (it would modify the heap being walked)
    const auto heap = core_heap();
    if (heap == nullptr || !HeapLock(heap)) return bases;
    PROCESS_HEAP_ENTRY e{};
    auto add = [&](const void* p) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (bases.size() < bases.capacity() && p != nullptr && VirtualQuery(p, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.AllocationBase != nullptr) {
            bases.push_back((uintptr_t)mbi.AllocationBase);
        }
    };
    while (HeapWalk(heap, &e)) {
        if ((e.wFlags & PROCESS_HEAP_REGION) != 0) {
            add(e.Region.lpFirstBlock);
        } else if ((e.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0 && e.cbData >= 0x7F000) {
            add(e.lpData); // Large blocks are VirtualAlloc'ed separately by the heap
        }
    }
    HeapUnlock(heap);
    return bases;
}

} // namespace hr

namespace {
void* heap_alloc(size_t n) {
    return HeapAlloc(hr::core_heap(), 0, n != 0 ? n : 1);
}

// Aligned allocation: request align + one pointer extra; the original address is stored just before the returned address
void* heap_alloc_aligned(size_t n, size_t align) {
    if (align <= 16) return heap_alloc(n);
    auto raw = (uintptr_t)heap_alloc(n + align + sizeof(void*));
    if (raw == 0) return nullptr;
    const auto p = (raw + sizeof(void*) + align - 1) & ~(uintptr_t)(align - 1);
    ((uintptr_t*)p)[-1] = raw;
    return (void*)p;
}

void heap_free(void* p) {
    if (p != nullptr) HeapFree(hr::core_heap(), 0, p);
}

void heap_free_aligned(void* p, size_t align) {
    if (p == nullptr) return;
    if (align <= 16) return heap_free(p);
    heap_free((void*)((uintptr_t*)p)[-1]);
}
} // namespace

void* operator new(size_t n) {
    if (auto p = heap_alloc(n)) return p;
    throw std::bad_alloc{};
}
void* operator new[](size_t n) {
    if (auto p = heap_alloc(n)) return p;
    throw std::bad_alloc{};
}
void* operator new(size_t n, const std::nothrow_t&) noexcept {
    return heap_alloc(n);
}
void* operator new[](size_t n, const std::nothrow_t&) noexcept {
    return heap_alloc(n);
}
void* operator new(size_t n, std::align_val_t a) {
    if (auto p = heap_alloc_aligned(n, (size_t)a)) return p;
    throw std::bad_alloc{};
}
void* operator new[](size_t n, std::align_val_t a) {
    if (auto p = heap_alloc_aligned(n, (size_t)a)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept {
    heap_free(p);
}
void operator delete[](void* p) noexcept {
    heap_free(p);
}
void operator delete(void* p, size_t) noexcept {
    heap_free(p);
}
void operator delete[](void* p, size_t) noexcept {
    heap_free(p);
}
void operator delete(void* p, const std::nothrow_t&) noexcept {
    heap_free(p);
}
void operator delete[](void* p, const std::nothrow_t&) noexcept {
    heap_free(p);
}
void operator delete(void* p, std::align_val_t a) noexcept {
    heap_free_aligned(p, (size_t)a);
}
void operator delete[](void* p, std::align_val_t a) noexcept {
    heap_free_aligned(p, (size_t)a);
}
void operator delete(void* p, size_t, std::align_val_t a) noexcept {
    heap_free_aligned(p, (size_t)a);
}
void operator delete[](void* p, size_t, std::align_val_t a) noexcept {
    heap_free_aligned(p, (size_t)a);
}
