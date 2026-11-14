#pragma once
// Find 8-byte-aligned pointers to given addresses in the process's writable private memory
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace hr {

struct ScanStats {
    uint64_t bytes_scanned{};
    uint64_t regions{};
    double milliseconds{};
};

// Returns value -> every address holding that value. The plugin core's private heap is skipped (redirecting references must skip the plugin's own containers)
std::unordered_map<uintptr_t, std::vector<uintptr_t>> scan_pointers(const std::vector<uintptr_t>& values, ScanStats& stats);

bool safe_read_ptr(uintptr_t addr, uintptr_t& out);

// SEH filter for guarded reads (__except (read_fault_filter(GetExceptionInformation()))).
// When a read hits another thread's stack guard page, the system clears the page's guard attribute before reporting the exception; that thread's stack limit is then not updated as its stack grows,
// and the next exception unwind terminates the process with STATUS_BAD_STACK (observed 2026-10-30: a thread created after the snapshot had its stack in an old region of the snapshot).
// Here the guard attribute is restored before the exception handler block runs
int read_fault_filter(struct _EXCEPTION_POINTERS* ep);
// VirtualQuery says [addr, addr+len) is readable: committed, not a guard page or NOACCESS (each thread caches the last region looked up)
bool vq_readable(uintptr_t addr, size_t len);

// Whether this is a managed object; safe to call on any address. REFramework's is_managed_object probes the address with IsBadReadPtr; probing another thread's stack guard page
// consumes it, and when that thread's stack later grows the process terminates with STATUS_BAD_STACK (0xC0000028) without a crash dump (observed 2026-10-29);
// on a worker thread this shows up as all resource loading hanging. Here the object header and object info are confirmed readable and the type definition is in the TDB array before calling REFramework
bool managed_object_safe(uintptr_t obj);

// Committed, readable, non-guard memory regions of the process (snapshot from one VirtualQuery walk).
// Used to rule out guard pages before calling APIs that probe addresses with IsBadReadPtr (such as REFramework's is_managed_object):
// probing another thread's stack guard page invalidates it, and that thread crashes when its stack grows later (STATUS_BAD_STACK, observed)
// Registered as this thread's current snapshot on construction: while it exists, vq_readable looks up the snapshot directly (background scan threads decide from the snapshot instead of calling VirtualQuery each time)
class ReadableMap {
public:
    ReadableMap();
    ~ReadableMap();
    ReadableMap(const ReadableMap&) = delete;
    ReadableMap& operator=(const ReadableMap&) = delete;
    // Whether [addr, addr+len) lies entirely within one readable region
    bool readable(uintptr_t addr, size_t len) const;
    // Start of the readable region containing addr; 0 if not readable
    uintptr_t region_start(uintptr_t addr) const;

private:
    struct Range {
        uintptr_t base, end;
    };
    const Range* find(uintptr_t addr) const;
    std::vector<Range> m_ranges;
};

}
