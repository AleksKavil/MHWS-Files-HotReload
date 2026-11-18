#pragma once
#include <atomic>
#include <cstdint>

namespace hr {

// Processing step the current thread is in (shown in crash records); set before critical steps
extern thread_local const char* g_trace_note;

// Install the vectored exception handler that records unexpected access violations etc. to path; crash_trace_remove must be called before the core unloads
void crash_trace_install(const wchar_t* path, void* self_module);
void crash_trace_remove();
// Append a plain text line (printf format) to the same file, e.g. "feature disabled" notes; each distinct text is written once per core load.
// Call only from normal code, not from inside exception handlers
void crash_trace_note(const char* fmt, ...);
// Access violations caused by this thread accessing [lo, hi) from now on are expected (counted, not recorded); (0, 0) cancels
void crash_trace_expect(uintptr_t lo, uintptr_t hi);

} // namespace hr
