// Crash trace: a vectored exception handler records access violations, guard page violations, stack overflows, etc. at the very start of exception dispatch,
// writing them to reframework/data/file_hotreload_crash.log (each entry flushed immediately). The file is created only when the first such exception is
// recorded, so normal sessions leave no file behind.
// When the process terminates with STATUS_BAD_STACK (0xC0000028) neither REFramework nor WER writes a dump; this is the only way to locate the faulting thread and code
#include "crash_trace.hpp"

#include <Windows.h>

#include <atomic>
#include <cstdio>
#include <cwchar>
#include <iterator>

namespace hr {

thread_local const char* g_trace_note = "";

namespace {
thread_local uintptr_t t_expect_lo = 0, t_expect_hi = 0;
}

void crash_trace_expect(uintptr_t lo, uintptr_t hi) {
    t_expect_lo = lo;
    t_expect_hi = hi;
}

namespace {

struct Module {
    const char* name;
    uintptr_t begin, end;
};

HANDLE g_file = INVALID_HANDLE_VALUE;
wchar_t g_path[MAX_PATH]{};
SYSTEMTIME g_loaded{};            // When this core was loaded (written as the session header before its first record)
SRWLOCK g_open_lock = SRWLOCK_INIT; // Several threads may hit their first exception at the same time
PVOID g_handler = nullptr;
DWORD g_main_tid = 0;
Module g_modules[6]{};
size_t g_module_count = 0;
std::atomic<int> g_lines{0};
std::atomic<int> g_expected{0};
constexpr int MAX_LINES = 300;

void add_module(const char* name, HMODULE m) {
    if (m == nullptr || g_module_count >= std::size(g_modules)) return;
    const auto base = (uintptr_t)m;
    const auto dos = (const IMAGE_DOS_HEADER*)base;
    const auto nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    g_modules[g_module_count++] = {name, base, base + nt->OptionalHeader.SizeOfImage};
}

const Module* module_of(uintptr_t a) {
    for (size_t i = 0; i < g_module_count; ++i) {
        if (a >= g_modules[i].begin && a < g_modules[i].end) return &g_modules[i];
    }
    return nullptr;
}

int format_addr(char* out, size_t n, uintptr_t a) {
    if (const auto m = module_of(a)) return _snprintf_s(out, n, _TRUNCATE, "%s+%llx", m->name, (unsigned long long)(a - m->begin));
    return _snprintf_s(out, n, _TRUNCATE, "%llx", (unsigned long long)a);
}

// Create (or append to) the crash log on the first record of this core load, preceded by a session header line
void open_file() {
    AcquireSRWLockExclusive(&g_open_lock);
    if (g_file == INVALID_HANDLE_VALUE && g_path[0] != 0) {
        const auto h = CreateFileW(g_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            char buf[128];
            const auto len = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "==== %04d-%02d-%02d %02d:%02d:%02d core loaded, main thread %lu ====\r\n", g_loaded.wYear,
                                         g_loaded.wMonth, g_loaded.wDay, g_loaded.wHour, g_loaded.wMinute, g_loaded.wSecond, g_main_tid);
            DWORD written = 0;
            if (len > 0) WriteFile(h, buf, (DWORD)len, &written, nullptr);
            g_file = h;
        }
    }
    ReleaseSRWLockExclusive(&g_open_lock);
}

void write_line(const char* s, int len) {
    if (len <= 0) return;
    if (g_file == INVALID_HANDLE_VALUE) open_file();
    if (g_file == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(g_file, s, (DWORD)len, &written, nullptr);
    FlushFileBuffers(g_file);
}

LONG CALLBACK on_exception(PEXCEPTION_POINTERS ep) {
    const auto rec = ep->ExceptionRecord;
    const auto code = rec->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != STATUS_GUARD_PAGE_VIOLATION && code != EXCEPTION_STACK_OVERFLOW && code != 0xC0000028 &&
        code != 0xC0000374 && code != EXCEPTION_ILLEGAL_INSTRUCTION && code != EXCEPTION_PRIV_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const auto addr = (uintptr_t)rec->ExceptionAddress;
    const auto m = module_of(addr);
    // Expected access violations: IsBadReadPtr (kernelbase) and this plugin's guarded reads, only counted
    const bool in_expected = code == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters > 1 && rec->ExceptionInformation[1] >= t_expect_lo &&
                             rec->ExceptionInformation[1] < t_expect_hi;
    if (in_expected || (code == EXCEPTION_ACCESS_VIOLATION && m != nullptr && (m == &g_modules[0] || m == &g_modules[1]))) {
        ++g_expected;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (g_lines.fetch_add(1) >= MAX_LINES) return EXCEPTION_CONTINUE_SEARCH;

    char buf[2048];
    int len = 0;
    SYSTEMTIME t{};
    GetLocalTime(&t);
    const auto tid = GetCurrentThreadId();
    char where[96];
    format_addr(where, sizeof(where), addr);
    const auto info0 = rec->NumberParameters > 0 ? (unsigned long long)rec->ExceptionInformation[0] : 0ull;
    const auto info1 = rec->NumberParameters > 1 ? (unsigned long long)rec->ExceptionInformation[1] : 0ull;
    const auto note = g_trace_note;
    len = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "[%02d:%02d:%02d.%03d] Exception %08lX at %s, thread %lu%s, access %llu @ %llx, marker: %s (%d expected violations before)\r\n  Stack:",
                      t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, code, where, tid, tid == g_main_tid ? " (main thread)" : "", info0, info1,
                      note ? note : "", g_expected.load());
    // Values on the stack that fall inside known modules (return address candidates), searched upward within this thread's stack range
    const auto ctx = ep->ContextRecord;
    const auto tib = (const NT_TIB*)NtCurrentTeb();
    const auto stack_lo = (uintptr_t)tib->StackLimit, stack_hi = (uintptr_t)tib->StackBase;
    auto sp = (uintptr_t)ctx->Rsp & ~(uintptr_t)7;
    int found = 0;
    if (sp >= stack_lo && sp < stack_hi) {
        for (auto p = sp; p + 8 <= stack_hi && p < sp + 0x4000 && found < 28; p += 8) {
            const auto v = *(const uintptr_t*)p;
            if (module_of(v) == nullptr) continue;
            char a[96];
            format_addr(a, sizeof(a), v);
            len += _snprintf_s(buf + len, sizeof(buf) - len, _TRUNCATE, " %s", a);
            ++found;
        }
    } else {
        len += _snprintf_s(buf + len, sizeof(buf) - len, _TRUNCATE, " rsp %llx is outside this thread's stack [%llx, %llx)", (unsigned long long)sp,
                           (unsigned long long)stack_lo, (unsigned long long)stack_hi);
    }
    len += _snprintf_s(buf + len, sizeof(buf) - len, _TRUNCATE, "\r\n");
    write_line(buf, len);
    return EXCEPTION_CONTINUE_SEARCH;
}

} // namespace

void crash_trace_install(const wchar_t* path, void* self_module) {
    if (g_handler != nullptr) return;
    wcsncpy_s(g_path, path, _TRUNCATE);
    GetLocalTime(&g_loaded);
    g_main_tid = GetCurrentThreadId();
    // Order: 0 kernelbase, 1 this plugin's core (access violations inside these two are expected); the rest are used to label addresses
    add_module("kernelbase", GetModuleHandleW(L"kernelbase.dll"));
    add_module("core", (HMODULE)self_module);
    add_module("exe", GetModuleHandleW(nullptr));
    add_module("ntdll", GetModuleHandleW(L"ntdll.dll"));
    add_module("reframework", GetModuleHandleW(L"dinput8.dll"));
    add_module("loader", GetModuleHandleW(L"file_hotreload.dll"));
    g_handler = AddVectoredExceptionHandler(1, on_exception);
}

void crash_trace_remove() {
    if (g_handler != nullptr) {
        RemoveVectoredExceptionHandler(g_handler);
        g_handler = nullptr;
    }
    if (g_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
}

} // namespace hr
