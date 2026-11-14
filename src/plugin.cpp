// file_hotreload core entry (loaded by the loader loader.cpp; can be hot-swapped while the game runs)
// Watches the natives directory; after a file is saved, evicts the resource cache, reloads it and replaces references.
#include <Windows.h>

#include <string>

#include <reframework/API.hpp>

#include "crash_trace.hpp"
#include "hotreload.hpp"

extern "C" __declspec(dllexport) bool core_init(const REFrameworkPluginInitializeParam* param) {
    reframework::API::initialize(param);
    // Crash records: same directory as the plugin log
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)&core_init, &self);
    wchar_t exe[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring path = exe;
    path = path.substr(0, path.find_last_of(L"\\/") + 1) + L"reframework\\data\\file_hotreload_crash.log";
    hr::crash_trace_install(path.c_str(), self);
    return true;
}

extern "C" __declspec(dllexport) void core_frame() {
    hr::HotReload::get().on_frame();
}

// Called by the loader after each engine update phase (application entry) ends
extern "C" __declspec(dllexport) void core_entry() {
    hr::HotReload::get().on_entry();
}

extern "C" __declspec(dllexport) void core_shutdown() {
    hr::HotReload::get().shutdown();
    hr::crash_trace_remove();
}
