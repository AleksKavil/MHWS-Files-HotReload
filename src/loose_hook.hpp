#pragma once
// Makes loose files added to natives while the game runs readable immediately
//
// REFramework's LooseFileLoader hooks the engine's "path -> hash" function (MHWilds: sub_14B042C10, argument is the full file path);
// when the file exists on disk it returns LOOSE_FILE_MARK and the engine reads from disk instead of the pak. It caches "exists" in global + thread_local sets,
// never checks the disk again after the first "missing" decision, and the thread_local part cannot be cleared from outside, so files added after the game starts do not work for paths already requested.
//
// Here another layer is chained on the same function: call the existing chain (REFramework's hook) first; if the result is not LOOSE_FILE_MARK, the path is registered by the plugin
// and the file really exists on disk, return LOOSE_FILE_MARK. If the function start is already a 5-byte jmp written by REFramework, only the jump target of these 5 bytes is replaced atomically;
// when not hooked, the first 5 bytes are push r15/push r14/push rsi, which are position-independent and can be copied into the trampoline as is.
// The hook lives in the loader (resident, not unloaded with core hot swaps); the core registers paths through the exported loader_force_loose.
#include <cstdint>

namespace hr {

// Install the hook; returns true on success or if already installed. log is used to report the result
bool loose_hook_install(void (*log_info)(const char*, ...), void (*log_error)(const char*, ...));

// Entry filter for ResourceManager::create_resource(manager, REType*, path): a non-null return is used as the result directly (it must already hold one reference, same as an engine cache hit);
// a null return falls through to the original function. The hook stays resident in the loader; before a core hot swap the filter is set to null (setting it waits for in-flight calls to finish)
using CreateResourceFilter = void* (*)(void* manager, void* type, const wchar_t* path);

// Set the logging functions used when the hooks are installed
void loader_hooks_set_log(void (*log_info)(const char*, ...), void (*log_error)(const char*, ...));

// When the engine closes a DirectStorage file it releases the object in its table once too often; REFramework LooseTextureLoader routes loose textures through it as well.
// Hook that function and AddRef once when closing a loose texture to offset it (vanilla paks untouched). Returns true on success or if already installed
bool dstorage_close_fix_install(void (*log_info)(const char*, ...), void (*log_error)(const char*, ...));

}


// Set the create_resource filter (installs the hook the first time a non-null filter is set; called on the main thread). Returns true on success
extern "C" __declspec(dllexport) bool loader_set_create_filter(hr::CreateResourceFilter filter);

// Register a path to be force-read as a loose file (natives-relative path such as "natives/STM/Art/a.pfb.18"; any separator and case)
extern "C" __declspec(dllexport) void loader_force_loose(const wchar_t* natives_path);

// Decision counters of a registered path: loose is how many times the path hash returned the loose marker (forced is how many of those were forced by the plugin), missing is how many times
// the file was not visible on disk and the pak hash was returned. Returns false if the path is not registered
extern "C" __declspec(dllexport) bool loader_loose_stats(const wchar_t* natives_path, uint32_t* loose, uint32_t* forced, uint32_t* missing);
