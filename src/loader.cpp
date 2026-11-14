// file_hotreload loader (REFramework plugin)
// Only loads / hot-swaps the core logic file_hotreload_core.dll, so changes to the plugin's own logic need no game restart.
// The core DLL lives in reframework/data/file_hotreload/core/; a shadow copy is loaded so the original can be overwritten at any time.
#include <Windows.h>

#include <filesystem>
#include <string>

#include <reframework/API.h>

#include "loose_hook.hpp"

#ifdef FILE_HOTRELOAD_MERGED
// Single-file build: the core entry points (plugin.cpp) are compiled into the same DLL as the loader
extern "C" bool core_init(const REFrameworkPluginInitializeParam* param);
extern "C" void core_frame();
extern "C" void core_entry();
extern "C" void core_shutdown();
#endif

namespace {
using CoreInitFn = bool (*)(const REFrameworkPluginInitializeParam*);
using CoreFrameFn = void (*)();
using CoreShutdownFn = void (*)();
using CoreEntryFn = void (*)();

const REFrameworkPluginInitializeParam* g_param{};
std::filesystem::path g_core_dir{};
HMODULE g_core{};
CoreFrameFn g_frame{};
CoreShutdownFn g_shutdown{};
CoreEntryFn g_entry{};
DWORD g_main_thread{};

// Per-frame update phases (via.Application entries, in execution order). After each phase the core checks whether the old components being rebuilt have been detached by the engine;
// if so, it attaches the new components and rewrites references inside that callback (no game code runs between detach and attach)
constexpr const char* k_update_entries[] = {
    "UpdateDialog", "UpdateRemoteHost", "UpdateStorage", "UpdateScene", "UpdateDevelopSystem", "UpdateWidget", "UpdateAutoPlay",
    "UpdateScenario", "UpdateCapture", "UpdateRdsEN", "UpdateCharacter", "BeginPhysics", "PreupdateMotionFrame", "PreupdateGUI",
    "UpdateAIMap", "UpdatePointGraph", "BeginDynamics", "BeginFrameRendering", "BeginHavok", "CreatePreupdateGroupFSM",
    "CreatePreupdateGroupBehaviorTree", "UpdateGlobalUserData", "UpdateUDS", "UpdateVR", "UpdateHID", "UpdateReflexInput",
    "UpdateUserService", "UpdateSystemService", "UpdateHardwareService", "UpdatePushNotificationService", "UpdateShareService",
    "UpdateSteam", "UpdateRebe", "UpdateEOS", "BeginUpdatePrimitive", "BeginUpdatePrimitiveGUI", "BeginUpdateSpineDraw", "BeginPuppet",
    "UpdateMotionFrame", "UpdateGUI", "PreupdateBehavior", "PreupdateBehaviorTree", "PreupdateFSM", "PreupdateNetwork",
    "PreupdateTimeline", "PreupdateVortexel", "PreupdateEffect", "PreupdateFluid", "DynamicsBeforeUpdateBehavior",
    "UpdateAudioRenderInfo", "UpdateBehavior", "BeginUpdateSoundGameParameter", "BeginUpdateTimeline", "BeginUpdateTimelineFsm2",
    "UpdateMLSupport", "CreateUpdateGroupBehaviorTree", "CreateUpdateGroupFSM", "UpdateTimeline", "PreUpdateAreaMap", "UpdateOctree",
    "UpdateAreaMap", "UpdateBehaviorTree", "UpdateAutomaton", "CreateNavigationChain", "UpdateTimelineFsm2", "UpdateNavigationPrev",
    "UpdateFSM", "UpdateMotion", "UpdateSpine", "PreupdateNetwork2", "EffectCollisionLimit", "UpdatePhysicsAfterUpdatePhase",
    "UpdateGeometry", "UpdateLandscape", "UpdateHoudini", "UpdatePhysicsCharacterController", "BeginUpdateHavok2", "UpdateDynamics",
    "UpdateNavigation", "UpdateFluidFlock", "UpdateSyncDynamics", "UpdateConstraintsBegin", "EndUpdateSoundGameParameter",
    "LateUpdateBehavior", "EditUpdateBehavior", "ClearAudioRenderInfo", "LateUpdateSpine", "BeginLateUpdateLandscape",
    "UpdateDynamicsAfterLateUpdate", "UpdateMovie", "BeginUpdateHavok", "BeginUpdateVortexel", "BeginUpdateEffect", "BeginUpdateNFX",
    "BeginUpdateFluid", "PrepareUpdateNFX", "UpdateDynamicsBeforeConstraintsEnd", "UpdateConstraintsEnd",
    "UpdateDynamicsAfterConstraintsEnd", "UpdateHavok3", "UpdatePhysicsAfterLateUpdatePhase", "UpdateVortexel", "PrerenderGUI",
    "PrepareRendering", "UpdateSound", "UpdateWwiselib", "UpdateSimpleWwise", "UpdateWwise", "UpdateAudioRender",
    "CreateSelectorGroupFSM", "UpdateHavok", "UpdateNetwork", "EndUpdateHavok", "UpdateFSMSelector", "UpdateBehaviorTreeSelector",
    "BeforeLockSceneRendering", "EndUpdateHavok2", "UpdateJointExpression", "UpdateDynamicsAfterJointExpression",
    "UpdateBehaviorTreeSelectorLegacy", "UpdateEffect", "EndUpdateEffect", "EndUpdateVortexel", "UpdateNFX", "UpdateFluid",
    "EndUpdateFluid", "PostUpdateNFX", "LateUpdateWidget", "LateUpdateVR", "BeforeLockSceneDynamics", "LateUpdateNFX", "LockScene",
    "EndDynamics", "EndPhysics", "LateUpdatePointGraph", "UpdateAIMapLate", "WaitRendering", "UpdateVRPose", "EndLateUpdateLandscape",
    "UpdatePuppet", "UpdateSpeedTree", "UnlockScene", "UpdateVM", "UpdateVirtualAllocator", "WaitForVblank",
};
FILETIME g_loaded_time{};
uint64_t g_frame_count{};
uint32_t g_generation{};

// Turn off REFramework LooseTextureLoader's DisableTextureCache: when on, every load of a loose texture creates a new copy (dozens to hundreds of copies of the same texture); hot reload does not need it.
// REFramework reads re2_fw_config.txt only after plugin DLLs are loaded, during module initialization (2026-11-03 log: DLL loaded 02:39:20, on_config_load 02:39:26),
// so rewriting the config in DllMain takes effect for this launch. Only this line is changed and line endings are preserved; write a temp file first, then replace
enum class CacheOption { untouched, disabled, failed };
CacheOption g_cache_option = CacheOption::untouched;

void disable_texture_cache_option(HMODULE self) {
    wchar_t exe[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, exe, MAX_PATH) == 0) return;
    std::wstring dir{exe};
    dir.resize(dir.find_last_of(L"\\/") + 1);
    const auto path = dir + L"re2_fw_config.txt";
    const auto tmp = path + L".file_hotreload.tmp";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string text{};
    LARGE_INTEGER size{};
    if (GetFileSizeEx(h, &size) && size.QuadPart > 0 && size.QuadPart < (1 << 20)) {
        text.resize((size_t)size.QuadPart);
        DWORD got = 0;
        if (!ReadFile(h, text.data(), (DWORD)text.size(), &got, nullptr) || got != text.size()) text.clear();
    }
    CloseHandle(h);
    static const std::string key = "LooseTextureLoader_DisableTextureCache=";
    size_t pos = text.find(key);
    while (pos != std::string::npos && pos != 0 && text[pos - 1] != '\n') pos = text.find(key, pos + 1);
    if (pos == std::string::npos || text.compare(pos + key.size(), 4, "true") != 0) return;
    text.replace(pos + key.size(), 4, "false");
    g_cache_option = CacheOption::failed;
    h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD put = 0;
    const bool ok = WriteFile(h, text.data(), (DWORD)text.size(), &put, nullptr) && put == text.size();
    CloseHandle(h);
    if (ok && MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        g_cache_option = CacheOption::disabled;
    } else {
        DeleteFileW(tmp.c_str());
    }
    (void)self;
}

bool file_time(const std::filesystem::path& p, FILETIME& out) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &fad)) return false;
    out = fad.ftLastWriteTime;
    return true;
}

void unload_core() {
    if (g_core == nullptr) return;
    if (g_shutdown) g_shutdown();
    g_entry = nullptr;
    FreeLibrary(g_core);
    g_core = nullptr;
    g_frame = nullptr;
    g_shutdown = nullptr;
}

void load_core() {
    const auto src = g_core_dir / L"file_hotreload_core.dll";
    FILETIME t{};
    if (!file_time(src, t)) return;

    unload_core();

    // Shadow copy: use a new file name each time to avoid clashing with an old copy that is still unloading
    const auto shadow_dir = g_core_dir / L"shadow";
    std::error_code ec{};
    std::filesystem::create_directories(shadow_dir, ec);
    for (const auto& e : std::filesystem::directory_iterator(shadow_dir, ec)) {
        std::filesystem::remove(e.path(), ec); // Deleting an old copy that is still in use fails; ignore
    }
    const auto shadow = shadow_dir / (L"core_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(++g_generation) + L".dll");
    if (!CopyFileW(src.c_str(), shadow.c_str(), FALSE)) {
        g_param->functions->log_error("[file_hotreload] Failed to copy core DLL: %lu", GetLastError());
        return;
    }

    g_core = LoadLibraryW(shadow.c_str());
    if (g_core == nullptr) {
        g_param->functions->log_error("[file_hotreload] Failed to load core DLL: %lu", GetLastError());
        return;
    }
    auto init = (CoreInitFn)GetProcAddress(g_core, "core_init");
    g_frame = (CoreFrameFn)GetProcAddress(g_core, "core_frame");
    g_shutdown = (CoreShutdownFn)GetProcAddress(g_core, "core_shutdown");
    if (init == nullptr || g_frame == nullptr || !init(g_param)) {
        g_param->functions->log_error("[file_hotreload] Core DLL initialization failed");
        g_frame = nullptr;
        unload_core();
        return;
    }
    g_entry = (CoreEntryFn)GetProcAddress(g_core, "core_entry"); // Older cores do not have this export
    g_loaded_time = t;
    g_param->functions->log_info("[file_hotreload] Core loaded (#%u)", g_generation);
}

void log_silent(const char*, ...) {}

// Forward only on the main thread (the one running on_update_behavior): core load/unload also happens there, so they never run concurrently
void on_post_entry() {
    if (g_entry != nullptr && GetCurrentThreadId() == g_main_thread) g_entry();
}

void on_update_behavior() {
    g_main_thread = GetCurrentThreadId();
    // Install the path-hash hook (REFramework's LooseFileLoader has finished hooking by now); on failure retry about once per second, at most 60 times
    static int hook_tries = 0;
    static bool hook_done = false;
    // The DirectStorage compensation is installed at initialization; on failure it is also retried about once per second, at most 60 times
    static int ds_tries = 0;
    if (ds_tries < 60 && g_frame_count % 60 == 30 && !hr::dstorage_close_fix_install(g_param->functions->log_info, &log_silent)) {
        if (++ds_tries == 60) hr::dstorage_close_fix_install(g_param->functions->log_info, g_param->functions->log_error);
    } else if (g_frame_count % 60 == 30) {
        ds_tries = 60;
    }
    if (!hook_done && hook_tries < 60 && g_frame_count % 60 == 0) {
        ++hook_tries;
        // Only report errors on the first and the last failure to avoid flooding the log
        hook_done = hr::loose_hook_install(g_param->functions->log_info,
                                           hook_tries == 1 || hook_tries == 60 ? g_param->functions->log_error : &log_silent);
    }
#ifdef FILE_HOTRELOAD_MERGED
    // Single-file build: the core code is in this DLL; initialize on the first update, no hot swapping
    static bool core_started = false;
    ++g_frame_count;
    if (!core_started) {
        core_started = true;
        if (core_init(g_param)) {
            g_frame = &core_frame;
            g_entry = &core_entry;
            g_shutdown = &core_shutdown;
            g_param->functions->log_info("[file_hotreload] Started (single-file build)");
        } else {
            g_param->functions->log_error("[file_hotreload] Core initialization failed");
        }
    }
#else
    // Check about once per second whether the core DLL was updated
    if (g_frame_count++ % 60 == 0) {
        FILETIME t{};
        if (file_time(g_core_dir / L"file_hotreload_core.dll", t) &&
            (g_core == nullptr || CompareFileTime(&t, &g_loaded_time) != 0)) {
            load_core();
        }
    }
#endif
    if (g_frame) g_frame();
}
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) disable_texture_cache_option(module);
    return TRUE;
}

extern "C" __declspec(dllexport) void reframework_plugin_required_version(REFrameworkPluginVersion* version) {
    version->major = REFRAMEWORK_PLUGIN_VERSION_MAJOR;
    version->minor = 0;
    version->patch = 0;
}

extern "C" __declspec(dllexport) bool reframework_plugin_initialize(const REFrameworkPluginInitializeParam* param) {
    g_param = param;
    hr::loader_hooks_set_log(param->functions->log_info, param->functions->log_error);
    if (g_cache_option == CacheOption::disabled) {
        param->functions->log_info("[file_hotreload] Turned off DisableTextureCache of REFramework LooseTextureLoader (re2_fw_config.txt); takes effect from this launch");
    } else if (g_cache_option == CacheOption::failed) {
        param->functions->log_error("[file_hotreload] Failed to write re2_fw_config.txt while turning off DisableTextureCache");
    }
    // Install as early as possible: loose textures are already loaded and closed during startup
    hr::dstorage_close_fix_install(param->functions->log_info, param->functions->log_error);
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    g_core_dir = std::filesystem::path(buf).parent_path() / L"reframework" / L"data" / L"file_hotreload" / L"core";
#ifndef FILE_HOTRELOAD_MERGED
    std::error_code ec{};
    std::filesystem::create_directories(g_core_dir, ec);
#endif
    param->functions->on_pre_application_entry("UpdateBehavior", on_update_behavior);
    for (const auto name : k_update_entries) param->functions->on_post_application_entry(name, on_post_entry);
    param->functions->log_info("[file_hotreload] Loader ready");
    return true;
}
