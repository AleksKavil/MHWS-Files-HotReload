#include <Windows.h>

#include <share.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cwctype>
#include <fstream>
#include <map>
#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

#include <reframework/API.hpp>

#include "crash_trace.hpp"
#include "hotreload.hpp"
#include "log.hpp"
#include "memory_scan.hpp"
#include "loose_hook.hpp"
#include "prefab_live.hpp"
#include "references.hpp"
#include "resource_cache.hpp"
#include "rsz_layout.hpp"

namespace hr {

namespace {
using API = reframework::API;

const TypeHandler k_handlers[] = {
    {L"efx", "via.effect.EffectResource", "via.effect.EffectResourceHolder", true, true, false, false, false},
    {L"efcsv", "via.effect.EffectCsvResource", "via.effect.EffectCsvResourceHolder", false, true, false, false, false},
    {L"uvs", "via.uvsequence.UVSequenceResource", "via.uvsequence.UVSequenceResourceHolder", false, true, false, false, false},
    // htex (ground edit collision brush; the whole game has only System/SystemSetting/HeightEditTexture.htex): besides efx, the presets of the system setting
    // GroundHeightEditData.user hold it through managed holders; with a cache-only update ground editing keeps using the old brush, so references are replaced by scanning
    {L"htex", "via.collisionlib.HeightTextureResource", "via.collisionlib.HeightTextureResourceHolder", false, true, false, false, false},
    // Character/equipment resources: after references are replaced, scene components using them are switched to the new one through setters (refresh_components; the engine rebuilds from the new resource next frame).
    // Besides components, equipment and character user data (ModelPartsInfo2, PlayerResident, etc.) hold them through managed holders and take them from there when re-equipping,
    // so references are replaced by scanning as well
    {L"sfur", "via.render.ShellFurResource", "via.render.ShellFurResourceHolder", false, false, false, false, false},
    {L"jcns", "via.motion.JointConstraintsResource", "via.motion.JointConstraintsResourceHolder", false, false, false, false, false},
    {L"fbxskel", "via.motion.FbxSkeletonResource", "via.motion.FbxSkeletonResourceHolder", false, false, false, false, false},
    {L"motbank", "via.motion.MotionBankResource", "via.motion.MotionBankResourceHolder", false, false, false, false, false},
    // gui is not here (cache update only): observed 2026-11-09, swapping the resource of a via.gui.GUI at runtime (scan-replacing holders + set_Asset) crashed the game 3 ms later
    // (exe+b0cee5b reads [0+0x50], not on the main thread)
    {L"pfb", "via.PrefabResource", "via.PrefabResourceHolder", false, false, true, true, false},
};

// Types not in k_handlers but with live handling after saving (refreshing users or cascading in finish_cached): the type is taken from the engine's resource type table,
// the cache is updated first and then handled. Other registered types (scn, msg, jmap, etc.) leave existing objects unchanged with a cache-only update, so they are not hot reloaded (removed at the user's request on 2026-11-11)
const std::unordered_set<std::string_view> k_cached_live_types = {
    "via.UserDataResource",          "via.physics.RequestSetColliderResource", "via.gui.GUIResource",
    "via.render.MeshResource",       "via.render.MeshMaterialResource",        "via.render.TextureResource",
    "via.render.MasterMaterialResource", "via.render.RenderTargetTextureResource", "via.motion.Chain2Resource",
    "via.character.CollisionShapePresetResource", "via.dynamics.GpuCloth2Resource", "via.dynamics.GpuClothResource",
    "via.motion.MotionListResource", "via.motion.MotionResource",
    // efx dependencies (cascade_effects reloads the loose efx that reference them)
    "via.userdata.UserVariablesResource", "via.render.AlembicMeshResource"};

struct CachedType {
    std::wstring ext;
    std::string type;
    std::string holder;
    TypeHandler handler{};
};

const TypeHandler* cache_handler_for_ext(const std::wstring& ext) {
    // Unregistered extensions are recorded as empty so the table is not looked up again
    static std::unordered_map<std::wstring, std::unique_ptr<CachedType>> handlers{};
    auto it = handlers.find(ext);
    if (it == handlers.end()) {
        std::unique_ptr<CachedType> h{};
        if (auto type = ResourceCache::resource_type_for_ext(ext); !type.empty() && k_cached_live_types.contains(type)) {
            h = std::make_unique<CachedType>();
            h->ext = ext;
            h->type = std::move(type);
            h->holder = h->type + "Holder";
            h->handler = {h->ext.c_str(), h->type.c_str(), h->holder.c_str(), false, false, false, false, true};
        }
        it = handlers.emplace(ext, std::move(h)).first;
    }
    return it->second ? &it->second->handler : nullptr;
}

// Managed wrappers holding a Resource*: ResourceHolder and its subclasses, via.Prefab; the pointer is always at object +0x10
const std::vector<std::string> k_owner_types = {"via.ResourceHolder", "via.Prefab"};
constexpr uintptr_t OWNER_RESOURCE_OFFSET = 0x10;

constexpr uintptr_t RES_READY = 0x38;
constexpr uintptr_t ARRAY_COUNT = 0x1C;
constexpr uintptr_t ARRAY_DATA = 0x20;

// via.effect.PlayerState / PlayerAction
constexpr uint32_t STATE_START = 1;
constexpr uint32_t STATE_RUNNING = 2;
constexpr uint32_t ACTION_START = 1;

void warm_property_index();

const TypeHandler* handler_for_ext(const std::wstring& ext) {
    for (const auto& h : k_handlers) {
        if (ext == h.ext) return &h;
    }
    return cache_handler_for_ext(ext);
}

std::wstring lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)std::towlower(c);
    return s;
}

bool is_number(const std::wstring& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; });
}

bool is_ready(uintptr_t res) {
    uintptr_t v = 0;
    return safe_read_ptr(res + RES_READY, v) && (v & 0xFF) != 0;
}

// Current stage of complete_scan (written to the log on exceptions)
const char* g_scan_stage = "";

// Called with SEH in a function without C++ objects; C++ exceptions (0xE06D7363), access violations, etc. are all caught here and the exception code returned
template <typename F> DWORD seh_call(F& f) {
    __try {
        f();
        return 0;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return GetExceptionCode();
    }
}

// Whether the managed object's type (including its parent chain) is any of the types in types
bool managed_is_a(uintptr_t obj, const std::vector<std::string>& types) {
    if (!managed_object_safe(obj)) return false;
    for (auto t = ((API::ManagedObject*)obj)->get_type_definition(); t != nullptr; t = t->get_parent_type()) {
        if (std::find(types.begin(), types.end(), t->get_full_name()) != types.end()) return true;
    }
    return false;
}
}

// For error logs: describe which managed object a pointer location belongs to (searching back at most 0x400 bytes)
std::string describe_slot(uintptr_t slot) {
    char buf[512];
    for (uintptr_t off = 0x10; off <= 0x400; off += 8) {
        const auto obj = slot - off;
        if (!managed_object_safe(obj)) continue;
        auto td = ((API::ManagedObject*)obj)->get_type_definition();
        sprintf_s(buf, "%llx = %s(%llx)+0x%llx", (unsigned long long)slot, td ? td->get_full_name().c_str() : "?",
                  (unsigned long long)obj, (unsigned long long)off);
        return buf;
    }
    sprintf_s(buf, "%llx = native memory", (unsigned long long)slot);
    return buf;
}

HotReload& HotReload::get() {
    // Not destructed: joining the watcher thread under the loader lock at process exit would deadlock
    static auto* instance = new HotReload();
    return *instance;
}

bool HotReload::initialize() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    m_game_dir = std::filesystem::path(buf).parent_path();
    m_natives_dir = m_game_dir / L"natives";

    std::error_code ec{};
    std::filesystem::create_directories(m_game_dir / L"reframework" / L"data", ec);

    std::string err{};
    if (!ResourceCache::validate(err)) {
        log_disabled("Resource table validation failed, plugin disabled: %s", err.c_str());
        return false;
    }
    // Hard-coded resource object and cache table offsets: the plugin modifies the cache table and reference counts with them, so the whole plugin is disabled if verification fails
    if (std::string report{}; !ResourceCache::check_layout(report)) {
        log_disabled("Layout check: %s; plugin disabled", report.c_str());
        return false;
    } else {
        log("Layout check: %s", report.c_str());
    }
    if (!m_cfg.enabled) {
        log("Config Enabled=0, plugin disabled");
        return false;
    }

    m_watcher = std::make_unique<FileWatcher>();
    if (!m_watcher->start(m_natives_dir.wstring(), err)) {
        log("Cannot watch %s: %s", narrow(m_natives_dir.wstring()).c_str(), err.c_str());
        return false;
    }
    log("Started, watching %s", narrow(m_natives_dir.wstring()).c_str());
    m_ref_index.start(m_natives_dir, {L".efx.", L".uvs.", L".motlist."});
    if (const auto types = ResourceCache::resource_types(); types.empty()) {
        log("Could not read the engine resource type table; files other than pfb/efx/uvs/efcsv will not update the cache");
    } else {
        log("Engine resource type table: %zu entries. pfb: live writes to instances; efx/uvs/efcsv/htex/sfur/jcns/fbxskel/motbank: references replaced; "
            "user/rcol/gui/mesh/mdf2/tex/mmtr/rtex/chain2/clsp/gpuc/motlist/mot/uvar/abcmesh: cache updated and users refreshed; other types are not handled", types.size());
    }
    PrefabLive::install_tracking();
    rsz_warm_up();
    warm_property_index();
    // Current content of .user files in natives (read in the background): used as the "previous version" on the first save of a session so only fields the file changed are written,
    // and values the game changed at runtime (such as EquipDataSetting arrays or the ActionParam action list) are not reset to the file values
    m_user_snapshot_future = std::async(std::launch::async, [dir = m_natives_dir] {
        std::vector<std::pair<std::wstring, std::vector<uint8_t>>> out{};
        std::error_code ec{};
        for (auto it = std::filesystem::recursive_directory_iterator(dir, ec); !ec && it != std::filesystem::recursive_directory_iterator();
             it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            auto name = it->path().filename().wstring();
            for (auto& ch : name) ch = (wchar_t)towlower(ch);
            if (name.find(L".user.") == std::wstring::npos && name.find(L".rcol.") == std::wstring::npos) continue;
            std::ifstream in{it->path(), std::ios::binary};
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            out.emplace_back(std::filesystem::relative(it->path(), dir, ec).generic_wstring(), std::move(data));
        }
        return out;
    });
    return true;
}

void HotReload::merge_user_snapshot() {
    if (!m_user_snapshot_future.valid() || m_user_snapshot_future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;
    uint32_t n = 0, nr = 0;
    for (auto& [rel, data] : m_user_snapshot_future.get()) {
        std::wstring res{};
        const TypeHandler* h{};
        if (data.empty() || !map_file(rel, res, h) || h == nullptr) continue;
        const bool rcol = lower(res).ends_with(L".rcol");
        if (std::string_view{h->resource_type} != "via.UserDataResource" && !rcol) continue;
        if (m_file_snapshot.try_emplace(ResourceCache::normalize(res), std::move(data)).second) ++(rcol ? nr : n);
    }
    if (n > 0) log("Recorded current contents of %u .user files in natives (the first save this session writes only fields changed in the file)", n);
    if (nr > 0) log("Recorded current contents of %u .rcol files in natives (the first save this session writes only parts changed in the file)", nr);
}

// Path relative to natives -> resource path. Example: STM/Art/VFX/a.efx.5571972 -> Art/VFX/a.efx
// Resource file name base.ext.version[.suffix...]: split it and check the version and suffixes. Only platform/language suffixes that appear after the version number in the game file list (data/MHWS_STM.list)
// are allowed; temporary files of editors or copy tools (.tmp, .bak, etc.) are not resource files
// (2026-11-02: when a tool wrote .992.tmp first and renamed it, the .tmp was taken as a save and triggered a reload while .992 did not exist yet, reading the pak)
static bool split_resource_name(const std::wstring& name, std::vector<std::wstring>& parts) {
    static const std::unordered_set<std::wstring> k_suffixes{L"x64", L"stm", L"en",   L"de", L"it", L"es", L"fr", L"ptbr", L"ru",
                                                             L"zhcn", L"es419", L"ja", L"pl", L"zhtw", L"ar", L"ko", L"th", L"fc"};
    parts.clear();
    for (size_t s = 0, e; s <= name.size(); s = e + 1) {
        e = name.find(L'.', s);
        if (e == std::wstring::npos) e = name.size();
        parts.push_back(name.substr(s, e - s));
    }
    if (parts.size() < 3 || !is_number(parts[2])) return false;
    for (size_t i = 3; i < parts.size(); ++i) {
        if (!k_suffixes.contains(lower(parts[i]))) return false;
    }
    return true;
}

// Whether a file name in natives is a resource file of this resource (base.ext, case-insensitive)
static bool is_resource_file_of(const std::wstring& file_name, const std::wstring& base_ext) {
    std::vector<std::wstring> parts{};
    return split_resource_name(file_name, parts) && lower(parts[0] + L"." + parts[1]) == lower(base_ext);
}

bool HotReload::map_file(const std::wstring& rel, std::wstring& res_path, const TypeHandler*& handler) const {
    std::wstring p = rel;
    const auto slash = p.find(L'/');
    if (slash == std::wstring::npos) return false;
    if (lower(p.substr(0, slash)) == L"stm") p = p.substr(slash + 1);

    const auto name_pos = p.rfind(L'/') == std::wstring::npos ? 0 : p.rfind(L'/') + 1;
    const auto name = p.substr(name_pos);

    std::vector<std::wstring> parts{};
    if (!split_resource_name(name, parts)) return false;

    handler = handler_for_ext(lower(parts[1]));
    if (handler == nullptr) return false;
    res_path = p.substr(0, name_pos) + parts[0] + L"." + parts[1];
    return true;
}

// Resource types registered by the engine but not hot reloaded (not in k_handlers or k_cached_live_types)
bool HotReload::unsupported_type(const std::wstring& rel) const {
    const auto name = rel.substr(rel.rfind(L'/') == std::wstring::npos ? 0 : rel.rfind(L'/') + 1);
    std::vector<std::wstring> parts{};
    if (!split_resource_name(name, parts)) return false;
    const auto ext = lower(parts[1]);
    return handler_for_ext(ext) == nullptr && !ResourceCache::resource_type_for_ext(ext).empty();
}

void HotReload::enqueue(const std::wstring& path, const TypeHandler* handler, const std::wstring& reason) {
    const auto key = ResourceCache::normalize(path);
    // A job for the same path is already queued: it reads the latest file when it starts, so merge. A job that is already loading may have read older content, so queue another one that loads after it finishes
    for (const auto& j : m_jobs) {
        if (j.stage == Stage::Queued && ResourceCache::normalize(j.path) == key) return;
    }
    Job job{};
    job.path = path;
    job.handler = handler;
    job.reason = reason;
    m_jobs.push_back(std::move(job));
}

// Have the loader register this file as "force read as a loose file" (for files added while the game runs, REFramework's existence cache records them as missing)
static void force_loose(const std::wstring& rel) {
    using ForceLooseFn = void (*)(const wchar_t*);
    static const auto fn = []() -> ForceLooseFn {
        const auto m = GetModuleHandleW(L"file_hotreload.dll");
        return m ? (ForceLooseFn)GetProcAddress(m, "loader_force_loose") : nullptr;
    }();
    if (fn != nullptr) fn((L"natives/" + rel).c_str());
}

// The loader's decision counters for a registered path (returns false with older loaders lacking this export)
static bool loose_stats(const std::wstring& rel, uint32_t& loose, uint32_t& forced, uint32_t& missing) {
    using StatsFn = bool (*)(const wchar_t*, uint32_t*, uint32_t*, uint32_t*);
    static const auto fn = []() -> StatsFn {
        const auto m = GetModuleHandleW(L"file_hotreload.dll");
        return m ? (StatsFn)GetProcAddress(m, "loader_loose_stats") : nullptr;
    }();
    return fn != nullptr && fn((L"natives/" + rel).c_str(), &loose, &forced, &missing);
}

void HotReload::collect_changes() {
    for (const auto& rel : m_watcher->poll(m_cfg.debounce_ms)) {
        m_ref_index.on_changed(rel);
        force_loose(rel);
        std::wstring res_path{};
        const TypeHandler* handler{};
        if (!map_file(rel, res_path, handler)) {
            if (unsupported_type(rel)) log("%s: type not supported for hot reload, ignored", narrow(rel).c_str());
            else if (m_cfg.verbose) log("Ignored: %s", narrow(rel).c_str());
            continue;
        }
        enqueue(res_path, handler, L"file saved");
        on_dependency_saved(res_path);
    }
}

namespace {
std::vector<std::wstring> mdf2_pending_deps(uintptr_t res);
}

std::filesystem::path HotReload::natives_file(const std::wstring& res_path) const {
    const std::filesystem::path rel{res_path};
    const auto dir = m_natives_dir / L"STM" / rel.parent_path();
    const auto base_ext = rel.filename().wstring();
    std::filesystem::path best{};
    std::filesystem::file_time_type best_time{};
    std::error_code ec{};
    for (std::filesystem::directory_iterator d{dir, ec}, end; !ec && d != end; d.increment(ec)) {
        if (!is_resource_file_of(d->path().filename().wstring(), base_ext) || !d->is_regular_file(ec)) continue;
        const auto t = d->last_write_time(ec);
        if (best.empty() || t > best_time) {
            best = d->path();
            best_time = t;
        }
    }
    return best;
}

// Whether natives/STM has a file for this resource path (any version number)
bool HotReload::dep_file_exists(const std::wstring& res_path) const {
    const std::filesystem::path rel{res_path};
    const auto dir = m_natives_dir / L"STM" / rel.parent_path();
    const auto base_ext = rel.filename().wstring();
    std::error_code ec{};
    for (std::filesystem::directory_iterator d{dir, ec}, end; !ec && d != end; d.increment(ec)) {
        if (is_resource_file_of(d->path().filename().wstring(), base_ext) && d->is_regular_file(ec)) return true;
    }
    return false;
}

// After some file is added/saved: reload mdf2 that kept old materials because it was missing; mdf2 currently loading and waiting for it stop waiting early (the timeout handling reloads them as "dependency file exists")
void HotReload::on_dependency_saved(const std::wstring& res_path) {
    const auto key = ResourceCache::normalize(res_path);
    std::vector<DepWait> again{};
    for (auto it = m_dep_waiting.begin(); it != m_dep_waiting.end();) {
        if (it->second.deps.contains(key)) {
            again.push_back(std::move(it->second));
            it = m_dep_waiting.erase(it);
        } else {
            ++it;
        }
    }
    static const auto mdf2 = handler_for_ext(L"mdf2");
    for (const auto& w : again) {
        m_dep_retries.erase(ResourceCache::normalize(w.path));
        enqueue(w.path, mdf2, L"dependency " + res_path);
    }
    for (auto& j : m_jobs) {
        if (j.stage != Stage::Loading || j.handler != mdf2 || !is_ready(j.new_res)) continue;
        const auto pending = mdf2_pending_deps(j.new_res);
        if (std::find(pending.begin(), pending.end(), key) == pending.end()) continue;
        m_dep_retries.erase(ResourceCache::normalize(j.path));
        j.frames = m_cfg.load_timeout_frames;
    }
}

// .user must be loaded through the engine's create_userdata (0x14A4A5FF0, 1.42.0.3): it builds the root object, stores it at resource +0x88, then reads the file;
// a UserDataResource created with create_resource has an empty +0x88 and the load thread hits an access violation reading it (crash observed 2026-10-31 at exe+a4d2036).
// The type argument of create_userdata is the root object's class (taken from the old resource's root object); the resource goes into the same cache table and the root object is returned.
// Reference relationships: the root object holds one reference to the resource; resource +0x88 points to the root object without holding it; the returned root object reference is its only reference.
// While the plugin holds the new resource it must also hold the root object, otherwise the root object is reclaimed, resource +0x88 dangles, and the game later reads freed memory when it takes the resource from the cache
// (observed 2026-11-07: reloading again after a cache-only update reported "old resource has no userdata root object"; after a tester saved HairAdjustList.user,
// setting hair crashed in HairAdjustList.getParam reading _Style). When the plugin releases this resource, release_resource releases the root object as well.
// The same holds for .user resources loaded by the game: whenever the plugin holds one (old resource during a reload, orphans), it also holds its root object (hold_userdata_root).
// Holding only the resource kept it in the cache after the game released the root (e.g. the equipment preview switched the helmet away while a reload was loading),
// and the next load of the path got a resource whose +0x88 pointed to a freed object (reproduced 2026-11-15: crash in HairAdjustList.getParam after putting the helmet back on)
namespace {
struct UserRoot {
    uintptr_t root{};
    uint32_t holds{}; // References to the resource held by the plugin (each released through release_resource)
    bool owned{};     // Root reference returned by create_userdata (its only reference); otherwise an extra reference added by the plugin
};
std::mutex g_user_roots_mutex{};
std::unordered_map<uintptr_t, UserRoot> g_user_roots{}; // .user resources held by the plugin -> root objects held with them
}

// Call after the plugin adds a reference to a via.UserDataResource: the root object is held for as long as the plugin holds the resource
static void hold_userdata_root(uintptr_t res) {
    constexpr uintptr_t USERDATA_ROOT = 0x88;
    std::lock_guard lock{g_user_roots_mutex};
    if (const auto it = g_user_roots.find(res); it != g_user_roots.end()) {
        ++it->second.holds;
        return;
    }
    uintptr_t root = 0;
    if (!safe_read_ptr(res + USERDATA_ROOT, root) || !managed_object_safe(root)) return;
    API::get()->sdk()->managed_object->add_ref((REFrameworkManagedObjectHandle)root);
    g_user_roots[res] = UserRoot{root, 1, false};
}

// Resources swapped out by the plugin that are no longer in the cache table: the plugin holds their last reference (one per resource); reap_retired destroys them
// through ResourceCache::destroy_unlisted once that is the only reference left. If handed to the game to release, the engine does not destroy them when they reach zero on the main thread (see resource_cache.hpp)
namespace {
std::mutex g_retired_mutex{};
std::unordered_set<uintptr_t> g_retired{};
}

namespace {
int64_t qpc_now() {
    LARGE_INTEGER c{};
    QueryPerformanceCounter(&c);
    return c.QuadPart;
}
double qpc_ms(int64_t ticks) {
    static const double freq = [] {
        LARGE_INTEGER f{};
        QueryPerformanceFrequency(&f);
        return (double)f.QuadPart;
    }();
    return (double)ticks * 1000.0 / freq;
}
}

// The plugin drops one resource reference. For a .user resource tracked in g_user_roots, the root object held with it is released when the plugin's last hold goes away
// (see the comments inside); resources no longer in the cache table are kept in g_retired until the plugin's reference is the last one
static void release_resource(uintptr_t res) {
    if (res == 0) return;
    const auto& api = API::get();
    uintptr_t root = 0;
    {
        std::lock_guard lock{g_user_roots_mutex};
        if (const auto it = g_user_roots.find(res); it != g_user_roots.end()) {
            auto& u = it->second;
            if (u.holds > 0) --u.holds;
            if (u.holds == 0) {
                // A reference the plugin added itself is always released. The root returned by create_userdata is released only when nothing but the plugin and the root hold the resource,
                // otherwise it is kept (possibly a small leak): someone else holding the resource may still read the root through +0x88
                uintptr_t refs = 0; // +0x28 resource reference count (int32)
                if (!u.owned || (safe_read_ptr(res + 0x28, refs) && (int32_t)(uint32_t)refs <= 2)) {
                    root = u.root;
                    g_user_roots.erase(it);
                }
            }
        }
    }
    bool keep = false;
    if (ResourceCache::destroy_supported() && !ResourceCache::listed(res)) {
        std::lock_guard lock{g_retired_mutex};
        keep = g_retired.insert(res).second;
    }
    if (!keep) api->sdk()->resource->release((REFrameworkResourceHandle)res);
    if (root != 0) api->sdk()->managed_object->release((REFrameworkManagedObjectHandle)root);
}

// Resources held by the plugin that are no longer in the cache table: destroyed once the plugin's is the only reference left; released normally if they are back in the table. Returns the number destroyed
static uint32_t reap_retired() {
    std::vector<uintptr_t> items{};
    {
        std::lock_guard lock{g_retired_mutex};
        items.assign(g_retired.begin(), g_retired.end());
    }
    uint32_t destroyed = 0;
    for (const auto res : items) {
        bool drop = false;
        uintptr_t raw = 0;
        const auto refs = safe_read_ptr(res + 0x28, raw) ? (int32_t)(uint32_t)raw : 0;
        if (refs <= 0) {
            drop = true; // Should not happen while the plugin holds a reference; stop tracking it
        } else if (ResourceCache::listed(res)) {
            API::get()->sdk()->resource->release((REFrameworkResourceHandle)res);
            drop = true;
        } else if (refs == 1 && ResourceCache::destroy_unlisted(res)) {
            ++destroyed;
            drop = true;
        }
        if (drop) {
            std::lock_guard lock{g_retired_mutex};
            g_retired.erase(res);
        }
    }
    return destroyed;
}

// When the core unloads: destroy what can be destroyed and hand the rest back to the engine (the game is still using them; they will not be destroyed when they later reach zero on the main thread)
static void release_retired_all() {
    reap_retired();
    std::vector<uintptr_t> items{};
    {
        std::lock_guard lock{g_retired_mutex};
        items.assign(g_retired.begin(), g_retired.end());
        g_retired.clear();
    }
    for (const auto res : items) API::get()->sdk()->resource->release((REFrameworkResourceHandle)res);
}

static uintptr_t create_userdata_resource(uintptr_t old_res, const std::string& path) {
    constexpr uintptr_t USERDATA_ROOT = 0x88;
    const auto& api = API::get();
    uintptr_t root = 0;
    if (!safe_read_ptr(old_res + USERDATA_ROOT, root) || !managed_object_safe(root)) {
        log("%s: old resource has no userdata root object, cannot reload", path.c_str());
        return 0;
    }
    const auto td = ((API::ManagedObject*)root)->get_type_definition();
    if (td == nullptr) return 0;
    const auto type = td->get_full_name();
    auto obj = api->sdk()->resource_manager->create_userdata((REFrameworkResourceManagerHandle)api->resource_manager(), type.c_str(), path.c_str());
    if (obj == nullptr) {
        log("%s: create_userdata(%s) failed", path.c_str(), type.c_str());
        return 0;
    }
    const auto res = ResourceCache::find(widen(path));
    uintptr_t new_root = 0;
    if (res == 0 || res == old_res || !safe_read_ptr(res + USERDATA_ROOT, new_root) || new_root != (uintptr_t)obj) {
        log("%s: no matching new resource in the cache after create_userdata", path.c_str());
        api->sdk()->managed_object->release(obj);
        return 0;
    }
    // Same as create_resource: the returned resource carries one reference; the root object's reference is kept with the resource and released in release_resource
    api->sdk()->resource->add_ref((REFrameworkResourceHandle)res);
    {
        std::lock_guard lock{g_user_roots_mutex};
        if (const auto prev = g_user_roots.find(res); prev != g_user_roots.end()) {
            api->sdk()->managed_object->release((REFrameworkManagedObjectHandle)prev->second.root);
        }
        g_user_roots[res] = UserRoot{(uintptr_t)obj, 1, true};
    }
    return res;
}

namespace {
// The GUI resource with path path currently used by some via.gui.GUI component in the scene (0 if none)
uintptr_t gui_resource_in_use(const std::wstring& path) {
    const auto& api = API::get();
    const auto vm = api->get_vm_context();
    static const auto get_scene = api->tdb()->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = api->tdb()->find_method("via.Scene", "findComponents(System.Type)");
    auto scene = get_scene ? get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager")) : nullptr;
    auto arr = scene && find_components ? find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.gui.GUI")) : nullptr;
    if (arr == nullptr) return 0;
    const auto key = ResourceCache::normalize(path);
    const auto count = *(uint32_t*)((uintptr_t)arr + ARRAY_COUNT);
    for (uint32_t i = 0; i < count; ++i) {
        const auto gui = *(uintptr_t*)((uintptr_t)arr + ARRAY_DATA + 8ull * i);
        const auto res = PrefabLive::gui_resource(gui);
        ResourceEntry e{};
        if (res != 0 && ResourceCache::read_entry(res, e) && ResourceCache::normalize(e.path) == key && !PrefabLive::gui_is_temp(gui)) return res;
    }
    return 0;
}

}

bool HotReload::start_job(Job& job) {
    const auto& api = API::get();
    const auto path = narrow(job.path);

    const auto key = ResourceCache::normalize(job.path);
    bool from_orphan = false;
    if (m_old_prefetch != nullptr) {
        // If not found, look it up again as usual (jobs added mid-loop, files not loaded)
        const auto f = m_old_prefetch->find(key);
        job.old_res = f != m_old_prefetch->end() ? f->second : ResourceCache::find(job.path);
    } else {
        job.old_res = ResourceCache::find(job.path);
    }
    if (auto it = m_orphans.find(key); it != m_orphans.end()) {
        // The orphan resource already holds a reference and is no longer in the cache
        if (job.old_res == 0) {
            job.old_res = it->second;
            from_orphan = true;
        } else {
            job.extra_old = it->second;
        }
        m_orphans.erase(it);
    }
    // mdf2/mesh not in the cache (e.g. previously only the cache was updated and the plugin's version has been released) while scene meshes still use the old version: reload with it as the old resource and refresh the meshes
    if (job.old_res == 0 && (std::string_view{job.handler->resource_type} == "via.render.MeshMaterialResource" ||
                             std::string_view{job.handler->resource_type} == "via.render.MeshResource")) {
        uintptr_t in_use = 0;
        auto run = [&] { in_use = refresh_meshes(job.path, 0, *job.handler); };
        if (seh_call(run) == 0 && in_use != 0) {
            api->sdk()->resource->add_ref((REFrameworkResourceHandle)in_use);
            job.old_res = in_use;
            from_orphan = true; // Reference already held and not in the cache: no need to remove it again
        }
    }
    // Same for gui: no longer in the cache (the plugin's version has been released) while a displayed GUI still uses the old version: reload with it as the old resource
    if (job.old_res == 0 && std::string_view{job.handler->resource_type} == "via.gui.GUIResource") {
        uintptr_t in_use = 0;
        auto run = [&] { in_use = gui_resource_in_use(job.path); };
        if (seh_call(run) == 0 && in_use != 0) {
            api->sdk()->resource->add_ref((REFrameworkResourceHandle)in_use);
            job.old_res = in_use;
            from_orphan = true; // Reference already held and not in the cache: no need to remove it again
        }
    }
    // Same for rcol: the same file may occupy separate cache entries under paths with different case (e.g. GameDesign/player/actiondata and GameDesign/Player/ActionData);
    // when the saved path is not found, the copy used by collision components in the scene is the old resource
    if (job.old_res == 0 && lower(job.path).ends_with(L".rcol")) {
        uintptr_t in_use = 0;
        auto run = [&] { in_use = PrefabLive::rcol_resource_in_use(job.path); };
        if (seh_call(run) == 0 && in_use != 0) {
            api->sdk()->resource->add_ref((REFrameworkResourceHandle)in_use);
            job.old_res = in_use;
            from_orphan = true;
        }
    }
    if (job.old_res == 0) {
        log("%s is not loaded now; the new file will be read the next time it loads", path.c_str());
        return false;
    }


    job.old_ready = job_loaded(job, job.old_res);
    const bool is_user = std::string_view{job.handler->resource_type} == "via.UserDataResource";
    if (!from_orphan) {
        api->sdk()->resource->add_ref((REFrameworkResourceHandle)job.old_res);
        if (is_user) hold_userdata_root(job.old_res);
        if (!ResourceCache::evict(job.old_res)) {
            log("%s: failed to evict from the cache", path.c_str());
            release_resource(job.old_res);
            return false;
        }
    }
    // Remove the other cache entries of the same path (different keys) as well: when mdf2 loads dependent textures it creates one per material, with keys different from the path-derived one;
    // removing only one entry left cascaded mdf2 reloads still hitting the old texture, so nothing changed on screen (observed 2026-11-01, only showing after a restart). Removed old resources stay held by their users
    job.evicted_extra = 0;
    if (job.handler->cache_only) {
        uintptr_t old_vt = 0;
        safe_read_ptr(job.old_res, old_vt);
        for (const auto other : ResourceCache::find_all(job.path, old_vt)) {
            if (other == job.old_res || other == job.extra_old) continue;
            // After removal from the table the plugin holds the last reference (release_resource moves it into g_retired), otherwise it would not be destroyed when its users release it to 0 on the main thread
            api->sdk()->resource->add_ref((REFrameworkResourceHandle)other);
            if (is_user) hold_userdata_root(other);
            if (ResourceCache::evict(other)) ++job.evicted_extra;
            release_resource(other);
        }
    }

    // Reload with the old resource's own path (case matching the game), so the new resource has the same cache key as the old one (the old resource can be put back if loading fails).
    // Types replaced by scanning need this too: when the natives directory case differs from the game (e.g. system/ vs System/), a new resource loaded from the file path
    // has a different cache key; the game later requests and loads another copy, and the next reload scans for that copy, missing references already repointed to the new resource (observed 2026-11-04 with htex)
    auto load_path = path;
    if (ResourceEntry e{}; ResourceCache::read_entry(job.old_res, e) && !e.path.empty()) {
        load_path = narrow(e.path);
    }
    // The file exists in natives: (re)register it before loading so the path hash returns the loose marker; record the counters to confirm after loading that the loose file was really read
    // (it was registered once when the file was saved; this is a fallback for dependency-triggered reloads or loads that did not read the loose file for other reasons after registering)
    job.loose_check = false;
    if (const auto file = natives_file(job.path); !file.empty()) {
        // Computed on strings (file is built from m_natives_dir); std::filesystem::relative accesses the disk
        const auto rel = file.lexically_relative(m_natives_dir).generic_wstring();
        if (!rel.empty() && !rel.starts_with(L"..")) {
            force_loose(rel);
            job.loose_rel = rel;
            job.loose_check = loose_stats(rel, job.loose_before, job.forced_before, job.missing_before);
        }
    }
    if (std::string_view{job.handler->resource_type} == "via.UserDataResource") {
        job.new_res = m_userdata_layout_ok ? create_userdata_resource(job.old_res, load_path) : 0;
        if (!m_userdata_layout_ok) log("%s: .user layout check failed or not finished yet, not reloading", path.c_str());
    } else {
        job.new_res = (uintptr_t)api->sdk()->resource_manager->create_resource(
            (REFrameworkResourceManagerHandle)api->resource_manager(), job.handler->resource_type, load_path.c_str());
    }
    if (job.new_res == 0 || job.new_res == job.old_res) {
        log("%s: failed to recreate the resource", path.c_str());
        m_orphans[key] = job.old_res;
        if (job.extra_old != 0) release_resource(job.extra_old);
        return false;
    }

    // The new resource entered the cache under the same key: while it loads, point the cache node back to the old resource (when the old one was in the cache and ready); commit_new repoints it to the new one after loading.
    // Otherwise a game request for the path during that time gets the new resource still loading, e.g. a mesh set to an mdf2 that has not finished loading never builds its materials (all black)
    job.old_in_cache = !from_orphan && job.old_ready && (job.handler->in_place || job.handler->cache_only) &&
                       ResourceCache::replace(job.new_res, job.old_res);

    job.stage = Stage::Loading;
    job.frames = 0;
    if (m_cfg.verbose) log("%s reload started old=%llx new=%llx (%s)", path.c_str(), job.old_res, job.new_res, narrow(job.reason).c_str());
    return true;
}

void HotReload::commit_new(Job& j) {
    if (!j.old_in_cache) return;
    // .user: the cache keeps pointing to the old resource until finish_cached knows whether the file changes were written into the data in use. On success the new resource is dropped,
    // so the game must never get it: anything taken from it in the meantime (e.g. a preview hunter's HairAdjustController._AdjustList) would point to a root object freed with it
    // (observed 2026-11-14 on a tester's machine: HairAdjustList.getParam read freed memory after the whole mod set was saved and the helmet was equipped in the equipment preview)
    if (std::string_view{j.handler->resource_type} == "via.UserDataResource") return;
    j.old_in_cache = false;
    if (!ResourceCache::replace(j.old_res, j.new_res)) {
        log("  %s: the old resource is no longer in the cache (released or removed by the game); the new resource was not put in the cache, later loads read the disk again", narrow(j.path).c_str());
    }
}

void HotReload::abandon_new(Job& j) {
    if (j.old_in_cache) {
        // The old resource stayed in the cache during loading and the new one is not there: just drop the new resource
        j.old_in_cache = false;
        release_resource(j.new_res);
        release_resource(j.old_res);
    } else if ((j.handler->in_place || j.handler->cache_only) && ResourceCache::replace(j.new_res, j.old_res)) {
        // The old resource goes back into the cache, as if nothing was reloaded
        release_resource(j.new_res);
        release_resource(j.old_res);
    } else {
        // Remove it from the cache so later loads do not get this resource
        ResourceCache::evict(j.new_res);
        release_resource(j.new_res);
        // The old resource is no longer in the cache but still used by instances: keep the reference and keep replacing it on the next save
        m_orphans[ResourceCache::normalize(j.path)] = j.old_res;
    }
    if (j.extra_old != 0) release_resource(j.extra_old);
    j.new_res = 0;
    j.old_res = 0;
    j.extra_old = 0;
}

bool HotReload::loaded_from_loose(const Job& j, std::string& why) const {
    if (!j.loose_check) return true;
    uint32_t loose = 0, forced = 0, missing = 0;
    if (!loose_stats(j.loose_rel, loose, forced, missing)) return true;
    if (loose != j.loose_before) return true;
    // Every time a registered path goes through the path hash it is counted: an unchanged loose count means this load read from the pak
    why = missing != j.missing_before ? "the file was not visible on disk during loading, the engine read it from the pak"
                                      : "no path lookup for this file during loading (file version number differs from what the game requests, or the new resource came from an existing load request)";
    char buf[96];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "; path lookup counts: loose +%u (forced +%u), file not visible +%u", loose - j.loose_before,
                forced - j.forced_before, missing - j.missing_before);
    why += buf;
    return false;
}

void HotReload::restart_effect_players(const ResMap& map) {
    if (map.empty()) return;
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();

    static const auto get_scene = tdb->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = tdb->find_method("via.Scene", "findComponents(System.Type)");
    static const auto player_t = tdb->find_type("via.effect.EffectPlayer");
    static const auto get_resource = player_t ? player_t->find_method("get_Resource") : nullptr;
    static const auto set_resource = player_t ? player_t->find_method("set_Resource") : nullptr;
    static const auto get_state = player_t ? player_t->find_method("get_State") : nullptr;
    static const auto set_action = player_t ? player_t->find_method("set_Action") : nullptr;
    if (!get_scene || !find_components || !get_resource || !set_resource || !get_state || !set_action) {
        log_disabled("EffectPlayer methods not found, skipping refresh");
        return;
    }

    auto scene_manager = api->get_native_singleton("via.SceneManager");
    auto scene = get_scene->call<API::ManagedObject*>(vm, scene_manager);
    if (scene == nullptr) return;
    auto arr = find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.effect.EffectPlayer"));
    if (arr == nullptr) return;

    const auto count = *(uint32_t*)((uintptr_t)arr + ARRAY_COUNT);
    uint32_t refreshed = 0, restarted = 0;
    for (uint32_t i = 0; i < count; ++i) {
        auto player = *(API::ManagedObject**)((uintptr_t)arr + ARRAY_DATA + 8ull * i);
        if (player == nullptr) continue;
        auto holder = get_resource->call<API::ManagedObject*>(vm, player);
        uintptr_t res = 0;
        if (holder == nullptr || !safe_read_ptr((uintptr_t)holder + OWNER_RESOURCE_OFFSET, res)) continue;
        const auto m = map.find(res);
        if (m == map.end()) continue;

        const auto state = get_state->call<uint32_t>(vm, player);
        auto new_holder = (API::ManagedObject*)api->sdk()->resource->create_holder((REFrameworkResourceHandle)m->second.first, m->second.second->holder_type);
        if (new_holder == nullptr) continue;
        set_resource->call<void>(vm, player, new_holder);
        ++refreshed;
        if (state == STATE_START || state == STATE_RUNNING) {
            set_action->call<void>(vm, player, ACTION_START);
            ++restarted;
        }
    }
    if (refreshed > 0) log("  Refreshed %u EffectPlayers (%u restarted)", refreshed, restarted);
}

// EPV data (elements of via.effect.script.EPVData<T>, base class via.effect.ProviderData) stores efx in native arrays
// without going through managed holders; the memory scan cannot replace them, so they are replaced with getResources/setResources
void HotReload::refresh_provider_data(const ResMap& map) {
    if (map.empty()) return;
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();

    static const auto get_scene = tdb->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = tdb->find_method("via.Scene", "findComponents(System.Type)");
    static const auto get_res_count = tdb->find_method("via.effect.ProviderData", "getResourcesCount");
    static const auto get_res = tdb->find_method("via.effect.ProviderData", "getResources(System.UInt64)");
    static const auto set_res = tdb->find_method("via.effect.ProviderData", "setResources(System.UInt64, via.effect.EffectResourceHolder)");
    if (!get_scene || !find_components || !get_res_count || !get_res || !set_res) {
        log_disabled("ProviderData methods not found, skipping EPV data refresh");
        return;
    }

    auto scene = get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager"));
    if (scene == nullptr) return;
    auto arr = find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.effect.script.EPVDataBase"));
    if (arr == nullptr) return;

    // EPVData<T> is generic; getElementCount/getElement are cached per concrete type
    struct ElementMethods {
        API::Method* count;
        API::Method* get;
    };
    static std::unordered_map<API::TypeDefinition*, ElementMethods> methods{};

    uint32_t replaced = 0;
    const auto count = *(uint32_t*)((uintptr_t)arr + ARRAY_COUNT);
    for (uint32_t i = 0; i < count; ++i) {
        auto data = *(API::ManagedObject**)((uintptr_t)arr + ARRAY_DATA + 8ull * i);
        if (data == nullptr) continue;
        auto td = data->get_type_definition();
        auto it = methods.find(td);
        if (it == methods.end()) {
            it = methods.emplace(td, ElementMethods{td->find_method("getElementCount"), td->find_method("getElement(System.UInt32)")}).first;
        }
        if (it->second.count == nullptr || it->second.get == nullptr) continue;

        const auto elements = it->second.count->call<uint32_t>(vm, data);
        for (uint32_t e = 0; e < elements; ++e) {
            auto element = it->second.get->call<API::ManagedObject*>(vm, data, e);
            if (element == nullptr) continue;
            const auto res_count = get_res_count->call<uint64_t>(vm, element);
            for (uint64_t r = 0; r < res_count; ++r) {
                auto holder = get_res->call<API::ManagedObject*>(vm, element, r);
                uintptr_t res = 0;
                if (holder == nullptr || !safe_read_ptr((uintptr_t)holder + OWNER_RESOURCE_OFFSET, res)) continue;
                const auto m = map.find(res);
                if (m == map.end()) continue;
                auto new_holder = (API::ManagedObject*)api->sdk()->resource->create_holder((REFrameworkResourceHandle)m->second.first, m->second.second->holder_type);
                if (new_holder == nullptr) continue;
                set_res->call<void>(vm, element, r, new_holder);
                ++replaced;
            }
        }
    }
    if (replaced > 0) log("  Replaced %u references in EPV data", replaced);
}

std::vector<std::wstring> HotReload::referrer_candidates(const std::wstring& path, const wchar_t* filter,
                                                        const TypeHandler* handler) const {
    std::vector<std::wstring> candidates{};
    if (handler == nullptr) return candidates;
    const auto self = ResourceCache::normalize(path);
    std::vector<std::wstring> files{};
    if (!m_ref_index.find(path, filter, files)) files = find_referrers(m_natives_dir, path, filter); // Index not built yet (the first few seconds after startup)
    for (const auto& rel : files) {
        std::wstring res_path{};
        const TypeHandler* h{};
        if (!map_file(rel, res_path, h) || h != handler) continue;
        if (ResourceCache::normalize(res_path) == self) continue;
        if (std::find(candidates.begin(), candidates.end(), res_path) == candidates.end()) candidates.push_back(res_path);
    }
    return candidates;
}

std::vector<std::wstring> HotReload::loaded_referrers(const std::wstring& path, const wchar_t* filter,
                                                     const TypeHandler* handler) const {
    std::vector<std::wstring> result{};
    const auto candidates = referrer_candidates(path, filter, handler);
    // Files not loaded naturally use the new dependency the next time they load. Look all of them up in one walk of the cache table (looking up one by one walks the whole table for every unloaded one)
    const auto loaded = ResourceCache::find_many(candidates);
    for (const auto& p : candidates) {
        if (loaded.contains(ResourceCache::normalize(p))) result.push_back(p);
    }
    return result;
}

void HotReload::cascade(const std::vector<std::pair<std::wstring, const TypeHandler*>>& done) {
    static const auto efx_handler = handler_for_ext(L"efx");
    std::vector<std::pair<std::wstring, std::vector<std::wstring>>> per{};
    std::vector<std::wstring> all{};
    for (const auto& [path, handler] : done) {
        if (handler == nullptr || !handler->referenced_by_efx) continue;
        auto c = referrer_candidates(path, L".efx.", efx_handler);
        all.insert(all.end(), c.begin(), c.end());
        per.emplace_back(path, std::move(c));
    }
    if (all.empty()) return;
    const auto loaded = ResourceCache::find_many(all);
    for (const auto& [path, candidates] : per) {
        for (const auto& p : candidates) {
            if (loaded.contains(ResourceCache::normalize(p))) enqueue(p, efx_handler, L"dependency " + path);
        }
    }
}

// Cache-update-only types referenced by path from efx. Counted over all 9245 efx of the game (number of efx in which they appear): uvs 8468, mdf2 3622, mesh 3089,
// uvar 2138, tex 1720, pfb 1404, efx 586, mmtr 372, efcsv 239, htex 92, user 52, mot 34, abcmesh 15, rtex 4.
// uvs/efcsv/efx go through cascade, pfb swaps content in place, the rest are handled here. user is excluded: efx neither loads nor holds the .user files it references, at load or playback (observed for 6)
bool HotReload::effect_dependency(const TypeHandler* h) {
    static const std::array<const TypeHandler*, 9> types{
        handler_for_ext(L"tex"),  handler_for_ext(L"mdf2"), handler_for_ext(L"mesh"), handler_for_ext(L"mmtr"),
        handler_for_ext(L"uvar"), handler_for_ext(L"htex"), handler_for_ext(L"mot"), handler_for_ext(L"abcmesh"),
        handler_for_ext(L"rtex")};
    return h != nullptr && std::find(types.begin(), types.end(), h) != types.end();
}

// Cache-update-only resources are taken and held by uvs and efx when they load (observed: uvs data stores texture resource pointers that still point to the old texture after it reloads),
// so the loose uvs (textures only) and efx referencing them are reloaded. When the same efx also references other files being reloaded in this batch (uvs, cascaded mdf2, etc.),
// waits_for_effect_deps in the start loop makes it wait for those; the cascade on their completion merges with it so it loads only once
void HotReload::cascade_effects(const Job& j) {
    if (!effect_dependency(j.handler)) return;
    static const auto uvs_handler = handler_for_ext(L"uvs");
    static const auto efx_handler = handler_for_ext(L"efx");
    const bool tex = std::string_view{j.handler->resource_type} == "via.render.TextureResource";
    const auto uvs = tex ? loaded_referrers(j.path, L".uvs.", uvs_handler) : std::vector<std::wstring>{};
    const auto efx = loaded_referrers(j.path, L".efx.", efx_handler);
    for (const auto& p : uvs) enqueue(p, uvs_handler, L"dependency " + j.path);
    for (const auto& p : efx) enqueue(p, efx_handler, L"dependency " + j.path);
    if (!uvs.empty()) log("  Referencing uvs: %zu, efx: %zu, reloaded as well", uvs.size(), efx.size());
    else if (!efx.empty()) log("  Referencing efx: %zu, reloaded as well", efx.size());
}

void HotReload::release_job_refs(const Job& j) {
    release_resource(j.old_res);
    if (j.extra_old != 0) release_resource(j.extra_old);
    release_resource(j.new_res);
}

const HotReload::HeldInfo* HotReload::cached_held(uintptr_t comp) {
    const auto it = m_held_cache.find(comp);
    if (it == m_held_cache.end()) return nullptr;
    uintptr_t vt = 0, go = 0, head = 0;
    // Component +0x08 low 32 bits are the reference count, +0x10 the owning GameObject; invalid once the component is released or its address reused by another object
    if (safe_read_ptr(comp, vt) && safe_read_ptr(comp + 0x10, go) && safe_read_ptr(comp + 8, head) && (int32_t)(uint32_t)head > 0 &&
        vt == it->second.vtable && go != 0 && go == it->second.go) {
        return &it->second;
    }
    m_held_cache.erase(it);
    return nullptr;
}

void HotReload::remember_held(uintptr_t comp, const std::vector<std::string>& owners) {
    uintptr_t vt = 0, go = 0;
    if (!safe_read_ptr(comp, vt) || !safe_read_ptr(comp + 0x10, go) || go == 0) return;
    if (m_held_cache.size() >= 4096) m_held_cache.clear();
    m_held_cache[comp] = {vt, go, owners};
}

static std::string join_owners(const std::vector<std::string>& owners) {
    std::string who{};
    for (size_t i = 0; i < owners.size() && i < 4; ++i) who += (i ? ", " : "") + owners[i];
    return who;
}

void HotReload::finish_jobs(std::vector<Job>& jobs) {
    // 0. pfb: existing native components whose data changed are first written in place property by property (no memory scan; visible about one or two frames after saving);
    //    then holders are checked in the background, and those not held by game code are still rebuilt from the new file (see step 1 and the handling of m_plans in on_frame).
    //    In-place writes cannot replace rebuilds: some setters only store the value, and the engine uses it only on rebuild/reset (e.g. CollisionShapePreset.set_Enabled).
    //    Held components are only written in place; the check result is cached and not rescanned on the next save
    for (auto& j : jobs) {
        if (!m_cfg.live_params || !j.handler->live_params || j.planned) continue;
        const auto candidates = PrefabLive::rebuild_candidates(j.old_res, j.new_res);
        if (!candidates.empty()) j.in_place = std::make_shared<std::unordered_set<uintptr_t>>(candidates.begin(), candidates.end());
    }
    // 1. Do the immediately visible part first: refresh effects, live parameters, cascades
    // EPV data and EffectPlayers using old resources: swap the whole batch together (the scene is walked only once)
    {
        ResMap effects{};
        for (const auto& j : jobs) {
            if (!j.handler->restart_effect_players) continue;
            for (const auto old : {j.old_res, j.extra_old}) {
                if (old != 0) effects[old] = {j.new_res, j.handler};
            }
        }
        refresh_provider_data(effects);
        if (m_cfg.restart_effects) restart_effect_players(effects);
    }
    std::vector<Job> finished{};
    std::vector<std::pair<std::wstring, const TypeHandler*>> cascade_done{};
    for (auto& j : jobs) {
        if (j.applied) {
            // Live parameters written, no components to rebuild
        } else if (j.planned) {
            log("Continuing %s: rebuilding components not held by game code from the new file", narrow(j.path).c_str());
        } else {
            log("Reloaded %s (%s)", narrow(j.path).c_str(), narrow(j.reason).c_str());
        }
        if (m_cfg.live_params && j.handler->live_params && !j.applied) {
            LiveApplyResult r{};
            g_trace_note = j.planned ? "live params: rebuild components not held" : "live params: in-place write";
            r = PrefabLive::apply(j.old_res, j.new_res, m_cfg.verbose, j.in_place.get());
            g_trace_note = "live params: after write";
            if (r.instances > 0) {
                log("  Live parameters: %u scene instances, %u components rebuilt, other writes to %u objects at %u places%s", r.instances, r.rebuilt, r.components, r.fields,
                    r.structure_changed ? "; some changes could not be hot-updated (see above)" : "");
            }
            queue_object_scan(r);
            if (!j.planned && j.in_place && !j.in_place->empty()) {
                // Components written in place: those checked and found held by game code are not rescanned; the rest get a background holder check, after which this job is processed again (rebuilding the unheld ones)
                std::vector<uintptr_t> unknown{};
                for (const auto c : *j.in_place) {
                    if (const auto h = cached_held(c)) {
                        log("  %s is held by game code (%s, earlier check reused), not rebuilt", PrefabLive::component_label(c).c_str(), join_owners(h->owners).c_str());
                    } else {
                        unknown.push_back(c);
                    }
                }
                if (!unknown.empty()) {
                    log("  Written in place; checking holders of %zu components, those not held are rebuilt from the new file", unknown.size());
                    auto plan = start_plan(std::move(unknown));
                    plan->job = std::move(j);
                    m_plans.push_back(std::move(plan));
                    continue;
                }
            }
        }
        if (m_cfg.cascade) cascade_done.emplace_back(j.path, j.handler);
        finished.push_back(std::move(j));
    }
    if (!cascade_done.empty()) cascade(cascade_done);

    // 2. Replace resource content in place (pfb); other types scan memory in the background and replace references on the main thread when done (see complete_scan)
    std::vector<Job> scan_jobs{};
    // Prefabs still holding the old versions of the cache-only resources of this batch (.user excluded: checked in finish_cached only when it falls back to a cache-only update)
    if (m_cfg.cascade) {
        std::vector<const Job*> cached{};
        for (const auto& j : finished) {
            if (j.handler->cache_only && std::string_view{j.handler->resource_type} != "via.UserDataResource") cached.push_back(&j);
        }
        if (!cached.empty()) {
            auto run = [&] { cascade_prefabs(cached); };
            if (const auto code = seh_call(run); code != 0) log("  Error while looking up prefabs using the old resources (exception 0x%08lX), skipped", code);
        }
    }
    for (auto& j : finished) {
        if (j.handler->cache_only) {
            finish_cached(j);
            continue;
        }
        if (j.handler->in_place && finish_in_place(j)) continue;
        scan_jobs.push_back(std::move(j));
    }
    if (scan_jobs.empty()) return;
    // Jobs just queued by a cascade that will also need scanning (uvs -> efx, a referenced efx -> the efx referencing it): skip scanning this batch for now and merge it into one scan when they complete
    // (each scan reads about 5 GB; previously one texture -> uvs -> efx cascade scanned twice). If the wait exceeds 120 frames, frame_body scans it separately
    if (scan_jobs_pending()) {
        if (m_scan_carry.empty()) m_scan_carry_since = m_frame;
        for (auto& j : scan_jobs) m_scan_carry.push_back(std::move(j));
        return;
    }
    for (auto& j : m_scan_carry) scan_jobs.push_back(std::move(j));
    m_scan_carry.clear();
    start_resource_scan(std::move(scan_jobs));
}

bool HotReload::scan_jobs_pending() const {
    const auto scans = [](const Job& j) { return !j.handler->cache_only && !j.handler->in_place; };
    return std::any_of(m_jobs.begin(), m_jobs.end(), scans) || std::any_of(m_ready.begin(), m_ready.end(), scans);
}

void HotReload::start_resource_scan(std::vector<Job> scan_jobs) {
    auto scan = std::make_unique<PendingScan>();
    std::vector<uintptr_t> olds{};
    for (const auto& j : scan_jobs) {
        scan->mapping[j.old_res] = j.new_res;
        olds.push_back(j.old_res);
        if (j.extra_old != 0) {
            scan->mapping[j.extra_old] = j.new_res;
            olds.push_back(j.extra_old);
        }
    }
    // The same file was reloaded twice within a merged batch (old -> new 1 -> new 2): references to the old one are repointed directly to the latest
    for (auto& [o, n] : scan->mapping) {
        for (int hops = 0; hops < 8; ++hops) {
            const auto it = scan->mapping.find(n);
            if (it == scan->mapping.end() || it->second == n) break;
            n = it->second;
        }
    }
    scan->stats = std::make_shared<ScanStats>();
    scan->result = std::async(std::launch::async, [olds, stats = scan->stats]() {
        g_trace_note = "background: scanning resource references";
        return scan_pointers(olds, *stats);
    });
    scan->jobs = std::move(scan_jobs);
    m_scans.push_back(std::move(scan));
}

std::unique_ptr<HotReload::PendingPlan> HotReload::start_plan(std::vector<uintptr_t> candidates) {
    auto plan = std::make_unique<PendingPlan>();
    auto mo = API::get()->sdk()->managed_object;
    for (const auto c : candidates) mo->add_ref((REFrameworkManagedObjectHandle)c);
    plan->candidates = std::move(candidates);
    plan->stats = std::make_shared<ScanStats>();
    plan->result = std::async(std::launch::async, [olds = plan->candidates, stats = plan->stats]() {
        g_trace_note = "background: scanning component references (holder check)";
        auto found = scan_pointers(olds, *stats);
        g_trace_note = "background: deciding holders";
        return PrefabLive::held_by_code(std::move(found));
    });
    return plan;
}

std::unordered_map<uintptr_t, std::vector<std::string>> HotReload::finish_plan(PendingPlan& plan) {
    std::unordered_map<uintptr_t, std::vector<std::string>> held{};
    if (plan.result.valid()) {
        try {
            held = plan.result.get();
        } catch (...) {
            // Check failed: treat everything as held (no rebuild, write in place)
            for (const auto c : plan.candidates) held[c] = {"?"};
        }
    }
    // Holding other than managed references: state registered into the component by game code at runtime (cannot be restored after a rebuild)
    for (const auto c : plan.candidates) {
        if (held.contains(c)) continue;
        try {
            if (auto who = PrefabLive::runtime_registered_by_game(c); !who.empty()) held[c] = {std::move(who)};
        } catch (...) {
        }
    }
    auto mo = API::get()->sdk()->managed_object;
    for (const auto c : plan.candidates) mo->release((REFrameworkManagedObjectHandle)c);
    plan.candidates.clear();
    return held;
}

HotReload::PendingScan* HotReload::queue_object_scan(const LiveApplyResult& r, bool keep_old) {
    if (r.replaced.empty()) return nullptr;
    // References from other objects to the pre-rebuild components/sub-objects: scan memory in the background and repoint them to the new objects on the main thread when done
    auto scan = std::make_unique<PendingScan>();
    scan->objects = true;
    scan->keep_old = keep_old;
    for (const auto& [o, n] : r.replaced) {
        uintptr_t header = 0;
        const auto td = PrefabLive::type_handle(o);
        if (td == nullptr || !safe_read_ptr(o, header)) {
            // Passed the type check when collected but its type can no longer be read now: it has been reclaimed (or reused), so do not release it and do not rewrite references to it
            log("    Pre-rebuild object %llx (new object %llx: %s) was already invalid when queued, not released", (unsigned long long)o, (unsigned long long)n,
                PrefabLive::type_name(PrefabLive::type_handle(n)).c_str());
            continue;
        }
        scan->held.push_back(o);
        scan->held_id[o] = {header, td};
        uintptr_t counter = 0;
        if (safe_read_ptr(o + 8, counter)) scan->held_refs[o] = (int32_t)(uint32_t)counter;
        uintptr_t go = 0;
        if (safe_read_ptr(o + 0x10, go) && go != 0) scan->held_go[o] = go;
        if (scan->mapping.emplace(o, n).second) scan->olds.push_back(o);
    }
    // A previous rebuild scan not yet finished: if its target is replaced again this time, repoint to the latest object (otherwise references would be repointed to an object that was already replaced)
    for (auto& pending : m_scans) {
        if (!pending->objects) continue;
        for (auto& [o, n] : pending->mapping) {
            if (const auto it = scan->mapping.find(n); it != scan->mapping.end()) n = it->second;
        }
    }
    // Start scanning while the old components are still working; commit (hand to the engine for destruction) only after the scan completes, and once they are detached attach the new components and rewrite references in the same update-phase callback.
    // Rewriting happens after detaching: the old components clean up part of their references themselves when detached (onDestroy), and rewriting first would conflict with that
    scan->wait_detached = r.old_components;
    start_object_scan(*scan);
    m_scans.push_back(std::move(scan));
    return m_scans.back().get();
}

void HotReload::finish_object_scan(PendingScan& scan) {
    g_scan_stage = g_trace_note = "attaching rebuilt components";
    PrefabLive::attach_ready(scan.wait_detached);
    g_scan_stage = g_trace_note = "redirecting component references";
    const std::unordered_set<uintptr_t> components(scan.wait_detached.begin(), scan.wait_detached.end());
    const auto patched = PrefabLive::patch_refs(*scan.slots, scan.mapping, components, m_cfg.verbose);
    g_scan_stage = g_trace_note = "releasing pre-rebuild objects";
    // Old objects still referenced by raw pointers from live components are kept (releasing them would leave dangling pointers). The old components are already detached, so what onDestroy cleaned up no longer counts
    // Raw pointers in other components (e.g. equipment's ChildSecondary pointing to the parent's Motion) are repointed to the new objects as well; old objects referenced this way are kept
    std::vector<std::string> raw_where{};
    const auto raw = PrefabLive::raw_still_referenced(*scan.raw_slots, &raw_where);
    const auto raw_patched = raw.empty() ? 0u : PrefabLive::patch_raw(*scan.raw_slots, scan.mapping);
    for (const auto& w : raw_where) log("    Native pointer: %s, now points to the new object", w.c_str());
    std::vector<uintptr_t> release_components{}, release_others{};
    size_t kept = 0;
    // Before releasing, verify it is still the object that was queued: memory committed and readable, object header and type unchanged, reference count greater than 0.
    // We hold a reference, so it should not be reclaimed; if it was, someone else decremented the count once too often. Releasing it now would hit an access violation inside the engine's release function,
    // and unwinding the engine stack frames through SEH terminates the process with STATUS_BAD_STACK (observed 2026-10-30)
    auto same_object = [&](uintptr_t o) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery((LPCVOID)o, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 ||
            o + 0x10 > (uintptr_t)mbi.BaseAddress + mbi.RegionSize) {
            return false;
        }
        uintptr_t header = 0, counter = 0;
        const auto it = scan.held_id.find(o);
        if (it == scan.held_id.end() || !safe_read_ptr(o, header) || header != it->second.first || !safe_read_ptr(o + 8, counter)) return false;
        return (int32_t)(uint32_t)counter > 0 && PrefabLive::type_handle(o) == it->second.second;
    };
    for (const auto o : scan.held) {
        if (raw.contains(o)) {
            ++kept;
            PrefabLive::clear_release_trace(o);
        } else if (!same_object(o)) {
            // For error logs: object header, type and count when queued and now
            const auto it = scan.held_id.find(o);
            MEMORY_BASIC_INFORMATION mbi{};
            const bool committed = VirtualQuery((LPCVOID)o, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.State == MEM_COMMIT &&
                                   (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
            uintptr_t header = 0, counter = 0;
            if (committed) {
                safe_read_ptr(o, header);
                safe_read_ptr(o + 8, counter);
            }
            const auto now_td = committed ? PrefabLive::type_handle(o) : nullptr;
            const auto rit = scan.held_refs.find(o);
            const auto git = scan.held_go.find(o);
            // When the engine destroys a GameObject it reclaims the components still on it directly, regardless of external references (confirmed by experiment 2026-10-31: after adding a reference to a component and destroying the GameObject,
            // the object header became exe+dfd1100 with count 0; destroying only the component, or detaching it first and then destroying the GameObject, does not do this). If the GameObject is destroyed between rebuild preparation and the old component being detached
            // (distant individuals in the field reclaimed by the game, etc.) this happens; it is normal, just skip the release
            const bool go_destroyed = git != scan.held_go.end() && !PrefabLive::game_object_alive(git->second);
            const char* go_state = git == scan.held_go.end() ? "no owning GameObject when queued" :
                                   (go_destroyed ? "owning GameObject destroyed, the engine reclaimed the component with it (normal)" : "owning GameObject still alive (abnormal)");
            log("    Pre-rebuild object %llx already reclaimed, release skipped (%s; when queued %s header %llx count %d; now %s header %llx count %d %s; released by the plugin on behalf of holders: %s)",
                (unsigned long long)o, go_state, it != scan.held_id.end() ? PrefabLive::type_name(it->second.second).c_str() : "not recorded",
                it != scan.held_id.end() ? (unsigned long long)it->second.first : 0ull, rit != scan.held_refs.end() ? rit->second : -999,
                PrefabLive::type_name(now_td).c_str(), (unsigned long long)header, (int32_t)(uint32_t)counter, committed ? "" : "memory not committed",
                PrefabLive::take_release_trace(o).c_str());
        } else {
            (components.contains(o) ? release_components : release_others).push_back(o);
            PrefabLive::clear_release_trace(o);
        }
    }
    const auto freed = PrefabLive::release_objects(release_components);
    uint32_t freed_others = 0;
    if (scan.keep_old) {
        PrefabLive::keep_replaced(release_others);
    } else {
        freed_others = PrefabLive::release_objects(release_others);
    }
    if (components.empty()) {
        // Old objects swapped out by .user (no components to wait to be detached)
        if (scan.keep_old) {
            log("  Replaced old objects: %zu; references elsewhere redirected to the new objects: %u; old objects kept, not released (background scan %.1f MB, %.0f ms)", scan.held.size(),
                patched + raw_patched, scan.stats->bytes_scanned / 1048576.0, scan.stats->milliseconds);
        } else {
            log("  Replaced old objects: %zu; references elsewhere redirected to the new objects: %u; reclaimed %u%s (background scan %.1f MB, %.0f ms)", scan.held.size(), patched + raw_patched,
                freed_others, kept == 0 ? "" : (", " + std::to_string(kept) + " were referenced by component native pointers, kept").c_str(), scan.stats->bytes_scanned / 1048576.0,
                scan.stats->milliseconds);
        }
    } else {
        log("  Rebuilt components: references in other objects redirected to the new objects: %u; old components reclaimed %u / %zu%s (background scan %.1f MB, %.0f ms)", patched, freed,
            components.size(), kept == 0 ? "" : (", " + std::to_string(kept) + " old objects were referenced by native pointers of other components (redirected to the new objects), kept").c_str(),
            scan.stats->bytes_scanned / 1048576.0, scan.stats->milliseconds);
    }
    scan.held.clear();
    g_scan_stage = g_trace_note = "";
}

// Committed rebuilds: attach and rewrite references once all old components are detached. Frames are counted when from_frame; after 120 frames without detaching they are processed anyway (the old component stays after the new one)
void HotReload::process_awaiting(bool from_frame) {
    if (m_awaiting.empty() || m_in_entry || GetCurrentThreadId() != m_main_thread) return;
    m_in_entry = true;
    constexpr uint32_t MAX_WAIT_FRAMES = 120;
    for (auto it = m_awaiting.begin(); it != m_awaiting.end();) {
        auto& s = **it;
        const bool detached = PrefabLive::all_detached(s.wait_detached);
        const bool overdue = from_frame && ++s.waited > MAX_WAIT_FRAMES;
        if (!detached && !overdue) {
            ++it;
            continue;
        }
        if (overdue && !detached) log("  Rebuilt components: old components still not detached by the engine after %u frames, attaching the new components anyway", MAX_WAIT_FRAMES);
        auto scan = std::move(*it);
        it = m_awaiting.erase(it);
        auto run = [&] { finish_object_scan(*scan); };
        if (const auto code = seh_call(run); code != 0) {
            log("  Error while attaching or rewriting references (stage: %s, exception 0x%08lX); the unfinished part was skipped", g_scan_stage, code);
        }
    }
    m_in_entry = false;
}

void HotReload::on_entry() {
    entry_body();
}

void HotReload::entry_body() {
    if (!m_initialized || m_failed) return;
    process_awaiting(false);
}

// Hooks in the loader are installed and retried there (about once per second, at most 60 times); once both are settled, record those it gave up on in the crash log
static void check_loader_hooks() {
    static bool done = false;
    static uint32_t calls = 0;
    if (done || calls++ % 60 != 0) return;
    using StateFn = void (*)(int*, int*);
    const auto m = GetModuleHandleW(L"file_hotreload.dll");
    const auto fn = m ? (StateFn)GetProcAddress(m, "loader_hook_state") : nullptr;
    if (fn == nullptr) { // Older loaders lack this export
        done = true;
        return;
    }
    int path_hash = 0, dstorage = 0;
    fn(&path_hash, &dstorage);
    if (path_hash == 0 || dstorage == 0) return;
    done = true;
    // The loader has already written the details to the REFramework log
    if (path_hash < 0) crash_trace_note("Engine path hash function hook not installed: loose files added while the game runs take effect only after a restart");
    if (dstorage < 0) crash_trace_note("DirectStorage file close compensation not installed: reference counts are not compensated when loose textures are closed");
}

void HotReload::on_frame() {
    check_loader_hooks();
    frame_body();
}

void HotReload::start_object_scan(PendingScan& scan) {
    scan.started = true;
    scan.stats = std::make_shared<ScanStats>();
    scan.slots = std::make_shared<std::vector<RefSlot>>();
    scan.raw_slots = std::make_shared<std::vector<RefSlot>>();
    // Scanning and filtering (whether it is a counted reference inside a managed object) both run on background threads; the main thread only does the CAS replacements
    scan.result = std::async(std::launch::async, [olds = scan.olds, mapping = scan.mapping, stats = scan.stats, slots = scan.slots, raw = scan.raw_slots]() {
        g_trace_note = "background: scanning references to pre-rebuild objects";
        auto found = scan_pointers(olds, *stats);
        g_trace_note = "background: filtering reference locations";
        *slots = PrefabLive::find_ref_slots(found, mapping, *raw);
        return found;
    });
}

// The old resource object takes the new content and stays in the cache; the new resource object carries the old content and is released later
bool HotReload::finish_in_place(const Job& j) {
    if (!PrefabLive::swap_content(j.old_res, j.new_res)) {
        log("  %s: replacing resource contents in place failed, scanning and replacing references instead", narrow(j.path).c_str());
        return false;
    }
    // The new resource's node in the cache is repointed to the old resource object; if the keys differ (cannot replace) it is removed from the cache and later loads read the disk again
    if (!ResourceCache::replace(j.new_res, j.old_res)) ResourceCache::evict(j.new_res);
    release_later(j.new_res);
    release_resource(j.old_res);
    if (j.extra_old != 0) release_resource(j.extra_old);
    return true;
}

// ---- Dependency cascade (parsed per type): mdf2 takes the texture and mmtr resources when it loads and holds them; meshes spawned later use them through the mdf2 in the cache,
//      so after a texture/mmtr cache update the mdf2 referencing it must be reloaded too (observed 2026-10-31: replacing only the texture left new instances with the old texture) ----
namespace {
// Read a 0-terminated UTF-16 string (at most cap-1 characters); returns 0 on failure
size_t read_wstr(uintptr_t addr, wchar_t* buf, size_t cap) {
    __try {
        size_t i = 0;
        for (; i + 1 < cap; ++i) {
            const wchar_t c = ((volatile wchar_t*)addr)[i];
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

// Read 4 bytes (pointers in material headers are not 8-byte aligned, so read 4 bytes at a time)
bool read_u32(uintptr_t addr, uint32_t& out) {
    __try {
        out = *(volatile uint32_t*)addr;
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

bool read_u64_unaligned(uintptr_t addr, uint64_t& out) {
    uint32_t lo = 0, hi = 0;
    if (!read_u32(addr, lo) || !read_u32(addr + 4, hi)) return false;
    out = ((uint64_t)hi << 32) | lo;
    return true;
}

// MeshMaterialResource +0x58 is the raw MDF data read at load (offsets relocated to addresses):
//   +0x00 "MDF\0", +0x06 u16 material count; material headers from +0x10, 0x64 bytes each (mdf2.45):
//   +0x14 u32 texture count, +0x3C texture header array, +0x54 mmtr path; texture headers are 0x20 bytes each, +0x10 texture path
constexpr uintptr_t MDF_DATA = 0x58;
constexpr uint32_t MDF_MAGIC = 0x0046444D; // "MDF\0" (little-endian)
constexpr uintptr_t MDF_MATERIALS = 0x10;
constexpr uintptr_t MDF_MATERIAL_SIZE = 0x64;
constexpr uintptr_t MAT_TEX_COUNT = 0x14;
constexpr uintptr_t MAT_TEX_HEADERS = 0x3C;
constexpr uintptr_t MAT_MMTR_PATH = 0x54;
constexpr uintptr_t TEX_HEADER_SIZE = 0x20;
constexpr uintptr_t TEX_PATH = 0x10;
constexpr uintptr_t MDF_MAX_SPAN = 0x1000000; // Maximum distance of in-file pointers from the data start

// Parameter info in the material header: +0x00 name, +0x0C parameter data size, +0x10 parameter count, +0x34 parameter header array, +0x4C parameter data;
// parameter headers are 0x18 bytes each: +0x00 name, +0x10 offset within the data, +0x14 component count. Texture header +0x00 is the slot name
constexpr uintptr_t MAT_NAME = 0x00;
constexpr uintptr_t MAT_PARAM_SIZE = 0x0C;
constexpr uintptr_t MAT_PARAM_COUNT = 0x10;
constexpr uintptr_t MAT_PARAM_HEADERS = 0x34;
constexpr uintptr_t MAT_PARAM_DATA = 0x4C;
constexpr uintptr_t PARAM_HEADER_SIZE = 0x18;
constexpr uintptr_t PARAM_OFFSET = 0x10;
constexpr uintptr_t PARAM_COMPONENTS = 0x14;
constexpr uintptr_t TEX_SLOT_NAME = 0x00;

struct MdfMaterial {
    std::unordered_map<std::wstring, std::vector<uint32_t>> params; // Parameter name -> components (float bit patterns)
    std::unordered_map<std::wstring, std::wstring> textures;        // Texture slot name -> path (normalized)
};
using MdfInfo = std::unordered_map<std::wstring, MdfMaterial>; // Material name -> content

// Parse the material parameters and textures in the raw data of an mdf2 resource; returns false if the format does not match
bool parse_mdf(uintptr_t res, MdfInfo& out) {
    uintptr_t data = 0;
    uint32_t magic = 0, head = 0;
    if (!safe_read_ptr(res + MDF_DATA, data) || data == 0 || !read_u32(data, magic) || magic != MDF_MAGIC || !read_u32(data + 4, head)) return false;
    const uint32_t materials = head >> 16;
    if (materials == 0 || materials > 1024) return false;
    const auto in_file = [&](uint64_t p) { return p > data && p < data + MDF_MAX_SPAN; };
    const auto text = [&](uint64_t p, std::wstring& s) {
        if (!in_file(p)) return false;
        wchar_t buf[260];
        if (read_wstr((uintptr_t)p, buf, 260) == 0) return false;
        s = buf;
        return true;
    };
    for (uint32_t m = 0; m < materials; ++m) {
        const auto mat = data + MDF_MATERIALS + MDF_MATERIAL_SIZE * m;
        uint64_t name_p = 0, param_headers = 0, param_data = 0, tex_headers = 0;
        uint32_t param_size = 0, param_count = 0, tex_count = 0;
        std::wstring name{};
        if (!read_u64_unaligned(mat + MAT_NAME, name_p) || !text(name_p, name) || !read_u32(mat + MAT_PARAM_SIZE, param_size) ||
            !read_u32(mat + MAT_PARAM_COUNT, param_count) || !read_u32(mat + MAT_TEX_COUNT, tex_count) ||
            !read_u64_unaligned(mat + MAT_PARAM_HEADERS, param_headers) || !read_u64_unaligned(mat + MAT_PARAM_DATA, param_data) ||
            !read_u64_unaligned(mat + MAT_TEX_HEADERS, tex_headers) || param_count > 4096 || tex_count > 1024) {
            return false;
        }
        auto& info = out[name];
        for (uint32_t i = 0; i < param_count && in_file(param_headers) && in_file(param_data); ++i) {
            const auto h = param_headers + PARAM_HEADER_SIZE * i;
            uint64_t pn = 0;
            uint32_t offset = 0, comps = 0;
            std::wstring pname{};
            if (!read_u64_unaligned(h, pn) || !text(pn, pname) || !read_u32(h + PARAM_OFFSET, offset) || !read_u32(h + PARAM_COMPONENTS, comps)) return false;
            if (comps == 0 || comps > 4 || offset + comps * 4 > param_size) continue;
            std::vector<uint32_t> v(comps);
            for (uint32_t c = 0; c < comps; ++c) {
                if (!read_u32(param_data + offset + 4 * c, v[c])) return false;
            }
            info.params[pname] = std::move(v);
        }
        for (uint32_t t = 0; t < tex_count && in_file(tex_headers); ++t) {
            const auto h = tex_headers + TEX_HEADER_SIZE * t;
            uint64_t sn = 0, pp = 0;
            std::wstring slot{}, path{};
            if (!read_u64_unaligned(h + TEX_SLOT_NAME, sn) || !text(sn, slot) || !read_u64_unaligned(h + TEX_PATH, pp)) return false;
            text(pp, path);
            info.textures[slot] = ResourceCache::normalize(path);
        }
    }
    return true;
}

// Whether the raw data of an mdf2 resource references target (a normalized resource path); returns false if the data format does not match
bool mdf2_references(uintptr_t res, const std::wstring& target) {
    uintptr_t data = 0;
    uint32_t magic = 0, head = 0;
    if (!safe_read_ptr(res + MDF_DATA, data) || data == 0 || !read_u32(data, magic) || magic != MDF_MAGIC || !read_u32(data + 4, head)) {
        return false;
    }
    const uint32_t materials = head >> 16;
    if (materials == 0 || materials > 1024) return false;
    const auto in_file = [&](uint64_t p) { return p > data && p < data + MDF_MAX_SPAN; };
    // Compared in place (copying and normalizing every texture path of 1264 mdf2 takes tens of milliseconds)
    const auto matches = [&](uint64_t p) { return in_file(p) && ResourceCache::path_matches((uintptr_t)p, target); };
    for (uint32_t m = 0; m < materials; ++m) {
        const auto mat = data + MDF_MATERIALS + MDF_MATERIAL_SIZE * m;
        uint32_t tex_count = 0;
        uint64_t headers = 0, mmtr = 0;
        if (!read_u32(mat + MAT_TEX_COUNT, tex_count) || !read_u64_unaligned(mat + MAT_TEX_HEADERS, headers) ||
            !read_u64_unaligned(mat + MAT_MMTR_PATH, mmtr)) {
            return false;
        }
        if (matches(mmtr)) return true;
        if (tex_count > 1024 || (tex_count > 0 && !in_file(headers))) return false;
        for (uint32_t t = 0; t < tex_count; ++t) {
            uint64_t path = 0;
            if (!read_u64_unaligned(headers + TEX_HEADER_SIZE * t + TEX_PATH, path)) return false;
            if (matches(path)) return true;
        }
    }
    return false;
}
}

// ---- Reuse already loaded textures when reloading mdf2 ----
namespace {
constexpr uintptr_t RES_FLAGS = 0x38;    // u8 load complete, u8 dependencies/upload complete
constexpr uint16_t RES_FULLY_LOADED = 0x0101;
bool fully_loaded(uintptr_t res) {
    uintptr_t v = 0;
    return safe_read_ptr(res + RES_FLAGS, v) && (uint16_t)(v & 0xFFFF) == RES_FULLY_LOADED;
}

}

namespace {
// Material objects of MeshMaterialResource (observed on 1.42.0.3): resource +0x68 array of material object pointers, +0x70 u32 count;
// material object +0x50 mmtr resource, +0x58 texture entry array (each 0x10 bytes {u64 id, resource*}), +0x60 u32 count.
// The mdf2's own +0x39 is set only after a mesh uses it (set_Material), so "ready to swap in" is judged by its dependencies: all resources referenced by the material objects are fully loaded.
// Returns known=false if the counts differ from the raw MDF data (material count, texture count per material)
constexpr uintptr_t MDF_RES_MATERIALS = 0x68;
constexpr uintptr_t MDF_RES_MATERIAL_COUNT = 0x70;
constexpr uintptr_t MAT_OBJ_MMTR = 0x50;
constexpr uintptr_t MAT_OBJ_TEXTURES = 0x58;
constexpr uintptr_t MAT_OBJ_TEXTURE_COUNT = 0x60;
constexpr uintptr_t TEX_ENTRY_SIZE = 0x10;
constexpr uintptr_t TEX_ENTRY_RES = 0x08;

bool is_resource_with_ext(uintptr_t res, const wchar_t* ext) {
    ResourceEntry e{};
    return res != 0 && ResourceCache::read_entry(res, e) && lower(e.path).ends_with(ext);
}

// mmtr and textures referenced by the material objects of the new mdf2 (entries that are not resources are not counted); returns false if the structure differs from the raw MDF data
bool mdf2_deps(uintptr_t res, std::vector<uintptr_t>& mmtrs, std::vector<uintptr_t>& textures) {
    uintptr_t data = 0, mats = 0;
    uint32_t magic = 0, head = 0, count = 0;
    if (!safe_read_ptr(res + MDF_DATA, data) || data == 0 || !read_u32(data, magic) || magic != MDF_MAGIC || !read_u32(data + 4, head)) return false;
    if (!safe_read_ptr(res + MDF_RES_MATERIALS, mats) || !read_u32(res + MDF_RES_MATERIAL_COUNT, count) || count != (head >> 16) || count == 0) return false;
    struct MatDeps {
        uintptr_t entries, mmtr;
        uint32_t n;
    };
    std::vector<MatDeps> deps(count);
    for (uint32_t m = 0; m < count; ++m) {
        uintptr_t obj = 0;
        uint32_t raw_n = 0;
        auto& d = deps[m];
        if (!safe_read_ptr(mats + 8ull * m, obj) || obj == 0 || !read_u32(data + MDF_MATERIALS + MDF_MATERIAL_SIZE * m + MAT_TEX_COUNT, raw_n) ||
            !safe_read_ptr(obj + MAT_OBJ_TEXTURES, d.entries) || !read_u32(obj + MAT_OBJ_TEXTURE_COUNT, d.n) || d.n != raw_n ||
            !safe_read_ptr(obj + MAT_OBJ_MMTR, d.mmtr)) {
            return false;
        }
    }
    for (const auto& d : deps) {
        if (is_resource_with_ext(d.mmtr, L".mmtr")) mmtrs.push_back(d.mmtr);
        for (uint32_t k = 0; k < d.n; ++k) {
            uintptr_t tex = 0;
            if (safe_read_ptr(d.entries + TEX_ENTRY_SIZE * k + TEX_ENTRY_RES, tex) && is_resource_with_ext(tex, L".tex")) textures.push_back(tex);
        }
    }
    return true;
}

// Resource second stage (0x140012500 on 1.42.0.3): calls resource vtable +0x50 (for textures, creating the render resource); on success sets +0x39 = 1 and returns true.
// A mesh calls it for textures with +0x39 == 0 when building materials; textures newly loaded at runtime and not yet used by a mesh stay at +0x39 = 0
// (observed 2026-11-01: a newly created loose texture becomes 0x0101 right after setMaterialTexture). A new mdf2 is swapped onto meshes only after its dependencies complete,
// so call it once first for new textures in its materials whose data is fully read (+0x38), to avoid waiting on each other
using ResourceFinalizeFn = bool (*)(uintptr_t res);
const uint8_t k_finalize_code[] = {0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x50,
                                   0x84, 0xC0, 0x74, 0x04, 0xC6, 0x46, 0x39, 0x01, 0x48, 0x83, 0xC4, 0x20, 0x5E, 0xC3};

ResourceFinalizeFn resource_finalize_fn() {
    static const auto fn = []() -> ResourceFinalizeFn {
        const auto base = (uintptr_t)GetModuleHandleW(nullptr);
        const auto nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
        auto section = IMAGE_FIRST_SECTION(nt);
        uintptr_t found = 0;
        int matches = 0;
        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
            if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
            const auto start = (const uint8_t*)(base + section->VirtualAddress);
            const size_t size = section->Misc.VirtualSize;
            for (size_t k = 0; k + sizeof(k_finalize_code) <= size; k += 16) { // Functions are 16-byte aligned
                if (memcmp(start + k, k_finalize_code, sizeof(k_finalize_code)) == 0) {
                    found = (uintptr_t)(start + k);
                    ++matches;
                }
            }
        }
        if (matches != 1) {
            log_disabled("  Resource completion function not found (signature matched %d times); mdf2 referencing textures newly loaded while the game runs will not take effect", matches);
            return nullptr;
        }
        return (ResourceFinalizeFn)found;
    }();
    return fn;
}

DWORD call_finalize(ResourceFinalizeFn fn, uintptr_t res, bool& ok) {
    __try {
        ok = fn(res);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

// Call the resource completion function for textures and mmtr in the new mdf2 whose data is read (+0x38) but whose second stage is not done (+0x39 = 0); returns the number completed.
// Resources newly loaded at runtime only complete their second stage when a mesh uses them, while a new mdf2 waits for its dependencies before being swapped onto meshes, so the plugin completes them first
// (mmtr: on 2026-11-03, after reloading default.mmtr the new mmtr stuck at 0x0001 and all 19 cascaded mdf2 reloads timed out waiting)
uint32_t create_pending_textures(uintptr_t res) {
    std::vector<uintptr_t> mmtrs{}, textures{};
    if (!mdf2_deps(res, mmtrs, textures)) return 0;
    textures.insert(textures.end(), mmtrs.begin(), mmtrs.end());
    const auto fn = resource_finalize_fn();
    if (fn == nullptr) return 0;
    uint32_t n = 0;
    std::unordered_set<uintptr_t> seen{};
    for (const auto tex : textures) {
        if (!seen.insert(tex).second || fully_loaded(tex) || !is_ready(tex)) continue;
        bool ok = false;
        if (const auto code = call_finalize(fn, tex, ok); code != 0) {
            log("  Error while completing dependency loads (exception 0x%08lX), skipped", code);
            continue;
        }
        n += ok ? 1 : 0;
    }
    return n;
}

// Normalized resource paths of dependencies (mmtr/textures) of the new mdf2 that are not fully loaded; if a file does not exist the engine still creates a resource whose +0x38 stays 0
std::vector<std::wstring> mdf2_pending_deps(uintptr_t res) {
    std::vector<uintptr_t> mmtrs{}, textures{};
    std::vector<std::wstring> out{};
    if (!mdf2_deps(res, mmtrs, textures)) return out;
    textures.insert(textures.end(), mmtrs.begin(), mmtrs.end());
    for (const auto r : textures) {
        ResourceEntry e{};
        if (fully_loaded(r) || !ResourceCache::read_entry(r, e)) continue;
        auto p = ResourceCache::normalize(e.path);
        if (std::find(out.begin(), out.end(), p) == out.end()) out.push_back(std::move(p));
    }
    return out;
}

bool mdf2_deps_loaded(uintptr_t res, bool& known) {
    std::vector<uintptr_t> mmtrs{}, textures{};
    known = mdf2_deps(res, mmtrs, textures);
    if (!known) return false;
    for (const auto r : mmtrs) {
        if (!fully_loaded(r)) return false;
    }
    for (const auto r : textures) {
        if (!fully_loaded(r)) return false;
    }
    return true;
}
}

// The resource can be handed to components: data fully read (+0x38); mdf2 additionally requires the referenced mmtr/textures to be fully loaded (their second stage is completed for them first)
bool resource_fully_ready(uintptr_t res) {
    if (res == 0 || !is_ready(res)) return false;
    if (!is_resource_with_ext(res, L".mdf2")) return true;
    create_pending_textures(res);
    bool known = false;
    const bool done = mdf2_deps_loaded(res, known);
    return done || !known;
}

bool HotReload::job_loaded(const Job& job, uintptr_t res) {
    if (!is_ready(res)) return false;
    if (std::string_view{job.handler->resource_type} != "via.render.MeshMaterialResource") return true;
    bool known = false;
    const bool done = mdf2_deps_loaded(res, known);
    return done || !known;
}

namespace {
std::wstring managed_string(const reframework::InvokeRet& r) {
    const auto s = (uintptr_t)r.ptr;
    uint32_t len = 0;
    if (r.exception_thrown || s == 0 || !read_u32(s + 0x10, len) || len == 0 || len > 1024) return {};
    std::wstring out((size_t)len, L'\0');
    for (uint32_t i = 0; i < len; ++i) {
        uint32_t two = 0;
        if (!read_u32(s + 0x14 + 2ull * i, two)) return {};
        out[i] = (wchar_t)(two & 0xFFFF);
    }
    return out;
}

void* u32_arg(uint32_t v) { return (void*)(uintptr_t)v; }

// Runtime state of one mesh material: variable values (float bit patterns, 1 component for float, 4 for float4) and textures (slot name -> {path, resource}, one reference held)
struct MaterialSnapshot {
    std::unordered_map<std::wstring, std::vector<uint32_t>> vars;
    std::unordered_map<std::wstring, std::pair<std::wstring, uintptr_t>> textures;
};

// getMaterialVariableType only ever returns these two (observed 2026-11-03: 649 meshes, 106k variables in the training area), and Mesh only has read/write methods for these two
constexpr uint32_t VAR_FLOAT = 1;
constexpr uint32_t VAR_FLOAT4 = 4;

// via.render.Mesh methods for materials and switches
struct MeshMethods {
    API::Method *get_material, *set_material, *get_mesh, *set_mesh;
    API::Method *enable_count, *get_enable, *set_enable, *parts_count, *get_parts, *set_parts;
    API::Method *material_num, *material_name, *var_num, *var_name, *var_type, *get_float, *get_float4, *set_float, *set_float4;
    API::Method *tex_num, *tex_name, *get_tex, *set_tex;
    bool materials_ok() const {
        return material_num && material_name && var_num && var_name && var_type && get_float && get_float4 && set_float && set_float4 && tex_num &&
               tex_name && get_tex && set_tex;
    }
};

const MeshMethods& mesh_methods() {
    static const MeshMethods m = [] {
        const auto tdb = API::get()->tdb();
        const auto f = [&](const char* name) { return tdb->find_method("via.render.Mesh", name); };
        return MeshMethods{f("get_Material"),
                           f("set_Material(via.render.MeshMaterialResourceHolder)"),
                           f("getMesh"),
                           f("setMesh(via.render.MeshResourceHolder)"),
                           f("getMaterialsEnableCount"),
                           f("getMaterialsEnable(System.UInt64)"),
                           f("setMaterialsEnable(System.UInt64, System.Boolean)"),
                           f("getPartsEnableCount"),
                           f("getPartsEnable(System.UInt64)"),
                           f("setPartsEnable(System.UInt64, System.Boolean)"),
                           f("get_MaterialNum"),
                           f("getMaterialName(System.UInt32)"),
                           f("getMaterialVariableNum(System.UInt32)"),
                           f("getMaterialVariableName(System.UInt32, System.UInt32)"),
                           f("getMaterialVariableType(System.UInt32, System.UInt32)"),
                           f("getMaterialFloat(System.UInt32, System.UInt32)"),
                           f("getMaterialFloat4(System.UInt32, System.UInt32)"),
                           f("setMaterialFloat(System.UInt32, System.UInt32, System.Single)"),
                           f("setMaterialFloat4(System.UInt32, System.UInt32, via.Float4)"),
                           f("getMaterialTextureNum(System.UInt32)"),
                           f("getMaterialTextureName(System.UInt32, System.UInt32)"),
                           f("getMaterialTexture(System.UInt32, System.UInt32)"),
                           f("setMaterialTexture(System.UInt32, System.UInt32, via.render.TextureResourceHolder)")};
    }();
    return m;
}

// Read one material variable (empty on failure). In invoke a Single is stored in an 8-byte slot as a double; Float4 is in bytes
std::vector<uint32_t> read_var(const MeshMethods& mm, API::ManagedObject* mesh, uint32_t m, uint32_t v, uint32_t t) {
    if (t == VAR_FLOAT) {
        const auto r = mm.get_float->invoke(mesh, {u32_arg(m), u32_arg(v)});
        if (r.exception_thrown) return {};
        const float f = (float)r.d;
        uint32_t bits = 0;
        memcpy(&bits, &f, 4);
        return {bits};
    }
    if (t == VAR_FLOAT4) {
        const auto r = mm.get_float4->invoke(mesh, {u32_arg(m), u32_arg(v)});
        if (r.exception_thrown) return {};
        std::vector<uint32_t> bits(4);
        memcpy(bits.data(), r.bytes.data(), 16);
        return bits;
    }
    return {};
}

bool write_var(const MeshMethods& mm, API::ManagedObject* mesh, uint32_t m, uint32_t v, uint32_t t, const std::vector<uint32_t>& bits) {
    if (t == VAR_FLOAT && bits.size() == 1) {
        float f = 0;
        memcpy(&f, &bits[0], 4);
        const double d = f;
        void* arg3 = nullptr;
        memcpy(&arg3, &d, 8);
        return !mm.set_float->invoke(mesh, {u32_arg(m), u32_arg(v), arg3}).exception_thrown;
    }
    if (t == VAR_FLOAT4 && bits.size() == 4) {
        alignas(16) float f4[4];
        memcpy(f4, bits.data(), 16);
        return !mm.set_float4->invoke(mesh, {u32_arg(m), u32_arg(v), (void*)f4}).exception_thrown;
    }
    return false;
}

// Current {path, resource} of a texture slot (resource 0 on failure)
std::pair<std::wstring, uintptr_t> read_tex(const MeshMethods& mm, API::ManagedObject* mesh, uint32_t m, uint32_t k) {
    const auto th = mm.get_tex->invoke(mesh, {u32_arg(m), u32_arg(k)});
    uintptr_t tres = 0;
    ResourceEntry te{};
    if (th.exception_thrown || th.ptr == nullptr || !safe_read_ptr((uintptr_t)th.ptr + OWNER_RESOURCE_OFFSET, tres) || tres == 0 ||
        !ResourceCache::read_entry(tres, te)) {
        return {};
    }
    return {ResourceCache::normalize(te.path), tres};
}

// The native implementations of Mesh.getMesh / get_Material first call a function that returns the resource slot (lea rax,[rcx+imm32]; ret; +0x340 / +0x338 on 1.42.0.3),
// then create a new holder from the Resource* in the slot. Going through invoke costs about 1 ms per call (645 meshes in 711 ms, measured), so the slot is read directly.
// The offset is taken from the getter's machine code: the target of the first call must be 48 8D 81 imm32 C3; returns 0 if not found (invoke is used instead)
uintptr_t resource_slot_offset(API::Method* getter) {
    if (getter == nullptr) return 0;
    const auto fn = (uintptr_t)getter->get_function_raw();
    for (uintptr_t p = fn; fn != 0 && p < fn + 0x40; ++p) {
        uint32_t w = 0;
        if (!read_u32(p, w) || (w & 0xFF) != 0xE8) continue;
        int32_t rel = 0;
        if (!read_u32(p + 1, (uint32_t&)rel)) return 0;
        const auto target = p + 5 + (intptr_t)rel;
        uint32_t a = 0, b = 0;
        if (!read_u32(target, a) || !read_u32(target + 4, b)) return 0;
        // 48 8D 81 [imm32] C3
        if ((a & 0xFFFFFF) != 0x818D48 || ((b >> 24) & 0xFF) != 0xC3) return 0;
        const uint32_t imm = (a >> 24) | ((b & 0xFFFFFF) << 8);
        return imm > 0 && imm < 0x10000 ? imm : 0;
    }
    return 0;
}

std::vector<bool> read_flags(API::Method* count, API::Method* get, API::ManagedObject* mesh, void* vm) {
    std::vector<bool> out{};
    if (count == nullptr || get == nullptr) return out;
    const auto n = count->call<uint64_t>(vm, mesh);
    for (uint64_t k = 0; k < n && k < 4096; ++k) out.push_back(get->call<bool>(vm, mesh, k));
    return out;
}

// When the count is unchanged, write back the switches that differ; returns the number written back
uint32_t restore_flags(API::Method* count, API::Method* get, API::Method* set, API::ManagedObject* mesh, void* vm, const std::vector<bool>& flags) {
    if (flags.empty() || count == nullptr || get == nullptr || set == nullptr || count->call<uint64_t>(vm, mesh) != flags.size()) return 0;
    uint32_t n = 0;
    for (uint64_t k = 0; k < flags.size(); ++k) {
        if (get->call<bool>(vm, mesh, k) == flags[k]) continue;
        set->call<void>(vm, mesh, k, (bool)flags[k]);
        ++n;
    }
    return n;
}
}

// After an mdf2/mesh cache update: meshes in the scene using the old resource of the same path switch to the new resource (Mesh.set_Material / setMesh), visible immediately.
// Matched by path: a mesh may still use an even older version (only the cache was updated before, or the cached version has been released).
// Runtime state (material parameters and textures, material switches and part switches changed at runtime by MeshSetting, MDF-XL, etc.) is recorded before the swap; after it:
//   mdf2: parameters/textures the file did not change (old mdf2 -> new mdf2) but whose runtime value differs from the old file get the runtime value back; ones the file changed take the new file value;
//   mesh: the material file is unchanged, so every parameter/texture that differs from before the swap is written back (observed that setMesh itself does not reset them; done as a safeguard).
// With new_res 0 it only looks up: returns the resource of this path currently used by scene meshes (no refresh)
// Mesh objects generated while effects play (parent has a via.effect.EffectPlayer). The effect system builds motion data for these meshes from the mesh skeleton;
// swapping in a mesh with a different skeleton via setMesh at runtime makes worker threads read with the old structure and crash (observed 11-03 at exe+a964d0e; the same file loads fine after a restart).
// The plugin does not replace them: the efx referencing the mesh/material is cascade-reloaded and replayed, and the effect rebuilds these objects with the new resources
static bool is_effect_mesh(API::ManagedObject* mesh) {
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();
    static const auto get_go = tdb->find_method("via.Component", "get_GameObject");
    static const auto get_transform = tdb->find_method("via.GameObject", "get_Transform");
    static const auto get_parent = tdb->find_method("via.Transform", "get_Parent");
    static const auto t_get_go = tdb->find_method("via.Transform", "get_GameObject");
    static const auto get_component = tdb->find_method("via.GameObject", "getComponent(System.Type)");
    static const auto player_type = api->typeof("via.effect.EffectPlayer");
    if (!get_go || !get_transform || !get_parent || !t_get_go || !get_component || !player_type) return false;
    const auto go = get_go->call<API::ManagedObject*>(vm, mesh);
    const auto t = go ? get_transform->call<API::ManagedObject*>(vm, go) : nullptr;
    const auto pt = t ? get_parent->call<API::ManagedObject*>(vm, t) : nullptr;
    const auto pgo = pt ? t_get_go->call<API::ManagedObject*>(vm, pt) : nullptr;
    return pgo != nullptr && get_component->call<API::ManagedObject*>(vm, pgo, player_type) != nullptr;
}

uintptr_t HotReload::refresh_meshes(const std::wstring& path, uintptr_t new_res, const TypeHandler& handler) {
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();
    const auto& mm = mesh_methods();
    static const auto get_scene = tdb->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = tdb->find_method("via.Scene", "findComponents(System.Type)");
    const bool is_mesh = std::string_view{handler.resource_type} == "via.render.MeshResource";
    const auto getter = is_mesh ? mm.get_mesh : mm.get_material;
    const auto setter = is_mesh ? mm.set_mesh : mm.set_material;
    if (!get_scene || !find_components || !getter || !setter) {
        log_disabled("  Mesh methods not found, meshes already in use are not refreshed");
        return 0;
    }
    const bool can_keep = mm.materials_ok();
    auto scene = get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager"));
    if (scene == nullptr) return 0;
    auto arr = find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.render.Mesh"));
    if (arr == nullptr) return 0;
    const auto target = ResourceCache::normalize(path);
    static const auto mesh_slot = resource_slot_offset(mm.get_mesh);
    static const auto material_slot = resource_slot_offset(mm.get_material);
    const auto slot = is_mesh ? mesh_slot : material_slot;
    const auto count = *(uint32_t*)((uintptr_t)arr + ARRAY_COUNT);
    uint32_t refreshed = 0, kept_enable = 0, kept_parts = 0, kept_vars = 0, kept_tex = 0, unparsed = 0, effect_meshes = 0;
    std::vector<std::wstring> kept_names{};
    std::unordered_set<API::ManagedObject*> touched_gos{}; // Objects whose meshes had their mesh/material swapped
    // Read each resource's path and parse its raw data only once
    std::unordered_map<uintptr_t, bool> same_path{};
    std::unordered_map<uintptr_t, std::pair<bool, MdfInfo>> parsed{};
    const auto mdf_of = [&](uintptr_t res) -> const MdfInfo* {
        auto it = parsed.find(res);
        if (it == parsed.end()) {
            MdfInfo info{};
            const bool ok = parse_mdf(res, info);
            it = parsed.emplace(res, std::make_pair(ok, std::move(info))).first;
        }
        return it->second.first ? &it->second.second : nullptr;
    };
    auto res_api = api->sdk()->resource;
    for (uint32_t i = 0; i < count; ++i) {
        auto mesh = *(API::ManagedObject**)((uintptr_t)arr + ARRAY_DATA + 8ull * i);
        if (mesh == nullptr) continue;
        uintptr_t res = 0;
        if (slot != 0) {
            if (!safe_read_ptr((uintptr_t)mesh + slot, res)) continue;
        } else {
            // When the offset cannot be found, use invoke (getter/setter without call: calling getMesh through call caused an access violation in testing)
            const auto got = getter->invoke(mesh, std::vector<void*>{});
            const auto holder = got.exception_thrown ? nullptr : (API::ManagedObject*)got.ptr;
            if (holder == nullptr || !safe_read_ptr((uintptr_t)holder + OWNER_RESOURCE_OFFSET, res)) continue;
        }
        if (res == 0 || res == new_res) continue;
        auto it = same_path.find(res);
        if (it == same_path.end()) {
            ResourceEntry e{};
            it = same_path.emplace(res, ResourceCache::read_entry(res, e) && ResourceCache::normalize(e.path) == target).first;
        }
        if (!it->second) continue;
        if (new_res == 0) return res;
        if (is_effect_mesh(mesh)) {
            ++effect_meshes;
            continue;
        }

        const auto enable = read_flags(mm.enable_count, mm.get_enable, mesh, vm);
        const auto parts = read_flags(mm.parts_count, mm.get_parts, mesh, vm);
        // mdf2: old/new file content is used to tell which parameters the file changed
        const MdfInfo* old_mdf = nullptr;
        const MdfInfo* new_mdf = nullptr;
        if (can_keep && !is_mesh) {
            old_mdf = mdf_of(res);
            new_mdf = mdf_of(new_res);
            // If the old mdf2 never loaded successfully (file does not exist, e.g. MDF-XL placeholder materials) it has no raw data and meshes have no material state from it; this is not a parse failure
            if ((old_mdf == nullptr && is_ready(res)) || new_mdf == nullptr) ++unparsed;
        }
        const bool keep_materials = can_keep && (is_mesh || (old_mdf && new_mdf));
        // Runtime state before the swap (material name -> snapshot)
        std::unordered_map<std::wstring, MaterialSnapshot> snap{};
        if (keep_materials) {
            const auto mats = mm.material_num->call<uint32_t>(vm, mesh);
            for (uint32_t m = 0; m < mats && m < 256; ++m) {
                const auto mname = managed_string(mm.material_name->invoke(mesh, {u32_arg(m)}));
                if (mname.empty() || (old_mdf && !old_mdf->contains(mname))) continue;
                auto& s = snap[mname];
                const auto vn = mm.var_num->call<uint32_t>(vm, mesh, m);
                for (uint32_t v = 0; v < vn && v < 4096; ++v) {
                    const auto vname = managed_string(mm.var_name->invoke(mesh, {u32_arg(m), u32_arg(v)}));
                    const auto t = mm.var_type->call<uint32_t>(vm, mesh, m, v);
                    if (vname.empty() || (t != VAR_FLOAT && t != VAR_FLOAT4)) continue;
                    if (auto bits = read_var(mm, mesh, m, v, t); !bits.empty()) s.vars[vname] = std::move(bits);
                }
                const auto tn = mm.tex_num->call<uint32_t>(vm, mesh, m);
                for (uint32_t k = 0; k < tn && k < 1024; ++k) {
                    const auto slot = managed_string(mm.tex_name->invoke(mesh, {u32_arg(m), u32_arg(k)}));
                    auto tex = read_tex(mm, mesh, m, k);
                    if (slot.empty() || tex.second == 0) continue;
                    // After the swap the old material/mesh may release its textures: hold them first and release after writing back or giving up
                    res_api->add_ref((REFrameworkResourceHandle)tex.second);
                    s.textures[slot] = std::move(tex);
                }
            }
        }

        auto new_holder = (API::ManagedObject*)res_api->create_holder((REFrameworkResourceHandle)new_res, handler.holder_type);
        if (new_holder != nullptr) {
            setter->invoke(mesh, {(void*)new_holder});
            ++refreshed;
            static const auto get_go = tdb->find_method("via.Component", "get_GameObject");
            if (const auto go = get_go ? get_go->call<API::ManagedObject*>(vm, mesh) : nullptr) touched_gos.insert(go);
            kept_enable += restore_flags(mm.enable_count, mm.get_enable, mm.set_enable, mesh, vm, enable);
            kept_parts += restore_flags(mm.parts_count, mm.get_parts, mm.set_parts, mesh, vm, parts);
            // Write back the runtime state
            const auto mats = snap.empty() ? 0u : mm.material_num->call<uint32_t>(vm, mesh);
            for (uint32_t m = 0; m < mats && m < 256; ++m) {
                const auto mname = managed_string(mm.material_name->invoke(mesh, {u32_arg(m)}));
                const auto sit = snap.find(mname);
                if (sit == snap.end()) continue;
                const MdfMaterial* om = nullptr;
                const MdfMaterial* nm = nullptr;
                if (!is_mesh) {
                    const auto oit = old_mdf->find(mname);
                    const auto nit = new_mdf->find(mname);
                    if (oit == old_mdf->end() || nit == new_mdf->end()) continue;
                    om = &oit->second;
                    nm = &nit->second;
                }
                const auto& s = sit->second;
                const auto vn = mm.var_num->call<uint32_t>(vm, mesh, m);
                for (uint32_t v = 0; v < vn && v < 4096; ++v) {
                    const auto vname = managed_string(mm.var_name->invoke(mesh, {u32_arg(m), u32_arg(v)}));
                    const auto rv = s.vars.find(vname);
                    if (rv == s.vars.end()) continue;
                    const auto t = mm.var_type->call<uint32_t>(vm, mesh, m, v);
                    if (is_mesh) {
                        if (read_var(mm, mesh, m, v, t) == rv->second) continue; // Not reset
                    } else {
                        const auto ov = om->params.find(vname);
                        const auto nv = nm->params.find(vname);
                        if (ov == om->params.end() || nv == nm->params.end()) continue;
                        if (ov->second != nv->second) continue;                                          // The file changed it: take the new file value
                        if (rv->second.size() != ov->second.size() || rv->second == ov->second) continue; // Not changed at runtime
                    }
                    if (!write_var(mm, mesh, m, v, t, rv->second)) continue;
                    ++kept_vars;
                    if (kept_names.size() < 12) kept_names.push_back(mname + L"." + vname);
                }
                const auto tn = mm.tex_num->call<uint32_t>(vm, mesh, m);
                for (uint32_t k = 0; k < tn && k < 1024; ++k) {
                    const auto slot = managed_string(mm.tex_name->invoke(mesh, {u32_arg(m), u32_arg(k)}));
                    const auto rt = s.textures.find(slot);
                    if (rt == s.textures.end()) continue;
                    if (is_mesh) {
                        if (read_tex(mm, mesh, m, k).first == rt->second.first) continue; // Not reset
                    } else {
                        // The file did not change this slot, but at runtime it was set to a different texture (different path): write the runtime texture back
                        const auto ot = om->textures.find(slot);
                        const auto nt = nm->textures.find(slot);
                        if (ot == om->textures.end() || nt == nm->textures.end()) continue;
                        if (ot->second != nt->second || rt->second.first == ot->second) continue;
                    }
                    auto th = res_api->create_holder((REFrameworkResourceHandle)rt->second.second, "via.render.TextureResourceHolder");
                    if (th == nullptr) continue;
                    mm.set_tex->invoke(mesh, {u32_arg(m), u32_arg(k), (void*)th});
                    ++kept_tex;
                    if (kept_names.size() < 12) kept_names.push_back(mname + L"." + slot);
                }
            }
        }
        for (const auto& [_, s] : snap) {
            for (const auto& [__, t] : s.textures) release_resource(t.second);
        }
    }
    // The texture streaming controller on the same object (via.render.StreamingTextureController) holds a reference to every texture in the texture list it collected (+0x40 array),
    // and does not recollect right after a mesh swaps its mesh/material: observed that parts updated only after 30 seconds to 10 minutes, during which the swapped-out old textures cannot be reclaimed.
    // request() makes it recollect from the current meshes immediately (observed 11-08: the list switched to the new textures on the spot)
    {
        static const auto get_component = tdb->find_method("via.GameObject", "getComponent(System.Type)");
        static const auto request = tdb->find_method("via.render.StreamingTextureController", "request");
        const auto controller_type = api->typeof("via.render.StreamingTextureController");
        for (const auto go : touched_gos) {
            if (get_component == nullptr || request == nullptr || controller_type == nullptr) break;
            if (const auto c = get_component->call<API::ManagedObject*>(vm, go, controller_type)) request->invoke(c, std::vector<void*>{});
        }
    }
    if (refreshed > 0) {
        std::string extra{};
        if (kept_enable > 0) extra += ", runtime material switches kept: " + std::to_string(kept_enable);
        if (kept_parts > 0) extra += ", runtime part switches kept: " + std::to_string(kept_parts);
        if (kept_vars + kept_tex > 0) {
            std::wstring names{};
            for (const auto& n : kept_names) names += (names.empty() ? L"" : L", ") + n;
            extra += ", runtime-modified material parameters kept: " + std::to_string(kept_vars) + ", textures: " + std::to_string(kept_tex) + " (" + narrow(names) +
                     (kept_vars + kept_tex > kept_names.size() ? " etc." : "") + ")";
        }
        if (unparsed > 0) extra += "; " + std::to_string(unparsed) + " meshes: old/new mdf2 could not be parsed, runtime material parameters not kept";
        log("  Meshes using it in the scene: %u switched to the new %s%s", refreshed, is_mesh ? "mesh" : "material", extra.c_str());
    }
    if (effect_meshes > 0) log("  Effect-generated meshes: %u not replaced; the effects use the new file when they regenerate", effect_meshes);
    return 0;
}

// ---- Common equipment resources: scene components using them switch to the new resource ----
// chain2: via.motion.Chain2.set_ChainAsset (the native implementation swaps +0x208 and sets +0x2A8 |= 1; the engine rebuilds the chain from the new resource on its next update)
// clsp: CollisionShapePresetInfo.set_Resource of via.character.CollisionShapePreset (only stores the pointer), then reset() to apply it
// gpuc: via.dynamics.GpuCloth.set_Resource (the native implementation tears down the old cloth before swapping +0xB0)
// rtex: component properties of type RenderTargetTextureResourceHolder (see rtt_properties)
// motlist: MotionBank.set_MotionList on the active motion bank of via.motion.Motion (a runtime via.motion.MotionBank expanded from the motbank);
//   the motbank resource holds parsed motlist pointers (+0x70 array, +0x78 count; Common.motbank has 42 entries on 1.42.0.3), and motion banks created from the motbank later
//   would get the old motlist, so old pointers of the same path in the cached motbank and the ones held by components are atomically replaced with the new resource (old resources released later)
// Matched by resource path (a component may still use an older version); the new resource itself is skipped
namespace {
uintptr_t holder_resource(const reframework::InvokeRet& r) {
    uintptr_t res = 0;
    if (r.exception_thrown || r.ptr == nullptr || !safe_read_ptr((uintptr_t)r.ptr + OWNER_RESOURCE_OFFSET, res)) return 0;
    return res;
}

// Properties holding some resource type: on the type, get_X() returns that resource's holder (or a base class, e.g. SkeletonResourceHolder for FbxSkeletonResourceHolder)
// and there is a set_X(same type); collected from the type database on first use. When the property's type is a component, scene components are queried directly; when it is not (JointConstraintsLayer,
// DynamicMotionBank, etc.), it is enumerated through a component method getX(integer) returning it together with getXCount() (JointConstraints.getLayer/getLayerCount,
// Motion.getDynamicMotionBank/getDynamicMotionBankCount).
// rtex: render targets are drawn into by about 25 component types such as PrimitiveVfxSubscene and read by mdf2; swapping only the mdf2 makes the content disappear (observed 2026-11-04 with water trails).
// sfur (ShellFurMesh), jcns (JointConstraintsLayer), fbxskel (CustomSkeleton etc.), motbank (Motion, DynamicMotionBank etc.):
// their native setters all clear the "built" state when swapping resources (ShellFur sets a rebuild flag, CustomSkeleton clears its applied flag, JointConstraintsLayer re-initializes,
// motion banks clear their expanded motion lists), and the engine rebuilds from the new resource next frame
struct HolderProperty {
    std::string owner;
    API::Method* get;
    API::Method* set;
};

struct OwnerSource {
    std::string component;
    API::Method* count;
    API::Method* item;
};

// Resource types swapped through the property index (resource type -> holder type)
const std::pair<std::string_view, const char*> k_property_types[] = {
    {"via.render.RenderTargetTextureResource", "via.render.RenderTargetTextureResourceHolder"},
    {"via.render.ShellFurResource", "via.render.ShellFurResourceHolder"},
    {"via.motion.JointConstraintsResource", "via.motion.JointConstraintsResourceHolder"},
    {"via.motion.FbxSkeletonResource", "via.motion.FbxSkeletonResourceHolder"},
    {"via.motion.MotionBankResource", "via.motion.MotionBankResourceHolder"},
};

bool holder_property_type(std::string_view type) {
    for (const auto& [t, _] : k_property_types) {
        if (t == type) return true;
    }
    return false;
}

struct PropertyIndex {
    API::TypeDefinition* component{};
    std::unordered_map<std::string, std::vector<HolderProperty>> props{};  // holder type -> properties
    std::unordered_map<std::string, std::vector<OwnerSource>> sources{};   // Non-component property owner type -> enumeration methods
};

// Walking the roughly 120k types of the type database takes over 100 ms, so it is built on a background thread when the core starts (reads the type database only)
PropertyIndex build_property_index() {
    PropertyIndex idx{};
    const auto tdb = API::get()->tdb();
    idx.component = tdb->find_type("via.Component");
    const auto base = tdb->find_type("via.ResourceHolder");
    // Return type -> holder types accepting it (the holder itself and its base classes, up to but excluding via.ResourceHolder)
    std::unordered_map<API::TypeDefinition*, std::vector<std::string>> accepted{};
    for (const auto& [_, holder] : k_property_types) {
        for (auto t = tdb->find_type(holder); t != nullptr && t != base; t = t->get_parent_type()) accepted[t].push_back(holder);
    }
    std::unordered_set<API::TypeDefinition*> owners{};
    const auto n = tdb->get_num_types();
    for (uint32_t i = 0; i < n; ++i) {
        const auto t = tdb->get_type(i);
        if (t == nullptr) continue;
        const auto methods = t->get_methods();
        for (const auto g : methods) {
            if (g == nullptr || g->get_num_params() != 0) continue;
            const auto it = accepted.find(g->get_return_type());
            if (it == accepted.end()) continue;
            const std::string_view name{g->get_name()};
            if (!name.starts_with("get_")) continue;
            const auto setter = "set_" + std::string{name.substr(4)};
            for (const auto s : methods) {
                if (s == nullptr || s->get_num_params() != 1 || setter != s->get_name()) continue;
                const auto params = s->get_params();
                if (params.size() != 1 || (API::TypeDefinition*)params[0].t != g->get_return_type()) continue;
                for (const auto& holder : it->second) idx.props[holder].push_back({t->get_full_name(), g, s});
                if (idx.component == nullptr || !t->is_derived_from(idx.component)) owners.insert(t);
                break;
            }
        }
    }
    const auto i32 = tdb->find_type("System.Int32");
    const auto u32 = tdb->find_type("System.UInt32");
    for (uint32_t i = 0; i < n && !owners.empty() && idx.component != nullptr; ++i) {
        const auto t = tdb->get_type(i);
        if (t == nullptr || !t->is_derived_from(idx.component)) continue;
        const auto methods = t->get_methods();
        for (const auto m : methods) {
            if (m == nullptr || m->get_num_params() != 1 || !owners.contains(m->get_return_type())) continue;
            const auto params = m->get_params();
            const auto pt = params.size() == 1 ? (API::TypeDefinition*)params[0].t : nullptr;
            if (pt != i32 && pt != u32) continue;
            const auto count_name = std::string{m->get_name()} + "Count";
            for (const auto c : methods) {
                if (c == nullptr || c->get_num_params() != 0 || count_name != c->get_name()) continue;
                idx.sources[m->get_return_type()->get_full_name()].push_back({t->get_full_name(), c, m});
                break;
            }
        }
    }
    return idx;
}

std::shared_future<PropertyIndex>& property_index_future() {
    static std::shared_future<PropertyIndex> f = std::async(std::launch::async, build_property_index).share();
    return f;
}

void warm_property_index() {
    property_index_future();
}

const PropertyIndex& property_index() {
    return property_index_future().get();
}
}

uint32_t HotReload::refresh_components(const Job& j) {
    const std::string_view type{j.handler->resource_type};
    const bool chain = type == "via.motion.Chain2Resource";
    const bool clsp = type == "via.character.CollisionShapePresetResource";
    const bool cloth = type == "via.dynamics.GpuCloth2Resource" || type == "via.dynamics.GpuClothResource";
    const bool motlist = type == "via.motion.MotionListResource";
    const bool by_property = holder_property_type(type);
    if (!chain && !clsp && !cloth && !motlist && !by_property) return 0;
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();
    static const auto get_scene = tdb->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = tdb->find_method("via.Scene", "findComponents(System.Type)");
    if (!get_scene || !find_components) return 0;
    auto scene = get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager"));
    if (scene == nullptr) return 0;
    const auto target = ResourceCache::normalize(j.path);
    std::unordered_map<uintptr_t, bool> same{};
    const auto matches = [&](uintptr_t res) {
        if (res == 0 || res == j.new_res) return false;
        auto it = same.find(res);
        if (it == same.end()) {
            ResourceEntry e{};
            it = same.emplace(res, ResourceCache::read_entry(res, e) && ResourceCache::normalize(e.path) == target).first;
        }
        return it->second;
    };
    auto res_api = api->sdk()->resource;
    const auto new_holder = [&]() { return (void*)res_api->create_holder((REFrameworkResourceHandle)j.new_res, j.handler->holder_type); };
    const auto components = [&](const char* t) -> std::vector<API::ManagedObject*> {
        std::vector<API::ManagedObject*> out{};
        auto arr = find_components->call<API::ManagedObject*>(vm, scene, api->typeof(t));
        if (arr == nullptr) return out;
        const auto count = *(uint32_t*)((uintptr_t)arr + ARRAY_COUNT);
        for (uint32_t i = 0; i < count; ++i) {
            if (auto c = *(API::ManagedObject**)((uintptr_t)arr + ARRAY_DATA + 8ull * i)) out.push_back(c);
        }
        return out;
    };
    const std::vector<void*> no_args{};
    uint32_t refreshed = 0;
    const char* what = "";
    if (chain) {
        what = "chains (Chain2)";
        static const auto get = tdb->find_method("via.motion.Chain2", "get_ChainAsset");
        static const auto set = tdb->find_method("via.motion.Chain2", "set_ChainAsset(via.motion.Chain2ResourceHolder)");
        if (!get || !set) return 0;
        for (auto c : components("via.motion.Chain2")) {
            if (!matches(holder_resource(get->invoke(c, no_args)))) continue;
            if (auto h = new_holder(); h && !set->invoke(c, {h}).exception_thrown) ++refreshed;
        }
    } else if (clsp) {
        what = "collision shape presets (CollisionShapePreset)";
        static const auto count_m = tdb->find_method("via.character.CollisionShapePreset", "getCollisionShapePresetInfosCount");
        static const auto info_m = tdb->find_method("via.character.CollisionShapePreset", "getCollisionShapePresetInfos(System.UInt32)");
        static const auto reset = tdb->find_method("via.character.CollisionShapePreset", "reset");
        static const auto get = tdb->find_method("via.character.CollisionShapePresetInfo", "get_Resource");
        static const auto set = tdb->find_method("via.character.CollisionShapePresetInfo", "set_Resource(via.character.CollisionShapePresetResourceHolder)");
        if (!count_m || !info_m || !reset || !get || !set) return 0;
        for (auto c : components("via.character.CollisionShapePreset")) {
            const auto n = count_m->invoke(c, no_args).dword;
            bool touched = false;
            for (uint32_t k = 0; k < n && k < 256; ++k) {
                const auto r = info_m->invoke(c, {(void*)(uintptr_t)k});
                auto info = r.exception_thrown ? nullptr : (API::ManagedObject*)r.ptr;
                if (info == nullptr || !matches(holder_resource(get->invoke(info, no_args)))) continue;
                if (auto h = new_holder(); h && !set->invoke(info, {h}).exception_thrown) touched = true;
            }
            if (!touched) continue;
            reset->invoke(c, no_args);
            ++refreshed;
        }
    } else if (cloth) {
        what = "cloth (GpuCloth)";
        static const auto get = tdb->find_method("via.dynamics.GpuCloth", "get_Resource");
        static const auto set = tdb->find_method("via.dynamics.GpuCloth", "set_Resource(via.dynamics.GpuClothResourceHolder)");
        if (!get || !set) return 0;
        for (auto c : components("via.dynamics.GpuCloth")) {
            if (!matches(holder_resource(get->invoke(c, no_args)))) continue;
            if (auto h = new_holder(); h && !set->invoke(c, {h}).exception_thrown) ++refreshed;
        }
    } else if (by_property) {
        // Counted per property owner type; the log lists type names and counts
        std::map<std::string, uint32_t> by_owner{};
        const auto& idx = property_index();
        const auto props = idx.props.find(j.handler->holder_type);
        static const std::vector<HolderProperty> none{};
        static const std::vector<OwnerSource> no_sources{};
        for (const auto& p : props == idx.props.end() ? none : props->second) {
            std::vector<API::ManagedObject*> owners{};
            const auto owner_t = tdb->find_type(p.owner.c_str());
            if (owner_t != nullptr && idx.component != nullptr && owner_t->is_derived_from(idx.component)) {
                owners = components(p.owner.c_str());
            } else {
                const auto s = idx.sources.find(p.owner);
                for (const auto& src : s == idx.sources.end() ? no_sources : s->second) {
                    for (auto c : components(src.component.c_str())) {
                        const auto n = (int32_t)src.count->invoke(c, no_args).dword;
                        for (int32_t k = 0; k < n && k < 1024; ++k) {
                            const auto r = src.item->invoke(c, {(void*)(intptr_t)k});
                            if (!r.exception_thrown && r.ptr != nullptr) owners.push_back((API::ManagedObject*)r.ptr);
                        }
                    }
                }
            }
            for (auto o : owners) {
                if (!matches(holder_resource(p.get->invoke(o, no_args)))) continue;
                if (auto h = new_holder(); h && !p.set->invoke(o, {h}).exception_thrown) {
                    ++refreshed;
                    ++by_owner[p.owner];
                }
            }
        }
        static std::string names{};
        names.clear();
        for (const auto& [owner, n] : by_owner) names += (names.empty() ? "" : ", ") + owner + " " + std::to_string(n);
        what = names.c_str();
    } else {
        what = "motions (Motion library)";
        static const auto count_m = tdb->find_method("via.motion.Motion", "getActiveMotionBankCount");
        static const auto bank_m = tdb->find_method("via.motion.Motion", "getActiveMotionBank(System.UInt32)");
        static const auto get = tdb->find_method("via.motion.MotionBank", "get_MotionList");
        static const auto set = tdb->find_method("via.motion.MotionBank", "set_MotionList(via.motion.MotionListBaseResourceHolder)");
        if (!count_m || !bank_m || !get || !set) return 0;
        for (auto c : components("via.motion.Motion")) {
            const auto n = count_m->invoke(c, no_args).dword;
            bool touched = false;
            for (uint32_t k = 0; k < n && k < 1024; ++k) {
                const auto r = bank_m->invoke(c, {(void*)(uintptr_t)k});
                auto bank = r.exception_thrown ? nullptr : (API::ManagedObject*)r.ptr;
                if (bank == nullptr || !matches(holder_resource(get->invoke(bank, no_args)))) continue;
                if (auto h = new_holder(); h && !set->invoke(bank, {h}).exception_thrown) touched = true;
            }
            refreshed += touched ? 1 : 0;
        }
        // motlist pointers in the motbank
        constexpr uintptr_t MOTBANK_LISTS = 0x70;
        constexpr uintptr_t MOTBANK_LIST_COUNT = 0x78;
        static const auto main_bank = tdb->find_method("via.motion.Motion", "get_MotionBankAsset");
        static const auto dyn_count = tdb->find_method("via.motion.Motion", "getDynamicMotionBankCount");
        static const auto dyn_bank = tdb->find_method("via.motion.Motion", "getDynamicMotionBank(System.Int32)");
        static const auto dyn_get = tdb->find_method("via.motion.DynamicMotionBank", "get_MotionBank");
        std::unordered_set<uintptr_t> motbanks{};
        for (const auto& e : ResourceCache::list(L".motbank", 1000000)) motbanks.insert(e.resource);
        for (auto c : components("via.motion.Motion")) {
            if (main_bank) motbanks.insert(holder_resource(main_bank->invoke(c, no_args)));
            const auto n = dyn_count ? (int32_t)dyn_count->invoke(c, no_args).dword : 0;
            for (int32_t k = 0; k < n && k < 512 && dyn_bank && dyn_get; ++k) {
                const auto r = dyn_bank->invoke(c, {(void*)(intptr_t)k});
                if (!r.exception_thrown && r.ptr) motbanks.insert(holder_resource(dyn_get->invoke((API::ManagedObject*)r.ptr, no_args)));
            }
        }
        motbanks.erase(0);
        uint32_t banks = 0;
        for (const auto mb : motbanks) {
            uintptr_t lists = 0;
            uint32_t n = 0;
            if (!safe_read_ptr(mb + MOTBANK_LISTS, lists) || lists == 0 || !read_u32(mb + MOTBANK_LIST_COUNT, n) || n == 0 || n > 4096) continue;
            bool hit = false;
            for (uint32_t k = 0; k < n; ++k) {
                uintptr_t r = 0;
                if (!safe_read_ptr(lists + 8ull * k, r)) break;
                if (!matches(r)) continue; // motlist resources of the same path (the new resource itself excluded)
                res_api->add_ref((REFrameworkResourceHandle)j.new_res);
                if ((uintptr_t)InterlockedCompareExchange64((volatile LONG64*)(lists + 8ull * k), (LONG64)j.new_res, (LONG64)r) == r) {
                    release_later(r);
                    hit = true;
                } else {
                    release_resource(j.new_res);
                }
            }
            banks += hit ? 1 : 0;
        }
        if (banks > 0) log("  Motion bank files (motbank) referencing it: %u switched to the new resource", banks);
    }
    if (refreshed > 0 && by_property) {
        log("  Objects using it in the scene: %u switched to the new resource (%s)", refreshed, what);
    } else if (refreshed > 0) {
        log("  %s using it in the scene: %u switched to the new resource", what, refreshed);
    }
    return refreshed;
}

// ---- In-place motlist update ----
// Observed 2026-11-02 (plc_BaseMove.motlist, Spine_1 translation): a playing action reads keyframes every frame from the buffer of the motlist resource it started with,
// and track bindings are built from the mot layout at that time; only repointing the action object to the new mot reads wrong data through the old bindings (abnormal values). When the new file has the same structure (only keyframe values changed)
// the data is written into the old buffer in place, taking effect immediately for playing actions and for mirror motlists referencing it
namespace {
constexpr uintptr_t MOTLIST_BUFFER = 0x60;   // motlist resource: file buffer (the engine rewrites in-file offsets to absolute pointers when loading)
constexpr uintptr_t MOTLIST_BASE_RES = 0x98; // Base motlist resource referenced by a mirror motlist (e.g. plc_BaseMove_Mir)
constexpr uintptr_t RESOURCE_REFCOUNT = 0x28;

// The u32 at 0x10 before the buffer is the allocation block size (in 16-byte units, including the 0x20-byte block header; a 10034384-byte file measured 0x991CF). Returns 0 if unreadable
size_t heap_block_capacity(uintptr_t buf) {
    uint32_t units = 0;
    if (buf < 0x10 || !read_u32(buf - 0x10, units) || units < 3 || units > (1u << 28)) return 0;
    return (size_t)units * 16 - 0x20;
}

// 8-byte positions in the new buffer that differ from the file: those landing inside the new buffer are pointers rewritten by the engine (the same position in the old buffer must be a pointer with the same relative position, otherwise the structure differs),
// the rest are fields the engine writes at runtime (keep the old values). Positions equal to the file are data: if the old buffer has a pointer there and the file's offset matches its position relative to the old buffer,
// it is the same pointer not yet rewritten, otherwise the structure differs; if it is not a pointer, write the difference into the old buffer
// prev: the same file as read on the previous reload (empty if none). Positions equal to the previous version are never written: the engine writes runtime caches into the buffer after an action is used
// (observed 2026-11-05 with plc_Comms_285_Loop: saving unchanged treated 40 such positions as differences and overwrote them); only positions the file really changed are written.
// Without a previous version, positions whose old value is a readable pointer are not written (only plain data is written)
void inplace_scan(const uint8_t* file, size_t size, const uint8_t* prev, size_t prev_size, uintptr_t ob, uintptr_t nb, size_t cap, bool apply,
                  uint32_t& mismatch, uint32_t& diffs) {
    const auto* o = (const uint8_t*)ob;
    const auto* n = (const uint8_t*)nb;
    const auto unchanged = [&](size_t i, size_t len) { return prev != nullptr && i + len <= prev_size && memcmp(prev + i, file + i, len) == 0; };
    size_t i = 0;
    for (; i + 8 <= size; i += 8) {
        if (unchanged(i, 8)) continue;
        uint64_t ov = 0, nv = 0, fv = 0;
        memcpy(&ov, o + i, 8);
        memcpy(&nv, n + i, 8);
        memcpy(&fv, file + i, 8);
        if (nv != fv) {
            if (nv >= nb && nv < nb + cap && !(ov >= ob && ov < ob + cap && ov - ob == nv - nb)) ++mismatch;
            continue;
        }
        if (ov == nv) continue;
        if (ov >= ob && ov < ob + cap) {
            // The old buffer already has a pointer while the new buffer still has the file offset here: the engine rewrites some pointers only on first use (observed with mot); a matching offset means the same pointer
            if (ov - ob != fv) ++mismatch;
            continue;
        }
        if (prev == nullptr && ov >= 0x10000 && ov < 0x7FFFFFFF0000ull && (ov & 7) == 0 && vq_readable((uintptr_t)ov, 8)) continue;
        ++diffs;
        if (apply) InterlockedExchange64((volatile LONG64*)(ob + i), (LONG64)nv);
    }
    for (; i < size; ++i) {
        if (unchanged(i, 1) || n[i] != file[i] || o[i] == n[i]) continue;
        ++diffs;
        if (apply) ((volatile uint8_t*)ob)[i] = n[i];
    }
}

DWORD inplace_seh(const uint8_t* file, size_t size, const uint8_t* prev, size_t prev_size, uintptr_t ob, uintptr_t nb, size_t cap, bool apply,
                  uint32_t& mismatch, uint32_t& diffs) {
    __try {
        inplace_scan(file, size, prev, prev_size, ob, nb, cap, apply, mismatch, diffs);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

}

// ---- External mot ----
// 375 motlists (NPCs, companions, player plc_Comms, some monster _05 motion banks) reference external .mot files by path, and action objects (via.motion.DynamicMotion etc.)
// hold the mot resources. When a mot is saved: if the file structure is the same (only keyframe values changed) the new data is written in place into the old mot in use, taking effect immediately for playing actions
// (the engine does not refetch looped actions with the same id); if the structure changed, loaded loose motlists in natives referencing it are queued for reload (like the efx cascade;
// motlists in paks are not handled), and the motlist handling then swaps the motlist pointers in the motbank
// and the Motion motion banks, so actions started afterwards use the new file. Returns false if some old version could not be updated in place
bool HotReload::update_mot_versions(const Job& j) {
    auto res_api = API::get()->sdk()->resource;
    auto& olds = m_motlist_old[ResourceCache::normalize(j.path)];
    std::erase_if(olds, [&](uintptr_t r) {
        uint32_t refs = 0;
        if (r != j.new_res && read_u32(r + RESOURCE_REFCOUNT, refs) && (int32_t)refs > 1) return false;
        release_resource(r);
        return true;
    });
    for (const auto r : {j.old_res, j.extra_old}) {
        if (r == 0 || r == j.new_res || std::find(olds.begin(), olds.end(), r) != olds.end()) continue;
        res_api->add_ref((REFrameworkResourceHandle)r);
        olds.push_back(r);
    }
    // Keep the file content read this time as the previous version for the next comparison (see inplace_scan)
    std::vector<uint8_t> data{};
    if (const auto file = natives_file(j.path); !file.empty()) {
        std::ifstream in{file, std::ios::binary};
        data.assign(std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{});
    }
    std::vector<uint8_t> prev{};
    {
        auto& snapshot = m_file_snapshot[ResourceCache::normalize(j.path)];
        prev = std::move(snapshot);
        snapshot = data;
    }
    const uint8_t* prev_ptr = prev.empty() ? nullptr : prev.data();
    const size_t prev_size = prev.size();
    if (olds.empty()) return true;
    uintptr_t nb = 0;
    if (data.empty() || !safe_read_ptr(j.new_res + MOTLIST_BUFFER, nb) || nb == 0) return false;
    const auto size = data.size();
    // mot buffers are often large page-allocated blocks without a block header at 0x10 before them: when the block capacity cannot be read, the pointer range is judged by the file size
    const auto span = [&](uintptr_t b) {
        const auto c = heap_block_capacity(b);
        return c >= size ? c : (size + 15) & ~(size_t)15;
    };
    const auto cap = span(nb);
    bool all = true, first_save = false;
    uint32_t updated = 0, values = 0;
    for (const auto r : olds) {
        uintptr_t ob = 0;
        if (!safe_read_ptr(r + MOTLIST_BUFFER, ob) || ob == 0 || ob == nb) continue;
        uint32_t mismatch = 0, diffs = 0;
        if (span(ob) != cap || !vq_readable(ob, size) || !vq_readable(nb, size) ||
            inplace_seh(data.data(), size, prev_ptr, prev_size, ob, nb, cap, false, mismatch, diffs) != 0 || mismatch != 0) {
            all = false;
            continue;
        }
        if (diffs == 0) continue;
        // No previous file version: file changes cannot be told apart from runtime data the engine writes after an action is used, so no in-place write
        if (prev_ptr == nullptr) {
            first_save = true;
            all = false;
            continue;
        }
        mismatch = diffs = 0;
        if (const auto code = inplace_seh(data.data(), size, prev_ptr, prev_size, ob, nb, cap, true, mismatch, diffs); code != 0) {
            log("  Error while updating old data in use in place (exception 0x%08lX)", code);
            all = false;
            continue;
        }
        ++updated;
        values += diffs;
    }
    if (updated > 0) log("  Old data in use: %u copies updated in place (%u places); motions currently playing take effect immediately", updated, values);
    if (first_save) log("  First reload of this file this session: motion data in use stays as is; later saves take effect immediately");
    return all;
}

void HotReload::update_motlist_versions(const Job& j) {
    auto res_api = API::get()->sdk()->resource;
    auto& olds = m_motlist_old[ResourceCache::normalize(j.path)];
    // Old versions only the plugin still holds: no action uses them anymore, release
    std::erase_if(olds, [&](uintptr_t r) {
        uint32_t refs = 0;
        if (r != j.new_res && read_u32(r + RESOURCE_REFCOUNT, refs) && (int32_t)refs > 1) return false;
        release_resource(r);
        return true;
    });
    // Also include base resources of the same path currently referenced by mirror motlists (e.g. versions loaded before a core hot swap that are not in the records)
    uintptr_t vtable = 0;
    safe_read_ptr(j.new_res, vtable);
    const auto key = ResourceCache::normalize(j.path);
    const auto motlists = ResourceCache::list(L".motlist", 1000000);
    std::vector<uintptr_t> found{j.old_res, j.extra_old};
    for (const auto& e : motlists) {
        uintptr_t vt = 0, base = 0;
        ResourceEntry be{};
        if (!safe_read_ptr(e.resource, vt) || vt != vtable || !safe_read_ptr(e.resource + MOTLIST_BASE_RES, base) || base == 0) continue;
        if (ResourceCache::read_entry(base, be) && ResourceCache::normalize(be.path) == key) found.push_back(base);
    }
    for (const auto r : found) {
        if (r == 0 || r == j.new_res || std::find(olds.begin(), olds.end(), r) != olds.end()) continue;
        res_api->add_ref((REFrameworkResourceHandle)r);
        olds.push_back(r);
    }
    // Keep the file content read this time as the previous version for the next comparison (see inplace_scan)
    std::vector<uint8_t> data{};
    if (const auto file = natives_file(j.path); !file.empty()) {
        std::ifstream in{file, std::ios::binary};
        data.assign(std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{});
    }
    std::vector<uint8_t> prev{};
    {
        auto& snapshot = m_file_snapshot[ResourceCache::normalize(j.path)];
        prev = std::move(snapshot);
        snapshot = data;
    }
    const uint8_t* prev_ptr = prev.empty() ? nullptr : prev.data();
    const size_t prev_size = prev.size();
    if (olds.empty()) return;
    uintptr_t nb = 0;
    if (data.empty() || !safe_read_ptr(j.new_res + MOTLIST_BUFFER, nb) || nb == 0) return;
    const auto cap = heap_block_capacity(nb);
    const auto size = data.size();
    uint32_t updated = 0, values = 0;
    std::unordered_set<uintptr_t> changed{};
    for (const auto r : olds) {
        uintptr_t ob = 0;
        if (!safe_read_ptr(r + MOTLIST_BUFFER, ob) || ob == 0 || ob == nb) continue;
        if (cap == 0 || heap_block_capacity(ob) != cap || size > cap || !vq_readable(ob, size) || !vq_readable(nb, size)) {
            changed.insert(r);
            continue;
        }
        uint32_t mismatch = 0, diffs = 0;
        if (inplace_seh(data.data(), size, prev_ptr, prev_size, ob, nb, cap, false, mismatch, diffs) != 0 || mismatch != 0) {
            changed.insert(r);
            continue;
        }
        if (diffs == 0) continue;
        mismatch = diffs = 0;
        if (const auto code = inplace_seh(data.data(), size, prev_ptr, prev_size, ob, nb, cap, true, mismatch, diffs); code != 0) {
            log("  Error while updating old data in use in place (exception 0x%08lX)", code);
            continue;
        }
        ++updated;
        values += diffs;
    }
    if (updated > 0) log("  Old data in use: %u copies updated in place (%u places); motions currently playing take effect immediately", updated, values);
    if (changed.empty()) return;
    log("  File structure changed (tracks, key counts, etc.); motions currently playing use the new file after they restart");
    // Mirror motlists referencing the old version: their action objects are copied from the base motlist and still point to the old data, so reload them too (they pick up the new base motlist by path)
    std::vector<std::wstring> paths{};
    for (const auto& e : motlists) {
        uintptr_t vt = 0, base = 0;
        if (e.resource == j.new_res || !safe_read_ptr(e.resource, vt) || vt != vtable) continue;
        if (!safe_read_ptr(e.resource + MOTLIST_BASE_RES, base) || !changed.contains(base)) continue;
        if (std::find(paths.begin(), paths.end(), e.path) == paths.end()) paths.push_back(e.path);
    }
    for (const auto& p : paths) enqueue(p, j.handler, L"dependency " + j.path);
    if (!paths.empty()) log("  Referencing motlists: %zu, reloaded as well", paths.size());
}

// Prefabs loaded before the reload keep the old resource in their dependency array (PrefabResource +0x68 {pointer, count/capacity}, see prefab_live.cpp) and spawn objects
// with it later. Example (observed 2026-11-15): a mod body was equipped while one texture referenced by its mdf2 was missing; the pfb took the mdf2 whose texture never finishes loading.
// After the texture was added the mdf2 was reloaded into the cache, but the body spawned from the pfb still used the old mdf2 and stayed invisible, even after re-equipping.
// Ready pfb resources in the cache whose dependency array contains the old resource are queued for reload: the new pfb takes its dependencies from the cache, and its content
// (dependency array included) is swapped into the old pfb object in place (finish_in_place), so later spawns use the new resource.
// .user: the pfb keeps the root objects of the .user files it references in a second array (+0x80 {pointer, count/capacity}; elements are via.UserData objects, checked 2026-11-15
// on 572 loaded pfbs). Only a cache-only .user update gets here (when the file changes are written into the data in use the old root object itself is updated and nothing is cascaded)
// One walk of the cache per batch (all cache-only jobs finished in the same frame are passed together); the walk compares vtables only (no path reads):
// walking with a path filter cost about 13 ms per call (measured 2026-11-15), which added up to a long frame when a whole mod set was saved
void HotReload::cascade_prefabs(const std::vector<const Job*>& jobs) {
    constexpr uintptr_t PREFAB_DEPS = 0x68, PREFAB_DEPS_COUNT = 0x70, PREFAB_USERDATA = 0x80, PREFAB_USERDATA_COUNT = 0x88;
    constexpr uintptr_t USERDATA_ROOT = 0x88;
    static const auto pfb = handler_for_ext(L"pfb");
    if (pfb == nullptr) return;
    // Old resource (or old .user root object) -> path of the job that replaced it
    std::unordered_map<uintptr_t, const std::wstring*> olds{}, old_roots{};
    std::unordered_set<uintptr_t> skip{};
    for (const auto j : jobs) {
        if (j == nullptr || j->handler == pfb) continue;
        const bool user = std::string_view{j->handler->resource_type} == "via.UserDataResource";
        for (const auto r : {j->old_res, j->extra_old}) {
            if (r == 0) continue;
            olds.emplace(r, &j->path);
            skip.insert(r);
            uintptr_t root = 0;
            if (user && safe_read_ptr(r + USERDATA_ROOT, root) && root != 0) old_roots.emplace(root, &j->path);
        }
    }
    if (olds.empty()) return;
    // PrefabResource vtable: taken once from the first .pfb entry in the cache (that lookup reads paths, but stops at the first match)
    static uintptr_t pfb_vtable = 0;
    if (pfb_vtable == 0) {
        const auto first = ResourceCache::list(L".pfb", 1);
        if (first.empty() || !lower(first.front().path).ends_with(L".pfb") || !safe_read_ptr(first.front().resource, pfb_vtable)) return;
    }
    // The element of the array {pointer at +arr_off, count at +count_off} of pfb res found in set (nullptr if none)
    const auto array_hit = [](uintptr_t res, uintptr_t arr_off, uintptr_t count_off, const std::unordered_map<uintptr_t, const std::wstring*>& set) -> const std::wstring* {
        uintptr_t arr = 0;
        uint32_t count = 0;
        if (set.empty() || !safe_read_ptr(res + arr_off, arr) || arr == 0 || !read_u32(res + count_off, count) || count == 0 || count > 4096) return nullptr;
        for (uint32_t k = 0; k < count; ++k) {
            uintptr_t v = 0;
            if (!safe_read_ptr(arr + 8ull * k, v)) return nullptr;
            if (const auto it = set.find(v); it != set.end()) return it->second;
        }
        return nullptr;
    };
    std::vector<std::pair<std::wstring, std::wstring>> hits{}; // {pfb path, path of the replaced resource}
    for (const auto& e : ResourceCache::list(L"", SIZE_MAX, {pfb_vtable})) {
        if (!e.ready || skip.contains(e.resource)) continue;
        auto by = array_hit(e.resource, PREFAB_DEPS, PREFAB_DEPS_COUNT, olds);
        if (by == nullptr) by = array_hit(e.resource, PREFAB_USERDATA, PREFAB_USERDATA_COUNT, old_roots);
        if (by != nullptr) hits.emplace_back(e.path, *by);
    }
    if (hits.empty()) return;
    log("  Loaded prefabs still using replaced resources: %zu, reloaded as well (objects spawned from them later use the new files)", hits.size());
    for (const auto& [path, by] : hits) enqueue(path, pfb, L"dependency " + by);
}

// Dependency handling after texture/rtex/mmtr cache updates: mdf2 takes and holds textures/mmtr when it loads, so meshes spawned later through the cached mdf2 still use the old texture.
// The mdf2 referencing it is queued for reload (the old mdf2 stays in the cache while loading; once loaded it is swapped in and scene meshes refreshed).
// The mdf2 is not removed from the cache: a later game request would get the mdf2 still loading and set it on a mesh immediately, whose materials then never build and stay black (observed 2026-11-03).
// (Textures used to remove the mdf2 and swap textures slot by slot because REFramework DisableTextureCache made every mdf2 reload create hundreds of textures; the loader now forces that option off)
void HotReload::cascade_cached(const Job& j) {
    cascade_effects(j);
    // rtex: effects draw into the render target and mdf2 (such as water surfaces) read it; both sides must switch to the same new resource
    static const auto rtex = handler_for_ext(L"rtex");
    const std::string_view type{j.handler->resource_type};
    if (type != "via.render.TextureResource" && type != "via.render.MasterMaterialResource" && j.handler != rtex) return;
    const auto mdf2 = handler_for_ext(L"mdf2");
    if (mdf2 == nullptr) return;
    const auto target = ResourceCache::normalize(j.path);
    const auto& api = API::get();
    const auto vm = api->get_vm_context();
    const auto& mm = mesh_methods();
    size_t checked = 0, invalid = 0;
    // mdf2 in the cache, plus old mdf2 versions still used by scene meshes that are no longer in the cache
    // Filter by the mdf2 resource vtable (filtering the whole table by path takes about 10 ms, by vtable about 1 ms): take the vtable of the first mdf2 encountered (all mdf2 share one class;
    // observed 2026-11-08: 1266 with 1 vtable); if filtering by vtable lists nothing, fall back to a full walk by path
    static std::vector<uintptr_t> mdf2_vtables{};
    if (mdf2_vtables.empty()) {
        for (const auto& e : ResourceCache::list(L".mdf2", 1)) {
            uintptr_t vt = 0;
            if (safe_read_ptr(e.resource, vt) && vt != 0) mdf2_vtables.push_back(vt);
        }
    }
    auto entries = mdf2_vtables.empty() ? std::vector<ResourceEntry>{} : ResourceCache::list(L".mdf2", 1000000, mdf2_vtables);
    if (entries.empty()) {
        entries = ResourceCache::list(L".mdf2", 1000000);
        for (const auto& e : entries) {
            uintptr_t vt = 0;
            if (safe_read_ptr(e.resource, vt) && vt != 0 && std::find(mdf2_vtables.begin(), mdf2_vtables.end(), vt) == mdf2_vtables.end()) mdf2_vtables.push_back(vt);
        }
    }
    {
        std::unordered_set<uintptr_t> listed{};
        for (const auto& e : entries) listed.insert(e.resource);
        static const auto get_scene = api->tdb()->find_method("via.SceneManager", "get_CurrentScene");
        static const auto find_components = api->tdb()->find_method("via.Scene", "findComponents(System.Type)");
        auto collect = [&] {
            auto scene = get_scene ? get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager")) : nullptr;
            auto arr = scene && find_components && mm.get_material ? find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.render.Mesh")) : nullptr;
            if (arr == nullptr) return;
            const auto count = *(uint32_t*)((uintptr_t)arr + ARRAY_COUNT);
            for (uint32_t i = 0; i < count; ++i) {
                auto mesh = *(API::ManagedObject**)((uintptr_t)arr + ARRAY_DATA + 8ull * i);
                auto holder = mesh ? mm.get_material->call<API::ManagedObject*>(vm, mesh) : nullptr;
                uintptr_t res = 0;
                if (holder == nullptr || !safe_read_ptr((uintptr_t)holder + OWNER_RESOURCE_OFFSET, res) || res == 0) continue;
                ResourceEntry e{};
                if (listed.insert(res).second && ResourceCache::read_entry(res, e)) entries.push_back(std::move(e));
            }
        };
        if (const auto code = seh_call(collect); code != 0) log("  Error while walking scene mesh materials (exception 0x%08lX)", code);
    }
    std::vector<std::wstring> paths{};
    for (const auto& e : entries) {
        // An mdf2 that never loaded successfully (file does not exist) has no raw data and references nothing
        if (!lower(e.path).ends_with(L".mdf2") || !e.ready) continue;
        ++checked;
        uintptr_t data = 0;
        uint32_t magic = 0;
        if (!safe_read_ptr(e.resource + MDF_DATA, data) || !read_u32(data, magic) || magic != MDF_MAGIC) {
            ++invalid;
            continue;
        }
        if (!mdf2_references(e.resource, target)) continue;
        if (std::find(paths.begin(), paths.end(), e.path) == paths.end()) paths.push_back(e.path);
    }
    for (const auto& p : paths) enqueue(p, mdf2, L"dependency " + j.path);
    if (!paths.empty() || invalid > 0) {
        log("  Referencing mdf2: %zu, reloaded as well (checked %zu loaded mdf2%s)", paths.size(), checked,
            invalid > 0 ? ("; " + std::to_string(invalid) + " have no raw data and could not be checked").c_str() : "");
    }
}

bool HotReload::update_userdata(const Job& j) {
    constexpr uintptr_t USERDATA_ROOT = 0x88;
    std::vector<uint8_t> data{};
    if (const auto file = natives_file(j.path); !file.empty()) {
        std::ifstream in{file, std::ios::binary};
        data.assign(std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{});
    }
    if (data.empty()) return false;
    // The natives snapshot from startup has not finished reading: wait for it (can only happen very shortly after startup)
    if (m_user_snapshot_future.valid()) {
        m_user_snapshot_future.wait();
        merge_user_snapshot();
    }
    std::vector<uint8_t> prev{};
    {
        auto& snapshot = m_file_snapshot[ResourceCache::normalize(j.path)];
        prev = std::move(snapshot);
        snapshot = data;
    }
    const auto slash = j.path.find_last_of(L"/\\");
    const auto label = narrow(slash == std::wstring::npos ? j.path : j.path.substr(slash + 1));
    bool ok = true;
    uint32_t roots = 0, fields = 0;
    LiveApplyResult swapped{};
    for (const auto r : {j.old_res, j.extra_old}) {
        uintptr_t root = 0;
        if (r == 0 || !safe_read_ptr(r + USERDATA_ROOT, root) || !managed_object_safe(root)) {
            if (r != 0) ok = false;
            continue;
        }
        auto res = PrefabLive::apply_userdata(prev, data, root, label);
        if (res.structure_changed) ok = false;
        ++roots;
        fields += res.fields;
        swapped.replaced.insert(swapped.replaced.end(), res.replaced.begin(), res.replaced.end());
        for (const auto old : res.old_resources) release_later(old);
    }
    // Writes that replaced the object itself: scan memory in the background, repoint other references to the old object (references copied away at game initialization, native pointers in components) to the new object, then release the old object
    if (!swapped.replaced.empty()) queue_object_scan(swapped, true);
    if (fields > 0) {
        log("  File changes written to the data the game is using: %u%s", fields, prev.empty() ? " (first reload of this file this session: fields differing from the new file were written)" : "");
    } else if (ok && roots > 0) {
        log("  Data the game is using already matches the new file, nothing to write");
    }
    return ok && roots > 0;
}

// rcol: components copy the user data and collision shapes from the rcol at initialization, so only swapping the cache does nothing for existing components. Write the file changes into every scene component using it
void HotReload::update_rcol(const Job& j) {
    std::vector<uint8_t> data{};
    if (const auto file = natives_file(j.path); !file.empty()) {
        std::ifstream in{file, std::ios::binary};
        data.assign(std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{});
    }
    if (data.empty()) return;
    if (m_user_snapshot_future.valid()) {
        m_user_snapshot_future.wait();
        merge_user_snapshot();
    }
    std::vector<uint8_t> prev{};
    {
        auto& snapshot = m_file_snapshot[ResourceCache::normalize(j.path)];
        prev = std::move(snapshot);
        snapshot = data;
    }
    auto r = PrefabLive::apply_rcol(j.path, prev, data);
    for (const auto old : r.old_resources) release_later(old);
    if (!r.replaced.empty()) {
        LiveApplyResult swapped{};
        swapped.replaced = std::move(r.replaced);
        queue_object_scan(swapped, true);
    }
    if (!r.ok) {
        log("  Collision components using it keep their data: %s", r.error.c_str());
        return;
    }
    if (r.structure_changed) {
        log("  Structure changed (%s); collision components using it keep their data, objects created later use the new file", r.error.c_str());
        return;
    }
    if (r.components == 0) {
        log("  No collision component in the scene uses it");
        return;
    }
    const auto written = r.ud_fields + r.shapes + r.joints + r.layers + r.masks;
    std::string detail{};
    if (r.ud_fields > 0) detail += ", user data: " + std::to_string(r.ud_fields);
    if (r.shapes > 0) detail += ", shapes: " + std::to_string(r.shapes);
    if (r.joints > 0) detail += ", bound joints: " + std::to_string(r.joints);
    if (r.layers > 0) detail += ", collision layers: " + std::to_string(r.layers);
    if (r.masks > 0) detail += ", collision masks: " + std::to_string(r.masks);
    log("  Collision components using it: %u (%u request sets), file changes written: %u%s%s", r.components, r.sets, written, detail.c_str(),
        prev.empty() ? " (first reload of this file this session: parts differing from the new file were written)" : "");
    if (!r.not_live.empty()) {
        std::string s{};
        for (const auto& x : r.not_live) s += (s.empty() ? "" : ", ") + x;
        log("  Not applied live (objects created later use the new file): %s", s.c_str());
    }
}

// Cache update only: the new resource already stays in the cache under the same key (commit_new repointed the cache node from the old resource to the new one when loading completed). The plugin holds a reference for it,
// otherwise it would be destroyed and removed from the cache when its count reaches zero before the game's next request; the old resource stays held by the objects still using it
void HotReload::finish_cached(const Job& j) {
    const auto key = ResourceCache::normalize(j.path);
    if (std::string_view{j.handler->resource_type} == "via.UserDataResource") {
        // Game code holds the .user root object directly (e.g. equipment appearance avp.user is held by cArmorSetPackage and others), so swapping the resource does nothing for them:
        // write the file changes into this object and keep the old resource in the cache, so later loads get this same object too
        bool in_place = false;
        auto run = [&] { in_place = update_userdata(j); };
        if (const auto code = seh_call(run); code != 0) log("  Error while writing data in use (exception 0x%08lX), skipped", code);
        // old_in_cache: commit_new left the old resource in the cache (see commit_new), the new one was never visible to the game
        const bool old_still_cached = j.old_in_cache;
        if (in_place && (old_still_cached || ResourceCache::replace(j.new_res, j.old_res))) {
            // The plugin keeps no reference to the old resource: a .user resource lives only as long as its root object (the root holds the resource, resource +0x88 does not hold the root).
            // Holding the resource without the root kept it in the cache after the game released the root, with +0x88 pointing to a freed object; the next load of the path
            // (e.g. putting the helmet back on in the equipment preview) got that resource (observed 2026-11-15: "old resource has no userdata root object" after switching the helmet away)
            if (const auto it = m_cached.find(key); it != m_cached.end()) {
                release_resource(it->second); // May be the old resource itself (from an earlier cache-only update, with its root held by the plugin)
                m_cached.erase(it);
            }
            release_resource(j.old_res);
            release_later(j.new_res);
            if (j.extra_old != 0) release_resource(j.extra_old);
            log("  %s: applied live (file changes written to the data the game is using)", narrow(j.path).c_str());
            return;
        }
        if (old_still_cached) {
            // Writing failed (structure changed, file unreadable): fall back to a cache-only update, the new resource goes into the cache now
            if (!ResourceCache::replace(j.old_res, j.new_res)) {
                log("  %s: the old resource is no longer in the cache (released or removed by the game); the new resource was not put in the cache, later loads read the disk again",
                    narrow(j.path).c_str());
            }
        } else if (in_place) {
            log("  The cache no longer holds the new resource, handled as cache-only");
        }
    }
    if (std::string_view{j.handler->resource_type} == "via.motion.MotionListResource") {
        auto run = [&] { update_motlist_versions(j); };
        if (const auto code = seh_call(run); code != 0) log("  Error while updating motion data in use (exception 0x%08lX), skipped", code);
    } else if (std::string_view{j.handler->resource_type} == "via.motion.MotionResource") {
        bool all = true;
        auto run = [&] { all = update_mot_versions(j); };
        if (const auto code = seh_call(run); code != 0) {
            log("  Error while updating motion data in use (exception 0x%08lX), skipped", code);
            all = false;
        }
        if (!all) {
            static const auto motlist = handler_for_ext(L"motlist");
            const auto paths = loaded_referrers(j.path, L".motlist.", motlist);
            if (!paths.empty()) log("  Referencing motlists: %zu, reloaded as well (motions started later use the new file)", paths.size());
            for (const auto& p : paths) enqueue(p, motlist, L"dependency " + j.path);
        }
    }
    // Other cache-only types were checked for the whole batch in finish_jobs; a .user gets here only when it fell back to a cache-only update
    if (m_cfg.cascade && std::string_view{j.handler->resource_type} == "via.UserDataResource") {
        auto run = [&] { cascade_prefabs({&j}); };
        if (const auto code = seh_call(run); code != 0) log("  Error while looking up prefabs using the old resource (exception 0x%08lX), skipped", code);
    }
    auto& held = m_cached[key];
    const auto previous = held;
    held = j.new_res;
    if (previous != 0 && previous != j.new_res) release_resource(previous);
    release_resource(j.old_res);
    if (j.extra_old != 0) release_resource(j.extra_old);
    const bool cached = ResourceCache::find(j.path) == j.new_res;
    const std::string_view type{j.handler->resource_type};
    const bool is_mdf2 = type == "via.render.MeshMaterialResource";
    const bool refresh = is_mdf2 || type == "via.render.MeshResource";
    // mdf2/mesh refresh scene meshes; textures replace the textures in scene meshes slot by slot, mmtr refreshes through the cascaded mdf2 reload; other types only affect later loads
    const bool component_live = type == "via.motion.Chain2Resource" || type == "via.character.CollisionShapePresetResource" ||
                                type == "via.dynamics.GpuCloth2Resource" || type == "via.dynamics.GpuClothResource" ||
                                type == "via.motion.MotionListResource" || type == "via.render.RenderTargetTextureResource";
    const bool live = refresh || component_live || type == "via.render.TextureResource" || type == "via.render.MasterMaterialResource" ||
                      type == "via.motion.MotionResource" || type == "via.gui.GUIResource" || type == "via.physics.RequestSetColliderResource";
    log("  %s: cache updated (%s); later loads and spawns use the new file%s%s%s%s", narrow(j.path).c_str(), j.handler->resource_type,
        live ? "" : "; objects already using it keep their data", cached ? "" : "; the new resource is not in the cache, later loads read the disk again",
        j.evicted_extra > 0 ? ("; " + std::to_string(j.evicted_extra) + " other cache entries with the same path removed as well").c_str() : "",
        (j.created_tex > 0 ? "; dependency resources finished loading (textures, mmtr): " + std::to_string(j.created_tex) : std::string{}).c_str());
    if (refresh) {
        auto run = [&] { refresh_meshes(j.path, j.new_res, *j.handler); };
        if (const auto code = seh_call(run); code != 0) log("  Error while refreshing mesh materials (exception 0x%08lX), skipped", code);
    } else if (component_live) {
        auto run = [&] { refresh_components(j); };
        if (const auto code = seh_call(run); code != 0) log("  Error while refreshing components using it (exception 0x%08lX), skipped", code);
    }
    if (type == "via.gui.GUIResource") {
        auto run = [&] { start_gui_update(j); };
        if (const auto code = seh_call(run); code != 0) log("  Error while preparing to update the displayed GUI (exception 0x%08lX), skipped", code);
    }
    if (lower(j.path).ends_with(L".rcol")) {
        auto run = [&] { update_rcol(j); };
        if (const auto code = seh_call(run); code != 0) log("  Error while writing collision components using it (exception 0x%08lX), skipped", code);
    }
    if (m_cfg.cascade) cascade_cached(j);
}

// gui: swapping the resource of a via.gui.GUI at runtime rebuilds the GUI, and the elements cached by the game's GUI controller classes become invalid and crash (observed 2026-11-09 with GUI020001),
// so the resource is not swapped; instead the file changes are written into the displayed GUI elements: one GUI is generated from the old file and one from the new file on hidden temporary objects (in two consecutive frames; the previous save's ones are not reused because icon material VariableVec etc. change with game state,
// and on 2026-11-09 reusing an old-file GUI generated 6 seconds earlier wrote 6-22 places even on an unchanged reload),
// and once ready they are compared by element path over several frames, writing only properties the file changed (PrefabLive::gui_diff_*). Added/removed elements and elements cloned from templates at runtime are not handled
void HotReload::start_gui_update(const Job& j) {
    const auto& api = API::get();
    const auto vm = api->get_vm_context();
    static const auto get_scene = api->tdb()->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = api->tdb()->find_method("via.Scene", "findComponents(System.Type)");
    auto scene = get_scene ? get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager")) : nullptr;
    auto arr = scene && find_components ? find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.gui.GUI")) : nullptr;
    if (arr == nullptr) return;
    const auto key = ResourceCache::normalize(j.path);
    PendingGui p{};
    p.path = j.path;
    const auto count = *(uint32_t*)((uintptr_t)arr + ARRAY_COUNT);
    for (uint32_t i = 0; i < count; ++i) {
        const auto gui = *(uintptr_t*)((uintptr_t)arr + ARRAY_DATA + 8ull * i);
        const auto res = PrefabLive::gui_resource(gui);
        ResourceEntry e{};
        if (res == 0 || res == j.new_res || !ResourceCache::read_entry(res, e) || ResourceCache::normalize(e.path) != key) continue;
        if (PrefabLive::gui_is_temp(gui)) continue; // The plugin's own comparison GUIs (kept for reuse)
        api->sdk()->managed_object->add_ref((REFrameworkManagedObjectHandle)gui);
        p.lives.push_back(gui);
    }
    if (p.lives.empty()) return;
    // Old file: the version in the cache before the reload (the last hot reload wrote exactly that one, so the displayed GUI's properties match it).
    // One comparison GUI is created per frame (the engine takes ten to several tens of milliseconds to generate a GUI with tens of thousands of elements; creating several in one frame drops frames noticeably); resources get a reference first so they are not released before creation finishes
    const uintptr_t sources[2] = {j.old_res, j.new_res};
    auto res_api = api->sdk()->resource;
    for (int k = 0; k < 2; ++k) {
        p.res[k] = sources[k];
        res_api->add_ref((REFrameworkResourceHandle)sources[k]);
    }
    m_pending_gui.push_back(std::move(p));
}

void HotReload::step_gui_updates() {
    // At most about 3 ms per frame (large GUIs have tens of thousands of elements; doing it all at once takes over 150 ms in one frame)
    constexpr double BUDGET_MS = 3.0;
    for (auto it = m_pending_gui.begin(); it != m_pending_gui.end();) {
        auto& p = *it;
        if (p.created < 2) {
            const auto k = p.created++;
            if ((p.gui[k] = PrefabLive::gui_temp_create(p.res[k], p.go[k])) == 0) {
                log("%s: failed to create the comparison GUI; the displayed GUI stays as is and uses the new file after a restart", narrow(p.path).c_str());
                finish_gui_update(p);
                it = m_pending_gui.erase(it);
                continue;
            }
            ++it;
            continue;
        }
        if (!p.ready) {
            bool ready = true;
            for (int k = 0; k < 2; ++k) ready = ready && PrefabLive::gui_view(p.gui[k]) != 0;
            if (!ready) {
                if (++p.frames >= 180) {
                    log("%s: timed out creating the comparison GUI; the displayed GUI stays as is and uses the new file after a restart", narrow(p.path).c_str());
                    finish_gui_update(p);
                    it = m_pending_gui.erase(it);
                } else {
                    ++it;
                }
                continue;
            }
            p.ready = true;
        }
        bool yielded = false;
        while (p.live_index < p.lives.size()) {
            if (p.diff == nullptr) {
                const auto lv = PrefabLive::gui_view(p.lives[p.live_index]);
                if (lv == 0) {
                    ++p.live_index;
                    continue;
                }
                p.diff = PrefabLive::gui_diff_begin(PrefabLive::gui_view(p.gui[0]), PrefabLive::gui_view(p.gui[1]), lv);
            }
            bool done = false;
            auto run = [&] { done = PrefabLive::gui_diff_step(p.diff, BUDGET_MS); };
            if (const auto code = seh_call(run); code != 0) {
                log("  Error while writing the displayed GUI (exception 0x%08lX), skipped", code);
                done = true;
            }
            if (!done) {
                yielded = true;
                break;
            }
            auto r = PrefabLive::gui_diff_end(p.diff);
            p.diff = nullptr;
            ++p.live_index;
            if (!r.ok) {
                if (!r.error.empty()) log("  %s", r.error.c_str());
                continue;
            }
            p.elements = r.elements;
            p.matched = std::max(p.matched, r.matched);
            p.written += (uint32_t)r.applied.size();
            if (p.applied.empty()) p.applied = std::move(r.applied);
            p.skipped.insert(p.skipped.end(), r.skipped.begin(), r.skipped.end());
            p.removed.insert(p.removed.end(), r.removed.begin(), r.removed.end());
            p.remove_failed.insert(p.remove_failed.end(), r.remove_failed.begin(), r.remove_failed.end());
            p.add_failed.insert(p.add_failed.end(), r.add_failed.begin(), r.add_failed.end());
            p.clones += r.clones;
            p.clone_written += r.clone_written;
            if (p.clone_applied.empty()) p.clone_applied = std::move(r.clone_applied);
            if (!r.to_add.empty()) p.adds.push_back({p.lives[p.live_index - 1], std::move(r.to_add)});
        }
        if (yielded) break; // Budget for this frame used up; continue next frame
        // Elements added by the file: create a donor GUI in one frame (moved off-screen, then drawing enabled), after it draws 2 frames attach the elements to the displayed GUI, then destroy the donor
        if (p.add_index < p.adds.size()) {
            auto& a = p.adds[p.add_index];
            bool next_live = false;
            auto run = [&] {
                if (p.donor == 0) {
                    p.donor = PrefabLive::gui_temp_create(p.res[1], p.donor_go);
                    if (p.donor == 0) {
                        for (const auto& item : a.items) p.add_failed.push_back(item.second);
                        next_live = true;
                        return;
                    }
                    PrefabLive::gui_offset(PrefabLive::gui_view(p.donor), -20000.0f, 0.0f);
                    PrefabLive::gui_temp_show(p.donor, p.donor_go);
                    p.donor_frames = 0;
                    return;
                }
                if (++p.donor_frames < 2) return;
                const auto lv = PrefabLive::gui_view(a.live);
                const auto dv = PrefabLive::gui_view(p.donor);
                for (const auto& [pk, k] : a.items) {
                    const auto parent = lv != 0 ? PrefabLive::gui_find(lv, pk) : 0;
                    const auto e = dv != 0 ? PrefabLive::gui_find(dv, k) : 0;
                    if (parent != 0 && e != 0 && PrefabLive::gui_add_child(parent, e)) {
                        // addChild does not recompute the world matrix; setting the position once does (observed 2026-11-10)
                        PrefabLive::gui_offset(e, 1.0f, 0.0f);
                        PrefabLive::gui_offset(e, -1.0f, 0.0f);
                        p.added.push_back(k);
                    } else {
                        p.add_failed.push_back(k);
                    }
                }
                next_live = true;
            };
            if (const auto code = seh_call(run); code != 0) {
                log("  Error while adding elements (exception 0x%08lX), skipped", code);
                next_live = true;
            }
            if (next_live) {
                if (p.donor != 0) PrefabLive::gui_temp_destroy(p.donor, p.donor_go);
                p.donor = p.donor_go = 0;
                ++p.add_index;
            }
            ++it;
            continue;
        }
        auto join = [](const std::vector<std::string>& v) {
            std::string s{};
            for (size_t i = 0; i < v.size() && i < 12; ++i) s += (i ? ", " : "") + v[i];
            if (v.size() > 12) s += " ... (" + std::to_string(v.size()) + " in total)";
            return s;
        };
        std::string structure{};
        if (p.clone_written > 0) structure += ", written to elements copied at runtime: " + std::to_string(p.clone_written);
        if (!p.added.empty()) structure += ", elements added: " + std::to_string(p.added.size());
        if (!p.removed.empty()) structure += ", elements removed: " + std::to_string(p.removed.size());
        log("%s: GUIs using it: %zu, file changes written: %u%s (elements in file: %u, matched: %u)", narrow(p.path).c_str(), p.lives.size(), p.written,
            structure.c_str(), p.elements, p.matched);
        if (!p.applied.empty()) log("  Applied properties: %s", join(p.applied).c_str());
        if (!p.clone_applied.empty()) log("  Applied properties on copied elements: %s", join(p.clone_applied).c_str());
        if (!p.added.empty()) log("  Added elements: %s", join(p.added).c_str());
        if (!p.removed.empty()) log("  Removed elements: %s", join(p.removed).c_str());
        if (!p.skipped.empty()) log("  Not written: %s", join(p.skipped).c_str());
        if (!p.add_failed.empty()) log("  Could not add (an element with the same name already exists there, or the parent was not found): %s", join(p.add_failed).c_str());
        if (!p.remove_failed.empty()) log("  Could not remove: %s", join(p.remove_failed).c_str());
        finish_gui_update(p);
        it = m_pending_gui.erase(it);
    }
}

void HotReload::finish_gui_update(PendingGui& p) {
    if (p.diff != nullptr) {
        PrefabLive::gui_diff_end(p.diff);
        p.diff = nullptr;
    }
    for (int k = 0; k < 2; ++k) PrefabLive::gui_temp_destroy(p.gui[k], p.go[k]);
    if (p.donor != 0) PrefabLive::gui_temp_destroy(p.donor, p.donor_go);
    p.donor = p.donor_go = 0;
    for (int k = 0; k < 2; ++k) {
        if (p.res[k] != 0) release_resource(p.res[k]);
        p.res[k] = 0;
    }
    auto mo = API::get()->sdk()->managed_object;
    for (const auto live : p.lives) mo->release((REFrameworkManagedObjectHandle)live);
    p.lives.clear();
}

// Offset verification of managed objects, the component chain, the type database and .user root objects (UserDataResource +0x88). Needs enough objects in the scene as samples;
// with too few samples it retries every 120 frames (live pfb writes, component raw pointer rewriting, reference redirection and .user reloads are disabled meanwhile)
void HotReload::check_layouts() {
    const auto r = PrefabLive::check_layout();
    // .user root objects: for .user resources ready in the cache, +0x88 should be an object derived from via.UserData
    uint32_t tested = 0, bad = 0;
    for (const auto& e : ResourceCache::list(L".user", 256)) {
        if (!e.ready) continue;
        ++tested;
        uintptr_t root = 0;
        bool ok = safe_read_ptr(e.resource + 0x88, root) && managed_object_safe(root);
        if (ok) {
            ok = false;
            for (auto t = ((API::ManagedObject*)root)->get_type_definition(); t != nullptr && !ok; t = t->get_parent_type()) {
                ok = t->get_full_name() == "via.UserData";
            }
        }
        if (!ok) ++bad;
    }
    const bool user_enough = tested >= 8;
    const bool user_ok = user_enough && bad * 20 <= tested;
    ++m_layout_attempts;
    if (!r.conclusive || !user_enough) {
        if (m_layout_attempts == 1) log("Layout check: not enough scene objects yet, checking again after entering a scene (pfb live writes, .user reload and reference redirection are disabled meanwhile)");
        return;
    }
    m_layout_pending = false;
    for (const auto& line : r.lines) log("Layout check: %s", line.c_str());
    log("Layout check: .user root objects: %s (sampled %u%s)", user_ok ? "passed" : "FAILED", tested,
        bad > 0 ? (", mismatched: " + std::to_string(bad)).c_str() : "");
    // .user writes compare fields through Differ using each type's deserialization sequence and reflected variable table, so .user is not reloaded either if the type info structure check fails
    m_userdata_layout_ok = user_ok && r.type_info;
    if (!r.managed) {
        log("Managed object layout check failed, plugin disabled");
        m_failed = true;
    }
    // Failed checks and the features they disable also go to the crash log (kept across launches)
    for (const auto& line : r.lines) {
        if (line.find("FAILED") != std::string::npos) crash_trace_note("Layout check: %s", line.c_str());
    }
    if (!user_ok) crash_trace_note("Layout check: .user root objects: FAILED (sampled %u, mismatched: %u)", tested, bad);
    std::string off{};
    if (!r.managed) off += "whole plugin, ";
    if (!r.components || !r.type_info || !r.component_flags) off += "pfb live writes, ";
    if (!r.components) off += "component raw pointer rewriting, ";
    if (!r.tdb_impl) off += "reference redirection after component rebuilds, ";
    if (!m_userdata_layout_ok) off += ".user reload, ";
    if (!off.empty()) {
        off.resize(off.size() - 2);
        crash_trace_note("Disabled after the layout check: %s", off.c_str());
    }
}

void HotReload::release_later(uintptr_t res) {
    m_deferred.emplace_back(res, m_frame + 120);
}

void HotReload::release_deferred(bool all) {
    for (auto it = m_deferred.begin(); it != m_deferred.end();) {
        if (all || m_frame >= it->second) {
            release_resource(it->first);
            it = m_deferred.erase(it);
        } else {
            ++it;
        }
    }
}

bool HotReload::complete_scan(PendingScan& scan) {
    auto res_api = API::get()->sdk()->resource;
    g_scan_stage = g_trace_note = "fetching scan results";
    const auto found = scan.result.get();
    if (scan.objects) {
        // Reference locations found: hand the old components to the engine for destruction; references to those that could not be committed are not rewritten
        g_scan_stage = g_trace_note = "committing rebuild";
        const auto dropped = PrefabLive::commit_rebuild(scan.wait_detached);
        if (!dropped.empty()) {
            const std::unordered_set<uintptr_t> d(dropped.begin(), dropped.end());
            for (const auto o : dropped) scan.mapping.erase(o);
            std::erase_if(scan.wait_detached, [&](uintptr_t o) { return d.contains(o); });
        }
        g_scan_stage = g_trace_note = "";
        return true;
    }
    g_scan_stage = g_trace_note = "replacing references";

    std::unordered_map<uintptr_t, uint32_t> patched{};
    for (const auto& [old_ptr, slots] : found) {
        const auto new_ptr = scan.mapping[old_ptr];
        if (m_cfg.verbose) {
            log("  Old resource %llx has %zu references:", old_ptr, slots.size());
            for (auto slot : slots) log("    %s", describe_slot(slot).c_str());
        }
        for (auto slot : slots) {
            // The scan runs in the background; reconfirm before replacing: still a managed holder/via.Prefab and still pointing to the old resource (CAS)
            if (!managed_is_a(slot - OWNER_RESOURCE_OFFSET, k_owner_types)) continue;
            if (InterlockedCompareExchange64((volatile LONG64*)slot, (LONG64)new_ptr, (LONG64)old_ptr) != (LONG64)old_ptr) continue;
            res_api->add_ref((REFrameworkResourceHandle)new_ptr);
            release_resource(old_ptr);
            ++patched[old_ptr];
        }
    }
    for (const auto& j : scan.jobs) {
        log("  %s: replaced %u references (background scan %.1f MB, %.0f ms)", narrow(j.path).c_str(), patched[j.old_res] + patched[j.extra_old],
            scan.stats->bytes_scanned / 1048576.0, scan.stats->milliseconds);
    }
    // sfur / jcns / fbxskel / motbank: components store the resource pointer internally, and the engine rebuilds from the new resource only after a setter swaps it in
    g_scan_stage = g_trace_note = "refreshing components using it";
    for (const auto& j : scan.jobs) {
        if (!holder_property_type(j.handler->resource_type)) continue;
        auto run = [&] { refresh_components(j); };
        if (const auto code = seh_call(run); code != 0) log("  Error while refreshing components using it (exception 0x%08lX), skipped", code);
    }
    g_scan_stage = g_trace_note = "releasing resource references";
    for (const auto& j : scan.jobs) release_job_refs(j);
    g_scan_stage = g_trace_note = "";
    return false;
}

void HotReload::shutdown() {
    m_ref_index.stop();
    PrefabLive::uninstall_tracking();
    if (m_watcher) m_watcher->stop();
    // Committed rebuilds: the old components were handed to the engine for destruction, so attach the new components and rewrite references immediately
    for (auto& scan : m_awaiting) {
        auto run = [&] { finish_object_scan(*scan); };
        if (const auto code = seh_call(run); code != 0) log("  Error while attaching or rewriting references (stage: %s, exception 0x%08lX)", g_scan_stage, code);
    }
    m_awaiting.clear();
    for (auto& scan : m_scans) {
        // If the result has been taken (complete_scan failed midway), stop waiting; resource references were already handled or kept in complete_scan
        if (!scan->result.valid()) continue;
        scan->result.wait();
        // Rebuilds not yet committed are abandoned (old components stay unchanged)
        if (scan->objects) PrefabLive::abort_rebuild(scan->wait_detached);
        for (const auto& j : scan->jobs) release_job_refs(j);
        // Uncommitted rebuilds: the old components are still there, so just release the references held here. Old objects swapped out by .user are no longer in the game data and are kept (forget_kept below only drops the records)
        if (scan->keep_old) {
            PrefabLive::keep_replaced(scan->held);
        } else {
            PrefabLive::release_objects(scan->held);
        }
    }
    m_scans.clear();
    for (const auto& j : m_scan_carry) release_job_refs(j);
    m_scan_carry.clear();
    for (auto& p : m_pending_gui) finish_gui_update(p);
    m_pending_gui.clear();
    PrefabLive::update(true);
    for (const auto& j : m_jobs) {
        if (j.stage != Stage::Loading) continue;
        release_resource(j.old_res);
        release_resource(j.new_res);
        if (j.extra_old) release_resource(j.extra_old);
    }
    m_jobs.clear();
    for (const auto& j : m_ready) release_job_refs(j);
    m_ready.clear();
    for (auto& plan : m_plans) {
        if (plan->result.valid()) plan->result.wait();
        finish_plan(*plan);
        release_job_refs(plan->job);
    }
    m_plans.clear();
    for (const auto& [_, res] : m_orphans) release_resource(res);
    m_orphans.clear();
    // New resources left in the cache: release the plugin's references (if nobody else holds them, the engine removes them from the cache and a later load reads the disk again, still the new file)
    for (const auto& [_, res] : m_cached) release_resource(res);
    m_cached.clear();
    for (const auto& [_, olds] : m_motlist_old) {
        for (const auto r : olds) release_resource(r);
    }
    m_motlist_old.clear();
    PrefabLive::forget_kept();
    release_deferred(true);
    release_retired_all();
    log("Core unloaded");
}

void HotReload::frame_body() {
    if (m_failed) return;
    if (!m_initialized) {
        m_initialized = true;
        if (!initialize()) {
            m_failed = true;
            return;
        }
    }
    merge_user_snapshot();
    ++m_frame;
    m_main_thread = GetCurrentThreadId();

    if (m_layout_pending && m_frame % 120 == 1) check_layouts();
    if (m_failed) return;
    release_deferred(false);
    if (m_frame % 60 == 0) reap_retired();
    PrefabLive::update();
    collect_changes();

    for (auto it = m_scans.begin(); it != m_scans.end();) {
        if ((*it)->result.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            // Remove from the list first so an error does not get processed again every following frame
            auto scan = std::move(*it);
            it = m_scans.erase(it);
            bool keep = false;
            auto run = [&] { keep = complete_scan(*scan); };
            if (const auto code = seh_call(run); code != 0) {
                log("  Error while replacing references (stage: %s, exception 0x%08lX); the unfinished part was skipped", g_scan_stage, code);
                if (scan->objects) {
                    // Committed ones attach as usual (the old components were handed to the engine for destruction), uncommitted ones are abandoned; references are not rewritten and old objects are kept
                    PrefabLive::attach_ready(scan->wait_detached);
                    PrefabLive::abort_rebuild(scan->wait_detached);
                    scan->held.clear();
                }
                keep = false;
            }
            if (keep) m_awaiting.push_back(std::move(scan));
        } else {
            ++it;
        }
    }
    // Fallback outside the engine update-phase callback (on_entry): attach here when the loader provides no phase callback, and handle wait timeouts
    process_awaiting(true);

    // Holder check done: components held by game code stay written in place (cached), the rest leave in_place and are rebuilt from the new file when the job is processed again
    for (auto it = m_plans.begin(); it != m_plans.end();) {
        if ((*it)->result.valid() && (*it)->result.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
            ++it;
            continue;
        }
        auto plan = std::move(*it);
        it = m_plans.erase(it);
        const auto checked = plan->candidates; // finish_plan clears it
        // Take the label before finish_plan releases the references
        std::vector<std::string> labels{};
        for (const auto c : checked) labels.push_back(PrefabLive::component_label(c));
        const auto held = finish_plan(*plan);
        plan->job.planned = true;
        if (!plan->job.in_place) plan->job.in_place = std::make_shared<std::unordered_set<uintptr_t>>();
        size_t rebuild = 0;
        for (size_t i = 0; i < checked.size(); ++i) {
            const auto c = checked[i];
            if (const auto h = held.find(c); h != held.end()) {
                if (h->second.size() != 1 || h->second[0] != "?") remember_held(c, h->second);
                log("  %s is held by game code (%s), not rebuilt", labels[i].c_str(), join_owners(h->second).c_str());
            } else {
                plan->job.in_place->erase(c);
                ++rebuild;
            }
        }
        plan->job.applied = rebuild == 0;
        m_ready.push_back(std::move(plan->job));
    }

    // Start new jobs; cascaded jobs start next frame so their dependencies finish eviction first
    // If the same file already has a job that finished loading and is waiting to be processed (a component rebuild is in progress), the new save is not loaded yet:
    // both jobs share the old resource, and processing them in the same batch makes them replace each other's cache entries (observed: the resource disappeared from the cache)
    auto pending_same_path = [&](const Job& j) {
        const auto key = ResourceCache::normalize(j.path);
        for (const auto& other : m_jobs) {
            if (&other != &j && other.stage != Stage::Queued && ResourceCache::normalize(other.path) == key) return true;
        }
        for (const auto& r : m_ready) {
            if (ResourceCache::normalize(r.path) == key) return true;
        }
        for (const auto& p : m_plans) {
            if (ResourceCache::normalize(p->job.path) == key) return true;
        }
        return false;
    };
    // Textures/mmtr referenced by the mdf2 are also being reloaded in this batch (several files saved together): the mdf2 waits for them before starting. Otherwise the mdf2 would still get the old textures when loading
    // (the cache holds the old ones while the new textures load) and would be cascade-reloaded once more after the textures finish; the cascade on texture completion during the wait merges with this queued job into one
    std::vector<std::wstring> dep_paths{};
    static const auto rtex_h = handler_for_ext(L"rtex");
    auto collect_dep = [&](const Job& j) {
        const std::string_view t{j.handler->resource_type};
        if (t == "via.render.TextureResource" || t == "via.render.MasterMaterialResource" || j.handler == rtex_h) {
            dep_paths.push_back(ResourceCache::normalize(j.path));
        }
    };
    for (const auto& j : m_jobs) collect_dep(j);
    for (const auto& j : m_ready) collect_dep(j);
    // uvs/efcsv/efx wait for files they reference that are also being reloaded in this batch (textures, mdf2, mesh and other efx dependency types, plus uvs, efcsv and referenced efx).
    // The cascade on dependency completion merges with this queued job, so it loads only once. efx only wait for each other on one-way references; mutually referencing ones do not wait (they would wait forever)
    static const auto uvs_h = handler_for_ext(L"uvs");
    static const auto efcsv_h = handler_for_ext(L"efcsv");
    static const auto efx_h = handler_for_ext(L"efx");
    auto effect_rank = [&](const TypeHandler* h) {
        if (effect_dependency(h)) return 1;
        if (h != nullptr && (h == uvs_h || h == efcsv_h)) return 2;
        if (h != nullptr && h == efx_h) return 3;
        return 0;
    };
    std::vector<std::pair<std::wstring, int>> effect_deps{};
    for (const auto& j : m_jobs) {
        if (const auto r = effect_rank(j.handler); r > 0) effect_deps.emplace_back(j.path, r);
    }
    for (const auto& j : m_ready) {
        if (const auto r = effect_rank(j.handler); r > 0) effect_deps.emplace_back(j.path, r);
    }
    // Each queued job must be checked against every other file of this batch for references: each file path is resolved only once per frame, and content comes from the in-memory efx/uvs index first (previously every check
    // scanned the directory and read the whole file from disk; a cascade of 23 efx took about 40 ms on the main thread)
    struct NativesFile {
        std::filesystem::path file;
        std::wstring rel; // Relative to natives (computed on strings; std::filesystem::relative accesses the disk)
    };
    std::unordered_map<std::wstring, NativesFile> file_memo{};
    auto natives_file_once = [&](const std::wstring& p) -> const NativesFile& {
        auto it = file_memo.find(p);
        if (it == file_memo.end()) {
            NativesFile f{natives_file(p), {}};
            if (!f.file.empty()) f.rel = f.file.lexically_relative(m_natives_dir).generic_wstring();
            it = file_memo.emplace(p, std::move(f)).first;
        }
        return it->second;
    };
    auto references = [&](const NativesFile& f, const std::wstring& needle) {
        bool known = false;
        const bool hit = !f.rel.empty() && m_ref_index.references(f.rel, needle, known);
        return known ? hit : file_references(f.file, needle);
    };
    auto waits_for_effect_deps = [&](const Job& j) {
        const auto rank = effect_rank(j.handler);
        if (rank < 2 || effect_deps.size() < 2) return false;
        const auto& file = natives_file_once(j.path);
        if (file.file.empty()) return false;
        const auto self = ResourceCache::normalize(j.path);
        for (const auto& [p, r] : effect_deps) {
            if (r > rank || ResourceCache::normalize(p) == self || !references(file, p)) continue;
            if (r < rank) return true;
            if (rank != 3) continue;
            // Both are efx: wait only if the other does not reference this one back
            const auto& other = natives_file_once(p);
            if (!other.file.empty() && !references(other, j.path)) return true;
        }
        return false;
    };
    auto waits_for_deps = [&](const Job& j) {
        if (waits_for_effect_deps(j)) return true;
        if (dep_paths.empty() || std::string_view{j.handler->resource_type} != "via.render.MeshMaterialResource") return false;
        const auto res = ResourceCache::find(j.path);
        if (res == 0) return false;
        bool wait = false;
        auto run = [&] {
            for (const auto& d : dep_paths) {
                if (mdf2_references(res, d)) {
                    wait = true;
                    return;
                }
            }
        };
        return seh_call(run) == 0 && wait;
    };
    // Several jobs starting in the same frame (a cascaded batch of efx, etc.): find all old resources in one walk of the cache table (about 1-2 ms each one by one; observed 2026-11-08: about 50 ms for 20)
    std::unordered_map<std::wstring, uintptr_t> old_prefetch{};
    {
        std::vector<std::wstring> queued{};
        for (const auto& j : m_jobs) {
            if (j.stage == Stage::Queued) queued.push_back(j.path);
        }
        if (queued.size() >= 2) {
            old_prefetch = ResourceCache::find_many(queued);
            m_old_prefetch = &old_prefetch;
        }
    }
    constexpr double START_BUDGET_MS = 4.0;
    const auto start_t0 = qpc_now();
    uint32_t n_started_now = 0;
    m_starts_deferred = false;
    struct PrefetchReset {
        const std::unordered_map<std::wstring, uintptr_t>*& p;
        ~PrefetchReset() { p = nullptr; }
    } prefetch_reset{m_old_prefetch};
    for (auto it = m_jobs.begin(); it != m_jobs.end();) {
        bool started = true;
        if (it->stage == Stage::Queued) {
            if (pending_same_path(*it) || waits_for_deps(*it)) {
                ++it;
                continue;
            }
            // At most about 4 ms per frame for starting new jobs (each takes about 1-3 ms: loose registration, the engine's create_resource, etc.); the rest continue next frame.
            // Observed 2026-11-08: saving a uvar cascaded to 23 efx, 20 of which started in the same frame, costing about 43 ms on the main thread
            if (n_started_now > 0 && qpc_ms(qpc_now() - start_t0) > START_BUDGET_MS) {
                m_starts_deferred = true;
                ++it;
                continue;
            }
            ++n_started_now;
            started = start_job(*it);
        }
        if (!started) {
            it = m_jobs.erase(it);
        } else {
            ++it;
        }
    }

    std::vector<Job> done{};
    std::vector<std::pair<std::wstring, const TypeHandler*>> retry{};
    std::vector<std::pair<std::wstring, const TypeHandler*>> loose_retry{};
    for (auto it = m_jobs.begin(); it != m_jobs.end();) {
        if (it->stage != Stage::Loading) {
            ++it;
            continue;
        }
        if (std::string_view{it->handler->resource_type} == "via.render.MeshMaterialResource" && is_ready(it->new_res)) {
            it->created_tex += create_pending_textures(it->new_res);
        }
        if (job_loaded(*it, it->new_res)) {
            const auto key = ResourceCache::normalize(it->path);
            if (std::string why{}; !loaded_from_loose(*it, why)) {
                // Hot reload targets loose files in natives: if the new resource did not read it (read the pak instead), do not replace; reload once more
                auto& tries = m_loose_retries[key];
                abandon_new(*it);
                if (tries < 2) {
                    ++tries;
                    loose_retry.push_back({it->path, it->handler});
                    log("%s: the new resource did not read the loose file %s (%s), reloading", narrow(it->path).c_str(), narrow(it->loose_rel).c_str(), why.c_str());
                } else {
                    m_loose_retries.erase(key);
                    log("%s: still did not read the loose file %s after reloading (%s); loaded instances keep the old resource", narrow(it->path).c_str(), narrow(it->loose_rel).c_str(),
                        why.c_str());
                }
                it = m_jobs.erase(it);
                continue;
            }
            m_loose_retries.erase(key);
            commit_new(*it);
            done.push_back(std::move(*it));
            it = m_jobs.erase(it);
        } else if (++it->frames > m_cfg.load_timeout_frames) {
            const bool is_mdf2 = std::string_view{it->handler->resource_type} == "via.render.MeshMaterialResource";
            const auto pending = is_mdf2 && it->old_ready && is_ready(it->new_res) ? mdf2_pending_deps(it->new_res) : std::vector<std::wstring>{};
            if (!it->old_ready) {
                // The old resource never reached the "complete" state either (e.g. a file missing in the dependency chain) but is still usable; old and new are in the same state, so replace as usual
                log("%s did not reach the loaded state (the resource before the reload did not either, a dependency may be missing); replacing it in its current state", narrow(it->path).c_str());
                commit_new(*it);
                done.push_back(std::move(*it));
            } else {
                if (!pending.empty()) {
                    // Reload after the dependency file is added/saved; on timeout, if the file is already on disk (added during the wait), reload immediately (at most 2 times in a row for the same mdf2)
                    const auto key = ResourceCache::normalize(it->path);
                    std::wstring names{};
                    bool exists = false;
                    for (const auto& d : pending) {
                        if (names.size() < 300) names += (names.empty() ? L"" : L", ") + d;
                        exists = exists || dep_file_exists(d);
                    }
                    auto& tries = m_dep_retries[key];
                    if (exists && tries < 2) {
                        ++tries;
                        retry.push_back({it->path, it->handler});
                        log("%s: dependencies have not finished loading (%s); the dependency files exist, reloading", narrow(it->path).c_str(), narrow(names).c_str());
                    } else {
                        m_dep_waiting[key] = DepWait{it->path, std::unordered_set<std::wstring>(pending.begin(), pending.end())};
                        log("%s: dependencies have not finished loading (%s); loaded instances keep the old resource. It reloads automatically when the dependency files are added or saved", narrow(it->path).c_str(),
                            narrow(names).c_str());
                    }
                } else if (is_ready(it->new_res)) {
                    log("%s: dependencies (textures etc.) have not finished loading; loaded instances keep the old resource", narrow(it->path).c_str());
                } else {
                    log("%s failed to load (the new file may be corrupt or malformed); loaded instances keep the old resource", narrow(it->path).c_str());
                }
                abandon_new(*it);
            }
            it = m_jobs.erase(it);
        } else {
            ++it;
        }
    }

    for (const auto& [path, handler] : retry) enqueue(path, handler, L"dependency file ready");
    for (const auto& [path, handler] : loose_retry) enqueue(path, handler, L"rereading loose file");
    // mdf2 successfully swapped in no longer wait for dependencies
    for (const auto& j : done) {
        const auto key = ResourceCache::normalize(j.path);
        m_dep_waiting.erase(key);
        m_dep_retries.erase(key);
    }

    // No new hot reload is processed until the previous component rebuild (scan, commit, attach) completes: the same component never has two rebuilds at once
    for (auto& j : done) m_ready.push_back(std::move(j));
    // Other jobs of the same batch are still loading or were just postponed: wait for them first (at most 60 frames) and process together, so the background memory scan runs only once
    // (each efx finishes loading in a different frame; processing batch by batch scanned 4-5 times per cascade, each reading about 5 GB)
    if (m_ready.empty()) {
        m_ready_since = 0;
    } else if (m_ready_since == 0) {
        m_ready_since = m_frame;
    }
    const bool more_coming = m_starts_deferred || std::any_of(m_jobs.begin(), m_jobs.end(), [](const Job& j) { return j.stage == Stage::Loading; });
    const bool hold = more_coming && m_frame - m_ready_since < 60;
    if (!m_ready.empty() && !hold && !PrefabLive::rebuild_busy() && m_awaiting.empty() && m_plans.empty()) {
        m_ready_since = 0;
        auto ready = std::move(m_ready);
        m_ready.clear();
        finish_jobs(ready);
    }
    // Jobs kept to be scanned together with the next cascade level: if the next level has no jobs to scan (load failed, skipped as not loaded, etc.) or the wait is too long, scan them on their own
    if (!m_scan_carry.empty() && (!scan_jobs_pending() || m_frame - m_scan_carry_since > 120)) {
        auto carry = std::move(m_scan_carry);
        m_scan_carry.clear();
        start_resource_scan(std::move(carry));
    }
    if (!m_pending_gui.empty()) step_gui_updates();
}

}
