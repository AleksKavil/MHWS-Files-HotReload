#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <array>
#include <cctype>
#include <filesystem>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <reframework/API.hpp>

#include "log.hpp"
#include "memory_scan.hpp"
#include "core_heap.hpp"
#include "crash_trace.hpp"
#include "prefab_live.hpp"
#include "resource_cache.hpp"
#include "rsz_layout.hpp"

namespace hr {

namespace {
using API = reframework::API;

constexpr uintptr_t PREFAB_RES_DATA = 0x58;
constexpr uintptr_t PREFAB_RES_SIZE = 0x60;
constexpr uintptr_t PFB_GO_COUNT = 0x04;
constexpr uintptr_t PFB_GOREF_COUNT = 0x0C;
constexpr uintptr_t PFB_GOREF_TABLE = 0x18; // Relocated to an address at load time
constexpr uintptr_t PFB_RSZ_OFFSET = 0x30;
constexpr uintptr_t PFB_GO_INFO = 0x38;
constexpr uint32_t PFB_MAGIC = 0x00424650;  // "PFB\0"
constexpr uint32_t RSZ_MAGIC = 0x005A5352;  // "RSZ\0"
constexpr uintptr_t RSZ_OBJECT_COUNT = 0x08;

constexpr uintptr_t ARRAY_COUNT = 0x1C;
constexpr uintptr_t ARRAY_DATA = 0x20;
constexpr uintptr_t STRING_LENGTH = 0x10;
constexpr uintptr_t STRING_CHARS = 0x14;

constexpr int MAX_DEPTH = 32; // Loop condition parameters of monster ActionParam are below level 12 (full check on 2026-11-05)

// Result of the structure verification at startup (PrefabLive::check_layout): with wrong component chain offsets, no live pfb writes and no component raw pointer rewriting;
// if the type database implementation table is misread, "counted references" are not judged (reference redirection then rewrites nothing)
bool g_components_layout_ok = false; // Disabled until verification passes
bool g_tdb_impl_layout_ok = false;
// Component message virtual function and behavior component flags: taken from engine machine code and sample-checked; -1 if not passed (related calls and writes are skipped, which disables live pfb writes)
int32_t g_component_message_off = -1; // Component virtual function fn(component, message name): called with L"awake" after createComponent attaches
int32_t g_behavior_start_off = -1;    // via.Behavior u8: non-zero means start has not run yet (read by get_Started)
int32_t g_behavior_awake_off = -1;    // via.Behavior u8: awake has run (checked by the message function when it receives "awake")
int32_t g_behavior_enabled_off = -1;  // via.Behavior u8: Enabled (read by get_Enabled)
// REType managed deserialization sequence (+0x68) verified; if not, sequence_of returns nothing
bool g_type_info_layout_ok = false;

struct NativeArray {
    uintptr_t* data;
    uint32_t size;
    uint32_t capacity;
};
using DeserializeFn = bool (*)(void*, NativeArray*, const uint8_t*, size_t);

// ---- Locating engine functions ----

uintptr_t function_start(uintptr_t addr) {
    DWORD64 image_base = 0;
    auto entry = RtlLookupFunctionEntry(addr, &image_base, nullptr);
    if (entry == nullptr) return 0;
    // Follow chained unwind info to find the main function entry
    for (int guard = 0; guard < 32; ++guard) {
        auto unwind = (uint8_t*)(image_base + entry->UnwindInfoAddress);
        const uint8_t flags = unwind[0] >> 3;
        if ((flags & UNW_FLAG_CHAININFO) == 0) break;
        const uint8_t code_count = unwind[2];
        auto chained = (PRUNTIME_FUNCTION)(unwind + 4 + ((code_count + 1) & ~1) * 2);
        entry = chained;
    }
    return image_base + entry->BeginAddress;
}

DeserializeFn find_deserialize() {
    static DeserializeFn fn = []() -> DeserializeFn {
        const auto base = (uintptr_t)GetModuleHandleW(nullptr);
        const auto nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
        auto section = IMAGE_FIRST_SECTION(nt);
        // cmp dword ptr [rbx], 'RSZ\0'
        const uint8_t pattern[] = {0x81, 0x3B, 0x52, 0x53, 0x5A, 0x00};
        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
            if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
            const auto start = (uint8_t*)(base + section->VirtualAddress);
            const auto end = start + section->Misc.VirtualSize - sizeof(pattern);
            for (auto p = start; p < end; ++p) {
                if (memcmp(p, pattern, sizeof(pattern)) == 0) {
                    const auto f = function_start((uintptr_t)p);
                    if (f != 0) {
                        log("RSZ deserialize function: %llx", (unsigned long long)f);
                        return (DeserializeFn)f;
                    }
                }
            }
        }
        log("RSZ deserialize function not found, pfb live parameter changes unavailable");
        return nullptr;
    }();
    return fn;
}

bool safe_deserialize(DeserializeFn fn, NativeArray* arr, const uint8_t* data, size_t size) {
    __try {
        return fn(nullptr, arr, data, size);
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

using InvokeFn = decltype(REFrameworkTDBMethod::invoke);

bool safe_invoke_raw(InvokeFn fn, API::Method* m, uintptr_t obj, void** args, unsigned args_size, reframework::InvokeRet* out) {
    __try {
        const auto r = fn((REFrameworkMethodHandle)m, (void*)obj, args, args_size, out, sizeof(*out));
        return r == REFRAMEWORK_ERROR_NONE && !out->exception_thrown;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

bool safe_invoke(API::Method* m, uintptr_t obj, void** args, unsigned args_size, reframework::InvokeRet* out) {
    return safe_invoke_raw(API::get()->sdk()->method->invoke, m, obj, args, args_size, out);
}

// ---- Managed object helpers ----

void add_ref(uintptr_t obj) {
    if (obj) API::get()->sdk()->managed_object->add_ref((REFrameworkManagedObjectHandle)obj);
}

void release(uintptr_t obj) {
    if (obj) API::get()->sdk()->managed_object->release((REFrameworkManagedObjectHandle)obj);
}

// Start of the managed field area as used by the engine at runtime (object + *(int32*)(object info - 8); the engine locates fields with it when releasing/deserializing objects).
// The TDB's offset_from_base - offset_from_fieldptr is off by 8 for some types (e.g. generic EPVData`1<T>, soundlib.SoundZoneGenerator: TDB gives 0x48,
// runtime is 0x50, so reading/writing by the TDB lands in the native parent class's data); recorded whenever an object is seen and preferred by fieldptr_base
std::mutex g_field_start_mutex{};
std::unordered_map<API::TypeDefinition*, uint32_t> g_field_start{};

bool safe_read_i32_at(uintptr_t addr, int32_t& out) {
    if (!vq_readable(addr, 4)) return false;
    __try {
        out = *(volatile int32_t*)addr;
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

API::TypeDefinition* type_of(uintptr_t obj) {
    if (!managed_object_safe(obj)) return nullptr;
    const auto td = ((API::ManagedObject*)obj)->get_type_definition();
    if (td != nullptr) {
        std::lock_guard lock{g_field_start_mutex};
        if (!g_field_start.contains(td)) {
            uintptr_t info = 0;
            int32_t start = 0;
            if (safe_read_ptr(obj, info) && info > 0x10000 && safe_read_i32_at(info - 8, start) && start >= 0x10 && start < 0x10000) {
                g_field_start.emplace(td, (uint32_t)start);
            }
        }
    }
    return td;
}

uint32_t runtime_field_start(API::TypeDefinition* td) {
    std::lock_guard lock{g_field_start_mutex};
    const auto it = g_field_start.find(td);
    return it == g_field_start.end() ? 0 : it->second;
}

const std::string& name_of(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, std::string> cache{};
    auto it = cache.find(td);
    if (it == cache.end()) it = cache.emplace(td, td ? td->get_full_name() : std::string{}).first;
    return it->second;
}

bool is_a(API::TypeDefinition* td, const char* base) {
    for (auto t = td; t != nullptr; t = t->get_parent_type()) {
        if (name_of(t) == base) return true;
    }
    return false;
}

// References to scene objects (GameObjects/components etc.) must not be copied from a deserialized copy onto an instance
bool is_scene_object(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, bool> cache{};
    auto it = cache.find(td);
    if (it != cache.end()) return it->second;
    const bool r = is_a(td, "via.GameObject") || is_a(td, "via.Component") || is_a(td, "via.Folder") || is_a(td, "via.Scene");
    cache.emplace(td, r);
    return r;
}

// Root object of an external userdata (.user): the engine gets it by path from the UserData resource (sub_14A4A6230; held by the resource and shared everywhere).
// In RSZ all such instances are in the userdata table and read no data (no embedded ones across 876 pfb tested), so only the whole reference can be swapped; their content can never be created or rewritten
bool is_userdata(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, bool> cache{};
    if (td == nullptr) return false;
    if (const auto it = cache.find(td); it != cache.end()) return it->second;
    const bool r = is_a(td, "via.UserData");
    cache.emplace(td, r);
    return r;
}

std::wstring read_string(uintptr_t s) {
    if (s == 0) return {};
    const auto len = *(int32_t*)(s + STRING_LENGTH);
    if (len <= 0 || len > 4096) return {};
    return std::wstring((const wchar_t*)(s + STRING_CHARS), len);
}

bool is_string_type(API::TypeDefinition* td) {
    return td != nullptr && name_of(td) == "System.String";
}

// Whether a value type contains references (structs containing references cannot simply be memcpy'd)
bool valuetype_has_refs(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, bool> cache{};
    auto it = cache.find(td);
    if (it != cache.end()) return it->second;
    cache[td] = false; // Recursion guard
    bool r = false;
    if (!td->is_primitive() && !td->is_enum()) {
        for (auto f : td->get_fields()) {
            if (f->is_static()) continue;
            auto ft = f->get_type();
            if (ft == nullptr) continue;
            if (!ft->is_valuetype() || (ft != td && valuetype_has_refs(ft))) {
                r = true;
                break;
            }
        }
    }
    cache[td] = r;
    return r;
}

// ---- pfb deserialization ----

struct PrefabTree {
    struct GameObject {
        std::wstring name;
        int parent{-1}; // GameObject index
        uintptr_t object{};
        std::vector<uintptr_t> components;
        int slot{};                                  // Index in the object table
        std::vector<int> component_slots;
        std::wstring path; // Name path relative to the root
    };
    std::vector<GameObject> gos;
    std::vector<uintptr_t> objects; // All deserialized objects (references held)
    // GameObjectRef info table: at instantiation the engine writes the target GameObject's reference ID into the holder through the reflected variable setter (RSZ only stores the raw GUID)
    struct GoRef {
        int object{};  // Object table index of the holder (component or data object)
        uint32_t prop{}; // Property id (see rsz_variable_by_id)
        int index{};   // Element index for indexed variables
        int target{};  // Object table index of the target GameObject
    };
    std::vector<GoRef> gorefs;

    ~PrefabTree() {
        for (auto o : objects) release(o);
    }
};

// via.GameObject+0x28 is the name string. get_Name is not used: when the GameObject is not in a scene yet (+0x18 null,
// e.g. a deserialized copy) it throws a VM null reference exception, and a direct call does not clear the exception state
constexpr uintptr_t GAME_OBJECT_NAME = 0x28;

std::wstring game_object_name(uintptr_t go) {
    uintptr_t s = 0;
    if (go == 0 || !safe_read_ptr(go + GAME_OBJECT_NAME, s)) return {};
    return read_string(s);
}

bool deserialize_prefab_data(uintptr_t data, uintptr_t size, PrefabTree& tree);

bool deserialize_prefab(uintptr_t res, PrefabTree& tree) {
    if (res == 0) return false;
    uintptr_t data = 0, size = 0;
    if (!safe_read_ptr(res + PREFAB_RES_DATA, data) || !safe_read_ptr(res + PREFAB_RES_SIZE, size) || data == 0) return false;
    return deserialize_prefab_data(data, size, tree);
}

// data: pfb data (the data in the resource or a copy; header tables may hold offsets or post-load addresses)
bool deserialize_prefab_data(uintptr_t data, uintptr_t size, PrefabTree& tree) {
    const auto fn = find_deserialize();
    if (fn == nullptr || data == 0 || size < 0x40) return false;
    if (*(uint32_t*)data != PFB_MAGIC) return false;
    const auto rsz_off = *(uint64_t*)(data + PFB_RSZ_OFFSET);
    if (rsz_off >= size || *(uint32_t*)(data + rsz_off) != RSZ_MAGIC) return false;
    const auto object_count = *(uint32_t*)(data + rsz_off + RSZ_OBJECT_COUNT);

    // Same as the engine's caller: preallocate and fill in the count
    std::vector<uintptr_t> buffer(object_count + 1, 0);
    NativeArray arr{buffer.data(), object_count, object_count};
    if (!safe_deserialize(fn, &arr, (const uint8_t*)(data + rsz_off), size - rsz_off)) {
        log("pfb deserialization failed");
        return false;
    }
    if (arr.data != buffer.data()) {
        log("pfb deserialize output array was reallocated, giving up (layout differs from what was expected)");
        return false;
    }
    tree.objects.assign(buffer.begin(), buffer.begin() + object_count);

    const auto go_count = *(int32_t*)(data + PFB_GO_COUNT);
    std::unordered_map<int, int> object_to_go{};
    for (int i = 0; i < go_count; ++i) {
        const auto info = data + PFB_GO_INFO + 12ull * i;
        const auto obj_index = *(int32_t*)info;
        const auto parent_obj = *(int32_t*)(info + 4);
        const auto comp_count = *(int32_t*)(info + 8);
        if (obj_index < 0 || (uint32_t)(obj_index + comp_count) >= object_count + 1) return false;

        PrefabTree::GameObject go{};
        go.object = tree.objects[obj_index];
        go.slot = obj_index;
        go.name = game_object_name(go.object);
        go.parent = parent_obj; // Store the object index first; converted below
        for (int c = 1; c <= comp_count; ++c) {
            go.components.push_back(tree.objects[obj_index + c]);
            go.component_slots.push_back(obj_index + c);
        }
        object_to_go[obj_index] = i;
        tree.gos.push_back(std::move(go));
    }
    // Parent object index -> GameObject index, and build name paths (same-named siblings get #index)
    for (auto& go : tree.gos) {
        auto it = object_to_go.find(go.parent);
        go.parent = (go.parent >= 0 && it != object_to_go.end()) ? it->second : -1;
    }
    std::function<std::wstring(int)> path_of = [&](int i) -> std::wstring {
        auto& go = tree.gos[i];
        if (!go.path.empty() || go.parent < 0) return go.path;
        int dup = 0;
        for (int j = 0; j < i; ++j) {
            if (tree.gos[j].parent == go.parent && tree.gos[j].name == go.name) ++dup;
        }
        const auto parent_path = path_of(go.parent);
        go.path = (parent_path.empty() ? L"" : parent_path + L"/") + go.name + (dup ? L"#" + std::to_wstring(dup) : L"");
        return go.path;
    };
    for (int i = 0; i < (int)tree.gos.size(); ++i) path_of(i);

    const auto goref_count = *(int32_t*)(data + PFB_GOREF_COUNT);
    auto goref_tbl = *(uint64_t*)(data + PFB_GOREF_TABLE);
    if (goref_tbl < size) goref_tbl += data; // An offset when not relocated
    if (goref_count > 0 && goref_tbl >= data && goref_tbl + 16ull * goref_count <= data + size) {
        for (int i = 0; i < goref_count; ++i) {
            const auto e = goref_tbl + 16ull * i;
            PrefabTree::GoRef g{*(int32_t*)e, *(uint32_t*)(e + 4), *(int32_t*)(e + 8), *(int32_t*)(e + 12)};
            if (g.object < 0 || g.target < 0 || (uint32_t)g.object >= object_count || (uint32_t)g.target >= object_count) continue;
            tree.gorefs.push_back(g);
        }
    }
    return !tree.gos.empty();
}

// ---- Scene instances ----

// Current processing stage (written to the log on exceptions)
const char* g_stage = "";
std::string g_stage_detail{};

// GameObjects in the scene whose names are in names
std::vector<uintptr_t> scene_objects_named_any(const std::unordered_set<std::wstring>& names) {
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();
    static const auto get_scene = tdb->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = tdb->find_method("via.Scene", "findComponents(System.Type)");
    static const auto get_go = tdb->find_method("via.Component", "get_GameObject");
    std::vector<uintptr_t> result{};
    if (!get_scene || !find_components || !get_go) return result;

    auto scene = get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager"));
    if (scene == nullptr) return result;
    auto arr = (uintptr_t)find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.Transform"));
    if (arr == 0) return result;
    const auto count = *(uint32_t*)(arr + ARRAY_COUNT);
    for (uint32_t i = 0; i < count; ++i) {
        const auto t = *(uintptr_t*)(arr + ARRAY_DATA + 8ull * i);
        if (t == 0) continue;
        const auto go = (uintptr_t)get_go->call<API::ManagedObject*>(vm, t);
        if (go != 0 && names.contains(game_object_name(go))) result.push_back(go);
    }
    return result;
}

std::vector<uintptr_t> components_of(uintptr_t go) {
    static const auto get_components = API::get()->tdb()->find_method("via.GameObject", "get_Components");
    std::vector<uintptr_t> result{};
    if (get_components == nullptr) return result;
    const auto arr = (uintptr_t)get_components->call<API::ManagedObject*>(API::get()->get_vm_context(), go);
    if (arr == 0) return result;
    const auto count = *(uint32_t*)(arr + ARRAY_COUNT);
    for (uint32_t i = 0; i < count; ++i) result.push_back(*(uintptr_t*)(arr + ARRAY_DATA + 8ull * i));
    return result;
}

// Collect the scene hierarchy under root by name path (same rules as PrefabTree::path)
void collect_live(uintptr_t root, std::unordered_map<std::wstring, uintptr_t>& out) {
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();
    static const auto get_transform = tdb->find_method("via.GameObject", "get_Transform");
    static const auto get_child = tdb->find_method("via.Transform", "get_Child");
    static const auto get_next = tdb->find_method("via.Transform", "get_Next");
    static const auto t_get_go = tdb->find_method("via.Transform", "get_GameObject");
    if (!get_transform || !get_child || !get_next || !t_get_go) return;

    out[L""] = root;
    std::function<void(uintptr_t, const std::wstring&, int)> walk = [&](uintptr_t transform, const std::wstring& path, int depth) {
        if (depth > 32) return;
        std::unordered_map<std::wstring, int> seen{};
        for (auto c = (uintptr_t)get_child->call<API::ManagedObject*>(vm, transform); c != 0;
             c = (uintptr_t)get_next->call<API::ManagedObject*>(vm, c)) {
            const auto go = (uintptr_t)t_get_go->call<API::ManagedObject*>(vm, c);
            const auto name = game_object_name(go);
            const int dup = seen[name]++;
            const auto child_path = (path.empty() ? L"" : path + L"/") + name + (dup ? L"#" + std::to_wstring(dup) : L"");
            out.emplace(child_path, go);
            walk(c, child_path, depth + 1);
        }
    };
    const auto t = (uintptr_t)get_transform->call<API::ManagedObject*>(vm, root);
    if (t != 0) walk(t, L"", 0);
}

uintptr_t parent_go_of(uintptr_t go) {
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();
    static const auto get_transform = tdb->find_method("via.GameObject", "get_Transform");
    static const auto get_parent = tdb->find_method("via.Transform", "get_Parent");
    static const auto t_get_go = tdb->find_method("via.Transform", "get_GameObject");
    if (!get_transform || !get_parent || !t_get_go || go == 0) return 0;
    const auto t = (uintptr_t)get_transform->call<API::ManagedObject*>(vm, go);
    const auto pt = t ? (uintptr_t)get_parent->call<API::ManagedObject*>(vm, t) : 0;
    return pt ? (uintptr_t)t_get_go->call<API::ManagedObject*>(vm, pt) : 0;
}

// ---- Instance source records: inline-hook the engine's prefab instantiate function (sub_14A4A5860) and record spawned root GameObject -> PrefabResource ----
// Engine GameObjects do not record their source prefab (+0x20 is the Folder); the game spawns weapons, attack objects etc. without going through the managed via.Prefab.instantiate,
// but every instantiation ends up calling fn(PrefabResource, GameObject** out, Folder, ...).
// Located via: native implementation of via.Prefab.instantiate(via.vec3) -> its first call (sub_14A4A5790) -> the call target inside it starting with the prologue below.
// The prologue is 8 pushes + sub rsp,imm32, 19 bytes in total with no RIP-relative addressing, moved verbatim into the trampoline.
constexpr uint8_t INSTANTIATE_PROLOGUE[] = {0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x55, 0x53, 0x48, 0x81, 0xEC};
constexpr size_t PATCH_LEN = 19;

using InstantiateFn = uintptr_t (*)(uintptr_t, uintptr_t*, uintptr_t, uintptr_t);

std::mutex g_track_mutex{};
std::unordered_map<uintptr_t, uintptr_t> g_spawned{}; // Root GameObject -> PrefabResource
// Root GameObject -> each child {name path, GameObject} when instantiation completed. The game may later move children elsewhere
// (e.g. CLSP_Ground of waist armor is moved under MasterPlayer); during hot reload, children not found by path use these records
using ChildList = std::vector<std::pair<std::wstring, uintptr_t>>;
std::unordered_map<uintptr_t, ChildList> g_spawn_children{};
// Offsets of a Transform's first child / next sibling (taken from the native implementations of via.Transform.get_Child/get_Next); 0 means children are not recorded
uintptr_t g_transform_child{};
uintptr_t g_transform_next{};
constexpr uintptr_t GO_TRANSFORM = 0x18;   // GameObject -> first component (Transform)
constexpr uintptr_t COMPONENT_GO = 0x10;   // Component -> owning GameObject

uintptr_t g_inst_target{};
uint8_t g_inst_saved[PATCH_LEN]{};
uint8_t* g_inst_tramp{};
std::atomic<int> g_inst_inflight{0};

// Instantiation may run off the main thread: read the Transform child chain directly without calling VM methods. Path rules are the same as collect_live
void record_spawn_children(uintptr_t go) {
    uintptr_t t = 0, first = 0;
    if (g_transform_child == 0 || g_transform_next == 0 || !safe_read_ptr(go + GO_TRANSFORM, t) || t == 0 ||
        !safe_read_ptr(t + g_transform_child, first) || first == 0) {
        return;
    }
    ChildList out{};
    std::function<void(uintptr_t, const std::wstring&, int)> walk = [&](uintptr_t transform, const std::wstring& path, int depth) {
        if (depth > 32) return;
        std::unordered_map<std::wstring, int> seen{};
        uintptr_t c = 0;
        if (!safe_read_ptr(transform + g_transform_child, c)) return;
        for (int guard = 0; c != 0 && guard < 4096 && out.size() < 4096; ++guard) {
            uintptr_t child_go = 0;
            if (!safe_read_ptr(c + COMPONENT_GO, child_go) || child_go == 0) break;
            const auto name = game_object_name(child_go);
            const int dup = seen[name]++;
            const auto child_path = (path.empty() ? L"" : path + L"/") + name + (dup ? L"#" + std::to_wstring(dup) : L"");
            out.emplace_back(child_path, child_go);
            walk(c, child_path, depth + 1);
            if (!safe_read_ptr(c + g_transform_next, c)) break;
        }
    };
    walk(t, L"", 0);
    std::lock_guard lock{g_track_mutex};
    g_spawn_children[go] = std::move(out);
}

uintptr_t instantiate_detour(uintptr_t res, uintptr_t* out, uintptr_t folder, uintptr_t extra) {
    ++g_inst_inflight;
    const auto r = ((InstantiateFn)g_inst_tramp)(res, out, folder, extra);
    uintptr_t go = 0;
    if (out != nullptr && safe_read_ptr((uintptr_t)out, go) && go != 0 && res != 0) {
        {
            std::lock_guard lock{g_track_mutex};
            g_spawned[go] = res;
            g_spawn_children.erase(go);
        }
        try {
            record_spawn_children(go);
        } catch (...) {
        }
    }
    --g_inst_inflight;
    return r;
}

bool write_code(uintptr_t addr, const void* bytes, size_t n) {
    DWORD old = 0;
    if (!VirtualProtect((void*)addr, n, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy((void*)addr, bytes, n);
    VirtualProtect((void*)addr, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, n);
    return true;
}

// Rewrite the function start: first write a 2-byte spin jump (jmp $), write the remaining bytes, then write back the first 2 bytes, so other threads never execute a half-written instruction
bool patch_entry(uintptr_t addr, const uint8_t* bytes) {
    DWORD old = 0;
    if (!VirtualProtect((void*)addr, PATCH_LEN, PAGE_EXECUTE_READWRITE, &old)) return false;
    InterlockedExchange16((volatile SHORT*)addr, (SHORT)0xFEEB);
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, PATCH_LEN);
    memcpy((void*)(addr + 2), bytes + 2, PATCH_LEN - 2);
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, PATCH_LEN);
    InterlockedExchange16((volatile SHORT*)addr, *(const SHORT*)bytes);
    VirtualProtect((void*)addr, PATCH_LEN, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, PATCH_LEN);
    return true;
}

uintptr_t first_call_target(uintptr_t fn, size_t range, const uint8_t* want = nullptr, size_t want_len = 0) {
    const auto image = (uintptr_t)GetModuleHandleW(nullptr);
    const auto nt = (PIMAGE_NT_HEADERS)(image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
    const auto image_end = image + nt->OptionalHeader.SizeOfImage;
    for (size_t i = 0; i + 5 <= range; ++i) {
        const auto p = (const uint8_t*)fn + i;
        if (p[0] != 0xE8) continue;
        const auto t = (uintptr_t)(p + 5) + *(const int32_t*)(p + 1);
        if (t < image || t + 32 > image_end) continue;
        if (want == nullptr || memcmp((const void*)t, want, want_len) == 0) return t;
    }
    return 0;
}

uintptr_t locate_instantiate() {
    const auto td = API::get()->tdb()->find_type("via.Prefab");
    if (td == nullptr) return 0;
    for (const auto m : td->get_methods()) {
        if (m == nullptr || std::string_view{m->get_name()} != "instantiate" || m->get_num_params() != 1) continue;
        const auto impl = (uintptr_t)m->get_function_raw();
        const auto mid = impl ? first_call_target(impl, 0x100) : 0;
        return mid ? first_call_target(mid, 0x200, INSTANTIATE_PROLOGUE, sizeof(INSTANTIATE_PROLOGUE)) : 0;
    }
    return 0;
}

// The engine function that attaches deserialized components to a GameObject during instantiation, sub_1401C1B40(GameObject, Scene, Component**, count):
// the next call right after the RSZ main function call in the instantiate function. It resets the component chain to the given list: components not in the list are removed,
// new components are registered with the scene (sub_14A48EA20, sets the owning GameObject) and get a reference, and finally virtual function +0x40 is called on the new components
using SetComponentsFn = void (*)(uintptr_t, uintptr_t, uintptr_t*, uint64_t);

SetComponentsFn locate_set_components() {
    static const auto fn = []() -> SetComponentsFn {
        // After the instance source hook is installed the function start is rewritten and cannot be found by the prologue; use the address recorded when hooking
        const auto inst = g_inst_target != 0 ? g_inst_target : locate_instantiate();
        const auto main = rsz_engine_deserializer();
        if (inst == 0 || main == 0) return nullptr;
        for (size_t i = PATCH_LEN; i + 5 <= 0x200; ++i) {
            const auto q = (const uint8_t*)inst + i;
            if (q[0] != 0xE8 || (uintptr_t)(q + 5) + *(const int32_t*)(q + 1) != main) continue;
            return (SetComponentsFn)first_call_target((uintptr_t)(q + 5), 0x80);
        }
        return nullptr;
    }();
    return fn;
}

// Objects in the records may have been destroyed and their memory freed: guard against access violations when checking
bool safe_is_managed(uintptr_t obj) {
    return managed_object_safe(obj);
}

// Whether the hierarchy of GameObject go matches the pfb. strict: identical root component types and every sub-path of the pfb exists;
// otherwise (spawn records with a known source, only ruling out addresses reused by other objects): at least half of the pfb's root component types and sub-paths exist (components may be added/removed at runtime)
bool matches_structure(uintptr_t go, const PrefabTree& tree, bool strict = true) {
    if (go == 0 || type_of(go) == nullptr || name_of(type_of(go)) != "via.GameObject") return false;
    std::multiset<std::string> want{}, have{};
    for (const auto c : tree.gos[0].components) want.insert(name_of(type_of(c)));
    for (const auto c : components_of(go)) have.insert(name_of(type_of(c)));
    if (strict && want != have) return false;
    if (!strict) {
        size_t hit = 0;
        for (const auto& t : std::set<std::string>(want.begin(), want.end())) hit += have.contains(t) ? 1 : 0;
        if (hit * 2 < std::set<std::string>(want.begin(), want.end()).size()) return false;
    }
    if (tree.gos.size() == 1) return true;
    std::unordered_map<std::wstring, uintptr_t> live{};
    collect_live(go, live);
    const auto found = (size_t)std::count_if(tree.gos.begin(), tree.gos.end(), [&](const auto& g) { return live.contains(g.path); });
    return strict ? found == tree.gos.size() : found * 2 >= tree.gos.size();
}

// Instances recorded with source old_res/new_res (verified to still be GameObjects with the same structure). Hot reload replaces resource content in place, so records keep old_res
std::vector<uintptr_t> tracked_instances(uintptr_t old_res, uintptr_t new_res, const PrefabTree& tree) {
    std::vector<uintptr_t> gos{};
    {
        std::lock_guard lock{g_track_mutex};
        for (auto& [go, res] : g_spawned) {
            if (res != old_res && res != new_res) continue;
            gos.push_back(go);
        }
    }
    std::vector<uintptr_t> out{};
    std::vector<uintptr_t> stale{};
    for (const auto go : gos) {
        bool ok = false;
        try {
            ok = safe_is_managed(go) && matches_structure(go, tree, false);
        } catch (...) {
            ok = false;
        }
        (ok ? out : stale).push_back(go);
    }
    if (!stale.empty()) {
        std::lock_guard lock{g_track_mutex};
        for (const auto go : stale) {
            g_spawned.erase(go);
            g_spawn_children.erase(go);
        }
    }
    return out;
}

// Instances (root GameObjects) in the scene spawned from this pfb:
// 1. By name: the root object names of the old and new files (instances were spawned from the old file; after a root rename the GameObject parameter write sets the new name)
//    plus the sources recorded at spawn time (via.Prefab.instantiate hook), which find single-GameObject instances renamed at runtime
// 2. By structure (when not found by name and the pfb has children, e.g. the root was renamed at runtime): candidates are parents of GameObjects named like the pfb's first-level children,
//    accepted only if the root's component types match and every sub-path of the pfb exists
std::vector<uintptr_t> find_instances(const PrefabTree& old_tree, const PrefabTree& new_tree, uintptr_t old_res, uintptr_t new_res,
                                     bool& by_structure, uint32_t& by_track) {
    by_structure = false;
    by_track = 0;
    g_stage_detail = "by name";
    auto roots = scene_objects_named_any({old_tree.gos[0].name, new_tree.gos[0].name});
    g_stage_detail = "by spawn record";
    for (const auto go : tracked_instances(old_res, new_res, old_tree)) {
        if (std::find(roots.begin(), roots.end(), go) != roots.end()) continue;
        roots.push_back(go);
        ++by_track;
    }
    g_stage_detail.clear();
    if (!roots.empty() || old_tree.gos.size() < 2) return roots;

    g_stage_detail = "by structure";
    std::unordered_set<std::wstring> first_level{};
    for (const auto& go : old_tree.gos) {
        if (go.parent == 0) first_level.insert(go.name);
    }
    std::multiset<std::string> root_types{};
    for (const auto c : old_tree.gos[0].components) root_types.insert(name_of(type_of(c)));

    std::unordered_set<uintptr_t> candidates{};
    for (const auto child : scene_objects_named_any(first_level)) {
        if (const auto p = parent_go_of(child)) candidates.insert(p);
    }
    for (const auto cand : candidates) {
        std::multiset<std::string> types{};
        for (const auto c : components_of(cand)) types.insert(name_of(type_of(c)));
        if (types != root_types) continue;
        std::unordered_map<std::wstring, uintptr_t> live{};
        collect_live(cand, live);
        if (std::all_of(old_tree.gos.begin(), old_tree.gos.end(), [&](const auto& go) { return live.contains(go.path); })) roots.push_back(cand);
    }
    by_structure = !roots.empty();
    return roots;
}

// ---- Diffing and applying ----

// RSZ deserialization sequence (NativeArray<DeserializeSequence> at REType+0x68, 16 bytes per entry)
// Only fields in the sequence come from the file; other fields are uninitialized in deserialized copies and must never take part in comparisons
struct SeqEntry {
    uint8_t code;
    uint8_t size;
    uint8_t depth;
    bool is_array;
    uint32_t offset; // Relative to the start of managed fields (object + fieldptr offset)
    API::TypeDefinition* type;
};

constexpr uintptr_t RETYPE_DESERIALIZERS = 0x68;
constexpr uint8_t SEQ_CODE_OBJECT = 1;
constexpr uint8_t SEQ_CODE_STRING = 20;

const std::vector<SeqEntry>* sequence_of(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, std::vector<SeqEntry>> cache{};
    auto it = cache.find(td);
    if (it != cache.end()) return &it->second;
    static const std::vector<SeqEntry> none{};
    if (!g_type_info_layout_ok) return &none; // Not cached: read only after verification passes
    auto& out = cache[td];
    const auto rt = (uintptr_t)td->get_type_info();
    if (rt == 0) return &out;
    uintptr_t data = 0, meta = 0;
    if (!safe_read_ptr(rt + RETYPE_DESERIALIZERS, data) || !safe_read_ptr(rt + RETYPE_DESERIALIZERS + 8, meta)) return &out;
    const auto count = (int32_t)(uint32_t)meta;
    if (data == 0 || count <= 0 || count > 4096 || !vq_readable(data, 16ull * count)) return &out;
    for (int i = 0; i < count; ++i) {
        const auto e = data + 16ull * i;
        const auto bits = *(uint32_t*)e;
        if (bits >> 31) continue; // static
        SeqEntry se{};
        se.code = bits & 0xFF;
        se.size = (bits >> 8) & 0xFF;
        se.depth = (bits >> 24) & 0x3F;
        se.is_array = ((bits >> 30) & 1) != 0;
        se.offset = *(uint32_t*)(e + 4);
        se.type = *(API::TypeDefinition**)(e + 8);
        out.push_back(se);
    }
    return &out;
}

// Start of managed fields = offset_from_base - offset_from_fieldptr of any instance field (searched along the type chain)
// Returns 0 for no managed fields (native type); not compared
uintptr_t tdb_field_base(API::TypeDefinition* td);

uintptr_t fieldptr_base(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, uintptr_t> cache{};
    auto it = cache.find(td);
    if (it == cache.end()) it = cache.emplace(td, tdb_field_base(td)).first;
    // Types with managed fields: prefer the field area start the engine recorded in objects already seen
    if (it->second == 0) return 0;
    const auto rt = runtime_field_start(td);
    return rt != 0 ? rt : it->second;
}

uintptr_t tdb_field_base(API::TypeDefinition* td) {
    uintptr_t base = 0;
    for (auto t = td; t != nullptr && base == 0; t = t->get_parent_type()) {
        for (auto f : t->get_fields()) {
            if (f->is_static()) continue;
            base = (uintptr_t)f->get_offset_from_base() - (uintptr_t)f->get_offset_from_fieldptr();
            break;
        }
    }
    return base;
}

// Native component type (not a managed type). "Has managed fields" cannot be used: managed classes without their own managed fields (e.g. app.GUIMapAfterIconDrawUpdater)
// are still managed components, and rebuilding them as native components would call their managed property getters (observed to throw)
bool native_type(API::TypeDefinition* td) {
    return td != nullptr && !rsz_managed_type((uintptr_t)td->get_type_info());
}

// Scene object (GameObject/component) copy -> corresponding object in the scene instance
using SceneMap = std::unordered_map<uintptr_t, uintptr_t>;

// A newly created object (not yet registered, negative reference count): references written into it are stored directly, and its child objects are registered recursively when it registers itself
bool is_newborn(uintptr_t obj) {
    return obj != 0 && *(volatile int32_t*)(obj + 8) < 0;
}

// Object in the new copy -> {object at the corresponding position in the old copy, object in the scene instance, scene object newly created this time}
struct Corr {
    uintptr_t old_obj{};
    uintptr_t live{};
    bool fresh{};
};
using CorrMap = std::unordered_map<uintptr_t, Corr>;

std::string format_value(API::TypeDefinition* td, const void* p) {
    char buf[96];
    const auto& n = name_of(td);
    if (n == "System.Single") sprintf_s(buf, "%g", *(const float*)p);
    else if (n == "System.Double") sprintf_s(buf, "%g", *(const double*)p);
    else if (n == "System.Boolean") sprintf_s(buf, "%s", *(const bool*)p ? "true" : "false");
    else if (n == "System.Int32" || td->is_enum()) sprintf_s(buf, "%d", *(const int32_t*)p);
    else if (n == "System.UInt32") sprintf_s(buf, "%u", *(const uint32_t*)p);
    else if (n == "via.vec3" || n == "via.Float3") sprintf_s(buf, "(%g, %g, %g)", ((const float*)p)[0], ((const float*)p)[1], ((const float*)p)[2]);
    else if (n == "via.vec4" || n == "via.Float4" || n == "via.Quaternion") sprintf_s(buf, "(%g, %g, %g, %g)", ((const float*)p)[0], ((const float*)p)[1], ((const float*)p)[2], ((const float*)p)[3]);
    else if (n == "via.Color") sprintf_s(buf, "#%08X", *(const uint32_t*)p);
    else return "<" + n + ">";
    return buf;
}

// ---- Managed value fields written through property setters ----
// Many components' setters do more than store the field and push the value to the engine (e.g. app.MeshSetting.set_ColorParam stores _ColorParam,
// sets _EditMaterialFlag and calls updateMaterial_ColorParam to write the mesh material); writing only the field has no effect.
// When the file changed a value field and the type has a same-named property setter (_Foo / <Foo>k__BackingField / Foo -> set_Foo, parameter type matching the field), call the setter
struct FieldSetter {
    API::Method* set{};
    bool slot{};   // Primitive types/enums go into an 8-byte argument slot
    bool single{}; // System.Single is a double in the argument slot
    std::string name;
};

std::string property_name(std::string f) {
    if (f.size() > 2 && f[0] == '<') {
        const auto end = f.find(">k__BackingField");
        return end == std::string::npos ? std::string{} : f.substr(1, end - 1);
    }
    if (!f.empty() && f[0] == '_') f.erase(0, 1);
    return f;
}

const FieldSetter* setter_for(API::TypeDefinition* td, uint32_t offset, API::TypeDefinition* field_type) {
    static std::unordered_map<API::TypeDefinition*, std::unordered_map<uint32_t, FieldSetter>> cache{};
    auto it = cache.find(td);
    if (it == cache.end()) {
        std::unordered_map<uint32_t, FieldSetter> m{};
        for (auto t = td; t != nullptr; t = t->get_parent_type()) {
            // REFramework reports wrong field offsets for generic types (8 short), so they are not matched
            if (name_of(t).find('`') != std::string::npos) continue;
            for (const auto f : t->get_fields()) {
                if (f == nullptr || f->is_static()) continue;
                const auto off = f->get_offset_from_fieldptr();
                if (m.contains(off)) continue;
                const auto ft = f->get_type();
                const auto prop = property_name(f->get_name());
                if (ft == nullptr || prop.empty()) continue;
                const auto setter_name = "set_" + prop;
                API::Method* found = nullptr;
                for (auto u = td; u != nullptr && found == nullptr; u = u->get_parent_type()) {
                    for (const auto mt : u->get_methods()) {
                        if (mt == nullptr || mt->is_static() || mt->get_num_params() != 1 || setter_name != mt->get_name()) continue;
                        const auto params = mt->get_params();
                        if (params.size() == 1 && (API::TypeDefinition*)params[0].t == ft) found = mt;
                        break;
                    }
                }
                if (found == nullptr) continue;
                FieldSetter fs{};
                fs.set = found;
                fs.slot = (ft->is_primitive() || ft->is_enum()) && ft->get_valuetype_size() <= 8;
                fs.single = name_of(ft) == "System.Single";
                fs.name = setter_name;
                m.emplace(off, std::move(fs));
            }
        }
        it = cache.emplace(td, std::move(m)).first;
    }
    const auto f = it->second.find(offset);
    if (f == it->second.end()) return nullptr;
    const auto& params = f->second.set->get_params();
    return params.size() == 1 && (API::TypeDefinition*)params[0].t == field_type ? &f->second : nullptr;
}

// Call the setter to write value; returns whether the setter wrote the field as value
bool write_by_setter(const FieldSetter& fs, uintptr_t obj, uintptr_t field, const void* value, size_t size) {
    alignas(16) std::array<uint8_t, 128> buf{};
    if (size > buf.size()) return false;
    memcpy(buf.data(), value, size);
    void* arg[1]{};
    if (fs.slot) {
        if (fs.single) {
            const double d = *(const float*)value;
            memcpy(&arg[0], &d, 8);
        } else {
            memcpy(&arg[0], value, size);
        }
    } else {
        arg[0] = buf.data();
    }
    reframework::InvokeRet out{};
    if (!safe_invoke(fs.set, obj, arg, sizeof(arg), &out)) return false;
    return memcmp((const void*)field, value, size) == 0;
}

// Bytes actually occupied by fields in a value type: alignment padding is ignored when comparing (padding bytes in deserialized copies are undefined, e.g. the 4th float of via.vec3)
void mark_fields(API::TypeDefinition* vt, uint32_t base, std::vector<uint8_t>& mask, int depth) {
    if (vt == nullptr || depth > 8) return;
    for (const auto f : vt->get_fields()) {
        if (f == nullptr || f->is_static()) continue;
        const auto ft = f->get_type();
        const auto off = base + f->get_offset_from_fieldptr();
        if (ft != nullptr && ft->is_valuetype() && !ft->is_primitive() && !ft->is_enum()) {
            mark_fields(ft, off, mask, depth + 1);
            continue;
        }
        const uint32_t size = ft == nullptr ? 0 : (ft->is_valuetype() ? ft->get_valuetype_size() : 8);
        for (uint32_t k = 0; k < size && off + k < mask.size(); ++k) mask[off + k] = 1;
    }
}

std::vector<uint8_t> significant_mask(API::TypeDefinition* vt, uint32_t size) {
    if (vt == nullptr || !vt->is_valuetype() || vt->is_primitive() || vt->is_enum() || size == 0) return {};
    std::vector<uint8_t> mask(size, 0);
    mark_fields(vt, 0, mask, 0);
    if (std::find(mask.begin(), mask.end(), 0) == mask.end() || std::find(mask.begin(), mask.end(), 1) == mask.end()) return {};
    return mask;
}

// Value types containing references (e.g. app.user_data.SetMissionBeaconPosList.MissionBeaconPos containing a STAGE_Serializable object,
// ValueTuple<enum, List<…>>): offsets of reference fields inside the struct (including nested structs). These fields cannot be compared or copied byte by byte —
// the two copies hold different object addresses, and copying directly would put a copy object's address into game data (dangling once the copy is released)
void collect_struct_refs(API::TypeDefinition* vt, uint32_t base, std::vector<uint32_t>& out, int depth) {
    if (vt == nullptr || depth > 8) return;
    for (const auto f : vt->get_fields()) {
        if (f == nullptr || f->is_static()) continue;
        const auto ft = f->get_type();
        if (ft == nullptr) continue;
        const auto off = base + f->get_offset_from_fieldptr();
        if (!ft->is_valuetype()) {
            out.push_back(off);
        } else if (!ft->is_primitive() && !ft->is_enum()) {
            collect_struct_refs(ft, off, out, depth + 1);
        }
    }
}

const std::vector<uint32_t>& struct_refs(API::TypeDefinition* vt) {
    static std::mutex mutex{};
    static std::unordered_map<API::TypeDefinition*, std::vector<uint32_t>> cache{};
    std::lock_guard lock{mutex};
    auto it = cache.find(vt);
    if (it == cache.end()) {
        std::vector<uint32_t> refs{};
        if (vt != nullptr && vt->is_valuetype() && !vt->is_primitive() && !vt->is_enum()) collect_struct_refs(vt, 0, refs, 0);
        it = cache.emplace(vt, std::move(refs)).first;
    }
    return it->second;
}

// A single element (p.size bytes) compared field by field
bool same_bytes(const std::vector<uint8_t>& mask, const uint8_t* a, const uint8_t* b, uint32_t size) {
    if (mask.size() != size) return memcmp(a, b, size) == 0;
    for (uint32_t k = 0; k < size; ++k) {
        if (mask[k] && a[k] != b[k]) return false;
    }
    return true;
}

// Field masks cached by type and size (for value comparisons of managed fields/array elements)
const std::vector<uint8_t>& value_mask(API::TypeDefinition* vt, uint32_t size) {
    static std::mutex mutex{};
    static std::map<std::pair<API::TypeDefinition*, uint32_t>, std::vector<uint8_t>> cache{};
    std::lock_guard lock{mutex};
    const auto key = std::make_pair(vt, size);
    auto it = cache.find(key);
    if (it == cache.end()) it = cache.emplace(key, significant_mask(vt, size)).first;
    return it->second;
}

bool same_value_bytes(API::TypeDefinition* vt, uintptr_t a, uintptr_t b, uint32_t size) {
    return size == 0 || same_bytes(value_mask(vt, size), (const uint8_t*)a, (const uint8_t*)b, size);
}

// Value types containing references: mask of meaningful bytes excluding reference fields
const std::vector<uint8_t>& value_mask_noref(API::TypeDefinition* vt, uint32_t size) {
    static std::mutex mutex{};
    static std::map<std::pair<API::TypeDefinition*, uint32_t>, std::vector<uint8_t>> cache{};
    std::lock_guard lock{mutex};
    const auto key = std::make_pair(vt, size);
    auto it = cache.find(key);
    if (it == cache.end()) {
        std::vector<uint8_t> mask(size, 0);
        mark_fields(vt, 0, mask, 0);
        for (const auto off : struct_refs(vt)) {
            for (uint32_t k = 0; k < 8 && off + k < size; ++k) mask[off + k] = 0;
        }
        it = cache.emplace(key, std::move(mask)).first;
    }
    return it->second;
}

// The part of a managed type read by native code: the nearest native ancestor type (null if it has no comparable properties). Implemented after props_of
API::TypeDefinition* native_part_type(API::TypeDefinition* t);

// ---- Resource references (via.ResourceHolder and derived): no serialized fields, compared by resource path ----
bool is_resource_holder(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, bool> cache{};
    if (td == nullptr) return false;
    if (const auto it = cache.find(td); it != cache.end()) return it->second;
    return cache[td] = is_a(td, "via.ResourceHolder");
}

// Resource path of the holder (lowercase); empty string if the holder is null or has no resource. Returns false if it cannot be read
bool holder_path(uintptr_t holder, std::wstring& out) {
    out.clear();
    if (holder == 0) return true;
    static const auto get_path = API::get()->tdb()->find_method("via.ResourceHolder", "get_ResourcePath");
    reframework::InvokeRet r{};
    if (get_path == nullptr || !safe_invoke(get_path, holder, nullptr, 0, &r) || r.exception_thrown) return false;
    if (r.ptr != nullptr) out = read_string((uintptr_t)r.ptr);
    for (auto& ch : out) ch = (wchar_t)towlower(ch);
    return true;
}

// Resource path of the holder (original case). Use it when loading a resource by path: resource cache keys are case-sensitive, and loading with a lowercase path creates a second resource for the same file
bool holder_path_raw(uintptr_t holder, std::wstring& out) {
    out.clear();
    if (holder == 0) return true;
    static const auto get_path = API::get()->tdb()->find_method("via.ResourceHolder", "get_ResourcePath");
    reframework::InvokeRet r{};
    if (get_path == nullptr || !safe_invoke(get_path, holder, nullptr, 0, &r) || r.exception_thrown) return false;
    if (r.ptr != nullptr) out = read_string((uintptr_t)r.ptr);
    return true;
}

bool same_holder_path(uintptr_t a, uintptr_t b) {
    std::wstring pa{}, pb{};
    return holder_path(a, pa) && holder_path(b, pb) && pa == pb;
}

// ---- via.Prefab (native object with get_Path but no set_Path): compared by path; when the path changed, the engine's duplicate() makes a copy from the new copy and swaps it in ----
bool is_prefab(API::TypeDefinition* td) {
    return td != nullptr && name_of(td) == "via.Prefab";
}

bool prefab_path(uintptr_t prefab, std::wstring& out) {
    out.clear();
    if (prefab == 0) return true;
    static const auto get_path = API::get()->tdb()->find_method("via.Prefab", "get_Path");
    reframework::InvokeRet r{};
    if (get_path == nullptr || !safe_invoke(get_path, prefab, nullptr, 0, &r) || r.exception_thrown) return false;
    if (r.ptr != nullptr) out = read_string((uintptr_t)r.ptr);
    for (auto& ch : out) ch = (wchar_t)towlower(ch);
    return true;
}

uintptr_t duplicate_prefab(uintptr_t prefab) {
    if (prefab == 0) return 0;
    static const auto dup = API::get()->tdb()->find_method("via.Prefab", "duplicate");
    reframework::InvokeRet r{};
    if (dup == nullptr || !safe_invoke(dup, prefab, nullptr, 0, &r) || r.exception_thrown) return 0;
    return (uintptr_t)r.ptr;
}

// Get the resource by path and create a holder of type holder_td (the holder holds the resource reference itself). The resource type is the holder type name without Holder
uintptr_t make_holder(API::TypeDefinition* holder_td, const std::wstring& path) {
    if (holder_td == nullptr || path.empty()) return 0;
    const auto& name = name_of(holder_td);
    if (!name.ends_with("Holder")) return 0;
    const auto& api = API::get();
    const auto res = (uintptr_t)api->sdk()->resource_manager->create_resource((REFrameworkResourceManagerHandle)api->resource_manager(),
                                                                             name.substr(0, name.size() - 6).c_str(), narrow(path).c_str());
    if (res == 0) return 0;
    const auto holder = (uintptr_t)api->sdk()->resource->create_holder((REFrameworkResourceHandle)res, name.c_str());
    api->sdk()->resource->release((REFrameworkResourceHandle)res);
    return holder;
}

// Resource references in managed fields: while the new resource is not fully loaded (mdf2 with referenced textures/mmtr) do not write yet; write once loading completes (PrefabLive::update).
// Meanwhile the field still points to the old resource, so game code never gets a half-loaded resource (same as pfb resource properties: a mesh given an unready mdf2 never builds materials)
bool holder_ready(uintptr_t holder); // Implemented after text_arg
struct PendingRefWrite {
    uintptr_t owner{}, header{}; // Object owning the field (given up once the object is reclaimed or reused)
    uintptr_t slot{};            // Field address (reference slot)
    uintptr_t expect{};          // Value in the slot when deferred: written later only if it is still this (given up if the game or a later save changed it)
    uintptr_t holder{};          // Reference slot mode: new holder (one reference held)
    uintptr_t target{};          // In-place mode (.user already has a holder of the same type): the holder whose resource is swapped; 0 for reference slot mode
    uintptr_t res{};             // In-place mode: new resource (one reference held)
    uint32_t frames{};
    std::string label;
};
std::vector<PendingRefWrite> g_pending_refs{};
// Old resource swapped out by the deferred write: released after 120 frames (same as hot reload's deferred release)
std::vector<std::pair<uintptr_t, uint32_t>> g_late_release{};

// Swap the resource of a holder in place (the holder object stays the same, so code holding it sees the new resource directly): get the resource by path and CAS it into holder +0x10;
// the old resource reference the holder held is transferred to g_replaced_resources and released later by the caller
std::vector<uintptr_t>& replaced_resources();
// owner: object containing the holder (when non-zero and the resource is not fully loaded, defer to g_pending_refs and swap once loading completes)
bool set_holder_resource(uintptr_t holder, API::TypeDefinition* holder_td, const std::wstring& path, uintptr_t owner = 0) {
    constexpr uintptr_t HOLDER_RESOURCE = 0x10;
    if (holder == 0 || holder_td == nullptr || path.empty()) return false;
    const auto& name = name_of(holder_td);
    if (!name.ends_with("Holder")) return false;
    const auto& api = API::get();
    const auto res = (uintptr_t)api->sdk()->resource_manager->create_resource((REFrameworkResourceManagerHandle)api->resource_manager(),
                                                                             name.substr(0, name.size() - 6).c_str(), narrow(path).c_str());
    if (res == 0) return false;
    uintptr_t old = 0;
    if (owner != 0 && !resource_fully_ready(res)) {
        // Resource not fully loaded: swap once loading completes (holder and resource each hold one reference)
        uintptr_t header = 0;
        safe_read_ptr(owner, header);
        safe_read_ptr(holder + HOLDER_RESOURCE, old);
        add_ref(holder);
        g_pending_refs.push_back({owner, header, holder + HOLDER_RESOURCE, old, 0, holder, res, 0, narrow(path)});
        return true;
    }
    if (!safe_read_ptr(holder + HOLDER_RESOURCE, old) ||
        (uintptr_t)InterlockedCompareExchange64((volatile LONG64*)(holder + HOLDER_RESOURCE), (LONG64)res, (LONG64)old) != old) {
        api->sdk()->resource->release((REFrameworkResourceHandle)res);
        return false;
    }
    if (old != 0) replaced_resources().push_back(old);
    return true;
}

// True while writing .user: replaced old objects (arrays, data objects, holders, etc.) are not released, and the plugin's references are kept until the game exits.
// Game or engine code may remember old object addresses without counting references; releasing immediately would make it access freed memory, while keeping them at worst keeps reading old data
bool g_keep_replaced = false;
std::vector<uintptr_t> g_kept_replaced{};
// Old objects swapped out in this pass -> new objects swapped in (the old object's reference is transferred to the pair): after the write, scan memory in the background and repoint other references from the old object to the new one
std::vector<std::pair<uintptr_t, uintptr_t>> g_replaced_pairs{};
// Old resources swapped out of holders changed in place (one reference held each; released later by the caller)
std::vector<uintptr_t> g_replaced_resources{};
std::vector<uintptr_t>& replaced_resources() {
    return g_replaced_resources;
}


class Differ {
public:
    Differ(bool verbose, const SceneMap* scene) : m_verbose(verbose), m_scene(scene) {}

    // Parts read by native code in data objects reachable through serialized reference fields: the native ancestor part of managed data objects (e.g. ExternParameter.Value of EffectCustomExternParameter)
    // and native data objects (e.g. via.Prefab, via.AnimationCurve). These are not in the managed serialized field sequence, and diff_object does not handle them.
    // o/o2 are two copies of the old data, n/n2 two copies of the new data, l the scene instance; matched by the same field path, collected only when types and array element counts agree
    struct NativePart {
        uintptr_t o, o2, n, n2, l;
        API::TypeDefinition* td; // Compare as this type (the native ancestor or the native type itself)
        std::string path;
    };
    void native_parts(uintptr_t o, uintptr_t o2, uintptr_t n, uintptr_t n2, uintptr_t l, API::TypeDefinition* td, const std::string& path, int depth,
                      std::vector<NativePart>& out) {
        if (o == 0 || n == 0 || l == 0 || td == nullptr || depth > MAX_DEPTH || !m_parts_seen.insert(l).second) return;
        const auto seq = sequence_of(td);
        const auto base = fieldptr_base(td);
        if (base == 0) return;
        auto visit = [&](uintptr_t po, uintptr_t po2, uintptr_t pn, uintptr_t pn2, uintptr_t pl, const std::string& p) {
            if (po == 0 || pn == 0 || pl == 0) return;
            const auto t = type_of(pn);
            if (t == nullptr || type_of(po) != t || type_of(pl) != t) return;
            if (is_userdata(t) || is_scene_object(t) || is_string_type(t) || is_resource_holder(t) || is_prefab(t)) return;
            if (po2 != 0 && type_of(po2) != t) po2 = 0;
            if (pn2 != 0 && type_of(pn2) != t) pn2 = 0;
            if (fieldptr_base(t) == 0) {
                if (m_parts_seen.insert(pl).second) out.push_back({po, po2, pn, pn2, pl, t, p});
                return;
            }
            if (const auto na = native_part_type(t); na != nullptr && !m_parts_seen.contains(pl)) out.push_back({po, po2, pn, pn2, pl, na, p});
            native_parts(po, po2, pn, pn2, pl, t, p, depth + 1, out);
        };
        auto rd = [](uintptr_t obj, uintptr_t off) -> uintptr_t { return obj != 0 ? *(uintptr_t*)(obj + off) : 0; };
        for (const auto& e : *seq) {
            const auto off = base + e.offset;
            const auto fp = path + "+0x" + to_hex(e.offset);
            if (e.is_array) {
                const auto& ei = elem_of(e);
                if (!ei.by_ref || ei.stride == 0) continue;
                View vo{}, vo2{}, vn{}, vn2{}, vl{};
                if (!view_of(rd(o, off), vo) || !view_of(rd(n, off), vn) || !view_of(rd(l, off), vl)) continue;
                if (vo.count != vn.count || vl.count != vn.count || vn.count == 0) continue;
                const bool has_o2 = o2 != 0 && view_of(rd(o2, off), vo2) && vo2.count == vo.count;
                const bool has_n2 = n2 != 0 && view_of(rd(n2, off), vn2) && vn2.count == vn.count;
                for (uint32_t i = 0; i < vn.count; ++i) {
                    const auto eo = (uintptr_t)ei.stride * i;
                    visit(*(uintptr_t*)(vo.elements + eo), has_o2 ? *(uintptr_t*)(vo2.elements + eo) : 0, *(uintptr_t*)(vn.elements + eo),
                          has_n2 ? *(uintptr_t*)(vn2.elements + eo) : 0, *(uintptr_t*)(vl.elements + eo), fp + "[" + std::to_string(i) + "]");
                }
            } else if (is_ref(e)) {
                visit(rd(o, off), rd(o2, off), rd(n, off), rd(n2, off), rd(l, off), fp);
            }
        }
    }
    // Objects newly created in diff_object (native part not read from the file)
    const std::unordered_set<uintptr_t>& created() const { return m_created; }

    uint32_t fields_changed() const { return m_fields; }
    bool structure_changed() const { return m_structure_changed; }
    // Writes that replaced the object itself (container element count changed, referenced object created/nulled/swapped for another .user or resource)
    uint32_t objects_replaced() const { return m_replaced; }
    // Number of times the element count changed / a List object had its content replaced in place

    // .user check: change every serialized value field in copy obj (and its data sub-objects) to a different value, replace strings with new content,
    // change value-type container elements one by one, and add an element to containers with 0 elements. Shared objects (other .user files, scene objects) and resource holders are left alone.
    // Native data objects (no managed field area) are recorded in natives and not changed. Returns the number of items changed
    uint32_t mutate_for_check(uintptr_t obj, API::TypeDefinition* td, int depth, std::unordered_set<uintptr_t>& visited,
                              std::unordered_set<std::string>& natives) {
        if (obj == 0 || td == nullptr || depth > MAX_DEPTH || !visited.insert(obj).second) return 0;
        const auto seq = sequence_of(td);
        const auto base = fieldptr_base(td);
        if (base == 0) return 0;
        uint32_t n = 0;
        std::function<void(uintptr_t)> visit{};
        auto flip = [&](uintptr_t p, API::TypeDefinition* vt, uint32_t size) {
            if (size == 0 || vt == nullptr) return;
            // Pointer types are not changed; for structs containing references only the value bytes are changed and reference fields are handled as references: a corrupted pointer is dereferenced by the engine when the copy is released
            // (crashed twice at exe+a49cf94 frame cleanup on 2026-11-05)
            const auto& vn = name_of(vt);
            if (vn == "System.IntPtr" || vn == "System.UIntPtr") return;
            if (has_refs(vt)) {
                const auto& mask = value_mask_noref(vt, size);
                for (uint32_t k = 0; k < size && k < mask.size(); ++k) {
                    if (!mask[k]) continue;
                    *(uint8_t*)(p + k) ^= 1;
                    ++n;
                    break;
                }
                for (const auto off : struct_refs(vt)) {
                    if (off + 8 <= size) visit(p + off);
                }
                return;
            }
            if (vn == "System.Boolean") {
                *(uint8_t*)p = *(uint8_t*)p ? 0 : 1;
            } else {
                *(uint8_t*)p ^= 1;
            }
            ++n;
        };
        visit = [&](uintptr_t slot) {
            const auto v = *(uintptr_t*)slot;
            const auto t = type_of(v);
            if (t == nullptr || is_userdata(t) || is_scene_object(t) || is_resource_holder(t)) return;
            if (is_string_type(t)) {
                const auto s = new_string(read_string(v) + L"_");
                if (s != 0) {
                    assign_ref(slot, s);
                    ++n;
                }
                return;
            }
            if (fieldptr_base(t) == 0) {
                // No managed field area: record true native types (e.g. via.Prefab, via.AnimationCurve); empty managed classes without fields can be ignored
                if (native_type(t)) natives.insert(name_of(t));
                return;
            }
            n += mutate_for_check(v, t, depth + 1, visited, natives);
        };
        for (const auto& e : *seq) {
            const auto off = base + e.offset;
            if (e.is_array) {
                const auto& ei = elem_of(e);
                View v{};
                if (ei.stride == 0 || !view_of(*(uintptr_t*)(obj + off), v)) continue;
                // List<T>: drop the last element (_size minus one) to check the in-place List update path when the element count changes
                if (const auto list = *(uintptr_t*)(obj + off); list != 0 && v.count > 0 && !name_of(type_of(list)).ends_with("[]")) {
                    const auto lt = type_of(list);
                    if (auto size_f = lt->find_field("_size"); size_f != nullptr) {
                        --*(int32_t*)(list + size_f->get_offset_from_base());
                        --v.count;
                        ++n;
                    }
                }
                if (v.count == 0 && !ei.by_ref && ei.td != nullptr) {
                    // Empty value-type array: replace it with a new 1-element array (to check writes when the element count changes)
                    const auto arr = (uintptr_t)API::get()->sdk()->functions->create_managed_array((REFrameworkTypeDefinitionHandle)ei.td, 1);
                    const auto cur = *(uintptr_t*)(obj + off);
                    if (arr != 0 && (cur == 0 || name_of(type_of(cur)).ends_with("[]"))) {
                        assign_ref(obj + off, arr);
                        ++n;
                    }
                    continue;
                }
                for (uint32_t i = 0; i < v.count; ++i) {
                    const auto ep = v.elements + (uintptr_t)ei.stride * i;
                    if (ei.by_ref) {
                        visit(ep);
                    } else {
                        flip(ep, ei.td, ei.stride);
                    }
                }
            } else if (is_ref(e)) {
                visit(obj + off);
            } else {
                flip(obj + off, e.type, value_size(e));
            }
        }
        return n;
    }

    // Compare the RSZ-serialized fields of o (old copy) and n (new copy) and write the differences into l (scene instance)
    void diff_object(uintptr_t o, uintptr_t n, uintptr_t l, API::TypeDefinition* td, const std::string& path, int depth) {
        if (o == 0 || n == 0 || l == 0 || td == nullptr || depth > MAX_DEPTH) return;
        if (!m_visited.insert(l).second) return;

        const auto seq = sequence_of(td);
        const auto base = fieldptr_base(td);
        if (seq->empty() || base == 0) return;
        if (m_verbose && depth == 0) {
            log("    [%s] %zu serialized fields, fields start at 0x%llx", name_of(td).c_str(), seq->size(), (unsigned long long)base);
        }

        // Recorded when entering an effect data element (via.effect.ProviderData); if a field changes, the element is marked as changed
        const auto prev_provider = m_current_provider;
        if (is_a(td, "via.effect.ProviderData")) m_current_provider = l;

        for (const auto& e : *seq) {
            const auto off = base + e.offset;
            const auto field_path = path + "+0x" + to_hex(e.offset) + "(" + (e.type ? name_of(e.type) : "?") + ")";
            if (e.is_array) {
                diff_container(o + off, n + off, l + off, e, field_path, depth);
            } else {
                diff_value(o + off, n + off, l + off, e, field_path, depth, l, td);
            }
        }
        m_current_provider = prev_provider;
    }

    // Newly created component: write every serialized field of the new copy n into the scene instance l
    void copy_all(uintptr_t n, uintptr_t l, API::TypeDefinition* td, const std::string& path) {
        if (n == 0 || l == 0 || td == nullptr || fieldptr_base(td) == 0) return;
        const auto prev_provider = m_current_provider;
        if (is_a(td, "via.effect.ProviderData")) m_current_provider = l;
        fill(n, l, td, 0);
        mark_changed();
        log("    %s: new component, all parameters in the file written", path.c_str());
        m_current_provider = prev_provider;
    }

    // Effect data elements (in scene instances) with changed fields
    const std::unordered_set<uintptr_t>& changed_providers() const { return m_changed_providers; }

    // Before attaching: replace references to scene objects (GameObjects/components) in object obj of the clean copy (and its data sub-objects) with the corresponding objects of the scene instance (m_scene)
    void remap_scene_refs(uintptr_t obj, API::TypeDefinition* td, const std::string& path, int depth = 0) {
        if (obj == 0 || td == nullptr || depth > MAX_DEPTH || !m_visited.insert(obj).second) return;
        const auto seq = sequence_of(td);
        const auto base = fieldptr_base(td);
        if (base == 0) return;
        auto fix = [&](uintptr_t slot) {
            const auto v = *(uintptr_t*)slot;
            const auto t = type_of(v);
            if (t == nullptr || is_string_type(t) || is_userdata(t)) return;
            if (!is_scene_object(t)) {
                remap_scene_refs(v, t, path, depth + 1);
                return;
            }
            const auto target = map_scene(v);
            if (target == v) return;
            assign_ref(slot, target);
            if (target == 0) log("    %s: referenced scene object %s not found in the instance, set to null", path.c_str(), name_of(t).c_str());
        };
        for (const auto& e : *seq) {
            const auto off = base + e.offset;
            if (e.is_array) {
                const auto& ei = elem_of(e);
                View v{};
                if (!ei.by_ref || ei.stride == 0 || !view_of(*(uintptr_t*)(obj + off), v)) continue;
                for (uint32_t i = 0; i < v.count; ++i) fix(v.elements + (uintptr_t)ei.stride * i);
            } else if (is_ref(e)) {
                fix(obj + off);
            }
        }
    }

    // After writing, map data objects referenced by the new copy n to the objects of the same type at the same field position in the scene instance l (also recording the old copy o's object when it is of the same type at the same position).
    // Objects in the scene instance newly created this time (clone) are marked as new. Used for GameObjectRef table entries whose holder is a data object
    void correspond(uintptr_t o, uintptr_t n, uintptr_t l, API::TypeDefinition* td, CorrMap& out, int depth = 0) {
        if (n == 0 || l == 0 || td == nullptr || depth > MAX_DEPTH) return;
        if (o != 0 && type_of(o) != td) o = 0;
        if (depth > 0) {
            if (out.contains(n)) return;
            out[n] = {o, l, m_created.contains(l)};
        }
        const auto seq = sequence_of(td);
        const auto base = fieldptr_base(td);
        if (base == 0) return;
        auto child = [&](uintptr_t po, uintptr_t pn, uintptr_t pl) {
            const auto tn = type_of(pn);
            if (tn == nullptr || type_of(pl) != tn || is_scene_object(tn) || is_string_type(tn) || is_userdata(tn) || fieldptr_base(tn) == 0) return;
            correspond(po, pn, pl, tn, out, depth + 1);
        };
        for (const auto& e : *seq) {
            const auto off = base + e.offset;
            if (e.is_array) {
                const auto& ei = elem_of(e);
                if (!ei.by_ref || ei.stride == 0) continue;
                View vo{}, vn{}, vl{};
                if (!view_of(*(uintptr_t*)(n + off), vn) || !view_of(*(uintptr_t*)(l + off), vl)) continue;
                if (o == 0 || !view_of(*(uintptr_t*)(o + off), vo)) vo = {};
                for (uint32_t i = 0; i < vn.count && i < vl.count; ++i) {
                    const auto eo = (uintptr_t)ei.stride * i;
                    child(i < vo.count ? *(uintptr_t*)(vo.elements + eo) : 0, *(uintptr_t*)(vn.elements + eo), *(uintptr_t*)(vl.elements + eo));
                }
            } else if (is_ref(e)) {
                child(o ? *(uintptr_t*)(o + off) : 0, *(uintptr_t*)(n + off), *(uintptr_t*)(l + off));
            }
        }
    }

private:
    static std::string to_hex(uint32_t v) {
        char buf[16];
        sprintf_s(buf, "%x", v);
        return buf;
    }

    void record(const std::string& path, API::TypeDefinition* td, const void* old_v, const void* new_v) {
        mark_changed();
        if (td != nullptr && old_v != nullptr) {
            log("    %s: %s -> %s", path.c_str(), format_value(td, old_v).c_str(), format_value(td, new_v).c_str());
        } else {
            log("    %s: updated", path.c_str());
        }
    }

    void mark_changed() {
        ++m_fields;
        if (m_current_provider != 0) m_changed_providers.insert(m_current_provider);
    }

    // Old values that were replaced: usually released immediately; under g_keep_replaced they are handed to the plugin (those with a new value are recorded as old -> new so other references can be repointed later; nulled ones are only kept)
    static void drop(uintptr_t old, uintptr_t now) {
        if (old == 0) return;
        if (!g_keep_replaced) {
            release(old);
        } else if (now != 0) {
            g_replaced_pairs.emplace_back(old, now);
        } else {
            g_kept_replaced.push_back(old);
        }
    }

    // Write into a reference slot of object holder: written directly when holder is a newly created object, otherwise add a reference to the new value and release the old one
    static void store(uintptr_t holder, uintptr_t slot, uintptr_t value) {
        const auto cur = *(uintptr_t*)slot;
        if (cur == value) return;
        if (is_newborn(holder)) {
            *(uintptr_t*)slot = value;
            return;
        }
        add_ref(value);
        *(uintptr_t*)slot = value;
        drop(cur, value);
    }

    // Reference slot of a scene instance (registered object)
    static void assign_ref(uintptr_t slot, uintptr_t value) {
        const auto cur = *(uintptr_t*)slot;
        if (cur == value) return;
        add_ref(value);
        *(uintptr_t*)slot = value;
        drop(cur, value);
    }

    bool is_ref(const SeqEntry& e) const {
        return e.code == SEQ_CODE_OBJECT || e.code == SEQ_CODE_STRING || (e.type != nullptr && !e.type->is_valuetype());
    }

    uint32_t value_size(const SeqEntry& e) const {
        return e.size ? e.size : (e.type ? e.type->get_valuetype_size() : 0);
    }

    // For array fields the sequence entry's type is the container type (T[] or List<T>); the element type is derived from the type name
    struct ElemInfo {
        API::TypeDefinition* td{};
        bool by_ref{};
        uint32_t stride{};
    };

    const ElemInfo& elem_of(const SeqEntry& e) {
        static std::unordered_map<API::TypeDefinition*, ElemInfo> cache{};
        if (const auto it = cache.find(e.type); it != cache.end()) return it->second;
        auto& info = cache[e.type];
        if (e.type == nullptr) return info;
        const auto& name = name_of(e.type);
        std::string elem{};
        if (name.ends_with("[]")) {
            elem = name.substr(0, name.size() - 2);
        } else if (const auto lt = name.find('<'), gt = name.rfind('>'); lt != std::string::npos && gt != std::string::npos && gt > lt) {
            elem = name.substr(lt + 1, gt - lt - 1);
        }
        info.td = elem.empty() ? nullptr : API::get()->tdb()->find_type(elem);
        info.by_ref = e.code == SEQ_CODE_OBJECT || e.code == SEQ_CODE_STRING || info.td == nullptr || !info.td->is_valuetype();
        info.stride = info.by_ref ? 8 : (info.td->get_valuetype_size() ? info.td->get_valuetype_size() : e.size);
        return info;
    }

    bool equal_elem(uintptr_t sa, uintptr_t sb, const ElemInfo& ei, int depth) {
        if (ei.by_ref) return equal_ref(*(uintptr_t*)sa, *(uintptr_t*)sb, depth);
        return equal_value(ei.td, sa, sb, ei.stride, depth);
    }

    // ---- Value types containing references (structs with object references): value bytes handled by mask, reference fields handled as references ----
    static bool has_refs(API::TypeDefinition* vt) {
        return vt != nullptr && vt->is_valuetype() && !vt->is_primitive() && !vt->is_enum() && !struct_refs(vt).empty();
    }

    bool equal_value(API::TypeDefinition* vt, uintptr_t a, uintptr_t b, uint32_t size, int depth) {
        if (!has_refs(vt)) return same_value_bytes(vt, a, b, size);
        if (!same_bytes(value_mask_noref(vt, size), (const uint8_t*)a, (const uint8_t*)b, size)) return false;
        for (const auto off : struct_refs(vt)) {
            if (off + 8 <= size && !equal_ref(*(uintptr_t*)(a + off), *(uintptr_t*)(b + off), depth + 1)) return false;
        }
        return true;
    }

    // Write struct src to dst (holder is the object or array containing dst): value bytes copied by mask; reference fields newly created from the copy when clone_refs, otherwise src's objects are reused
    void copy_struct(API::TypeDefinition* vt, uintptr_t src, uintptr_t dst, uint32_t size, uintptr_t holder, int depth, bool clone_refs) {
        const auto& mask = value_mask_noref(vt, size);
        for (uint32_t k = 0; k < size && k < mask.size(); ++k) {
            if (mask[k]) ((uint8_t*)dst)[k] = ((const uint8_t*)src)[k];
        }
        for (const auto off : struct_refs(vt)) {
            if (off + 8 > size) continue;
            const auto v = *(uintptr_t*)(src + off);
            store(holder, dst + off, clone_refs ? clone(v, depth + 1) : v);
        }
    }

    // Existing struct: write only what the file changed (value bytes written as a whole, reference fields compared and written one by one as references)
    void diff_struct(API::TypeDefinition* vt, uintptr_t so, uintptr_t sn, uintptr_t sl, uint32_t size, const std::string& path, int depth) {
        const auto& mask = value_mask_noref(vt, size);
        if (!same_bytes(mask, (const uint8_t*)so, (const uint8_t*)sn, size)) {
            for (uint32_t k = 0; k < size && k < mask.size(); ++k) {
                if (mask[k]) ((uint8_t*)sl)[k] = ((const uint8_t*)sn)[k];
            }
            record(path, nullptr, nullptr, nullptr);
        }
        for (const auto off : struct_refs(vt)) {
            if (off + 8 <= size) diff_ref(so + off, sn + off, sl + off, path + "+0x" + to_hex(off), depth + 1);
        }
    }

    uintptr_t map_scene(uintptr_t copy) const {
        if (copy == 0 || m_scene == nullptr) return 0;
        const auto it = m_scene->find(copy);
        return it == m_scene->end() ? 0 : it->second;
    }

    // ---- Deep comparison (deciding whether the file changed what a reference points to) ----

    bool equal_ref(uintptr_t a, uintptr_t b, int depth) {
        if (a == b) return true;
        if (a == 0 || b == 0 || depth > MAX_DEPTH) return false;
        const auto ta = type_of(a), tb = type_of(b);
        if (ta == nullptr || ta != tb) return false;
        if (is_userdata(ta)) return false; // Shared objects: if not the same object, they are different .user files
        if (is_scene_object(ta)) return map_scene(a) == map_scene(b);
        if (is_string_type(ta)) return read_string(a) == read_string(b);
        if (is_resource_holder(ta)) return same_holder_path(a, b);
        if (is_prefab(ta)) {
            std::wstring pa{}, pb{};
            return prefab_path(a, pa) && prefab_path(b, pb) && pa == pb;
        }
        const auto seq = sequence_of(ta);
        const auto base = fieldptr_base(ta);
        if (base == 0) return false; // Native data objects cannot be compared field by field
        for (const auto& e : *seq) {
            const auto off = base + e.offset;
            if (e.is_array) {
                View va{}, vb{};
                if (!view_of(*(uintptr_t*)(a + off), va) || !view_of(*(uintptr_t*)(b + off), vb) || va.count != vb.count) return false;
                const auto& ei = elem_of(e);
                for (uint32_t i = 0; i < va.count; ++i) {
                    if (!equal_elem(va.elements + (uintptr_t)ei.stride * i, vb.elements + (uintptr_t)ei.stride * i, ei, depth + 1)) return false;
                }
            } else if (!equal_element(a + off, b + off, e, depth + 1)) {
                return false;
            }
        }
        return true;
    }

    bool equal_element(uintptr_t sa, uintptr_t sb, const SeqEntry& e, int depth) {
        if (is_ref(e)) return equal_ref(*(uintptr_t*)sa, *(uintptr_t*)sb, depth);
        return equal_value(e.type, sa, sb, value_size(e), depth);
    }

    // ---- Copying: create new objects from the new copy (never reference objects of the copy directly) ----

    uintptr_t new_string(const std::wstring& text) {
        return (uintptr_t)API::get()->sdk()->functions->create_managed_string(text.c_str());
    }

    // Reference value in the copy -> value that can go into the scene instance: scene objects mapped, strings and data objects newly created
    uintptr_t clone(uintptr_t src, int depth) {
        if (src == 0) return 0;
        if (const auto it = m_clones.find(src); it != m_clones.end()) return it->second;
        const auto td = type_of(src);
        if (td == nullptr) return 0;
        if (is_scene_object(td)) return map_scene(src);
        if (is_userdata(td)) return src; // Shared object, referenced directly (a reference is added when stored)
        if (is_string_type(td)) return new_string(read_string(src));
        if (is_resource_holder(td)) {
            std::wstring path{};
            return holder_path_raw(src, path) ? make_holder(td, path) : 0;
        }
        if (is_prefab(td)) return duplicate_prefab(src);
        if (depth > MAX_DEPTH) return 0;
        if (fieldptr_base(td) == 0) {
            log("      Cannot create native type object %s", name_of(td).c_str());
            return 0;
        }
        const auto obj = (uintptr_t)td->create_instance(0);
        if (obj == 0) {
            log("      Failed to create %s", name_of(td).c_str());
            return 0;
        }
        m_clones[src] = obj;
        m_created.insert(obj);
        fill(src, obj, td, depth + 1);
        return obj;
    }

    // Write every serialized field of src into the same-type object dst
    void fill(uintptr_t src, uintptr_t dst, API::TypeDefinition* td, int depth) {
        const auto seq = sequence_of(td);
        const auto base = fieldptr_base(td);
        if (base == 0) return;
        for (const auto& e : *seq) {
            const auto off = base + e.offset;
            if (e.is_array) {
                store(dst, dst + off, build_container(*(uintptr_t*)(src + off), nullptr, nullptr, e, depth));
            } else if (is_ref(e)) {
                store(dst, dst + off, clone(*(uintptr_t*)(src + off), depth));
            } else if (const auto size = value_size(e)) {
                if (has_refs(e.type)) {
                    copy_struct(e.type, src + off, dst + off, size, dst, depth, true);
                } else {
                    memcpy((void*)(dst + off), (void*)(src + off), size);
                }
            }
        }
    }

    // Container (serialized as an array in RSZ: T[] or List<T>)
    struct View {
        uintptr_t elements{}; // Address of the first element
        uint32_t count{};
    };

    bool view_of(uintptr_t container, View& v) {
        v = {};
        if (container == 0) return true; // A null reference counts as 0 elements
        auto td = type_of(container);
        if (td == nullptr) return false;
        if (name_of(td).ends_with("[]")) {
            v.elements = container + ARRAY_DATA;
            v.count = *(uint32_t*)(container + ARRAY_COUNT);
            return true;
        }
        // List<T>: _items(T[]) + _size
        auto items_f = td->find_field("_items");
        auto size_f = td->find_field("_size");
        if (items_f == nullptr || size_f == nullptr) return false;
        const auto items = *(uintptr_t*)(container + items_f->get_offset_from_base());
        const auto size = *(int32_t*)(container + size_f->get_offset_from_base());
        if (size < 0 || (size > 0 && items == 0)) return false;
        v.count = (uint32_t)size;
        v.elements = items ? items + ARRAY_DATA : 0;
        return true;
    }

    // Build a new container from the new copy's container cn. When vo/vl are given, leading elements that are the same in the old and new copies keep the scene instance's elements.
    // When reuse is an existing List<T> of the same type in the scene instance, no new List is created: the new element array is filled and swapped into its _items and _size (the List object itself is unchanged,
    // so code holding this List sees the new content directly); returns reuse
    uintptr_t build_container(uintptr_t cn, const View* vo, const View* vl, const SeqEntry& e, int depth, uintptr_t reuse = 0) {
        if (cn == 0 || e.type == nullptr) return 0;
        const auto tdc = type_of(cn);
        View vn{};
        const auto& ei = elem_of(e);
        if (tdc == nullptr || ei.td == nullptr || ei.stride == 0 || !view_of(cn, vn)) {
            log("      Cannot determine the element type of container %s", name_of(e.type).c_str());
            return 0;
        }
        const bool by_ref = ei.by_ref;
        const uint32_t stride = ei.stride;
        const bool is_list = !name_of(tdc).ends_with("[]");
        if (reuse != 0 && (!is_list || type_of(reuse) != tdc)) reuse = 0;

        const auto arr = (uintptr_t)API::get()->sdk()->functions->create_managed_array((REFrameworkTypeDefinitionHandle)ei.td, vn.count);
        if (arr == 0) return 0;
        const auto elems = arr + ARRAY_DATA;
        // Fill the new array first, then put it into the container (when modifying a List in place the game never reads a half-filled array)
        auto finish = [&]() -> uintptr_t {
            if (!is_list) return arr;
            auto items_f = tdc->find_field("_items");
            auto size_f = tdc->find_field("_size");
            if (items_f == nullptr || size_f == nullptr) return 0;
            if (reuse != 0) {
                // When other threads read this List at the same time, _size must never exceed the length of _items at any moment: when shrinking change _size first and then swap the array,
                // when growing (or unchanged) swap the array first and then change _size
                const auto size_slot = (volatile int32_t*)(reuse + size_f->get_offset_from_base());
                const auto items_slot = reuse + items_f->get_offset_from_base();
                if ((int64_t)vn.count < (int64_t)*size_slot) {
                    *size_slot = (int32_t)vn.count;
                    std::atomic_signal_fence(std::memory_order_seq_cst); // Keep the compiler from reordering the two writes (on x64 writes are already ordered)
                    assign_ref(items_slot, arr);
                } else {
                    assign_ref(items_slot, arr);
                    std::atomic_signal_fence(std::memory_order_seq_cst);
                    *size_slot = (int32_t)vn.count;
                }
                if (auto version_f = tdc->find_field("_version"); version_f != nullptr) ++*(int32_t*)(reuse + version_f->get_offset_from_base());
                return reuse;
            }
            // List<T>: create a new List of the same type with the new array
            const auto container = (uintptr_t)tdc->create_instance(0);
            if (container == 0) return 0;
            store(container, container + items_f->get_offset_from_base(), arr);
            *(int32_t*)(container + size_f->get_offset_from_base()) = (int32_t)vn.count;
            return container;
        };
        for (uint32_t i = 0; i < vn.count; ++i) {
            const auto off = (uintptr_t)stride * i;
            const bool keep = vo != nullptr && vl != nullptr && i < vo->count && i < vl->count &&
                              equal_elem(vo->elements + off, vn.elements + off, ei, depth + 1);
            if (by_ref) {
                const auto v = keep ? *(uintptr_t*)(vl->elements + off) : clone(*(uintptr_t*)(vn.elements + off), depth + 1);
                store(arr, elems + off, v);
            } else if (has_refs(ei.td)) {
                copy_struct(ei.td, (keep ? vl->elements : vn.elements) + off, elems + off, stride, arr, depth + 1, !keep);
            } else {
                memcpy((void*)(elems + off), (void*)((keep ? vl->elements : vn.elements) + off), stride);
            }
        }
        return finish();
    }

    // ---- Writing differences ----

    // Single value: value types compared by sequence size; references compare content or recurse
    // owner/owner_td: the scene object owning the field and its type (0 when there is no owner, e.g. array elements), used for writing through property setters
    void diff_value(uintptr_t so, uintptr_t sn, uintptr_t sl, const SeqEntry& e, const std::string& path, int depth, uintptr_t owner = 0,
                    API::TypeDefinition* owner_td = nullptr) {
        if (is_ref(e)) {
            diff_ref(so, sn, sl, path, depth, owner);
            return;
        }
        const auto size = value_size(e);
        if (has_refs(e.type)) {
            diff_struct(e.type, so, sn, sl, size, path, depth);
            return;
        }
        if (same_value_bytes(e.type, so, sn, size)) return;
        std::vector<uint8_t> old_v((uint8_t*)sl, (uint8_t*)sl + size);
        const auto fs = owner != 0 && owner_td != nullptr && e.type != nullptr
                            ? setter_for(owner_td, (uint32_t)(sl - owner - fieldptr_base(owner_td)), e.type)
                            : nullptr;
        if (fs != nullptr && write_by_setter(*fs, owner, sl, (const void*)sn, size)) {
            record(path + " (" + fs->name + ")", e.type, old_v.data(), (void*)sn);
            return;
        }
        memcpy((void*)sl, (void*)sn, size);
        record(path, e.type, old_v.data(), (void*)sn);
    }

    // owner: the object owning the field (when non-zero, resource references can be deferred until loaded, see g_pending_refs)
    void diff_ref(uintptr_t so, uintptr_t sn, uintptr_t sl, const std::string& path, int depth, uintptr_t owner = 0) {
        const auto po = *(uintptr_t*)so;
        const auto pn = *(uintptr_t*)sn;
        const auto pl = *(uintptr_t*)sl;
        // The file did not change what it points to: keep the scene instance's current reference
        if (equal_ref(po, pn, depth)) return;

        const auto tn = type_of(pn);
        const auto to = type_of(po);
        if ((tn && is_userdata(tn)) || (to && is_userdata(to))) {
            // The referenced .user changed: switch to the shared object obtained by the new copy (the old .user object's content is not rewritten)
            if (pl == pn) return;
            assign_ref(sl, pn);
            mark_changed();
            ++m_replaced;
            log("    %s: userdata reference %s -> %s", path.c_str(), pl ? name_of(type_of(pl)).c_str() : "null", pn ? name_of(tn).c_str() : "null");
            return;
        }
        if ((tn && is_string_type(tn)) || (to && is_string_type(to))) {
            const auto new_text = read_string(pn);
            const auto str = pn != 0 ? new_string(new_text) : 0;
            if (pn != 0 && str == 0) return;
            const auto old_text = read_string(pl);
            assign_ref(sl, str);
            mark_changed();
            log("    %s: \"%s\" -> \"%s\"", path.c_str(), narrow(old_text).c_str(), narrow(new_text).c_str());
            return;
        }
        if ((tn && is_scene_object(tn)) || (to && is_scene_object(to))) {
            const auto target = map_scene(pn);
            if (pn != 0 && target == 0) {
                log("    %s: referenced scene object not found in the instance, skipped", path.c_str());
                return;
            }
            if (pl == target) return;
            assign_ref(sl, target);
            mark_changed();
            ++m_replaced;
            log("    %s: scene object reference -> %s", path.c_str(), target ? name_of(type_of(target)).c_str() : "null");
            return;
        }
        if (pn == 0) {
            if (pl == 0) return;
            assign_ref(sl, 0);
            mark_changed();
            ++m_replaced;
            log("    %s: reference set to null", path.c_str());
            return;
        }
        if (is_resource_holder(tn)) {
            // Resource reference: get the resource by the new file's path and create a new holder (the same way the game swaps resources)
            std::wstring np{}, lp{}, raw{};
            if (!holder_path(pn, np)) return;
            if (pl != 0 && type_of(pl) == tn && holder_path(pl, lp) && lp == np) return;
            // Load with the original-case path (matching the cache key the game requests, so no second resource is created for the same file)
            if (!holder_path_raw(pn, raw) || raw.empty()) raw = np;
            // .user writes: when a holder of the same type already exists, swap its resource in place; the holder object is unchanged
            const auto pending_before = g_pending_refs.size();
            if (g_keep_replaced && pl != 0 && type_of(pl) == tn && set_holder_resource(pl, tn, raw, owner)) {
                mark_changed();
                log("    %s: resource %s -> %s (in place%s)", path.c_str(), narrow(lp).c_str(), narrow(np).c_str(),
                    g_pending_refs.size() > pending_before ? ", resource loading, written when loaded" : "");
                return;
            }
            const auto h = make_holder(tn, raw);
            if (h == 0) {
                log("    %s: cannot obtain resource %s", path.c_str(), narrow(np).c_str());
                return;
            }
            if (owner != 0 && !holder_ready(h)) {
                uintptr_t header = 0;
                safe_read_ptr(owner, header);
                add_ref(h);
                g_pending_refs.push_back({owner, header, sl, pl, h, 0, 0, 0, narrow(raw)});
                mark_changed();
                log("    %s: resource %s -> %s (resource loading, written when loaded)", path.c_str(), narrow(lp).c_str(), narrow(np).c_str());
                return;
            }
            assign_ref(sl, h);
            mark_changed();
            ++m_replaced;
            log("    %s: resource %s -> %s", path.c_str(), narrow(lp).c_str(), narrow(np).c_str());
            return;
        }
        if (is_prefab(tn)) {
            std::wstring np{}, lp{};
            if (!prefab_path(pn, np)) return;
            if (pl != 0 && type_of(pl) == tn && prefab_path(pl, lp) && lp == np) return;
            const auto d = duplicate_prefab(pn);
            if (d == 0) {
                log("    %s: cannot duplicate prefab %s", path.c_str(), narrow(np).c_str());
                return;
            }
            assign_ref(sl, d);
            mark_changed();
            ++m_replaced;
            log("    %s: prefab %s -> %s", path.c_str(), narrow(lp).c_str(), narrow(np).c_str());
            return;
        }
        // Object of the same type: recurse, writing only fields changed in the file
        if (po != 0 && pl != 0 && to == tn && type_of(pl) == tn) {
            diff_object(po, pn, pl, tn, path, depth + 1);
            return;
        }
        const auto c = clone(pn, depth + 1);
        if (c == 0) {
            structure(path, "cannot create the referenced object");
            return;
        }
        assign_ref(sl, c);
        mark_changed();
        ++m_replaced;
        log("    %s: created object %s", path.c_str(), name_of(tn).c_str());
    }

    void structure(const std::string& path, const char* what) {
        m_structure_changed = true;
        log("    %s: %s, cannot hot-update", path.c_str(), what);
    }

    void diff_container(uintptr_t so, uintptr_t sn, uintptr_t sl, const SeqEntry& e, const std::string& path, int depth) {
        const auto co = *(uintptr_t*)so;
        const auto cn = *(uintptr_t*)sn;
        const auto cl = *(uintptr_t*)sl;
        View vo{}, vn{}, vl{};
        if (!view_of(co, vo) || !view_of(cn, vn) || !view_of(cl, vl)) return;
        if (vo.count != vn.count) {
            // Element count changed: rebuild the container; when the scene instance's container was not changed at runtime, unchanged elements keep the instance's values
            const bool same_shape = cl != 0 && vl.count == vo.count;
            // When the instance already has a List<T>, replace its content in place (for .user writes; pfb still creates a new one, and pfb's old object references are handled by the rebuild flow)
            const auto reuse = g_keep_replaced && cn != 0 ? cl : 0;
            const auto c = cn != 0 ? build_container(cn, same_shape ? &vo : nullptr, same_shape ? &vl : nullptr, e, depth, reuse) : 0;
            if (cn != 0 && c == 0) {
                structure(path, "cannot rebuild the container");
                return;
            }
            mark_changed();
            if (c != 0 && c == cl) {
                log("    %s: element count %u -> %u, updated in place", path.c_str(), vo.count, vn.count);
                return;
            }
            assign_ref(sl, c);
            ++m_replaced;
            log("    %s: element count %u -> %u, rebuilt", path.c_str(), vo.count, vn.count);
            return;
        }
        if (vl.count != vo.count || vo.count == 0) return; // The instance container was changed at runtime; do not overwrite

        const auto& ei = elem_of(e);
        const bool by_ref = ei.by_ref;
        const uint32_t stride = ei.stride;
        if (stride == 0) return;
        for (uint32_t i = 0; i < vo.count; ++i) {
            const auto off = (uintptr_t)stride * i;
            const auto ep = path + "[" + std::to_string(i) + "]";
            if (by_ref) {
                diff_ref(vo.elements + off, vn.elements + off, vl.elements + off, ep, depth + 1);
            } else if (has_refs(ei.td)) {
                diff_struct(ei.td, vo.elements + off, vn.elements + off, vl.elements + off, stride, ep, depth + 1);
            } else if (!same_value_bytes(ei.td, vo.elements + off, vn.elements + off, stride)) {
                std::vector<uint8_t> old_v((uint8_t*)(vl.elements + off), (uint8_t*)(vl.elements + off) + stride);
                memcpy((void*)(vl.elements + off), (void*)(vn.elements + off), stride);
                record(ep, ei.td, old_v.data(), (void*)(vn.elements + off));
            }
        }
    }

    bool m_verbose;
    const SceneMap* m_scene{};
    bool m_structure_changed{};
    uint32_t m_fields{};
    uint32_t m_replaced{};
    uintptr_t m_current_provider{};
    std::unordered_set<uintptr_t> m_changed_providers{};
    std::unordered_set<uintptr_t> m_visited{};
    std::unordered_map<uintptr_t, uintptr_t> m_clones{}; // Copy object -> newly created object (keeping shared references)
    std::unordered_set<uintptr_t> m_created{};           // Newly created objects
    std::unordered_set<uintptr_t> m_parts_seen{};        // Instance objects already visited by native_parts
};

// Index of the occurrence-th component of the same type; -1 if none
int find_component(const std::vector<uintptr_t>& comps, API::TypeDefinition* td, int occurrence) {
    for (int i = 0; i < (int)comps.size(); ++i) {
        if (type_of(comps[i]) == td && occurrence-- == 0) return i;
    }
    return -1;
}

// ---- Native objects: call the type's own native deserialize function directly ----

// RSZ block of the pfb resource split per instance
bool walk_prefab(uintptr_t res, RszWalk& w) {
    uintptr_t data = 0, size = 0;
    if (!safe_read_ptr(res + PREFAB_RES_DATA, data) || !safe_read_ptr(res + PREFAB_RES_SIZE, size) || data == 0) {
        w.error = "cannot read pfb data";
        return false;
    }
    if (*(uint32_t*)data != PFB_MAGIC) {
        w.error = "not pfb data";
        return false;
    }
    const auto rsz_off = *(uint64_t*)(data + PFB_RSZ_OFFSET);
    if (rsz_off >= size) {
        w.error = "RSZ offset out of range";
        return false;
    }
    return rsz_walk((const uint8_t*)(data + rsz_off), size - rsz_off, w);
}

// The root Transform's position/rotation is placed by the game: save it before rereading and restore it afterwards
class PoseKeeper {
public:
    explicit PoseKeeper(uintptr_t transform) : m_transform(transform) {
        const auto tdb = API::get()->tdb();
        static const auto get_pos = tdb->find_method("via.Transform", "get_LocalPosition");
        static const auto get_rot = tdb->find_method("via.Transform", "get_LocalRotation");
        m_ok = transform != 0 && get_pos && get_rot && safe_invoke(get_pos, transform, nullptr, 0, &m_pos) &&
               safe_invoke(get_rot, transform, nullptr, 0, &m_rot);
    }
    ~PoseKeeper() {
        if (!m_ok) return;
        const auto tdb = API::get()->tdb();
        static const auto set_pos = tdb->find_method("via.Transform", "set_LocalPosition");
        static const auto set_rot = tdb->find_method("via.Transform", "set_LocalRotation");
        reframework::InvokeRet out{};
        // Value-type arguments are passed by pointer
        alignas(16) float pos[4]{}, rot[4]{};
        memcpy(pos, m_pos.bytes.data(), 12);
        memcpy(rot, m_rot.bytes.data(), 16);
        void* pos_arg[] = {pos};
        void* rot_arg[] = {rot};
        if (set_pos) safe_invoke(set_pos, m_transform, pos_arg, sizeof(pos_arg), &out);
        if (set_rot) safe_invoke(set_rot, m_transform, rot_arg, sizeof(rot_arg), &out);
    }
    PoseKeeper(const PoseKeeper&) = delete;
    PoseKeeper& operator=(const PoseKeeper&) = delete;
    bool ok() const { return m_ok; }

private:
    uintptr_t m_transform{};
    bool m_ok{};
    reframework::InvokeRet m_pos{}, m_rot{};
};

// ---- Native objects: apply only the parameters changed in the file ----
// Native deserialization writes every field. To keep parameters the file did not change at the scene instance's current values (possibly changed by the game at runtime),
// go through the type's public get_X/set_X properties: record the current values, run native deserialization with the old data and then the new data, recording each time;
// properties that differ between old and new are file changes and keep the new value; other properties changed by deserialization are written back to their original values with setters.

// Sources of readable/writable parameters:
// - Reflected variables: REFieldList+0x20 -> {pad, VariableDescriptor**, num}. Descriptor (72 bytes) +0x00 name, +0x0C bit2 read-only / bit1, bit4 indexed,
//   +0x10 getter fn(descriptor, object, out[, index]), +0x18 bit0-4 type kind / bit7-9 passing mode (0 value, 1 object reference, 2 pointer into internal storage) /
//   bit10- size, +0x20 type name, +0x3C setter offset relative to the getter (0 means no setter). setter fn(descriptor, object, pointer to value[, index])
//   Indexed variables (per-item switches such as PartsEnable, MaterialsEnable): +0x40 is the offset of the element count getter fn(descriptor, object, out) relative to the getter
// - TDB methods: get_X/set_X or getX/setX, called through REFramework invoke (fills in what reflected variables lack)
using ReflAccessor = void (*)(uintptr_t, uintptr_t, void*);
using ReflIndexed = void (*)(uintptr_t, uintptr_t, void*, uint64_t);
constexpr uintptr_t FIELDLIST_VARIABLES = RSZ_FIELDLIST_VARIABLES; // Shared with rsz_layout and verified at startup
constexpr uint32_t REFL_KIND_STRUCT = 17;
constexpr uint32_t REFL_PASS_OBJECT = 1;
constexpr uint32_t REFL_PASS_POINTER = 2;
constexpr uint32_t MAX_PROP_SIZE = 128;
constexpr uint32_t MAX_PROP_ELEMENTS = 1024;

struct NativeProp {
    std::string name;
    // TDB methods
    API::Method* get{};
    API::Method* set{};
    bool slot{}; // The value goes into an 8-byte argument slot (primitives/enums; System.Single is a double in the slot)
    // Reflected variables
    uintptr_t desc{};
    ReflAccessor rget{};
    ReflAccessor rset{};
    bool by_pointer{};
    bool indexed{}; // Indexed: rget/rset take an extra index argument; the element count comes from rcount
    ReflAccessor rcount{};
    uint32_t size{}; // Number of bytes compared (a single element when indexed)
    std::vector<uint8_t> mask; // Bytes actually occupied by fields in a struct (empty means compare everything)
    std::string type_name;     // Value type name (the type name string for reflected variables, the return type for TDB methods)
};

std::string read_cstr(uintptr_t p) {
    std::string s{};
    for (int i = 0; p != 0 && i < 256; ++i) {
        uintptr_t q = 0;
        if (!safe_read_ptr(p + i, q) || (q & 0xFF) == 0) break;
        s.push_back((char)(q & 0xFF));
    }
    return s;
}

void add_reflection_props(API::TypeDefinition* td, std::vector<NativeProp>& out, std::unordered_set<std::string>& seen) {
    for (auto t = td; t != nullptr; t = t->get_parent_type()) {
        const auto fields = rsz_field_list((uintptr_t)t->get_type_info());
        uintptr_t vars = 0, data = 0, num = 0;
        if (fields == 0 || !safe_read_ptr(fields + FIELDLIST_VARIABLES, vars) || vars == 0 || !safe_read_ptr(vars + 0x08, data) ||
            !safe_read_ptr(vars + 0x10, num) || data == 0) {
            continue;
        }
        for (uint32_t i = 0; i < (uint32_t)num && i < 4096; ++i) {
            uintptr_t d = 0, name = 0, head = 0, getter = 0, info = 0, tname = 0, tail = 0, ext = 0;
            if (!safe_read_ptr(data + 8ull * i, d) || d == 0 || !safe_read_ptr(d, name) || !safe_read_ptr(d + 0x08, head) ||
                !safe_read_ptr(d + 0x10, getter) || !safe_read_ptr(d + 0x18, info) || !safe_read_ptr(d + 0x20, tname) ||
                !safe_read_ptr(d + 0x38, tail) || !safe_read_ptr(d + 0x40, ext)) {
                continue;
            }
            // +0x0C bit2 read-only, bit1 indexed
            const auto head_flags = (uint32_t)(head >> 32);
            const auto indexed = (head_flags & 2) != 0;
            const auto count_off = (int32_t)(uint32_t)ext;
            if (indexed && count_off == 0) continue;
            const auto readonly = (head_flags & 4) != 0;
            const auto set_off = (int32_t)(tail >> 32);
            const auto f = (uint32_t)info;
            const auto kind = f & 0x1F, pass = (f >> 7) & 7, size = (f >> 10) & 0xFFFFF;
            if (readonly || getter == 0 || set_off == 0 || size == 0 || size > MAX_PROP_SIZE || pass == REFL_PASS_OBJECT) continue;
            if (kind == REFL_KIND_STRUCT) {
                // Only value-type structs without references are taken
                const auto vt = API::get()->tdb()->find_type(read_cstr(tname));
                if (vt == nullptr || !vt->is_valuetype() || valuetype_has_refs(vt)) continue;
            } else if (kind == 0 || kind > 14 || pass != 0) {
                continue; // No type, strings and other kinds
            }
            const auto prop = read_cstr(name);
            if (prop.empty() || !seen.insert(prop).second) continue;
            NativeProp np{};
            np.name = prop;
            np.desc = d;
            np.rget = (ReflAccessor)getter;
            np.rset = (ReflAccessor)(getter + (intptr_t)set_off);
            np.by_pointer = pass == REFL_PASS_POINTER;
            np.indexed = indexed;
            if (indexed) np.rcount = (ReflAccessor)(getter + (intptr_t)count_off);
            np.size = size;
            np.type_name = read_cstr(tname);
            if (kind == REFL_KIND_STRUCT) np.mask = significant_mask(API::get()->tdb()->find_type(read_cstr(tname)), size);
            out.push_back(std::move(np));
        }
    }
}

const std::vector<NativeProp>& props_of(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, std::vector<NativeProp>> cache{};
    auto it = cache.find(td);
    if (it != cache.end()) return it->second;
    auto& out = cache[td];
    std::unordered_set<std::string> seen{};
    add_reflection_props(td, out, seen);

    // Property names: get_X/set_X or getX/setX (X starting with an uppercase letter)
    auto suffix = [](const std::string& name, const char* prefix) -> std::string {
        const std::string p = prefix;
        if (!name.starts_with(p)) return {};
        if (name.size() > p.size() + 1 && name[p.size()] == '_') return name.substr(p.size() + 1);
        if (name.size() > p.size() && std::isupper((unsigned char)name[p.size()])) return name.substr(p.size());
        return {};
    };
    std::unordered_map<std::string, API::Method*> setters{};
    std::vector<std::pair<std::string, API::Method*>> getters{};
    for (auto t = td; t != nullptr; t = t->get_parent_type()) {
        for (const auto m : t->get_methods()) {
            if (m == nullptr || m->is_static()) continue;
            const std::string name = m->get_name();
            if (const auto x = suffix(name, "set"); !x.empty() && m->get_num_params() == 1) {
                setters.emplace(x, m); // Derived classes first
            } else if (const auto y = suffix(name, "get"); !y.empty() && m->get_num_params() == 0) {
                getters.emplace_back(y, m);
            }
        }
    }
    for (const auto& [prop, g] : getters) {
        if (!seen.insert(prop).second) continue;
        const auto rt = g->get_return_type();
        const auto sit = setters.find(prop);
        if (rt == nullptr || sit == setters.end() || !rt->is_valuetype() || valuetype_has_refs(rt)) continue;
        const auto params = sit->second->get_params();
        if (params.size() != 1 || (API::TypeDefinition*)params[0].t != rt) continue;
        NativeProp np{};
        np.name = prop;
        np.get = g;
        np.set = sit->second;
        np.type_name = name_of(rt);
        const auto vt_size = rt->get_valuetype_size();
        np.slot = (rt->is_primitive() || rt->is_enum()) && vt_size <= 8;
        np.size = np.slot ? (name_of(rt) == "System.Single" ? 8 : std::max<uint32_t>(vt_size, 1)) : vt_size;
        if (np.size == 0 || np.size > MAX_PROP_SIZE) continue;
        if (!np.slot) np.mask = significant_mask(rt, np.size);
        out.push_back(std::move(np));
    }
    return out;
}

struct PropValue {
    bool ok{};
    uint32_t count{};           // Element count when indexed
    std::vector<uint8_t> bytes; // Value (all elements in sequence when indexed)
};

bool safe_reflect(ReflAccessor fn, uintptr_t desc, uintptr_t obj, void* io) {
    __try {
        fn(desc, obj, io);
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

bool safe_reflect_at(ReflIndexed fn, uintptr_t desc, uintptr_t obj, void* io, uint64_t index) {
    __try {
        fn(desc, obj, io, index);
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

bool safe_copy_from(void* dst, uintptr_t src, uint32_t size) {
    if (!vq_readable(src, size)) return false;
    __try {
        memcpy(dst, (const void*)src, size);
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

// Output of a reflected getter: the value itself, or (when passed by pointer) a pointer into internal storage
bool take_value(const NativeProp& p, const uint8_t* buf, uint8_t* dst) {
    if (!p.by_pointer) {
        memcpy(dst, buf, p.size);
        return true;
    }
    uintptr_t src = 0;
    memcpy(&src, buf, 8);
    return src >= 0x10000 && safe_copy_from(dst, src, p.size);
}

PropValue read_prop(const NativeProp& p, uintptr_t obj) {
    PropValue v{};
    alignas(16) std::array<uint8_t, MAX_PROP_SIZE + 16> buf{};
    if (p.desc != 0 && p.indexed) {
        uint64_t count = 0;
        if (!safe_reflect(p.rcount, p.desc, obj, &count)) return v;
        v.count = (uint32_t)count;
        if (v.count > MAX_PROP_ELEMENTS) return v;
        v.bytes.resize((size_t)v.count * p.size);
        for (uint32_t i = 0; i < v.count; ++i) {
            buf.fill(0);
            if (!safe_reflect_at((ReflIndexed)p.rget, p.desc, obj, buf.data(), i) ||
                !take_value(p, buf.data(), v.bytes.data() + (size_t)i * p.size)) {
                return v;
            }
        }
        v.ok = true;
        return v;
    }
    v.bytes.resize(p.size);
    if (p.desc != 0) {
        v.ok = safe_reflect(p.rget, p.desc, obj, buf.data()) && take_value(p, buf.data(), v.bytes.data());
        return v;
    }
    reframework::InvokeRet r{};
    if (!safe_invoke(p.get, obj, nullptr, 0, &r)) return v;
    v.ok = true;
    memcpy(v.bytes.data(), p.slot ? (const uint8_t*)&r.qword : r.bytes.data(), p.size);
    return v;
}

std::vector<PropValue> snapshot(const std::vector<NativeProp>& props, uintptr_t obj) {
    std::vector<PropValue> out(props.size());
    for (size_t i = 0; i < props.size(); ++i) out[i] = read_prop(props[i], obj);
    return out;
}

bool same_value(const NativeProp& p, const PropValue& a, const PropValue& b) {
    if (!a.ok || !b.ok || a.count != b.count || a.bytes.size() != b.bytes.size()) return false;
    if (p.mask.empty() || p.size == 0) return a.bytes == b.bytes;
    for (size_t off = 0; off + p.size <= a.bytes.size(); off += p.size) {
        if (!same_bytes(p.mask, a.bytes.data() + off, b.bytes.data() + off, p.size)) return false;
    }
    return true;
}

// Target value after the file change: indexed properties are merged element by element (elements the file changed take n, the rest keep base); other properties take n
PropValue merge_changed(const NativeProp& p, const PropValue& base, const PropValue& o, const PropValue& n) {
    if (!p.indexed || !base.ok || base.count != o.count || o.count != n.count) return n;
    PropValue out = base;
    for (uint32_t i = 0; i < n.count; ++i) {
        const auto off = (size_t)i * p.size;
        if (!same_bytes(p.mask, o.bytes.data() + off, n.bytes.data() + off, p.size)) memcpy(out.bytes.data() + off, n.bytes.data() + off, p.size);
    }
    return out;
}

bool restore_value(const NativeProp& p, uintptr_t obj, const PropValue& v) {
    alignas(16) std::array<uint8_t, MAX_PROP_SIZE + 16> buf{};
    if (p.desc != 0 && p.indexed) {
        // Write back differing elements one by one; a change in element count cannot be written back
        const auto cur = read_prop(p, obj);
        if (!cur.ok || cur.count != v.count) return false;
        bool ok = true;
        for (uint32_t i = 0; i < v.count; ++i) {
            const auto off = (size_t)i * p.size;
            if (same_bytes(p.mask, cur.bytes.data() + off, v.bytes.data() + off, p.size)) continue;
            buf.fill(0);
            memcpy(buf.data(), v.bytes.data() + off, p.size);
            ok &= safe_reflect_at((ReflIndexed)p.rset, p.desc, obj, buf.data(), i);
        }
        return ok;
    }
    memcpy(buf.data(), v.bytes.data(), p.size);
    if (p.desc != 0) return safe_reflect(p.rset, p.desc, obj, buf.data());
    reframework::InvokeRet out{};
    void* arg[1]{};
    if (p.slot) {
        memcpy(&arg[0], v.bytes.data(), 8);
    } else {
        arg[0] = buf.data();
    }
    return safe_invoke(p.set, obj, arg, sizeof(arg), &out);
}

std::string join(const std::vector<std::string>& v, size_t max = 12) {
    std::string s{};
    for (size_t i = 0; i < v.size() && i < max; ++i) s += (i ? ", " : "") + v[i];
    if (v.size() > max) s += " ... (" + std::to_string(v.size()) + " in total)";
    return s;
}

// ---- String/resource path properties: TDB get_X/set_X whose type is System.String or a subclass of via.ResourceHolder ----
// Not included in the value-type property table (props_of). Resources are compared by path; on write, the resource is obtained by path and a new holder passed to the setter (the same way the game swaps resources)
struct TextProp {
    std::string name;
    API::Method* get{};
    API::Method* set{};
    bool resource{};
    std::string holder_type;   // Resource holder type name
    std::string resource_type; // Resource type name (holder type name without Holder)
    // Indexed: getX(index) / setX(index, value) / getXCount(), e.g. Resources of via.effect.ProviderData
    bool indexed{};
    API::Method* count{};
};

struct TextValue {
    bool ok{};
    bool null{};
    std::wstring text;                                // Resources as lowercase paths (for comparison)
    std::vector<std::pair<bool, std::wstring>> items; // Indexed: each element {is null, value}
    std::wstring raw;                                 // Original-case paths of resources (for writing, not compared)
    std::vector<std::wstring> raw_items;
    bool operator==(const TextValue& o) const { return ok == o.ok && null == o.null && text == o.text && items == o.items; }
};

const std::vector<TextProp>& text_props_of(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, std::vector<TextProp>> cache{};
    if (const auto it = cache.find(td); it != cache.end()) return it->second;
    auto& out = cache[td];
    if (td == nullptr || name_of(td) == "via.GameObject") return out; // GameObject name changes are handled as structure (paths)
    std::unordered_set<std::string> seen{};
    // Value type: System.String or a subclass of via.ResourceHolder
    auto value_kind = [](API::TypeDefinition* rt, TextProp& p) {
        if (rt == nullptr) return false;
        const auto& rn = name_of(rt);
        if (rn == "System.String") return true;
        if (!is_a(rt, "via.ResourceHolder") || !rn.ends_with("Holder")) return false;
        p.resource = true;
        p.holder_type = rn;
        p.resource_type = rn.substr(0, rn.size() - 6); // Resource types are in the engine's native type table (not in the TDB); create_resource looks them up by name
        return true;
    };
    auto is_index = [](API::TypeDefinition* t) {
        if (t == nullptr) return false;
        const auto& n = name_of(t);
        return n == "System.UInt64" || n == "System.Int64" || n == "System.UInt32" || n == "System.Int32";
    };
    // Property names: get_X/set_X, or getX/setX (X starting uppercase, e.g. Mesh's get_Mesh/setMesh); set_X preferred
    auto suffix = [](const std::string& n, const char* prefix) -> std::string {
        const std::string pre = prefix;
        if (n.size() <= pre.size() + 1 || !n.starts_with(pre)) return {};
        const auto rest = n.substr(pre.size());
        if (rest[0] == '_') return rest.size() > 1 ? rest.substr(1) : std::string{};
        return isupper((unsigned char)rest[0]) ? rest : std::string{};
    };
    for (auto t = td; t != nullptr; t = t->get_parent_type()) {
        std::unordered_map<std::string, API::Method*> setters{}, indexed_setters{}, getters0{};
        for (const auto m : t->get_methods()) {
            if (m == nullptr || m->is_static()) continue;
            const std::string n = m->get_name();
            const auto np = m->get_num_params();
            if (const auto x = suffix(n, "set"); !x.empty()) {
                if (np == 1 && (n.starts_with("set_") || !setters.contains(x))) setters[x] = m;
                if (np == 2) indexed_setters[x] = m;
            }
            if (const auto x = suffix(n, "get"); !x.empty() && np == 0) getters0[x] = m;
        }
        for (const auto m : t->get_methods()) {
            if (m == nullptr || m->is_static()) continue;
            const std::string n = m->get_name();
            const auto prop = suffix(n, "get");
            if (prop.empty() || seen.contains(prop)) continue;
            const auto rt = m->get_return_type();
            TextProp p{prop, m};
            if (m->get_num_params() == 0) {
                const auto sit = setters.find(prop);
                if (sit == setters.end()) continue;
                const auto params = sit->second->get_params();
                if (params.size() != 1 || (API::TypeDefinition*)params[0].t != rt || !value_kind(rt, p)) continue;
                p.set = sit->second;
            } else if (m->get_num_params() == 1) {
                const auto sit = indexed_setters.find(prop);
                const auto cit = getters0.find(prop + "Count");
                if (sit == indexed_setters.end() || cit == getters0.end() || !is_index((API::TypeDefinition*)m->get_params()[0].t)) continue;
                const auto params = sit->second->get_params();
                if (params.size() != 2 || !is_index((API::TypeDefinition*)params[0].t) || (API::TypeDefinition*)params[1].t != rt ||
                    !is_index(cit->second->get_return_type()) || !value_kind(rt, p)) {
                    continue;
                }
                p.set = sit->second;
                p.indexed = true;
                p.count = cit->second;
            } else {
                continue;
            }
            seen.insert(prop);
            out.push_back(std::move(p));
        }
    }
    return out;
}

// Object returned by the getter -> {is null, value}; resources give their path (lowercase)
// raw: original-case path of the resource (may be a null pointer)
bool text_of(const TextProp& p, uintptr_t ptr, bool& null, std::wstring& text, std::wstring* raw = nullptr) {
    text.clear();
    if (raw != nullptr) raw->clear();
    null = ptr == 0;
    if (null) return true;
    if (!p.resource) {
        text = read_string(ptr);
        return true;
    }
    std::wstring r{};
    if (!holder_path_raw(ptr, r)) return false;
    text = r;
    for (auto& ch : text) ch = (wchar_t)towlower(ch);
    if (raw != nullptr) *raw = std::move(r);
    null = text.empty();
    return true;
}

TextValue read_text(const TextProp& p, uintptr_t obj) {
    TextValue v{};
    if (obj == 0) return v;
    reframework::InvokeRet r{};
    if (!p.indexed) {
        if (!safe_invoke(p.get, obj, nullptr, 0, &r) || r.exception_thrown) return v;
        v.ok = text_of(p, (uintptr_t)r.ptr, v.null, v.text, &v.raw);
        return v;
    }
    if (!safe_invoke(p.count, obj, nullptr, 0, &r) || r.exception_thrown) return v;
    const auto n = r.qword;
    if (n > 4096) return v;
    for (uint64_t i = 0; i < n; ++i) {
        void* args[1]{(void*)(uintptr_t)i};
        reframework::InvokeRet er{};
        if (!safe_invoke(p.get, obj, args, sizeof(args), &er) || er.exception_thrown) return v;
        std::pair<bool, std::wstring> item{};
        std::wstring raw{};
        if (!text_of(p, (uintptr_t)er.ptr, item.first, item.second, &raw)) return v;
        v.items.push_back(std::move(item));
        v.raw_items.push_back(std::move(raw));
    }
    v.ok = true;
    return v;
}

// Setter argument: strings become new managed strings; resources are obtained by path and wrapped in a new holder (the holder holds the resource reference itself).
// When the new resource value is empty (the file cleared the resource path) pass an empty holder: observed 2026-11-12 that ShellFurMesh.set_Resource(null) reads back empty and writing the original resource back restores it
bool text_arg(const TextProp& p, bool null, const std::wstring& text, void*& arg) {
    arg = nullptr;
    if (!p.resource) {
        if (null) return true;
        arg = (void*)API::get()->sdk()->functions->create_managed_string(text.c_str());
        return arg != nullptr;
    }
    if (null || text.empty()) return true;
    arg = (void*)make_holder(API::get()->tdb()->find_type(p.holder_type), text);
    return arg != nullptr;
}

// Whether the resource in a holder can be handed to components (mdf2 must also wait for its referenced textures/mmtr to load: checking only +0x38, observed 2026-11-12
// that after switching to a weapon material never loaded before one instance had MaterialReady=false and 0 materials). An empty holder counts as complete
bool holder_ready(uintptr_t holder) {
    if (holder == 0) return true;
    uintptr_t res = 0;
    return safe_read_ptr(holder + 0x10, res) && resource_fully_ready(res);
}

// Resources still loading at write time: call the setter once more after loading completes (meshes build materials only in set_Material, and getting an mdf2 still loading leaves them without materials;
// observed 2026-11-12: after changing the Mesh/Material path back, one instance had MaterialReady=false and 0 materials)
struct PendingTextWrite {
    uintptr_t obj{}, header{};
    const TextProp* p{};
    uintptr_t holder{}; // One reference held
    uint32_t frames{};
    std::string label;
};
std::vector<PendingTextWrite> g_pending_text{};


// Reason for the most recent write_text failure (written into the "Not written" log)
std::string g_text_fail{};

// Success only if reading back after the write equals v. Indexed properties write only differing elements; a different element count (structure change) is not written
bool write_text(const TextProp& p, uintptr_t obj, const TextValue& v) {
    g_text_fail.clear();
    if (!v.ok) return false;
    reframework::InvokeRet r{};
    if (!p.indexed) {
        void* args[1]{};
        // Resources are obtained by their original-case path (cache keys are case-sensitive: a lowercase path loads a second resource for the same file)
        if (!text_arg(p, v.null, p.resource && !v.raw.empty() ? v.raw : v.text, args[0])) {
            g_text_fail = "cannot create resource from path " + narrow(v.raw.empty() ? v.text : v.raw);
            return false;
        }
        std::erase_if(g_pending_text, [&](PendingTextWrite& w) {
            if (w.obj != obj || w.p != &p) return false;
            release(w.holder);
            return true;
        });
        // Resource still loading: write as usual first (creating the resource without handing it to a component does not make the engine load it: observed 2026-11-12 the mesh/material load flags stayed 0 for 8 seconds),
        // then call the setter once more after loading completes (PrefabLive::update), so the mesh rebuilds its materials with the ready material
        if (p.resource && args[0] != nullptr && !holder_ready((uintptr_t)args[0])) {
            uintptr_t header = 0;
            safe_read_ptr(obj, header);
            add_ref((uintptr_t)args[0]);
            g_pending_text.push_back({obj, header, &p, (uintptr_t)args[0], 0, narrow(v.raw.empty() ? v.text : v.raw)});
            g_text_fail = "resource loading";
        }
        if (!safe_invoke(p.set, obj, args, sizeof(args), &r) || r.exception_thrown) {
            g_text_fail = "setter error";
            return false;
        }
    } else {
        const auto cur = read_text(p, obj);
        if (!cur.ok || cur.items.size() != v.items.size()) {
            g_text_fail = "element count differs";
            return false;
        }
        for (size_t i = 0; i < v.items.size(); ++i) {
            if (cur.items[i] == v.items[i]) continue;
            void* args[2]{(void*)(uintptr_t)i, nullptr};
            const auto& path = i < v.raw_items.size() && !v.raw_items[i].empty() ? v.raw_items[i] : v.items[i].second;
            if (!text_arg(p, v.items[i].first, path, args[1])) {
                g_text_fail = "cannot create resource from path " + narrow(v.items[i].second);
                return false;
            }
            if (!safe_invoke(p.set, obj, args, sizeof(args), &r) || r.exception_thrown) {
                g_text_fail = "setter error";
                return false;
            }
        }
    }
    const auto back = read_text(p, obj);
    if (back == v) return true;
    // Empty resource: a null holder and a holder without a path both count as empty
    if (p.resource && !p.indexed && back.ok && (back.null || back.text.empty()) && (v.null || v.text.empty())) return true;
    g_text_fail = "read back " + (back.null ? std::string{"null"} : narrow(back.text)) + ", expected " + narrow(v.text);
    return false;
}

// String/resource properties changed in the file: the old/new copies differ, and the other copy of the same data (o2/n2, may be 0) agrees with each
bool text_changed(const TextProp& p, uintptr_t o, uintptr_t o2, uintptr_t n, uintptr_t n2, TextValue& vo, TextValue& vn) {
    vo = read_text(p, o);
    vn = read_text(p, n);
    if (!vo.ok || !vn.ok || vo == vn) return false;
    if (o2 != 0 && !(read_text(p, o2) == vo)) return false;
    if (n2 != 0 && !(read_text(p, n2) == vn)) return false;
    return true;
}

// When instance data changed, apply the parameters changed in the file to the scene object. Returns 1 when handled
// reflection_only: keep runtime values using reflected variables only (native ancestor part of managed components; the managed class's own get/set methods are not called)
// Activation state controlled by the game at runtime (GameObject.UpdateSelf/DrawSelf, component/behavior Enabled): the game toggles these as needed (pooled projectiles waiting for use,
// inactive effects, etc.); when the file changes them, the new value is written only if the instance's current value still equals the old file value (untouched by the game); values the game changed keep the game's state.
// Otherwise objects the game disabled would be activated: a pooled projectile switched on crashed in ace.ShellBase.update reading a null pointer (observed 2026-10-30, dump scene_g153_0532.dmp)
bool runtime_state_prop(const std::string& name) {
    return name == "UpdateSelf" || name == "DrawSelf" || name == "Enabled";
}


// Activation states judged as game-controlled (object address + property name -> object header): once remembered, this state of the instance always keeps the game's value.
// Comparing only "current value == old file value" is not enough: after a previous change the old file value may happen to equal what the game set (a disabled pooled projectile: file true->false kept it false,
// and changing it back to true then found the old value false equal to the instance, wrote true and activated the projectile, which crashed in testing)
std::map<std::pair<uintptr_t, std::string>, uintptr_t> g_game_controlled{};

bool game_controlled(uintptr_t live, const std::string& name) {
    const auto it = g_game_controlled.find({live, name});
    if (it == g_game_controlled.end()) return false;
    uintptr_t header = 0;
    if (safe_read_ptr(live, header) && header == it->second && type_of(live) != nullptr) return true;
    g_game_controlled.erase(it); // Object reclaimed or reused
    return false;
}

// Activation states the plugin itself wrote (object address + property name -> {object header, value written}). The second round of the same save (rebuilding unheld components from the new file)
// compares again: held components were written to the new value in the first round, which differs from the old file value but must not be taken as a game change (observed 2026-11-11: ch03_037_0015's
// CollisionShapePreset.Enabled was misjudged and stayed at the false the plugin wrote; changing the file back to true no longer wrote it)
struct PluginWrote {
    uintptr_t header{};
    PropValue value{};
};
std::map<std::pair<uintptr_t, std::string>, PluginWrote> g_plugin_wrote{};

void remember_plugin_write(uintptr_t live, const std::string& name, const PropValue& v) {
    uintptr_t header = 0;
    if (!v.ok || !safe_read_ptr(live, header)) return;
    if (g_plugin_wrote.size() >= 65536) g_plugin_wrote.clear();
    g_plugin_wrote[{live, name}] = {header, v};
}

// Whether the current value is the value the plugin last wrote (object not reclaimed or reused)
bool written_by_plugin(const NativeProp& p, uintptr_t live, const PropValue& current) {
    const auto it = g_plugin_wrote.find({live, p.name});
    if (it == g_plugin_wrote.end()) return false;
    uintptr_t header = 0;
    if (!safe_read_ptr(live, header) || header != it->second.header || type_of(live) == nullptr) {
        g_plugin_wrote.erase(it);
        return false;
    }
    return same_value(p, current, it->second.value);
}

void keep_runtime_state(uintptr_t live, const std::string& label, const std::string& name) {
    uintptr_t header = 0;
    if (safe_read_ptr(live, header)) {
        if (g_game_controlled.size() >= 65536) g_game_controlled.clear();
        g_game_controlled[{live, name}] = header;
    }
    log("  [Conclusion] Not applied: %s.%s (activation state controlled by the game at runtime; the game has changed it away from the file's old value, so the game's current state is kept)", label.c_str(), name.c_str());
}

uint32_t native_direct(const RszWalk& ow, int oi, const RszWalk& nw, int ni, uintptr_t live, const std::string& label,
                       bool keep_pose, bool reflection_only = false) {
    if (!ow.has(oi) || !nw.has(ni)) return 0;
    const auto ol = ow.length(oi);
    const auto nl = nw.length(ni);
    const auto ob = ow.bytes(oi);
    const auto nb = nw.bytes(ni);
    if (ol == nl && memcmp(ob, nb, nl) == 0) return 0;

    for (const auto& [w, k] : {std::pair{&ow, oi}, std::pair{&nw, ni}}) {
        const auto probe = rsz_probe_native(*w, k);
        if (probe != NativeProbe::Ok) {
            log("    %s: data changed, but native deserialization of the %s data %s; skipped", label.c_str(), w == &ow ? "old" : "new", to_string(probe));
            return 0;
        }
    }
    const auto td = type_of(live);
    if (td == nullptr) return 0;
    std::vector<NativeProp> reflection_props{};
    if (reflection_only) {
        for (const auto& p : props_of(td)) {
            if (p.desc != 0) reflection_props.push_back(p);
        }
    }
    const auto& props = reflection_only ? reflection_props : props_of(td);

    std::vector<std::string> applied{}, kept{}, failed{}, text_failed{};
    bool ok = false;
    {
        std::unique_ptr<PoseKeeper> pose{};
        if (keep_pose) {
            pose = std::make_unique<PoseKeeper>(live);
            if (!pose->ok()) {
                log("    %s: cannot save the root object's position/rotation, skipped", label.c_str());
                return 0;
            }
        }
        static const std::vector<TextProp> no_text{};
        const auto& tprops = reflection_only ? no_text : text_props_of(td);
        auto read_texts = [&]() {
            std::vector<TextValue> v{};
            for (const auto& p : tprops) v.push_back(read_text(p, live));
            return v;
        };
        const auto current = snapshot(props, live);
        const bool ok_old = rsz_apply_native(ow, oi, live);
        const auto from_old = snapshot(props, live);
        const auto text_old = read_texts();
        ok = rsz_apply_native(nw, ni, live) && ok_old;
        const auto from_new = snapshot(props, live);
        const auto text_new = read_texts();
        // Strings/resources: deserialization only changes storage, so write the old value and then the new value through the setter to make sure the setter's processing runs
        for (size_t i = 0; i < tprops.size(); ++i) {
            if (!text_old[i].ok || !text_new[i].ok || text_old[i] == text_new[i]) continue;
            write_text(tprops[i], live, text_old[i]);
            (write_text(tprops[i], live, text_new[i]) ? applied : text_failed).push_back(tprops[i].name);
        }

        for (size_t i = 0; i < props.size(); ++i) {
            const auto& p = props[i];
            if (!from_old[i].ok || !from_new[i].ok) continue;
            if (!same_value(p, from_old[i], from_new[i])) {
                const bool state = !p.indexed && runtime_state_prop(p.name) && current[i].ok;
                if (state && ((!same_value(p, current[i], from_old[i]) && !written_by_plugin(p, live, current[i])) || game_controlled(live, p.name))) {
                    restore_value(p, live, current[i]); // Deserialization overwrote the storage: write back the game's current state
                    keep_runtime_state(live, label, p.name);
                    continue;
                }
                // Indexed properties: only elements the file changed take the new value; the rest are written back to their runtime values
                const auto target = merge_changed(p, current[i], from_old[i], from_new[i]);
                // Deserialization only changes storage and does not run setter notifications (e.g. Mesh.set_Occluder notifies the renderer to register the occluder; changing only the flag crashed the render thread in testing).
                // A setter returns early when the value is unchanged, so first write back the old file value through the setter and then the new value, to make sure the engine's processing runs
                restore_value(p, live, from_old[i]);
                restore_value(p, live, target);
                if (state) remember_plugin_write(live, p.name, target);
                applied.push_back(p.name);
                continue;
            }
            if (!current[i].ok || same_value(p, current[i], from_new[i])) continue;
            // The file did not change this parameter but the scene instance's value (changed at runtime) was overwritten by deserialization: write it back
            const auto after = restore_value(p, live, current[i]) ? read_prop(p, live) : PropValue{};
            (same_value(p, after, current[i]) ? kept : failed).push_back(p.name);
        }
    }
    log("    %s: file parameter changes (%u -> %u bytes) applied%s%s", label.c_str(), ol, nl, keep_pose ? " (root object position/rotation kept)" : "",
        ok ? "" : ", but the read length differed or execution failed");
    log("      Applied properties: %s", applied.empty() ? "(none; the change may be in fields not exposed as properties, or clamped by the engine)" : join(applied).c_str());
    if (!kept.empty()) log("      Unchanged properties keeping runtime values: %s", join(kept).c_str());
    if (!failed.empty()) log("      Properties whose runtime values could not be written back: %s", join(failed).c_str());
    if (!text_failed.empty()) log("      Not written: %s", join(text_failed).c_str());
    return 1;
}

// ---- Native components that read sub-object references (Motion's Layer, Chain2's EnvWind, etc.): compared through reflected properties ----
// These components cannot have native deserialization rerun on the scene instance (sub-objects would be replaced by the copy's objects, losing runtime state).
// Instead: read the reflected properties of the old and new copies; differences are file changes and are written to the scene instance through setters;
// reflected variables referencing sub-objects (passed as object references) are only read, and the corresponding sub-objects on all three sides are compared recursively one by one.

struct ObjProp {
    std::string name;
    uintptr_t desc{};
    ReflAccessor rget{};
    bool indexed{};
    ReflAccessor rcount{};
};
// Note: sub-objects must not be obtained through TDB methods (such as EffectPlayer.getExternParameters(i)): the VM call treats the returned internal object as a new reference
// and releases it at frame end; the object gets released early and crashes in deferred release processing (observed 2026-10-29, exe+a49d09f). Sub-objects are read only through reflected variables.

const std::vector<ObjProp>& obj_props_of(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, std::vector<ObjProp>> cache{};
    if (const auto it = cache.find(td); it != cache.end()) return it->second;
    auto& out = cache[td];
    std::unordered_set<std::string> seen{};
    for (auto t = td; t != nullptr; t = t->get_parent_type()) {
        const auto fields = rsz_field_list((uintptr_t)t->get_type_info());
        uintptr_t vars = 0, data = 0, num = 0;
        if (fields == 0 || !safe_read_ptr(fields + FIELDLIST_VARIABLES, vars) || vars == 0 || !safe_read_ptr(vars + 0x08, data) ||
            !safe_read_ptr(vars + 0x10, num) || data == 0) {
            continue;
        }
        for (uint32_t i = 0; i < (uint32_t)num && i < 4096; ++i) {
            uintptr_t d = 0, name = 0, head = 0, getter = 0, info = 0, ext = 0;
            if (!safe_read_ptr(data + 8ull * i, d) || d == 0 || !safe_read_ptr(d, name) || !safe_read_ptr(d + 0x08, head) ||
                !safe_read_ptr(d + 0x10, getter) || !safe_read_ptr(d + 0x18, info) || !safe_read_ptr(d + 0x40, ext) || getter == 0) {
                continue;
            }
            const auto f = (uint32_t)info;
            if ((f & 0x1F) != REFL_KIND_STRUCT || ((f >> 7) & 7) != REFL_PASS_OBJECT) continue;
            const auto indexed = (((uint32_t)(head >> 32)) & 2) != 0;
            const auto count_off = (int32_t)(uint32_t)ext;
            if (indexed && count_off == 0) continue;
            const auto prop = read_cstr(name);
            if (prop.empty() || !seen.insert(prop).second) continue;
            ObjProp op{prop, d, (ReflAccessor)getter, indexed};
            if (indexed) op.rcount = (ReflAccessor)(getter + (intptr_t)count_off);
            out.push_back(std::move(op));
        }
    }
    return out;
}

// Value of an object reference variable: count is the element count (1 for non-indexed variables); returns false on failure
API::TypeDefinition* native_part_type(API::TypeDefinition* t) {
    static std::unordered_map<API::TypeDefinition*, API::TypeDefinition*> cache{};
    if (const auto it = cache.find(t); it != cache.end()) return it->second;
    API::TypeDefinition* out = nullptr;
    for (auto p = t != nullptr ? t->get_parent_type() : nullptr; p != nullptr; p = p->get_parent_type()) {
        if (!native_type(p)) continue;
        const auto& name = name_of(p);
        if (name != "System.Object" && name != "via.Object" && (!props_of(p).empty() || !obj_props_of(p).empty())) out = p;
        break;
    }
    cache[t] = out;
    return out;
}

// Native parts of data objects inside managed components (collected by Differ::native_parts): compare old/new copy properties and object memory, and write file changes to the scene instance through setters / memory.
// Not handled without a second copy (uninitialized values cannot be ruled out); objects newly created in diff_object have native parts not read from the file, so they are not handled
uint32_t apply_native_parts(const std::vector<Differ::NativePart>& parts, const std::unordered_set<uintptr_t>& created, const std::string& label);

bool read_objs(const ObjProp& op, uintptr_t obj, std::vector<uintptr_t>& out) {
    out.clear();
    if (!op.indexed) {
        uintptr_t v = 0;
        if (!safe_reflect(op.rget, op.desc, obj, &v)) return false;
        out.push_back(v);
        return true;
    }
    uint64_t count = 0;
    if (!safe_reflect(op.rcount, op.desc, obj, &count) || (uint32_t)count > MAX_PROP_ELEMENTS) return false;
    for (uint32_t i = 0; i < (uint32_t)count; ++i) {
        uintptr_t v = 0;
        if (!safe_reflect_at((ReflIndexed)op.rget, op.desc, obj, &v, i)) return false;
        out.push_back(v);
    }
    return true;
}

// Write an object reference variable (only used for shared objects such as userdata): the reflected setter (+0x3C, when not read-only), otherwise the TDB set_<name>(reference); read back to verify after writing
bool set_object_ref(const ObjProp& op, uintptr_t obj, size_t index, uintptr_t value) {
    uintptr_t head = 0, tail = 0;
    const auto flags = safe_read_ptr(op.desc + 0x08, head) ? (uint32_t)(head >> 32) : 4u;
    const auto set_off = safe_read_ptr(op.desc + 0x38, tail) ? (int32_t)(tail >> 32) : 0;
    bool called = false;
    if ((flags & 4) == 0 && set_off != 0) {
        const auto setter = (ReflAccessor)((uintptr_t)op.rget + (intptr_t)set_off);
        auto v = value;
        called = op.indexed ? safe_reflect_at((ReflIndexed)setter, op.desc, obj, &v, index) : safe_reflect(setter, op.desc, obj, &v);
    } else if (!op.indexed) {
        API::Method* m = nullptr;
        const auto want = "set_" + op.name;
        for (auto t = type_of(obj); t != nullptr && m == nullptr; t = t->get_parent_type()) {
            for (const auto x : t->get_methods()) {
                if (x != nullptr && !x->is_static() && x->get_num_params() == 1 && want == x->get_name()) {
                    m = x;
                    break;
                }
            }
        }
        if (m != nullptr) {
            void* args[1]{(void*)value};
            reframework::InvokeRet r{};
            called = safe_invoke(m, obj, args, sizeof(args), &r) && !r.exception_thrown;
        }
    }
    std::vector<uintptr_t> now{};
    return called && read_objs(op, obj, now) && index < now.size() && now[index] == value;
}

// Noise properties: properties seen with different values across copies of the same data (they read uninitialized storage or storage unrelated to the data, e.g. Mesh.ForceFrontFace,
// UserParamPerInstance). Once found they are remembered and never treated as file changes again: comparing only two copies at the time is not enough, because occasionally the two copies happen to agree
// while old and new differ, writing garbage into the instance (observed 2026-10-29). props_of results are cached permanently, so they are keyed by property object address
std::unordered_set<const NativeProp*> g_noisy_props{};

void note_noise(const NativeProp& p, const PropValue& a, const PropValue& b) {
    if (a.ok && b.ok && !same_value(p, a, b)) g_noisy_props.insert(&p);
}

// Check every property of td with more copies (such as the one from the RSZ split) and remember the noise properties found
void scan_noise(API::TypeDefinition* td, uintptr_t a, uintptr_t a2, uintptr_t b, uintptr_t b2) {
    if (td == nullptr) return;
    for (const auto& p : props_of(td)) {
        if (g_noisy_props.contains(&p)) continue;
        for (const auto [x, y] : {std::pair{a, a2}, {b, b2}}) {
            if (x != 0 && y != 0 && type_of(x) == type_of(y)) note_noise(p, read_prop(p, x), read_prop(p, y));
        }
    }
}

bool prop_changed(const NativeProp& p, uintptr_t o, uintptr_t o2, uintptr_t n, uintptr_t n2, PropValue& vo, PropValue& vn) {
    if (g_noisy_props.contains(&p)) return false;
    vo = read_prop(p, o);
    vn = read_prop(p, n);
    if (!vo.ok || !vn.ok) return false;
    const auto vn2 = n2 != 0 ? read_prop(p, n2) : PropValue{};
    const auto vo2 = o2 != 0 ? read_prop(p, o2) : PropValue{};
    note_noise(p, vo, vo2);
    note_noise(p, vn, vn2);
    if (g_noisy_props.contains(&p) || same_value(p, vo, vn)) return false;
    // Reading the second copy failed: not counted as a file change this time (not recorded as a noise property)
    return (n2 == 0 || vn2.ok) && (o2 == 0 || vo2.ok);
}

// ---- Storage not exposed as properties: compare copy memory (the object itself and internal memory blocks it points to) ----
// Some file fields are deserialized into storage without a corresponding property (e.g. IkLegSpine.BlendRate, AmbientOcclusionGeometryElement.AOIntensity),
// often in engine-allocated memory blocks the object references by pointer. Value bytes that differ between the old and new copies are the result of file changes, and only those bytes are written to the scene instance.
// Conditions: old/new copies differ; two copies of the same data agree (ruling out uninitialized values); the scene instance still equals the old file value (proving it has the same structure,
// not rewritten or reallocated at runtime; otherwise not written). Object headers and pointers themselves are not written; blocks pointed to (non-managed objects) are compared recursively within a limited window
struct RawRun {
    uintptr_t l, n;      // Addresses in the scene instance / new copy
    uint32_t len;
    uintptr_t nbase;     // Start and size of the region (in the new copy): used to judge whether it belongs to a value already handled by properties
    uint32_t nsize;
    std::string where;   // Log: +0xoffset or pointer offset->block+0xoffset
    bool live_changed{}; // The instance value equals neither the old file nor the new file (changed at runtime); not written
};

API::TypeDefinition* safe_type_of(uintptr_t obj);

constexpr uint32_t RAW_BLOCK_WINDOW = 0x200; // Size of internal memory blocks unknown: only compare within this range
// Do not follow pointers into internal memory blocks: observed in IkLegSpine copies that these locations are uninitialized memory (differing between the two copies, heap fill values in the instance),
// and the same location in the scene instance may also be random; writing based on it could corrupt unrelated memory. Only the object itself is compared (size REType+0x30, matching the TDB)
constexpr int RAW_MAX_DEPTH = 0;

bool raw_region_info(uint64_t v, uintptr_t& end) {
    if (v < 0x10000 || v >= 0x00007FFFFFFFFFFFull || (v & 7) != 0) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery((LPCVOID)v, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return false;
    }
    end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    return true;
}

bool raw_pointer(uint64_t v) {
    uintptr_t end = 0;
    return raw_region_info(v, end);
}

void raw_region(uintptr_t o, uintptr_t o2, uintptr_t n, uintptr_t n2, uintptr_t l, uint32_t size, uint32_t header, int depth, const std::string& where,
                std::vector<RawRun>& out, std::unordered_set<uintptr_t>& seen) {
    size &= ~7u;
    if (size <= header || out.size() > 4096 || !seen.insert(l).second) return;
    std::vector<uint8_t> bo(size), bn(size), bo2(size), bn2(size), bl(size);
    if (!safe_copy_from(bo.data(), o, size) || !safe_copy_from(bn.data(), n, size) || !safe_copy_from(bl.data(), l, size)) return;
    const bool has_o2 = o2 != 0 && safe_copy_from(bo2.data(), o2, size);
    const bool has_n2 = n2 != 0 && safe_copy_from(bn2.data(), n2, size);
    if (depth > 0 && (!has_o2 || !has_n2)) return; // Block contents are compared only when two copies are available for cross-checking
    char buf[48];
    for (uint32_t w = (header + 7) & ~7u; w + 8 <= size; w += 8) {
        uint64_t wo, wn, wo2 = 0, wn2 = 0, wl;
        memcpy(&wo, bo.data() + w, 8);
        memcpy(&wn, bn.data() + w, 8);
        memcpy(&wl, bl.data() + w, 8);
        if (has_o2) memcpy(&wo2, bo2.data() + w, 8);
        if (has_n2) memcpy(&wn2, bn2.data() + w, 8);
        const bool ptr = raw_pointer(wo) || raw_pointer(wn);
        if (ptr) {
            // Separately allocated internal memory blocks: when all five sides are pointers, old/new point to different blocks and they are not managed objects, compare block contents recursively
            uintptr_t eo = 0, en = 0, eo2 = 0, en2 = 0, el = 0;
            const bool regions = raw_region_info(wo, eo) && raw_region_info(wn, en) && raw_region_info(wo2, eo2) && raw_region_info(wn2, en2) &&
                                 raw_region_info(wl, el);
            const auto managed = regions ? (safe_type_of(wl) != nullptr || safe_type_of(wn) != nullptr) : false;
            if (depth < RAW_MAX_DEPTH && wo != wn && has_o2 && has_n2 && regions && !managed) {
                uint64_t win = RAW_BLOCK_WINDOW;
                for (const auto [p, e] : {std::pair{wo, eo}, {wn, en}, {wo2, eo2}, {wn2, en2}, {wl, el}}) win = std::min<uint64_t>(win, e - p);
                sprintf_s(buf, "+0x%x->", w);
                raw_region(wo, wo2, wn, wn2, wl, (uint32_t)win, 0, depth + 1, where + buf, out, seen);
            }
            continue;
        }
        if (wo == wn) continue;
        for (uint32_t k = 0; k < 8; ++k) {
            const auto i = w + k;
            if (bo[i] == bn[i]) continue;
            if ((has_o2 && bo[i] != bo2[i]) || (has_n2 && bn[i] != bn2[i])) continue; // Uninitialized values
            const bool live_changed = bl[i] != bo[i] && bl[i] != bn[i];
            if (!out.empty() && out.back().l + out.back().len == l + i && out.back().live_changed == live_changed) {
                ++out.back().len;
            } else {
                sprintf_s(buf, "+0x%x", i);
                out.push_back({l + i, n + i, 1, n, size, where + buf, live_changed});
            }
        }
    }
}

// Sub-objects in the second copy corresponding to objs (none when the counts differ)
std::vector<uintptr_t> second_objs(const ObjProp& op, uintptr_t obj2, size_t count) {
    std::vector<uintptr_t> v{};
    if (obj2 == 0 || !read_objs(op, obj2, v) || v.size() != count) v.assign(count, 0);
    return v;
}

void reflect_diff(uintptr_t o, uintptr_t o2, uintptr_t n, uintptr_t n2, uintptr_t l, API::TypeDefinition* td, const std::string& path, int depth,
                  std::unordered_set<uintptr_t>& visited, std::vector<std::string>& applied, std::vector<std::string>& skipped) {
    if (o == 0 || n == 0 || l == 0 || td == nullptr || depth > 4 || !visited.insert(l).second) return;
    // td may be a native ancestor of the object type (native part of a managed data object): the second copy is checked by the object's own type
    if (o2 != 0 && type_of(o2) != type_of(o)) o2 = 0;
    if (n2 != 0 && type_of(n2) != type_of(n)) n2 = 0;
    for (const auto& p : props_of(td)) {
        PropValue vo{}, vn{};
        if (!prop_changed(p, o, o2, n, n2, vo, vn)) continue;
        const auto vl = read_prop(p, l);
        const bool state = !p.indexed && runtime_state_prop(p.name) && vl.ok;
        if (state && ((!same_value(p, vl, vo) && !written_by_plugin(p, l, vl)) || game_controlled(l, p.name))) {
            keep_runtime_state(l, path.empty() ? std::string{"(component)"} : path, p.name);
            continue;
        }
        const auto target = merge_changed(p, vl, vo, vn);
        if (same_value(p, vl, target)) continue;
        const auto name = path + p.name;
        const bool ok = restore_value(p, l, target) && same_value(p, read_prop(p, l), target);
        if (state && ok) remember_plugin_write(l, p.name, target);
        (ok ? applied : skipped).push_back(name);
    }
    // Strings/resource paths
    for (const auto& p : text_props_of(td)) {
        TextValue vo{}, vn{};
        if (!text_changed(p, o, o2, n, n2, vo, vn) || read_text(p, l) == vn) continue;
        if (write_text(p, l, vn)) {
            applied.push_back(path + p.name + (g_text_fail == "resource loading" ? " (resource loading, written again when loaded)" : ""));
        } else {
            skipped.push_back(path + p.name + " (" + g_text_fail + ")");
        }
    }
    // Storage not exposed as properties is not written through memory (observed 2026-10-29): uninitialized bytes in copies are often allocator fill values (fefdfe); two copies allocated around the same time
    // happen to agree while old/new copies differ, so cross-checking two copies cannot filter them out, and the same location in the scene instance is uninitialized memory too, so writing there changes unrelated bytes.
    // Offline, the "memory" category took effect in-game for 0/46, so there is no dependable benefit.
    std::vector<uintptr_t> so{}, sn{}, sl{};
    for (const auto& op : obj_props_of(td)) {
        if (!read_objs(op, o, so) || !read_objs(op, n, sn) || !read_objs(op, l, sl)) continue;
        if (so.size() != sn.size()) {
            skipped.push_back(path + op.name + " (sub-object count " + std::to_string(so.size()) + " -> " + std::to_string(sn.size()) + ")");
            continue;
        }
        if (sl.size() != so.size()) continue; // The scene instance's sub-object was changed at runtime
        const auto so2 = second_objs(op, o2, so.size()), sn2 = second_objs(op, n2, sn.size());
        for (size_t i = 0; i < so.size(); ++i) {
            const auto t = type_of(sn[i]);
            if (is_userdata(t) || is_userdata(type_of(so[i]))) {
                // Shared .user objects must not be rewritten, only their reference swapped; left alone if the file did not change it or the instance already has the new value
                if (so[i] == sn[i] || sl[i] == sn[i]) continue;
                const auto name = path + op.name + (op.indexed ? "[" + std::to_string(i) + "]" : "");
                if (set_object_ref(op, l, i, sn[i])) {
                    applied.push_back(name + " (userdata reference)");
                } else {
                    skipped.push_back(name + " (userdata reference changed, no usable setter)");
                }
                continue;
            }
            if (t == nullptr || type_of(so[i]) != t || type_of(sl[i]) != t || is_scene_object(t)) continue;
            const auto sub = path + op.name + (op.indexed ? "[" + std::to_string(i) + "]" : "") + ".";
            // Managed data objects (e.g. the UserData app.col_user_data.ActBtnParam of colliders in via.physics.Colliders): property comparison only sees the native ancestor part,
            // so managed fields are written field by field the way managed components are (found by the 2026-11-12 effect check: changing the nullable value field _OwnRangeDegreeRiding wrote 0 places)
            if (!native_type(t) && fieldptr_base(t) != 0 && visited.insert(sl[i]).second) {
                static const SceneMap no_scene{};
                Differ d{false, &no_scene};
                d.diff_object(so[i], sn[i], sl[i], t, sub, 0);
                if (d.fields_changed() > 0) applied.push_back(sub + " (managed fields: " + std::to_string(d.fields_changed()) + ")");
                visited.erase(sl[i]);
            }
            reflect_diff(so[i], so2[i], sn[i], sn2[i], sl[i], t, sub, depth + 1, visited, applied, skipped);
        }
    }
}

// Native components held by game code: compare properties of the old/new copies o/n (including sub-objects) and write the file-changed properties to the scene instance l through setters.
// Deserialization is not rerun on the instance: that would reset state the game built at runtime (e.g. NavigationSurface filters; after a reset worker threads crashed in testing),
// and would also skip setter notifications (e.g. Mesh.set_Occluder notifying the renderer, crashed in testing). o2/n2 are other copies of the same data (noise filtering; may be 0)
uint32_t native_reflect(uintptr_t o, uintptr_t o2, uintptr_t n, uintptr_t n2, uintptr_t l, const std::string& label, uintptr_t o3, uintptr_t n3) {
    const auto td = type_of(l);
    if (td == nullptr || type_of(o) != td || type_of(n) != td) return 0;
    // Third copy: find this type's noise properties first (it is very unlikely that three copies happen to agree while old/new differ)
    scan_noise(td, o, o3, n, n3);
    scan_noise(td, o2, o3, n2, n3);
    std::unordered_set<uintptr_t> visited{};
    std::vector<std::string> applied{}, skipped{};
    reflect_diff(o, o2, n, n2, l, td, "", 0, visited, applied, skipped);
    if (applied.empty() && skipped.empty()) return 0;
    log("    %s: file changes written by property", label.c_str());
    if (!applied.empty()) log("      Applied properties: %s", join(applied).c_str());
    if (!skipped.empty()) log("      Not written: %s", join(skipped).c_str());
    return applied.empty() ? 0 : 1;
}

uint32_t apply_native_parts(const std::vector<Differ::NativePart>& parts, const std::unordered_set<uintptr_t>& created, const std::string& label) {
    std::unordered_set<uintptr_t> visited{};
    std::vector<std::string> applied{}, skipped{};
    for (const auto& p : parts) {
        if (created.contains(p.l) || p.o2 == 0 || p.n2 == 0) continue;
        reflect_diff(p.o, p.o2, p.n, p.n2, p.l, p.td, p.path + ".", 1, visited, applied, skipped);
    }
    if (applied.empty() && skipped.empty()) return 0;
    log("    %s (native part of a data object): file changes written by property", label.c_str());
    if (!applied.empty()) log("      Applied properties: %s", join(applied).c_str());
    if (!skipped.empty()) log("      Not written: %s", join(skipped).c_str());
    return (uint32_t)applied.size();
}

// Whether the old/new copies of a native component that reads sub-object references differ in the count of a sub-object array
bool sub_object_count_changed(uintptr_t oc, uintptr_t nc) {
    const auto td = type_of(nc);
    if (td == nullptr || oc == 0 || type_of(oc) != td) return false;
    std::vector<uintptr_t> a{}, b{};
    for (const auto& prop : obj_props_of(td)) {
        if (read_objs(prop, oc, a) && read_objs(prop, nc, b) && a.size() != b.size()) return true;
    }
    return false;
}

bool reads_refs(const RszWalk& ow, int oi, const RszWalk& nw, int ni) {
    return (nw.has(ni) && rsz_probe_native(nw, ni) == NativeProbe::ReadsRefs) || (ow.has(oi) && rsz_probe_native(ow, oi) == NativeProbe::ReadsRefs);
}

// ---- Native components that read sub-object references: new components, or when the sub-object count changes ----
// A component's native deserialization treats sub-object arrays as "resize to the count in the file, then set each one". When run on the scene instance, the instance array is built as follows:
// - Scene objects (GameObjects/components) map to the corresponding objects of the scene instance
// - Sub-objects at existing positions map to the scene instance's current sub-objects (objects unchanged, runtime state kept); afterwards only file-changed values are written through reflected properties
// - Sub-objects at new positions take the deserialized objects from another untouched copy (clean); that copy's component is never released, so its destruction cannot affect the shared sub-objects
// The component's own value properties: when the old/new copy properties are the same (file unchanged), write back the runtime values
uint32_t native_adopt(RszWalk& clean, int ni, uintptr_t oc, uintptr_t nc, uintptr_t lc, const std::unordered_map<int, uintptr_t>& slot_live,
                      bool fresh, const std::string& label) {
    const auto td = type_of(lc);
    if (td == nullptr || !clean.ok || !clean.has(ni)) {
        log("    %s: no usable data range, parameters not written", label.c_str());
        return 0;
    }
    std::vector<uintptr_t> objs = clean.inst_objects;
    std::unordered_map<uintptr_t, uint32_t> index_of{};
    for (uint32_t j = 0; j < objs.size(); ++j) {
        if (objs[j] != 0) index_of.emplace(objs[j], j);
    }
    for (size_t k = 0; k < clean.object_table.size(); ++k) {
        const auto inst = clean.object_table[k];
        if (inst <= 0 || (size_t)inst >= objs.size()) continue;
        const auto it = slot_live.find((int)k);
        objs[inst] = it == slot_live.end() ? 0 : it->second;
    }

    struct Kept {
        uintptr_t o, n, l;
        std::string path;
    };
    std::vector<Kept> kept{};
    uint32_t added = 0, removed = 0;
    const auto copy = clean.objects[ni];
    std::vector<uintptr_t> np{}, lp{}, op{}, ntp{};
    for (const auto& prop : obj_props_of(td)) {
        if (!read_objs(prop, copy, np)) continue;
        if (!read_objs(prop, lc, lp)) lp.clear();
        if (oc == 0 || !read_objs(prop, oc, op)) op.clear();
        if (!read_objs(prop, nc, ntp)) ntp.clear();
        for (size_t k = 0; k < np.size(); ++k) {
            if (np[k] == 0 || is_userdata(type_of(np[k]))) continue; // userdata: already the shared object in the instance array
            if (k < lp.size() && lp[k] != 0 && type_of(lp[k]) == type_of(np[k])) {
                if (const auto it = index_of.find(np[k]); it != index_of.end()) objs[it->second] = lp[k];
                if (k < op.size() && k < ntp.size()) {
                    kept.push_back({op[k], ntp[k], lp[k], prop.name + (prop.indexed ? "[" + std::to_string(k) + "]" : "") + "."});
                }
            } else {
                ++added;
            }
        }
        if (lp.size() > np.size()) removed += (uint32_t)(lp.size() - np.size());
    }

    const auto& props = props_of(td);
    const auto current = fresh ? std::vector<PropValue>{} : snapshot(props, lc);
    const bool ok = rsz_apply_native_objs(clean, ni, lc, objs);
    std::vector<std::string> applied{}, kept_runtime{}, skipped{};
    if (!fresh && oc != 0) {
        for (size_t i = 0; i < props.size(); ++i) {
            const auto& p = props[i];
            const auto vo = read_prop(p, oc);
            const auto vn = read_prop(p, nc);
            const auto after = read_prop(p, lc);
            if (!vo.ok || !vn.ok || !after.ok) continue;
            if (same_value(p, vo, vn)) {
                if (current[i].ok && !same_value(p, current[i], after) && restore_value(p, lc, current[i])) kept_runtime.push_back(p.name);
                continue;
            }
            const auto target = merge_changed(p, current[i], vo, vn);
            if (!same_value(p, target, after)) restore_value(p, lc, target);
            applied.push_back(p.name);
        }
        std::unordered_set<uintptr_t> visited{};
        for (const auto& k : kept) reflect_diff(k.o, 0, k.n, 0, k.l, type_of(k.l), k.path, 1, visited, applied, skipped);
    }
    add_ref(copy); // The copy component is never released: the new sub-objects are already referenced by the scene instance

    std::unordered_set<uintptr_t> kept_objs{};
    for (const auto& k : kept) kept_objs.insert(k.l);
    log("    %s: %s; sub-objects added %u / removed %u / kept %zu%s", label.c_str(), fresh ? "new component, all parameters written from the file" : "sub-object count changed, reread from the file",
        added, removed, kept_objs.size(), ok ? "" : " (read length differed or execution failed)");
    if (!applied.empty()) log("      Applied properties: %s", join(applied).c_str());
    if (!kept_runtime.empty()) log("      Unchanged properties keeping runtime values: %s", join(kept_runtime).c_str());
    if (!skipped.empty()) log("      Not written: %s", join(skipped).c_str());
    return 1;
}

// End of instance inst's data: the start of the next instance that reads data (or the end of the data area if none)
uint32_t inst_data_end(const RszWalk& w, int32_t inst) {
    for (size_t i = (size_t)inst + 1; i < w.inst_begin.size(); ++i) {
        if (w.inst_begin[i] != UINT32_MAX) return w.inst_begin[i];
    }
    return w.data_size;
}

// The complete data of the slot-th object of the object table (managed or native) together with its sub-objects: in RSZ, referenced instances come before their referrers,
// so it spans from the data end of the nearest object table object with a smaller instance index to the end of its own data
bool full_region(const RszWalk& w, int slot, uint32_t& start, uint32_t& end) {
    if (!w.ok || slot < 0 || (size_t)slot >= w.object_table.size()) return false;
    const auto inst = w.object_table[slot];
    if (inst <= 0 || (size_t)inst >= w.inst_begin.size()) return false;
    int32_t prev = 0;
    for (const auto k : w.object_table) {
        if (k < inst && k > prev) prev = k;
    }
    start = prev > 0 ? inst_data_end(w, prev) : 0;
    end = inst_data_end(w, inst);
    return end >= start && end <= w.data_size;
}

// Whether this object's data (including sub-objects) is identical in the old and new files; returns false when the range cannot be determined
bool same_full_data(const RszWalk& ow, int oi, const RszWalk& nw, int ni) {
    uint32_t os = 0, oe = 0, ns = 0, ne = 0;
    if (!full_region(ow, oi, os, oe) || !full_region(nw, ni, ns, ne)) return false;
    return oe - os == ne - ns && memcmp(ow.data + os, nw.data + ns, oe - os) == 0;
}

// Parameters of effect data elements (Scale/Color, etc.) are read only when effect instances are created; end the playing effects spawned from these elements' efx,
// and looped effects are requested again by the game next frame with the new parameters. Returns the number ended
uint32_t kill_effects_of(const std::unordered_set<uintptr_t>& providers) {
    if (providers.empty()) return 0;
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();
    static const auto get_res_count = tdb->find_method("via.effect.ProviderData", "getResourcesCount");
    static const auto get_res = tdb->find_method("via.effect.ProviderData", "getResources(System.UInt64)");
    static const auto get_scene = tdb->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = tdb->find_method("via.Scene", "findComponents(System.Type)");
    static const auto get_resource = tdb->find_method("via.effect.EffectPlayer", "get_Resource");
    static const auto set_action = tdb->find_method("via.effect.EffectPlayer", "set_Action(via.effect.PlayerAction)");
    if (!get_res_count || !get_res || !get_scene || !find_components || !get_resource || !set_action) return 0;

    std::unordered_set<uintptr_t> resources{};
    for (const auto p : providers) {
        const auto count = get_res_count->call<uint64_t>(vm, p);
        for (uint64_t r = 0; r < count && r < 64; ++r) {
            const auto holder = (uintptr_t)get_res->call<API::ManagedObject*>(vm, p, r);
            uintptr_t res = 0;
            if (holder != 0 && safe_read_ptr(holder + 0x10, res) && res != 0) resources.insert(res);
        }
    }
    if (resources.empty()) return 0;

    auto scene = get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager"));
    if (scene == nullptr) return 0;
    const auto arr = (uintptr_t)find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.effect.EffectPlayer"));
    if (arr == 0) return 0;

    constexpr uint32_t ACTION_KILL = 2; // via.effect.PlayerAction.Kill
    uint32_t killed = 0;
    const auto count = *(uint32_t*)(arr + ARRAY_COUNT);
    for (uint32_t i = 0; i < count; ++i) {
        const auto player = *(uintptr_t*)(arr + ARRAY_DATA + 8ull * i);
        if (player == 0) continue;
        const auto holder = (uintptr_t)get_resource->call<API::ManagedObject*>(vm, player);
        uintptr_t res = 0;
        if (holder == 0 || !safe_read_ptr(holder + 0x10, res) || !resources.contains(res)) continue;
        set_action->call<void>(vm, player, ACTION_KILL);
        ++killed;
    }
    return killed;
}
}

bool rsz_deserialize(const uint8_t* rsz, size_t size, std::vector<uintptr_t>& objects) {
    objects.clear();
    const auto fn = find_deserialize();
    if (fn == nullptr || size < 0x30 || *(const uint32_t*)rsz != RSZ_MAGIC) return false;
    const auto object_count = *(const uint32_t*)(rsz + RSZ_OBJECT_COUNT);
    if (object_count == 0 || object_count > 4096) return false;
    std::vector<uintptr_t> buffer(object_count + 1, 0);
    NativeArray arr{buffer.data(), object_count, object_count};
    if (!safe_deserialize(fn, &arr, rsz, size) || arr.data != buffer.data()) return false;
    objects.assign(buffer.begin(), buffer.begin() + object_count);
    return true;
}

void rsz_release(std::vector<uintptr_t>& objects) {
    for (auto o : objects) release(o);
    objects.clear();
}

uintptr_t rsz_engine_deserializer() {
    return (uintptr_t)find_deserialize();
}

// Content of a PrefabResource (IDA: written by the loader sub_14A4A5D90, freed by the destructor sub_14024DF10; it contains no pointer back to the resource object):
// +0x58 data +0x60 size, +0x68 dependent resource array {pointer, count/capacity, ready progress}, +0x80 userdata array {same}
constexpr uintptr_t PREFAB_CONTENT_BEGIN = 0x58;
constexpr uintptr_t PREFAB_CONTENT_END = 0x98;

bool PrefabLive::swap_content(uintptr_t a, uintptr_t b) {
    if (a == 0 || b == 0 || a == b || *(const uintptr_t*)a != *(const uintptr_t*)b) return false; // Same type (vtable)
    for (auto off = PREFAB_CONTENT_BEGIN; off < PREFAB_CONTENT_END; off += 8) {
        auto& x = *(volatile uint64_t*)(a + off);
        auto& y = *(volatile uint64_t*)(b + off);
        const uint64_t t = x;
        x = y;
        y = t;
    }
    return true;
}

// Child records are also kept across cores: the block holds {magic, root count}, then for each root {root GameObject, child count}, and for each child {GameObject, path length, path characters}
constexpr wchar_t SPAWN_CHILDREN_ENV[] = L"FILE_HOTRELOAD_SPAWN_CHILDREN";
constexpr uint32_t SPAWN_CHILDREN_MAGIC = 0x43505348; // "HSPC"

void save_spawn_children() {
    std::vector<uint8_t> data{};
    auto put = [&](const void* p, size_t n) { data.insert(data.end(), (const uint8_t*)p, (const uint8_t*)p + n); };
    const uint32_t magic = SPAWN_CHILDREN_MAGIC;
    uint32_t roots = 0;
    put(&magic, 4);
    put(&roots, 4);
    for (const auto& [root, children] : g_spawn_children) {
        if (!safe_is_managed(root) || !g_spawned.contains(root)) continue;
        const uint64_t r = root;
        const uint32_t n = (uint32_t)children.size();
        put(&r, 8);
        put(&n, 4);
        for (const auto& [path, go] : children) {
            const uint64_t g = go;
            const uint32_t len = (uint32_t)path.size();
            put(&g, 8);
            put(&len, 4);
            put(path.data(), path.size() * sizeof(wchar_t));
        }
        ++roots;
    }
    if (roots == 0) return;
    memcpy(data.data() + 4, &roots, 4);
    auto block = (uint8_t*)VirtualAlloc(nullptr, data.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (block == nullptr) return;
    memcpy(block, data.data(), data.size());
    wchar_t buf[32]{};
    swprintf_s(buf, L"%llx", (unsigned long long)(uintptr_t)block);
    SetEnvironmentVariableW(SPAWN_CHILDREN_ENV, buf);
}

uint32_t load_spawn_children() {
    wchar_t buf[32]{};
    if (GetEnvironmentVariableW(SPAWN_CHILDREN_ENV, buf, 32) == 0) return 0;
    SetEnvironmentVariableW(SPAWN_CHILDREN_ENV, nullptr);
    const auto block = (const uint8_t*)(uintptr_t)wcstoull(buf, nullptr, 16);
    MEMORY_BASIC_INFORMATION mbi{};
    if (block == nullptr || !VirtualQuery(block, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return 0;
    const auto end = (const uint8_t*)mbi.BaseAddress + mbi.RegionSize;
    auto p = block;
    auto get = [&](void* out, size_t n) {
        if (p + n > end) return false;
        memcpy(out, p, n);
        p += n;
        return true;
    };
    uint32_t magic = 0, roots = 0, loaded = 0;
    if (get(&magic, 4) && magic == SPAWN_CHILDREN_MAGIC && get(&roots, 4)) {
        std::lock_guard lock{g_track_mutex};
        for (uint32_t i = 0; i < roots; ++i) {
            uint64_t root = 0;
            uint32_t n = 0;
            if (!get(&root, 8) || !get(&n, 4)) break;
            ChildList children{};
            bool ok = true;
            for (uint32_t k = 0; k < n && ok; ++k) {
                uint64_t go = 0;
                uint32_t len = 0;
                std::wstring path{};
                ok = get(&go, 8) && get(&len, 4) && len < 4096;
                if (!ok) break;
                path.resize(len);
                ok = get(path.data(), len * sizeof(wchar_t));
                children.emplace_back(std::move(path), (uintptr_t)go);
            }
            if (!ok) break;
            if (g_spawned.contains((uintptr_t)root)) {
                g_spawn_children[(uintptr_t)root] = std::move(children);
                ++loaded;
            }
        }
    }
    VirtualFree((void*)block, 0, MEM_RELEASE);
    return loaded;
}

// Transform child chain offsets: the native implementations of via.Transform.get_Child/get_Next are mov rax, [rdx+imm8]; ret
uintptr_t accessor_offset(const char* type, const char* method) {
    const auto m = API::get()->tdb()->find_method(type, method);
    const auto fn = m != nullptr ? (const uint8_t*)m->get_function_raw() : nullptr;
    if (fn == nullptr || fn[0] != 0x48 || fn[1] != 0x8B || fn[2] != 0x42 || fn[4] != 0xC3) return 0;
    return fn[3];
}

// Spawn records survive core hot swaps: on unload they are written into a resident in-process memory block (address stored in a process environment variable), and the new core reads and frees it after hooking.
// Between two cores the hook is briefly removed (unload then load within the same frame); instances spawned meanwhile are not recorded
constexpr wchar_t SPAWN_ENV[] = L"FILE_HOTRELOAD_SPAWNED";
constexpr uint32_t SPAWN_MAGIC = 0x4E505348; // "HSPN"

struct SpawnBlock {
    uint32_t magic;
    uint32_t count;
    uintptr_t pairs[1][2]; // {root GameObject, PrefabResource}
};

void save_spawned() {
    std::vector<std::pair<uintptr_t, uintptr_t>> live{};
    for (const auto& [go, res] : g_spawned) {
        if (safe_is_managed(go)) live.emplace_back(go, res);
    }
    if (live.empty()) return;
    const auto size = sizeof(SpawnBlock) + sizeof(uintptr_t) * 2 * live.size();
    auto block = (SpawnBlock*)VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (block == nullptr) return;
    block->magic = SPAWN_MAGIC;
    block->count = (uint32_t)live.size();
    for (size_t i = 0; i < live.size(); ++i) {
        block->pairs[i][0] = live[i].first;
        block->pairs[i][1] = live[i].second;
    }
    wchar_t buf[32]{};
    swprintf_s(buf, L"%llx", (unsigned long long)(uintptr_t)block);
    SetEnvironmentVariableW(SPAWN_ENV, buf);
}

uint32_t load_spawned() {
    wchar_t buf[32]{};
    if (GetEnvironmentVariableW(SPAWN_ENV, buf, 32) == 0) return 0;
    SetEnvironmentVariableW(SPAWN_ENV, nullptr);
    const auto block = (SpawnBlock*)(uintptr_t)wcstoull(buf, nullptr, 16);
    uint32_t n = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    if (block != nullptr && VirtualQuery(block, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT && block->magic == SPAWN_MAGIC) {
        std::lock_guard lock{g_track_mutex};
        for (uint32_t i = 0; i < block->count; ++i) {
            if (!safe_is_managed(block->pairs[i][0])) continue;
            g_spawned.emplace(block->pairs[i][0], block->pairs[i][1]);
            ++n;
        }
        VirtualFree(block, 0, MEM_RELEASE);
    }
    return n;
}

void PrefabLive::install_tracking() {
    if (g_inst_target != 0) return;
    g_transform_child = accessor_offset("via.Transform", "get_Child");
    g_transform_next = accessor_offset("via.Transform", "get_Next");
    if (g_transform_child == 0 || g_transform_next == 0) log("Spawn records: could not get the child offsets from via.Transform.get_Child/get_Next, child objects are not recorded");
    const auto target = locate_instantiate();
    if (target == 0) {
        log("Spawn records: prefab instantiate function not found (prologue mismatch), not recording");
        return;
    }
    // Trampoline: the original function's first 19 bytes + jmp [rip] -> original function +19
    auto tramp = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (tramp == nullptr) return;
    memcpy(g_inst_saved, (const void*)target, PATCH_LEN);
    memcpy(tramp, g_inst_saved, PATCH_LEN);
    const uint8_t jmp_abs[6] = {0xFF, 0x25, 0, 0, 0, 0};
    memcpy(tramp + PATCH_LEN, jmp_abs, 6);
    *(uint64_t*)(tramp + PATCH_LEN + 6) = target + PATCH_LEN;
    FlushInstructionCache(GetCurrentProcess(), tramp, 64);
    g_inst_tramp = tramp;
    // Original function start: jmp [rip] -> instantiate_detour, the rest padded with nop
    uint8_t patch[PATCH_LEN]{};
    memcpy(patch, jmp_abs, 6);
    *(uint64_t*)(patch + 6) = (uint64_t)&instantiate_detour;
    memset(patch + 14, 0x90, PATCH_LEN - 14);
    if (!patch_entry(target, patch)) {
        log("Spawn records: cannot patch the instantiate function");
        return;
    }
    g_inst_target = target;
    log("Spawn records: hooked prefab instantiate function +%llx", (unsigned long long)(target - (uintptr_t)GetModuleHandleW(nullptr)));
    if (const auto n = load_spawned()) log("Spawn records: reusing %u spawn records from the previous core", n);
    if (const auto n = load_spawn_children()) log("Spawn records: reusing %u child object records from the previous core", n);
}

void PrefabLive::uninstall_tracking() {
    if (g_inst_target != 0) {
        patch_entry(g_inst_target, g_inst_saved);
        g_inst_target = 0;
        // Wait for threads inside the handler to leave (the core is about to be unloaded); the trampoline is not freed since threads may still be in it
        for (int i = 0; i < 1000 && g_inst_inflight.load() > 0; ++i) Sleep(1);
    }
    std::lock_guard lock{g_track_mutex};
    save_spawn_children();
    save_spawned();
    g_spawned.clear();
    g_spawn_children.clear();
}


namespace {
// ---- Structure changes: add/remove GameObjects/components on scene instances ----

API::Method* find_method_n(const char* type_name, const char* name, uint32_t params) {
    const auto td = API::get()->tdb()->find_type(type_name);
    if (td == nullptr) return nullptr;
    for (const auto m : td->get_methods()) {
        if (m != nullptr && m->get_num_params() == params && std::string_view{m->get_name()} == name) return m;
    }
    return nullptr;
}

uintptr_t invoke_ptr(API::Method* m, uintptr_t obj, std::initializer_list<void*> args) {
    if (m == nullptr) return 0;
    std::vector<void*> a(args);
    reframework::InvokeRet r{};
    if (!safe_invoke(m, obj, a.empty() ? nullptr : a.data(), (unsigned)(a.size() * sizeof(void*)), &r)) return 0;
    return (uintptr_t)r.ptr;
}

bool invoke_void(API::Method* m, uintptr_t obj, std::initializer_list<void*> args) {
    if (m == nullptr) return false;
    std::vector<void*> a(args);
    reframework::InvokeRet r{};
    return safe_invoke(m, obj, a.empty() ? nullptr : a.data(), (unsigned)(a.size() * sizeof(void*)), &r);
}

// Children not found by name path in the instance hierarchy: use the record from instantiation time (the game may have moved them elsewhere later).
// The recorded object must still be a valid GameObject whose name equals the last segment of the path
uint32_t add_moved_children(uintptr_t root, std::unordered_map<std::wstring, uintptr_t>& live) {
    ChildList rec{};
    {
        std::lock_guard lock{g_track_mutex};
        const auto it = g_spawn_children.find(root);
        if (it == g_spawn_children.end()) return 0;
        rec = it->second;
    }
    static const auto get_valid = find_method_n("via.GameObject", "get_Valid", 0);
    uint32_t n = 0;
    for (const auto& [path, go] : rec) {
        if (live.contains(path) || !safe_is_managed(go) || type_of(go) == nullptr || name_of(type_of(go)) != "via.GameObject") continue;
        const auto slash = path.rfind(L'/');
        const auto last = path.substr(slash == std::wstring::npos ? 0 : slash + 1);
        const auto hash = last.rfind(L'#');
        const auto name = game_object_name(go);
        if (name != last && (hash == std::wstring::npos || name != last.substr(0, hash))) continue;
        if (get_valid != nullptr && (invoke_ptr(get_valid, go, {}) & 0xFF) == 0) continue;
        live[path] = go;
        ++n;
    }
    return n;
}

uintptr_t transform_of(uintptr_t go) {
    static const auto m = find_method_n("via.GameObject", "get_Transform", 0);
    return invoke_ptr(m, go, {});
}

// Create a GameObject named name under parent (in the same Folder as parent); its local coordinates are then written from the Transform data
uintptr_t create_child_go(const std::wstring& name, uintptr_t parent) {
    static const auto get_folder = find_method_n("via.GameObject", "get_Folder", 0);
    static const auto create = find_method_n("via.GameObject", "create", 2);
    static const auto set_parent = find_method_n("via.Transform", "setParent", 2);
    const auto folder = invoke_ptr(get_folder, parent, {});
    const auto str = (void*)API::get()->sdk()->functions->create_managed_string(name.c_str());
    const auto go = invoke_ptr(create, 0, {str, (void*)folder});
    if (go == 0) return 0;
    const auto t = transform_of(go);
    const auto pt = transform_of(parent);
    if (t == 0 || pt == 0 || !invoke_void(set_parent, t, {(void*)pt, (void*)(uintptr_t)0})) {
        log("    %s: created but cannot be attached under its parent", narrow(name).c_str());
    }
    return go;
}

bool destroy_go(uintptr_t go) {
    static const auto m = find_method_n("via.GameObject", "destroy", 1);
    return invoke_void(m, 0, {(void*)go});
}

bool destroy_component(uintptr_t comp) {
    static const auto m = find_method_n("via.Component", "destroy", 1);
    return invoke_void(m, 0, {(void*)comp});
}

int path_depth(const std::wstring& path) {
    return path.empty() ? 0 : 1 + (int)std::count(path.begin(), path.end(), L'/');
}

// ---- GameObjectRef info table (pfb header goref table) ----
// After deserialization, the engine's instantiation (sub_14A4A5860) handles each table entry: it creates a runtime reference ID from the target GameObject (sub_14007FA90,
// the same function as the native implementation of via.Scene.createRefId), then writes it through the holder type's reflected variable setter (indexed variables get the array index).
// GameObjectRef fields in RSZ data only store the raw GUID, so after creating/rewriting such fields they must be resolved again from the table.
// Entries handled: the holder was newly created this time; the entry is new or its target path changed; the field's raw value differs between the old/new copies (the raw GUID in the file was written into the data).
// Entries in the old file but not in the new one: as with a fresh instantiation, the field takes the raw value from the file.

constexpr uint32_t GOREF_ID_SIZE = 16;

struct RefVar {
    uintptr_t desc{};
    uint32_t flags{};
    ReflAccessor get{};
    ReflAccessor set{};
    bool indexed{};
    bool by_pointer{};
    std::string name;
};

// Same tests as the engine's instantiate function: +0x0C bit2 read-only; bit1 indexed; setter = getter + [desc+0x3C]
bool ref_var(uintptr_t obj, uint32_t prop, RefVar& v) {
    v = {};
    v.desc = rsz_variable_by_id(obj, prop);
    uintptr_t head = 0, getter = 0, info = 0, tail = 0, name = 0;
    if (v.desc == 0 || !safe_read_ptr(v.desc, name) || !safe_read_ptr(v.desc + 0x08, head) || !safe_read_ptr(v.desc + 0x10, getter) ||
        !safe_read_ptr(v.desc + 0x18, info) || !safe_read_ptr(v.desc + 0x38, tail)) {
        return false;
    }
    v.flags = (uint32_t)(head >> 32);
    v.name = read_cstr(name);
    if ((v.flags & 4) != 0) return false;
    v.get = (ReflAccessor)getter;
    v.set = (ReflAccessor)(getter + (intptr_t)(int32_t)(tail >> 32));
    v.indexed = (v.flags & 6) == 2 || (getter != 0 && (v.flags & 2) != 0);
    v.by_pointer = (((uint32_t)info >> 7) & 7) == REFL_PASS_POINTER;
    return true;
}

bool read_ref_var(const RefVar& v, uintptr_t obj, int index, uint8_t* out) {
    alignas(16) std::array<uint8_t, MAX_PROP_SIZE + 16> buf{};
    if (v.get == nullptr) return false;
    const bool ok = v.indexed ? safe_reflect_at((ReflIndexed)v.get, v.desc, obj, buf.data(), (uint64_t)index) : safe_reflect(v.get, v.desc, obj, buf.data());
    if (!ok) return false;
    if (!v.by_pointer) {
        memcpy(out, buf.data(), GOREF_ID_SIZE);
        return true;
    }
    uintptr_t src = 0;
    memcpy(&src, buf.data(), 8);
    return src >= 0x10000 && safe_copy_from(out, src, GOREF_ID_SIZE);
}

bool write_ref_var(const RefVar& v, uintptr_t obj, int index, const uint8_t* value) {
    alignas(16) std::array<uint8_t, MAX_PROP_SIZE + 16> buf{};
    memcpy(buf.data(), value, GOREF_ID_SIZE);
    return v.indexed ? safe_reflect_at((ReflIndexed)v.set, v.desc, obj, buf.data(), (uint64_t)index) : safe_reflect(v.set, v.desc, obj, buf.data());
}

uintptr_t current_scene() {
    const auto& api = API::get();
    static const auto get_scene = api->tdb()->find_method("via.SceneManager", "get_CurrentScene");
    return get_scene ? (uintptr_t)get_scene->call<API::ManagedObject*>(api->get_vm_context(), api->get_native_singleton("via.SceneManager")) : 0;
}

// Runtime reference ID of the target GameObject (via.Scene.createRefId)
bool make_ref_id(uintptr_t go, uint8_t* out) {
    static const auto m = find_method_n("via.Scene", "createRefId", 1);
    const auto scene = current_scene();
    if (m == nullptr || scene == 0 || go == 0) return false;
    void* args[1]{(void*)go};
    reframework::InvokeRet r{};
    if (!safe_invoke(m, scene, args, sizeof(args), &r) || r.exception_thrown) return false;
    memcpy(out, r.bytes.data(), GOREF_ID_SIZE);
    for (uint32_t i = 0; i < GOREF_ID_SIZE; ++i) {
        if (out[i] != 0) return true;
    }
    return false;
}

uint32_t apply_gorefs(const PrefabTree& old_tree, const PrefabTree& new_tree, const CorrMap& corr,
                      const std::unordered_map<std::wstring, uintptr_t>& live, const std::unordered_map<int, std::wstring>& old_go_path,
                      const std::unordered_map<int, std::wstring>& new_go_path, const std::function<std::string(const std::wstring&)>& label_of) {
    // Display name of the holder: GameObject path:type for components
    std::unordered_map<uintptr_t, std::string> holder_label{};
    for (const auto& go : new_tree.gos) {
        for (const auto c : go.components) holder_label[c] = label_of(go.path) + ":" + name_of(type_of(c));
    }
    auto label = [&](uintptr_t n, const RefVar& v, int index) {
        const auto it = holder_label.find(n);
        auto s = it != holder_label.end() ? it->second : name_of(type_of(n));
        s += "." + (v.name.empty() ? std::string{"?"} : v.name);
        if (v.indexed) s += "[" + std::to_string(index) + "]";
        return s;
    };

    // Old copy object -> new copy object
    std::unordered_map<uintptr_t, uintptr_t> old_to_new{};
    for (const auto& [n, c] : corr) {
        if (c.old_obj != 0) old_to_new.emplace(c.old_obj, n);
    }
    using Key = std::tuple<uintptr_t, uint32_t, int>; // New copy holder, property id, index
    std::map<Key, std::wstring> old_entries{};
    for (const auto& g : old_tree.gorefs) {
        const auto it = old_to_new.find(old_tree.objects[g.object]);
        const auto pit = old_go_path.find(g.target);
        if (it == old_to_new.end() || pit == old_go_path.end()) continue;
        old_entries[{it->second, g.prop, g.index}] = pit->second;
    }

    uint32_t applied = 0;
    std::set<Key> new_keys{};
    for (const auto& g : new_tree.gorefs) {
        const auto n = new_tree.objects[g.object];
        const Key key{n, g.prop, g.index};
        new_keys.insert(key);
        const auto cit = corr.find(n);
        RefVar v{};
        if (cit == corr.end()) {
            if (ref_var(n, g.prop, v)) log("    %s: holder of the GameObjectRef not found in the scene instance, skipped", label(n, v, g.index).c_str());
            continue;
        }
        const auto& c = cit->second;
        if (!ref_var(c.live, g.prop, v)) {
            log("    %s: no writable reflected variable for GameObjectRef property 0x%x, skipped", name_of(type_of(c.live)).c_str(), g.prop);
            continue;
        }
        const auto pit = new_go_path.find(g.target);
        const auto oit = old_entries.find(key);
        uint8_t raw_o[GOREF_ID_SIZE]{}, raw_n[GOREF_ID_SIZE]{};
        RefVar vo{}, vn{};
        const bool raw_changed = c.old_obj == 0 || !ref_var(c.old_obj, g.prop, vo) || !ref_var(n, g.prop, vn) ||
                                 !read_ref_var(vo, c.old_obj, g.index, raw_o) || !read_ref_var(vn, n, g.index, raw_n) ||
                                 memcmp(raw_o, raw_n, GOREF_ID_SIZE) != 0;
        const char* reason = c.fresh                                                        ? "new object"
                             : oit == old_entries.end()                                     ? "new reference"
                             : (pit != new_go_path.end() && oit->second != pit->second)     ? "target changed"
                             : raw_changed                                                  ? "field data changed"
                                                                                            : nullptr;
        if (reason == nullptr) continue; // File unchanged: keep the runtime reference
        const auto& target_path = pit != new_go_path.end() ? pit->second : std::wstring{};
        const auto lit = pit != new_go_path.end() ? live.find(target_path) : live.end();
        if (lit == live.end()) {
            log("    %s: target GameObject %s not found in the scene instance, skipped", label(n, v, g.index).c_str(), label_of(target_path).c_str());
            continue;
        }
        uint8_t id[GOREF_ID_SIZE]{};
        if (!make_ref_id(lit->second, id)) {
            log("    %s: cannot generate a reference ID for %s", label(n, v, g.index).c_str(), label_of(target_path).c_str());
            continue;
        }
        uint8_t now[GOREF_ID_SIZE]{};
        const bool ok = write_ref_var(v, c.live, g.index, id) && read_ref_var(v, c.live, g.index, now) && memcmp(now, id, GOREF_ID_SIZE) == 0;
        log("    %s: GameObjectRef -> %s (%s)%s", label(n, v, g.index).c_str(), label_of(target_path).c_str(), reason, ok ? "" : ", write failed");
        if (ok) ++applied;
    }

    // Entries in the old file but not in the new one: the field takes the raw value from the file
    for (const auto& [key, path] : old_entries) {
        if (new_keys.contains(key)) continue;
        const auto [n, prop, index] = key;
        const auto cit = corr.find(n);
        RefVar v{}, vn{};
        if (cit == corr.end() || !ref_var(cit->second.live, prop, v) || !ref_var(n, prop, vn)) continue;
        uint8_t raw[GOREF_ID_SIZE]{};
        const bool ok = read_ref_var(vn, n, index, raw) && write_ref_var(v, cit->second.live, index, raw);
        log("    %s: removed from the GameObjectRef table (previous target %s), %s", label(n, v, index).c_str(), label_of(path).c_str(),
            ok ? "raw value from the file written" : "write failed");
        if (ok) ++applied;
    }
    return applied;
}

// ---- New components: same as engine instantiation, first get a component object with complete data from RSZ deserialization, then attach it to the GameObject ----
// via.GameObject.createComponent is not used: it calls the component's callbacks right after attaching, before the serialized data is written,
// so components whose initialization depends on the data (e.g. app.Tamagusari's Parameter) fail to initialize but stay on the GameObject, and then crash in update.
constexpr uintptr_t GO_FIRST_COMPONENT = 0x18; // GameObject -> first component (Transform)
constexpr uintptr_t COMPONENT_NEXT = 0x18;     // Component -> next component of the same GameObject
constexpr uintptr_t COMPONENT_OWNER = 0x10;    // Component -> owning GameObject

uintptr_t g_last_exception_address{};
uint32_t g_last_exception_code{};

int record_exception(EXCEPTION_POINTERS* ep) {
    g_last_exception_address = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
    g_last_exception_code = ep->ExceptionRecord->ExceptionCode;
    return read_fault_filter(ep);
}

bool safe_set_components(SetComponentsFn fn, uintptr_t go, uintptr_t scene, uintptr_t* comps, uint64_t n) {
    __try {
        fn(go, scene, comps, n);
        return true;
    } __except (record_exception(GetExceptionInformation())) {
        log("    Component attach function exception %08x at exe+%llx", g_last_exception_code,
            (unsigned long long)(g_last_exception_address - (uintptr_t)GetModuleHandleW(nullptr)));
        return false;
    }
}

// Component message virtual function (+0x50 on 1.42.0.3; the offset is taken from machine code by check_layout): called with L"awake" after createComponent attaches,
// behavior components whose awake has not run (awake flag 0) run awake at that point
using ComponentMessageFn = void (*)(uintptr_t, const wchar_t*);

bool send_awake(uintptr_t comp) {
    const auto off = g_component_message_off;
    if (off < 0) return false;
    __try {
        const auto vt = *(const uintptr_t*)comp;
        ((ComponentMessageFn) * (const uintptr_t*)(vt + off))(comp, L"awake");
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

// Append the unattached component object comp to GameObject go in the scene (calling the engine's component attach function with "existing components + comp")
bool attach_component(uintptr_t go, uintptr_t comp) {
    const auto fn = locate_set_components();
    const auto scene = current_scene();
    if (fn == nullptr || scene == 0 || go == 0 || comp == 0) return false;
    std::vector<uintptr_t> list{};
    uintptr_t c = 0;
    if (!safe_read_ptr(go + GO_FIRST_COMPONENT, c)) return false;
    for (int i = 0; c != 0 && i < 1024; ++i) {
        if (c == comp) return false;
        list.push_back(c);
        if (!safe_read_ptr(c + COMPONENT_NEXT, c)) return false;
    }
    if (list.empty() || c != 0) return false;
    list.push_back(comp);
    if (!safe_set_components(fn, go, scene, list.data(), list.size())) return false;
    uintptr_t owner = 0;
    return safe_read_ptr(comp + COMPONENT_OWNER, owner) && owner == go;
}

// ---- Component rebuild: existing components whose file data changed are rebuilt from the new file ----
// The engine's component attach function resets the component chain to the given list (IDA sub_1401C1B40):
// - Old components not in the list: removed through virtual function +0x48 (behavior components unregister from the behavior manager; awake ones get onDestroy through a VM call, sub_156012B20),
//   the owning GameObject (+0x10) is cleared, they are unregistered from the scene (sub_140047E40) and their reference released
// - New components: registered with the scene (sub_14A48EA20), a reference added, and finally virtual function +0x40 called (behavior components set +0x30 pending start, +0x31 pending awake and register with the behavior manager)
// The replacement takes two steps:
// 1. This frame: the old component is handed to the engine for deferred destruction through via.Component.destroy (a reference is added when queued; removal, including onDestroy, runs at a safe time); the new component is already prepared in the copy
// 2. Once the old component is detached (owning GameObject cleared): attach the new component with the attach function in the order "old component replaced by the new one in the original chain" and send awake; start is called by the engine on its next update
// - The old component cannot be removed directly this frame: parallel tasks already started this frame (e.g. the GpuCloth update, IDA sub_14A558A00) still work on the component list cached at the start of the frame, which crashed in testing
// - The new component cannot be attached before destroying the old one: the new component sees the state left by the old one when it initializes. Observed with via.render.Mesh: the Transform's joints are created by the Mesh,
//   so when the new Mesh attaches the joints already exist (not created again), and when the old Mesh is detached it removes the joints with it, leaving the mesh frozen in place;
//   via.motion.Chain2 looking up the same GameObject's CollisionShapePreset by type gets the old component
// In between, the component is absent for about one frame (mesh not shown, collision not active)

// Correspondence of data sub-objects before and after the rebuild (afterwards references in other objects to the old sub-objects are repointed to the new ones, e.g. Motion layers cached by the game):
// native components match by the index of object reference reflected variables, only when the types agree; managed components match by serialized field position with Differ::correspond
void native_sub_pairs(uintptr_t o, uintptr_t n, API::TypeDefinition* td, int depth, std::vector<std::pair<uintptr_t, uintptr_t>>& out,
                      std::unordered_set<uintptr_t>& seen) {
    if (o == 0 || n == 0 || td == nullptr || depth > 3) return;
    std::vector<uintptr_t> so{}, sn{};
    for (const auto& op : obj_props_of(td)) {
        if (!read_objs(op, o, so) || !read_objs(op, n, sn)) continue;
        for (size_t i = 0; i < so.size() && i < sn.size(); ++i) {
            const auto t = type_of(so[i]);
            if (t == nullptr || so[i] == sn[i] || type_of(sn[i]) != t || is_scene_object(t) || is_userdata(t) || !seen.insert(so[i]).second) continue;
            out.emplace_back(so[i], sn[i]);
            native_sub_pairs(so[i], sn[i], t, depth + 1, out, seen);
        }
    }
}

// Elements (via.effect.ProviderData) of EPV effect data components. Element parameters are read only when effect instances are created:
// on rebuild, end the playing effects spawned from the old elements' efx; looped effects are requested again by the game next frame with the new parameters
constexpr const char* EPV_DATA_TYPE = "via.effect.script.EPVDataBase";

std::unordered_set<uintptr_t> epv_elements(uintptr_t comp, API::TypeDefinition* td) {
    std::unordered_set<uintptr_t> out{};
    if (!is_a(td, EPV_DATA_TYPE)) return out;
    const auto count_m = td->find_method("getElementCount");
    const auto get_m = td->find_method("getElement(System.UInt32)");
    if (count_m == nullptr || get_m == nullptr) return out;
    const auto n = (uint32_t)invoke_ptr(count_m, comp, {});
    for (uint32_t i = 0; i < n && i < 4096; ++i) {
        if (const auto e = invoke_ptr(get_m, comp, {(void*)(uintptr_t)i})) out.insert(e);
    }
    return out;
}

// ---- Derived fields of EPV effect data ----
// awake of app.EPVExpertCommonData:
// - updateElementOwner: when the element count differs from ElementNumOld, set Owner on elements whose Owner is null and update ElementNumOld
// - setupElements: TypeID_Fixed/CategoryID_Fixed -> _TypeID/_CategoryID, each element's ElementID_Fixed -> _ElementID,
//   GroupNameParameters -> _GroupNames
// Existing components only get the file-changed fields written, so these values computed by awake would not update. Only when their inputs are changed by the file is the component's own awake called to recompute them
// (observed 2026-10-23 that it can be called repeatedly: after appending an element, the new element's Owner/_ElementID/_GroupNames are correct and existing elements unchanged; restored at the user's request on 2026-11-11)
template <typename T> bool field_of(uintptr_t obj, const char* name, T& out) {
    if (obj == 0) return false;
    const auto p = ((API::ManagedObject*)obj)->get_field<T>(name);
    if (p == nullptr) return false;
    out = *p;
    return true;
}

// Elements of System.Collections.Generic.List`1 (reference types)
std::vector<uintptr_t> list_items(uintptr_t list) {
    std::vector<uintptr_t> out{};
    uintptr_t items = 0;
    int32_t size = 0;
    if (!field_of(list, "_items", items) || !field_of(list, "_size", size) || items == 0 || size <= 0) return out;
    const auto cap = *(const uint32_t*)(items + ARRAY_COUNT);
    for (int32_t i = 0; i < size && (uint32_t)i < cap; ++i) out.push_back(*(const uintptr_t*)(items + ARRAY_DATA + 8ull * i));
    return out;
}

template <typename T> bool field_differs(uintptr_t a, uintptr_t b, const char* name) {
    T x{}, y{};
    const bool ha = field_of(a, name, x), hb = field_of(b, name, y);
    return ha != hb || (ha && x != y);
}

bool group_params_differ(uintptr_t a, uintptr_t b) {
    uintptr_t la = 0, lb = 0;
    field_of(a, "GroupNameParameters", la);
    field_of(b, "GroupNameParameters", lb);
    const auto ia = list_items(la), ib = list_items(lb);
    if (ia.size() != ib.size()) return true;
    for (size_t i = 0; i < ia.size(); ++i) {
        if (field_differs<bool>(ia[i], ib[i], "Enable")) return true;
        for (const auto name : {"GroupNameLv0", "GroupNameLv1"}) {
            uintptr_t sa = 0, sb = 0;
            field_of(ia[i], name, sa);
            field_of(ib[i], name, sb);
            if (read_string(sa) != read_string(sb)) return true;
        }
    }
    return false;
}

// Whether awake input fields differ between the old/new copies
bool epv_inputs_changed(uintptr_t oc, uintptr_t nc, API::TypeDefinition* td) {
    if (oc == 0 || nc == 0 || !is_a(td, EPV_DATA_TYPE)) return false;
    const auto count_m = td->find_method("getElementCount");
    const auto get_m = td->find_method("getElement(System.UInt32)");
    if (count_m == nullptr || get_m == nullptr) return false;
    const auto n = (uint32_t)invoke_ptr(count_m, oc, {});
    if (n != (uint32_t)invoke_ptr(count_m, nc, {})) return true;
    if (field_differs<int32_t>(oc, nc, "TypeID_Fixed") || field_differs<int32_t>(oc, nc, "CategoryID_Fixed")) return true;
    for (uint32_t i = 0; i < n && i < 4096; ++i) {
        const auto eo = invoke_ptr(get_m, oc, {(void*)(uintptr_t)i});
        const auto en = invoke_ptr(get_m, nc, {(void*)(uintptr_t)i});
        if (field_differs<int32_t>(eo, en, "ElementID_Fixed") || group_params_differ(eo, en)) return true;
    }
    return false;
}

// Call the awake method of the component type (including parents) (a component that already received the awake message will not run it again, so the method is called directly)
bool invoke_awake(uintptr_t comp, API::TypeDefinition* td) {
    for (auto t = td; t != nullptr; t = t->get_parent_type()) {
        for (const auto m : t->get_methods()) {
            if (m != nullptr && !m->is_static() && m->get_num_params() == 0 && std::string_view{m->get_name()} == "awake") {
                return invoke_void(m, comp, {});
            }
        }
    }
    return false;
}

// Native components that are held and can only be written property by property: some setters only store the value and use it only after a reset (e.g. CollisionShapePreset.set_Enabled only writes +0x92).
// If the type (including parents) has a parameterless reset(), it is called once after writing any change (reset only sets a request flag; the engine rebuilds internal data from the current values on its next update,
// and the component object is unchanged). User's choice on 2026-11-11: no per-property list; any type with reset() is reset after a write (except k_no_reset_types); chains/cloth/IK return to their rest pose on reset.
// Tested 2026-11-11 with training-area equipment, the field and the base camp (test code since removed):
// - Need reset to take effect: CollisionShapePreset Enabled/Priority/UseGlobalShape, GpuCloth AsyncEnabled/OverwriteRestLength
//   (Chain2.EnableGroupTagHash does too, but it is not a pfb serialized field, so the file cannot change it)
// - Types not reset: a control group (values kept when reset is not called) confirmed that reset reverts the parameters just written — IkLeg2 (51 on the player, 33 on base camp NPCs;
//   not on field NPCs), Ragdoll damping (player), IkMultiBone.IsDepthOrder (player and monsters), RetargetRig left/right foot IK scale, 8 of IkWagon (gimmick Gm401).
//   These components compute from the stored values every frame, so not resetting does not affect the result
const char* const k_no_reset_types[] = {"via.motion.IkLeg2", "via.dynamics.Ragdoll", "via.motion.IkMultiBone", "via.motion.RetargetRig",
                                        "via.motion.IkWagon"};

void reset_after_write(uintptr_t comp, API::TypeDefinition* td, const std::string& label) {
    for (const auto t : k_no_reset_types) {
        if (is_a(td, t)) return;
    }
    static std::unordered_map<API::TypeDefinition*, API::Method*> cache{};
    auto it = cache.find(td);
    if (it == cache.end()) {
        API::Method* m = nullptr; // reset() may be defined in a parent class (Chain2 and others derive from via.motion.SecondaryAnimation)
        for (auto t = td; t != nullptr && m == nullptr; t = t->get_parent_type()) {
            for (const auto x : t->get_methods()) {
                if (x != nullptr && !x->is_static() && x->get_num_params() == 0 && std::string_view{x->get_name()} == "reset") {
                    m = x;
                    break;
                }
            }
        }
        it = cache.emplace(td, m).first;
    }
    if (it->second == nullptr) return;
    const bool ok = invoke_void(it->second, comp, {});
    log("    %s: reset() called so the written parameters take effect%s", label.c_str(), ok ? "" : " (execution error)");
}

// Native components held by game code (a managed object other than scene objects holds a reference to them): not rebuilt; file-changed parameters are written in place (determined by the caller's reference scan)
const std::unordered_set<uintptr_t>* g_in_place{};

// ---- Keeping runtime values after rebuilds ----
// Rebuilt components are initialized from the file. When a property's runtime value before the rebuild differs from its value after initialization and the file did not change the property (old/new copies the same), the runtime value is written back with the setter
// (e.g. Enabled turned off by the game at runtime). Compared against the value after initialization: values derived during initialization from the same data are not written back. Indexed properties are handled element by element.
// Native components are handled right after awake; behavior components (via.Behavior) after the engine runs start (start flag 0).
// Managed components only have their native ancestor part's reflected properties handled: managed serialized fields may hold state derived during initialization and are not written back
constexpr uint32_t RESTORE_WAIT_FRAMES = 120;

// The behavior component's start has run (returns false if the offset did not pass verification)
bool behavior_started(uintptr_t comp) {
    uintptr_t v = 0;
    return g_behavior_start_off >= 0 && safe_read_ptr(comp + (uint32_t)g_behavior_start_off, v) && (v & 0xFF) == 0;
}

struct RestoreJob {
    uintptr_t comp{};
    std::string label;
    std::vector<NativeProp> props;
    std::vector<PropValue> runtime, file_old, file_new;
    // String/resource path properties (TDB get/set): the game also changes these at runtime, e.g. the player's CustomSkeleton skeleton resource is switched from the male skeleton in the file to the female one,
    // and without writing it back after a rebuild the joints specific to the female skeleton are lost (observed: 4 Bust_HJ)
    const std::vector<TextProp>* tprops{};
    std::vector<TextValue> text_runtime, text_old, text_new;
    bool wait_start{};
    uint32_t frames{};
};

// For managed types take the string/resource path properties of the nearest native ancestor (consistent with restore_props)
const std::vector<TextProp>& restore_text_props(API::TypeDefinition* td) {
    static const std::vector<TextProp> none{};
    auto t = td;
    while (t != nullptr && fieldptr_base(t) != 0) t = t->get_parent_type();
    return t != nullptr ? text_props_of(t) : none;
}

std::vector<TextValue> read_texts(const std::vector<TextProp>* tprops, uintptr_t obj) {
    std::vector<TextValue> out{};
    if (tprops == nullptr || obj == 0) return out;
    for (const auto& p : *tprops) out.push_back(read_text(p, obj));
    return out;
}
std::vector<RestoreJob> g_restores{};

// The reflected variable table of a managed type also includes managed fields (e.g. ace.MeshSettingCore's _IsStart), so only the reflected variables of the nearest native ancestor (e.g. via.Behavior) are taken
std::vector<NativeProp> restore_props(API::TypeDefinition* td) {
    auto t = td;
    while (t != nullptr && fieldptr_base(t) != 0) t = t->get_parent_type();
    if (t == nullptr) return {};
    std::vector<NativeProp> out{};
    for (const auto& p : props_of(t)) {
        if (t == td || p.desc != 0) out.push_back(p);
    }
    return out;
}

// The component object (after the object header) read as 8-byte words, used to judge whether a setter changed internal arrays
std::vector<uint64_t> object_words(uintptr_t obj, uint32_t size) {
    constexpr uint32_t HEADER = 0x30, MAX_SIZE = 0x4000;
    std::vector<uint64_t> out{};
    if (size <= HEADER) return out;
    out.resize((std::min(size, MAX_SIZE) - HEADER) / 8);
    if (!safe_copy_from(out.data(), obj + HEADER, (uint32_t)(out.size() * 8))) out.clear();
    return out;
}

bool pointer_like(uint64_t v) {
    return v >= 0x10000 && v < 0x00007FFFFFFFFFFFull && (v & 7) == 0;
}

// Structural gaps caused by a write-back: a setter changed an engine array {data pointer, u32 count, u32 capacity} inside the object (pointer or count changed) and the array has null elements.
// E.g. FiltersCount of via.navigation.NavigationSurface: it only resizes the filter array to the runtime count, the new positions have no filter objects,
// and worker threads crash on a null pointer when walking it (observed). Setters that only change pointers without leaving gaps (e.g. Enabled registering/unregistering render objects) do not count
bool leaves_null_elements(const std::vector<uint64_t>& before, const std::vector<uint64_t>& after) {
    constexpr uint32_t MAX_ELEMENTS = 65536;
    if (before.size() != after.size()) return true;
    for (size_t i = 0; i + 1 < after.size(); ++i) {
        if (before[i] == after[i] && before[i + 1] == after[i + 1]) continue;
        const auto data = after[i];
        const auto count = (uint32_t)after[i + 1], capacity = (uint32_t)(after[i + 1] >> 32);
        if (!pointer_like(data) || count == 0 || count > capacity || capacity > MAX_ELEMENTS) continue;
        std::vector<uint64_t> items(count);
        if (!safe_copy_from(items.data(), (uintptr_t)data, count * 8)) continue;
        if (std::find(items.begin(), items.end(), 0ull) != items.end()) return true;
    }
    return false;
}

// Structure of a component: element counts of all indexed reflected variables, and objects pointed to by object reference variables
struct CountVar {
    uintptr_t desc{};
    ReflAccessor rcount{};
};

const std::vector<CountVar>& count_vars_of(API::TypeDefinition* td) {
    static std::unordered_map<API::TypeDefinition*, std::vector<CountVar>> cache{};
    if (const auto it = cache.find(td); it != cache.end()) return it->second;
    auto& out = cache[td];
    for (auto t = td; t != nullptr; t = t->get_parent_type()) {
        const auto fields = rsz_field_list((uintptr_t)t->get_type_info());
        uintptr_t vars = 0, data = 0, num = 0;
        if (fields == 0 || !safe_read_ptr(fields + FIELDLIST_VARIABLES, vars) || vars == 0 || !safe_read_ptr(vars + 0x08, data) ||
            !safe_read_ptr(vars + 0x10, num) || data == 0) {
            continue;
        }
        for (uint32_t i = 0; i < (uint32_t)num && i < 4096; ++i) {
            uintptr_t d = 0, head = 0, getter = 0, ext = 0;
            if (!safe_read_ptr(data + 8ull * i, d) || d == 0 || !safe_read_ptr(d + 0x08, head) || !safe_read_ptr(d + 0x10, getter) ||
                !safe_read_ptr(d + 0x40, ext) || getter == 0) {
                continue;
            }
            const auto count_off = (int32_t)(uint32_t)ext;
            if ((((uint32_t)(head >> 32)) & 2) == 0 || count_off == 0) continue;
            out.push_back({d, (ReflAccessor)(getter + (intptr_t)count_off)});
        }
    }
    return out;
}

std::vector<uint64_t> structure_of(API::TypeDefinition* td, uintptr_t obj) {
    std::vector<uint64_t> out{};
    if (td == nullptr) return out;
    for (const auto& v : count_vars_of(td)) {
        uint64_t count = 0;
        out.push_back(safe_reflect(v.rcount, v.desc, obj, &count) ? count : ~0ull);
    }
    for (const auto& op : obj_props_of(td)) {
        if (op.indexed) continue; // Element counts are already above
        uintptr_t v = 0;
        out.push_back(safe_reflect(op.rget, op.desc, obj, &v) ? v : ~0ull);
    }
    return out;
}

void run_restore(const RestoreJob& j) {
    const auto after = snapshot(j.props, j.comp);
    const auto td = type_of(j.comp);
    const uint32_t size = td ? td->get_size() : 0;
    std::vector<std::string> kept{}, failed{}, structural{};
    for (size_t i = 0; i < j.props.size(); ++i) {
        const auto& p = j.props[i];
        const auto &s0 = j.runtime[i], &fo = j.file_old[i], &fn = j.file_new[i], &a = after[i];
        if (!s0.ok || !fo.ok || !fn.ok || !a.ok) continue;
        auto target = a;
        if (p.indexed) {
            if (s0.count != a.count || fo.count != a.count || fn.count != a.count) continue;
            for (uint32_t k = 0; k < a.count; ++k) {
                const auto off = (size_t)k * p.size;
                if (same_bytes(p.mask, fo.bytes.data() + off, fn.bytes.data() + off, p.size)) memcpy(target.bytes.data() + off, s0.bytes.data() + off, p.size);
            }
        } else {
            if (!same_value(p, fo, fn)) continue;
            target = s0;
        }
        if (same_value(p, target, a)) continue;
        // The write-back changed the component's structure (element counts of indexed variables, sub-objects): e.g. PrivateLayerCount of via.motion.Motion creates motion layers by the runtime count,
        // but without the settings the game applied to those layers at runtime, and app.mcHumanHeadControl referencing them crashed when using them (observed). Only values that do not change structure are written back
        const auto words_before = object_words(j.comp, size);
        const auto structure_before = structure_of(td, j.comp);
        const bool ok = restore_value(p, j.comp, target) && same_value(p, read_prop(p, j.comp), target);
        if (structure_of(td, j.comp) != structure_before ||
            (!words_before.empty() && leaves_null_elements(words_before, object_words(j.comp, size)))) {
            restore_value(p, j.comp, a); // Undo: keep the values after initialization from the file
            structural.push_back(p.name);
            continue;
        }
        (ok ? kept : failed).push_back(p.name);
    }
    // String/resource path properties: when the file did not change them (old/new copies the same) and the runtime value differs from the value after initialization from the file, write the runtime value back
    if (j.tprops != nullptr && j.text_runtime.size() == j.tprops->size() && j.text_old.size() == j.tprops->size() &&
        j.text_new.size() == j.tprops->size()) {
        for (size_t i = 0; i < j.tprops->size(); ++i) {
            const auto& p = (*j.tprops)[i];
            const auto &s0 = j.text_runtime[i], &fo = j.text_old[i], &fn = j.text_new[i];
            if (!s0.ok || !fo.ok || !fn.ok || !(fo == fn)) continue;
            const auto a = read_text(p, j.comp);
            if (!a.ok || a == s0) continue;
            const auto words_before = object_words(j.comp, size);
            const auto structure_before = structure_of(td, j.comp);
            const bool ok = write_text(p, j.comp, s0);
            if (structure_of(td, j.comp) != structure_before ||
                (!words_before.empty() && leaves_null_elements(words_before, object_words(j.comp, size)))) {
                write_text(p, j.comp, a);
                structural.push_back(p.name);
                continue;
            }
            (ok ? kept : failed).push_back(p.name);
        }
    }
    if (!kept.empty()) log("    %s: properties keeping runtime values: %s", j.label.c_str(), join(kept).c_str());
    if (!structural.empty()) {
        log("    %s: properties that would change the component structure, runtime values not written back: %s", j.label.c_str(), join(structural).c_str());
    }
    if (!failed.empty()) {
        log("    %s: properties whose runtime values could not be kept: %s", j.label.c_str(), join(failed).c_str());
    }
}

// A rebuild takes three steps, so game code never uses an old component that has already been detached:
// 1. Prepare (apply): the new component is ready in a clean copy while the old one keeps working; the caller immediately scans in the background for references from other objects to the old component/sub-objects
// 2. Commit (after the scan completes, commit_rebuild): record runtime values and hand the old component to the engine for deferred destruction
// 3. Attach (in the first update-phase callback after the engine detached the old component, attach_ready): attach the new component, run awake, and the caller then rewrites references
struct RebuildAttach {
    uintptr_t go{};
    std::vector<uintptr_t> chain;                      // Component chain at commit time (used to insert at the original position)
    std::vector<std::pair<uintptr_t, uintptr_t>> repl; // Old component -> new component (one reference to the new component held here; the old one is held by the caller)
    std::vector<std::string> labels;
    std::vector<std::string> reasons;
    std::vector<std::vector<uintptr_t>> subs;          // Matches repl: data sub-objects of the old component (references to them are not rewritten if the commit fails)
    std::vector<RestoreJob> restores;                  // Matches repl: runtime values recorded at commit
    bool committed{};
};

std::vector<RebuildAttach> g_pending_attach{};

std::vector<uintptr_t> component_chain(uintptr_t go) {
    std::vector<uintptr_t> out{};
    uintptr_t c = 0;
    if (!safe_read_ptr(go + GO_FIRST_COMPONENT, c)) return out;
    for (int i = 0; c != 0 && i < 1024; ++i) {
        out.push_back(c);
        if (!safe_read_ptr(c + COMPONENT_NEXT, c)) break;
    }
    return out;
}

bool rebuild_pending_for(uintptr_t comp) {
    for (const auto& a : g_pending_attach) {
        for (const auto& [o, n] : a.repl) {
            if (o == comp || n == comp) return true;
        }
    }
    return false;
}

bool game_object_valid(uintptr_t go) {
    static const auto get_valid = find_method_n("via.GameObject", "get_Valid", 0);
    return go != 0 && safe_is_managed(go) && (get_valid == nullptr || (invoke_ptr(get_valid, go, {}) & 0xFF) != 0);
}

// Step 2: commit. Record runtime values, end effects using the old parameters, and hand the old components to the engine for deferred destruction.
// Returns the old components that could not be committed and their data sub-objects (the caller does not rewrite references to them)
std::vector<uintptr_t> commit_entry(RebuildAttach& a) {
    std::vector<uintptr_t> dropped{};
    const bool go_ok = game_object_valid(a.go);
    a.chain = go_ok ? component_chain(a.go) : std::vector<uintptr_t>{};
    std::unordered_set<uintptr_t> providers{};
    for (size_t i = 0; go_ok && i < a.repl.size(); ++i) {
        const auto o = a.repl[i].first;
        a.restores[i].runtime = snapshot(a.restores[i].props, o);
        a.restores[i].text_runtime = read_texts(a.restores[i].tprops, o);
        if (const auto td = type_of(o)) {
            for (const auto e : epv_elements(o, td)) providers.insert(e);
        }
    }
    const auto killed = go_ok ? kill_effects_of(providers) : 0;
    RebuildAttach kept{};
    kept.go = a.go;
    kept.chain = a.chain;
    kept.committed = true;
    for (size_t i = 0; i < a.repl.size(); ++i) {
        const auto [o, n] = a.repl[i];
        const bool in_chain = std::find(a.chain.begin(), a.chain.end(), o) != a.chain.end();
        if (!go_ok || !in_chain || !destroy_component(o)) {
            const char* why = !go_ok ? "GameObject no longer exists" : (!in_chain ? "old component is no longer on the GameObject" : "cannot destroy the old component");
            log("    %s: %s, not rebuilt", a.labels[i].c_str(), why);
            dropped.push_back(o);
            dropped.insert(dropped.end(), a.subs[i].begin(), a.subs[i].end());
            release(n);
            continue;
        }
        kept.repl.push_back(a.repl[i]);
        kept.labels.push_back(a.labels[i]);
        kept.reasons.push_back(a.reasons[i]);
        kept.subs.push_back(a.subs[i]);
        kept.restores.push_back(std::move(a.restores[i]));
    }
    if (killed > 0) log("    Ended %u effect instances with old parameters (looping effects regenerate with the new parameters)", killed);
    a = std::move(kept);
    return dropped;
}

// Step 3: call the attach function with the original component chain order (old components replaced by new ones) plus components that appeared since; old components not yet detached are kept after the new ones
void attach_rebuilt(RebuildAttach& a) {
    const auto fn = locate_set_components();
    const auto scene = current_scene();
    static const auto get_valid = find_method_n("via.GameObject", "get_Valid", 0);
    const bool go_ok = a.go != 0 && safe_is_managed(a.go) && (get_valid == nullptr || (invoke_ptr(get_valid, a.go, {}) & 0xFF) != 0);
    if (fn == nullptr || scene == 0 || !go_ok) {
        for (size_t i = 0; i < a.repl.size(); ++i) log("    %s: GameObject no longer exists, new component not attached", a.labels[i].c_str());
        for (const auto& [o, n] : a.repl) release(n);
        return;
    }
    const auto current = component_chain(a.go);
    const std::unordered_set<uintptr_t> now(current.begin(), current.end());
    std::unordered_map<uintptr_t, uintptr_t> new_of{};
    for (const auto& [o, n] : a.repl) new_of[o] = n;
    std::vector<uintptr_t> list{};
    std::unordered_set<uintptr_t> listed{};
    for (const auto c : a.chain) {
        if (const auto it = new_of.find(c); it != new_of.end()) {
            list.push_back(it->second);
            if (now.contains(c)) list.push_back(c); // The old component has not been detached yet (wait timed out)
        } else if (now.contains(c)) {
            list.push_back(c);
        }
        listed.insert(c);
    }
    for (const auto c : current) {
        if (!listed.contains(c)) list.push_back(c);
    }
    const bool ok = !list.empty() && safe_set_components(fn, a.go, scene, list.data(), list.size());
    for (size_t i = 0; i < a.repl.size(); ++i) {
        const auto n = a.repl[i].second;
        uintptr_t owner = 0;
        if (!ok || !safe_read_ptr(n + COMPONENT_OWNER, owner) || owner != a.go) {
            log("    %s: failed to attach the new component", a.labels[i].c_str());
            continue;
        }
        if (!send_awake(n)) {
            log("    %s: error during awake", a.labels[i].c_str());
        }
    }
    for (auto& j : a.restores) {
        uintptr_t owner = 0;
        if (!safe_read_ptr(j.comp + COMPONENT_OWNER, owner) || owner != a.go) continue;
        if (!j.wait_start) {
            run_restore(j);
            continue;
        }
        add_ref(j.comp);
        g_restores.push_back(std::move(j));
    }
    for (const auto& [o, n] : a.repl) release(n);
}

// ---- Reference redirection after rebuilds: whether a location hit by the memory scan is a counted reference inside a managed object ----
// Runs on a background thread: reads only memory and the TDB, without using helper functions in this file that have static caches
constexpr uintptr_t MANAGED_HEADER = 0x10;
constexpr uintptr_t MAX_OWNER_SEARCH = 0x10000;

bool safe_read_i32(uintptr_t addr, int32_t& out) {
    __try {
        out = *(volatile int32_t*)addr;
        return true;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

// Range of the TDB type definition array: managed object +0x00 is the object info, object info +0x00 is the type definition (an entry of the array)
struct TypeRange {
    uintptr_t begin{}, end{}, stride{};
};

const TypeRange& type_range() {
    static const TypeRange r = [] {
        const auto tdb = API::get()->tdb();
        const auto n = tdb->get_num_types();
        TypeRange t{};
        if (n < 2) return t;
        t.begin = (uintptr_t)tdb->get_type(0);
        t.stride = (uintptr_t)tdb->get_type(1) - t.begin;
        t.end = t.begin + t.stride * n;
        return t;
    }();
    return r;
}

// Whether c looks like a managed object: object header and object info readable (no guard pages), type definition inside the TDB array.
// Only then is REFramework's is_managed_object called, so its internal IsBadReadPtr never probes a guard page
template <typename Readable> bool plausible_object(uintptr_t c, const Readable& readable) {
    const auto& r = type_range();
    uintptr_t info = 0, td = 0;
    if (r.stride == 0 || !readable(c, 0x10) || !safe_read_ptr(c, info) || !readable(info, 8) || !safe_read_ptr(info, td)) return false;
    return td >= r.begin && td < r.end && (td - r.begin) % r.stride == 0;
}

API::TypeDefinition* safe_type_of(uintptr_t obj) {
    if (!managed_object_safe(obj)) return nullptr;
    __try {
        return ((API::ManagedObject*)obj)->get_type_definition();
    } __except (read_fault_filter(GetExceptionInformation())) {
        return nullptr;
    }
}

// ---- The engine's notion of "references that hold a reference count" ----
// When an object is released (IDA sub_14A49D260) the engine decrements child references one by one according to the type's reference bitmap; only positions in the bitmap hold counts:
// - type definition +0x08 bits 38-55 are the index into the type implementation table (TDB typesImpl, 0x30 per entry), +0x2C bits 26-28 the kind (1/5 class/value type, 2 array, 4 delegate)
// - implementation entry +0x08 is the field area size, +0x20 the reference bitmap (one bit per 8 bytes; when the field area is >= 513 bytes +0x20 is a pointer to the bitmap, otherwise the bitmap is at +0x20 itself)
// - class/value type: field area start = object + *(int32*)(object info - 8)
// - array: +0x10 element type, +0x1C count, elements from +0x20; value-type elements use the element type's bitmap (stride is its field area size rounded down to a multiple of 8), otherwise every element holds a count
// - delegate: +0x10 count, 24-byte entries from +0x18, each starting with the target object
// There is also a bitmap at +0x28 used by GC marking, containing only references that may form cycles; it cannot be used to judge counts
constexpr uintptr_t TD_IMPL_INDEX = 0x08;
constexpr uintptr_t TD_KIND = 0x2C;
constexpr uintptr_t IMPL_FIELD_SIZE = 0x08;
constexpr uintptr_t IMPL_OWNED_REFS = 0x20;
constexpr uintptr_t IMPL_STRIDE = 0x30;
constexpr uint32_t BITMAP_INLINE_MAX = 512;

// TDB type implementation table: the entry right after the type definition array pointer (types) in the TDB structure
uintptr_t types_impl() {
    static const uintptr_t base = [] {
        const auto tdb = (uintptr_t)API::get()->tdb();
        const auto types = (uintptr_t)API::get()->tdb()->get_type(0);
        for (uintptr_t off = 0; tdb != 0 && off < 0x100; off += 8) {
            uintptr_t v = 0, impl = 0;
            if (safe_read_ptr(tdb + off, v) && v == types && safe_read_ptr(tdb + off + 8, impl) && impl != 0) return impl;
        }
        return (uintptr_t)0;
    }();
    return base;
}

bool type_impl(uintptr_t td, uintptr_t& impl, uint32_t& kind) {
    uintptr_t bits = 0, kind_word = 0;
    const auto base = g_tdb_impl_layout_ok ? types_impl() : 0;
    if (base == 0 || !safe_read_ptr(td + TD_IMPL_INDEX, bits) || !safe_read_ptr(td + TD_KIND, kind_word)) return false;
    impl = base + IMPL_STRIDE * ((bits >> 38) & 0x3FFFF);
    kind = ((uint32_t)kind_word >> 26) & 7;
    return true;
}

// Bit index of an implementation entry's reference bitmap (the index-th 8 bytes in the field area)
bool owned_bit(uintptr_t impl, uint64_t index) {
    uintptr_t head = 0, size_word = 0;
    if (!safe_read_ptr(impl + IMPL_OWNED_REFS, head) || head == 0 || !safe_read_ptr(impl + IMPL_FIELD_SIZE, size_word)) return false;
    const auto size = (uint32_t)size_word;
    if (size < 8 || index >= size / 8) return false;
    const auto words = size > BITMAP_INLINE_MAX ? head : impl + IMPL_OWNED_REFS;
    uintptr_t w = 0;
    return safe_read_ptr(words + 8 * (index >> 6), w) && ((w >> (index & 63)) & 1) != 0;
}

// Whether slot is a counted reference inside object owner
bool owned_ref_slot(uintptr_t owner, uintptr_t slot) {
    uintptr_t info = 0, td = 0, impl = 0;
    uint32_t kind = 0;
    if (!safe_read_ptr(owner, info) || !safe_read_ptr(info, td) || !type_impl(td, impl, kind)) return false;
    switch (kind) {
    case 1:
    case 5: {
        int32_t start = 0;
        if (!safe_read_i32(info - 8, start)) return false;
        const auto fields = owner + start;
        return slot >= fields && (slot - fields) % 8 == 0 && owned_bit(impl, (slot - fields) / 8);
    }
    case 2: {
        uintptr_t etd = 0, count_word = 0, eimpl = 0, size_word = 0;
        uint32_t ekind = 0;
        if (!safe_read_ptr(owner + 0x10, etd) || !safe_read_ptr(owner + ARRAY_COUNT - 4, count_word) || slot < owner + ARRAY_DATA) return false;
        const auto count = (uint32_t)(count_word >> 32);
        const auto rel = slot - (owner + ARRAY_DATA);
        if (!type_impl(etd, eimpl, ekind)) return false;
        if (ekind != 5) return rel % 8 == 0 && rel / 8 < count;
        if (!safe_read_ptr(eimpl + IMPL_FIELD_SIZE, size_word)) return false;
        const auto stride = (uint32_t)size_word & ~7u;
        if (stride == 0 || rel / stride >= count || (rel % stride) % 8 != 0) return false;
        return owned_bit(eimpl, (rel % stride) / 8);
    }
    case 4: {
        int32_t count = 0;
        if (!safe_read_i32(owner + 0x10, count) || slot < owner + 0x18) return false;
        const auto rel = slot - (owner + 0x18);
        return rel % 24 == 0 && rel / 24 < (uint32_t)count;
    }
    default:
        return false;
    }
}

// Number of bytes occupied by managed object obj (including its header); 0 if unavailable.
// Classes/boxed value types use the type size; System.String is 0x14 + 2×length + 2; arrays are count × element stride from +0x20 (8 bytes for references, the field area size rounded down to a multiple of 8 for value types);
// delegates are count×24 from +0x18
uintptr_t managed_extent(uintptr_t obj) {
    uintptr_t info = 0, td = 0, impl = 0;
    uint32_t kind = 0;
    if (!safe_read_ptr(obj, info) || !safe_read_ptr(info, td) || !type_impl(td, impl, kind)) return 0;
    switch (kind) {
    case 1:
    case 5: {
        const auto t = safe_type_of(obj);
        if (t == nullptr) return 0;
        if (name_of(t) == "System.String") {
            int32_t len = 0;
            return safe_read_i32(obj + 0x10, len) && len >= 0 && len < 0x10000000 ? 0x14 + 2ull * (uint32_t)len + 2 : 0;
        }
        return t->get_size();
    }
    case 2: {
        uintptr_t etd = 0, count_word = 0, eimpl = 0, size_word = 0;
        uint32_t ekind = 0;
        if (!safe_read_ptr(obj + 0x10, etd) || !safe_read_ptr(obj + ARRAY_COUNT - 4, count_word) || !type_impl(etd, eimpl, ekind)) return 0;
        const auto count = (uint64_t)(uint32_t)(count_word >> 32);
        uint64_t stride = 8;
        if (ekind == 5) {
            if (!safe_read_ptr(eimpl + IMPL_FIELD_SIZE, size_word)) return 0;
            stride = std::max<uint64_t>((uint32_t)size_word & ~7u, 1);
        }
        return ARRAY_DATA + count * stride;
    }
    case 4: {
        int32_t count = 0;
        return safe_read_i32(obj + 0x10, count) && count >= 0 ? 0x18 + 24ull * (uint32_t)count : 0;
    }
    default:
        return 0;
    }
}

// The nearest managed object header before slot, provided slot falls within the range that object occupies; otherwise slot is native memory (engine structures, native arrays, etc.) and 0 is returned.
// Previously only the nearest object header was found, so positions inside native arrays were attributed to some unrelated managed object before them (observed 2026-11-08: the streaming controller's texture array was reported
// as System.String +0xa58 and so on)
uintptr_t owner_of_slot(uintptr_t slot, uintptr_t region, const std::function<bool(uintptr_t, size_t)>& readable) {
    for (uintptr_t back = MANAGED_HEADER; back <= MAX_OWNER_SEARCH && slot - back >= region && back < slot; back += 8) {
        const auto c = slot - back;
        if (!plausible_object(c, readable) || safe_type_of(c) == nullptr) continue;
        const auto extent = managed_extent(c);
        return extent != 0 && slot + 8 <= c + extent ? c : 0;
    }
    return 0;
}

// The managed object containing slot (see owner_of_slot), provided slot is a counted reference inside it
bool managed_ref_slot(uintptr_t slot, const ReadableMap& map, uintptr_t& owner) {
    owner = 0;
    const auto region = map.region_start(slot);
    if (region == 0) return false;
    owner = owner_of_slot(slot, region, [&](uintptr_t a, size_t n) { return map.readable(a, n); });
    return owner != 0 && owned_ref_slot(owner, slot);
}

// Component object header: +0x00 vtable, +0x08 reference count, +0x10 owning GameObject, +0x18 component chain, +0x20/+0x28 scene chain of same-type components (maintained by the engine)
constexpr uintptr_t COMPONENT_HEADER = 0x30;

// Usable on background threads: whether the type derives from via.Component (without the cached is_a)
bool component_type(API::TypeDefinition* td) {
    for (auto t = td; t != nullptr; t = t->get_parent_type()) {
        if (t->get_full_name() == "via.Component") return true;
    }
    return false;
}

// Usable on background threads: whether this is a scene object type (component, GameObject, Folder, Scene)
bool scene_type(API::TypeDefinition* td) {
    for (auto t = td; t != nullptr; t = t->get_parent_type()) {
        const auto n = t->get_full_name();
        if (n == "via.Component" || n == "via.GameObject" || n == "via.Folder" || n == "via.Scene") return true;
    }
    return false;
}

// Instance hierarchy (including children moved elsewhere by the game)
std::unordered_map<std::wstring, uintptr_t> instance_live_paths(uintptr_t root) {
    std::unordered_map<std::wstring, uintptr_t> live{};
    collect_live(root, live);
    add_moved_children(root, live);
    return live;
}

// Run one complete native deserialization of the new data on the newly created native object
bool native_full(const RszWalk& nw, int ni, uintptr_t live, const std::string& label) {
    if (!nw.has(ni)) {
        log("    %s: no split data range, parameters not written", label.c_str());
        return false;
    }
    const auto probe = rsz_probe_native(nw, ni);
    if (probe != NativeProbe::Ok) {
        log("    %s: native deserialization %s, parameters not written", label.c_str(), to_string(probe));
        return false;
    }
    const bool ok = rsz_apply_native(nw, ni, live);
    log("    %s: new object, all parameters in the file written%s", label.c_str(), ok ? "" : " (read length differed or execution failed)");
    return true;
}

}

static LiveApplyResult apply_impl(uintptr_t old_res, uintptr_t new_res, bool verbose);

LiveApplyResult PrefabLive::apply(uintptr_t old_res, uintptr_t new_res, bool verbose, const std::unordered_set<uintptr_t>* in_place) {
    // Under /EHa catch(...) also catches access violations, so exceptions do not propagate into REFramework callbacks
    if (!g_components_layout_ok) {
        log("  pfb live parameters: component layout check at startup failed, disabled (instances created later use the new file)");
        return {};
    }
    g_in_place = in_place;
    struct Reset {
        ~Reset() { g_in_place = nullptr; }
    } reset{};
    try {
        return apply_impl(old_res, new_res, verbose);
    } catch (...) {
        log("  pfb live parameters: exception during processing (stage: %s %s), aborted", g_stage, g_stage_detail.c_str());
        return {};
    }
}

namespace {
constexpr uint32_t USR_MAGIC = 0x00525355; // "USR\0"
constexpr uintptr_t USR_RSZ_OFFSET = 0x20;  // RSZ block offset (u64)

// Root object deserialized from the RSZ block of a USR file (first object table entry, reference held, caller releases); 0 on failure.
// Other .user files it references are fetched by path by the engine as shared objects (the same ones as in the game), not created in the copy
uintptr_t userdata_copy(const std::vector<uint8_t>& file) {
    if (file.size() < 0x30 || *(const uint32_t*)file.data() != USR_MAGIC) return 0;
    const auto off = *(const uint64_t*)(file.data() + USR_RSZ_OFFSET);
    if (off >= file.size()) return 0;
    std::vector<uintptr_t> objects{};
    if (!rsz_deserialize(file.data() + off, file.size() - off, objects) || objects.empty()) return 0;
    for (size_t i = 1; i < objects.size(); ++i) release(objects[i]);
    return objects[0];
}
}

LiveApplyResult PrefabLive::apply_userdata(const std::vector<uint8_t>& old_file, const std::vector<uint8_t>& new_file, uintptr_t live_root,
                                           const std::string& label) {
    LiveApplyResult result{};
    struct Copies {
        uintptr_t o{}, o2{}, n{}, n2{};
        ~Copies() {
            for (const auto p : {o, o2, n, n2}) {
                if (p != 0) release(p);
            }
        }
    } c{};
    try {
        const auto td = type_of(live_root);
        if (td == nullptr) {
            log("  %s: the data in use is not a valid object, not updated", label.c_str());
            result.structure_changed = true;
            return result;
        }
        c.n = userdata_copy(new_file);
        c.n2 = userdata_copy(new_file);
        if (c.n == 0 || type_of(c.n) != td) {
            log("  %s: new file %s; the data in use is not updated", label.c_str(), c.n == 0 ? "failed to parse" : ("has a different root object type (" + name_of(type_of(c.n)) + ")").c_str());
            result.structure_changed = true;
            return result;
        }
        if (!old_file.empty()) {
            c.o = userdata_copy(old_file);
            c.o2 = userdata_copy(old_file);
            if (c.o == 0 || type_of(c.o) != td) {
                if (c.o != 0) release(c.o);
                if (c.o2 != 0) release(c.o2);
                c.o = c.o2 = 0;
            }
        }
        // With a previous file version only the fields the file changed are written (values changed at runtime but not in the file are kept); without one, compare against the values in use
        const auto o = c.o != 0 ? c.o : live_root;
        RszVmScope scope{false};
        g_keep_replaced = true;
        g_replaced_pairs.clear();
        g_replaced_resources.clear();
        struct KeepReset {
            LiveApplyResult& r;
            ~KeepReset() {
                g_keep_replaced = false;
                // Old and new objects swapped: the caller scans memory in the background, repoints other references from the old objects to the new ones, then releases the old objects
                r.replaced = std::move(g_replaced_pairs);
                r.old_resources = std::move(g_replaced_resources);
                g_replaced_pairs.clear();
                g_replaced_resources.clear();
            }
        } keep_reset{result};
        SceneMap scene{};
        Differ differ{false, &scene};
        differ.diff_object(o, c.n, live_root, td, label, 0);
        result.fields = differ.fields_changed();
        result.structure_changed = differ.structure_changed();
        result.objects_replaced = differ.objects_replaced();
        // Parts of data objects read by native code (e.g. the path of via.Prefab, keyframes of via.AnimationCurve): compared and written through reflected properties.
        // With a previous file version, two copies of the old data separate file changes; without one, the values in use are the old values (same as managed fields)
        {
            std::vector<Differ::NativePart> parts{};
            if (c.o != 0 && c.o2 != 0) {
                Differ{false, &scene}.native_parts(c.o, c.o2, c.n, c.n2, live_root, td, "", 0, parts);
            } else {
                Differ{false, &scene}.native_parts(live_root, live_root, c.n, c.n2, live_root, td, "", 0, parts);
            }
            result.fields += apply_native_parts(parts, differ.created(), label);
        }
        if (result.fields > 0) result.components = 1;
    } catch (...) {
        log("  %s: exception while writing the data in use, aborted", label.c_str());
        result.structure_changed = true;
    }
    return result;
}

// ---- rcol ----
// File format follows the v25+ branch of RE-Engine-Lib REE-Lib/RszFile/RcolFile.cs; MHWilds rcol.28 shape records measured 160 bytes (80 of info without a cmat field + 80 of geometry)
namespace {
struct RcolShapeRec {
    int32_t type{};
    std::wstring name, joint1, joint2;
    int32_t layer{}, attr{};
    uint32_t skip{}, ignore{};
    std::array<uint8_t, 80> geom{};
};
using RcolGuid = std::array<uint8_t, 16>;
struct RcolGroupRec {
    std::wstring name;
    int32_t layer{};
    uint32_t mask{};
    // Collision layers and masks are actually determined by GUIDs (converted to FilterInfo Layer and MaskBits through the collision definition cdef; observed 2026-11-10 that all 142 request sets' layer numbers matched)
    RcolGuid layer_guid{};
    std::vector<RcolGuid> mask_guids;
    int32_t num_shapes{}, num_extra{};
    std::vector<RcolShapeRec> shapes; // Normal shapes first, extra (mirror) shapes after
};
struct RcolSetRec {
    uint32_t id{};
    int32_t group{}, ud{}, shape_ud{};
    std::wstring name, key;
};
struct RcolFileRec {
    bool ok{};
    std::vector<RcolGroupRec> groups;
    std::vector<RcolSetRec> sets;
    uint64_t data_offset{};
};

constexpr uint32_t RCOL_MAGIC = 0x4c4f4352;
constexpr size_t RCOL_GROUP_SIZE = 80, RCOL_SHAPE_SIZE = 160, RCOL_SHAPE_INFO = 80, RCOL_SET_SIZE = 48;

RcolFileRec rcol_parse(const std::vector<uint8_t>& a) {
    RcolFileRec f{};
    const auto n = a.size();
    auto rd32 = [&](size_t o) -> uint32_t { return o + 4 <= n ? *(const uint32_t*)(a.data() + o) : 0; };
    auto rd64 = [&](size_t o) -> uint64_t { return o + 8 <= n ? *(const uint64_t*)(a.data() + o) : 0; };
    auto wstr = [&](uint64_t o) {
        std::wstring s{};
        for (; o + 1 < n && s.size() < 512; o += 2) {
            const wchar_t c = (wchar_t)(a[o] | (a[o + 1] << 8));
            if (c == 0) break;
            s.push_back(c);
        }
        return s;
    };
    if (n < 0x88 || rd32(0) != RCOL_MAGIC) return f;
    const auto num_groups = (int32_t)rd32(4), num_sets = (int32_t)rd32(16);
    const auto groups_off = rd64(0x30), sets_off = rd64(0x40);
    f.data_offset = rd64(0x38);
    if (num_groups < 0 || num_groups > 4096 || num_sets < 0 || num_sets > 65536 || groups_off + (uint64_t)num_groups * RCOL_GROUP_SIZE > n ||
        sets_off + (uint64_t)num_sets * RCOL_SET_SIZE > n || f.data_offset >= n) {
        return f;
    }
    for (int32_t i = 0; i < num_groups; ++i) {
        const auto o = groups_off + (uint64_t)i * RCOL_GROUP_SIZE;
        RcolGroupRec g{};
        g.name = wstr(rd64(o + 16));
        g.num_shapes = (int32_t)rd32(o + 28);
        g.num_extra = (int32_t)rd32(o + 32);
        const auto shapes_off = rd64(o + 40);
        g.layer = (int32_t)rd32(o + 48);
        g.mask = rd32(o + 52);
        {
            const auto num_mask = (int32_t)rd32(o + 36);
            const auto mask_off = rd64(o + 56);
            memcpy(g.layer_guid.data(), a.data() + o + 64, 16);
            if (num_mask < 0 || num_mask > 64 || (num_mask > 0 && mask_off + (uint64_t)num_mask * 16 > n)) return f;
            for (int32_t k = 0; k < num_mask; ++k) {
                RcolGuid gd{};
                memcpy(gd.data(), a.data() + mask_off + (uint64_t)k * 16, 16);
                g.mask_guids.push_back(gd);
            }
        }
        const auto total = (uint64_t)std::max(0, g.num_shapes) + (uint64_t)std::max(0, g.num_extra);
        if (g.num_shapes < 0 || g.num_extra < 0 || total > 4096 || (total > 0 && shapes_off + total * RCOL_SHAPE_SIZE > n)) return f;
        for (uint64_t k = 0; k < total; ++k) {
            const auto so = shapes_off + k * RCOL_SHAPE_SIZE;
            RcolShapeRec s{};
            s.name = wstr(rd64(so + 16));
            s.layer = (int32_t)rd32(so + 32);
            s.attr = (int32_t)rd32(so + 36);
            s.skip = rd32(so + 40);
            s.type = (int32_t)rd32(so + 44);
            s.ignore = rd32(so + 48);
            s.joint1 = wstr(rd64(so + 56));
            s.joint2 = wstr(rd64(so + 64));
            memcpy(s.geom.data(), a.data() + so + RCOL_SHAPE_INFO, s.geom.size());
            g.shapes.push_back(std::move(s));
        }
        f.groups.push_back(std::move(g));
    }
    for (int32_t i = 0; i < num_sets; ++i) {
        const auto o = sets_off + (uint64_t)i * RCOL_SET_SIZE;
        RcolSetRec r{};
        r.id = rd32(o);
        r.group = (int32_t)rd32(o + 4);
        r.ud = (int32_t)rd32(o + 8);
        r.shape_ud = (int32_t)rd32(o + 12);
        r.name = wstr(rd64(o + 24));
        r.key = wstr(rd64(o + 32));
        if (r.group < 0 || r.group >= num_groups) return f;
        f.sets.push_back(std::move(r));
    }
    f.ok = true;
    return f;
}

// Same structure: request sets have the same index IDs and groups, and each group has the same number and types of shapes
bool rcol_same_structure(const RcolFileRec& a, const RcolFileRec& b, std::string& why) {
    if (a.sets.size() != b.sets.size()) {
        why = "request set count " + std::to_string(a.sets.size()) + " -> " + std::to_string(b.sets.size());
        return false;
    }
    if (a.groups.size() != b.groups.size()) {
        why = "group count " + std::to_string(a.groups.size()) + " -> " + std::to_string(b.groups.size());
        return false;
    }
    for (size_t i = 0; i < a.sets.size(); ++i) {
        if (a.sets[i].id != b.sets[i].id || a.sets[i].group != b.sets[i].group) {
            why = "request set " + narrow(b.sets[i].name) + ": ID or group";
            return false;
        }
    }
    for (size_t i = 0; i < a.groups.size(); ++i) {
        const auto& ga = a.groups[i];
        const auto& gb = b.groups[i];
        if (ga.num_shapes != gb.num_shapes || ga.num_extra != gb.num_extra) {
            why = "group " + narrow(gb.name) + ": shape count";
            return false;
        }
        for (size_t k = 0; k < ga.shapes.size(); ++k) {
            if (ga.shapes[k].type != gb.shapes[k].type) {
                why = "group " + narrow(gb.name) + ": shape types";
                return false;
            }
        }
    }
    return true;
}

// Value type of the property matching the shape geometry (same-named struct property on the collider shape, e.g. CapsuleShape.Capsule)
const char* rcol_geom_type(int32_t shape_type) {
    switch (shape_type) {
    case 0: return "via.AABB";
    case 1: case 2: return "via.Sphere";
    case 3: case 4: return "via.Capsule";
    case 5: return "via.OBB";
    case 12: return "via.Cylinder";
    default: return nullptr;
    }
}

// Shape geometry is read/written only through TDB methods (get_X returning the wanted struct, set_X taking it, e.g. CapsuleShape.get_Capsule/set_Capsule).
// props_of is not used: the same-named reflected variable it prefers does not affect the shape when written (observed 2026-11-10: a reflected Capsule write read back unchanged, while set_Capsule/set_Radius took effect immediately)
const NativeProp* rcol_geom_prop(uintptr_t shape, const char* want) {
    static std::map<std::pair<API::TypeDefinition*, std::string>, std::unique_ptr<NativeProp>> cache{};
    const auto td = shape != 0 && want != nullptr ? type_of(shape) : nullptr;
    if (td == nullptr) return nullptr;
    auto& slot = cache[{td, want}];
    if (slot != nullptr) return slot->get != nullptr ? slot.get() : nullptr;
    slot = std::make_unique<NativeProp>();
    for (auto t = td; t != nullptr && slot->get == nullptr; t = t->get_parent_type()) {
        for (const auto m : t->get_methods()) {
            if (m == nullptr || m->is_static() || m->get_num_params() != 0) continue;
            const std::string name = m->get_name();
            const auto rt = m->get_return_type();
            if (!name.starts_with("get_") || rt == nullptr || name_of(rt) != want) continue;
            const auto setter = find_method_n(name_of(t).c_str(), ("set_" + name.substr(4)).c_str(), 1);
            if (setter == nullptr) continue;
            const auto size = rt->get_valuetype_size();
            if (size == 0 || size > 80) continue;
            slot->name = name.substr(4);
            slot->get = m;
            slot->set = setter;
            slot->type_name = want;
            slot->size = size;
            slot->mask = significant_mask(rt, size);
            break;
        }
    }
    return slot->get != nullptr ? slot.get() : nullptr;
}

// rcol resource used by the component's g-th request set group (0 if none or validation fails).
// RequestSetGroup.get_Resource is not called: it adds a reference to the resource pointer in the group data and creates a holder, and for some components the address returned by getRequestSetGroups
// is readable but its content invalid, so get_Resource writes to an invalid address (observed 2026-11-10: dozens of write access violations on the main thread). Instead the group struct is read directly and validated:
// group +0x70 points back to the owning component, +0x10 is the resource pointer (observed 0x90 bytes per group on MasterPlayer); the resource must be a readable cache entry with a path ending in .rcol
constexpr uintptr_t RCOL_GROUP_RESOURCE = 0x10, RCOL_GROUP_OWNER = 0x70, RCOL_GROUP_SIZE_LIVE = 0x90;
uintptr_t rcol_group_resource(API::Method* get_group, uintptr_t comp, uint32_t g, std::wstring* path_out = nullptr) {
    reframework::InvokeRet gr{};
    void* garg[1]{(void*)(uintptr_t)g};
    if (!safe_invoke(get_group, comp, garg, sizeof(garg), &gr) || gr.exception_thrown) return 0;
    const auto grp = (uintptr_t)gr.ptr;
    uintptr_t owner = 0, res = 0;
    if (grp < 0x10000 || !vq_readable(grp, RCOL_GROUP_SIZE_LIVE) || !safe_read_ptr(grp + RCOL_GROUP_OWNER, owner) || owner != comp) return 0;
    if (!safe_read_ptr(grp + RCOL_GROUP_RESOURCE, res) || res < 0x10000) return 0;
    ResourceEntry e{};
    if (!ResourceCache::read_entry(res, e)) return 0;
    std::wstring low = e.path;
    for (auto& c : low) c = (wchar_t)towlower(c);
    if (!low.ends_with(L".rcol")) return 0;
    if (path_out != nullptr) *path_out = std::move(low);
    return res;
}

// Collision definition (via.physics.System.CollisionDefinition, common.cdef): resource +0x58 is the file data as is (in-file offsets have been replaced with absolute addresses by the engine, observed 2026-11-10).
// Version 7 layout per RE-Engine-Lib CdefFile.cs: 32-byte header (+4 layer count, +8 mask count), layer table of 64 entries × 48 bytes (GUID first; the index is the layer number),
// collision bits 64 × 8 bytes, then +0xE20 is the mask table address; mask entries are 48 bytes (GUID first, +36 is the mask index, matching the MaskBits bit)
struct CdefTables {
    bool ok{};
    std::map<RcolGuid, int32_t> layer;
    std::map<RcolGuid, uint32_t> mask_bit;
};
constexpr uint32_t CDEF_MAGIC = 0x46454443;
constexpr uintptr_t CDEF_RES_DATA = 0x58, CDEF_LAYERS = 0x20, CDEF_ENTRY = 48, CDEF_MASKS_PTR = 0xE20;

const CdefTables& cdef_tables() {
    static CdefTables cache{};
    static uintptr_t cached_base = 0;
    const auto& api = API::get();
    static const auto get_def = api->tdb()->find_method("via.physics.System", "get_CollisionDefinition");
    const auto sys = api->get_native_singleton("via.physics.System");
    if (get_def == nullptr || sys == nullptr) return cache = CdefTables{};
    const auto holder = (uintptr_t)get_def->call<API::ManagedObject*>(api->get_vm_context(), sys);
    uintptr_t res = 0, base = 0;
    if (holder == 0 || !safe_read_ptr(holder + 0x10, res) || res == 0 || !safe_read_ptr(res + CDEF_RES_DATA, base) || base < 0x10000) return cache = CdefTables{};
    if (base == cached_base && cache.ok) return cache;
    CdefTables t{};
    auto safe_read_u32 = [](uintptr_t addr, uint32_t& v) {
        int32_t x = 0;
        if (!safe_read_i32(addr, x)) return false;
        v = (uint32_t)x;
        return true;
    };
    uint32_t magic = 0, layers = 0, masks = 0;
    uintptr_t masks_ptr = 0;
    if (!vq_readable(base, CDEF_MASKS_PTR + 8) || !safe_read_u32(base, magic) || magic != CDEF_MAGIC || !safe_read_u32(base + 4, layers) || layers > 64 ||
        !safe_read_u32(base + 8, masks) || masks > 4096 || !safe_read_ptr(base + CDEF_MASKS_PTR, masks_ptr) || masks_ptr < base + CDEF_MASKS_PTR ||
        masks_ptr > base + 0x1000000 || (masks > 0 && !vq_readable(masks_ptr, (size_t)masks * CDEF_ENTRY))) {
        cached_base = base;
        return cache = CdefTables{};
    }
    for (uint32_t i = 0; i < 64; ++i) {
        RcolGuid g{};
        memcpy(g.data(), (const void*)(base + CDEF_LAYERS + (uintptr_t)i * CDEF_ENTRY), 16);
        t.layer.emplace(g, (int32_t)i);
    }
    for (uint32_t i = 0; i < masks; ++i) {
        RcolGuid g{};
        const auto e = masks_ptr + (uintptr_t)i * CDEF_ENTRY;
        memcpy(g.data(), (const void*)e, 16);
        uint32_t bit = 0;
        safe_read_u32(e + 36, bit);
        if (bit < 32) t.mask_bit.emplace(g, bit);
    }
    t.ok = true;
    cached_base = base;
    return cache = std::move(t);
}

// Layer number of the group (-1 if its GUID is not in the collision definition) and mask (resolved is false if some GUID cannot be found)
int32_t cdef_layer(const CdefTables& t, const RcolGroupRec& g) {
    const auto it = t.layer.find(g.layer_guid);
    return it == t.layer.end() ? -1 : it->second;
}
uint32_t cdef_mask(const CdefTables& t, const RcolGroupRec& g, bool& resolved) {
    uint32_t bits = 0;
    resolved = true;
    for (const auto& m : g.mask_guids) {
        const auto it = t.mask_bit.find(m);
        if (it == t.mask_bit.end()) {
            resolved = false;
            continue;
        }
        bits |= 1u << it->second;
    }
    return bits;
}

PropValue rcol_geom_value(const NativeProp& p, const RcolShapeRec& s) {
    PropValue v{};
    v.ok = true;
    v.bytes.assign(s.geom.begin(), s.geom.begin() + p.size);
    return v;
}
} // namespace

uintptr_t PrefabLive::rcol_resource_in_use(const std::wstring& path) {
    const auto& api = API::get();
    const auto vm = api->get_vm_context();
    static const auto get_scene = api->tdb()->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = api->tdb()->find_method("via.Scene", "findComponents(System.Type)");
    static const auto groups_count = find_method_n("via.physics.RequestSetCollider", "getRequestSetGroupsCount", 0);
    static const auto get_group = find_method_n("via.physics.RequestSetCollider", "getRequestSetGroups", 1);
    if (get_scene == nullptr || find_components == nullptr || groups_count == nullptr || get_group == nullptr) return 0;
    auto scene = get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager"));
    const auto arr = scene ? (uintptr_t)find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.physics.RequestSetCollider")) : 0;
    int32_t count = 0;
    if (arr == 0 || !safe_read_i32(arr + ARRAY_COUNT, count)) return 0;
    auto fold = [](std::wstring s) {
        for (auto& c : s) c = (wchar_t)towlower(c);
        return s;
    };
    const auto key = fold(ResourceCache::normalize(path));
    for (int32_t ci = 0; ci < count && ci < 100000; ++ci) {
        uintptr_t comp = 0;
        if (!safe_read_ptr(arr + ARRAY_DATA + 8ull * ci, comp) || comp == 0) continue;
        const auto ng = (uint32_t)invoke_ptr(groups_count, comp, {});
        for (uint32_t g = 0; g < ng && g < 256; ++g) {
            std::wstring rpath{};
            const auto res = rcol_group_resource(get_group, comp, g, &rpath);
            if (res != 0 && fold(ResourceCache::normalize(rpath)) == key) return res;
        }
    }
    return 0;
}

PrefabLive::RcolApply PrefabLive::apply_rcol(const std::wstring& path, const std::vector<uint8_t>& prev, const std::vector<uint8_t>& data) {
    RcolApply out{};
    const auto fn = rcol_parse(data);
    if (!fn.ok) {
        out.error = "failed to parse the new file";
        return out;
    }
    auto fo = prev.empty() ? RcolFileRec{} : rcol_parse(prev);
    const bool have_old = fo.ok;
    out.ok = true;
    if (have_old) {
        std::string why{};
        if (!rcol_same_structure(fo, fn, why)) {
            out.structure_changed = true;
            out.error = why;
            return out;
        }
    }
    const auto& api = API::get();
    const auto vm = api->get_vm_context();
    static const auto get_scene = api->tdb()->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = api->tdb()->find_method("via.Scene", "findComponents(System.Type)");
    static const auto groups_count = find_method_n("via.physics.RequestSetCollider", "getRequestSetGroupsCount", 0);
    static const auto get_group = find_method_n("via.physics.RequestSetCollider", "getRequestSetGroups", 1);
    static const auto num_sets = find_method_n("via.physics.RequestSetCollider", "getNumRequestSetsFromIndex", 1);
    static const auto set_id = find_method_n("via.physics.RequestSetCollider", "getRequestSetId", 2);
    static const auto set_ud = find_method_n("via.physics.RequestSetCollider", "getRequestSetUserDataFromIndex", 2);
    static const auto num_cols = find_method_n("via.physics.RequestSetCollider", "getNumCollidablesFromIndex", 2);
    static const auto get_col = find_method_n("via.physics.RequestSetCollider", "getCollidableFromIndex", 3);
    static const auto get_shape = find_method_n("via.physics.Collidable", "get_Shape", 0);
    static const auto shape_ud = find_method_n("via.physics.Shape", "get_UserData", 0);
    static const auto col_ud = find_method_n("via.physics.Collidable", "get_UserData", 0);
    static const auto joint_a_get = find_method_n("via.physics.Collider", "get_JointNameA", 0);
    static const auto joint_b_get = find_method_n("via.physics.Collider", "get_JointNameB", 0);
    static const auto joint_a_set = find_method_n("via.physics.Collider", "set_JointNameA", 1);
    static const auto joint_b_set = find_method_n("via.physics.Collider", "set_JointNameB", 1);
    static const auto get_filter = find_method_n("via.physics.Collidable", "get_FilterInfo", 0);
    static const auto fi_layer_get = find_method_n("via.physics.FilterInfo", "get_Layer", 0);
    static const auto fi_layer_set = find_method_n("via.physics.FilterInfo", "set_Layer", 1);
    static const auto fi_mask_get = find_method_n("via.physics.FilterInfo", "get_MaskBits", 0);
    static const auto fi_mask_set = find_method_n("via.physics.FilterInfo", "set_MaskBits", 1);
    if (get_scene == nullptr || find_components == nullptr || groups_count == nullptr || get_group == nullptr ||
        num_sets == nullptr || set_id == nullptr || set_ud == nullptr || num_cols == nullptr || get_col == nullptr || get_shape == nullptr) {
        out.error = "RequestSetCollider interface not found";
        return out;
    }
    auto scene = get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager"));
    const auto arr = scene ? (uintptr_t)find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.physics.RequestSetCollider")) : 0;
    int32_t count = 0;
    if (arr == 0 || !safe_read_i32(arr + ARRAY_COUNT, count)) return out;
    // Paths are compared case-insensitively: the same file may be written with different case in the game (e.g. GameDesign/player/actiondata and GameDesign/Player/ActionData)
    auto fold = [](std::wstring s) {
        for (auto& c : s) c = (wchar_t)towlower(c);
        return s;
    };
    const auto key = fold(ResourceCache::normalize(path));

    // User data: deserialize the RSZ blocks of the old and new files once each (object table order = for each request set [set user data, user data of each shape in its group])
    struct Objects {
        std::vector<uintptr_t> v;
        ~Objects() {
            for (const auto o : v) {
                if (o != 0) release(o);
            }
        }
    } on{}, oo{};
    rsz_deserialize(data.data() + fn.data_offset, data.size() - fn.data_offset, on.v);
    if (have_old) rsz_deserialize(prev.data() + fo.data_offset, prev.size() - fo.data_offset, oo.v);
    auto obj_at = [](const Objects& o, int32_t i) -> uintptr_t { return i >= 0 && (size_t)i < o.v.size() ? o.v[i] : 0; };

    // Memory layout of shape geometry: a struct type is confirmed to match the file only if at least one shape in use is byte-identical to the file geometry (new or old); only then are shapes of that type written
    std::unordered_map<std::string, bool> layout_ok{};
    struct Live {
        uintptr_t col{}, shape{};
        const RcolShapeRec* n{};
        const RcolShapeRec* o{};
    };
    std::vector<Live> shapes{};
    std::unordered_set<std::string> not_live{};
    RszVmScope scope{false};
    g_keep_replaced = true;
    g_replaced_pairs.clear();
    g_replaced_resources.clear();
    struct KeepReset {
        RcolApply& r;
        ~KeepReset() {
            g_keep_replaced = false;
            r.replaced = std::move(g_replaced_pairs);
            r.old_resources = std::move(g_replaced_resources);
            g_replaced_pairs.clear();
            g_replaced_resources.clear();
        }
    } keep_reset{out};
    SceneMap scene_map{};
    auto diff_ud = [&](uintptr_t o, uintptr_t n, uintptr_t l, const std::string& label) {
        const auto td = l != 0 ? type_of(l) : nullptr;
        if (n == 0 || td == nullptr || type_of(n) != td) return;
        if (o != 0 && type_of(o) != td) o = 0;
        Differ differ{false, &scene_map};
        differ.diff_object(o != 0 ? o : l, n, l, td, label, 0);
        out.ud_fields += differ.fields_changed();
    };

    for (int32_t ci = 0; ci < count && ci < 100000; ++ci) {
        uintptr_t comp = 0;
        if (!safe_read_ptr(arr + ARRAY_DATA + 8ull * ci, comp) || comp == 0) continue;
        const auto ng = (uint32_t)invoke_ptr(groups_count, comp, {});
        bool used = false;
        for (uint32_t g = 0; g < ng && g < 256; ++g) {
            std::wstring rpath{};
            if (rcol_group_resource(get_group, comp, g, &rpath) == 0 || fold(ResourceCache::normalize(rpath)) != key) continue;
            used = true;
            ++out.groups;
            uintptr_t owner = 0;
            safe_read_ptr(comp + COMPONENT_OWNER, owner);
            const auto gl = owner != 0 ? narrow(game_object_name(owner)) : std::string{"?"};
            const auto nsets = (uint32_t)invoke_ptr(num_sets, comp, {(void*)(uintptr_t)g});
            for (uint32_t s = 0; s < nsets && s < 65536; ++s) {
                const auto id = (uint32_t)invoke_ptr(set_id, comp, {(void*)(uintptr_t)g, (void*)(uintptr_t)s});
                const auto it = std::find_if(fn.sets.begin(), fn.sets.end(), [&](const RcolSetRec& r) { return r.id == id; });
                if (it == fn.sets.end()) continue;
                const auto si = (size_t)(it - fn.sets.begin());
                const auto& sn = *it;
                const RcolSetRec* so = have_old ? &fo.sets[si] : nullptr;
                ++out.sets;
                const auto label = gl + ":" + narrow(sn.name);
                // User data of the request set (e.g. app.col_user_data.AttackParamPl)
                const auto lud = invoke_ptr(set_ud, comp, {(void*)(uintptr_t)g, (void*)(uintptr_t)s});
                diff_ud(so ? obj_at(oo, so->ud) : 0, obj_at(on, sn.ud), lud, label);
                // Colliders and shapes: matched to the shapes of the group in order
                const auto& gn = fn.groups[sn.group];
                const RcolGroupRec* go = so ? &fo.groups[so->group] : nullptr;
                const auto ncol = (uint32_t)invoke_ptr(num_cols, comp, {(void*)(uintptr_t)g, (void*)(uintptr_t)s});
                for (uint32_t k = 0; k < ncol && k < gn.shapes.size(); ++k) {
                    const auto col = invoke_ptr(get_col, comp, {(void*)(uintptr_t)g, (void*)(uintptr_t)s, (void*)(uintptr_t)k});
                    if (col == 0) continue;
                    const auto& shn = gn.shapes[k];
                    const RcolShapeRec* sho = go ? &go->shapes[k] : nullptr;
                    shapes.push_back({col, invoke_ptr(get_shape, col, {}), &shn, sho});
                    // User data of the shape: attached to the shape or the collider (whichever has the type matching the file)
                    const auto fud = obj_at(on, sn.shape_ud + (int32_t)k);
                    if (fud != 0) {
                        uintptr_t live_ud = 0;
                        for (const auto cand : {shape_ud != nullptr ? invoke_ptr(shape_ud, shapes.back().shape, {}) : 0,
                                                col_ud != nullptr ? invoke_ptr(col_ud, col, {}) : 0}) {
                            if (cand != 0 && type_of(cand) == type_of(fud)) {
                                live_ud = cand;
                                break;
                            }
                        }
                        if (live_ud != 0) {
                            diff_ud(so ? obj_at(oo, so->shape_ud + (int32_t)k) : 0, fud, live_ud, label + "/" + narrow(shn.name));
                        }
                    }
                    // Bound joint names
                    if (sho != nullptr && (sho->joint1 != shn.joint1 || sho->joint2 != shn.joint2) && joint_a_set != nullptr && joint_b_set != nullptr) {
                        auto set_text = [&](API::Method* get, API::Method* set, const std::wstring& was, const std::wstring& now) {
                            if (was == now) return;
                            const auto cur = get != nullptr ? read_string(invoke_ptr(get, col, {})) : std::wstring{};
                            if (cur != was && cur != now) return; // Changed by the game
                            if (cur == now) return;
                            const auto str = (void*)api->sdk()->functions->create_managed_string(now.c_str());
                            if (invoke_void(set, col, {str})) ++out.joints;
                        };
                        set_text(joint_a_get, joint_a_set, sho->joint1, shn.joint1);
                        set_text(joint_b_get, joint_b_set, sho->joint2, shn.joint2);
                    }
                    if (sho != nullptr) {
                        if (sho->layer != shn.layer) not_live.insert("shape layer");
                        if (sho->attr != shn.attr) not_live.insert("shape attribute");
                        if (sho->skip != shn.skip || sho->ignore != shn.ignore) not_live.insert("shape skip/ignore flags");
                    }
                }
                if (so != nullptr && (so->name != sn.name || so->key != sn.key)) not_live.insert("request set name");
                // Collision layers and masks: the group's layer GUID and mask GUIDs are converted through the collision definition and written into the FilterInfo of each collider of the request set (the collider's own object;
                // writes affect collision detection immediately: observed 2026-11-10 that after clearing the Attack_Enemy bit of the long sword's attack hitbox, hitting a training dummy did no damage).
                // Only what the file changed is written, and only where the collider's current value equals the old file's converted value (values changed by the game are kept); masks with any unknown GUID are not written
                const bool layer_changed = go == nullptr || go->layer_guid != gn.layer_guid;
                const bool mask_changed = go == nullptr || go->mask_guids != gn.mask_guids;
                if ((layer_changed || mask_changed) && get_filter != nullptr && fi_layer_get != nullptr && fi_layer_set != nullptr && fi_mask_get != nullptr &&
                    fi_mask_set != nullptr) {
                    const auto& cdef = cdef_tables();
                    if (!cdef.ok) {
                        if (go != nullptr) not_live.insert("collision layers and masks (collision definition unreadable)");
                    } else {
                        const auto ln = cdef_layer(cdef, gn), lo = go != nullptr ? cdef_layer(cdef, *go) : -1;
                        bool mn_ok = false, mo_ok = false;
                        const auto mn = cdef_mask(cdef, gn, mn_ok);
                        const auto mo = go != nullptr ? cdef_mask(cdef, *go, mo_ok) : 0u;
                        if (layer_changed && ln < 0 && go != nullptr) not_live.insert("collision layer (layer GUID not in the collision definition)");
                        if (mask_changed && !mn_ok && go != nullptr) not_live.insert("collision mask (mask GUID not in the collision definition)");
                        for (uint32_t k = 0; k < ncol; ++k) {
                            const auto col = invoke_ptr(get_col, comp, {(void*)(uintptr_t)g, (void*)(uintptr_t)s, (void*)(uintptr_t)k});
                            const auto fi = col != 0 ? invoke_ptr(get_filter, col, {}) : 0;
                            if (fi == 0) continue;
                            if (layer_changed && ln >= 0) {
                                const auto cur = (int32_t)(uint32_t)invoke_ptr(fi_layer_get, fi, {});
                                if (cur != ln && (go == nullptr || cur == lo) && invoke_void(fi_layer_set, fi, {(void*)(uintptr_t)(uint32_t)ln})) ++out.layers;
                            }
                            if (mask_changed && mn_ok) {
                                const auto cur = (uint32_t)invoke_ptr(fi_mask_get, fi, {});
                                if (cur != mn && (go == nullptr || (mo_ok && cur == mo)) && invoke_void(fi_mask_set, fi, {(void*)(uintptr_t)mn})) ++out.masks;
                            }
                        }
                    }
                }
            }
        }
        if (used) ++out.components;
    }
    // Shape geometry: verify the layout first, then write what the file changed (without a previous version, write what differs from the current value)
    for (const auto& l : shapes) {
        const auto want = rcol_geom_type(l.n->type);
        const auto p = rcol_geom_prop(l.shape, want);
        if (p == nullptr) continue;
        const auto cur = read_prop(*p, l.shape);
        if (!cur.ok) continue;
        if (same_value(*p, cur, rcol_geom_value(*p, *l.n)) || (l.o != nullptr && same_value(*p, cur, rcol_geom_value(*p, *l.o)))) layout_ok[want] = true;
    }
    for (const auto& l : shapes) {
        const auto want = rcol_geom_type(l.n->type);
        const bool changed = l.o == nullptr || l.o->geom != l.n->geom;
        if (!changed) continue;
        const auto p = rcol_geom_prop(l.shape, want);
        if (p == nullptr || !layout_ok[want ? want : ""]) {
            if (l.o != nullptr) not_live.insert(std::string{"shape geometry ("} + (want ? want : "unsupported shape") + ")");
            continue;
        }
        const auto target = rcol_geom_value(*p, *l.n);
        const auto cur = read_prop(*p, l.shape);
        if (!cur.ok || same_value(*p, cur, target)) continue;
        if (l.o != nullptr && !same_value(*p, cur, rcol_geom_value(*p, *l.o))) continue; // The game changed this shape
        if (restore_value(*p, l.shape, target) && same_value(*p, read_prop(*p, l.shape), target)) ++out.shapes;
    }
    out.not_live.assign(not_live.begin(), not_live.end());
    return out;
}

// Create a via.gui.GUI with resource as its resource on a hidden temporary GameObject (the engine generates a GUI from it, used to read the elements and properties in the file).
// Returns the GUI component and writes the GameObject to go; the plugin holds one reference to each, released with gui_temp_destroy when done
uintptr_t PrefabLive::gui_temp_create(uintptr_t resource, uintptr_t& go) {
    static const auto create = find_method_n("via.GameObject", "create", 1);
    static const auto set_draw = find_method_n("via.GameObject", "set_Draw", 1);
    static const auto create_comp = find_method_n("via.GameObject", "createComponent", 1);
    static const auto set_asset = find_method_n("via.gui.GUI", "set_Asset", 1);
    static const auto set_update = find_method_n("via.GameObject", "set_UpdateSelf", 1);
    static const auto set_speed = find_method_n("via.gui.GUI", "set_PlaySpeed", 1);
    go = 0;
    const auto& api = API::get();
    if (resource == 0 || create == nullptr || create_comp == nullptr || set_asset == nullptr) return 0;
    const auto str = (void*)api->sdk()->functions->create_managed_string(L"file_hotreload_gui_compare");
    go = invoke_ptr(create, 0, {str});
    if (go == 0) return 0;
    add_ref(go);
    invoke_void(set_draw, go, {(void*)(uintptr_t)0});
    // No update, no playback: GUI animations made two GUIs generated from the same file read different positions and colors at different moments (observed 2026-11-09 with ui090100);
    // once frozen, set_Asset finishes generating immediately and stays unchanged, and the engine does not have to update these GUIs with tens of thousands of elements every frame
    invoke_void(set_update, go, {(void*)(uintptr_t)0});
    const auto gui = invoke_ptr(create_comp, go, {(void*)api->typeof("via.gui.GUI")});
    if (gui != 0) invoke_void(set_speed, gui, {(void*)(uintptr_t)0}); // 0.0
    const auto holder = gui != 0 ? (uintptr_t)api->sdk()->resource->create_holder((REFrameworkResourceHandle)resource, "via.gui.GUIResourceHolder") : 0;
    if (gui == 0 || holder == 0 || !invoke_void(set_asset, gui, {(void*)holder})) {
        destroy_go(go);
        release(go);
        go = 0;
        return 0;
    }
    // Turn the component off after generation so the engine stops processing this GUI every frame (elements and properties remain readable when off)
    static const auto set_enabled = find_method_n("via.gui.GUI", "set_Enabled", 1);
    invoke_void(set_enabled, gui, {(void*)(uintptr_t)0});
    add_ref(gui);
    return gui;
}

// The GUI has been generated: if get_Ready is true and there is a root element, return the root element (View), otherwise 0
uintptr_t PrefabLive::gui_view(uintptr_t gui) {
    static const auto get_ready = find_method_n("via.gui.GUI", "get_Ready", 0);
    static const auto get_view = find_method_n("via.gui.GUI", "get_View", 0);
    if (gui == 0 || get_ready == nullptr || get_view == nullptr) return 0;
    if ((invoke_ptr(get_ready, gui, {}) & 0xFF) == 0) return 0;
    return invoke_ptr(get_view, gui, {});
}

// Whether this is a comparison GUI created by gui_temp_create (GameObject named file_hotreload_gui_compare)
bool PrefabLive::gui_is_temp(uintptr_t gui) {
    static const auto get_go = find_method_n("via.Component", "get_GameObject", 0);
    static const auto get_name = find_method_n("via.GameObject", "get_Name", 0);
    const auto go = gui != 0 && get_go != nullptr ? invoke_ptr(get_go, gui, {}) : 0;
    const auto name = go != 0 && get_name != nullptr ? invoke_ptr(get_name, go, {}) : 0;
    return name != 0 && read_string(name) == L"file_hotreload_gui_compare";
}

uintptr_t PrefabLive::gui_find(uintptr_t view, const std::string& path) {
    static const auto get_child = find_method_n("via.gui.TransformObject", "get_Child", 0);
    static const auto get_next = find_method_n("via.gui.PlayObject", "get_Next", 0);
    static const auto get_name = find_method_n("via.gui.PlayObject", "get_Name", 0);
    if (get_child == nullptr || get_next == nullptr || get_name == nullptr) return 0;
    auto cur = view;
    size_t pos = 0;
    while (cur != 0 && pos < path.size()) {
        if (path[pos] == '/') {
            ++pos;
            continue;
        }
        const auto slash = path.find('/', pos);
        const auto seg = path.substr(pos, slash == std::string::npos ? std::string::npos : slash - pos);
        pos = slash == std::string::npos ? path.size() : slash;
        uintptr_t hit = 0;
        for (auto c = invoke_ptr(get_child, cur, {}); c != 0; c = invoke_ptr(get_next, c, {})) {
            if (narrow(read_string(invoke_ptr(get_name, c, {}))) == seg) {
                hit = c;
                break;
            }
        }
        cur = hit;
    }
    return cur;
}

bool PrefabLive::gui_add_child(uintptr_t parent, uintptr_t child) {
    static const auto add_child = find_method_n("via.gui.TransformObject", "addChild", 1);
    const auto r = parent != 0 && child != 0 ? invoke_ptr(add_child, parent, {(void*)child}) : 0;
    return (r & 0xFF) != 0;
}

bool PrefabLive::gui_remove(uintptr_t elem) {
    static const auto remove = find_method_n("via.gui.PlayObject", "remove", 0);
    return elem != 0 && invoke_void(remove, elem, {});
}

bool PrefabLive::gui_set_visible(uintptr_t elem, bool visible) {
    static const auto set_visible = find_method_n("via.gui.PlayObject", "set_Visible", 1);
    return elem != 0 && invoke_void(set_visible, elem, {(void*)(uintptr_t)(visible ? 1 : 0)});
}

bool PrefabLive::gui_offset(uintptr_t elem, float dx, float dy) {
    const auto td = elem != 0 ? type_of(elem) : nullptr;
    if (td == nullptr) return false;
    for (const auto& p : props_of(td)) {
        if (p.name != "Position" || p.size < 8) continue;
        auto v = read_prop(p, elem);
        if (!v.ok || v.bytes.size() < 8) return false;
        float xy[2]{};
        memcpy(xy, v.bytes.data(), 8);
        xy[0] += dx;
        xy[1] += dy;
        memcpy(v.bytes.data(), xy, 8);
        return restore_value(p, elem, v);
    }
    return false;
}

void PrefabLive::gui_temp_show(uintptr_t gui, uintptr_t go) {
    static const auto set_draw = find_method_n("via.GameObject", "set_Draw", 1);
    static const auto set_update = find_method_n("via.GameObject", "set_UpdateSelf", 1);
    static const auto set_enabled = find_method_n("via.gui.GUI", "set_Enabled", 1);
    invoke_void(set_update, go, {(void*)(uintptr_t)1});
    invoke_void(set_draw, go, {(void*)(uintptr_t)1});
    invoke_void(set_enabled, gui, {(void*)(uintptr_t)1});
}

// Resource currently used by the GUI component (Asset holder +0x10)
uintptr_t PrefabLive::gui_resource(uintptr_t gui) {
    static const auto get_asset = find_method_n("via.gui.GUI", "get_Asset", 0);
    const auto holder = gui != 0 && get_asset != nullptr ? invoke_ptr(get_asset, gui, {}) : 0;
    uintptr_t res = 0;
    if (holder == 0 || !safe_read_ptr(holder + 0x10, res)) return 0;
    return res;
}

void PrefabLive::gui_temp_destroy(uintptr_t gui, uintptr_t go) {
    if (go != 0) {
        destroy_go(go);
        release(go);
    }
    if (gui != 0) release(gui);
}

// ---- gui: write file changes into the displayed GUI elements ----
// Done over several frames (large GUIs have tens of thousands of elements; doing it all at once takes over 150 ms in one frame): first walk the 3 element trees step by step (old file, new file, displayed GUI),
// then compare and write element by element. Every element collected from the displayed GUI gets a reference, so freed memory is never accessed if the game removes it meanwhile
struct PrefabLive::GuiDiff {
    struct Tree {
        std::unordered_map<std::string, uintptr_t> at;
        std::unordered_set<std::string> dup;
        std::vector<std::string> order;
        // Elements whose children are pending expansion: {element, path, depth, next child to process (0 means start from the first)}; can pause midway when there are many children
        std::vector<std::tuple<uintptr_t, std::string, int, uintptr_t>> stack;
        bool live{};
    };
    Tree trees[3]; // o, n, l
    size_t walk_tree{};
    size_t next{}; // Comparison position within trees[1].order
    // Elements cloned at runtime (paths present in the displayed GUI but not in the file): matched to template elements in the file
    size_t clone_next{};                                                       // Processing position within trees[2].order
    std::unordered_map<std::string, std::string> clone_of;                     // Displayed GUI path -> template path in the file
    std::unordered_map<std::string, std::vector<std::string>> file_children;   // New file: parent path -> child element paths
    bool children_built{};
    // Properties of template elements changed in the file (computed once per template; clones only read these properties)
    struct TemplateChanges {
        std::vector<std::tuple<const NativeProp*, PropValue, PropValue>> values; // {property, old, new}
        std::vector<std::tuple<const TextProp*, TextValue, TextValue>> texts;
    };
    std::unordered_map<std::string, TemplateChanges> template_changes;
    std::vector<uintptr_t> held;
    GuiApply out;
};

PrefabLive::GuiDiff* PrefabLive::gui_diff_begin(uintptr_t o, uintptr_t n, uintptr_t l) {
    auto d = new GuiDiff{};
    const uintptr_t roots[3] = {o, n, l};
    for (int i = 0; i < 3; ++i) {
        auto& t = d->trees[i];
        t.live = i == 2;
        t.at[""] = roots[i];
        t.order.push_back("");
        t.stack.emplace_back(roots[i], std::string{}, 0, uintptr_t{0});
    }
    if (l != 0) {
        add_ref(l);
        d->held.push_back(l);
    }
    return d;
}

bool PrefabLive::gui_diff_step(GuiDiff* d, double budget_ms) {
    const auto& api = API::get();
    static const auto get_child = api->tdb()->find_method("via.gui.TransformObject", "get_Child");
    static const auto get_next = api->tdb()->find_method("via.gui.PlayObject", "get_Next");
    static const auto get_name = api->tdb()->find_method("via.gui.PlayObject", "get_Name");
    static const auto transform_td = api->tdb()->find_type("via.gui.TransformObject");
    if (get_child == nullptr || get_next == nullptr || get_name == nullptr || transform_td == nullptr) {
        d->out.error = "via.gui.TransformObject.get_Child / PlayObject.get_Next / get_Name not found";
        return true;
    }
    const auto vm = api->get_vm_context();
    auto call_obj = [&](API::Method* m, uintptr_t obj) { return (uintptr_t)m->call<API::ManagedObject*>(vm, (API::ManagedObject*)obj); };
    LARGE_INTEGER freq{}, start{}, now{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    auto over = [&] {
        QueryPerformanceCounter(&now);
        return (now.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart > budget_ms;
    };
    uint32_t steps = 0;
    // 1. Walk the element trees: element paths are "parent path/name"; paths that are ambiguous because of same-named siblings under one parent are not handled
    while (d->walk_tree < 3) {
        auto& t = d->trees[d->walk_tree];
        if (t.stack.empty()) {
            ++d->walk_tree;
            continue;
        }
        auto [obj, prefix, depth, cursor] = std::move(t.stack.back());
        t.stack.pop_back();
        const auto td = obj != 0 ? type_of(obj) : nullptr;
        if (td == nullptr || depth > 48 || !td->is_derived_from(transform_td)) {
            if ((++steps & 31) == 0 && over()) return false;
            continue;
        }
        for (auto c = cursor != 0 ? cursor : call_obj(get_child, obj); c != 0 && t.order.size() < 200000; c = call_obj(get_next, c)) {
            auto key = prefix + "/" + narrow(read_string(call_obj(get_name, c)));
            if (t.at.emplace(key, c).second) {
                t.order.push_back(key);
                if (t.live) {
                    add_ref(c);
                    d->held.push_back(c);
                }
            } else {
                t.dup.insert(key);
            }
            t.stack.emplace_back(c, std::move(key), depth + 1, uintptr_t{0});
            if ((++steps & 31) == 0 && over()) {
                // Next time continue from the next sibling (independent of which of the already pushed children is processed first; paths are unaffected)
                if (const auto nx = call_obj(get_next, c); nx != 0) t.stack.emplace_back(obj, prefix, depth, nx);
                return false;
            }
        }
        if ((++steps & 31) == 0 && over()) return false;
    }
    auto& to = d->trees[0];
    auto& tn = d->trees[1];
    auto& tl = d->trees[2];
    static const auto param_setter = api->tdb()->find_type("via.gui.ParamSetter");
    auto pick = [](const GuiDiff::Tree& t, const std::string& k) -> uintptr_t {
        if (t.dup.contains(k)) return 0;
        const auto it = t.at.find(k);
        return it == t.at.end() ? 0 : it->second;
    };
    if (d->next == 0) {
        d->out.elements = (uint32_t)tn.order.size();
        const auto parent_of = [](const std::string& k) {
            const auto s = k.rfind('/');
            return s == std::string::npos ? std::string{} : k.substr(0, s);
        };
        // Elements added by the file: take only the topmost one (whose parent already exists in the old file); its whole subtree is attached with it
        for (const auto& k : tn.order) {
            if (k.empty() || to.at.contains(k)) continue;
            const auto pk = parent_of(k);
            if (!to.at.contains(pk)) continue;
            // No two elements under the same parent may share a name (the engine's addChild refuses); ambiguous paths are not handled
            if (tn.dup.contains(k) || tl.at.contains(k) || pick(tl, pk) == 0) {
                d->out.add_failed.push_back(k);
            } else {
                d->out.to_add.emplace_back(pk, k);
            }
        }
    }
    // 2. Element by element: for elements of the same type, write only properties the file changed (values, strings, resource paths)
    std::vector<std::pair<const NativeProp*, PropValue>> failed{};
    while (d->next < tn.order.size()) {
        const auto& k = tn.order[d->next++];
        const auto eo = pick(to, k), en = pick(tn, k), el = pick(tl, k);
        if (eo == 0 || en == 0 || el == 0) continue;
        const auto td = type_of(el);
        if (td == nullptr || type_of(eo) != td || type_of(en) != td) continue;
        ++d->out.matched;
        const bool param = param_setter != nullptr && td->is_derived_from(param_setter);
        const auto label = (k.empty() ? std::string{"/"} : k) + ".";
        for (const auto& p : props_of(td)) {
            const auto vo = read_prop(p, eo), vn = read_prop(p, en);
            if (!vo.ok || !vn.ok || same_value(p, vo, vn)) continue;
            const auto vl = read_prop(p, el);
            // Properties whose values differ on every generation: in a 2026-11-09 test, 3 copies were generated from each of the 109 GUI files in the scene and compared element by element; only
            // ParamSetter's IntegerValueInternal/UnsignedIntValueInternal (293 elements in 37 files) differed, everything else matched.
            // These two count as file changes only when the displayed GUI agrees with the old file (the parameter really is an integer with a definite value); otherwise they are random values, and writing them would break the GUI
            // (without the second copy and without this check, reloading ui090100 unchanged wrote 31 random values into the shop GUI)
            if (param && (p.name == "IntegerValueInternal" || p.name == "UnsignedIntValueInternal") && !same_value(p, vl, vo)) continue;
            const auto target = merge_changed(p, vl, vo, vn);
            if (same_value(p, vl, target)) continue;
            if (restore_value(p, el, target) && same_value(p, read_prop(p, el), target)) {
                d->out.applied.push_back(label + p.name);
            } else {
                failed.emplace_back(&p, target);
            }
        }
        for (const auto& p : text_props_of(td)) {
            TextValue vo{}, vn{};
            if (!text_changed(p, eo, 0, en, 0, vo, vn) || read_text(p, el) == vn) continue;
            (write_text(p, el, vn) ? d->out.applied : d->out.skipped).push_back(label + p.name);
        }
        // Properties that could not be written are checked once more after the element's other properties are written: derived properties (e.g. ManipPosition following Position) are at the target value by then and do not count as failures
        for (const auto& [p, target] : failed) {
            if (!same_value(*p, read_prop(*p, el), target)) d->out.skipped.push_back(label + p->name);
        }
        failed.clear();
        if ((++steps & 15) == 0 && over()) return false;
    }
    // 3. Elements cloned at runtime (the game clones from templates: "templateName_N", list items "Item_row_col"; these paths are not in the file):
    // matched level by level to template elements in the file — once the parent is matched, first look for a same-named child (a clone's children share names with the template's), then strip a trailing "_number",
    // and finally take the only child of the same type under the template's parent. Properties the file changed on the template are written to a clone only if its current value still equals the template's old value (values the game set on a particular clone
    // are kept)
    if (!d->children_built) {
        for (const auto& k : tn.order) {
            if (k.empty()) continue;
            const auto s = k.rfind('/');
            d->file_children[k.substr(0, s)].push_back(k);
        }
        d->children_built = true;
    }
    auto strip_index = [](std::string s) {
        // Strip trailing "_number" (possibly several, e.g. Item_9_0 -> Item)
        for (;;) {
            const auto u = s.rfind('_');
            if (u == std::string::npos || u + 1 >= s.size()) return s;
            if (!std::all_of(s.begin() + (ptrdiff_t)u + 1, s.end(), [](char c) { return c >= '0' && c <= '9'; })) return s;
            s.resize(u);
        }
    };
    while (d->clone_next < tl.order.size()) {
        const auto& k = tl.order[d->clone_next++];
        // Present in the old file means it is an element the file deleted (removed in step 4), not a clone
        if (k.empty() || tn.at.contains(k) || to.at.contains(k) || tl.dup.contains(k)) continue;
        const auto s = k.rfind('/');
        const auto pk = k.substr(0, s);
        const auto name = k.substr(s + 1);
        std::string fpk{};
        if (tn.at.contains(pk)) {
            fpk = pk;
        } else if (const auto it = d->clone_of.find(pk); it != d->clone_of.end()) {
            fpk = it->second;
        } else {
            continue; // The parent cannot be matched either (not cloned from a template in the file)
        }
        const auto el = pick(tl, k);
        const auto td = el != 0 ? type_of(el) : nullptr;
        if (td == nullptr) continue;
        std::string fk{};
        auto usable = [&](const std::string& cand) { return pick(tn, cand) != 0 && type_of(pick(tn, cand)) == td; };
        if (const auto c1 = fpk + "/" + name; usable(c1)) {
            fk = c1;
        } else if (const auto c2 = fpk + "/" + strip_index(name); c2 != c1 && usable(c2)) {
            fk = c2;
        } else if (const auto ch = d->file_children.find(fpk); ch != d->file_children.end()) {
            for (const auto& c : ch->second) {
                if (!usable(c)) continue;
                if (!fk.empty()) {
                    fk.clear(); // More than one of the same type; cannot be matched
                    break;
                }
                fk = c;
            }
        }
        if (fk.empty()) continue;
        d->clone_of[k] = fk;
        const auto eo = pick(to, fk), en = pick(tn, fk);
        if (eo == 0 || en == 0 || type_of(eo) != td) continue;
        ++d->out.clones;
        auto tc = d->template_changes.find(fk);
        if (tc == d->template_changes.end()) {
            GuiDiff::TemplateChanges c{};
            for (const auto& p : props_of(td)) {
                auto vo = read_prop(p, eo), vn = read_prop(p, en);
                if (vo.ok && vn.ok && !same_value(p, vo, vn)) c.values.emplace_back(&p, std::move(vo), std::move(vn));
            }
            for (const auto& p : text_props_of(td)) {
                TextValue vo{}, vn{};
                if (text_changed(p, eo, 0, en, 0, vo, vn)) c.texts.emplace_back(&p, std::move(vo), std::move(vn));
            }
            tc = d->template_changes.emplace(fk, std::move(c)).first;
        }
        const auto label = k + ".";
        for (const auto& [p, vo, vn] : tc->second.values) {
            if (!same_value(*p, read_prop(*p, el), vo)) continue; // The game set this clone's value individually
            if (restore_value(*p, el, vn) && same_value(*p, read_prop(*p, el), vn)) {
                ++d->out.clone_written;
                if (d->out.clone_applied.size() < 64) d->out.clone_applied.push_back(label + p->name);
            }
        }
        for (const auto& [p, vo, vn] : tc->second.texts) {
            if (!(read_text(*p, el) == vo)) continue;
            if (write_text(*p, el, vn)) {
                ++d->out.clone_written;
                if (d->out.clone_applied.size() < 64) d->out.clone_applied.push_back(label + p->name);
            }
        }
        if ((++steps & 15) == 0 && over()) return false;
    }
    // 4. Elements deleted by the file: the topmost one (whose parent is still in the new file) is hidden and then removed, its children removed with it.
    // Observed 2026-11-09 with ui020003: after removing the gauge body held by game code, the game kept running normally
    for (const auto& k : to.order) {
        if (k.empty() || tn.at.contains(k)) continue;
        const auto s = k.rfind('/');
        if (!tn.at.contains(s == std::string::npos ? std::string{} : k.substr(0, s))) continue;
        const auto el = pick(tl, k);
        if (el == 0) continue; // No longer present in the displayed GUI (removed by an earlier hot reload, or the path is ambiguous)
        gui_set_visible(el, false);
        (gui_remove(el) ? d->out.removed : d->out.remove_failed).push_back(k);
    }
    d->out.ok = true;
    return true;
}

PrefabLive::GuiApply PrefabLive::gui_diff_end(GuiDiff* d) {
    if (d == nullptr) return {};
    for (const auto e : d->held) release(e);
    auto out = std::move(d->out);
    delete d;
    return out;
}

void PrefabLive::keep_replaced(const std::vector<uintptr_t>& objects) {
    g_kept_replaced.insert(g_kept_replaced.end(), objects.begin(), objects.end());
}

uint32_t PrefabLive::forget_kept() {
    const auto n = (uint32_t)g_kept_replaced.size();
    g_kept_replaced.clear();
    return n;
}

std::string PrefabLive::runtime_registered_by_game(uintptr_t comp) {
    // via.physics.RequestSetCollider: app.ColliderSwitcher.activateAttack/Damage/Sensor and others register collision request sets at runtime;
    // these registrations are runtime state built by game code that a rebuilt component lacks. After force-rebuilding a training-area NPC's component with unchanged data (14 ids, 4 request sets, 3 registered),
    // the physics worker thread processed the stale registrations, read a null pointer and crashed (exe+164a73cb, observed 2026-10-30, dump isolate_npc_rsc_0606.dmp). Components with runtime registrations are treated as held
    const auto td = safe_type_of(comp);
    if (td == nullptr || name_of(td) != "via.physics.RequestSetCollider") return {};
    static const auto get_registered = find_method_n("via.physics.RequestSetCollider", "get_NumRegisteredRequestSetIds", 0);
    if (get_registered == nullptr) return {};
    const auto n = (uint32_t)invoke_ptr(get_registered, comp, {});
    if (n == 0) return {};
    return "collision request sets registered at runtime: " + std::to_string(n) + " (app.ColliderSwitcher etc.)";
}

const void* PrefabLive::type_handle(uintptr_t obj) {
    return safe_type_of(obj);
}

std::string PrefabLive::type_name(const void* td) {
    return td != nullptr ? name_of((API::TypeDefinition*)td) : std::string{"?"};
}

std::string PrefabLive::component_label(uintptr_t comp) {
    uintptr_t go = 0;
    const auto td = safe_type_of(comp);
    const auto name = safe_read_ptr(comp + COMPONENT_OWNER, go) && go != 0 ? narrow(game_object_name(go)) : std::string{"?"};
    return name + ":" + (td ? name_of(td) : std::string{"?"});
}

std::vector<uintptr_t> PrefabLive::rebuild_candidates(uintptr_t old_res, uintptr_t new_res) {
    std::vector<uintptr_t> out{};
    try {
        PrefabTree old_tree{}, new_tree{};
        if (!deserialize_prefab(old_res, old_tree) || !deserialize_prefab(new_res, new_tree)) return out;
        RszWalk old_walk{}, new_walk{};
        if (!walk_prefab(old_res, old_walk) || !walk_prefab(new_res, new_walk)) return out;
        bool by_structure = false;
        uint32_t by_track = 0;
        std::unordered_map<std::wstring, const PrefabTree::GameObject*> old_by_path{};
        for (const auto& go : old_tree.gos) old_by_path[go.path] = &go;
        for (const auto root : find_instances(old_tree, new_tree, old_res, new_res, by_structure, by_track)) {
            const auto live = instance_live_paths(root);
            for (const auto& ngo : new_tree.gos) {
                const auto oit = old_by_path.find(ngo.path);
                const auto lit = live.find(ngo.path);
                if (oit == old_by_path.end() || lit == live.end()) continue;
                const auto comps = components_of(lit->second);
                std::unordered_map<API::TypeDefinition*, int> occurrence{};
                for (size_t ci = 0; ci < ngo.components.size(); ++ci) {
                    const auto td = type_of(ngo.components[ci]);
                    if (td == nullptr) continue;
                    const int occ = occurrence[td]++;
                    if (!native_type(td) || name_of(td) == "via.Transform") continue;
                    const int oi = find_component(oit->second->components, td, occ);
                    const int li = find_component(comps, td, occ);
                    if (oi < 0 || li < 0) continue;
                    if (!same_full_data(old_walk, oit->second->component_slots[oi], new_walk, ngo.component_slots[ci])) out.push_back(comps[li]);
                }
            }
        }
    } catch (...) {
        out.clear();
    }
    return out;
}

// Native array in the component body {element pointer, u32 count, u32 capacity}
struct NativeArrayRef {
    uintptr_t holder{};
    uintptr_t data{};
    uint32_t count{};
};

std::vector<NativeArrayRef> native_arrays_of(uintptr_t comp, const ReadableMap& map) {
    std::vector<NativeArrayRef> out{};
    const auto td = safe_type_of(comp);
    const uint32_t size = td != nullptr && td->get_size() >= 0x40 ? std::min<uint32_t>(td->get_size(), 0x2000) : 0x1000;
    for (uintptr_t off = MANAGED_HEADER; off + 16 <= size; off += 8) {
        if (!map.readable(comp + off, 16)) break;
        const auto data = *(volatile uintptr_t*)(comp + off);
        const auto count = *(volatile uint32_t*)(comp + off + 8);
        const auto cap = *(volatile uint32_t*)(comp + off + 12);
        if (data < 0x10000 || (data & 7) != 0 || count == 0 || count > cap || cap > 0x10000 || !map.readable(data, 8)) continue;
        // Pointers to managed objects (a field that happens to be followed by two small integers) are not native element buffers
        if (plausible_object(data, [&](uintptr_t a, size_t len) { return map.readable(a, len); }) && safe_type_of(data) != nullptr) continue;
        out.push_back({comp, data, count});
    }
    return out;
}

// The native location slot falls inside the element area of a native array of another component on the same GameObject (elements estimated at most 0x100 bytes): returns that component
uintptr_t native_array_holder(uintptr_t comp, uintptr_t slot, const ReadableMap& map,
                              std::unordered_map<uintptr_t, std::vector<NativeArrayRef>>& cache) {
    uintptr_t go = 0;
    if (!safe_read_ptr(comp + COMPONENT_OWNER, go) || go == 0) return 0;
    auto it = cache.find(go);
    if (it == cache.end()) {
        std::vector<NativeArrayRef> arrays{};
        for (const auto c : component_chain(go)) {
            auto a = native_arrays_of(c, map);
            arrays.insert(arrays.end(), a.begin(), a.end());
        }
        it = cache.emplace(go, std::move(arrays)).first;
    }
    for (const auto& a : it->second) {
        if (a.holder != comp && slot >= a.data && slot < a.data + (uintptr_t)a.count * 0x100 && ((slot - a.data) & 7) == 0) return a.holder;
    }
    return 0;
}

std::unordered_map<uintptr_t, std::vector<std::string>> PrefabLive::held_by_code(const std::unordered_map<uintptr_t, std::vector<uintptr_t>>& found) {
    std::unordered_map<uintptr_t, std::vector<std::string>> out{};
    const ReadableMap map{};
    std::unordered_map<uintptr_t, std::vector<NativeArrayRef>> arrays{};
    for (const auto& [comp, slots] : found) {
        std::unordered_set<std::string> names{};
        for (const auto slot : slots) {
            uintptr_t owner = 0;
            bool owned = false;
            try {
                owned = managed_ref_slot(slot, map, owner);
            } catch (...) {
                owned = false;
            }
            // The component is registered in a native array of another component on the same GameObject: the engine builds such lists only when the holder initializes, so after a rebuild the new component would not be registered and the old one would still be used.
            // The secondary animation list of via.motion.Motion (+0x188, entries start with a SecondaryAnimation*) is an exception: after a rebuild, when attaching the new component the list entries are repointed to it
            // and Motion.restartSecondary is called (find_ref_slots / patch_raw), so it does not count as held. Lists of other holders cannot be re-registered and are still treated as held
            if (!owned) {
                uintptr_t holder = 0;
                try {
                    holder = native_array_holder(comp, slot, map, arrays);
                } catch (...) {
                    holder = 0;
                }
                if (holder != 0) {
                    const auto htd = safe_type_of(holder);
                    if (htd != nullptr && is_a(htd, "via.motion.Motion")) continue;
                    names.insert((htd ? htd->get_full_name() : std::string{"?"}) + " native array");
                }
                continue;
            }
            int32_t refs = 0;
            if (owner == 0 || owner == comp || !safe_read_i32(owner + 8, refs) || refs <= 0) continue;
            const auto td = safe_type_of(owner);
            if (td == nullptr || scene_type(td)) continue;
            names.insert(td->get_full_name());
        }
        if (!names.empty()) out[comp].assign(names.begin(), names.end());
    }
    return out;
}

static LiveApplyResult apply_impl(uintptr_t old_res, uintptr_t new_res, bool verbose) {
    LiveApplyResult result{};
    // Locate the type implementation table on the main thread (used later by background scans to filter references)
    static const bool impl_located = [] {
        const auto base = types_impl();
        if (base != 0) {
            log("TDB type implementation table %llx", (unsigned long long)base);
        } else {
            log("TDB type implementation table not found: references in other objects are not rewritten after rebuilding components");
        }
        return base != 0;
    }();
    (void)impl_located;
    PrefabTree old_tree{}, new_tree{};
    g_stage = "deserializing old resource";
    const bool old_ok = deserialize_prefab(old_res, old_tree);
    g_stage = "deserializing new resource";
    const bool new_ok = old_ok && deserialize_prefab(new_res, new_tree);
    if (verbose) log("  pfb live parameters: old %zu GameObjects / new %zu", old_tree.gos.size(), new_tree.gos.size());
    if (!old_ok || !new_ok) {
        log("  pfb live parameters: deserialization failed, skipped");
        return result;
    }

    // Native objects get the RSZ data split per instance and their native deserialize functions called directly; if the split fails, native objects are not modified live
    g_stage = "splitting RSZ instances";
    RszWalk old_walk{}, new_walk{};
    const bool direct = walk_prefab(old_res, old_walk) && walk_prefab(new_res, new_walk);
    if (!direct) {
        log("  pfb live parameters: RSZ instance split failed (%s), native objects are not modified live", (old_walk.ok ? new_walk : old_walk).error.c_str());
    } else if (verbose) {
        log("  pfb live parameters: RSZ instances split, old %u / new %u", old_walk.instance_count - 1, new_walk.instance_count - 1);
    }

    const auto root_name = new_tree.gos[0].name;
    g_stage = "finding scene instances";
    bool by_structure = false;
    uint32_t by_track = 0;
    const auto roots = find_instances(old_tree, new_tree, old_res, new_res, by_structure, by_track);
    g_stage_detail = "collecting results";
    if (by_track > 0) log("  pfb live parameters: found %u renamed instances by spawn record", by_track);
    if (by_structure) {
        log("  pfb live parameters: no instance named %s; %zu matched by hierarchy (the root object may have been renamed at runtime)", narrow(root_name).c_str(), roots.size());
    } else if (verbose) {
        log("  pfb live parameters: root object %s, %zu scene instances", narrow(root_name).c_str(), roots.size());
    }
    if (roots.empty()) {
        if (verbose) log("  pfb live parameters: no instance named %s in the scene", narrow(root_name).c_str());
        return result;
    }

    // Old/new matched by path; new GameObjects are created shallowest first, deleted ones destroyed deepest first
    std::unordered_map<std::wstring, const PrefabTree::GameObject*> old_by_path{}, new_by_path{};
    for (const auto& go : old_tree.gos) old_by_path[go.path] = &go;
    for (const auto& go : new_tree.gos) new_by_path[go.path] = &go;
    std::vector<const PrefabTree::GameObject*> new_order{}, removed{};
    for (const auto& go : new_tree.gos) new_order.push_back(&go);
    for (const auto& go : old_tree.gos) {
        if (!new_by_path.contains(go.path)) removed.push_back(&go);
    }
    std::stable_sort(new_order.begin(), new_order.end(), [](auto a, auto b) { return path_depth(a->path) < path_depth(b->path); });
    std::stable_sort(removed.begin(), removed.end(), [](auto a, auto b) { return path_depth(a->path) > path_depth(b->path); });
    auto label_of = [&](const std::wstring& path) { return narrow(path.empty() ? root_name : path); };
    // Object table index -> GameObject path (targets of the GameObjectRef info table)
    std::unordered_map<int, std::wstring> old_go_path{}, new_go_path{};
    for (const auto& go : old_tree.gos) old_go_path[go.slot] = go.path;
    for (const auto& go : new_tree.gos) new_go_path[go.slot] = go.path;
    const bool has_gorefs = !old_tree.gorefs.empty() || !new_tree.gorefs.empty();

    for (const auto root : roots) {
        g_stage_detail = "entering VM scope";
        // Creating objects and assigning references both happen inside the occupied thread context (new objects are registered when stored into scene objects)
        RszVmScope scope{false};
        // An untouched copy of the new resource: native components that read sub-object references and are new or whose sub-object count changed take their added sub-objects from it.
        // Split separately for each scene instance (on demand); instances never share sub-objects
        std::unique_ptr<RszWalk> clean{};
        auto clean_walk = [&]() -> RszWalk& {
            if (!clean) {
                clean = std::make_unique<RszWalk>();
                if (!walk_prefab(new_res, *clean)) log("  pfb live parameters: splitting the new resource copy failed (%s)", clean->error.c_str());
            }
            return *clean;
        };
        // Another copy of the old resource (used with clean_walk to filter noise in property comparisons: properties that already differ between two copies of the same data do not count as file changes)
        std::unique_ptr<RszWalk> old_clean{};
        auto old_clean_walk = [&]() -> RszWalk& {
            if (!old_clean) {
                old_clean = std::make_unique<RszWalk>();
                walk_prefab(old_res, *old_clean);
            }
            return *old_clean;
        };
        auto second_copy = [](RszWalk& w, int slot, API::TypeDefinition* td) -> uintptr_t {
            return w.ok && slot >= 0 && (size_t)slot < w.objects.size() && type_of(w.objects[slot]) == td ? w.objects[slot] : 0;
        };
        std::unordered_map<std::wstring, uintptr_t> live{};
        g_stage = "collecting instance hierarchy";
        g_stage_detail.clear();
        collect_live(root, live);
        if (const auto moved = add_moved_children(root, live)) {
            log("  pfb live parameters: %s has %u child objects moved elsewhere by the game, handled by the instantiate-time record", narrow(root_name).c_str(), moved);
        }
        ++result.instances;

        // ---- Structure: deletions ----
        g_stage = "deleting GameObjects";
        for (const auto ogo : removed) {
            const auto it = live.find(ogo->path);
            if (it == live.end()) continue;
            const bool ok = destroy_go(it->second);
            log("    %s: deleted in the file, %s", label_of(ogo->path).c_str(), ok ? "GameObject destroyed in the scene" : "destroy failed");
            const auto prefix = ogo->path + L"/";
            for (auto l = live.begin(); l != live.end();) {
                l = (l->first == ogo->path || l->first.starts_with(prefix)) ? live.erase(l) : std::next(l);
            }
        }

        // ---- Structure: new GameObjects ----
        g_stage = "adding GameObjects";
        std::unordered_set<std::wstring> fresh_gos{};
        for (const auto ngo : new_order) {
            if (live.contains(ngo->path)) continue;
            if (old_by_path.contains(ngo->path)) {
                log("    %s: this GameObject is not in the scene instance (possibly removed at runtime), skipped", label_of(ngo->path).c_str());
                continue;
            }
            const auto pos = ngo->path.rfind(L'/');
            const auto parent_path = pos == std::wstring::npos ? std::wstring{} : ngo->path.substr(0, pos);
            const auto pit = live.find(parent_path);
            if (pit == live.end()) {
                result.structure_changed = true;
                log("    %s: parent not found, cannot create", label_of(ngo->path).c_str());
                continue;
            }
            const auto go = create_child_go(ngo->name, pit->second);
            if (go == 0) {
                result.structure_changed = true;
                log("    %s: failed to create the GameObject", label_of(ngo->path).c_str());
                continue;
            }
            live[ngo->path] = go;
            fresh_gos.insert(ngo->path);
            log("    %s: added in the file, GameObject created", label_of(ngo->path).c_str());
        }

        // ---- Structure: add/remove components and build the copy object -> scene instance object mapping ----
        g_stage = "adding/removing components";
        struct Pair {
            const PrefabTree::GameObject* ngo;
            const PrefabTree::GameObject* ogo; // The new GameObject is empty
            uintptr_t live_go;
            bool fresh_go;
            std::vector<uintptr_t> live_comps;  // One-to-one with ngo->components (0 means none)
            std::vector<int> old_index;         // Index of the old component corresponding to ngo->components (-1 means new)
            std::vector<uint8_t> fresh;         // The component was newly created this time
            std::vector<uint8_t> attached;      // New components are taken from the clean copy (data complete, attached to the GameObject)
        };
        struct PendingAttach {
            size_t pair;
            size_t comp;
            std::string label;
        };
        std::vector<PendingAttach> pending{};
        std::vector<std::pair<uintptr_t, std::string>> to_awake{}; // Components attached successfully: awake after GameObjectRef is written (same order as instantiation)
        std::vector<Pair> pairs{};
        SceneMap scene{};
        for (const auto ngo : new_order) {
            const auto lit = live.find(ngo->path);
            if (lit == live.end()) continue;
            const auto oit = old_by_path.find(ngo->path);
            const auto ogo = oit == old_by_path.end() ? nullptr : oit->second;
            // When the old file does not have it but the scene already has an object at the same path (e.g. spawned at runtime), it is also written completely as a new object
            Pair p{ngo, ogo, lit->second, fresh_gos.contains(ngo->path) || ogo == nullptr};
            const auto label = label_of(ngo->path);

            // Components in the old file but not in the new one: destroy the corresponding components in the scene instance
            if (p.ogo != nullptr) {
                std::unordered_map<API::TypeDefinition*, int> new_count{}, seen{};
                for (const auto c : ngo->components) ++new_count[type_of(c)];
                const auto comps = components_of(p.live_go);
                for (const auto oc : p.ogo->components) {
                    const auto td = type_of(oc);
                    if (td == nullptr || seen[td]++ < new_count[td]) continue;
                    const auto li = find_component(comps, td, seen[td] - 1);
                    if (li < 0) continue;
                    const bool ok = destroy_component(comps[li]);
                    log("    %s:%s: deleted in the file, %s", label.c_str(), name_of(td).c_str(), ok ? "component destroyed in the scene" : "destroy failed");
                }
            }

            auto comps = components_of(p.live_go);
            std::unordered_map<API::TypeDefinition*, int> occurrence{};
            for (const auto nc : ngo->components) {
                const auto td = type_of(nc);
                const int occ = td ? occurrence[td]++ : 0;
                const int oi = (td && p.ogo) ? find_component(p.ogo->components, td, occ) : -1;
                const int li = td ? find_component(comps, td, occ) : -1;
                uintptr_t live_c = li >= 0 ? comps[li] : 0;
                bool attached = false;
                if (td != nullptr && li < 0) {
                    const auto slot = ngo->component_slots[p.live_comps.size()];
                    auto& cw = clean_walk();
                    const auto copy = cw.ok && (size_t)slot < cw.objects.size() ? cw.objects[slot] : 0;
                    if (oi >= 0) {
                        log("    %s:%s: this component is not in the scene instance (possibly removed at runtime), skipped", label.c_str(), name_of(td).c_str());
                    } else if (occ > 0) {
                        result.structure_changed = true;
                        log("    %s:%s: the engine does not allow several components of the same type on one GameObject, not created", label.c_str(), name_of(td).c_str());
                    } else if (copy == 0 || type_of(copy) != td || locate_set_components() == nullptr) {
                        result.structure_changed = true;
                        log("    %s:%s: added in the file, but %s; not created", label.c_str(), name_of(td).c_str(),
                            locate_set_components() == nullptr ? "the engine's component attach function was not located" : "the new resource copy has no matching component object");
                    } else {
                        live_c = copy;
                        attached = true;
                        pending.push_back({pairs.size(), p.live_comps.size(), label + ":" + name_of(td)});
                    }
                }
                p.live_comps.push_back(live_c);
                p.old_index.push_back(oi);
                p.fresh.push_back(attached || (p.fresh_go && li >= 0));
                p.attached.push_back(attached);
            }

            scene[ngo->object] = p.live_go;
            if (p.ogo != nullptr) scene[p.ogo->object] = p.live_go;
            for (size_t ci = 0; ci < ngo->components.size(); ++ci) {
                if (p.live_comps[ci] == 0) continue;
                scene[ngo->components[ci]] = p.live_comps[ci];
                if (p.old_index[ci] >= 0) scene[p.ogo->components[p.old_index[ci]]] = p.live_comps[ci];
            }
            pairs.push_back(std::move(p));
        }

        // ---- Existing components whose file data (including sub-objects) changed: take the component from the new resource's clean copy instead, and replace in place afterwards (Transform cannot be replaced, so its parameters are written) ----
        g_stage = "comparing component data";
        struct Rebuild {
            size_t pair;
            size_t comp;
            uintptr_t old_live; // Old component in the scene
            uintptr_t copy;     // Component in the clean copy (becomes the scene component after replacement)
            uintptr_t oc, nc;   // Components in the old/new copies
            std::string label;
            std::string reason;
        };
        std::vector<Rebuild> rebuilds{};
        // Existing components that can be rebuilt (Transform cannot be replaced)
        auto rebuildable = [&](const Pair& p, size_t ci) {
            const int oi = p.old_index[ci];
            const auto td = type_of(p.ngo->components[ci]);
            // Only native components are rebuilt: managed components have lots of runtime state (associations injected by the spawn flow, internal objects they create themselves) that cannot be restored generically after a rebuild (crashed in testing),
            // so their file-changed fields are written in place instead (see the "data" part).
            // Components whose previous rebuild has not finished are not processed again (the caller does not start a new pfb hot reload before the rebuild completes; this is only a safeguard)
            return p.ogo != nullptr && !p.fresh_go && oi >= 0 && !p.attached[ci] && !p.fresh[ci] && p.live_comps[ci] != 0 && td != nullptr &&
                   native_type(td) && name_of(td) != "via.Transform" && !rebuild_pending_for(p.live_comps[ci]) &&
                   (g_in_place == nullptr || !g_in_place->contains(p.live_comps[ci]));
        };
        auto mark_rebuild = [&](size_t pi, size_t ci, const std::string& reason) {
            auto& p = pairs[pi];
            const auto nc = p.ngo->components[ci];
            const auto oc = p.ogo->components[p.old_index[ci]];
            const auto td = type_of(nc);
            const auto label = label_of(p.ngo->path) + ":" + name_of(td);
            auto& cw = clean_walk();
            const int ns = p.ngo->component_slots[ci];
            const auto copy = cw.ok && (size_t)ns < cw.objects.size() ? cw.objects[ns] : 0;
            if (copy == 0 || type_of(copy) != td || locate_set_components() == nullptr) {
                result.structure_changed = true;
                const std::string why = locate_set_components() == nullptr ? "the engine's component attach function was not located" : "the new resource copy has no matching component object";
                log("    %s: %s, but %s; not rebuilt", label.c_str(), reason.c_str(), why.c_str());
                return false;
            }
            rebuilds.push_back({pi, ci, p.live_comps[ci], copy, oc, nc, label, reason});
            p.live_comps[ci] = copy;
            p.fresh[ci] = 1;
            p.attached[ci] = 1;
            scene[nc] = copy;
            scene[oc] = copy;
            return true;
        };
        for (size_t pi = 0; pi < pairs.size(); ++pi) {
            const auto& p = pairs[pi];
            for (size_t ci = 0; ci < p.ngo->components.size(); ++ci) {
                if (!rebuildable(p, ci)) continue;
                const auto td = type_of(p.ngo->components[ci]);
                g_stage_detail = label_of(p.ngo->path) + ":" + name_of(td);
                const int ns = p.ngo->component_slots[ci];
                const int os = p.ogo->component_slots[p.old_index[ci]];
                if (!direct) continue; // Split failed: native components cannot be compared
                const bool same = same_full_data(old_walk, os, new_walk, ns);
                if (!same) mark_rebuild(pi, ci, "file data changed");
            }
        }
        // Raw pointers in other components to the rebuilt component (e.g. via.motion.Chain2 +0x180 referencing the CollisionShapePreset on the same GameObject) do not cause the referrers to be rebuilt too
        // (rebuilding them along would lose runtime state the referrers built, such as a character Motion's private motion layers, which crashed in testing); the caller repoints them to the new component after attaching
        g_stage_detail.clear();

        std::unordered_map<int, uintptr_t> slot_live{};
        CorrMap corr{};
        for (const auto& q : pairs) {
            slot_live[q.ngo->slot] = q.live_go;
            corr[q.ngo->object] = {q.ogo ? q.ogo->object : 0, q.live_go, q.fresh_go};
            for (size_t ci = 0; ci < q.ngo->components.size(); ++ci) {
                if (q.live_comps[ci] == 0) continue;
                slot_live[q.ngo->component_slots[ci]] = q.live_comps[ci];
                const int oi = q.old_index[ci];
                corr[q.ngo->components[ci]] = {oi >= 0 ? q.ogo->components[oi] : 0, q.live_comps[ci], q.fresh[ci] != 0 || oi < 0};
            }
        }

        // ---- Structure: attach new components (first replace scene object references in the copy with the instance's objects, then attach) ----
        if (!pending.empty()) {
            g_stage = "attaching new components";
            auto& cw = clean_walk();
            SceneMap clean_map{};
            for (const auto& [k, l] : slot_live) {
                if ((size_t)k < cw.objects.size() && cw.objects[k] != 0) clean_map[cw.objects[k]] = l;
            }
            for (const auto& a : pending) {
                auto& p = pairs[a.pair];
                const auto comp = p.live_comps[a.comp];
                const auto td = type_of(comp);
                g_stage_detail = a.label;
                if (fieldptr_base(td) != 0) {
                    Differ remap{verbose, &clean_map};
                    remap.remap_scene_refs(comp, td, a.label);
                }
                const bool ok = attach_component(p.live_go, comp);
                log("    %s: added in the file, %s", a.label.c_str(), ok ? "component created from the file data and attached" : "attach failed");
                if (!ok) {
                    result.structure_changed = true;
                    p.live_comps[a.comp] = 0;
                    continue;
                }
                to_awake.emplace_back(comp, a.label);
                ++result.components;
            }
        }

        // ---- Rebuild: call the component attach function once per GameObject and replace in place (old components go through the engine's removal flow, including onDestroy) ----
        if (!rebuilds.empty()) {
            g_stage = "rebuilding components";
            auto& cw = clean_walk();
            SceneMap clean_map{};
            for (const auto& [k, l] : slot_live) {
                if ((size_t)k < cw.objects.size() && cw.objects[k] != 0) clean_map[cw.objects[k]] = l;
            }
            std::map<size_t, std::vector<size_t>> by_pair{};
            for (size_t r = 0; r < rebuilds.size(); ++r) by_pair[rebuilds[r].pair].push_back(r);
            for (const auto& [pi, items] : by_pair) {
                auto& p = pairs[pi];
                std::unordered_map<size_t, RestoreJob> jobs{};
                std::unordered_map<size_t, std::vector<std::pair<uintptr_t, uintptr_t>>> subs{};
                for (const auto r : items) {
                    const auto& rb = rebuilds[r];
                    const auto td = type_of(rb.copy);
                    g_stage_detail = rb.label;
                    if (fieldptr_base(td) != 0) {
                        Differ remap{verbose, &clean_map};
                        remap.remap_scene_refs(rb.copy, td, rb.label);
                    }
                    // Old/new file values (the copies are released when this function returns, so record them now); runtime values are recorded at commit
                    RestoreJob j{};
                    j.comp = rb.copy;
                    j.label = rb.label;
                    j.props = restore_props(td);
                    j.file_old = snapshot(j.props, rb.oc);
                    j.file_new = snapshot(j.props, rb.nc);
                    j.tprops = &restore_text_props(td);
                    j.text_old = read_texts(j.tprops, rb.oc);
                    j.text_new = read_texts(j.tprops, rb.nc);
                    j.wait_start = is_a(td, "via.Behavior");
                    jobs.emplace(r, std::move(j));
                    // Old data sub-object -> new data sub-object
                    auto& sp = subs[r];
                    if (fieldptr_base(td) != 0) {
                        CorrMap m{};
                        Differ{verbose, &scene}.correspond(0, rb.copy, rb.old_live, td, m);
                        for (const auto& [n, c] : m) {
                            if (c.live != 0 && c.live != n) sp.emplace_back(c.live, n);
                        }
                    } else {
                        std::unordered_set<uintptr_t> seen{};
                        native_sub_pairs(rb.old_live, rb.copy, td, 0, sp, seen);
                    }
                }
                // Step 1 (prepare): old components keep working while the caller scans for references to them in the background; after the scan completes they are committed (commit_rebuild) and, once detached, the new ones attached (attach_ready).
                // Old components and data sub-objects are held by the caller (released after references are rewritten); new components are held here until attached
                g_stage_detail = label_of(p.ngo->path);
                RebuildAttach pa{};
                pa.go = p.live_go;
                for (const auto r : items) {
                    const auto& rb = rebuilds[r];
                    log("    %s: %s, component rebuilt from the new file", rb.label.c_str(), rb.reason.c_str());
                    ++result.rebuilt;
                    add_ref(rb.old_live);
                    add_ref(rb.copy);
                    pa.repl.emplace_back(rb.old_live, rb.copy);
                    pa.labels.push_back(rb.label);
                    pa.reasons.push_back(rb.reason);
                    pa.restores.push_back(std::move(jobs[r]));
                    auto& olds = pa.subs.emplace_back();
                    result.replaced.emplace_back(rb.old_live, rb.copy);
                    result.old_components.push_back(rb.old_live);
                    for (const auto& [o, n] : subs[r]) {
                        add_ref(o);
                        olds.push_back(o);
                        result.replaced.emplace_back(o, n);
                    }
                }
                if (!pa.repl.empty()) g_pending_attach.push_back(std::move(pa));
            }
            g_stage_detail.clear();
        }

        // ---- Data ----
        for (const auto& p : pairs) {
            const auto& ngo = *p.ngo;
            const bool is_root = ngo.path.empty();
            const auto go_label = label_of(ngo.path);

            // GameObject's own properties (UpdateSelf/DrawSelf/TimeScale, etc.)
            if (const auto go_td = type_of(ngo.object); go_td != nullptr && type_of(p.live_go) == go_td && direct) {
                g_stage = "comparing GameObjects";
                g_stage_detail = go_label;
                const auto n = p.fresh_go ? (native_full(new_walk, ngo.slot, p.live_go, go_label) ? 1u : 0u)
                                          : native_direct(old_walk, p.ogo->slot, new_walk, ngo.slot, p.live_go, go_label, false);
                if (n > 0) {
                    ++result.components;
                    result.fields += n;
                }
            }

            for (size_t ci = 0; ci < ngo.components.size(); ++ci) {
                const auto nc = ngo.components[ci];
                const auto lc = p.live_comps[ci];
                const auto td = type_of(nc);
                if (td == nullptr || lc == 0) continue;
                const auto label = go_label + ":" + name_of(td);
                g_stage = "comparing components";
                g_stage_detail = label;
                const int oi = p.old_index[ci];
                const bool fresh = p.fresh[ci] != 0;
                if (p.attached[ci]) {
                    // New or rebuilt components: data comes from engine deserialization and is complete; only the correspondence of GameObjectRef holders needs to be established (awake comes last)
                    if (fieldptr_base(td) != 0 && has_gorefs) Differ{verbose, &scene}.correspond(0, nc, lc, td, corr);
                    continue;
                }
                const bool existing = !fresh && oi >= 0;
                const bool held = existing && g_in_place != nullptr && g_in_place->contains(lc);
                if (existing && native_type(td) && name_of(td) != "via.Transform" && !held) {
                    // Existing native components: those whose data changed were rebuilt; unchanged ones are not handled
                    continue;
                }
                if (native_type(td)) {
                    // Native components: new ones are written completely; Transform and components held by game code are not replaced, only parameters changed in the file are applied
                    if (!direct) continue;
                    uint32_t n = 0;
                    const int ns = ngo.component_slots[ci];
                    const int os = existing ? p.ogo->component_slots[oi] : -1;
                    if (!existing) {
                        if (new_walk.has(ns) && rsz_probe_native(new_walk, ns) == NativeProbe::ReadsRefs) {
                            n = native_adopt(clean_walk(), ns, 0, nc, lc, slot_live, true, label);
                        } else {
                            n = native_full(new_walk, ns, lc, label) ? 1 : 0;
                        }
                    } else if (held && same_full_data(old_walk, os, new_walk, ns)) {
                        // This component (including sub-objects) is unchanged in the file
                    } else if (held) {
                        // In-place writes (candidates written in place first, components held by game code): file changes are written property by property (no deserialization rerun on the instance, see native_reflect);
                        // when the sub-object count changes, sub-objects are reread from the file
                        const auto oc = p.ogo->components[oi];
                        n = reads_refs(old_walk, os, new_walk, ns) && sub_object_count_changed(oc, nc)
                                ? native_adopt(clean_walk(), ns, oc, nc, lc, slot_live, false, label)
                                : native_reflect(oc, second_copy(old_clean_walk(), os, td), nc, second_copy(clean_walk(), ns, td), lc, label,
                                                 second_copy(old_walk, os, td), second_copy(new_walk, ns, td));
                        if (n > 0) reset_after_write(lc, td, label);
                    } else {
                        n = native_direct(old_walk, os, new_walk, ns, lc, label, is_root && name_of(td) == "via.Transform");
                    }
                    if (n > 0) {
                        ++result.components;
                        result.fields += n;
                    }
                    continue;
                }
                // Managed components: existing ones only get the fields changed in the file written (through same-named property setters when present); other fields and runtime state stay unchanged;
                // ones present in the scene but not in the old file (e.g. added at runtime) get every parameter from the file written
                Differ differ{verbose, &scene};
                const auto oc = existing ? p.ogo->components[oi] : 0;
                if (existing) {
                    differ.diff_object(oc, nc, lc, td, label, 0);
                } else {
                    differ.copy_all(nc, lc, td, label);
                }
                if (has_gorefs) differ.correspond(oc, nc, lc, td, corr);
                if (differ.structure_changed()) result.structure_changed = true;

                // The part of a managed component read by its nearest native ancestor (e.g. Enabled of via.Behavior)
                uint32_t nn = 0;
                if (direct) {
                    const int ns = ngo.component_slots[ci];
                    const auto native_label = label + " (native part)";
                    if (!existing) {
                        if (new_walk.has(ns) && new_walk.length(ns) > 0) nn = native_full(new_walk, ns, lc, native_label) ? 1 : 0;
                    } else {
                        const int os = p.ogo->component_slots[oi];
                        nn = native_direct(old_walk, os, new_walk, ns, lc, native_label, false, true);
                        // native_direct skips cases where the native ancestor's deserialization reads object references (e.g. the native part of app.ChainSub2):
                        // as with held native components, properties of the old/new copies are compared and written through setters instead (using the nearest native ancestor's properties)
                        if (nn == 0 && !same_full_data(old_walk, os, new_walk, ns)) {
                            auto nat = td;
                            while (nat != nullptr && fieldptr_base(nat) != 0) nat = nat->get_parent_type();
                            if (nat != nullptr) {
                                std::unordered_set<uintptr_t> visited{};
                                std::vector<std::string> applied{}, skipped{};
                                reflect_diff(oc, second_copy(old_clean_walk(), os, td), nc, second_copy(clean_walk(), ns, td), lc, nat, "", 0, visited, applied,
                                             skipped);
                                if (!applied.empty() || !skipped.empty()) {
                                    log("    %s: file changes written by property", native_label.c_str());
                                    if (!applied.empty()) log("      Applied properties: %s", join(applied).c_str());
                                    if (!skipped.empty()) log("      Not written: %s", join(skipped).c_str());
                                    nn = (uint32_t)applied.size();
                                }
                            }
                        }
                        // Parts of referenced data objects read by native code
                        if (!same_full_data(old_walk, os, new_walk, ns)) {
                            std::vector<Differ::NativePart> parts{};
                            Differ{false, &scene}.native_parts(oc, second_copy(old_clean_walk(), os, td), nc, second_copy(clean_walk(), ns, td), lc, td, "",
                                                               0, parts);
                            nn += apply_native_parts(parts, differ.created(), label);
                        }
                    }
                    if (nn > 0 && differ.fields_changed() == 0) ++result.components;
                    result.fields += nn;
                }
                // EPV effect data: when the file changes the element count, ids or group settings, run awake to recompute derived fields (Owner/_ElementID/_GroupNames, etc.)
                if (existing && differ.fields_changed() > 0 && epv_inputs_changed(oc, nc, td)) {
                    const bool ok = invoke_awake(lc, td);
                    log("    %s: element count or ID/grouping changed, awake run to recompute derived fields%s", label.c_str(), ok ? "" : " (execution error)");
                }
                if (differ.fields_changed() > 0) {
                    ++result.components;
                    result.fields += differ.fields_changed();
                    const auto killed = kill_effects_of(differ.changed_providers());
                    if (killed > 0) log("    Ended %u effect instances with old parameters (looping effects regenerate with the new parameters)", killed);
                }
            }
        }

        // ---- GameObjectRef info table ----
        if (has_gorefs) {
            g_stage = "GameObjectRef";
            g_stage_detail.clear();
            result.fields += apply_gorefs(old_tree, new_tree, corr, live, old_go_path, new_go_path, label_of);
        }

        // ---- Newly attached/rebuilt components: data and GameObjectRef are both ready, so run awake (start is called by the engine before the first update) ----
        for (const auto& [comp, label] : to_awake) {
            g_stage = "awake";
            g_stage_detail = label;
            if (!send_awake(comp)) log("    %s: error during awake", label.c_str());
        }

    }
    return result;
}

namespace {
bool involves(const RebuildAttach& a, const std::unordered_set<uintptr_t>& olds) {
    return std::any_of(a.repl.begin(), a.repl.end(), [&](const auto& r) { return olds.contains(r.first); });
}

void attach_entry(RebuildAttach& a) {
    try {
        RszVmScope scope{false};
        attach_rebuilt(a);
    } catch (...) {
        log("    Exception while attaching rebuilt components, skipped");
    }
}
}

std::vector<uintptr_t> PrefabLive::commit_rebuild(const std::vector<uintptr_t>& old_components) {
    const std::unordered_set<uintptr_t> olds(old_components.begin(), old_components.end());
    std::vector<uintptr_t> dropped{};
    for (auto it = g_pending_attach.begin(); it != g_pending_attach.end();) {
        if (it->committed || !involves(*it, olds)) {
            ++it;
            continue;
        }
        try {
            RszVmScope scope{false};
            const auto d = commit_entry(*it);
            dropped.insert(dropped.end(), d.begin(), d.end());
        } catch (...) {
            log("    Exception while committing the rebuild, skipped");
            for (size_t i = 0; i < it->repl.size(); ++i) {
                dropped.push_back(it->repl[i].first);
                dropped.insert(dropped.end(), it->subs[i].begin(), it->subs[i].end());
                release(it->repl[i].second);
            }
            it->repl.clear();
        }
        if (it->repl.empty()) {
            it = g_pending_attach.erase(it);
        } else {
            ++it;
        }
    }
    return dropped;
}

void PrefabLive::attach_ready(const std::vector<uintptr_t>& old_components) {
    const std::unordered_set<uintptr_t> olds(old_components.begin(), old_components.end());
    for (auto it = g_pending_attach.begin(); it != g_pending_attach.end();) {
        if (!it->committed || !involves(*it, olds)) {
            ++it;
            continue;
        }
        auto a = std::move(*it);
        it = g_pending_attach.erase(it);
        attach_entry(a);
    }
}

void PrefabLive::abort_rebuild(const std::vector<uintptr_t>& old_components) {
    const std::unordered_set<uintptr_t> olds(old_components.begin(), old_components.end());
    for (auto it = g_pending_attach.begin(); it != g_pending_attach.end();) {
        if (it->committed || !involves(*it, olds)) {
            ++it;
            continue;
        }
        for (size_t i = 0; i < it->repl.size(); ++i) {
            log("    %s: rebuild not completed (reference scan aborted), original component kept", it->labels[i].c_str());
            release(it->repl[i].second);
        }
        it = g_pending_attach.erase(it);
    }
}

bool PrefabLive::rebuild_busy() {
    return !g_pending_attach.empty();
}

namespace {
// Deferred resource writes: call the setter once the resource finishes loading; give up if the object becomes invalid or on timeout (600 frames)
void step_pending_text(bool shutdown) {
    if (g_pending_text.empty()) return;
    RszVmScope scope{false};
    for (auto it = g_pending_text.begin(); it != g_pending_text.end();) {
        auto& w = *it;
        uintptr_t header = 0;
        const bool alive = safe_read_ptr(w.obj, header) && header == w.header && safe_type_of(w.obj) != nullptr;
        if (!shutdown && alive && !holder_ready(w.holder) && ++w.frames < 600) {
            ++it;
            continue;
        }
        if (!shutdown && alive && holder_ready(w.holder)) {
            void* args[1]{(void*)w.holder};
            reframework::InvokeRet r{};
            const bool ok = safe_invoke(w.p->set, w.obj, args, sizeof(args), &r) && !r.exception_thrown;
            log("    %s: resource loaded, %s %s", w.p->name.c_str(), ok ? "written again" : "error writing again:", w.label.c_str());
        } else if (!shutdown && alive) {
            log("    %s: resource %s did not finish loading within 10 seconds, not written again", w.p->name.c_str(), w.label.c_str());
        }
        release(w.holder);
        it = g_pending_text.erase(it);
    }
}
} // namespace

// Deferred managed resource writes: write into the reference slot (or swap the resource of the holder in place) once the resource is fully loaded; give up if the object becomes invalid, the slot was changed, or on timeout (600 frames)
void step_pending_refs(bool shutdown) {
    auto res_api = API::get()->sdk()->resource;
    for (auto it = g_late_release.begin(); it != g_late_release.end();) {
        if (shutdown || ++it->second >= 120) {
            res_api->release((REFrameworkResourceHandle)it->first);
            it = g_late_release.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = g_pending_refs.begin(); it != g_pending_refs.end();) {
        auto& w = *it;
        uintptr_t header = 0, cur = 0;
        const bool alive = safe_read_ptr(w.owner, header) && header == w.header && safe_type_of(w.owner) != nullptr &&
                           safe_read_ptr(w.slot, cur) && cur == w.expect;
        const uintptr_t new_res = w.target != 0 ? w.res : 0;
        bool ready = false;
        if (alive) {
            if (w.target != 0) {
                ready = resource_fully_ready(w.res);
            } else {
                ready = holder_ready(w.holder);
            }
        }
        if (!shutdown && alive && !ready && ++w.frames < 600) {
            ++it;
            continue;
        }
        if (!shutdown && alive) {
            // Write whether ready or timed out: on timeout the behavior is the same as without deferral
            if (w.target != 0) {
                if ((uintptr_t)InterlockedCompareExchange64((volatile LONG64*)w.slot, (LONG64)new_res, (LONG64)w.expect) == w.expect) {
                    if (w.expect != 0) g_late_release.emplace_back(w.expect, 0);
                    w.res = 0; // The reference has been handed to the holder
                }
                release(w.target);
            } else {
                add_ref(w.holder);
                if ((uintptr_t)InterlockedCompareExchange64((volatile LONG64*)w.slot, (LONG64)w.holder, (LONG64)w.expect) == w.expect) {
                    release(w.expect);
                } else {
                    release(w.holder);
                }
                release(w.holder);
            }
            log("    %s: resource %s, written", w.label.c_str(), ready ? "loaded" : "not loaded within 10 seconds");
        } else {
            if (w.target != 0) release(w.target);
            if (w.holder != 0) release(w.holder);
        }
        if (w.res != 0) res_api->release((REFrameworkResourceHandle)w.res);
        it = g_pending_refs.erase(it);
    }
}

void PrefabLive::update(bool shutdown) {
    step_pending_text(shutdown);
    step_pending_refs(shutdown);
    // Core unload: committed ones (old components already handed to the engine for destruction) are attached immediately so no component goes missing; uncommitted ones are abandoned (old components still in place)
    if (shutdown) {
        for (auto& a : g_pending_attach) {
            if (a.committed) {
                attach_entry(a);
            } else {
                for (const auto& [o, n] : a.repl) release(n);
            }
        }
        g_pending_attach.clear();
    }
    if (g_restores.empty()) return;
    std::vector<RestoreJob> ready{};
    for (auto it = g_restores.begin(); it != g_restores.end();) {
        uintptr_t owner = 0;
        const bool alive = safe_read_ptr(it->comp + COMPONENT_OWNER, owner) && owner != 0;
        const bool started = alive && behavior_started(it->comp);
        if (!shutdown && alive && !started && ++it->frames <= RESTORE_WAIT_FRAMES) {
            ++it;
            continue;
        }
        if (!shutdown && alive) {
            ready.push_back(std::move(*it));
        } else {
            release(it->comp);
        }
        it = g_restores.erase(it);
    }
    for (const auto& j : ready) {
        try {
            RszVmScope scope{false};
            run_restore(j);
        } catch (...) {
            log("    %s: exception while writing back runtime values, skipped", j.label.c_str());
        }
        release(j.comp);
    }
}

// Motion secondary animation list: Motion +0x188 {entry pointer, u32 count, u32 capacity}, entries are 0x28 bytes starting with a SecondaryAnimation*
constexpr uintptr_t MOTION_SECONDARY_LIST = 0x188;
constexpr uintptr_t MOTION_SECONDARY_ENTRY = 0x28;

bool motion_list_entry(uintptr_t motion, uintptr_t slot) {
    uintptr_t data = 0, meta = 0;
    if (!vq_readable(motion + MOTION_SECONDARY_LIST, 16) || !safe_read_ptr(motion + MOTION_SECONDARY_LIST, data) ||
        !safe_read_ptr(motion + MOTION_SECONDARY_LIST + 8, meta) || data == 0 || slot < data) {
        return false;
    }
    return (slot - data) % MOTION_SECONDARY_ENTRY == 0 && (slot - data) / MOTION_SECONDARY_ENTRY < (uint32_t)meta;
}

// owner really is a component attached to a GameObject (it is in the owning GameObject's component chain). When memory is reused, the "object header" found searching backwards from the location
// may be leftover data of a freed component: observed that the plugin's own list recording old objects happened to be allocated there, was taken for raw pointers in a component and rewritten to new objects,
// after which the new object was released instead (one decrement too many, access violation in the engine's release function)
bool attached_component(uintptr_t owner) {
    if (!g_components_layout_ok) return false;
    static const auto go_td = API::get()->tdb()->find_type("via.GameObject");
    uintptr_t go = 0, c = 0;
    if (!vq_readable(owner + COMPONENT_OWNER, 8) || !safe_read_ptr(owner + COMPONENT_OWNER, go) || go == 0) return false;
    bool is_go = false;
    for (auto t = safe_type_of(go); t != nullptr && !is_go; t = t->get_parent_type()) is_go = t == go_td;
    if (!is_go) return false;
    if (!vq_readable(go + GO_FIRST_COMPONENT, 8) || !safe_read_ptr(go + GO_FIRST_COMPONENT, c)) return false;
    for (int i = 0; c != 0 && i < 1024; ++i) {
        if (c == owner) return true;
        if (!vq_readable(c + COMPONENT_NEXT, 8) || !safe_read_ptr(c + COMPONENT_NEXT, c)) break;
    }
    return false;
}

std::vector<RefSlot> PrefabLive::find_ref_slots(const std::unordered_map<uintptr_t, std::vector<uintptr_t>>& found,
                                                const std::unordered_map<uintptr_t, uintptr_t>& mapping, std::vector<RefSlot>& raw_slots) {
    // References inside the objects involved in the rebuild themselves (old components, new components and their sub-objects) are not handled
    std::unordered_set<uintptr_t> involved{};
    for (const auto& [o, n] : mapping) {
        involved.insert(o);
        involved.insert(n);
    }
    std::vector<RefSlot> out{};
    const ReadableMap map{};
    std::unordered_map<uintptr_t, std::vector<NativeArrayRef>> arrays{};
    for (const auto& [old_ptr, slots] : found) {
        if (!mapping.contains(old_ptr)) continue;
        for (const auto slot : slots) {
            uintptr_t owner = 0;
            bool ok = false;
            try {
                ok = managed_ref_slot(slot, map, owner);
            } catch (...) {
                ok = false;
            }
            if (!ok) {
                // Entries of the Motion secondary animation list on the same GameObject (in heap memory outside the Motion object, so the "owning object" found backwards is an unrelated heap object):
                // like raw pointers in components, repointed to the new component after the old one is detached
                uintptr_t holder = 0;
                try {
                    holder = native_array_holder(old_ptr, slot, map, arrays);
                } catch (...) {
                    holder = 0;
                }
                const auto htd = holder != 0 ? safe_type_of(holder) : nullptr;
                if (htd != nullptr && is_a(htd, "via.motion.Motion")) {
                    if (!involved.contains(holder) && motion_list_entry(holder, slot)) raw_slots.push_back({slot, holder, old_ptr, htd});
                    continue;
                }
            }
            int32_t refs = 0;
            if (owner == 0 || involved.contains(owner) || !safe_read_i32(owner + 8, refs) || refs <= 0) continue;
            if (ok) {
                out.push_back({slot, owner, old_ptr, safe_type_of(owner)});
                continue;
            }
            // Raw pointers in live components (not counted, never updated by the engine): they dangle once the old object is reclaimed. Record the locations,
            // recheck after the old component is detached (onDestroy may have cleared them), and keep old objects that are still pointed to
            const auto td = safe_type_of(owner);
            if (td != nullptr && slot - owner >= COMPONENT_HEADER && slot - owner < td->get_size() && component_type(td) && attached_component(owner)) {
                raw_slots.push_back({slot, owner, old_ptr, td});
            }
        }
    }
    return out;
}

// [addr, addr+len) is currently committed, readable and not a guard page
bool readable_now(uintptr_t addr, size_t len) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (addr < 0x10000 || VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT) return false;
    if ((mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 || (mbi.Protect & 0xFF) == 0) return false;
    return addr + len <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
}

// Whether slot is an element of some engine array {data pointer, u32 count, u32 capacity} inside object owner (the array header is in the object; elements may be in the object or on the heap)
struct EngineArrayRef {
    uintptr_t header{};
    uint32_t index{};
    uint32_t count{};
};

EngineArrayRef engine_array_of(uintptr_t owner, uint32_t size, uintptr_t slot) {
    constexpr uint32_t MAX_ELEMENTS = 65536;
    const uint32_t limit = std::min<uint32_t>(size, 0x4000);
    for (uint32_t off = COMPONENT_HEADER; off + 16 <= limit; off += 8) {
        uintptr_t data = 0, meta = 0;
        if (!safe_read_ptr(owner + off, data) || !safe_read_ptr(owner + off + 8, meta)) break;
        const auto count = (uint32_t)meta, capacity = (uint32_t)(meta >> 32);
        if (data == 0 || count == 0 || count > capacity || capacity > MAX_ELEMENTS) continue;
        if (slot >= data && slot < data + 8ull * count && (slot - data) % 8 == 0) return {owner + off, (uint32_t)((slot - data) / 8), count};
    }
    return {};
}

std::unordered_set<uintptr_t> PrefabLive::raw_still_referenced(const std::vector<RefSlot>& raw_slots, std::vector<std::string>* where) {
    std::unordered_set<uintptr_t> out{};
    for (const auto& s : raw_slots) {
        int32_t refs = 0;
        uintptr_t v = 0;
        if (!readable_now(s.owner, 0x10) || !readable_now(s.slot, 8) || !safe_read_i32(s.owner + 8, refs) || refs <= 0 ||
            safe_type_of(s.owner) != s.owner_type) {
            continue;
        }
        if (!safe_read_ptr(s.slot, v) || v != s.old_ptr) continue;
        out.insert(s.old_ptr);
        if (where != nullptr) {
            char buf[160];
            const auto td = (API::TypeDefinition*)s.owner_type;
            const auto arr = engine_array_of(s.owner, td ? td->get_size() : 0, s.slot);
            if (arr.header != 0) {
                sprintf_s(buf, "+0x%llx (array in object +0x%llx, item %u/%u)", (unsigned long long)(s.slot - s.owner), (unsigned long long)(arr.header - s.owner),
                          arr.index, arr.count);
            } else {
                sprintf_s(buf, "+0x%llx", (unsigned long long)(s.slot - s.owner));
            }
            const auto go = [&] {
                uintptr_t g = 0;
                return safe_read_ptr(s.owner + COMPONENT_OWNER, g) ? g : 0;
            }();
            where->push_back(name_of(type_of(s.old_ptr)) + " referenced by " + (go ? narrow(game_object_name(go)) + ":" : std::string{}) +
                             name_of((API::TypeDefinition*)s.owner_type) + buf);
        }
    }
    return out;
}

bool writable(uintptr_t addr);

uint32_t PrefabLive::patch_raw(const std::vector<RefSlot>& raw_slots, const std::unordered_map<uintptr_t, uintptr_t>& mapping) {
    uint32_t patched = 0;
    std::unordered_set<uintptr_t> motions{}; // Motions whose secondary animation lists were rewritten
    for (const auto& s : raw_slots) {
        const auto it = mapping.find(s.old_ptr);
        int32_t refs = 0;
        if (it == mapping.end() || !readable_now(s.owner, 0x10) || !writable(s.slot) || !safe_read_i32(s.owner + 8, refs) || refs <= 0 ||
            safe_type_of(s.owner) != s.owner_type) {
            continue;
        }
        const auto n = it->second;
        add_ref(n);
        if (InterlockedCompareExchange64((volatile LONG64*)s.slot, (LONG64)n, (LONG64)s.old_ptr) != (LONG64)s.old_ptr) {
            release(n);
            continue;
        }
        ++patched;
        // Location outside the object body: Motion secondary animation list entry (find_ref_slots)
        const auto td = (API::TypeDefinition*)s.owner_type;
        if (td != nullptr && (s.slot < s.owner || s.slot >= s.owner + td->get_size())) motions.insert(s.owner);
    }
    // After the list is repointed to the new component, have Motion reinitialize its secondary animations from the list (the engine calls the component's reset function for each entry, and the component re-initializes on its next update)
    static const auto restart = find_method_n("via.motion.Motion", "restartSecondary", 0);
    for (const auto m : motions) {
        if (restart == nullptr) break;
        RszVmScope scope{false};
        reframework::InvokeRet r{};
        const bool ok = safe_invoke(restart, m, nullptr, 0, &r);
        log("    %s: secondary motion list now points to the rebuilt component, %s", component_label(m).c_str(), ok ? "restartSecondary called" : "calling restartSecondary failed");
    }
    return patched;
}

// The page at the location is still committed and writable (the scan runs in the background, memory may be freed meanwhile; an access violation on the main thread triggers REFramework's crash handling, which hung in testing)
bool writable(uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT) return false;
    if ((mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) return false;
    const auto prot = mbi.Protect & 0xFF;
    return (prot == PAGE_READWRITE || prot == PAGE_EXECUTE_READWRITE) && addr + 8 <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
}

// Whether the declared type at the location can hold obj. false means definitely incompatible: the location is not a reference to obj but a dangling pointer that happens to equal obj's address
// (the object it pointed to was freed and its memory reused by obj). Rewriting it would corrupt the owning object and release obj once more on its behalf, so obj gets reclaimed while still in use,
// crashing later during GC marking (observed: when a companion's Ragdoll was rebuilt repeatedly, List<GroupNameParameter>._items was rewritten as a reference to the Ragdoll).
// Such dangling pointers are not rare in game memory (observed: 25 found on the second rebuild of an NPC Ragdoll, including elements of a System.String[]).
// Rule: the declared type must be obj's type or one of its parents; array locations require obj to be an array too. Exceptions treated as compatible: System.Object / via.Object,
// interfaces (C# naming convention starting with I), unresolvable generic parameters, struct interiors, delegates
bool interface_like(const std::string& name) {
    const auto dot = name.rfind('.');
    const auto base = dot == std::string::npos ? name : name.substr(dot + 1);
    return base.size() >= 2 && base[0] == 'I' && isupper((unsigned char)base[1]);
}

bool slot_type_accepts(uintptr_t owner, uintptr_t slot, uintptr_t obj) {
    const auto otd = safe_type_of(owner);
    const auto vtd = safe_type_of(obj);
    if (otd == nullptr || vtd == nullptr) return true;
    const auto& oname = name_of(otd);
    const auto& vname = name_of(vtd);
    API::TypeDefinition* declared = nullptr;
    std::string dname{};
    if (oname.size() > 2 && oname.ends_with("[]")) {
        dname = oname.substr(0, oname.size() - 2); // Array element type
    } else {
        uintptr_t info = 0;
        int32_t start = 0;
        if (!safe_read_ptr(owner, info) || !safe_read_i32(info - 8, start) || start <= 0 || slot < owner + start) return true;
        const auto rel = (uint32_t)(slot - owner - start);
        for (auto t = otd; t != nullptr && dname.empty(); t = t->get_parent_type()) {
            for (const auto f : t->get_fields()) {
                if (f == nullptr || f->is_static()) continue;
                const auto off = f->get_offset_from_fieldptr();
                const auto ft = f->get_type();
                if (ft == nullptr) continue;
                if (off == rel) {
                    if (ft->is_valuetype()) return true; // Position of a struct's first field, treated as compatible
                    dname = name_of(ft);
                    declared = ft;
                    break;
                }
                if (ft->is_valuetype() && rel > off && rel < off + ft->get_size()) return true; // Inside a struct
            }
        }
        if (dname.empty()) return true;
    }
    if (dname.size() > 2 && dname.ends_with("[]")) return vname.ends_with("[]");
    if (dname == "System.Object" || dname == "via.Object" || interface_like(dname)) return true;
    if (declared == nullptr) declared = API::get()->tdb()->find_type(dname.c_str());
    if (declared == nullptr) return true; // Unresolvable types such as generic parameters
    if (declared->is_valuetype()) return false;
    if (vname.ends_with("[]")) return dname == "System.Array";
    return is_a(vtd, dname.c_str());
}

// Reference counts: only locations that hold counts in the engine's reference bitmap are rewritten, and only when the owning object is registered (reference count > 0; child references of newly created unregistered objects hold no counts yet,
// e.g. the array returned by findComponents). After rewriting, the location holds one reference to the new object (add_ref).
// - Old components (in release_old): release the old reference on behalf of the original holder. Locations referencing components are usually written at initialization and only read afterwards; old components must be reclaimed,
//   otherwise their render proxies live on with the object and old meshes/cloth keep being displayed in place (observed: after a GpuCloth rebuild the old cloth stayed in place)
// - Data sub-objects: not released on behalf of the original holder. They may be read/written by worker threads at the same time (e.g. the effect system's references to EPV elements); if the other side already read the old value and later releases it by its own logic,
//   releasing again here would decrement once too often and reclaim the object while still referenced (frequent EPV rebuilds crashed during GC traversal in testing); not releasing at worst leaves the data object unreclaimed
// For error logs: records of releasing old components on behalf of their original holders (old object -> "holder type+offset (count before release)"), printed when an old object is reclaimed early
std::unordered_map<uintptr_t, std::vector<std::string>> g_release_trace{};

std::string PrefabLive::take_release_trace(uintptr_t old_obj) {
    const auto it = g_release_trace.find(old_obj);
    if (it == g_release_trace.end()) return "none";
    std::string s{};
    for (size_t i = 0; i < it->second.size(); ++i) s += (i ? "; " : "") + it->second[i];
    g_release_trace.erase(it);
    return s;
}

namespace {
bool go_valid(uintptr_t go) {
    static const auto get_valid = find_method_n("via.GameObject", "get_Valid", 0);
    return go != 0 && safe_is_managed(go) && type_of(go) != nullptr && name_of(type_of(go)) == "via.GameObject" &&
           (get_valid == nullptr || (invoke_ptr(get_valid, go, {}) & 0xFF) != 0);
}
} // namespace

bool PrefabLive::game_object_alive(uintptr_t go) {
    return go != 0 && go_valid(go);
}

void PrefabLive::clear_release_trace(uintptr_t old_obj) {
    g_release_trace.erase(old_obj);
}

uint32_t PrefabLive::patch_refs(const std::vector<RefSlot>& slots, const std::unordered_map<uintptr_t, uintptr_t>& mapping,
                                const std::unordered_set<uintptr_t>& release_old, bool verbose) {
    uint32_t patched = 0;
    for (const auto& s : slots) {
        const auto it = mapping.find(s.old_ptr);
        if (it == mapping.end() || !writable(s.owner) || !writable(s.slot) || !plausible_object(s.owner, readable_now)) continue;
        // The owning object is still alive (a freed object's memory may still contain its type header), still the type seen at scan time, and the location still holds a count and still points to the old object
        if (*(volatile int32_t*)(s.owner + 8) <= 0) continue;
        if (s.owner_type == nullptr || safe_type_of(s.owner) != s.owner_type || !owned_ref_slot(s.owner, s.slot) ||
            *(volatile uintptr_t*)s.slot != s.old_ptr) {
            continue;
        }
        if (!slot_type_accepts(s.owner, s.slot, s.old_ptr)) {
            log("    Skipped a reference location of mismatched type: the value at %s(%llx)+0x%llx equals the address of %s (dangling pointer, not rewritten or released)", name_of(type_of(s.owner)).c_str(),
                (unsigned long long)s.owner, (unsigned long long)(s.slot - s.owner), name_of(type_of(s.old_ptr)).c_str());
            continue;
        }
        const auto new_ptr = it->second;
        add_ref(new_ptr);
        if (InterlockedCompareExchange64((volatile LONG64*)s.slot, (LONG64)new_ptr, (LONG64)s.old_ptr) != (LONG64)s.old_ptr) {
            release(new_ptr);
            continue;
        }
        if (release_old.contains(s.old_ptr)) {
            int32_t before = 0;
            safe_read_i32(s.old_ptr + 8, before);
            char buf[192];
            sprintf_s(buf, "%s(%llx)+0x%llx count before release %d", name_of(type_of(s.owner)).c_str(), (unsigned long long)s.owner,
                      (unsigned long long)(s.slot - s.owner), before);
            if (g_release_trace.size() < 65536) g_release_trace[s.old_ptr].push_back(buf);
            release(s.old_ptr);
        }
        ++patched;
        if (verbose) {
            log("    Reference redirected to the new object: %s(%llx)+0x%llx -> %s", name_of(type_of(s.owner)).c_str(), (unsigned long long)s.owner,
                (unsigned long long)(s.slot - s.owner), name_of(type_of(new_ptr)).c_str());
        }
    }
    return patched;
}

bool PrefabLive::all_detached(const std::vector<uintptr_t>& components) {
    for (const auto c : components) {
        uintptr_t owner = 0;
        if (safe_read_ptr(c + COMPONENT_OWNER, owner) && owner != 0) return false;
    }
    return true;
}

uint32_t PrefabLive::release_objects(const std::vector<uintptr_t>& objects) {
    // Objects whose reference count was 1 before the release (only the one held here) are reclaimed along with it
    uint32_t freed = 0;
    // Mark the object being released in crash records (the engine reclaims child objects along with it, so on errors the type can be found from this)
    thread_local char note[256]{};
    const auto prev = g_trace_note;
    for (const auto o : objects) {
        int32_t refs = 0;
        if (safe_read_i32(o + 8, refs) && refs == 1) ++freed;
        const auto td = safe_type_of(o);
        _snprintf_s(note, sizeof(note), _TRUNCATE, "releasing object %llx (%s, count %d)", (unsigned long long)o, td ? name_of(td).c_str() : "?", refs);
        g_trace_note = note;
        release(o);
    }
    g_trace_note = prev;
    return freed;
}

namespace {
bool read_managed_string(uintptr_t s, std::wstring& out) {
    out.clear();
    int32_t len = 0;
    if (s == 0 || !safe_read_i32(s + STRING_LENGTH, len) || len < 0 || len > 4096) return false;
    for (int32_t i = 0; i < len; ++i) {
        int32_t two = 0;
        if (!safe_read_i32(s + STRING_CHARS + 2ull * i, two)) return false;
        out.push_back((wchar_t)(two & 0xFFFF));
    }
    return true;
}
}

namespace {
bool in_image(uintptr_t p, size_t len) {
    static const auto range = [] {
        const auto base = (uintptr_t)GetModuleHandleW(nullptr);
        const auto nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
        return std::pair<uintptr_t, uintptr_t>{base, base + nt->OptionalHeader.SizeOfImage};
    }();
    return p >= range.first && p + len <= range.second;
}

// RIP-relative lea (48/4C 8D modrm=00 reg 101) referencing L"awake" within the first range bytes of the function: returns the end of that instruction, or 0 if none
uintptr_t awake_ref_in(uintptr_t fn, size_t range) {
    if (!in_image(fn, range + 8)) return 0;
    for (size_t i = 0; i + 7 <= range; ++i) {
        const auto p = (const uint8_t*)fn + i;
        if ((p[0] != 0x48 && p[0] != 0x4C) || p[1] != 0x8D || (p[2] & 0xC7) != 0x05) continue;
        const auto t = (uintptr_t)(p + 7) + *(const int32_t*)(p + 3);
        if (in_image(t, 12) && vq_readable(t, 12) && wmemcmp((const wchar_t*)t, L"awake", 6) == 0) return (uintptr_t)(p + 7);
    }
    return 0;
}

// First cmp byte ptr [reg+disp8], 0 (80 /7 disp8 00, modrm 0x78-0x7F, no SIB) within range bytes from at: returns disp8, or -1 if none
int32_t cmp_byte_zero_disp(uintptr_t at, size_t range) {
    if (!in_image(at, range + 4)) return -1;
    for (size_t i = 0; i + 4 <= range; ++i) {
        const auto p = (const uint8_t*)at + i;
        if (p[0] == 0x80 && (p[1] & 0xF8) == 0x78 && p[1] != 0x7C && p[3] == 0x00) return p[2];
    }
    return -1;
}

struct ComponentFlags {
    int32_t message = -1, start = -1, awake = -1, enabled = -1;
    std::string error;
};

// get_Started: cmp byte ptr [rdx+X],0; sete al; get_Enabled: mov al,[rdx+X]; ret (rdx is the component, rcx the VM context)
void read_behavior_getters(uintptr_t started, uintptr_t enabled, int32_t& start_off, int32_t& enabled_off) {
    __try {
        if (in_image(started, 8)) {
            const auto p = (const uint8_t*)started;
            if (p[0] == 0x80 && p[1] == 0x7A && p[3] == 0x00 && p[4] == 0x0F && p[5] == 0x94 && p[6] == 0xC0) start_off = p[2];
        }
        if (in_image(enabled, 4)) {
            const auto p = (const uint8_t*)enabled;
            if (p[0] == 0x8A && p[1] == 0x42 && p[3] == 0xC3) enabled_off = p[2];
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// Number of functions referencing L"awake" within the first 0x108 bytes of the vtable; slot is the offset of the (last) slot holding one, awake the offset of the flag it checks afterwards
int32_t scan_vtable_awake(uintptr_t vt, int32_t& slot, int32_t& awake) {
    int32_t hits = 0;
    __try {
        for (int32_t off = 0; off <= 0x100; off += 8) {
            const auto at = awake_ref_in(*(const uintptr_t*)(vt + off), 0x80);
            if (at == 0) continue;
            ++hits;
            slot = off;
            awake = cmp_byte_zero_disp(at, 0x40);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hits = -1;
    }
    return hits;
}

// Offsets of the component message virtual function and behavior component flags (1.42.0.3: message +0x50, start +0x30, awake +0x31, Enabled +0x32):
// - start, Enabled: native implementations of via.Behavior.get_Started / get_Enabled are cmp byte [rdx+X],0; sete al / mov al,[rdx+X]
// - message: the slot of the only function in a behavior component's vtable that references L"awake" (after comparing the message name with "awake" it checks the awake flag, then runs awake)
// - awake: the first cmp byte [reg+X],0 after the "awake" reference in that function
ComponentFlags locate_component_flags(const std::vector<uintptr_t>& behaviors) {
    ComponentFlags f{};
    const auto tdb = API::get()->tdb();
    const auto raw = [&](const char* name) -> uintptr_t {
        const auto m = tdb->find_method("via.Behavior", name);
        return m != nullptr ? (uintptr_t)m->get_function_raw() : 0;
    };
    read_behavior_getters(raw("get_Started"), raw("get_Enabled"), f.start, f.enabled);
    if (f.start < 0 || f.enabled < 0) {
        f.error = "machine code of get_Started / get_Enabled is not the expected byte read";
        return f;
    }
    std::set<uintptr_t> vtables{};
    uint32_t agreed = 0;
    for (const auto c : behaviors) {
        uintptr_t vt = 0;
        if (vtables.size() >= 16 || !safe_read_ptr(c, vt) || vt == 0 || !vtables.insert(vt).second || !vq_readable(vt, 0x108)) continue;
        int32_t slot = -1, awake = -1;
        const auto hits = scan_vtable_awake(vt, slot, awake);
        if (hits != 1 || awake < 0) {
            f.error = "functions referencing \"awake\" in behavior component vtables: " + std::to_string(hits) + (hits == 1 ? ", and it does not check the awake flag" : "");
            return f;
        }
        if (agreed > 0 && (slot != f.message || awake != f.awake)) {
            f.error = "message virtual function or awake flag differs between behavior components";
            return f;
        }
        f.message = slot;
        f.awake = awake;
        ++agreed;
    }
    if (agreed < 2) f.error = "only " + std::to_string(agreed) + " behavior component vtables in the scene could be checked";
    return f;
}
}

LayoutReport PrefabLive::check_layout() {
    LayoutReport r{};
    const auto& api = API::get();
    const auto tdb = api->tdb();
    const auto vm = api->get_vm_context();
    static const auto get_scene = tdb->find_method("via.SceneManager", "get_CurrentScene");
    static const auto find_components = tdb->find_method("via.Scene", "findComponents(System.Type)");
    static const auto get_length = tdb->find_method("System.Array", "get_Length");
    static const auto get_go = tdb->find_method("via.Component", "get_GameObject");
    static const auto get_name = tdb->find_method("via.GameObject", "get_Name");
    const auto join = [](const std::vector<std::string>& v) {
        std::string s{};
        for (size_t i = 0; i < v.size(); ++i) s += (i ? "; " : "") + v[i];
        return s;
    };
    bool enough = true;

    // (1) Managed arrays, strings, holders: compared against results from engine APIs
    std::vector<std::string> mp{};
    auto scene = get_scene ? get_scene->call<API::ManagedObject*>(vm, api->get_native_singleton("via.SceneManager")) : nullptr;
    const auto arr = scene && find_components ? (uintptr_t)find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.Transform")) : 0;
    int32_t count = 0;
    if (arr == 0 || get_length == nullptr) {
        enough = false;
        mp.push_back("cannot get the Transform array in the scene");
    } else {
        const auto len = (int32_t)get_length->invoke((API::ManagedObject*)arr, std::vector<void*>{}).dword;
        uintptr_t e0 = 0;
        if (!safe_read_i32(arr + ARRAY_COUNT, count) || count != len) {
            mp.push_back("array +0x1C count " + std::to_string(count) + ", actual " + std::to_string(len));
        } else if (count > 0 && (!safe_read_ptr(arr + ARRAY_DATA, e0) || safe_type_of(e0) == nullptr || !is_a(safe_type_of(e0), "via.Transform"))) {
            mp.push_back("array +0x20 first element is not a Transform");
        }
        if (count < 16) enough = false;
    }
    std::wstring ws{};
    if (!read_managed_string((uintptr_t)api->create_managed_string(L"file_hotreload"), ws) || ws != L"file_hotreload") {
        mp.push_back("string +0x10/+0x14 contents unreadable");
    }
    uintptr_t tex = 0;
    for (const auto& e : ResourceCache::list(L".tex", 64)) {
        if (e.ready) {
            tex = e.resource;
            break;
        }
    }
    if (tex == 0) {
        enough = false;
        mp.push_back("no texture in the cache, cannot check holders");
    } else {
        const auto h = (uintptr_t)api->sdk()->resource->create_holder((REFrameworkResourceHandle)tex, "via.render.TextureResourceHolder");
        uintptr_t v = 0;
        if (h == 0 || !safe_read_ptr(h + 0x10, v) || v != tex) mp.push_back("holder +0x10 is not its resource");
    }
    r.managed = mp.empty();
    r.lines.push_back(std::string{"Managed arrays/strings/holders: "} + (r.managed ? "passed" : "FAILED: " + join(mp)));

    // (2) Component chain and GameObject names: sample Transforms in the scene
    uint32_t tested = 0, bad = 0;
    std::string first_bad{};
    for (int32_t i = 0; r.managed && i < count && tested < 64; ++i) {
        uintptr_t t = 0;
        if (!safe_read_ptr(arr + ARRAY_DATA + 8ull * i, t) || t == 0) continue;
        const auto go = get_go ? (uintptr_t)get_go->call<API::ManagedObject*>(vm, (API::ManagedObject*)t) : 0;
        if (go == 0) continue;
        ++tested;
        std::string why{};
        uintptr_t v = 0;
        if (!safe_read_ptr(t + COMPONENT_OWNER, v) || v != go) why = "component +0x10 is not the owning GameObject";
        if (why.empty() && (!safe_read_ptr(go + GO_FIRST_COMPONENT, v) || v != t)) why = "GameObject +0x18 is not the first component (Transform)";
        if (why.empty()) {
            uintptr_t c = t;
            int n = 0;
            for (; c != 0 && n < 256; ++n) {
                uintptr_t o = 0;
                if (!safe_read_ptr(c + COMPONENT_OWNER, o) || o != go || safe_type_of(c) == nullptr || !safe_read_ptr(c + COMPONENT_NEXT, c)) break;
            }
            if (c != 0) why = "component +0x18 next-component chain does not hold";
        }
        if (why.empty()) {
            std::wstring a{}, b{};
            uintptr_t sn = 0;
            const auto nm = get_name ? (uintptr_t)get_name->call<API::ManagedObject*>(vm, (API::ManagedObject*)go) : 0;
            if (!safe_read_ptr(go + GAME_OBJECT_NAME, sn) || !read_managed_string(sn, a) || !read_managed_string(nm, b) || a != b) {
                why = "GameObject +0x28 name differs from get_Name";
            }
        }
        if (!why.empty()) {
            ++bad;
            if (first_bad.empty()) first_bad = why;
        }
    }
    if (tested < 16) enough = false;
    r.components = r.managed && tested >= 16 && bad * 20 <= tested;
    r.lines.push_back("Component chain and GameObject: " + std::string{r.components ? "passed" : "FAILED"} + " (sampled " + std::to_string(tested) +
                      (bad > 0 ? ", mismatched " + std::to_string(bad) + ": " + first_bad : std::string{}) + ")");

    // (3) Type database implementation table: kind bits and reference bitmaps. Derive reference field positions from type database fields (only for classes whose fields are all references or primitive value types) and compare against the bitmap bit by bit
    g_tdb_impl_layout_ok = true; // During verification read with the current interpretation
    std::vector<std::string> tp{};
    const auto kind_of = [&](const char* name) {
        const auto t = tdb->find_type(name);
        uintptr_t impl = 0;
        uint32_t k = 0;
        return t != nullptr && type_impl((uintptr_t)t, impl, k) ? (int)k : -1;
    };
    if (types_impl() == 0) tp.push_back("type implementation table not found");
    if (const auto k = kind_of("System.Object[]"); k != 2) tp.push_back("array kind should be 2, read " + std::to_string(k));
    if (const auto k = kind_of("System.Action"); k != 4) tp.push_back("delegate kind should be 4, read " + std::to_string(k));
    uint32_t types_tested = 0, types_ok = 0;
    std::string first_type{};
    const auto n = tdb->get_num_types();
    for (uint32_t i = 0; tp.empty() && i < n && types_tested < 400; i += 7) {
        const auto t = tdb->get_type(i);
        if (t == nullptr || t->is_valuetype()) continue;
        const auto size = t->get_size();
        if (size <= 0x10 || size > 0x2000) continue;
        uintptr_t impl = 0;
        uint32_t k = 0;
        if (!type_impl((uintptr_t)t, impl, k) || k == 2 || k == 4) continue;
        std::set<uint64_t> expect{};
        bool usable = true, any = false;
        for (auto p = t; p != nullptr && usable; p = p->get_parent_type()) {
            for (const auto f : p->get_fields()) {
                if (f == nullptr || f->is_static()) continue;
                const auto ft = f->get_type();
                if (ft == nullptr) {
                    usable = false;
                    break;
                }
                any = true;
                const auto off = f->get_offset_from_fieldptr();
                if (ft->is_valuetype()) {
                    if (!ft->is_primitive() && !ft->is_enum()) usable = false;
                } else if (off % 8 != 0) {
                    usable = false;
                } else {
                    expect.insert(off / 8);
                }
            }
        }
        uintptr_t fs = 0;
        if (!usable || !any || !safe_read_ptr(impl + IMPL_FIELD_SIZE, fs)) continue;
        const auto words = (uint32_t)fs / 8;
        if (words == 0 || words > 0x400) continue;
        bool match = k == 1 || k == 5;
        for (uint64_t idx = 0; match && idx < words; ++idx) match = owned_bit(impl, idx) == (expect.count(idx) != 0);
        for (const auto e : expect) match = match && e < words;
        ++types_tested;
        if (match) {
            ++types_ok;
        } else if (first_type.empty()) {
            first_type = name_of(t);
        }
    }
    if (tp.empty() && types_tested < 50) tp.push_back("only " + std::to_string(types_tested) + " types could be checked");
    if (tp.empty() && types_ok * 20 < types_tested * 19) {
        tp.push_back("reference bitmap mismatches fields " + std::to_string(types_tested - types_ok) + "/" + std::to_string(types_tested) + " (e.g. " + first_type + ")");
    }
    r.tdb_impl = tp.empty();
    r.lines.push_back(std::string{"Type library reference bitmaps: "} + (r.tdb_impl ? "passed (checked " + std::to_string(types_tested) + " types)" : "FAILED: " + join(tp)));

    // (4) Type info structures: REType hash/parent type, REFieldList variable table (verified by rsz_layout); deserialization sequence of managed types (REType +0x68):
    // each entry's offset must be the offset of some instance field in the type database (counted from il2cpp_dump on 2026-11-08: all 248657 entries of 44824 types match)
    std::string ti{};
    const bool rsz_types = rsz_check_type_layout(ti);
    uint32_t seq_types = 0, seq_bad = 0;
    std::string seq_first{};
    for (uint32_t i = 0; i < n && seq_types < 400; i += 5) {
        const auto t = tdb->get_type(i);
        const auto rt = t != nullptr ? (uintptr_t)t->get_type_info() : 0;
        if (rt == 0 || !rsz_managed_type(rt)) continue;
        uintptr_t data = 0, meta = 0;
        const bool readable = safe_read_ptr(rt + RETYPE_DESERIALIZERS, data) && safe_read_ptr(rt + RETYPE_DESERIALIZERS + 8, meta);
        const auto count = (int32_t)(uint32_t)meta;
        if (readable && count == 0) continue;
        std::set<uint32_t> offsets{};
        for (auto p = t; p != nullptr; p = p->get_parent_type()) {
            for (const auto fld : p->get_fields()) {
                if (fld != nullptr && !fld->is_static()) offsets.insert(fld->get_offset_from_fieldptr());
            }
        }
        if (offsets.empty()) continue;
        bool ok = readable && data != 0 && count > 0 && count <= 4096 && vq_readable(data, 16ull * count);
        uint32_t checked = 0;
        for (int32_t k = 0; ok && k < count; ++k) {
            uintptr_t w = 0;
            if (!safe_read_ptr(data + 16ull * k, w)) {
                ok = false;
                break;
            }
            if (((uint32_t)w >> 31) != 0) continue; // Static fields
            ++checked;
            ok = offsets.contains((uint32_t)(w >> 32));
        }
        if (ok && checked == 0) continue;
        ++seq_types;
        if (!ok && seq_bad++ == 0) seq_first = name_of(t);
    }
    std::vector<std::string> tip{};
    if (!rsz_types) tip.push_back(ti);
    if (seq_types < 50) {
        tip.push_back("only " + std::to_string(seq_types) + " managed types with deserialize sequences could be checked");
    } else if (seq_bad * 50 > seq_types) {
        tip.push_back("REType +0x68 deserialize sequence mismatches field offsets " + std::to_string(seq_bad) + "/" + std::to_string(seq_types) + " (e.g. " + seq_first + ")");
    }
    r.type_info = tip.empty();
    g_type_info_layout_ok = r.type_info;
    r.lines.push_back(std::string{"Type info structures: "} +
                      (r.type_info ? "passed (" + ti + ", deserialize sequences " + std::to_string(seq_types) + ")" : "FAILED: " + join(tip)));

    // (5) Component message virtual function and behavior component start/awake flags: taken from machine code and sample-checked against get_Started/get_Enabled;
    // behavior components in the scene have all run awake, so the awake flag should be set
    const auto hx = [](int32_t v) {
        char b[16];
        snprintf(b, sizeof(b), "%X", (unsigned)v);
        return std::string{b};
    };
    std::vector<uintptr_t> behaviors{};
    const auto barr = r.managed && scene && find_components
                          ? (uintptr_t)find_components->call<API::ManagedObject*>(vm, scene, api->typeof("via.Behavior"))
                          : 0;
    int32_t bcount = 0;
    if (barr != 0 && safe_read_i32(barr + ARRAY_COUNT, bcount)) {
        // Components not started yet may come first in the list: take at most 8192 and collect 512 running samples below
        for (int32_t i = 0; i < bcount && behaviors.size() < 8192; ++i) {
            uintptr_t c = 0;
            if (safe_read_ptr(barr + ARRAY_DATA + 8ull * i, c) && c != 0) behaviors.push_back(c);
        }
    }
    if (behaviors.size() < 32) enough = false;
    const auto cf = locate_component_flags(std::vector<uintptr_t>(behaviors.begin(), behaviors.begin() + std::min<size_t>(behaviors.size(), 512)));
    std::vector<std::string> fp{};
    if (!cf.error.empty()) fp.push_back(cf.error);
    uint32_t sampled = 0, bad_start = 0, bad_enabled = 0, awake_set = 0, running = 0;
    if (fp.empty()) {
        static const auto get_started = tdb->find_method("via.Behavior", "get_Started");
        static const auto get_enabled = tdb->find_method("via.Behavior", "get_Enabled");
        const auto comp_t = tdb->find_type("via.Component"), beh_t = tdb->find_type("via.Behavior");
        const auto comp_size = comp_t != nullptr ? (int32_t)comp_t->get_size() : 0;
        const auto beh_size = beh_t != nullptr ? (int32_t)beh_t->get_size() : 0;
        if (cf.awake == cf.start || cf.awake == cf.enabled || cf.awake < comp_size || cf.awake >= beh_size) {
            fp.push_back("awake flag +0x" + hx(cf.awake) + " overlaps start/Enabled or lies outside via.Behavior's own fields");
        }
        for (const auto c : behaviors) {
            if (!fp.empty() || get_started == nullptr || get_enabled == nullptr || running >= 512) break;
            uintptr_t vs = 0, va = 0, ve = 0;
            if (!safe_read_ptr(c + cf.start, vs) || !safe_read_ptr(c + cf.awake, va) || !safe_read_ptr(c + cf.enabled, ve)) continue;
            ++sampled;
            const bool st = get_started->call<bool>(vm, (API::ManagedObject*)c);
            const bool en = get_enabled->call<bool>(vm, (API::ManagedObject*)c);
            if (((vs & 0xFF) == 0) != st) ++bad_start;
            if (((ve & 0xFF) != 0) != en) ++bad_enabled;
            // awake is counted only among started and enabled components: anything started has necessarily run awake, while components never started
            // or disabled (e.g. instances not yet started) are not counted
            if (st && en) {
                ++running;
                if ((va & 0xFF) == 1) ++awake_set;
            }
        }
        if (fp.empty()) {
            if (sampled < 32) enough = false;
            if (bad_start > 0) fp.push_back("start flag mismatches get_Started " + std::to_string(bad_start) + "/" + std::to_string(sampled));
            if (bad_enabled > 0) fp.push_back("Enabled mismatches get_Enabled " + std::to_string(bad_enabled) + "/" + std::to_string(sampled));
            if (running < 32) enough = false;
            if (running > 0 && awake_set * 50 < running * 49) {
                fp.push_back("awake flag +0x" + hx(cf.awake) + " set on only " + std::to_string(awake_set) + "/" + std::to_string(running) + " (started and enabled components)");
            }
        }
    }
    r.component_flags = fp.empty();
    g_component_message_off = r.component_flags ? cf.message : -1;
    g_behavior_start_off = r.component_flags ? cf.start : -1;
    g_behavior_awake_off = r.component_flags ? cf.awake : -1;
    g_behavior_enabled_off = r.component_flags ? cf.enabled : -1;
    r.lines.push_back(std::string{"Component messages and behavior flags: "} +
                      (r.component_flags ? "passed (message virtual function +0x" + hx(cf.message) + ", start +0x" + hx(cf.start) + ", awake +0x" +
                                               hx(cf.awake) + ", sampled " + std::to_string(sampled) + ")"
                                         : "FAILED: " + join(fp)));

    r.conclusive = enough;
    // With too few samples stay disabled and wait for the caller to retry
    g_components_layout_ok = enough && r.components && r.type_info && r.component_flags;
    g_tdb_impl_layout_ok = r.tdb_impl;
    return r;
}


}
