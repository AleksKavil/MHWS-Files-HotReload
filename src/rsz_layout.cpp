#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <reframework/API.hpp>

#include "crash_trace.hpp"
#include "log.hpp"
#include "memory_scan.hpp"
#include "prefab_live.hpp"
#include "rsz_layout.hpp"

namespace hr {

namespace {
using API = reframework::API;

constexpr uint32_t RSZ_MAGIC = 0x005A5352; // "RSZ\0"
constexpr uintptr_t RSZ_OBJECT_COUNT = 0x08;
constexpr uintptr_t RSZ_INSTANCE_COUNT = 0x0C;
constexpr uintptr_t RSZ_USERDATA_COUNT = 0x10;
constexpr uintptr_t RSZ_INSTANCE_TABLE = 0x18;
constexpr uintptr_t RSZ_DATA = 0x20;
constexpr uintptr_t RSZ_USERDATA_TABLE = 0x28;
constexpr uintptr_t RSZ_OBJECT_TABLE = 0x30;
constexpr uint32_t RSZ_USERDATA_ENTRY = 16; // {instance index, type hash, path offset (8)}
constexpr uint32_t MAX_INSTANCES = 1 << 20;
constexpr uintptr_t RETYPE_HASH = 0x08;         // Matches the type hash in the RSZ instance table (the engine's main function validates existing objects with it), i.e. the type database fqn
constexpr uintptr_t RETYPE_PARENT = 0x40;       // The engine's instantiate function builds the type chain: mov rax,[rax+40h]
constexpr uintptr_t FIELDLIST_VARIABLES = RSZ_FIELDLIST_VARIABLES;
// Startup verification result for the three offsets above (rsz_check_type_layout); if it failed, lookups by type hash and variable descriptors by property id both return nothing
bool g_type_layout_ok = false;

struct NativeArray {
    uintptr_t* data;
    uint32_t size;
    uint32_t capacity;
};

// The engine allocates 36 qwords on the stack for the data stream and initializes only the first 4
struct Stream {
    uintptr_t start;
    uintptr_t cursor;
    uintptr_t end;
    uintptr_t extra[33];
};

using RszMainFn = bool (*)(void*, NativeArray*, const uint8_t*, size_t);
using GetTypeFn = uintptr_t (*)(uintptr_t);
using NativeDeserFn = void (*)(uintptr_t, Stream*, NativeArray*);
using CtxFn = void (*)(uintptr_t);
using ScopeFn = void (*)(uintptr_t, uint8_t);

// ---- Extracting functions and offsets from the engine's machine code ----

struct Engine {
    bool ok{};
    RszMainFn main{};
    // Instance dispatch: call [rax+VT]; test byte ptr [rax+FLAGS],MANAGED; ...; mov rcx,[rax+FIELDS]; ...; mov rcx,[rip+default REFieldList]
    uint8_t vt_get_type{};
    uint8_t flags_off{};
    uint8_t managed_flag{};
    uint8_t fields_off{};
    uint8_t deser_off{};        // REFieldList -> deserialize function (taken from the native dispatch function's mov rax,[rcx+DESER])
    uint8_t native_base_off{};  // Managed REType -> nearest native ancestor REType (taken from the managed deserialize function)
    uintptr_t default_fields{}; // Slot holding the default used when the REFieldList is null
    // Thread context: usage count, scope depth, and enter/leave functions
    uint8_t ctx_refs{};
    uint8_t ctx_depth{};
    CtxFn ctx_begin{};
    CtxFn ctx_gc{};
    CtxFn ctx_end{};
    ScopeFn scope_flag{};
    // Pending managed exception: [[ctx+EXC_HOLDER]+EXC_SLOT]; the engine's handler clears the slot and reports it (REFramework does not locate this function in this game)
    uint8_t exc_holder{};
    uint8_t exc_slot{};
    CtxFn ctx_unhandled{};
};

uintptr_t call_target(const uint8_t* p) {
    return (uintptr_t)(p + 5) + *(const int32_t*)(p + 1);
}

// Byte match with wildcards (-1)
const uint8_t* find_bytes(const uint8_t* from, size_t len, std::initializer_list<int> pat) {
    const auto n = pat.size();
    for (size_t i = 0; i + n <= len; ++i) {
        size_t k = 0;
        for (const int b : pat) {
            if (b >= 0 && from[i + k] != (uint8_t)b) break;
            ++k;
        }
        if (k == n) return from + i;
    }
    return nullptr;
}

bool is_function_entry(uintptr_t addr) {
    DWORD64 image_base = 0;
    const auto entry = RtlLookupFunctionEntry(addr, &image_base, nullptr);
    return entry != nullptr && image_base + entry->BeginAddress == addr;
}

Engine locate_engine() {
    Engine e{};
    const auto main = rsz_engine_deserializer();
    if (main == 0) return e;
    e.main = (RszMainFn)main;
    const auto code = (const uint8_t*)main;
    constexpr size_t MAIN_LEN = 0x1000;
    constexpr int _ = -1;

    // Instance dispatch
    const auto p = find_bytes(code, MAIN_LEN, {0xFF, 0x50, _, 0xF6, 0x40, _, _, 0x75, _, 0x48, 0x8B, 0x48, _, 0x48, 0x85, 0xC9, 0x75, _, 0x48, 0x8B, 0x0D});
    if (p == nullptr) {
        log("[RSZ] Instance dispatch code not found in the main function");
        return e;
    }
    e.vt_get_type = p[2];
    e.flags_off = p[5];
    e.managed_flag = p[6];
    e.fields_off = p[12];
    e.default_fields = (uintptr_t)(p + 25) + *(const int32_t*)(p + 21);

    // After it: native dispatch (leaf function: mov rax,[rcx+DESER]; test rax,rax) and managed deserialization (has unwind info)
    const auto image = (uintptr_t)GetModuleHandleW(nullptr);
    const auto nt = (PIMAGE_NT_HEADERS)(image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
    const auto image_end = image + nt->OptionalHeader.SizeOfImage;
    uintptr_t managed = 0;
    for (uint32_t j = 25; j < 0x80 && managed == 0; ++j) {
        if (p[j] != 0xE8) continue;
        const auto t = call_target(p + j);
        if (t < image || t + 16 > image_end) continue;
        const auto d = (const uint8_t*)t;
        if (e.deser_off == 0) {
            if (d[0] == 0x48 && d[1] == 0x8B && d[2] == 0x41 && d[4] == 0x48 && d[5] == 0x85 && d[6] == 0xC0) {
                e.deser_off = d[3];
                j += 4;
            }
        } else if (is_function_entry(t)) {
            managed = t;
        }
    }
    if (e.deser_off == 0 || managed == 0) {
        log("[RSZ] Native dispatch function / managed deserialize function not found");
        return e;
    }
    // Managed deserialization: mov rax,[rdi+NATIVE_BASE]; mov rcx,[rax+FIELDS]; test rcx,rcx; jnz; mov rcx,[rip+default]
    const auto m = find_bytes((const uint8_t*)managed, 0x100, {0x48, 0x8B, _, _, 0x48, 0x8B, 0x48, e.fields_off, 0x48, 0x85, 0xC9, 0x75, _, 0x48, 0x8B, 0x0D});
    if (m == nullptr) {
        log("[RSZ] Native ancestor offset not found in the managed deserialize function");
        return e;
    }
    e.native_base_off = m[3];

    // Start: mov eax,[rax+REFS]; test eax,eax; jnz; mov rcx,rsi; call context init
    const auto b = find_bytes(code, 0x100, {0x8B, 0x40, _, 0x85, 0xC0, 0x75, _, 0x48, 0x89, _, 0xE8});
    // Scope: inc dword ptr [rsi+DEPTH]; mov rcx,rsi; mov dl,1; call deserialize flag
    const auto s = find_bytes(code, MAIN_LEN, {0xFF, 0x46, _, 0x48, 0x89, _, 0xB2, 0x01, 0xE8});
    if (b == nullptr || s == nullptr) {
        log("[RSZ] Thread context enter code not found in the main function");
        return e;
    }
    e.ctx_refs = b[2];
    e.ctx_begin = (CtxFn)call_target(b + 10);
    e.ctx_depth = s[2];
    e.scope_flag = (ScopeFn)call_target(s + 8);
    // Before the scope: mov rax,[rsi+HOLDER]; cmp qword ptr [rax+SLOT],0; jz; mov rcx,rsi; call unhandled exception
    const auto x = s - 0x13;
    if (x < code || x[0] != 0x48 || x[1] != 0x8B || x[4] != 0x48 || x[5] != 0x83 || x[6] != 0x78 || x[8] != 0x00 || x[9] != 0x74 || x[11] != 0x48 ||
        x[12] != 0x89 || x[14] != 0xE8) {
        log("[RSZ] Managed exception check code not found in the main function");
        return e;
    }
    e.exc_holder = x[3];
    e.exc_slot = x[7];
    e.ctx_unhandled = (CtxFn)call_target(x + 14);
    // End: dec eax; mov [rsi+REFS],eax; test eax,eax; jnz; mov rax,[rsi+50h]; cmp qword ptr [rax+18h],0; jnz; mov rcx,rsi; call frame cleanup; mov rcx,rsi; call leave
    const auto t = find_bytes(code, MAIN_LEN, {0xFF, 0xC8, 0x89, _, e.ctx_refs, 0x85, 0xC0, 0x75, _, 0x48, 0x8B, _, _, 0x48, 0x83, _, _, 0x00, 0x0F, 0x85, _, _,
                                               _, _, 0x48, 0x89, _, 0xE8, _, _, _, _, 0x48, 0x89, _, 0xE8});
    if (t == nullptr) {
        log("[RSZ] Thread context end code not found in the main function");
        return e;
    }
    e.ctx_gc = (CtxFn)call_target(t + 27);
    e.ctx_end = (CtxFn)call_target(t + 35);
    e.ok = true;

    log("[RSZ] Main function +%llx; REType: type vtable slot 0x%x, flags +0x%x&0x%x, field list +0x%x, native ancestor +0x%x; REFieldList deserialize +0x%x; "
        "context: count +0x%x, depth +0x%x, enter +%llx, frame cleanup +%llx, end +%llx, scope +%llx",
        (unsigned long long)(main - image), e.vt_get_type, e.flags_off, e.managed_flag, e.fields_off, e.native_base_off, e.deser_off, e.ctx_refs,
        e.ctx_depth, (unsigned long long)((uintptr_t)e.ctx_begin - image), (unsigned long long)((uintptr_t)e.ctx_gc - image),
        (unsigned long long)((uintptr_t)e.ctx_end - image), (unsigned long long)((uintptr_t)e.scope_flag - image));
    log("[RSZ] Managed exception slot [ctx+0x%x]+0x%x, unhandled exception +%llx", e.exc_holder, e.exc_slot, (unsigned long long)((uintptr_t)e.ctx_unhandled - image));
    return e;
}

const Engine& engine() {
    static const Engine e = locate_engine();
    return e;
}

// ---- Thread context: same usage/scope handling as the engine's main function ----

using VmScope = RszVmScope;

bool pending_exception(uintptr_t ctx) {
    const auto& e = engine();
    const auto holder = *(const uintptr_t*)(ctx + e.exc_holder);
    return holder != 0 && *(const uintptr_t*)(holder + e.exc_slot) != 0;
}

// Exception object type and message (System.Exception._message)
std::string describe_exception(uintptr_t ctx) {
    const auto& e = engine();
    const auto exc = *(const uintptr_t*)(*(const uintptr_t*)(ctx + e.exc_holder) + e.exc_slot);
    if (!managed_object_safe(exc)) return "not a managed object";
    const auto obj = (API::ManagedObject*)exc;
    const auto td = obj->get_type_definition();
    std::string text = td ? td->get_full_name() : "unknown type";
    const auto msg = obj->get_field<uintptr_t>("_message");
    if (msg != nullptr && *msg != 0) {
        const auto len = *(const int32_t*)(*msg + 0x10);
        if (len > 0 && len < 4096) text += ": " + narrow(std::wstring((const wchar_t*)(*msg + 0x14), (size_t)len));
    }
    return text;
}

// Same as the engine: if an exception is pending, hand it to the engine to clear and report
void handle_exception(uintptr_t ctx) {
    if (!pending_exception(ctx)) return;
    log("    Managed exception during a plugin call (%s), handed to the engine to clear", describe_exception(ctx).c_str());
    engine().ctx_unhandled(ctx);
}

// ---- Types and deserialize functions ----

bool safe_type_of(uintptr_t obj, uint8_t vt, uintptr_t& out) {
    __try {
        const auto vtable = *(const uintptr_t*)obj;
        out = ((GetTypeFn) * (const uintptr_t*)(vtable + vt))(obj);
        return out != 0;
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

uintptr_t retype_of(uintptr_t obj) {
    uintptr_t rt = 0;
    return obj != 0 && safe_type_of(obj, engine().vt_get_type, rt) ? rt : 0;
}

bool is_managed_type(uintptr_t rt) {
    const auto& e = engine();
    return (*(const uint8_t*)(rt + e.flags_off) & e.managed_flag) != 0;
}

// Same as instance dispatch: managed types use their nearest native ancestor; a null REFieldList uses the default
uintptr_t fields_of(uintptr_t rt) {
    const auto& e = engine();
    if (is_managed_type(rt)) rt = *(const uintptr_t*)(rt + e.native_base_off);
    if (rt == 0) return 0;
    const auto fields = *(const uintptr_t*)(rt + e.fields_off);
    return fields ? fields : *(const uintptr_t*)e.default_fields;
}

// Type hash -> REType (walks the TDB once)
uintptr_t retype_by_hash(uint32_t hash) {
    static const auto index = [] {
        std::unordered_map<uint32_t, uintptr_t> m{};
        const auto tdb = API::get()->tdb();
        const auto n = tdb->get_num_types();
        for (uint32_t i = 0; i < n; ++i) {
            const auto td = tdb->get_type(i);
            const auto rt = td ? (uintptr_t)td->get_type_info() : 0;
            if (rt != 0) m.emplace(*(const uint32_t*)(rt + RETYPE_HASH), rt);
        }
        log("[RSZ] Type hash index: %zu entries", m.size());
        return m;
    }();
    if (!g_type_layout_ok) return 0;
    const auto it = index.find(hash);
    return it == index.end() ? 0 : it->second;
}

std::string type_name_by_hash(uint32_t hash) {
    static const auto index = [] {
        std::unordered_map<uint32_t, std::string> m{};
        const auto tdb = API::get()->tdb();
        const auto n = tdb->get_num_types();
        for (uint32_t i = 0; i < n; ++i) {
            const auto td = tdb->get_type(i);
            const auto rt = td ? (uintptr_t)td->get_type_info() : 0;
            if (rt != 0) m.emplace(*(const uint32_t*)(rt + RETYPE_HASH), td->get_full_name());
        }
        return m;
    }();
    if (!g_type_layout_ok) return {};
    const auto it = index.find(hash);
    return it == index.end() ? std::string{} : it->second;
}

// ---- Splitting: temporarily replace REFieldList+0x28 with a trampoline and record where each instance is read ----

struct Record {
    uintptr_t obj;
    uintptr_t before;
    uintptr_t after;
};

struct Recorder {
    std::vector<Record> records;
    int depth{};
    // Instance array before the first instance is read (userdata instances have already been fetched by path by the engine, without reading data)
    uint32_t want_objs{};
    std::vector<uintptr_t> objs;
};

thread_local Recorder* t_recorder = nullptr;

// One trampoline per REFieldList: mov r9, entry; mov rax, recorder_thunk; jmp rax
struct PatchEntry {
    uintptr_t fields{};
    NativeDeserFn original{};
    uint8_t* stub{};
};

void recorder_thunk(uintptr_t obj, Stream* s, NativeArray* objs, PatchEntry* entry) {
    const auto rec = t_recorder;
    if (rec == nullptr || rec->depth > 0) {
        // Other threads or nested calls: forward unchanged
        if (entry->original) entry->original(obj, s, objs);
        return;
    }
    ++rec->depth;
    if (rec->records.empty() && rec->objs.empty() && objs != nullptr && objs->size == rec->want_objs) {
        rec->objs.assign(objs->data, objs->data + objs->size);
    }
    const auto before = s->cursor;
    if (entry->original) entry->original(obj, s, objs);
    rec->records.push_back({obj, before, s->cursor});
    --rec->depth;
}

PatchEntry* patch_entry(uintptr_t fields) {
    // Trampolines are never freed once created (other threads may still hold old pointers around the restore)
    static std::unordered_map<uintptr_t, PatchEntry*> entries{};
    auto& slot = entries[fields];
    if (slot != nullptr) return slot;
    auto entry = new PatchEntry{};
    entry->fields = fields;
    auto stub = (uint8_t*)VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (stub == nullptr) {
        delete entry;
        return nullptr;
    }
    uint8_t* q = stub;
    *q++ = 0x49; *q++ = 0xB9; // mov r9, imm64
    *(uint64_t*)q = (uint64_t)entry;
    q += 8;
    *q++ = 0x48; *q++ = 0xB8; // mov rax, imm64
    *(uint64_t*)q = (uint64_t)&recorder_thunk;
    q += 8;
    *q++ = 0xFF; *q++ = 0xE0; // jmp rax
    FlushInstructionCache(GetCurrentProcess(), stub, 32);
    entry->stub = stub;
    slot = entry;
    return entry;
}

bool writable(uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
}

class FieldListPatch {
public:
    bool add(uintptr_t fields) {
        if (fields == 0) return false;
        for (const auto& p : m_patched) {
            if (p->fields == fields) return true;
        }
        const auto slot = fields + engine().deser_off;
        if (!writable(slot)) return false;
        const auto entry = patch_entry(fields);
        if (entry == nullptr) return false;
        entry->original = *(const NativeDeserFn*)slot;
        InterlockedExchangePointer((void* volatile*)slot, entry->stub);
        m_patched.push_back(entry);
        return true;
    }
    ~FieldListPatch() {
        const auto off = engine().deser_off;
        for (const auto p : m_patched) {
            InterlockedCompareExchangePointer((void* volatile*)(p->fields + off), (void*)p->original, p->stub);
        }
    }

private:
    std::vector<PatchEntry*> m_patched;
};

bool safe_main(RszMainFn fn, NativeArray* arr, const uint8_t* data, size_t size) {
    __try {
        return fn(nullptr, arr, data, size);
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

// ---- Trial run and apply ----

// Native deserialization; reading the instance array within [lo, hi) is recorded as reading an object reference
int guard_filter(EXCEPTION_POINTERS* ep, uintptr_t lo, uintptr_t hi, bool& hit_guard) {
    const auto r = ep->ExceptionRecord;
    hit_guard = r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && r->NumberParameters >= 2 && r->ExceptionInformation[1] >= lo &&
                r->ExceptionInformation[1] < hi;
    return read_fault_filter(ep);
}

bool safe_native(NativeDeserFn fn, uintptr_t obj, Stream* s, NativeArray* objs, uintptr_t lo, uintptr_t hi, bool& hit_guard) {
    hit_guard = false;
    // During a trial run, reading [lo, hi) (the inaccessible instance array) is an expected access violation; the crash trace only counts it
    crash_trace_expect(lo, hi);
    __try {
        fn(obj, s, objs);
        crash_trace_expect(0, 0);
        return true;
    } __except (guard_filter(GetExceptionInformation(), lo, hi, hit_guard)) {
        crash_trace_expect(0, 0);
        return false;
    }
}

struct NativeRun {
    bool ran{};
    bool hit_guard{};
    uintptr_t consumed{};
};

NativeRun run_native(const RszWalk& w, uint32_t slot, uintptr_t obj, std::vector<uintptr_t>* real_objs = nullptr) {
    NativeRun r{};
    const auto rt = retype_of(obj);
    if (rt == 0) return r; // For managed types fields_of picks the nearest native ancestor's deserialize function
    const auto fields = fields_of(rt);
    const auto fn = fields ? *(const NativeDeserFn*)(fields + engine().deser_off) : nullptr;
    if (fn == nullptr) {
        r.ran = true;
        return r;
    }
    Stream s{};
    s.start = (uintptr_t)w.data;
    s.cursor = (uintptr_t)w.data + w.begin[slot];
    s.end = (uintptr_t)w.data + w.data_size;
    NativeArray objs{(uintptr_t*)w.guard, w.instance_count, w.instance_count};
    if (real_objs != nullptr) objs = NativeArray{real_objs->data(), (uint32_t)real_objs->size(), (uint32_t)real_objs->size()};
    {
        VmScope scope{};
        r.ran = safe_native(fn, obj, &s, &objs, w.guard, w.guard + w.guard_size, r.hit_guard);
    }
    r.consumed = s.cursor - ((uintptr_t)w.data + w.begin[slot]);
    return r;
}

void release(uintptr_t obj) {
    if (obj) API::get()->sdk()->managed_object->release((REFrameworkManagedObjectHandle)obj);
}

uint32_t align_up(uint32_t v, uint32_t a) {
    return (v + a - 1) & ~(a - 1);
}

bool fail(RszWalk& w, std::string msg) {
    w.ok = false;
    w.error = std::move(msg);
    return false;
}
}

std::string rsz_type_name(uint32_t hash) {
    return type_name_by_hash(hash);
}

void rsz_warm_up() {
    if (engine().ok) retype_by_hash(0);
}

RszVmScope::RszVmScope(bool deserialize) : m_deserialize(deserialize) {
    const auto& e = engine();
    const auto ctx_obj = API::get()->get_vm_context();
    if (!e.ok || ctx_obj == nullptr) return;
    m_ctx = ctx_obj;
    const auto ctx = (uintptr_t)ctx_obj;
    auto& refs = *(int32_t*)(ctx + e.ctx_refs);
    if (refs == 0) e.ctx_begin(ctx);
    ++refs;
    // Exceptions left over before entering (e.g. thrown and unhandled when another script called a managed method): clear them first like the engine's main function does
    if (pending_exception(ctx)) {
        log("Leftover managed exception in the thread context (%s), handed to the engine to clear", describe_exception(ctx).c_str());
        e.ctx_unhandled(ctx);
    }
    ++*(int32_t*)(ctx + e.ctx_depth);
    if (m_deserialize) e.scope_flag(ctx, 1);
}

RszVmScope::~RszVmScope() {
    const auto& e = engine();
    if (!e.ok || m_ctx == nullptr) return;
    const auto ctx = (uintptr_t)m_ctx;
    if (m_deserialize) e.scope_flag(ctx, 0);
    const auto depth = --*(int32_t*)(ctx + e.ctx_depth);
    handle_exception(ctx);
    if (depth == 0) e.ctx_gc(ctx);
    auto& refs = *(int32_t*)(ctx + e.ctx_refs);
    if (--refs == 0) {
        handle_exception(ctx);
        e.ctx_gc(ctx);
        e.ctx_end(ctx);
    }
}

RszWalk::~RszWalk() {
    for (auto o : objects) release(o);
    if (guard != 0) VirtualFree((void*)guard, 0, MEM_RELEASE);
}

const char* to_string(NativeProbe p) {
    switch (p) {
    case NativeProbe::Ok: return "reads value data only";
    case NativeProbe::ReadsRefs: return "reads object references";
    case NativeProbe::LengthMismatch: return "read length differs from the split";
    default: return "execution error";
    }
}

bool rsz_walk(const uint8_t* rsz, size_t size, RszWalk& w) {
    const auto& e = engine();
    if (!e.ok) return fail(w, "engine deserialize function not located");
    if (size < RSZ_OBJECT_TABLE || *(const uint32_t*)rsz != RSZ_MAGIC) return fail(w, "not an RSZ block");

    const auto object_count = *(const uint32_t*)(rsz + RSZ_OBJECT_COUNT);
    const auto n = *(const uint32_t*)(rsz + RSZ_INSTANCE_COUNT);
    const auto userdata_count = *(const uint32_t*)(rsz + RSZ_USERDATA_COUNT);
    const auto inst_off = *(const uint64_t*)(rsz + RSZ_INSTANCE_TABLE);
    const auto data_off = *(const uint64_t*)(rsz + RSZ_DATA);
    const auto userdata_off = *(const uint64_t*)(rsz + RSZ_USERDATA_TABLE);
    if (n < 2 || n > MAX_INSTANCES || object_count == 0 || object_count >= n) return fail(w, "abnormal instance count");
    if (inst_off + 8ull * n > size || data_off > size || userdata_off + (uint64_t)RSZ_USERDATA_ENTRY * userdata_count > size) {
        return fail(w, "abnormal RSZ header offsets");
    }
    w.data = rsz + data_off;
    w.data_size = (uint32_t)(size - data_off);
    w.instance_count = n;

    // REFieldList used by each instance type in the block (userdata instances do not read data)
    std::unordered_set<uint32_t> userdata{};
    for (uint32_t u = 0; u < userdata_count; ++u) userdata.insert(*(const uint32_t*)(rsz + userdata_off + (uint64_t)RSZ_USERDATA_ENTRY * u));
    uint32_t expected = 0;
    FieldListPatch patch{};
    for (uint32_t i = 1; i < n; ++i) {
        const auto hash = *(const uint32_t*)(rsz + inst_off + 8ull * i);
        if (hash == 0 || userdata.contains(i)) continue;
        const auto rt = retype_by_hash(hash);
        if (rt == 0) return fail(w, "type hash of instance " + std::to_string(i) + " not found");
        if (!patch.add(fields_of(rt))) return fail(w, "field list of instance " + std::to_string(i) + " cannot be replaced");
        ++expected;
    }

    // Regular engine deserialization, recording where each instance is read along the way
    Recorder rec{};
    rec.records.reserve(expected);
    rec.want_objs = n;
    std::vector<uintptr_t> out(object_count + 1, 0);
    NativeArray arr{out.data(), object_count, object_count};
    t_recorder = &rec;
    const bool ok = safe_main(e.main, &arr, rsz, size);
    t_recorder = nullptr;
    if (!ok || arr.data != out.data()) {
        if (arr.data == out.data()) w.objects.assign(out.begin(), out.begin() + object_count);
        return fail(w, "engine deserialization failed");
    }
    w.objects.assign(out.begin(), out.begin() + object_count);
    if (rec.records.size() != expected) {
        return fail(w, "recorded " + std::to_string(rec.records.size()) + " instances, expected " + std::to_string(expected));
    }
    const auto lo = (uintptr_t)w.data;
    const auto hi = lo + w.data_size;
    uintptr_t prev = lo;
    for (const auto& r : rec.records) {
        if (r.before < prev || r.after < r.before || r.after > hi) return fail(w, "recorded read positions are not contiguous");
        prev = r.after;
    }

    // Objects in the object table: for purely native objects the native part is the whole instance; for managed objects record the part read by the nearest native ancestor
    std::unordered_map<uintptr_t, const Record*> by_obj{};
    for (const auto& r : rec.records) by_obj.emplace(r.obj, &r);
    // Instance index -> copy object: records are in instance order, skipping null instances and userdata; userdata instances use the shared object the engine fetched by path
    w.inst_objects.assign(n, 0);
    w.inst_begin.assign(n, UINT32_MAX);
    for (uint32_t i = 1, r = 0; i < n && r < rec.records.size(); ++i) {
        const auto hash = *(const uint32_t*)(rsz + inst_off + 8ull * i);
        if (hash == 0 || userdata.contains(i)) continue;
        w.inst_begin[i] = (uint32_t)(rec.records[r].before - lo);
        w.inst_objects[i] = rec.records[r++].obj;
    }
    if (rec.objs.size() == n) {
        for (const auto u : userdata) {
            if (u < n) w.inst_objects[u] = rec.objs[u];
        }
    } else if (!userdata.empty()) {
        return fail(w, "userdata instance not obtained");
    }
    w.object_table.assign((const int32_t*)(rsz + RSZ_OBJECT_TABLE), (const int32_t*)(rsz + RSZ_OBJECT_TABLE) + object_count);
    w.begin.assign(object_count, 0);
    w.end.assign(object_count, 0);
    w.native.assign(object_count, 0);
    for (uint32_t k = 0; k < object_count; ++k) {
        const auto obj = w.objects[k];
        const auto it = by_obj.find(obj);
        const auto rt = retype_of(obj);
        if (it == by_obj.end() || rt == 0) continue;
        w.begin[k] = (uint32_t)(it->second->before - lo);
        w.end[k] = (uint32_t)(it->second->after - lo);
        w.native[k] = 1;
    }

    w.guard_size = align_up((uint32_t)(8ull * n), 0x10000);
    w.guard = (uintptr_t)VirtualAlloc(nullptr, w.guard_size, MEM_RESERVE, PAGE_NOACCESS);
    if (w.guard == 0) return fail(w, "cannot allocate memory for detection");
    w.ok = true;
    return true;
}

uintptr_t rsz_variable_by_id(uintptr_t obj, uint32_t prop_id) {
    const auto& e = engine();
    const auto rt = retype_of(obj);
    if (!e.ok || rt == 0 || !g_type_layout_ok) return 0;
    uintptr_t desc = 0;
    __try {
        uintptr_t chain[64]{};
        uint32_t n = 0;
        for (auto t = rt; t != 0 && n < 64; t = *(const uintptr_t*)(t + RETYPE_PARENT)) chain[n++] = t;
        const auto up = prop_id >> 16;
        if (n == 0 || n == 64 || up >= n) return 0;
        const auto level = chain[n - 1 - up];
        auto fields = *(const uintptr_t*)(level + e.fields_off);
        if (fields == 0) fields = *(const uintptr_t*)e.default_fields;
        const auto vars = fields ? *(const uintptr_t*)(fields + FIELDLIST_VARIABLES) : 0;
        if (vars == 0) return 0;
        const auto data = *(const uintptr_t*)(vars + 0x08);
        const auto num = *(const uint32_t*)(vars + 0x10);
        const auto index = prop_id & 0xFFFF;
        if (data != 0 && index < num) desc = *(const uintptr_t*)(data + 8ull * index);
    } __except (read_fault_filter(GetExceptionInformation())) {
        desc = 0;
    }
    return desc;
}

bool rsz_managed_type(uintptr_t retype) {
    const auto& e = engine();
    if (!e.ok || retype == 0) return false;
    __try {
        return is_managed_type(retype);
    } __except (read_fault_filter(GetExceptionInformation())) {
        return false;
    }
}

uintptr_t rsz_field_list(uintptr_t retype) {
    const auto& e = engine();
    if (!e.ok || retype == 0) return 0;
    uintptr_t fields = 0;
    __try {
        fields = *(const uintptr_t*)(retype + e.fields_off);
    } __except (read_fault_filter(GetExceptionInformation())) {
        fields = 0;
    }
    return fields;
}

bool rsz_check_type_layout(std::string& report) {
    const auto tdb = API::get()->tdb();
    uint32_t tested = 0, bad_hash = 0, parents = 0, bad_parent = 0, vars = 0, bad_vars = 0;
    std::string first_hash{}, first_parent{}, first_vars{};
    const auto n = tdb->get_num_types();
    for (uint32_t i = 0; i < n && tested < 600; i += 5) {
        const auto td = tdb->get_type(i);
        const auto ti = td != nullptr ? td->get_type_info() : nullptr;
        const auto rt = (uintptr_t)ti;
        if (rt == 0) continue;
        uintptr_t v = 0;
        // Hash: the type database fqn (murmur3 of the full type name). Generic and array types compute fqn from a different name and differ from +0x08 (about 20% observed on 2026-11-08), so they are excluded
        const auto name = td->get_full_name();
        if (name.find_first_of("`<[") == std::string::npos) {
            ++tested;
            if (!safe_read_ptr(rt + RETYPE_HASH, v) || (uint32_t)v != td->get_fqn()) {
                if (bad_hash++ == 0) first_hash = name;
            }
        }
        // Parent type and reflected variable table: compared against REFramework's TypeInfo API
        if (const auto parent = (uintptr_t)ti->get_parent(); parent != 0) {
            ++parents;
            if (!safe_read_ptr(rt + RETYPE_PARENT, v) || v != parent) {
                if (bad_parent++ == 0) first_parent = td->get_full_name();
            }
        }
        const auto api_vars = (uintptr_t)ti->get_reflection_properties();
        const auto fields = rsz_field_list(rt);
        if (api_vars != 0 && fields != 0) {
            ++vars;
            if (!safe_read_ptr(fields + FIELDLIST_VARIABLES, v) || v != api_vars) {
                if (bad_vars++ == 0) first_vars = td->get_full_name();
            }
        }
    }
    std::vector<std::string> problems{};
    const auto check = [&](const char* what, uint32_t total, uint32_t bad, uint32_t need, const std::string& example) {
        if (total < need) {
            problems.push_back(std::string{what} + ": only " + std::to_string(total) + " types could be checked");
        } else if (bad * 50 > total) {
            problems.push_back(std::string{what} + ": mismatched " + std::to_string(bad) + "/" + std::to_string(total) + " (e.g. " + example + ")");
        }
    };
    check("REType +0x08 hash", tested, bad_hash, 200, first_hash);
    check("REType +0x40 parent type", parents, bad_parent, 100, first_parent);
    check("REFieldList +0x20 variable table", vars, bad_vars, 50, first_vars);
    g_type_layout_ok = problems.empty();
    if (g_type_layout_ok) {
        report = "checked " + std::to_string(tested) + " types";
    } else {
        for (size_t i = 0; i < problems.size(); ++i) report += (i ? "; " : "") + problems[i];
    }
    return g_type_layout_ok;
}

NativeProbe rsz_probe_native(const RszWalk& w, uint32_t slot) {
    if (!w.ok || !w.has(slot)) return NativeProbe::Failed;
    const auto r = run_native(w, slot, w.objects[slot]);
    if (r.hit_guard) return NativeProbe::ReadsRefs;
    if (!r.ran) return NativeProbe::Failed;
    return r.consumed == w.length(slot) ? NativeProbe::Ok : NativeProbe::LengthMismatch;
}

bool rsz_apply_native_objs(const RszWalk& w, uint32_t slot, uintptr_t live, std::vector<uintptr_t>& objs) {
    if (!w.ok || !w.has(slot) || live == 0 || objs.size() != w.instance_count) return false;
    if (retype_of(live) != retype_of(w.objects[slot])) return false;
    const auto r = run_native(w, slot, live, &objs);
    return r.ran && r.consumed == w.length(slot);
}

bool rsz_apply_native(const RszWalk& w, uint32_t slot, uintptr_t live) {
    if (!w.ok || !w.has(slot) || live == 0) return false;
    if (retype_of(live) != retype_of(w.objects[slot])) return false;
    const auto r = run_native(w, slot, live);
    return r.ran && !r.hit_guard && r.consumed == w.length(slot);
}

}
