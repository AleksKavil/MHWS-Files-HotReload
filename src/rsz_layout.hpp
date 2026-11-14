#pragma once
// Split an RSZ data block per instance, and invoke a type's own native deserialize function directly on scene instances
//
// Engine RSZ deserialization (sub_14029A4E0, IDA analysis): first create every instance from the instance table, then use one data stream
// {start, current, end, 0} (alignment computed on absolute addresses) to read each instance in instance-index order:
// - Managed types (REType+0x0C & 0x20): sub_14AA11E50 first reads the native part through the nearest native ancestor's (REType+0x78) REFieldList, then reads the managed sequence
// - Native types: read through their own REFieldList (REType+0x58, default if null); a derived class's function also reads the parent class fields
// Both call the function at REFieldList+0x28 through sub_14B10FB00 as fn(object, stream, instance array); object references are stored as instance indices and resolved through the instance array.
//
// Splitting: during one regular engine deserialization, temporarily replace REFieldList+0x28 of every type used in the block with a trampoline that records, for each instance,
// the stream position when reading starts and when the native part has been read, and restore afterwards. The deserialization itself is done entirely by the engine's normal flow (context, scope, object registration).
// Trial runs and applies take the thread context and enter the deserialization scope the same way the engine's main function does.
// Required functions and offsets are extracted at runtime from the machine code of the engine's main function, adapting automatically after game updates.
#include <cstdint>
#include <string>
#include <vector>

namespace hr {

// Take the thread context and enter a local frame scope the way the engine's RSZ main function does (managed objects created meanwhile are allocated here and registered when stored into scene objects);
// when deserialize is true, also enter the deserialization state (used for trial runs / applying native deserialization)
// Locate engine functions and build the type hash index in advance (so the first hot reload does not spend this time on the main thread)
void rsz_warm_up();
// Type hash in the RSZ instance table -> full TDB type name (empty if not found)
std::string rsz_type_name(uint32_t hash);
class RszVmScope {
public:
    explicit RszVmScope(bool deserialize = true);
    ~RszVmScope();
    RszVmScope(const RszVmScope&) = delete;
    RszVmScope& operator=(const RszVmScope&) = delete;

private:
    void* m_ctx{};
    bool m_deserialize{};
};

struct RszWalk {
    bool ok{};
    std::string error;
    const uint8_t* data{};          // Start of the data area in the original RSZ block (the stream points here; alignment matches the engine's load)
    uint32_t data_size{};
    std::vector<uintptr_t> objects; // Deserialized copies by object table index, holding references
    std::vector<uint32_t> begin, end; // Object table index -> data range of the native object (relative to the data area)
    std::vector<uint8_t> native;      // Data range recorded for the native part (the whole instance for purely native objects; the part read by the nearest native ancestor for managed objects)
    std::vector<uintptr_t> inst_objects; // Instance index -> copy object (including data sub-objects; userdata is the shared object the engine fetched by path; null instances are 0)
    std::vector<int32_t> object_table;   // Object table index -> instance index
    std::vector<uint32_t> inst_begin;    // Instance index -> stream position when reading started (relative to the data area; UINT32_MAX for instances that read no data)
    uintptr_t guard{};                // Inaccessible "instance array", used to detect / intercept object reference reads
    size_t guard_size{};
    uint32_t instance_count{};

    RszWalk() = default;
    RszWalk(const RszWalk&) = delete;
    RszWalk& operator=(const RszWalk&) = delete;
    ~RszWalk();

    bool has(uint32_t slot) const { return slot < native.size() && native[slot]; }
    uint32_t length(uint32_t slot) const { return end[slot] - begin[slot]; }
    const uint8_t* bytes(uint32_t slot) const { return data + begin[slot]; }
};

// Deserialize and split an RSZ block (rsz points to the "RSZ\0" header, size is the length to the end of the block). The memory at rsz must stay valid for the lifetime of out
bool rsz_walk(const uint8_t* rsz, size_t size, RszWalk& out);

enum class NativeProbe {
    Ok,             // Reads only value data, length matches the split
    ReadsRefs,      // Read an object reference (not usable on scene instances: the reference would point into the copy)
    LengthMismatch, // Length read differs from the split result
    Failed,         // Execution error
};
const char* to_string(NativeProbe p);

// Trial-run the native deserialization of the slot-th object of the object table on the copy (for managed objects, their native ancestor part): the instance array is replaced with inaccessible memory, so reading an object reference triggers an access violation
NativeProbe rsz_probe_native(const RszWalk& w, uint32_t slot);

// REFieldList -> reflected variable table {pad, VariableDescriptor**, u32 count} (verified by rsz_check_type_layout)
inline constexpr uintptr_t RSZ_FIELDLIST_VARIABLES = 0x20;

// The REType's REFieldList (offset taken from engine code); 0 if none or not located
uintptr_t rsz_field_list(uintptr_t retype);
// Whether the REType is a managed type (same flag bit the engine's RSZ main function dispatches on; managed classes without managed fields count too)
bool rsz_managed_type(uintptr_t retype);
// Verify at startup the hard-coded REType +0x08 hash (against the type database fqn), +0x40 parent type and REFieldList +0x20 variable table (against REFramework's
// TypeInfo API) of this file. If verification fails, lookups by type hash and variable descriptors by property id return nothing. Writes the verdict to report
bool rsz_check_type_layout(std::string& report);

// Property id in the pfb GameObjectRef table -> reflected variable descriptor of the object type (same as the engine's instantiate function sub_14A4A5860:
// a type chain is built along the REType parent chain; the high 16 bits are the level counted from the root type, the low 16 bits are the variable index in that level's REFieldList); 0 if not found
uintptr_t rsz_variable_by_id(uintptr_t obj, uint32_t prop_id);

// Run native deserialization with the data of the slot-th object of the object table on the scene object live (must be the same type as the copy); returns whether the length read matches the split
bool rsz_apply_native(const RszWalk& w, uint32_t slot, uintptr_t live);

// Same as above, but object references are resolved through objs (instance index -> object; size must be instance_count)
bool rsz_apply_native_objs(const RszWalk& w, uint32_t slot, uintptr_t live, std::vector<uintptr_t>& objs);

}
