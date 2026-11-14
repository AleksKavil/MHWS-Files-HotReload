#pragma once
// Access to the via.ResourceManager resource cache table (MHWilds, based on IDA analysis of sub_140061410 / sub_14B0051B0)
//
// ResourceManager layout:
//   +0x490  SRWLOCK            resource table lock
//   +0xDF0  hash table         keyed by path murmur hash
//   +0xDF8  bucket_count
//   +0xE00  element_count
//   +0xE18  buckets            buckets[i] points to the predecessor of bucket i's first node; buckets[bucket_count] is the global list head (before-begin)
// Node: [0]=next [1]=bucket (top bit is a flag) [2]=key [3]=Resource*
// Resource layout:
//   +0x08  wchar_t* path (without the natives/STM/ prefix and version number)
//   +0x28  int32 reference count
//   +0x30  uint64 key (same as the node key)
//   +0x38  uint8 load-complete flag
//
// When Resource::release (0x14B006090 in 1.42.0.3) drops the count to zero with the thread-local flag not set (main thread etc.), it deletes the node and destroys the resource only if the first node
// with that key in the table points to itself (queued at ResourceManager +0x68 for destruction by the resource thread); if the node is missing or points to another resource it just returns,
// leaving the resource at zero references forever, still holding the resources it references (observed 2026-11-07: an mdf2 replaced by a reload was released to 0 by a mesh on the main thread,
// was still there 10 minutes later, so its textures were never reclaimed). Therefore old resources replaced by the plugin keep their last reference held by the plugin and are destroyed with destroy_unlisted once that is the only one left.

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace hr {

struct ResourceEntry {
    uintptr_t resource{};
    uint64_t key{};
    uint64_t node_key{}; // Key in the cache node (filled in by list)
    bool ready{};
    std::wstring path{};
};

class ResourceCache {
public:
    static bool validate(std::string& err);
    // Verify the hard-coded structure offsets of this file at startup (ResourceManager lock and hash table, cache nodes, resource path/reference count/key/load flag/state flag):
    // (1) offset immediates in the engine's release machine code; (2) sampled nodes and resources of the cache table must be self-consistent. Writes the verdict to report; returns false on failure
    static bool check_layout(std::string& report);
    static uintptr_t manager();

    // Returns every resource whose path contains filter (case-insensitive); returns all if filter is empty
    // When vtables is non-empty, list only resources whose vtable is in it (vtables are compared first without reading paths, which walks much faster)
    static std::vector<ResourceEntry> list(const std::wstring& filter, size_t limit, const std::vector<uintptr_t>& vtables = {});
    // Exact path match (case-insensitive, '\\' treated as '/'). First compute the cache key from the path as is and look up the bucket directly; if not found, walk the whole cache table
    static uintptr_t find(const std::wstring& path);
    // Look up several paths (same rules as find; those not found by key are resolved together in one walk); returns normalized path -> resource; unloaded paths are absent from the result
    static std::unordered_map<std::wstring, uintptr_t> find_many(const std::vector<std::wstring>& paths);
    // Whether the engine-memory path string str (wchar_t*) equals normalized after normalization (compared in place, no copy)
    static bool path_matches(uintptr_t str, const std::wstring& normalized);
    // The same path may have several entries (different keys): when mdf2 loads dependent textures it creates one per material, with keys different from the one create_resource computes from the path (observed 2026-11-01:
    // 4 entries for one texture). Returns all matching entries
    // When vtable is non-zero only resources with that vtable are considered (all entries of a path share the resource type; passing the old resource's vtable skips the vast majority of entries)
    static std::vector<uintptr_t> find_all(const std::wstring& path, uintptr_t vtable = 0);
    // Remove the resource from the cache table; a later create_resource for the same path creates a new resource and reads it from disk
    static bool evict(uintptr_t resource);
    // Repoint the cache node pointing to from so it points to to (both must have the same key). After that, from dropping to zero will not delete the node
    // (release only deletes nodes pointing to itself), and to stays in the cache under that key
    static bool replace(uintptr_t from, uintptr_t to);

    // Same test as the engine's release: the first node with this resource's key in the table points to this resource
    static bool listed(uintptr_t resource);
    // Destroy a resource that is not in the table and whose only remaining reference is the caller's: count 1 -> 0 (CAS; fails if someone adds a reference meanwhile), set +0x3B |= 2, and as the engine's release does,
    // push it onto the destruction queue and wake the resource thread. Returns false if the engine functions were not located, the resource is in the table, or the count is not 1 (the caller keeps holding it)
    static bool destroy_unlisted(uintptr_t resource);
    // Whether the destruction queue has been located (the reason for failure is written to err)
    static bool destroy_supported(std::string* err = nullptr);

    static bool read_entry(uintptr_t resource, ResourceEntry& out);
    static std::wstring normalize(std::wstring path);

    // The engine's extension -> resource type table (used by sub_14B0E80D0, called at the start of create_resource):
    // ResourceManager+0xE20 std::map<uint32 extension CRC32, REType*>; the CRC32 is over the UTF-16LE bytes of the extension (after the last '.'),
    // initial value 0xFFFFFFFF, no final xor. Read-only lookup (the engine function inserts a new node for unregistered extensions, so it cannot be called directly).
    // Returns the native resource type name (REType+0x20), or empty if not registered
    static std::string resource_type_for_ext(const std::wstring& ext);
    // Every entry of the table {extension CRC32, type name}
    static std::vector<std::pair<uint32_t, std::string>> resource_types();
    static uint32_t ext_crc(const std::wstring& ext);
};

}
