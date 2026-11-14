#pragma once
// Live pfb parameter editing: apply the fields that differ between the old and new pfb to objects already instantiated in the scene
//
// How it works (MHWilds, IDA analysis of sub_14A4A5860 = prefab instantiation):
// - PrefabResource+0x58 points to the raw pfb data in memory, +0x60 is the data size
// - pfb header +0x04 is the GameObject count, +0x30 the RSZ block offset, and the GameObject info table starts at +0x38
//   each entry is 12 bytes {object index, parent GameObject info index, component count}
// - Engine RSZ deserialize function (sub_14029A4E0, signature (_, NativeArray* out, data, size))
//   the output array follows the RSZ object table: objects[object index] is the via.GameObject, followed by its component-count components
// - The old and new resources are each deserialized once (not instantiated, so no Awake/registration side effects), compared, and applied to scene instances:
//   components whose data changed are rebuilt from the new file (the engine's component attach function replaces them in place, old components go through the engine's removal flow, new components get awake/start);
//   GameObject and Transform cannot be replaced, so only the parameters changed in the file are written
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace hr {

// Reference location hit by the memory scan: a reference field/array element in managed object owner pointing to old object old_ptr
struct RefSlot {
    uintptr_t slot;
    uintptr_t owner;
    uintptr_t old_ptr;
    const void* owner_type; // Type of the owning object at scan time (verified on the main thread before rewriting)
};

struct LiveApplyResult {
    uint32_t instances{};   // Number of matched scene instances (root GameObjects)
    uint32_t rebuilt{};     // Number of components rebuilt from the new file
    uint32_t components{};  // Number of components/GameObjects added or with parameters written
    uint32_t fields{};      // Number of fields written
    bool structure_changed{}; // There are structural changes that cannot be hot-updated (see the log)
    uint32_t objects_replaced{}; // .user: number of writes that replaced the object itself (container element count changed, referenced object created/nulled/swapped for another)
    std::vector<uintptr_t> old_resources; // .user: old resources swapped out after a holder changed its resource in place (one reference held each; the caller releases them later)
    // Objects before and after the rebuild (components and their data sub-objects): old -> new. One reference is held on each old object;
    // the caller scans memory to repoint references from other objects to the new objects (patch_refs) and then releases them through release_objects
    std::vector<std::pair<uintptr_t, uintptr_t>> replaced;
    // Old components replaced (handed to the engine for deferred destruction). The reference scan waits until the engine has detached them (detaching cleans up part of their references itself)
    std::vector<uintptr_t> old_components;
};

// Structure offset verification at startup (PrefabLive::check_layout)
struct LayoutReport {
    bool managed{};    // Managed array +0x1C/+0x20, string +0x10/+0x14, holder +0x10: relied on everywhere; the plugin is disabled if this fails
    bool components{}; // Component +0x10 owning GameObject, GameObject +0x18 first component, component +0x18 next, GameObject +0x28 name: if this fails, live pfb writes and component raw pointer rewriting are disabled
    bool tdb_impl{};   // Kinds and reference bitmaps of the type database implementation table: reference redirection is disabled if this fails
    bool type_info{};  // REType hash/parent type/deserialization sequence and REFieldList variable table: live pfb writes and .user reloads are disabled if this fails
    bool component_flags{}; // Component message virtual function and behavior start/awake flags (taken from machine code and sample-checked): live pfb writes are disabled if this fails
    bool conclusive{}; // Enough samples (enough objects and textures in the scene); if not, the caller retries later and the related features stay disabled meanwhile
    std::vector<std::string> lines;
};

// The resource can be handed to components: data fully read; mdf2 additionally requires the referenced mmtr/textures to be fully loaded (implemented in hotreload.cpp)
bool resource_fully_ready(uintptr_t res);

// Parse an RSZ block with the engine's RSZ deserialize function (no instantiation). objects returns the root objects in object table order,
// each holding a reference; the caller releases them with rsz_release
bool rsz_deserialize(const uint8_t* rsz, size_t size, std::vector<uintptr_t>& objects);
void rsz_release(std::vector<uintptr_t>& objects);
// Address of the engine RSZ deserialize function (located by signature); 0 if not found
uintptr_t rsz_engine_deserializer();

class PrefabLive {
public:
    // Verify the hard-coded offsets of managed objects, the component chain and the type database implementation table in this file (against results from engine APIs); failing parts are disabled immediately
    static LayoutReport check_layout();
    // in_place: native components not rebuilt but with file-changed parameters written in place (candidates written in place first, components held by game code)
    static LiveApplyResult apply(uintptr_t old_res, uintptr_t new_res, bool verbose, const std::unordered_set<uintptr_t>* in_place = nullptr);
    // .user: write the fields changed in the new file into the root object live_root the game is using (UserDataResource +0x88, shared by everyone).
    // old_file / new_file are complete USR files; when old_file is empty (first reload this session) the current values of live_root are used as the old values and every field that differs from the new file is written.
    // Called on the main thread; structure_changed true means the update could not be done (different root object type, deserialization failed, or structural changes that cannot be hot-updated)
    static LiveApplyResult apply_userdata(const std::vector<uint8_t>& old_file, const std::vector<uint8_t>& new_file, uintptr_t live_root,
                                          const std::string& label);
    // rcol: the component (via.physics.RequestSetCollider) copies the user data and collision shapes from the rcol at initialization, so swapping the resource does nothing for existing components.
    // Parse the old and new files (when prev is empty the values in use are the old values); if the structure is the same, match every scene component using this rcol by request set ID:
    // write the file changes to request set/shape user data field by field, and write shape geometry (after its layout is verified) and bound joint names to the colliders. Called on the main thread
    struct RcolApply {
        bool ok{};                // File parsed successfully
        bool structure_changed{}; // Request set/group/shape structure differs; components in use keep their original data
        std::string error;
        uint32_t components{}, groups{}, sets{};
        uint32_t ud_fields{}, shapes{}, joints{}, layers{}, masks{};
        std::vector<std::string> not_live; // Items changed in the file that cannot be written live (layer, attributes, names, etc.)
        std::vector<std::pair<uintptr_t, uintptr_t>> replaced; // Objects swapped out while writing user data (same as .user)
        std::vector<uintptr_t> old_resources;                  // Old resources swapped out after a holder changed its resource in place (released later by the caller)
    };
    static RcolApply apply_rcol(const std::wstring& path, const std::vector<uint8_t>& prev, const std::vector<uint8_t>& data);
    // The rcol resource with path path (case-insensitive) currently used by collision components in the scene; 0 if none
    static uintptr_t rcol_resource_in_use(const std::wstring& path);
    // Old objects replaced in apply_userdata are held by the plugin and never released. When the core unloads (including hot swaps) only the records are dropped and the references are kept until the game exits
    // (the game may still remember these addresses; releasing them on unload would bring back the risk of accessing freed memory); returns the number dropped
    static uint32_t forget_kept();
    // Hand objects to the keep list above (the reference the caller held is transferred to the plugin and never released): old objects swapped out by .user whose references were repointed to the new objects
    static void keep_replaced(const std::vector<uintptr_t>& objects);
    // gui: o is the root element (View) of the GUI generated from the old file, n the one from the new file, l the displayed GUI. Elements are matched by "parent path/name";
    // on elements of the same type only the properties changed in the file (values, strings, resource paths) are written; values changed at runtime but not in the file are kept.
    // Elements deleted by the file (the topmost one whose parent still exists) are hidden and removed from the displayed GUI; elements added by the file (the topmost one whose parent already existed in the old file)
    // are only collected into to_add, and the caller attaches them from a new-file GUI that has drawn one frame off-screen.
    // Done over several frames: each gui_diff_step uses at most budget_ms and returns true when finished; called on the main thread
    struct GuiApply {
        bool ok{};
        std::string error;
        uint32_t elements{}, matched{};
        std::vector<std::string> applied, skipped;
        std::vector<std::pair<std::string, std::string>> to_add; // {parent element path, new element path}
        std::vector<std::string> add_failed;                     // Could not add: an element with the same name already exists, or the parent was not found or is ambiguous
        std::vector<std::string> removed, remove_failed;
        uint32_t clones{}, clone_written{};      // Elements cloned at runtime: number matched to a template, number of writes
        std::vector<std::string> clone_applied; // First 64
    };
    struct GuiDiff;
    static GuiDiff* gui_diff_begin(uintptr_t o, uintptr_t n, uintptr_t l);
    static bool gui_diff_step(GuiDiff* d, double budget_ms);
    static GuiApply gui_diff_end(GuiDiff* d);
    // Create a via.gui.GUI (with resource as its resource) on a hidden temporary GameObject so the engine generates a GUI from it; returns the GUI component and writes the GameObject to go
    static uintptr_t gui_temp_create(uintptr_t resource, uintptr_t& go);
    static void gui_temp_destroy(uintptr_t gui, uintptr_t go);
    // Returns the root element (View) once the GUI is ready, otherwise 0
    static uintptr_t gui_view(uintptr_t gui);
    // Resource currently used by the GUI component
    static uintptr_t gui_resource(uintptr_t gui);
    // Whether this is a comparison GUI created by gui_temp_create
    static bool gui_is_temp(uintptr_t gui);
    // GUI elements: find, attach, remove, move (used to add/remove elements the file added/removed)
    static uintptr_t gui_find(uintptr_t view, const std::string& path); // Path as in gui_diff ("/RootWindow/..."); no reference added
    static bool gui_add_child(uintptr_t parent, uintptr_t child);
    static bool gui_remove(uintptr_t elem);
    static bool gui_set_visible(uintptr_t elem, bool visible);
    static bool gui_offset(uintptr_t elem, float dx, float dy);
    static void gui_temp_show(uintptr_t gui, uintptr_t go); // Enable the temporary GUI's component, drawing and update
    // For logs: "GameObject name:component type"
    static std::string component_label(uintptr_t comp);
    // Take (and clear) the record of releasing this old object on behalf of its original holder, for error logs; clear only clears
    static std::string take_release_trace(uintptr_t old_obj);
    static void clear_release_trace(uintptr_t old_obj);
    // Whether the GameObject is still alive (false once destroyed by the game), for error logs
    static bool game_object_alive(uintptr_t go);
    // Returns a description if the component holds registration state built by game code at runtime that cannot be restored after a rebuild (treated as held by game code), otherwise empty
    static std::string runtime_registered_by_game(uintptr_t comp);
    static const void* type_handle(uintptr_t obj);
    static std::string type_name(const void* td);
    // Main thread, scene not modified: existing native components (objects in scene instances) whose file data changed and that the rules would rebuild
    static std::vector<uintptr_t> rebuild_candidates(uintptr_t old_res, uintptr_t new_res);
    // Background thread: components in the memory scan results held by game code (a live managed object other than scene objects points to them with a counted reference) -> holder type name
    static std::unordered_map<uintptr_t, std::vector<std::string>> held_by_code(const std::unordered_map<uintptr_t, std::vector<uintptr_t>>& found);
    // Swap the content of two PrefabResources (data, dependent resources, userdata); the resource objects themselves stay the same.
    // After a hot reload the old resource object carries the new content: every via.Prefab holding it uses the new file on its next instantiation, with no reference replacement needed
    static bool swap_content(uintptr_t a, uintptr_t b);
    // Inline-hook the engine's prefab instantiate function and record the source resource of each spawned root GameObject (used to find instances renamed at runtime)
    static void install_tracking();
    static void uninstall_tracking();
    // Called every frame: after rebuilt behavior components run start, write back properties changed at runtime but not in the file.
    // With shutdown true, unfinished items are abandoned (committed rebuilds attach immediately, uncommitted ones are dropped)
    static void update(bool shutdown = false);
    // Rebuild step 2 (after the reference scan completes): hand old components to the engine for deferred destruction. Returns the old components that could not be committed and their data sub-objects (references to them must not be rewritten)
    static std::vector<uintptr_t> commit_rebuild(const std::vector<uintptr_t>& old_components);
    // Rebuild step 3 (after the old components are detached): attach the new components and run awake; the caller then rewrites references
    static void attach_ready(const std::vector<uintptr_t>& old_components);
    // Abandon rebuilds not yet committed (old components stay unchanged)
    static void abort_rebuild(const std::vector<uintptr_t>& old_components);
    // Whether some rebuild has not finished attaching (no new pfb hot reload starts meanwhile)
    static bool rebuild_busy();
    // Locations in the memory scan results that are reference fields/array elements of managed objects (excluding the objects involved in the rebuild themselves). Reads only the TDB and memory, so it can run on a background thread
    // raw_slots: locations of raw pointers (not counted) in live components that point to old objects
    static std::vector<RefSlot> find_ref_slots(const std::unordered_map<uintptr_t, std::vector<uintptr_t>>& found,
                                               const std::unordered_map<uintptr_t, uintptr_t>& mapping, std::vector<RefSlot>& raw_slots);
    // Main thread: old objects still pointed to by raw_slots (with the owning component alive) — they must not be released
    // where: a description of each "old object type referenced by GameObject:component type+offset"
    static std::unordered_set<uintptr_t> raw_still_referenced(const std::vector<RefSlot>& raw_slots, std::vector<std::string>* where = nullptr);
    // Main thread: repoint raw pointers in live components that still point to old objects to the new objects (the new object gets one more reference; the old object is kept by the caller since the other side may still cache data inside it)
    static uint32_t patch_raw(const std::vector<RefSlot>& raw_slots, const std::unordered_map<uintptr_t, uintptr_t>& mapping);
    // Main thread: repoint references to the new objects (CAS, only when still pointing to the old object and the owner is still valid); returns the number replaced
    // release_old: old objects released on behalf of their original holders when rewritten (replaced old components); other old objects (data sub-objects) only add a reference to the new object
    static uint32_t patch_refs(const std::vector<RefSlot>& slots, const std::unordered_map<uintptr_t, uintptr_t>& mapping,
                               const std::unordered_set<uintptr_t>& release_old, bool verbose);
    // Whether all components have been detached by the engine (owning GameObject cleared)
    static bool all_detached(const std::vector<uintptr_t>& components);
    // Release the old objects held, returning how many were reclaimed as a result (no other references left)
    static uint32_t release_objects(const std::vector<uintptr_t>& objects);
};

}
