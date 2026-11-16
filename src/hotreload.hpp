#pragma once
// Hot reload orchestration: watch natives changes -> evict cache -> reload -> replace references -> refresh users -> cascade dependencies
#include <cstdint>
#include <deque>
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <future>
#include <map>

#include "file_watcher.hpp"
#include "memory_scan.hpp"
#include "prefab_live.hpp"
#include "references.hpp"

namespace hr {

struct TypeHandler {
    const wchar_t* ext;           // Lowercase extension, e.g. L"efx"
    const char* resource_type;    // e.g. "via.effect.EffectResource"
    const char* holder_type;      // e.g. "via.effect.EffectResourceHolder"
    bool restart_effect_players;  // After reloading, refresh the EffectPlayers currently using it
    bool referenced_by_efx;       // May be referenced by path from efx; after reloading, cascade-reload the efx that reference it
    bool live_params;             // Apply the differing fields between old and new to objects already instantiated in the scene (pfb)
    bool in_place;                // Replace the content of the resource object in place (pfb); no memory scan to replace references is needed
    // Cache update only (other extensions registered in the engine's resource type table): the new resource stays in the cache and later loads/spawns use the new file;
    // references in existing objects are not rewritten (objects already in use keep the original data)
    bool cache_only;
};

// Configuration is built into the code (no ini is read or written)
struct Config {
    bool enabled{true};
    uint32_t debounce_ms{0};
    uint32_t load_timeout_frames{900};
    bool restart_effects{true};
    bool cascade{true};
#ifdef FILE_HOTRELOAD_VERBOSE
    bool verbose{true}; // Test build: log the old/new resources of every reload, per-field pfb differences and reference rewrite details
#else
    bool verbose{false};
#endif
    bool live_params{true};
};

class HotReload {
public:
    static HotReload& get();

    void on_frame();
    // Called by the loader after each engine update phase (application entry) ends: rebuilds whose old components have been detached attach here and rewrite references;
    // no game code runs between detach and attach
    void on_entry();
    void shutdown();

private:
    enum class Stage { Queued, Loading };

    void frame_body();
    void entry_body();
    struct Job {
        std::wstring path; // Resource path, e.g. Art/VFX/a.efx
        const TypeHandler* handler{};
        Stage stage{Stage::Queued};
        uintptr_t old_res{};
        uintptr_t new_res{};
        uintptr_t extra_old{}; // Old resource of the same path in the orphan table (when the cache also has an entry); replaced as well
        // While the new resource loads the cache node points to the old resource: a game request for the path then gets the ready old resource instead of the one still loading
        // (meshes build materials only in set_Material; setting an mdf2 that is still loading stays black forever, observed 2026-11-03). It is repointed to the new resource once loading completes
        bool old_in_cache{};
        uint32_t evicted_extra{}; // Cache-update-only types: number of other cache entries of the same path (different keys) removed as well
        bool old_ready{};
        uint32_t frames{};
        std::wstring reason{};
        // pfb: in_place is the native components written in place (not rebuilt). All native components whose data changed are written in place first;
        // planned true means the holders of components whose in-place write did not take effect have been checked, and the unheld ones have been moved out of in_place (rebuilt from the new file this time)
        bool planned{};
        // Live parameters already written (the check found no components to rebuild); later processing only does the remaining steps
        bool applied{};
        std::shared_ptr<std::unordered_set<uintptr_t>> in_place;
        uint32_t created_tex{}; // mdf2: number of GPU resources created for new textures
        // When natives has a file for this resource: the file registered before loading (natives-relative path) and the loader's decision counters, used after loading to confirm the loose file was read
        std::wstring loose_rel{};
        uint32_t loose_before{};
        uint32_t forced_before{};
        uint32_t missing_before{};
        bool loose_check{};
    };
    // The new resource is not used (load failed, loose file not read): put the old resource back in the cache; if that fails keep it in the orphan table and keep replacing on the next save
    void abandon_new(Job& j);
    // The new resource finished loading and is used: repoint the cache node from the old resource to the new one
    void commit_new(Job& j);
    // After loading, confirm the new resource was read from the loose file in natives; otherwise give the reason in why
    bool loaded_from_loose(const Job& j, std::string& why) const;
    std::unordered_map<std::wstring, uint32_t> m_loose_retries{}; // Retries after the loose file was not read
    // After the cache update of chain2 / clsp / gpuc / motlist / rtex, and after reference replacement of sfur / jcns / fbxskel / motbank:
    // components in the scene using the old resource of the same path switch to the new resource; returns the number of components refreshed
    uint32_t refresh_components(const Job& j);
    // Resource fully loaded: mdf2 also requires its dependencies (textures etc.) to be complete (+0x39); other types check +0x38
    static bool job_loaded(const Job& job, uintptr_t res);
    // mdf2 kept its old material because dependencies were incomplete: normalized mdf2 path -> {mdf2 resource path, incomplete dependencies (normalized resource paths)}; reloaded once those dependency files are added or saved
    struct DepWait {
        std::wstring path;
        std::unordered_set<std::wstring> deps;
    };
    std::unordered_map<std::wstring, DepWait> m_dep_waiting{};
    std::unordered_map<std::wstring, uint32_t> m_dep_retries{}; // Consecutive retries while the dependency files exist but are still incomplete
    bool dep_file_exists(const std::wstring& res_path) const;
    void on_dependency_saved(const std::wstring& res_path);

    // Components checked and found held by game code (positive results only): not rescanned on the next save. If a component address is reused, the entry is invalidated by vtable and owning GameObject
    struct HeldInfo {
        uintptr_t vtable{};
        uintptr_t go{};
        std::vector<std::string> owners;
    };
    std::unordered_map<uintptr_t, HeldInfo> m_held_cache{};
    const HeldInfo* cached_held(uintptr_t comp);
    void remember_held(uintptr_t comp, const std::vector<std::string>& owners);

    // Pre-rebuild check: a background scan finds who holds the native components about to be rebuilt; those held by game code (managed objects other than scene objects) are not rebuilt
    struct PendingPlan {
        Job job;
        std::vector<uintptr_t> candidates; // One reference each is held here
        std::shared_ptr<ScanStats> stats;
        std::future<std::unordered_map<uintptr_t, std::vector<std::string>>> result;
    };
    std::unique_ptr<PendingPlan> start_plan(std::vector<uintptr_t> candidates);
    // Take the check result and release the candidate components' references; returns components held by game code -> holder types
    std::unordered_map<uintptr_t, std::vector<std::string>> finish_plan(PendingPlan& plan);

    // Background memory scan: replace old resource pointers in managed holders / via.Prefab (affects objects spawned later, not the immediately visible result);
    // or (objects) repoint references in managed objects from pre-rebuild components/sub-objects to the rebuilt objects
    struct PendingScan {
        std::future<std::unordered_map<uintptr_t, std::vector<uintptr_t>>> result;
        std::shared_ptr<ScanStats> stats;
        std::unordered_map<uintptr_t, uintptr_t> mapping; // Old resource -> new resource (objects: old object -> new object)
        std::vector<Job> jobs;                            // Holds old/new references, released after the scan completes
        bool objects{};
        // Old objects replaced by .user: not released even after references are repointed to the new objects. The scan only changes managed reference slots and components' native pointers; other pointers in engine native memory
        // (including ones into the object's interior) cannot be changed and would dangle after release; while kept they read old data instead of freed memory
        bool keep_old{};
        std::vector<uintptr_t> held;                      // objects: old objects whose references are held, released after the scan completes
        std::unordered_map<uintptr_t, std::pair<uintptr_t, const void*>> held_id; // Old object -> {object header +0, type}: verify it is still the same object before releasing
        std::unordered_map<uintptr_t, int32_t> held_refs;                        // For error logs: reference count of the old object when queued (including the one held by the plugin)
        std::unordered_map<uintptr_t, uintptr_t> held_go;                        // For error logs: GameObject owning the old component when queued
        std::shared_ptr<std::vector<RefSlot>> slots;      // objects: managed object reference locations found in the background
        std::shared_ptr<std::vector<RefSlot>> raw_slots;  // objects: raw pointer locations in live components pointing to old objects (rechecked at attach; old objects still pointed to are not released)
        bool started{true};
        // objects: the old components being replaced. Committed after the scan completes (handed to the engine for destruction); new components are attached and references rewritten once they are detached
        std::vector<uintptr_t> wait_detached;
        uint32_t waited{};
        std::vector<uintptr_t> olds;
    };
    void start_object_scan(PendingScan& scan);
    // Component rebuild: while the old component is still working, immediately scan in the background for references from other objects to the old component/sub-objects
    PendingScan* queue_object_scan(const LiveApplyResult& r, bool keep_old = false);
    // Last step of a component rebuild: attach the new component, rewrite references, release old objects
    void finish_object_scan(PendingScan& scan);
    void process_awaiting(bool from_frame);

    bool initialize();
    // Returns true: the rebuild scan has been committed and is waiting for the old components to be detached (moved into m_awaiting)
    bool complete_scan(PendingScan& scan);
    bool finish_in_place(const Job& job);
    void finish_cached(const Job& job);
    void cascade_cached(const Job& job);
    void cascade_prefabs(const std::vector<const Job*>& jobs);
    uintptr_t refresh_meshes(const std::wstring& path, uintptr_t new_res, const TypeHandler& handler);
    void release_later(uintptr_t res);
    void release_deferred(bool all);
    void release_job_refs(const Job& job);
    void collect_changes();
    void enqueue(const std::wstring& path, const TypeHandler* handler, const std::wstring& reason);
    bool start_job(Job& job);
    void finish_jobs(std::vector<Job>& jobs);
    // Scan memory in the background; once done, repoint references to each job's old resources to the new resources on the main thread (complete_scan)
    void start_resource_scan(std::vector<Job> jobs);
    // Whether any queued, loading or pending job needs a memory scan after completion
    bool scan_jobs_pending() const;
    // Old resource -> {new resource, type}: resources reloaded in one batch are handled together and the scene is walked only once (handling them one by one cost about 12 ms extra on the main thread for a cascade of 23 efx)
    using ResMap = std::unordered_map<uintptr_t, std::pair<uintptr_t, const TypeHandler*>>;
    void restart_effect_players(const ResMap& map);
    void refresh_provider_data(const ResMap& map);
    // A batch of files that finished reloading (path, type): loaded loose efx referencing them are reloaded together (the cache table is walked only once)
    void cascade(const std::vector<std::pair<std::wstring, const TypeHandler*>>& done);
    void cascade_effects(const Job& job);
    static bool effect_dependency(const TypeHandler* h);
    // Resource paths of type handler, currently loaded, from loose files in natives whose names contain filter and that reference path
    std::vector<std::wstring> loaded_referrers(const std::wstring& path, const wchar_t* filter, const TypeHandler* handler) const;
    // Loose files in natives of type handler that reference path (resource paths; whether loaded is not checked)
    std::vector<std::wstring> referrer_candidates(const std::wstring& path, const wchar_t* filter, const TypeHandler* handler) const;
    bool map_file(const std::wstring& rel, std::wstring& res_path, const TypeHandler*& handler) const;
    bool unsupported_type(const std::wstring& rel) const;

    bool m_initialized{false};
    bool m_failed{false};
    // Structure verification after startup (managed objects, component chain, type database, .user root objects): concluded only once there are enough scene objects; the related features are disabled until then
    bool m_layout_pending{true};
    uint32_t m_layout_attempts{};
    bool m_userdata_layout_ok{false};
    void check_layouts();
    uint64_t m_frame{};
    bool m_starts_deferred{};    // Jobs that could start this frame but were postponed by the time budget
    uint64_t m_ready_since{};    // Frame when the earliest job in m_ready finished loading (timer while waiting for other jobs of the same batch)
    Config m_cfg{};
    std::filesystem::path m_game_dir{};
    std::filesystem::path m_natives_dir{};
    std::unique_ptr<FileWatcher> m_watcher{};
    // Old resources of jobs starting this frame (normalized path -> resource), found by the start loop in one walk of the cache table; start_job prefers them
    const std::unordered_map<std::wstring, uintptr_t>* m_old_prefetch{};
    mutable ReferrerIndex m_ref_index{}; // Content index of loose efx/uvs/motlist in natives (dependency cascades look up referrers)
    std::vector<Job> m_jobs{};
    std::vector<std::unique_ptr<PendingScan>> m_scans{};
    // Committed rebuilds waiting for old components to be detached (scan results ready)
    std::vector<std::unique_ptr<PendingScan>> m_awaiting{};
    // Jobs that finished loading and wait for the previous component rebuild to finish
    std::vector<Job> m_ready{};
    std::vector<Job> m_scan_carry{}; // Completed jobs waiting to be scanned together with the next cascade level
    // gui: write file changes element by element into the displayed GUI. Written once the comparison GUIs (one from the old file, one from the new file) are ready
    struct PendingGui {
        std::wstring path;
        std::vector<uintptr_t> lives; // via.gui.GUI components using this file (references held by the plugin)
        uintptr_t res[2]{};            // Resources of the comparison GUIs: [0] old file, [1] new file (references held by the plugin)
        uintptr_t go[2]{}, gui[2]{};
        int created{};                 // Number of temporary GUIs created (one per frame)
        uint32_t frames{};
        bool ready{};
        size_t live_index{};
        PrefabLive::GuiDiff* diff{};
        uint32_t written{}, elements{}, matched{};
        std::vector<std::string> applied, skipped;
        // Elements added by the file: for each displayed GUI, a "donor" GUI generated from the new file (moved off-screen; elements only get draw data after it has drawn 2 frames);
        // elements are attached over and then the donor is destroyed (observed 2026-11-10: elements that never drew do not show when attached)
        struct Adds {
            uintptr_t live{};
            std::vector<std::pair<std::string, std::string>> items; // {parent element path, new element path}
        };
        std::vector<Adds> adds;
        size_t add_index{};
        uintptr_t donor{}, donor_go{};
        uint32_t donor_frames{};
        std::vector<std::string> added, add_failed, removed, remove_failed;
        uint32_t clones{}, clone_written{}; // Elements cloned at runtime
        std::vector<std::string> clone_applied;
    };
    std::vector<PendingGui> m_pending_gui{};
    void start_gui_update(const Job& j);
    void update_rcol(const Job& j);
    void step_gui_updates();
    void finish_gui_update(PendingGui& p);
    uint64_t m_scan_carry_since{};
    std::vector<std::unique_ptr<PendingPlan>> m_plans{};
    uint32_t m_main_thread{}; // Thread running on_frame (the engine main thread)
    bool m_in_entry{};
    // Old resources removed from the cache after a failed reload but still used by instances (one reference held); used as the old resource on the next reload of the same path
    std::unordered_map<std::wstring, uintptr_t> m_orphans{};
    // Resource objects carrying the old content after an in-place replacement: released later (other threads may be instantiating from the old data)
    std::vector<std::pair<uintptr_t, uint64_t>> m_deferred{};
    // Cache-update-only types: new resources left in the cache after reloading (one reference held each, released on the next save of the same file or when the core unloads),
    // so later loads take them directly without reading the disk again
    std::unordered_map<std::wstring, uintptr_t> m_cached{};
    // motlist: when an action starts playing, track bindings are built from the mot layout at that time, and keyframes are read from that resource's buffer every frame afterwards; swapping resources only affects actions started later.
    // One reference each is held here on the replaced old versions (released when only the plugin holds them); on reload new data is written in place into old versions with the same structure (shared by motlist and external mot, keyed by resource path)
    std::unordered_map<std::wstring, std::vector<uintptr_t>> m_motlist_old{};
    // File content of motlist / mot read on the previous reload: in-place updates only write positions that really changed from the previous version
    std::unordered_map<std::wstring, std::vector<uint8_t>> m_file_snapshot{};
    void update_motlist_versions(const Job& j);
    // External mot (referenced by motlist by path): when the structure is the same, write in place into the old mot in use; returns false if some old version could not be updated in place (the motlist referencing it must be reloaded)
    bool update_mot_versions(const Job& j);
    // .user: write the fields changed in the new file into the root object the game is using (old resource +0x88, held directly by game code).
    // Returns true if every write succeeded (the caller keeps the old resource in the cache, so everything keeps sharing this one object)
    bool update_userdata(const Job& j);
    // Contents of .user files in natives read in the background at startup (natives-relative path, content), merged into m_file_snapshot on the main thread once read
    std::future<std::vector<std::pair<std::wstring, std::vector<uint8_t>>>> m_user_snapshot_future{};
    void merge_user_snapshot();
    // File for this resource path under natives/STM (any version number, the most recently modified); empty if none
    std::filesystem::path natives_file(const std::wstring& res_path) const;

};

}
