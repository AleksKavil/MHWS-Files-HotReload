#pragma once
// Find loose files that reference a resource path (efx stores dependency paths as UTF-16)
#include <atomic>
#include <filesystem>
#include <future>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace hr {

// Among files under root whose names contain name_filter, look for the UTF-16 string needle (ASCII case-insensitive, '\\' treated as '/')
// Returns paths relative to root ('/'-separated)
std::vector<std::wstring> find_referrers(const std::filesystem::path& root, const std::wstring& needle,
                                         const std::wstring& name_filter);

// Whether a single file contains the UTF-16 string needle (same rules as above)
bool file_references(const std::filesystem::path& file, const std::wstring& needle);

// Content index of files under root whose names contain given fragments (such as .efx., .uvs.), so dependency cascades can find referrers in memory.
// Previously every cascade walked natives recursively on the main thread and read every efx (observed 2026-11-08: saving one mesh took 29 ms on the main thread, dropping frames).
// Loaded in the background at startup; files reported by the watcher are re-read on the next query; if a folder is reported (a whole folder moved in, the watcher reports only the folder) the index is rebuilt in the background;
// files found are first confirmed to still be on disk (the watcher does not report deletions)
class ReferrerIndex {
public:
    ~ReferrerIndex();
    void start(const std::filesystem::path& root, std::vector<std::wstring> name_filters);
    void stop();
    // Changes reported by the file watcher (relative to root, '/'-separated)
    void on_changed(const std::wstring& rel);
    // When the index is ready, write the results to out and return true; return false if not ready yet (the caller falls back to find_referrers)
    bool find(const std::wstring& needle, const std::wstring& name_filter, std::vector<std::wstring>& out);
    // Whether file rel in the index references needle (same rules as file_references). Returns false with known=false if the index is not ready or the file is not indexed
    bool references(const std::wstring& rel, const std::wstring& needle, bool& known);

private:
    struct Entry {
        std::wstring name; // Normalized file name
        std::string fold0, fold1;
    };
    bool wanted(const std::wstring& normalized_name) const;
    bool read_entry(const std::filesystem::path& file, Entry& out) const;
    void refresh_dirty(); // Caller holds m_mtx
    void schedule_rebuild();
    void rebuild_loop();

    std::filesystem::path m_root{};
    std::vector<std::wstring> m_filters{};
    std::mutex m_mtx{};
    std::unordered_map<std::wstring, Entry> m_entries{};
    std::unordered_set<std::wstring> m_dirty{};  // To be re-read (on the next query)
    std::unordered_set<std::wstring> m_recent{}; // Re-read after the current rebuild started: marked to be re-read again once the rebuild result is swapped in, so it is not overwritten by stale content
    bool m_ready{false};
    std::future<void> m_worker{};
    std::atomic<bool> m_again{false};
    std::atomic<bool> m_stop{false};
};

}
