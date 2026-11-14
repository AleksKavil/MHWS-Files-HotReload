#include <chrono>
#include <cwctype>
#include <fstream>

#include "references.hpp"
#include "resource_cache.hpp"

namespace hr {

namespace {
// Lowercase the UTF-16 ASCII characters of the file content and unify separators, starting at alignment align
std::string fold_utf16(const std::string& data, size_t align) {
    std::string out = data.substr(align);
    for (size_t i = 0; i + 1 < out.size(); i += 2) {
        if (out[i + 1] != 0) continue;
        char& c = out[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        else if (c == '\\') c = '/';
    }
    return out;
}

std::string utf16_pattern(const std::wstring& needle) {
    std::string pattern{};
    for (auto c : ResourceCache::normalize(needle)) {
        pattern.push_back((char)(c & 0xFF));
        pattern.push_back((char)(c >> 8));
    }
    return pattern;
}

// UTF-16 strings in efx are not guaranteed to be 2-byte aligned; check both alignments
bool contains(const std::string& data, const std::string& pattern) {
    return data.size() >= pattern.size() &&
           (fold_utf16(data, 0).find(pattern) != std::string::npos || fold_utf16(data, 1).find(pattern) != std::string::npos);
}
}

bool file_references(const std::filesystem::path& file, const std::wstring& needle) {
    const auto pattern = utf16_pattern(needle);
    if (pattern.empty()) return false;
    std::ifstream f(file, std::ios::binary);
    const std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return contains(data, pattern);
}

// ---- ReferrerIndex ----

ReferrerIndex::~ReferrerIndex() {
    stop();
}

void ReferrerIndex::start(const std::filesystem::path& root, std::vector<std::wstring> name_filters) {
    stop();
    m_root = root;
    m_filters.clear();
    for (const auto& f : name_filters) m_filters.push_back(ResourceCache::normalize(f));
    m_stop = false;
    schedule_rebuild();
}

void ReferrerIndex::stop() {
    m_stop = true;
    if (m_worker.valid()) m_worker.wait();
    m_worker = {};
}

bool ReferrerIndex::wanted(const std::wstring& name) const {
    for (const auto& f : m_filters) {
        if (name.find(f) != std::wstring::npos) return true;
    }
    return false;
}

bool ReferrerIndex::read_entry(const std::filesystem::path& file, Entry& out) const {
    std::ifstream f(file, std::ios::binary);
    if (!f) return false;
    const std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    out.name = ResourceCache::normalize(file.filename().wstring());
    out.fold0 = fold_utf16(data, 0);
    out.fold1 = data.empty() ? std::string{} : fold_utf16(data, 1);
    return true;
}

void ReferrerIndex::schedule_rebuild() {
    m_again = true;
    if (m_worker.valid() && m_worker.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return; // Rebuild in progress: run another round when it finishes
    m_worker = std::async(std::launch::async, [this] { rebuild_loop(); });
}

void ReferrerIndex::rebuild_loop() {
    while (m_again.exchange(false) && !m_stop) {
        {
            std::lock_guard lock{m_mtx};
            m_recent.clear();
        }
        std::unordered_map<std::wstring, Entry> built{};
        std::error_code ec{};
        for (auto it = std::filesystem::recursive_directory_iterator(m_root, ec);
             !ec && !m_stop && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
            if (!it->is_regular_file(ec) || !wanted(ResourceCache::normalize(it->path().filename().wstring()))) continue;
            Entry e{};
            if (!read_entry(it->path(), e)) continue;
            built.emplace(std::filesystem::relative(it->path(), m_root, ec).generic_wstring(), std::move(e));
        }
        if (m_stop) return;
        std::lock_guard lock{m_mtx};
        m_entries = std::move(built);
        for (const auto& r : m_recent) m_dirty.insert(r);
        m_recent.clear();
        m_ready = true;
    }
}

void ReferrerIndex::on_changed(const std::wstring& rel) {
    std::error_code ec{};
    if (std::filesystem::is_directory(m_root / rel, ec)) {
        schedule_rebuild();
        return;
    }
    const auto name = ResourceCache::normalize(std::filesystem::path(rel).filename().wstring());
    if (!wanted(name)) return;
    std::lock_guard lock{m_mtx};
    m_dirty.insert(rel);
}

void ReferrerIndex::refresh_dirty() {
    for (const auto& rel : m_dirty) {
        Entry e{};
        if (read_entry(m_root / rel, e)) {
            m_entries[rel] = std::move(e);
        } else {
            m_entries.erase(rel);
        }
        m_recent.insert(rel);
    }
    m_dirty.clear();
}

bool ReferrerIndex::references(const std::wstring& rel, const std::wstring& needle, bool& known) {
    known = false;
    const auto pattern = utf16_pattern(needle);
    std::lock_guard lock{m_mtx};
    if (!m_ready || pattern.empty()) return false;
    refresh_dirty();
    const auto it = m_entries.find(rel);
    if (it == m_entries.end()) return false;
    known = true;
    return it->second.fold0.find(pattern) != std::string::npos || it->second.fold1.find(pattern) != std::string::npos;
}

bool ReferrerIndex::find(const std::wstring& needle, const std::wstring& name_filter, std::vector<std::wstring>& out) {
    out.clear();
    const auto pattern = utf16_pattern(needle);
    const auto filter_n = ResourceCache::normalize(name_filter);
    std::lock_guard lock{m_mtx};
    if (!m_ready) return false;
    refresh_dirty();
    if (pattern.empty()) return true;
    std::vector<std::wstring> gone{};
    for (const auto& [rel, e] : m_entries) {
        if (!filter_n.empty() && e.name.find(filter_n) == std::wstring::npos) continue;
        if (e.fold0.find(pattern) == std::string::npos && e.fold1.find(pattern) == std::string::npos) continue;
        std::error_code ec{};
        if (!std::filesystem::is_regular_file(m_root / rel, ec)) {
            gone.push_back(rel); // The watcher does not report deletions: confirm when looking up
            continue;
        }
        out.push_back(rel);
    }
    for (const auto& rel : gone) m_entries.erase(rel);
    return true;
}

std::vector<std::wstring> find_referrers(const std::filesystem::path& root, const std::wstring& needle,
                                         const std::wstring& name_filter) {
    std::vector<std::wstring> result{};
    const auto filter_n = ResourceCache::normalize(name_filter);
    const auto pattern = utf16_pattern(needle);
    if (pattern.empty()) return result;

    std::error_code ec{};
    for (auto it = std::filesystem::recursive_directory_iterator(root, ec);
         !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
        if (!it->is_regular_file(ec)) continue;
        const auto name = ResourceCache::normalize(it->path().filename().wstring());
        if (!filter_n.empty() && name.find(filter_n) == std::wstring::npos) continue;

        std::ifstream f(it->path(), std::ios::binary);
        const std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (contains(data, pattern)) result.push_back(std::filesystem::relative(it->path(), root, ec).generic_wstring());
    }
    return result;
}

}
