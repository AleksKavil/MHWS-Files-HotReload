#pragma once
// Watches file writes under the natives directory and reports relative paths after debouncing
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace hr {

class FileWatcher {
public:
    ~FileWatcher();

    bool start(const std::wstring& dir, std::string& err);
    void stop();
    bool running() const { return m_running; }
    const std::wstring& dir() const { return m_dir; }

    // Returns files whose last write is older than debounce_ms (paths relative to dir, '/'-separated)
    std::vector<std::wstring> poll(uint32_t debounce_ms);

private:
    void run();

    std::wstring m_dir{};
    void* m_handle{nullptr};
    void* m_stop_event{nullptr};
    std::thread m_thread{};
    bool m_running{false};

    std::mutex m_mtx{};
    struct Pending {
        std::chrono::steady_clock::time_point last_change{};
        uint64_t size{UINT64_MAX};
        uint64_t write_time{};
    };
    std::unordered_map<std::wstring, Pending> m_pending{};
};

}
