#include <Windows.h>

#include "file_watcher.hpp"

namespace hr {

FileWatcher::~FileWatcher() {
    stop();
}

bool FileWatcher::start(const std::wstring& dir, std::string& err) {
    stop();

    m_handle = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (m_handle == INVALID_HANDLE_VALUE) {
        m_handle = nullptr;
        err = "CreateFileW failed, error " + std::to_string(GetLastError());
        return false;
    }
    m_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_dir = dir;
    m_running = true;
    m_thread = std::thread([this]() { run(); });
    return true;
}

void FileWatcher::stop() {
    if (!m_running) return;
    SetEvent(m_stop_event);
    if (m_thread.joinable()) m_thread.join();
    CloseHandle(m_handle);
    CloseHandle(m_stop_event);
    m_handle = nullptr;
    m_stop_event = nullptr;
    m_running = false;
}

void FileWatcher::run() {
    alignas(DWORD) static thread_local BYTE buffer[64 * 1024];
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const DWORD filter = FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE;

    while (true) {
        ResetEvent(ov.hEvent);
        if (!ReadDirectoryChangesW(m_handle, buffer, sizeof(buffer), TRUE, filter, nullptr, &ov, nullptr)) {
            break;
        }
        HANDLE waits[2] = {ov.hEvent, m_stop_event};
        const auto w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (w != WAIT_OBJECT_0) {
            CancelIoEx(m_handle, &ov);
            WaitForSingleObject(ov.hEvent, 1000);
            break;
        }
        DWORD bytes = 0;
        if (!GetOverlappedResult(m_handle, &ov, &bytes, FALSE) || bytes == 0) {
            continue; // Buffer overflow: drop this batch and keep watching
        }

        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock _{m_mtx};
        for (auto* info = (FILE_NOTIFY_INFORMATION*)buffer;;) {
            if (info->Action == FILE_ACTION_ADDED || info->Action == FILE_ACTION_MODIFIED ||
                info->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                std::wstring name(info->FileName, info->FileNameLength / sizeof(wchar_t));
                for (auto& c : name) {
                    if (c == L'\\') c = L'/';
                }
                auto& p = m_pending[name];
                p.last_change = now;
                // Record size and modification time right away; when the debounce expires only confirm once that they are unchanged
                WIN32_FILE_ATTRIBUTE_DATA fad{};
                const auto full = m_dir + L"\\" + name;
                if (GetFileAttributesExW(full.c_str(), GetFileExInfoStandard, &fad)) {
                    p.size = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
                    p.write_time = ((uint64_t)fad.ftLastWriteTime.dwHighDateTime << 32) | fad.ftLastWriteTime.dwLowDateTime;
                }
            }
            if (info->NextEntryOffset == 0) break;
            info = (FILE_NOTIFY_INFORMATION*)((BYTE*)info + info->NextEntryOffset);
        }
    }
    CloseHandle(ov.hEvent);
}

std::vector<std::wstring> FileWatcher::poll(uint32_t debounce_ms) {
    std::vector<std::wstring> ready{};
    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock _{m_mtx};
    for (auto it = m_pending.begin(); it != m_pending.end();) {
        auto& p = it->second;
        if (now - p.last_change < std::chrono::milliseconds(debounce_ms)) {
            ++it;
            continue;
        }

        const auto full = m_dir + L"\\" + it->first;
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExW(full.c_str(), GetFileExInfoStandard, &fad) || (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            it = m_pending.erase(it); // Deleted, or a directory
            continue;
        }
        const uint64_t size = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        const uint64_t write_time = ((uint64_t)fad.ftLastWriteTime.dwHighDateTime << 32) | fad.ftLastWriteTime.dwLowDateTime;

        // Size or modification time differs from the last check: still being written (e.g. copying a large file), restart the timer
        if (size != p.size || write_time != p.write_time) {
            p.size = size;
            p.write_time = write_time;
            p.last_change = now;
            ++it;
            continue;
        }

        // Cannot be opened while an editor holds it exclusively; retry next time
        HANDLE h = CreateFileW(full.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            ++it;
            continue;
        }
        CloseHandle(h);
        ready.push_back(it->first);
        it = m_pending.erase(it);
    }
    return ready;
}

}
