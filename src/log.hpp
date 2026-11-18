#pragma once
#include <string>

namespace hr {
void log(const char* fmt, ...);
// A feature is disabled or unavailable (startup check failed, engine function not found, etc.): written to the REFramework log like log(),
// and also to file_hotreload_crash.log so it is kept across launches (each distinct message once per core load)
void log_disabled(const char* fmt, ...);
std::string narrow(const std::wstring& w);
std::wstring widen(const std::string& s);
}
