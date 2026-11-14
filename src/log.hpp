#pragma once
#include <string>

namespace hr {
void log(const char* fmt, ...);
std::string narrow(const std::wstring& w);
std::wstring widen(const std::string& s);
}
