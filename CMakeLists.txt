cmake_minimum_required(VERSION 3.20)
project(file_hotreload CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# REFramework plugin API headers (reframework/API.h, API.hpp) from https://github.com/praydog/REFramework (MIT, see include/reframework/LICENSE)
set(REFRAMEWORK_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

option(FILE_HOTRELOAD_VERBOSE "Log old/new resources of every reload, per-field pfb differences and reference rewrite details" OFF)

# Loader and core logic are compiled into a single file_hotreload.dll (goes into reframework/plugins)
add_library(file_hotreload SHARED
    src/loader.cpp
    src/plugin.cpp
    src/hotreload.cpp
    src/resource_cache.cpp
    src/memory_scan.cpp
    src/file_watcher.cpp
    src/references.cpp
    src/log.cpp
    src/prefab_live.cpp
    src/rsz_layout.cpp
    src/crash_trace.cpp
    src/core_heap.cpp
    src/loose_hook.cpp
)
target_include_directories(file_hotreload PRIVATE "${REFRAMEWORK_INCLUDE_DIR}" src)
target_compile_definitions(file_hotreload PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS FILE_HOTRELOAD_MERGED)
if(FILE_HOTRELOAD_VERBOSE)
    target_compile_definitions(file_hotreload PRIVATE FILE_HOTRELOAD_VERBOSE)
endif()
# The plugin relies on structured exception handling when touching game memory, which needs /EHa
string(REPLACE "/EHsc" "/EHa" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
target_compile_options(file_hotreload PRIVATE /W3 /wd4267 /utf-8)
