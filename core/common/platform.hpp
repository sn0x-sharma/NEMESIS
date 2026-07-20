// platform.hpp — cross-platform (Linux + Windows) OS shims.
//
// WHY: NEMESIS must build and run on both Linux and Windows. The only OS-specific
// primitives P0 needs are (a) running a child process and reading its exit code /
// stdout — used to validate modules through node and later to drive engine targets —
// and (b) a temp path. Isolating the #ifdef here keeps every other file portable.
#pragma once
#include <array>
#include <cstdio>
#include <cstdlib>
#include <string>

#if defined(_WIN32)
#define NEMESIS_OS_WINDOWS 1
#define popen _popen
#define pclose _pclose
#else
#define NEMESIS_OS_POSIX 1
#endif

namespace nemesis {

inline const char* os_name() {
#if defined(NEMESIS_OS_WINDOWS)
    return "windows";
#else
    return "linux";
#endif
}

// Run a shell command, capture stdout, and return the exit code via `exit_code`.
// Portable through popen/_popen. Used by the node validator and (later) targets.
inline std::string run_capture(const std::string& cmd, int* exit_code = nullptr) {
    std::string out;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        if (exit_code) *exit_code = -1;
        return out;
    }
    std::array<char, 4096> buf{};
    size_t n;
    while ((n = fread(buf.data(), 1, buf.size(), pipe)) > 0) out.append(buf.data(), n);
    int rc = pclose(pipe);
#if defined(NEMESIS_OS_WINDOWS)
    if (exit_code) *exit_code = rc;
#else
    if (exit_code) *exit_code = (rc == -1) ? -1 : (rc & 0x7F ? 128 + (rc & 0x7F) : (rc >> 8) & 0xFF);
#endif
    return out;
}

// A writable temp directory ending in a path separator. Honors TMPDIR/TEMP when set.
inline std::string temp_dir() {
#if defined(NEMESIS_OS_WINDOWS)
    const char* t = std::getenv("TEMP");
    if (!t) t = std::getenv("TMP");
    std::string base = t ? t : ".";
    if (!base.empty() && base.back() != '\\' && base.back() != '/') base += '\\';
    return base;
#else
    const char* t = std::getenv("TMPDIR");
    std::string base = t ? t : "/tmp";
    if (base.empty() || base.back() != '/') base += '/';
    return base;
#endif
}

// Create a directory (and parents) if absent. Portable enough for build/corpus dirs.
inline void ensure_dir(const std::string& path) {
#if defined(NEMESIS_OS_WINDOWS)
    std::system(("if not exist \"" + path + "\" mkdir \"" + path + "\"").c_str());
#else
    std::system(("mkdir -p '" + path + "'").c_str());
#endif
}

// Remove *.wasm from a directory (keeps batch counts honest between runs).
inline void clear_wasm(const std::string& dir) {
#if defined(NEMESIS_OS_WINDOWS)
    std::system(("del /q \"" + dir + "\\*.wasm\" 2>NUL").c_str());
#else
    std::system(("rm -f '" + dir + "'/*.wasm 2>/dev/null").c_str());
#endif
}

// Return whether an executable is resolvable on PATH.
inline bool have_tool(const std::string& tool) {
#if defined(NEMESIS_OS_WINDOWS)
    std::string cmd = "where " + tool + " >NUL 2>NUL";
#else
    std::string cmd = "command -v " + tool + " >/dev/null 2>&1";
#endif
    return std::system(cmd.c_str()) == 0;
}

}  // namespace nemesis
