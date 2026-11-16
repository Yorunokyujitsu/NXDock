// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 DeLFuS77
#include "compress_meta.hpp"

#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace nxdock {
namespace {

bool EndsWithNoCase(const std::string& s, const char* end) {
    const size_t n = std::strlen(end);
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; i++) {
        if (std::tolower((unsigned char)s[s.size() - n + i]) != std::tolower((unsigned char)end[i])) return false;
    }
    return true;
}

bool Exists(const std::string& p) {
    struct stat st{};
    return stat(p.c_str(), &st) == 0;
}

int CountIps(const std::string& dir) {
    int n = 0;
    DIR* d = opendir(dir.c_str());
    if (!d) return 0;
    while (dirent* e = readdir(d)) {
        const std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        if (EndsWithNoCase(name, ".ips")) n++;
        else n += CountIps(dir + "/" + name); // a folder per patch set
    }
    closedir(d);
    return n;
}

// Detects embedded patch code in package3 without hashes, privileged syscalls, or Atmosphère modifications.
uint32_t ReadLe32(const unsigned char *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

// Limit the amount of data read from an untrusted or corrupt SD file.
constexpr size_t MaxSegmentSize = 2 * 1024 * 1024;

template <size_t N>
bool Contains(const std::vector<unsigned char> &bytes, const std::array<unsigned char, N> &pattern) {
    return std::search(bytes.begin(), bytes.end(), pattern.begin(), pattern.end()) != bytes.end();
}

// Mesosphere uses kernel pattern matching to locate FS patch targets.
// Detects two patterns from g_fs_narrow_patterns (u16, wildcard = 0x0100, little-endian).
constexpr std::array<unsigned char, 20> nocntchk = {
    0x06,0x00,0x94,0x00,0x00,0x01,0x00,0x01,0x00,0x00,
    0x00,0x01,0x42,0x00,0x00,0x01,0x00,0x00,0x91,0x00
};
constexpr std::array<unsigned char, 24> noncasigchk = {
    0x40,0x00,0xF9,0x00,0x00,0x01,0x00,0x01,0x00,0x01,
    0x00,0x01,0x00,0x01,0x00,0x01,0x40,0x00,
    0xB9,0x00,0x09,0x00,0x1C,0x00
};

// Fusee bypasses NCA header signature checks using mov w0, wzr and nop.
// Detects these adjacent instructions without relying on firmware-specific offsets.
constexpr std::array<unsigned char, 8> fuseePatch = {
    0xE0, 0x03, 0x1F, 0x2A, // mov w0, wzr
    0x1F, 0x20, 0x03, 0xD5  // nop
};

} // namespace

EmbeddedFsPatchType DetectEmbeddedFsPatches(const std::string &sd) {
    FILE *f = std::fopen((sd + "/atmosphere/package3").c_str(), "rb");
    if (!f) return EmbeddedFsPatchType::None;

    std::array<unsigned char, 0x240> hdr{};
    EmbeddedFsPatchType result = EmbeddedFsPatchType::None;
    if (std::fread(hdr.data(), 1, hdr.size(), f) == hdr.size() && std::memcmp(hdr.data(), "PK31", 4) == 0 && std::memcmp(hdr.data() + 0x20, "FSS0", 4) == 0) {
        std::vector<unsigned char> bytes;
        // FSS0 entries start at 0x40, each containing offset, size, type, reserved, and name fields.
        for (size_t i = 0; i < 14; ++i) {
            const unsigned char *entry = hdr.data() + 0x40 + i * 0x20;
            const bool mesosphere = std::memcmp(entry + 16, "mesosphere", 11) == 0;
            const bool fusee = std::memcmp(entry + 16, "fusee", 6) == 0;
            if (!mesosphere && !fusee) continue;

            const uint32_t offset = ReadLe32(entry);
            const uint32_t length = ReadLe32(entry + 4);
            if (!length || length > MaxSegmentSize || offset < hdr.size() || offset > 0x800000u || length > 0x800000u - offset) continue;
            bytes.resize(length);
            if (std::fseek(f, static_cast<long>(offset), SEEK_SET) != 0 || std::fread(bytes.data(), 1, length, f) != length) continue;

            if (mesosphere && Contains(bytes, nocntchk) && Contains(bytes, noncasigchk)) {
                result = EmbeddedFsPatchType::Mesosphere;
                break; // Mesosphere takes priority if both implementations are present.
            }
            if (fusee && Contains(bytes, fuseePatch)) result = EmbeddedFsPatchType::Fusee;
        }
    }
    std::fclose(f);
    return result;
}

std::vector<CompressedGame> LoadCompressed(const std::string& path) {
    std::vector<CompressedGame> out;
    FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return out;
    char line[256];
    while (std::fgets(line, sizeof(line), f)) {
        char program[40] = {};
        unsigned long long app = 0, saved = 0;
        long long when = 0;
        if (std::sscanf(line, "%llx %39s %llu %lld", &app, program, &saved, &when) == 4 && std::strlen(program) == 32) {
            out.push_back({app, program, saved, when});
        }
    }
    std::fclose(f);
    return out;
}

bool SaveCompressed(const std::string& path, const std::vector<CompressedGame>& games) {
    if (games.empty()) {
        std::remove(path.c_str());
        return true;
    }
    const std::string tmp = path + ".tmp";
    FILE* f = std::fopen(tmp.c_str(), "w");
    if (!f) return false;
    for (const auto& g : games) std::fprintf(f, "%016llX %s %llu %lld\n", g.app_id, g.program.c_str(), g.saved, g.when);
    if (std::fclose(f) != 0) return false;
    std::remove(path.c_str());
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

Sigpatches FindSigpatches(const std::string& sd) {
    Sigpatches s;
    if (CountIps(sd + "/atmosphere/kip_patches/fs_patches") > 0) {
        s.found = true;
        s.how = "atmosphere/kip_patches/fs_patches";
        return s;
    }
    if (Exists(sd + "/atmosphere/contents/420000000000000B/exefs.nsp")) {
        s.found = true;
        s.how = "sys-patch";
        return s;
    }
    if (FILE* f = std::fopen((sd + "/bootloader/patches.ini").c_str(), "r")) {
        char line[256];
        while (std::fgets(line, sizeof(line), f)) {
            if (std::strncmp(line, "[FS:", 4) == 0) {
                s.found = true;
                s.how = "bootloader/patches.ini";
                break;
            }
        }
        std::fclose(f);
    }
    if (s.found) return s;
    // Detect embedded FS patches by code patterns when no external patches are found.
    const auto embedded = DetectEmbeddedFsPatches(sd);
    if (embedded != EmbeddedFsPatchType::None) {
        s.found = true;
        s.how = embedded == EmbeddedFsPatchType::Mesosphere ? "Embedded - Mesosphere" : "Embedded - Fusee";
    }
    return s;
}

} // namespace nxdock
