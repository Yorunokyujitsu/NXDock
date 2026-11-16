// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 DeLFuS77
//
// The list of the games NXDock compressed, and the look for sigpatches on an SD card made up here
// (24A).
#include "compress_meta.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdlib>
#include <string>

using namespace nxdock;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static void Touch(const std::string& p, const char* text = "") {
    if (FILE* f = std::fopen(p.c_str(), "w")) {
        std::fputs(text, f);
        std::fclose(f);
    }
}

// Create a test PK31/FSS0 package with known FS patch patterns.
static void Put32(std::vector<unsigned char>& b, size_t at, unsigned value) {
    for (unsigned i = 0; i < 4; ++i) b[at + i] = static_cast<unsigned char>(value >> (i * 8));
}

static void MakePackage3(const std::string &path, const char *segment, const std::vector<unsigned char> &content) {
    std::vector<unsigned char> pkg(0x1000 + content.size(), 0);
    std::memcpy(pkg.data(), "PK31", 4);
    std::memcpy(pkg.data() + 0x20, "FSS0", 4);
    const size_t descriptor = std::strcmp(segment, "mesosphere") == 0 ? 0xc0 : 0xe0;
    Put32(pkg, descriptor, 0x1000);
    Put32(pkg, descriptor + 4, static_cast<unsigned>(content.size()));
    std::memcpy(pkg.data() + descriptor + 16, segment, std::strlen(segment));
    std::memcpy(pkg.data() + 0x1000, content.data(), content.size());
    if (FILE *f = std::fopen(path.c_str(), "wb")) {
        std::fwrite(pkg.data(), 1, pkg.size(), f);
        std::fclose(f);
    }
}

int main(int argc, char **argv) {
    const std::string root = "/tmp/compress_meta";
    std::system(("rm -rf " + root + " && mkdir -p " + root).c_str());
    {
        const std::string path = root + "/compressed.txt";
        CHECK(LoadCompressed(path).empty());
        std::vector<CompressedGame> games = {{0x0100BB801B79C000ull, "0123456789ABCDEF0123456789ABCDEF", 3900000000ull, 1794300000},
                                             {0x01003DA0254A4000ull, "FEDCBA9876543210FEDCBA9876543210", 20000000ull, 1794300100}};
        CHECK(SaveCompressed(path, games));
        const auto back = LoadCompressed(path);
        CHECK(back.size() == 2 && back[0].app_id == games[0].app_id && back[0].program == games[0].program && back[0].saved == games[0].saved &&
              back[1].when == games[1].when);
        CHECK(SaveCompressed(path, {}) && LoadCompressed(path).empty());
    }
    {
        // no patches, then each of the three ways
        const std::string sd = root + "/sd";
        std::system(("mkdir -p " + sd + "/atmosphere/kip_patches/fs_patches/empty " + sd + "/bootloader").c_str());
        CHECK(!FindSigpatches(sd).found); // an empty folder is not patches
        Touch(sd + "/bootloader/patches.ini", "[Loader:1]\n.nosigchk=0:0x0:0x1,00\n");
        CHECK(!FindSigpatches(sd).found);
        Touch(sd + "/bootloader/patches.ini", "[FS:0123456789ABCDEF]\n.nosigchk=0:0x0:0x1,00\n");
        auto s = FindSigpatches(sd);
        CHECK(s.found && s.how == "bootloader/patches.ini");
        Touch(sd + "/atmosphere/kip_patches/fs_patches/empty/ABCDEF.ips");
        s = FindSigpatches(sd);
        CHECK(s.found && s.how == "atmosphere/kip_patches/fs_patches");
        std::system(("rm -rf " + sd + " && mkdir -p " + sd + "/atmosphere/contents/420000000000000B").c_str());
        Touch(sd + "/atmosphere/contents/420000000000000B/exefs.nsp");
        s = FindSigpatches(sd);
        CHECK(s.found && s.how == "sys-patch");
    }
    {
        const std::string sd = root + "/embedded";
        std::system(("mkdir -p " + sd + "/atmosphere").c_str());
        const std::string pkg = sd + "/atmosphere/package3";
        std::vector<unsigned char> data(160, 0xAA);
        const std::array<unsigned char, 20> m1 = {
            0x06,0,0x94,0,0,1,0,1,0,0,0,1,0x42,0,0,1,0,0,0x91,0
        };
        const std::array<unsigned char, 24> m2 = {
            0x40,0,0xF9,0,0,1,0,1,0,1,0,1,0,1,0,1,0x40,0,0xB9,0,9,0,0x1C,0
        };
        std::memcpy(data.data() + 4, m1.data(), m1.size());
        std::memcpy(data.data() + 48, m2.data(), m2.size());
        MakePackage3(pkg, "mesosphere", data);
        CHECK(DetectEmbeddedFsPatches(sd) == EmbeddedFsPatchType::Mesosphere);
        CHECK(FindSigpatches(sd).found);
        std::system(("mkdir -p " + sd + "/bootloader").c_str());
        Touch(sd + "/bootloader/patches.ini", "[FS:0123456789ABCDEF]\n");
        CHECK(FindSigpatches(sd).how == "bootloader/patches.ini");
        std::remove((sd + "/bootloader/patches.ini").c_str());
        data[4] ^= 0xFF;
        MakePackage3(pkg, "mesosphere", data);
        CHECK(DetectEmbeddedFsPatches(sd) == EmbeddedFsPatchType::None);
        CHECK(!FindSigpatches(sd).found);

        data.assign(160, 0xAA);
        // Detect Fusee's adjacent NCA signature bypass instructions
        // instead of relying on firmware-specific FS offsets.
        const std::array<unsigned char, 8> fs_payload = {
            0xE0, 0x03, 0x1F, 0x2A, // mov w0, wzr
            0x1F, 0x20, 0x03, 0xD5  // nop
        };
        std::memcpy(data.data() + 4, fs_payload.data(), fs_payload.size());
        MakePackage3(pkg, "fusee", data);
        CHECK(DetectEmbeddedFsPatches(sd) == EmbeddedFsPatchType::Fusee);
        CHECK(FindSigpatches(sd).found);
        // Both instructions must be present and adjacent.
        data[4] ^= 0xFF;
        MakePackage3(pkg, "fusee", data);
        CHECK(DetectEmbeddedFsPatches(sd) == EmbeddedFsPatchType::None);
        data[4] ^= 0xFF;
        data[8] ^= 0xFF;
        MakePackage3(pkg, "fusee", data);
        CHECK(DetectEmbeddedFsPatches(sd) == EmbeddedFsPatchType::None);
        data[8] ^= 0xFF;
        MakePackage3(pkg, "fusee", data);
        CHECK(DetectEmbeddedFsPatches(sd) == EmbeddedFsPatchType::Fusee);
        // Reject invalid PK31 headers even if the patch payload is present.
        MakePackage3(pkg, "fusee", data);
        if (FILE *f = std::fopen(pkg.c_str(), "r+b")) {
            std::fputc('X', f);
            std::fclose(f);
        }
        CHECK(DetectEmbeddedFsPatches(sd) == EmbeddedFsPatchType::None);
    }
    // Test Mesosphere and Fusee detection when both paths are provided.
    if (argc == 3) {
        const auto first = DetectEmbeddedFsPatches(argv[1]);
        const auto second = DetectEmbeddedFsPatches(argv[2]);
        CHECK(first == EmbeddedFsPatchType::Mesosphere);
        CHECK(second == EmbeddedFsPatchType::Fusee);
    }
    if (failures) std::printf("%d failed\n", failures);
    else std::printf("compress_meta: all passed\n");
    return failures ? 1 : 0;
}
