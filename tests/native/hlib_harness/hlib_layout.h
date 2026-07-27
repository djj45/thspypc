#pragma once

#include <array>
#include <cstdint>

namespace hlib_layout {

struct Rvas {
    std::uint32_t chquote_constructor;
    std::uint32_t chquote_vtable;
    std::uint32_t chquote_parse;
    std::uint32_t chquote_record_count;
    std::uint32_t hd_version_classifier;
    std::uint32_t wrapper;
    std::uint32_t wrapper_constructor_call;
    std::uint32_t wrapper_parse_call;
};

struct RvaSignature {
    const char* name;
    std::uint32_t rva;
    std::array<std::uint8_t, 16> bytes;
    const char* mask;
};

struct SupportedBuild {
    const wchar_t* file_version;
    const wchar_t* sha256;
    std::uint64_t file_size;
    std::uint32_t image_size;
    bool internal_rvas_rebased;
    Rvas rvas;
};

inline constexpr SupportedBuild kHlib234{
    L"2.3.4",
    L"07F371026341E0F9B88232274DBE4252A185C56D589CD35F50531921879550D7",
    4752616ULL,
    0x008C7000U,
    true,
    {
        0x0003E4F0U,
        0x0016BF30U,
        0x0003EA40U,
        0x0003E910U,
        0x00040D10U,
        0x00066C90U,
        0x00066CF1U,
        0x00066D42U,
    },
};

// Absolute addresses in exception metadata are relocated at load time.  Their
// four bytes are wildcarded while the surrounding instructions remain exact.
inline constexpr std::array<RvaSignature, 6> kHlib234Signatures{{
    {
        "CHQuoteFile::CHQuoteFile",
        0x0003E4F0U,
        {0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x00, 0x00,
         0x00, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00},
        "xxxxxx????xxxxxx",
    },
    {
        "CHQuoteFile::parse",
        0x0003EA40U,
        {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x2C, 0x89, 0x4D,
         0xFC, 0x83, 0x7D, 0x08, 0x00, 0x74, 0x0C, 0x83},
        "xxxxxxxxxxxxxxxx",
    },
    {
        "CHQuoteFile::record_count",
        0x0003E910U,
        {0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x8B,
         0x4D, 0xFC, 0xE8, 0x11, 0x0E, 0x00, 0x00, 0x0F},
        "xxxxxxxxxxxxxxxx",
    },
    {
        "classify_hd_version",
        0x00040D10U,
        {0x55, 0x8B, 0xEC, 0xB8, 0x01, 0x00, 0x00, 0x00,
         0x6B, 0xC8, 0x00, 0x8B, 0x55, 0x08, 0x0F, 0xBE},
        "xxxxxxxxxxxxxxxx",
    },
    {
        "construct_and_parse_wrapper",
        0x00066C90U,
        {0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x00, 0x00,
         0x00, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00},
        "xxxxxx????xxxxxx",
    },
    {
        "wrapper_vtable_parse_call",
        0x00066D37U,
        {0x8B, 0x11, 0x8B, 0x8D, 0xFC, 0xFE, 0xFF, 0xFF,
         0x8B, 0x42, 0x14, 0xFF, 0xD0, 0x85, 0xC0, 0x74},
        "xxxxxxxxxxxxxxxx",
    },
}};

}  // namespace hlib_layout
