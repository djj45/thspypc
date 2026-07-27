#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "hlib_layout.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "version.lib")

namespace {

static_assert(sizeof(void*) == 4, "hlib_harness must be compiled for x86");

struct LoadedModule {
    HMODULE module = nullptr;
    DLL_DIRECTORY_COOKIE cookie = nullptr;

    ~LoadedModule() {
        if (module != nullptr) {
            FreeLibrary(module);
        }
        if (cookie != nullptr) {
            RemoveDllDirectory(cookie);
        }
    }

    LoadedModule(const LoadedModule&) = delete;
    LoadedModule& operator=(const LoadedModule&) = delete;
    LoadedModule() = default;

    LoadedModule(LoadedModule&& other) noexcept
        : module(other.module), cookie(other.cookie) {
        other.module = nullptr;
        other.cookie = nullptr;
    }

    LoadedModule& operator=(LoadedModule&& other) noexcept {
        if (this != &other) {
            if (module != nullptr) {
                FreeLibrary(module);
            }
            if (cookie != nullptr) {
                RemoveDllDirectory(cookie);
            }
            module = other.module;
            cookie = other.cookie;
            other.module = nullptr;
            other.cookie = nullptr;
        }
        return *this;
    }
};

struct ProbeResult {
    std::uintptr_t object = 0;
    std::uintptr_t vtable = 0;
    std::uintptr_t parse_entry = 0;
    int parse_result = 0;
    int record_count = -1;
    DWORD exception_code = 0;
};

std::string utf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0,
        nullptr, nullptr);
    if (size <= 0) {
        throw std::runtime_error("WideCharToMultiByte failed");
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(),
        size, nullptr, nullptr);
    return result;
}

std::string json_escape(const std::string& value) {
    std::ostringstream stream;
    for (const unsigned char ch : value) {
        switch (ch) {
            case '\\':
                stream << "\\\\";
                break;
            case '"':
                stream << "\\\"";
                break;
            case '\b':
                stream << "\\b";
                break;
            case '\f':
                stream << "\\f";
                break;
            case '\n':
                stream << "\\n";
                break;
            case '\r':
                stream << "\\r";
                break;
            case '\t':
                stream << "\\t";
                break;
            default:
                if (ch < 0x20) {
                    stream << "\\u" << std::hex << std::setw(4)
                           << std::setfill('0') << static_cast<int>(ch);
                } else {
                    stream << static_cast<char>(ch);
                }
        }
    }
    return stream.str();
}

std::wstring error_message(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD count = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring result =
        count == 0 ? L"Windows error " + std::to_wstring(code)
                   : std::wstring(buffer, count);
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    while (!result.empty() &&
           (result.back() == L'\r' || result.back() == L'\n')) {
        result.pop_back();
    }
    return result;
}

std::vector<std::uint8_t> read_file(const std::wstring& path) {
    HANDLE file = CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE |
                                           FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error(
            "CreateFileW failed: " + utf8(error_message(GetLastError())));
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
        size.QuadPart > 1024LL * 1024LL * 1024LL) {
        const DWORD error = GetLastError();
        CloseHandle(file);
        throw std::runtime_error(
            "GetFileSizeEx failed: " + utf8(error_message(error)));
    }

    std::vector<std::uint8_t> data(static_cast<std::size_t>(size.QuadPart));
    std::size_t offset = 0;
    while (offset < data.size()) {
        const DWORD requested = static_cast<DWORD>(
            std::min<std::size_t>(data.size() - offset, 1U << 20));
        DWORD received = 0;
        if (!ReadFile(file, data.data() + offset, requested, &received, nullptr)) {
            const DWORD error = GetLastError();
            CloseHandle(file);
            throw std::runtime_error(
                "ReadFile failed: " + utf8(error_message(error)));
        }
        if (received == 0) {
            CloseHandle(file);
            throw std::runtime_error("unexpected end of file");
        }
        offset += received;
    }
    CloseHandle(file);
    return data;
}

std::wstring sha256(const std::vector<std::uint8_t>& data) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<std::uint8_t> object;
    std::vector<std::uint8_t> digest;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    }

    DWORD object_size = 0;
    DWORD digest_size = 0;
    DWORD copied = 0;
    status = BCryptGetProperty(
        algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &copied, 0);
    if (status >= 0) {
        status = BCryptGetProperty(
            algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&digest_size), sizeof(digest_size), &copied,
            0);
    }
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("BCryptGetProperty failed");
    }

    object.resize(object_size);
    digest.resize(digest_size);
    status = BCryptCreateHash(
        algorithm, &hash, object.data(), object_size, nullptr, 0, 0);
    if (status >= 0 && !data.empty()) {
        status = BCryptHashData(
            hash, const_cast<PUCHAR>(data.data()),
            static_cast<ULONG>(data.size()), 0);
    }
    if (status >= 0) {
        status = BCryptFinishHash(hash, digest.data(), digest_size, 0);
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        throw std::runtime_error("SHA-256 calculation failed");
    }

    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setfill(L'0');
    for (const std::uint8_t byte : digest) {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}

std::wstring file_version(const std::wstring& path) {
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (size == 0) {
        return {};
    }
    std::vector<std::uint8_t> buffer(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buffer.data())) {
        return {};
    }

    struct Translation {
        WORD language;
        WORD code_page;
    };
    Translation* translations = nullptr;
    UINT translations_size = 0;
    if (VerQueryValueW(
            buffer.data(), L"\\VarFileInfo\\Translation",
            reinterpret_cast<void**>(&translations), &translations_size) &&
        translations != nullptr && translations_size >= sizeof(Translation)) {
        wchar_t query[64]{};
        swprintf_s(
            query, L"\\StringFileInfo\\%04x%04x\\FileVersion",
            translations[0].language, translations[0].code_page);
        wchar_t* value = nullptr;
        UINT value_size = 0;
        if (VerQueryValueW(
                buffer.data(), query, reinterpret_cast<void**>(&value),
                &value_size) &&
            value != nullptr && value_size > 1) {
            return std::wstring(value);
        }
    }

    VS_FIXEDFILEINFO* info = nullptr;
    UINT info_size = 0;
    if (!VerQueryValueW(
            buffer.data(), L"\\", reinterpret_cast<void**>(&info), &info_size) ||
        info == nullptr || info_size < sizeof(VS_FIXEDFILEINFO)) {
        return {};
    }
    std::wostringstream stream;
    stream << HIWORD(info->dwFileVersionMS) << L'.'
           << LOWORD(info->dwFileVersionMS) << L'.'
           << HIWORD(info->dwFileVersionLS);
    const WORD revision = LOWORD(info->dwFileVersionLS);
    if (revision != 0) {
        stream << L'.' << revision;
    }
    return stream.str();
}

std::wstring parent_path(const std::wstring& path) {
    const std::size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return L".";
    }
    return path.substr(0, separator);
}

LoadedModule load_module(const std::wstring& path) {
    if (!SetDefaultDllDirectories(
            LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS)) {
        throw std::runtime_error(
            "SetDefaultDllDirectories failed: " +
            utf8(error_message(GetLastError())));
    }

    LoadedModule result;
    const std::wstring directory = parent_path(path);
    result.cookie = AddDllDirectory(directory.c_str());
    if (result.cookie == nullptr) {
        throw std::runtime_error(
            "AddDllDirectory failed: " + utf8(error_message(GetLastError())));
    }
    result.module = LoadLibraryExW(
        path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS |
            LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (result.module == nullptr) {
        throw std::runtime_error(
            "LoadLibraryExW failed: " + utf8(error_message(GetLastError())));
    }
    return result;
}

IMAGE_NT_HEADERS32* nt_headers(HMODULE module) {
    auto* base = reinterpret_cast<std::uint8_t*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        throw std::runtime_error("loaded module has an invalid DOS header");
    }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        throw std::runtime_error("loaded module is not a valid PE32 x86 image");
    }
    return nt;
}

bool readable_page(const MEMORY_BASIC_INFORMATION& info) {
    if (info.State != MEM_COMMIT || (info.Protect & PAGE_GUARD) != 0 ||
        (info.Protect & PAGE_NOACCESS) != 0) {
        return false;
    }
    const DWORD protection = info.Protect & 0xFF;
    return protection == PAGE_READONLY || protection == PAGE_READWRITE ||
           protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ ||
           protection == PAGE_EXECUTE_READWRITE ||
           protection == PAGE_EXECUTE_WRITECOPY;
}

std::vector<std::uint8_t> snapshot_image(
    HMODULE module, std::uint32_t image_size) {
    std::vector<std::uint8_t> output(image_size, 0);
    auto* base = reinterpret_cast<std::uint8_t*>(module);
    std::size_t offset = 0;
    while (offset < output.size()) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(base + offset, &info, sizeof(info)) == 0) {
            throw std::runtime_error(
                "VirtualQuery failed: " + utf8(error_message(GetLastError())));
        }
        auto* region_base = reinterpret_cast<std::uint8_t*>(info.BaseAddress);
        const std::size_t region_offset =
            region_base <= base ? 0 : static_cast<std::size_t>(region_base - base);
        const std::size_t region_end = std::min<std::size_t>(
            output.size(), region_offset + info.RegionSize);
        const std::size_t copy_start = std::max(offset, region_offset);
        if (region_end <= copy_start) {
            throw std::runtime_error("VirtualQuery returned a non-advancing region");
        }
        if (readable_page(info)) {
            std::copy(
                base + copy_start, base + region_end,
                output.begin() + static_cast<std::ptrdiff_t>(copy_start));
        }
        offset = region_end;
    }
    return output;
}

void write_file(
    const std::wstring& path, const std::vector<std::uint8_t>& data) {
    HANDLE file = CreateFileW(
        path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error(
            "cannot create output: " + utf8(error_message(GetLastError())));
    }
    std::size_t offset = 0;
    while (offset < data.size()) {
        const DWORD requested = static_cast<DWORD>(
            std::min<std::size_t>(data.size() - offset, 1U << 20));
        DWORD written = 0;
        if (!WriteFile(
                file, data.data() + offset, requested, &written, nullptr) ||
            written != requested) {
            const DWORD error = GetLastError();
            CloseHandle(file);
            throw std::runtime_error(
                "WriteFile failed: " + utf8(error_message(error)));
        }
        offset += written;
    }
    CloseHandle(file);
}

std::wstring option(
    int argc, wchar_t** argv, const std::wstring& name, bool required = true) {
    for (int index = 2; index + 1 < argc; ++index) {
        if (argv[index] == name) {
            return argv[index + 1];
        }
    }
    if (required) {
        throw std::runtime_error("missing option: " + utf8(name));
    }
    return {};
}

std::string address_hex(std::uintptr_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << value;
    return stream.str();
}

bool invoke_chquote_probe(
    HMODULE module, const std::uint8_t* input, int input_size, int mode,
    ProbeResult* result) {
    using Constructor = void*(__thiscall*)(void* self);
    using Parse = int(__thiscall*)(
        void* self, const void* input, int input_size, int mode);
    using RecordCount = int(__thiscall*)(void* self);

    __try {
        void* object = VirtualAlloc(
            nullptr, 0x40, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (object == nullptr) {
            result->exception_code = GetLastError();
            return false;
        }
        auto* base = reinterpret_cast<std::uint8_t*>(module);
        const auto constructor = reinterpret_cast<Constructor>(
            base + hlib_layout::kHlib234.rvas.chquote_constructor);
        void* constructed = constructor(object);
        result->object = reinterpret_cast<std::uintptr_t>(constructed);
        if (constructed == nullptr) {
            return false;
        }

        auto** vtable = *reinterpret_cast<void***>(constructed);
        result->vtable = reinterpret_cast<std::uintptr_t>(vtable);
        const auto expected_vtable = reinterpret_cast<std::uintptr_t>(
            base + hlib_layout::kHlib234.rvas.chquote_vtable);
        if (result->vtable != expected_vtable) {
            return false;
        }

        const auto parse = reinterpret_cast<Parse>(vtable[5]);
        result->parse_entry = reinterpret_cast<std::uintptr_t>(vtable[5]);
        const auto expected_parse = reinterpret_cast<std::uintptr_t>(
            base + hlib_layout::kHlib234.rvas.chquote_parse);
        if (result->parse_entry != expected_parse) {
            return false;
        }
        result->parse_result = parse(constructed, input, input_size, mode);
        if (result->parse_result == 0) {
            const auto record_count = reinterpret_cast<RecordCount>(
                base + hlib_layout::kHlib234.rvas.chquote_record_count);
            result->record_count = record_count(constructed);
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result->exception_code = GetExceptionCode();
        return false;
    }
}

bool known_build(
    const std::wstring& version, const std::wstring& digest,
    std::uint64_t file_size, std::uint32_t image_size) {
    const auto& expected = hlib_layout::kHlib234;
    return version == expected.file_version && digest == expected.sha256 &&
           file_size == expected.file_size && image_size == expected.image_size;
}

bool signatures_match(HMODULE module) {
    const auto* base = reinterpret_cast<const std::uint8_t*>(module);
    for (const auto& signature : hlib_layout::kHlib234Signatures) {
        const auto* actual = base + signature.rva;
        for (std::size_t index = 0; index < signature.bytes.size(); ++index) {
            if (signature.mask[index] == 'x' &&
                actual[index] != signature.bytes[index]) {
                std::cerr << "signature mismatch: " << signature.name
                          << " rva=" << address_hex(signature.rva)
                          << " byte=" << index << '\n';
                return false;
            }
        }
    }
    return true;
}

void print_usage() {
    std::wcerr
        << L"Usage:\n"
        << L"  hlib_harness.exe fingerprint --dll <hlib.dll>\n"
        << L"  hlib_harness.exe probe-chquote --dll <hlib.dll> "
           L"--input <file>\n"
        << L"  hlib_harness.exe scan-ascii --dll <hlib.dll> --needle <text>\n"
        << L"  hlib_harness.exe dump-image --dll <hlib.dll> --output <file>\n";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc < 4) {
            print_usage();
            return 2;
        }
        const std::wstring command = argv[1];
        const std::wstring dll_path = option(argc, argv, L"--dll");
        const std::vector<std::uint8_t> file_bytes = read_file(dll_path);
        const std::wstring digest = sha256(file_bytes);
        const std::wstring version = file_version(dll_path);
        LoadedModule loaded = load_module(dll_path);
        IMAGE_NT_HEADERS32* nt = nt_headers(loaded.module);
        const std::uint32_t image_size = nt->OptionalHeader.SizeOfImage;
        const bool is_known = known_build(
            version, digest, file_bytes.size(), image_size);
        const bool rva_signatures_match =
            is_known && signatures_match(loaded.module);

        if (command == L"fingerprint") {
            std::cout
                << "{\"command\":\"fingerprint\",\"architecture\":\"x86\","
                << "\"pointer_size\":" << sizeof(void*) << ",\"dll\":\""
                << json_escape(utf8(dll_path)) << "\",\"file_size\":"
                << file_bytes.size() << ",\"sha256\":\""
                << json_escape(utf8(digest)) << "\",\"file_version\":\""
                << json_escape(utf8(version)) << "\",\"known_build\":"
                << (is_known ? "true" : "false") << ",\"module_base\":\""
                << address_hex(reinterpret_cast<std::uintptr_t>(loaded.module))
                << "\",\"image_size\":" << image_size
                << ",\"internal_rvas_rebased\":"
                << (hlib_layout::kHlib234.internal_rvas_rebased ? "true"
                                                                : "false")
                << ",\"rva_signatures_match\":"
                << (rva_signatures_match ? "true" : "false") << "}\n";
            if (!is_known) {
                return 3;
            }
            return rva_signatures_match ? 0 : 4;
        }

        if (command == L"probe-chquote") {
            if (!is_known || !rva_signatures_match) {
                throw std::runtime_error(
                    "probe refused: DLL identity or RVA signatures mismatch");
            }
            const std::wstring input_path = option(argc, argv, L"--input");
            const std::vector<std::uint8_t> input = read_file(input_path);
            if (input.empty() || input.size() > 64U * 1024U * 1024U) {
                throw std::runtime_error(
                    "probe input must be between 1 byte and 64 MiB");
            }
            ProbeResult result;
            const bool invoked = invoke_chquote_probe(
                loaded.module, input.data(), static_cast<int>(input.size()), 0,
                &result);
            std::ostringstream parse_hex;
            parse_hex << "0x" << std::hex << std::uppercase
                      << static_cast<std::uint32_t>(result.parse_result);
            std::ostringstream exception_hex;
            exception_hex << "0x" << std::hex << std::uppercase
                          << result.exception_code;
            std::cout
                << "{\"command\":\"probe-chquote\",\"input\":\""
                << json_escape(utf8(input_path)) << "\",\"input_size\":"
                << input.size() << ",\"invoked\":"
                << (invoked ? "true" : "false") << ",\"object\":\""
                << address_hex(result.object) << "\",\"vtable\":\""
                << address_hex(result.vtable) << "\",\"parse_entry\":\""
                << address_hex(result.parse_entry) << "\",\"parse_result\":"
                << result.parse_result << ",\"parse_result_hex\":\""
                << parse_hex.str() << "\",\"exception_code\":\""
                << exception_hex.str() << "\",\"record_count\":"
                << result.record_count << "}\n";
            if (!invoked) {
                return 5;
            }
            return result.parse_result == 0 ? 0 : 6;
        }

        const std::vector<std::uint8_t> image =
            snapshot_image(loaded.module, image_size);
        if (command == L"dump-image") {
            const std::wstring output = option(argc, argv, L"--output");
            write_file(output, image);
            std::cout << "{\"command\":\"dump-image\",\"known_build\":"
                      << (is_known ? "true" : "false")
                      << ",\"output\":\"" << json_escape(utf8(output))
                      << "\",\"bytes\":" << image.size() << "}\n";
            return 0;
        }
        if (command == L"scan-ascii") {
            const std::string needle = utf8(option(argc, argv, L"--needle"));
            if (needle.empty()) {
                throw std::runtime_error("needle must not be empty");
            }
            std::vector<std::uint32_t> matches;
            auto cursor = image.begin();
            while (cursor != image.end()) {
                cursor = std::search(
                    cursor, image.end(), needle.begin(), needle.end());
                if (cursor == image.end()) {
                    break;
                }
                matches.push_back(static_cast<std::uint32_t>(
                    std::distance(image.begin(), cursor)));
                ++cursor;
            }
            std::cout << "{\"command\":\"scan-ascii\",\"known_build\":"
                      << (is_known ? "true" : "false") << ",\"needle\":\""
                      << json_escape(needle) << "\",\"matches\":[";
            for (std::size_t index = 0; index < matches.size(); ++index) {
                if (index != 0) {
                    std::cout << ',';
                }
                std::cout << '"' << address_hex(matches[index]) << '"';
            }
            std::cout << "]}\n";
            return 0;
        }

        throw std::runtime_error("unknown command: " + utf8(command));
    } catch (const std::exception& error) {
        std::cerr << "hlib_harness: " << error.what() << '\n';
        return 1;
    }
}
