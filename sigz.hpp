#pragma once
#include <vector>
#include <string>
#include <ranges>
#include <windows.h>

// Read the README please!
// https://github.com/creaffy/sigz

namespace sigz {
    constexpr inline int WILDCARD = -1;
    constexpr inline int NO_LIMIT = -1;

    [[nodiscard]] inline void* scan_unsafe_first(
        void* first,
        void* last,
        const std::vector<int>& pattern
    ) {
        for (unsigned char* ptr = reinterpret_cast<unsigned char*>(first); ptr < reinterpret_cast<unsigned char*>(last) - pattern.size() + 1; ++ptr) {
            bool found = true;
            for (size_t i = 0; i < pattern.size(); ++i) {
                if (pattern[i] == sigz::WILDCARD || ptr[i] == pattern[i])
                    continue;
                found = false;
                break;
            }
            if (found)
                return ptr;
        }
        return nullptr;
    }

    [[nodiscard]] inline std::vector<void*> scan_unsafe(
        void* first,
        void* last,
        const std::vector<int>& pattern,
        size_t limit = sigz::NO_LIMIT
    ) {
        std::vector<void*> results{};
        void* next = first;
        while ((results.size() != limit || limit == sigz::NO_LIMIT) && next < last) {
            void* ptr = sigz::scan_unsafe_first(next, last, pattern);
            if (ptr == nullptr)
                break;
            next = reinterpret_cast<char*>(ptr) + 1;
            results.push_back(ptr);
        }
        return results;
    }

    [[nodiscard]] inline std::vector<void*> scan(
        void* first,
        void* last,
        const std::vector<int>& pattern,
        size_t limit = sigz::NO_LIMIT
    ) {
        std::vector<MEMORY_BASIC_INFORMATION> regions{};
        MEMORY_BASIC_INFORMATION region_info{};
        for (char* ptr = reinterpret_cast<char*>(first); ptr < reinterpret_cast<char*>(last); ++ptr) {
            if (!VirtualQuery(ptr, &region_info, sizeof(region_info)))
                return {};
            regions.push_back(region_info);
            ptr += region_info.RegionSize;
        }
        size_t remaining = limit;
        std::vector<void*> results{};
        for (auto& region : regions) {
            constexpr DWORD flags1 = PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;
            constexpr DWORD flags2 = PAGE_TARGETS_INVALID | PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS;
            if ((region.State & (MEM_COMMIT | MEM_RESERVE)) == 0 || region.Protect == 0 || (region.Protect & flags1) == 0 || (region.Protect & flags2) != 0)
                continue;
            void* region_first = region.BaseAddress;
            void* region_last = reinterpret_cast<char*>(region.BaseAddress) + region.RegionSize;
            auto region_results = sigz::scan_unsafe(max(first, region_first), min(last, region_last), pattern, remaining);
            for (void* ptr : region_results)
                results.push_back(ptr);
            if (region_results.size() != remaining)
                remaining -= region_results.size();
            if (limit != sigz::NO_LIMIT && remaining == 0)
                break;
        }
        return results;
    }

    [[nodiscard]] inline void* scan_first(
        void* first,
        void* last,
        const std::vector<int>& pattern
    ) {
        std::vector<void*> result = sigz::scan(first, last, pattern, 1);
        return result.empty() ? nullptr : result.front();
    }

    [[nodiscard]] inline std::vector<void*> scan_image(
        std::string_view name,
        const std::vector<int>& pattern,
        size_t limit = sigz::NO_LIMIT
    ) {
        char* base = reinterpret_cast<char*>(GetModuleHandleA(name.data()));
        if (!base)
            return {};
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        return sigz::scan_unsafe(base, base + nt->OptionalHeader.SizeOfImage, pattern, limit);
    }

    [[nodiscard]] inline void* scan_image_first(
        std::string_view name,
        const std::vector<int>& pattern
    ) {
        std::vector<void*> result = sigz::scan_image(name, pattern, 1);
        return result.empty() ? nullptr : result.front();
    }

    [[nodiscard]] inline void* scan_process_first(
        const std::vector<int>& pattern
    ) {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        return sigz::scan_first(si.lpMinimumApplicationAddress, si.lpMaximumApplicationAddress, pattern);
    }

    [[nodiscard]] inline std::vector<void*> scan_process(
        const std::vector<int>& pattern,
        size_t limit = sigz::NO_LIMIT
    ) {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        return sigz::scan(si.lpMinimumApplicationAddress, si.lpMaximumApplicationAddress, pattern, limit);
    }

    namespace make {
        [[nodiscard]] inline std::vector<int> ida(
            std::string_view pattern
        ) {
            std::vector<int> result{};
            for (auto&& token : std::ranges::split_view(pattern, ' ') | std::views::transform([](auto e) { return std::string_view(e); }))
                result.push_back(token == "?" ? sigz::WILDCARD : std::stoi(token.data(), nullptr, 16));
            return result;
        }

        [[nodiscard]] inline std::vector<int> x64dbg(
            std::string_view pattern
        ) {
            std::vector<int> result{};
            for (auto&& token : std::ranges::split_view(pattern, ' ') | std::views::transform([](auto e) { return std::string_view(e); }))
                result.push_back(token == "??" ? sigz::WILDCARD : std::stoi(token.data(), nullptr, 16));
            return result;
        }

        [[nodiscard]] inline std::vector<int> string(
            std::string_view str,
            bool null = true
        ) {
            return std::vector<int>(str.begin(), null ? str.end() + 1 : str.end());
        }

        [[nodiscard]] inline std::vector<int> string(
            std::wstring_view str,
            bool null = true
        ) {
            const char* first = reinterpret_cast<const char*>(str.begin()._Unwrapped());
            const char* last = reinterpret_cast<const char*>(str.end()._Unwrapped());
            return std::vector<int>(first, null ? last + 2 : last);
        }

        template <class T>
        [[nodiscard]] inline std::vector<int> value(
            const T& data
        ) {
            return std::vector<int>(reinterpret_cast<const char*>(&data), reinterpret_cast<const char*>(&data) + sizeof(T));
        }
    }
}
