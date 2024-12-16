# sigz

C++ Internal Memory Scanning Library for Windows.

## Notes

-   This is really a minimal library with only basic functionality.
-   Please report any bugs <3
-   `sigz::scan_unsafe()` does not check page protection.
-   If a pattern spans over more than one region, it won't be found.
-   `sigz::scan()` checks page protection, `sigz::scan_image()` does not. It trusts the PE headers.
-   When a scan fails, nullptr or an empty vector is returned. I found using std::expected and other error handling annoying to work with so I just got rid of it entirely lol.
-   Pattern validity is not checked. You need to make sure everything is right before using a pattern or else you may crash.
-   'first' and 'last' mean the range [first, last) will be scanned.
-   When passing structures into `sigz::make::value<T>()` remember about paddings and vtables.

## Usage

### Patterns

Patterns are just `std::vector<int>`'s. They can contain values between 0x00 and 0xFF. Use `sigz::WILDCARD` (or just -1) for wildcard. <br/>
There are helper functions for generating patterns in the `sigz::make` namespace.

### Scan Functions

-   `sigz::scan_unsafe(first, last, pattern, limit = sigz::NO_LIMIT)` <br/>
    Scans range without checking page protection. Returns a vector of results.

-   `sigz::scan_unsafe_first(first, last, pattern)` <br/>
    Scans range without checking page protection. Returns the first match.

-   `sigz::scan(first, last, pattern, limit = sigz::NO_LIMIT)` <br/>
    Scans range and checks page protection. Skips unreadable memory regions. Returns a vector of results.

-   `sigz::scan_first(first, last, pattern)` <br/>
    Scans range and checks page protection. Skips unreadable memory regions. Returns the first match.

-   `sigz::scan_image(name, pattern, limit = sigz::NO_LIMIT)` <br/>
    Scans given module. Trusts that the entire module is readable. Returns a vector of results.

-   `sigz::scan_image_first(name, pattern)` <br/>
    Scans given module. Trusts that the entire module is readable. Returns the first match.

-   `sigz::scan_process(pattern, limit = sigz::NO_LIMIT)` <br/>
    Scans entire address space of the current process. Checks page protection. Returns a vector of results.

-   `sigz::scan_process_first(pattern)` <br/>
    Scans entire address space of the current process. Checks page protection. Returns the first match.

### Helper Functions

-   `sigz::make::ida(pattern)` <br/>
    Generates a pattern based on a string signature. Uses "?" as a wildcard. Example: `00 ? 0a af 01 ? 54`

-   `sigz::make::x64dbg(pattern)` <br/>
    Generates a pattern based on a string signature. Uses "??" as a wildcard. Example: `00 ?? 0a af 01 ?? 54`

-   `sigz::make::string(pattern)` <br/>
    Generates a pattern based on a string. There are versions of this function for both strings and wstrings.

-   `sigz::make::value<T>(data)` <br/>
    Generates a pattern based on the structure of T in memory. Remember about paddings and vtables.
