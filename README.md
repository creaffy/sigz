# sigz

Modern C++ Internal Memory Scanner For Windows.

## Usage

### Scanning Module

Multiple results

```cpp
sigz::scan_image<sigz::vec>("ntdll.dll", sigz::make_sig<sigz::string>("MZ"), 5);
```

Single result

```cpp
sigz::scan_image<sigz::ptr>("ntdll.dll", sigz::make_sig<sigz::value>(1llu));
sigz::scan_image_first("ntdll.dll", sigz::make_sig<sigz::ida>("00 01 ? ? 02 03"));
```

### Scanning Range

Multiple results

```cpp
sigz::scan<sigz::vec>(first, last, sigz::make_sig<sigz::x64dbg>("00 01 ?? ?? 02 03"), 7);
```

Single result

```cpp
sigz::scan<sigz::ptr>(first, last, sigz::make_sig<sigz::x64dbg>("00 01 ?? ?? 02 03"));
sigz::scan_first(first, last, sigz::make_sig<sigz::string>(L"abcdef"));
```

## Helpers

Scan functions use std::vector<int16_t> as the pattern. All elements must be in the [0x00, 0xFF] range or be equal to -1 (wildcard). To make your life easier, sigz provides helper functions for generating said vectors.

IDA style patterns. Uses "?" for wildcards.

```cpp
sigz::make_sig<sigz::ida>("0A B8 8A ? ? FA");
```

x64dbg style patterns. Uses "??" for wildcards.

```cpp
sigz::make_sig<sigz::x64dbg>("0A B8 8A ?? ?? FA");
```

Signatures generated from a string (or a wstring). Second arg indicates whether or not null byte will be addded. It's set to true by default.

```cpp
sigz::make_sig<sigz::string>("hi");
sigz::make_sig<sigz::string>(L"hi", false);
```

Signatures generated from structures. It's just a template so it supports everything.

```cpp
sigz::make_sig<sigz::value>(true);
sigz::make_sig<sigz::value>(69llu);
sigz::make_sig<sigz::value>(some_type_t{ 0, 0, 1, 2 });
```
