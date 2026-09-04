# Analysis: balloons.exe

**File:** `MDE_File_Sample_173ca697f0387c389dbf4cf635dc9bf3345c0f48/balloons.exe`
**Date:** 2026-09-04
**Analyst:** lumb3r

---

## Summary

PE32 Windows GUI executable. Delphi/Free Pascal compiled. Resources show signs of packing/encryption.

---

## File Information

| Property | Value |
|----------|-------|
| Type | PE32 executable (GUI) Intel i386 |
| Size | 2,701,712 bytes (2.6 MB) |
| MD5 | 4e807c5f0868e9c939ba4159ea09587c |
| SHA256 | f9e181e588f8971c7a01400898c02da985c17ea38c07948772f91bda270dc886 |
| Compiler | Delphi / Free Pascal (section names, strings) |
| Timestamp | 1779452278 (2026-01-22) |
| Entry Point | 0xb1e60 |
| Image Base | 0x400000 |
| Digital Signature | **None** (unsigned) |

---

## Sections

| Section | Virtual Addr | Virtual Size | Raw Size | Entropy | Notes |
|---------|-------------|-------------|----------|---------|-------|
| .text | 0x1000 | 0xaf80c | 0xafa00 | 6.38 | Code |
| .itext | 0xb1000 | 0x18cc | 0x1a00 | 6.04 | Import table |
| .data | 0xb3000 | 0x3f3c | 0x4000 | 5.18 | Initialized data |
| .bss | 0xb7000 | 0x734c | 0x0 | 0.00 | Uninitialized |
| .idata | 0xbf000 | 0x1068 | 0x1200 | 4.82 | Import data |
| .didata | 0xc1000 | 0x1a4 | 0x200 | 2.76 | Delayed import |
| .edata | 0xc2000 | 0x71 | 0x200 | 1.34 | Export data |
| .tls | 0xc3000 | 0x18 | 0x0 | 0.00 | Thread local storage |
| .rdata | 0xc4000 | 0x5d | 0x200 | 1.38 | Read-only data |
| .reloc | 0xc5000 | 0x11fec | 0x12000 | 6.70 | Relocations |
| .rsrc | 0xd7000 | 0xcde4 | 0xce00 | **7.40** | **Resources (packed)** |

---

## Imports

| DLL | Suspicious APIs |
|-----|-----------------|
| kernel32.dll | VirtualAlloc, VirtualProtect, CreateProcessW, FindResourceW, LoadResource, SizeofResource |
| advapi32.dll | RegOpenKeyExW, OpenProcessToken, AdjustTokenPrivileges, LookupPrivilegeValueW |
| user32.dll | CreateWindowExW, SetWindowLongW, CallWindowProcW |
| oleaut32.dll | SafeArrayCreate, SafeArrayPutElement, SafeArrayGetElement |
| comctl32.dll | InitCommonControls |

---

## Resources

| Type | Count | Entropy Range | Assessment |
|------|-------|---------------|------------|
| ID:3 (icons/images) | 6 | 7.67-7.98 | **High entropy - likely encrypted/packed** |
| ID:6 (strings?) | 12 | 3.11-3.51 | Normal |
| ID:10 | 3 | 3.74-5.23 | Normal |
| ID:14 | 1 | 2.63 | Normal |
| ID:16 | 1 | 2.70 | Normal |
| ID:24 (manifest) | 1 | 4.89 | Normal |

---

## Key Findings

1. **Unsigned executable** - No digital signature despite certificate-related strings in resources (OS loader artifacts)
2. **High entropy resources** - ID:3 resources show entropy >7.6, suggesting encryption or packing
3. **TLS callbacks** - Present (anti-debug technique)
4. **Common APIs** - VirtualAlloc/VirtualProtect/CreateProcess are common in legitimate software but warrant monitoring
5. **Network imports** - winhttp.dll referenced in resources but not in imports table (dynamic loading?)

---

## Recommendations

1. **Dynamic analysis** - Execute in isolated sandbox with network monitoring
2. **Resource extraction** - Dump and analyze high-entropy resources
3. **String analysis** - Check for obfuscated strings
4. **Behavioral monitoring** - Monitor process injection, network connections, persistence

---

## Status

- [x] Static analysis
- [ ] Dynamic analysis
- [ ] Resource extraction
- [ ] Behavioral monitoring
