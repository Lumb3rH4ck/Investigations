# Analysis: balloons.exe

**File:** `MDE_File_Sample_173ca697f0387c389dbf4cf635dc9bf3345c0f48/balloons.exe`
**Date:** 2026-09-04
**Analyst:** Rhys Wilson

---

## Summary

**Legitimate Inno Setup installer** for "Balloons" software by EOS MIST LTD. Not malware. The high-entropy resources were compressed PNG icons, not packed/encrypted data.

---

## File Information

| Property | Value |
|----------|-------|
| Type | PE32 executable (GUI) Intel i386 |
| Size | 2,701,712 bytes (2.6 MB) |
| MD5 | 4e807c5f0868e9c939ba4159ea09587c |
| SHA256 | f9e181e588f9971c7a01400898c02da985c17ea38c07948772f91bda270dc886 |
| Compiler | Inno Setup (Delphi/Free Pascal) |
| Timestamp | 1779452278 (2026-01-22) |
| Entry Point | 0xb1e60 |
| Digital Signature | **None** (unsigned) |

---

## Product Information

| Field | Value |
|-------|-------|
| **Company** | EOS MIST LTD |
| **Product** | Balloons Installer |
| **Version** | 16.51.2.1 |
| **Copyright** | © 2026 EOS MIST LTD |
| **Installer** | Inno Setup |

---

## Sections

| Section | Virtual Size | Raw Size | Entropy | Notes |
|---------|-------------|----------|---------|-------|
| .text | 0xaf80c | 0xafa00 | 6.38 | Code |
| .itext | 0x18cc | 0x1a00 | 6.04 | Import table |
| .data | 0x3f3c | 0x4000 | 5.18 | Initialized data |
| .bss | 0x734c | 0x0 | 0.00 | Uninitialized |
| .idata | 0x1068 | 0x1200 | 4.82 | Import data |
| .didata | 0x1a4 | 0x200 | 2.76 | Delayed import |
| .edata | 0x71 | 0x200 | 1.34 | Export data |
| .tls | 0x18 | 0x0 | 0.00 | Thread local storage |
| .rdata | 0x5d | 0x200 | 1.38 | Read-only data |
| .reloc | 0x11fec | 0x12000 | 6.70 | Relocations |
| .rsrc | 0xcde4 | 0xce00 | 7.40 | Resources (PNG icons) |

---

## Resources

| Type | Count | Details |
|------|-------|---------|
| **Icons (ID:3)** | 6 | PNG 16x16, 32x32, 48x48, 64x64, 128x128, 256x256 (all 8-bit RGBA) |
| **Strings (ID:6)** | 12 | String table entries |
| **Version (ID:16)** | 1 | VS_VERSION_INFO |
| **Manifest (ID:24)** | 1 | Inno Setup manifest |

**Note:** High entropy in .rsrc section was due to PNG compression, NOT packing/encryption.

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

## Key Findings

1. **Legitimate installer** - Built with Inno Setup, not malware
2. **PNG icons** - High entropy resources are valid compressed PNG images
3. **Unsigned** - No digital signature (common for smaller software vendors)
4. **TLS callbacks** - Present (anti-debug, common in Delphi apps)
5. **Standard APIs** - All imports are normal for an installer

---

## Verdict

**BENIGN** - This is a legitimate software installer for "Balloons" by EOS MIST LTD. The MDE (Microsoft Defender for Endpoint) alert was a false positive.

---

## Status

- [x] Static analysis
- [x] Resource extraction
- [x] Verification (Inno Setup installer)
- [ ] Dynamic analysis (optional - low risk)
