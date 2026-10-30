# Investigation: ID-5966877 — balloons.exe

**Date:** 2026-10-30  
**Analyst:** Lumb3rH4ck  
**Classification:** ⚠️ HIGHLY SUSPICIOUS  
**Verdict:** Do NOT execute on host system. Dropper/RAT/Credential stealer indicators.

---

## File Info
- **Filename:** balloons.exe
- **Size:** 2,701,712 bytes (2.6 MB)
- **Type:** PE32 Windows GUI (32-bit)
- **Compiler:** Embarcadero Delphi (VCL framework)
- **Image Base:** 0x400000
- **Entry Point:** RVA 0xB1E60
- **Sections:** 11
- **Code Signing:** GlobalSign + DigiCert (embedded in .rsrc)

---

## Anti-Analysis Detection

### Anti-VM (Score: 10/10 — VM DETECTED)
- VMware MAC: `00:50:56` (2 hits)
- Parallels MAC: `00:1c:42`
- QEMU/KVM MAC: `52:54:00`
- 33 CPUID checks throughout .text

### Anti-Sandbox (Score: 10/10 — SANDBOX DETECTED)
- Username checks: Admin, test, Test, user, User (16 indicators)

### Anti-Debug (17 indicators)
- Timing: GetTickCount (x4), GetTickCount64, QueryPerformanceCounter, QueryPerformanceFrequency, GetSystemTime, GetLocalTime
- Debug APIs: GetLastError, SetLastError, OpenThread, SuspendThread, ResumeThread
- INT3 breakpoints: cluster of 6 at 0x08A7C9
- Debugger scans: kernel32.dll references

---

## Capabilities

### Process Injection
- `VirtualAlloc` — allocate memory in target process
- `VirtualProtect` — change memory permissions (RX → RWX)
- `CreateProcessW` — spawn suspended process for hollowing
- `GetProcAddress` + `LoadLibraryA` — dynamic API resolution (evades static IAT analysis)

### Network
- `winhttp.dll` — HTTP requests (C2 communication)
- `UrlMon` — URLDownloadToFile (payload fetching)

### Persistence / Evasion
- Mutex: `AppMutex`, `SetupMutex` (singleton enforcement)
- 8,066 `int 0x80` syscall patterns (Linux/embedded shellcode compatibility)
- TLS callbacks (anti-debug before main entry)

---

## Packer Detection
- **Verdict:** NOT PACKED (0/10)
- Section entropy: .text=6.38, .rsrc=7.40 (high — embedded encrypted payload)
- All sections have normal names and sizes

---

## YARA Matches
| Severity | Rule | Address | Detail |
|----------|------|---------|--------|
| CRITICAL | process_injection | 0x0B6180 | VirtualAlloc |
| MEDIUM | anti_analysis | 0x072D87 | GetTickCount |
| MEDIUM | anti_analysis | 0x072DA5 | GetTickCount |
| MEDIUM | anti_analysis | 0x0B60BA | GetTickCount |

---

## Embedded Content
- **PNG icons/images** in .rsrc (standard Delphi resources)
- **X.509 code-signing certificates** (GlobalSign Root R3, GlobalSign Code Signing R45, DigiCert Trusted G4, DigiCert Assured ID)
- **High entropy .rsrc (7.40)** — likely contains encrypted secondary payload or configuration

---

## Strings of Interest
```
AppMutex
SetupMutex
DefaultUserInfoName
contact@eosmistops.com
winhttp.dll (loadFrom: %SystemRoot%\system32\)
```

---

## Threat Assessment

This executable exhibits characteristics consistent with:

1. **Dropper/Installer** — Delphi GUI wrapper, embedded payload in .rsrc
2. **Remote Access Trojan (RAT)** — Anti-VM/sandbox, network capability, process injection
3. **Credential Stealer** — Mutex singleton, anti-analysis, dynamic API resolution

The extensive anti-analysis (VM + sandbox + debug) combined with process injection APIs and network capability strongly suggests this is **not** a legitimate application.

---

## Recommendations
- ❌ Do NOT execute on host or any production system
- 🧪 If dynamic analysis needed: use `deob-sandbox` Docker container
- 🔍 Extract .rsrc for embedded payload analysis (entropy 7.40)
- 📡 Monitor network for C2 indicators if executed in sandbox

---

## Tools Used
- `triage.py` — Auto-detect: Type=pe
- `detect_packer.py` — NOT PACKED (0/10)
- `detect_antidebug.py` — 17 indicators
- `detect_antivm.py` — VM DETECTED (10/10)
- `detect_sandbox.py` — SANDBOX DETECTED (10/10)
- `deob_shellcode.py` — 8,066 syscalls
- `yara_scan.py` — 4 matches (1 critical, 3 medium)
- `report_gen.py` — Comprehensive report
