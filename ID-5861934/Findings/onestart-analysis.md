# Analysis: OneStart (1).exe

**File:** `MDE_File_Sample_6b62cf170344cc96763037c89fd4da9be5654a7a/OneStart (1).exe`
**Date:** 2026-09-09
**Analyst:** lumb3r

---

## Summary

**PUP/PUA (Potentially Unwanted Program)** — Browser installer/dropper for "OneStart Browser" by OneStart Technologies LLC. Not malware, but uses deceptive distribution tactics (fake PDF utility landing pages, pre-checked options to hijack browser defaults, background persistence). Flagged by MDE for unwanted behavior.

---

## File Information

| Property | Value |
|----------|-------|
| Type | PE32 executable (GUI) Intel i386, Mono/.Net assembly |
| Size | 461,424 bytes |
| MD5 | 59ccf747e93dae15c5af5d037b763bfe |
| SHA256 | 430c783801d2e30c314c76f379ed28f98c540f530f309a95c542ae68043d78b1 |
| .NET Version | v4.0.30319 (.NET Framework 4.8) |
| Assembly | OneStart, Version=6.0.32.0 |
| Timestamp | 2717155353 |
| Digital Signature | **Yes** — DigiCert Trusted G4 Code Signing |

---

## Product Information

| Field | Value |
|-------|-------|
| **Company** | OneStart Technologies LLC (Delaware) |
| **Product** | OneStart Browser Installer |
| **Version** | 6.0.32.0 |
| **Copyright** | OneStart.ai 2025 |
| **Framework** | WPF (.NET 4.8) |

---

## Sections

| Section | Virtual Address | Raw Size | Entropy | Notes |
|---------|----------------|----------|---------|-------|
| .text | 0x00002000 | 0x00042400 | 5.69 | .NET IL code |
| .rsrc | 0x00046000 | 0x0002ba00 | 4.61 | Resources (images, XAML) |
| .reloc | 0x00072000 | 0x00000200 | 0.10 | Relocations |

**Full file entropy:** 5.4049/8.0

---

## .NET Metadata

| Property | Value |
|----------|-------|
| Metadata Version | 1.1 |
| Streams | 5 (#~, #Strings, #US, #GUID, #Blob) |
| TypeDef | 40 types |
| Method | 267 methods |
| Field | 179 fields |
| Assembly References | 10 |
| Custom Attributes | 221 |

---

## Key Classes & Components

| Class/Namespace | Purpose |
|-----------------|---------|
| `InstallerWpfApp` | Main WPF application |
| `InstallerWpfApp.MainWindow` | Main installer window |
| `InstallerWpfApp.Page1c`–`Page6a` | 6 installer page variants (A/B testing) |
| `InstallerWpfApp.Source.Analytics` | Telemetry/logging |
| `InstallerWpfApp.Source.Config` | Configuration management |
| `InstallerWpfApp.Source.PageNavigation` | Page navigation logic |
| `InstallerWpfApp.Source.DispatcherHelper` | Window management |

---

## Network Indicators

| URL | Purpose |
|-----|---------|
| `https://event.onestartapi.com/` | Analytics/telemetry endpoint |
| `https://resources.onestartapi.com/UpdaterSetup_134.0.6998.112.exe` | Browser payload download |
| `https://onestart.ai/` | Main website |
| `https://onestart.ai/terms-of-use/` | Terms of service |
| `https://onestart.ai/privacy-policy/` | Privacy policy |
| `https://onestart.ai/uninstall/` | Uninstall page |

---

## Telemetry Events

| Event Name | Description |
|------------|-------------|
| `WpfInstallStart` | Installer started |
| `WpfInstallAccept` | User clicked "Accept and Install" |
| `WpfChangeInstallPath` | Installation path changed |

---

## Behavioral Analysis

### Installation Flow
1. WPF installer displays one of 6 page variants (different messaging per campaign)
2. User clicks "Accept and Install"
3. Installer downloads `UpdaterSetup_134.0.6998.112.exe` from `resources.onestartapi.com`
4. Executes via Google Omaha protocol: `--install --install-dir="..." --install-pref="..."`
5. Default install path: `C:\Users\Name\OneStart.ai`

### Dark Patterns / PUP Behaviors
- **Pre-checked "Import settings from your current browser"** — data hijacking
- **Pre-checked "Start with Windows"** — persistence
- **Pre-checked "Run in background for start-up boost and notifications"** — background execution
- **"Set as default browser"** option (hidden on some pages, visible on others)
- **Multiple page variants** — some emphasize "PDF tools" to disguise browser installation
- **Omaha protocol** — Google Update mechanism for silent auto-updates

### Installer Page Variants
| Page | Messaging |
|------|-----------|
| Page1c | Download progress + install |
| Page2a | "Unlock top-tier PDF solutions with ease using our powerful browser" |
| Page3a | Same as Page2a with layout variation |
| Page4a | "PDF File Converter" — emphasizes PDF conversion |
| Page5a | Welcome screen with PDF messaging |
| Page6a | Terms-focused with scrollable description |

---

## Digital Signature

| Field | Value |
|-------|-------|
| **Subject** | OneStart Technologies LLC |
| **Location** | Dover, Delaware |
| **Issuer** | DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 |
| **Valid From** | 2025-05-16 |
| **Valid To** | 2026-03-18 |
| **Serial** | 0e:10:48:03:01:77:14:ce:54:12:0e:10:48:03:01 |

---

## Key Findings

1. **PUP/PUA** — Browser installer using deceptive distribution tactics
2. **6 installer variants** — A/B testing for conversion optimization
3. **Downloads actual browser** — Chromium-based browser via Omaha protocol
4. **Telemetry** — Tracks install start, accept, and path changes
5. **Dark patterns** — Pre-checked options for browser hijacking and persistence
6. **Code signed** — Valid DigiCert signature (certificate may be expired)
7. **No malicious code** — The installer itself is not malware, but the distribution method is unwanted

---

## Verdict

**PUA (Potentially Unwanted Application)** — This is a browser installer that uses deceptive practices to install the OneStart Browser. The installer:
- Disguises browser installation as a PDF utility
- Pre-opts users into browser data import, startup persistence, and background execution
- Uses Google Omaha for silent installation and auto-updates

Not malware, but warrants MDE alert due to unwanted bundling/hijacking behavior.

---

## Payload Analysis: UpdaterSetup_134.0.6998.112.exe

### Overview
The installer downloads this payload from `https://resources.onestartapi.com/UpdaterSetup_134.0.6998.112.exe`. It is a **modified Google Chrome Updater** (Omaha protocol) rebranded as "OneStartUpdater".

### Payload File Info

| Property | Value |
|----------|-------|
| Type | PE32+ executable (GUI) x86-64 |
| Size | 8,025,200 bytes (8 MB) |
| MD5 | d4b848ac70b590ae1bbd0a6bb89d1eba |
| SHA256 | d58d35bba208867cc5b4a1b593c981d210178ab6cf480f49dd564f4108342d3e |
| Sections | 13 |
| Entropy | 7.09/8.0 |
| Signed | Yes (DigiCert) |

### Nested Archive Structure
The payload contains a **7z archive** embedded in its `.rsrc` section, which itself contains another 7z archive (`updater.7z`), which contains:

| File | Size | Description |
|------|------|-------------|
| `bin/updater.exe` | 6,589,040 bytes | Inner Chrome updater executable |
| `bin/uninstall.cmd` | 845 bytes | Uninstall script for OneStartUpdater |

### Inner Updater (updater.exe)

| Property | Value |
|----------|-------|
| Type | PE32+ executable (GUI) x86-64 |
| Size | 6,589,040 bytes |
| MD5 | 17b0a6ff85e3715fa43fa8b78acbef1a |
| SHA256 | 6ac1d9573257b52cbd3dbd997372e2270565e94ec8b390d51259e89e98faf2ef |
| Timestamp | 1727757852 (2024-10-01) |

### Chrome Updater Components (from debug strings)
The updater is built from Google's Chromium source tree (`chrome/updater/`):

- `activity.cc` / `activity_impl_win.cc` — Activity tracking
- `app_server.cc` / `app_server_win.cc` — COM server
- `check_for_updates_task.cc` — Update checking
- `installer.cc` / `installer_api.cc` — Installation logic
- `dm_client.cc` / `dm_message.cc` — Device management
- `policy_fetcher.cc` / `policy_manager.cc` — Policy management
- `update_service_impl.cc` — Update service
- `task_scheduler.cc` — Scheduled tasks
- `uninstall.cc` — Uninstallation
- `update_usage_stats_task.cc` — Usage statistics

### Payload Network Indicators

| URL | Purpose |
|-----|---------|
| `https://updates.onestartapi.com/onestart/service/update2/json` | Omaha update endpoint |
| `https://event.onestartapi.com` | Analytics |
| `https://onestartapi.com` | API base |
| `https://resources.onestartapi.com/assets/` | Asset downloads |
| `https://m.google.com/devicemanagement/data/api` | Google device management |

### Payload Imports (Suspicious APIs)
- **ADVAPI32.dll**: `CreateProcessAsUserW`, `CreateProcessWithTokenW`, `CryptEncrypt`, `RegSetValueExW`
- **KERNEL32.dll**: `CreateProcessW`, `VirtualAlloc`, `VirtualProtect`, `ConnectNamedPipe`
- **WINHTTP.dll**: Full HTTP stack (`WinHttpOpen`, `WinHttpConnect`, `WinHttpSendRequest`)
- **WS2_32.dll**: Raw socket API (`socket`, `connect`, `send`, `recv`)
- **SHELL32.dll**: `ShellExecuteExW`
- **CRYPT32.dll**: Certificate decoding/validation

### Uninstall Script (`uninstall.cmd`)
```batch
rem Validates path contains \OneStart.ai\OneStartUpdater
rem Retries deletion 15 times with 1s delays
rem Removes parent directory if --remove-dir specified
```

---

## Dynamic Analysis

### Attempts
1. **Wine (Docker)**: Created `wine-sandbox:latest` image with Wine 8.0. The .NET WPF installer requires .NET Framework 4.8 and an X server. Wine partially initialized but could not load `kernel32.dll` due to read-only filesystem constraints in the sandbox.
2. **Xvfb + Wine**: Attempted virtual framebuffer but Wine registry writes failed on tmpfs.

### Limitations
- The sandbox environment (`deob-sandbox:latest`) is read-only with no Wine/Mono
- Building a custom Wine image works but .NET Framework installation requires Windows components
- Full dynamic analysis requires a Windows VM or native execution

### Recommended Dynamic Analysis Setup
- Windows 10/11 VM with network isolation
- Process Monitor (ProcMon) for file/registry tracking
- Wireshark for network capture (filter: `host onestartapi.com`)
- API hooking with Frida or Detours for Omaha protocol analysis

---

## Status

- [x] Static analysis
- [x] .NET metadata parsing
- [x] String extraction
- [x] Network indicator identification
- [x] Payload analysis (UpdaterSetup.exe)
- [x] Nested archive extraction (7z → updater.7z → updater.exe + uninstall.cmd)
- [x] Chrome updater component identification
- [~] Dynamic analysis (partial — Wine attempted, requires Windows VM)
- [ ] Behavioral monitoring (requires Windows VM)
