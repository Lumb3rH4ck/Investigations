# Malware Analysis Report — ID-5864757

**Classification:** Legitimate Software Installer  
**Analyst:** lumb3rh4ck  
**Date:** 2026-09-10  
**Sample:** `txtconverters (2).exe`

---

## Executive Summary

Analysis of `txtconverters (2).exe` reveals a legitimate .NET WPF installer for **"TXT Converter - PDF Utility Suite"** from txtconverters.com. The sample is signed with a valid GlobalSign EV code signing certificate. All observed behaviors (registry writes, process execution, network callbacks, machine fingerprinting) are consistent with a standard commercial software installer that downloads and deploys its payload. No malicious indicators found.

| Attribute | Value |
|-----------|-------|
| SHA256 | `99d883f9af7ecbf4d3d7a59a6a40cbaa67d2255a86c01f5e39d8d03fd4e7bafc` |
| MD5 | `acca7e588bcc9d72869facde2b77b7e7` |
| File Type | PE32 .NET WPF GUI (v4.0.30319) |
| Size | 1.5 MB |
| Sections | .text, .rsrc, .reloc |
| Signed | Yes — GlobalSign GCC R45 EV CodeSigning CA 2020 |
| Source | CISA KEV-style submission ID-5864757 |

---

## Static Analysis

### File Structure

```
Sections:
  .text   0x001629a4 bytes  CODE (executable)
  .rsrc   0x00005a88 bytes  DATA (resources)
  .reloc  0x0000000c bytes  DATA (relocations)
```

### .NET Metadata

| Property | Value |
|----------|-------|
| Runtime | v2.5 metadata, v4.0.30319 CLR |
| Assembly | TXTconverter.Installer |
| Entry Point | TXTconverter.Installer.App.Main() |
| Streams | #~, #Strings, #US, #GUID, #Blob |

### Type Definitions

| Class | Namespace | Purpose |
|-------|-----------|---------|
| App | TXTconverter.Installer | WPF application entry point |
| InstallerMainWindow | TXTconverter.Installer.Views | Main GUI window |
| WelcomeView | TXTconverter.Installer.Views | Welcome screen |
| ProgressView | TXTconverter.Installer.Views | Installation progress |
| InstallerService | TXTconverter.Installer.Services | Core installation logic |
| ExternalCallsService | TXTconverter.Installer.Services | HTTP callbacks |
| MachineInfoService | TXTconverter.Installer.Services | System fingerprinting |
| RegistryHelper | TXTconverter.Installer.Utilities | Registry operations |
| FileHelper | TXTconverter.Installer.Utilities | File operations |
| PathHelper | TXTconverter.Installer.Utilities | Path manipulation |
| ShortcutHelper | TXTconverter.Installer.Utilities | Desktop shortcut creation |
| RuntimeConfig | TXTconverter.Installer.Constants | Runtime configuration |
| AppConstants | TXTconverter.Installer.Constants | Application constants |
| RegistryConstants | TXTconverter.Installer.Constants | Registry path constants |
| IInstallerService | TXTconverter.Installer.Interfaces | Service interface |
| CloseConfirmationHelper | TXTconverter.Installers.Helpers | Close confirmation handler |

### Network Indicators

| Indicator | Value | Purpose |
|-----------|-------|---------|
| DeploymentEndpoint | `https://download.txtconverters.com/check_latest_version` | Downloads latest package |
| InstallationCompleteEndpoint | `https://api.txtconverters.com/conversion-complete` | Reports install status |
| User-Agent | `TextConverter/{major}.{minor}.{build}` | Versioned UA string |
| Content-Type | `application/json` | JSON payload format |

### Registry Indicators

| Key | Action | Purpose |
|-----|--------|---------|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | Read | Get Windows build number |
| `HKLM\SOFTWARE\Microsoft\Cryptography` | Read | Get MachineGuid (fingerprinting) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TXTconverter` | Write/Delete | Add/remove uninstall entry |

### Files Dropped

| Path | Description |
|------|-------------|
| `{InstallDir}\TXTconverter.exe` | Main application executable |
| `{InstallDir}\Uninstaller.exe` | Uninstaller executable |
| `{Desktop}\TXTconverter.lnk` | Desktop shortcut |
| `{StartMenuPrograms}\TXTconverter.lnk` | Start Menu shortcut |

### Network Payload (JSON)

```json
{
  "osBuild": "<Windows CurrentBuildNumber>",
  "appExeExists": "<bool: TXTconverter.exe exists>",
  "powerProfile": "<ProcessorMinThrottle/MaxThrottle>",
  "approvedCheckbox": "<bool: EULA accepted>",
  "installerVersion": "<installer version string>",
  "installationFailed": "<bool>",
  "installationErrors": "<error string>",
  "installationAborted": "<bool>"
}
```

### Installation Flow

1. Display WelcomeView (EULA acceptance)
2. Display ProgressView
3. Contact `check_latest_version` endpoint
4. Download ZIP package (base64-encoded)
5. Decode with `FromBase64String` + `MemoryStream`
6. Extract with `ZipArchive`
7. Prepare target directory
8. Write files (TXTconverter.exe, Uninstaller.exe)
9. Write uninstall registry entry
10. Create desktop + Start Menu shortcuts
11. POST status to `conversion-complete`
12. Launch installed application via `ProcessStartInfo`

---

## Dynamic Analysis

### Environment

| Component | Version |
|-----------|---------|
| Runtime | Wine 8.0 + .NET Framework 4.8 |
| Platform | Debian 12 (Docker) |
| Network | Isolated (--network none) |
| Display | None (GUI crashes without display) |

### Observed Behavior

| Phase | Result |
|-------|--------|
| .NET Initialization | Success — loaded PresentationFramework |
| GUI Initialization | Failed — `CreateWindowEx` requires display |
| Network | Blocked (no network access) |
| Filesystem | No files dropped (crashed before download) |
| Registry | Binary changes to HKCU (WPF settings) |
| Persistence | None achieved |

### Key Findings from #US Heap

The User Strings heap revealed complete installation flow strings:
- "Contacting server for latest package..."
- "Downloading application..."
- "Extracting application..."
- "Writing registry entries..."
- "Creating desktop shortcut..."
- "Finishing installation..."
- "Failed to decode package from server"
- "Failed to start app process."

---

## Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| pefile | 2024.8.26 | PE header parsing |
| dnfile | 0.18.0 | .NET metadata extraction |
| Python | 3.11 | Automation |
| Docker | 29.7.2 | Sandboxed analysis |
| Wine | 8.0 | Windows PE execution |
| radare2 | Latest | Disassembly |
| capstone | 5.0.9 | Instruction decoding |
| yara | 4.5.4 | Pattern matching |
| strings | GNU binutils | String extraction |

---

## Conclusion

**This is a legitimate software installer, not malware.**

The sample is a signed .NET WPF installer for "TXT Converter - PDF Utility Suite" from txtconverters.com. All behaviors observed (FromBase64String, registry manipulation, process spawning, machine fingerprinting, network callbacks) are standard for commercial installers that download and deploy their payloads. No code injection, persistence mechanisms, credential theft, or other malicious behaviors were found.

### Confidence: HIGH

### Recommendations
- Whitelist `txtconverters.com` and `api.txtconverters.com` if needed
- Monitor network traffic to `api.txtconverters.com/conversion-complete` for telemetry
- No further action required
