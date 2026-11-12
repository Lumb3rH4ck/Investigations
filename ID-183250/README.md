# Malware Analysis Report — UFile / UFileSetup.exe (FAIRLIE LIMITED EV-signed dropper)

**Analyst:** opencode (automated RE analysis)
**Date:** 2026-11-12
**Sample:** `ID-183250.zip` → `ufile.exe` (internal name `UFileSetup.exe`)
**Verdict:** **MALICIOUS — EV-signed .NET dropper / downloader for a server-controlled payload (UFile "PDF utility" chain)**
**Confidence:** High (valid EV signature, full IL reconstruction, live payload captured from the C2)

---

## 1. Executive Summary

- **Verdict: MALICIOUS** (adware / browser-search-hijacker delivery chain; EV-signed dropper/installer).
- **Confidence: HIGH** — the sample is a known, publicly analyzed binary (exact SHA-256 match) and its behavior was fully reconstructed from IL.
- The archive contains a single .NET WPF installer, `ufile.exe` (internal name `UFileSetup.exe`), branded as the "UFile" PDF utility. It is signed with a valid GlobalSign **EV code-signing certificate** belonging to **FAIRLIE LIMITED** (Cyprus). On execution it shows a fake setup wizard, downloads a ZIP payload from `https://alyclick.com/get_u`, extracts it to `%LOCALAPPDATA%\Programs\UFile`, creates Desktop/Start-Menu shortcuts, writes an uninstall registry entry, copies an uninstaller, launches the installed `UFile.exe`, and reports success/failure to `https://alyclick.com/u_flow_done`.
- The installed `UFile.exe` is a separate stage (not contained in this archive). With approval, the live `POST /get_u` was replayed and the real payload captured (4.3 MB `UFile.zip`). The **current** build (v21.3.0.5, SHA-256 `b7e6d1bc…`) is a signed PDF utility with no observed malicious code; an earlier build described in public analysis (`6a915d4c…`) contained the `DeployService` that retrieves an encrypted `AutomationPref` stage from `api.catchasail.com` and hijacks Chrome's default search provider. The payload is server-controlled and can change at any time. This first-stage sample is the **initial signed dropper** of that chain.

## 2. Sample Metadata

| Field | Value |
|-------|-------|
| Archive | `ID-183250.zip` (1,119,556 bytes, password-protected, deflate) |
| Filename(s) | `ufile.exe` (extracted); internal/original name `UFileSetup.exe` |
| Size | 1,137,520 bytes (0x115B70) |
| MD5 | `3f8c1e6ce632f46eb4f47454a98526a5` |
| SHA1 | `dddc244162683442b667b33f2e65f75675dd74ac` |
| SHA256 | `6bb5a82d9acd6d846d5ebd928ec8eec8c0ac67cf7a76d3c6b0e225169fd382e3` |
| SHA512 | `e45587dd86c980495bc971f069ac91daab69e34335acfa39bbec49a6ebe986edc78df35f6b59217bcc73be3c1a009c524b206e3a648d2eaeb3a645360ee62b35` |
| File type / format | PE32 executable, .NET CLR 4.0 (mscoree `_CorExeMain`), WPF GUI subsystem (2) |
| Architecture | x86 (Machine 0x14C), 32-bit |
| Sections | `.text` (entropy 7.99), `.rsrc` (7.56), `.reloc` (0.10); no packer/overlay beyond Authenticode cert table |
| Entry point | RVA 0x112222; .NET entry-point token 0x06000007 (`Main`) |
| Compile timestamp | 2026-08-20 13:33:27 UTC (1787232807) |
| Packer / protector | None (managed .NET, not obfuscated; metadata fully readable) |
| Languages / frameworks | C# / .NET Framework 4.x, WPF (PresentationFramework, PresentationCore, WindowsBase), System.IO.Compression |
| Assembly | `UFileSetup.exe`, MVID `81b3c52f-ed3b-4412-ad48-dd55146cd86b`, version 19.0.7.8 |
| Version resource | FileDescription "UFile Setup", ProductName "UFile", FileVersion/ProductVersion 19.0.7.8, Copyright © 2024 |
| Digital signature | Authenticode, **valid** (verified locally with `signify`), EV code signing |
| Signer subject | `CN=FAIRLIE LIMITED, O=FAIRLIE LIMITED, E=myro@fairlie.xyz`, 31 Oikonomou Konstantinou, Strovolos, Nicosia, Cyprus; org serial HE424676; jurisdiction CY |
| Issuer | `GlobalSign GCC R45 EV CodeSigning CA 2020` (GlobalSign nv-sa, BE), chain to GlobalSign Code Signing Root R45 / Root CA R3 |
| Cert serial | `641DA2847A22364E02640605` |
| Cert thumbprint (SHA1) | `B486151303A89351C7AD52775C7A6D2B2E505E41` |
| Cert thumbprint (SHA256) | `927C81B5DE528F8FE8EB60B285D4F831BCE7ED295208BC42280F95033B82C9A9` |
| Cert validity | 2026-06-08 09:53:49 UTC → 2027-06-09 09:53:49 UTC |
| Signing time | 2026-08-20 13:37:00 UTC (PKCS#7 `signingTime`), timestamp responder DigiCert SHA256 RSA4096 Timestamp Responder 2025 |
| Source / origin | https://github.com/Lumb3rH4ck/Investigations/blob/main/ID-183250.zip |

### Captured payload (from live C2)

Controlled egress was approved and the live `POST https://alyclick.com/get_u` was replayed, returning the exact ZIP the installer downloads.

| Field | Value |
|-------|-------|
| Captured ZIP | `UFile.zip`, 4,305,945 bytes, SHA256 `134d4217051d9e98e63604d26f934500054fb55c60c82a98a6c343030665e2f1` |
| HTTP | `200`, `Content-Type: application/zip`, `Content-Disposition: attachment; filename="UFile.zip"` |
| `UFile.exe` | 1,187,696 bytes, SHA256 `b7e6d1bcd44f55c6f4586e2ccc02e846b53fae54cffc31e389a71db0a8aa0231`, MD5 `4edeae4855a0a37772f0d2b880815377` |
| `UFile.exe` type | x64 PE32+ .NET 4.x WPF app, version 21.3.0.5, compile 2026-08-18 06:38:33 UTC, signed FAIRLIE LIMITED (Authenticode **valid**) |
| `UFileUninstaller.exe` | 25,968 bytes, SHA256 `a2041e48000177411bc3c0397de637a8bc049601c081f3cf72a4a93747ab67eb`, x86 .NET, signed FAIRLIE LIMITED (Authenticode **valid**) |
| `Tools/qpdf/*` | QPDF 3.x library + Microsoft-signed VC++ runtime DLLs; qpdf30.dll unsigned, contains standard QPDF/OpenSSL symbols, no suspicious network/execution API observed |

## 3. Static Analysis

- **File format details**: PE32, 3 sections, high entropy in `.text` (normal for .NET), `.rsrc` holds 5 PNG icons, a 5-entry icon group, VERSIONINFO (19.0.7.8), and an `asInvoker` application manifest. The Authenticode certificate table sits at file offset 0x112C00, size 0x2F70, ending exactly at EOF (no separate overlay).
- **Imports**: only `mscoree.dll!_CorExeMain` (managed entry). All real capability is in the .NET metadata/method bodies.
- **Notable strings / URLs**:
  - `https://alyclick.com/get_u` (payload download, POST JSON)
  - `https://alyclick.com/u_flow_done` (install/abort telemetry, POST JSON)
  - `/vid=`, `/ch=`, `/so=` command-line parameters
  - `%LOCALAPPDATA%\Programs\UFile` (InstallDir = `GetFolderPath(28)` + `Programs\UFile`)
  - `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UFile`
  - `UFile.exe`, `UFileUninstaller.exe`, `UFile.lnk`
  - `UFile.Setup`, `UFile.Setup.Core`, `UFile.Setup.Views` namespaces
- **API / capability mapping**:
  - Networking: `WebRequest.Create`, `HttpWebRequest`, POST, `GetRequestStream`, `GetResponse`, `GetResponseStream`, timeouts 60 s / 10 s.
  - Cryptography: `SHA256.Create`, `ComputeHash`, `Encoding.UTF8` (machine-ID hash).
  - Filesystem: `ZipArchive`, `ZipArchiveEntry.ExtractToFile`, `File.Copy`, `Directory.CreateDirectory`, path-traversal check on ZIP entries.
  - Process: `Process.GetProcessesByName("UFile")`, `Process.MainModule.FileName`, `Process.Start`.
  - Registry: `Registry.CurrentUser.CreateSubKey("...\\Uninstall\\UFile")`, `SetValue` for DisplayName/UninstallString/InstallLocation/Publisher/DisplayVersion/DisplayIcon/NoModify/NoRepair.
  - Shell: `IShellLinkW` COM interop for shortcuts.
  - Evasion / fingerprinting: `GetVolumeInformationW` (C: volume serial), `CreateFileW`+`GetFileTime` on `C:\Windows` (install timestamp), `GetPwrCapabilities` (power profile bitmask), `GetProcessesByName`.
- **YARA / signature matches**: local rules `UFile_Installer_Generic` and `FAIRLIE_EV_Cert_Indicators` both match. No AV signatures run locally (offline).

## 4. Packing & Obfuscation

- No packer/crypter. The binary is a normal, unobfuscated managed .NET assembly; all type/method names and IL are intact.
- No dynamic resolution or encrypted blobs in this first stage. (The second stage retrieved at runtime is encrypted, but that is a separate sample.)
- The high entropy (7.98) is typical of .NET metadata/IL, not packing.

## 5. Disassembly / Decompilation Findings

Method bodies were disassembled from IL; key logic:

- **`Main` / `OnStartup`**: WPF app startup; caches `GetMachineGuid()` in a static field and parses `/vid=`, `/ch=`, `/so=` args into `CommandLineArgs`.
- **`SetupOrchestrator.Execute`** (RVA 0x2108):
  1. Progress 5 % "Connecting to server..." → `EndpointReporter.DownloadPayload(progressCb)`.
  2. If ZIP bytes null/empty → progress 0 % "Transfer failed" → `SendInstallFinish(false,"download failed")`.
  3. `IsReRun()` (checks if `%LOCALAPPDATA%\Programs\UFile\UFile.exe` exists); if not rerun and `IsAppRunning()` → "Please close UFile and try again" → finish(false,"app running").
  4. Progress 72 % "Extracting files..." → `ExtractZipToDirectory(zip, InstallDir)` (path-traversal check via `StartsWith(installDir)`).
  5. Progress 85 % "Creating shortcuts..." → `CreateShortcuts()` (Desktop + Start Menu\Programs → `InstallDir\UFile.exe`).
  6. Progress 92 % "Configuring system..." → `WriteRegistryEntries()` (HKCU uninstall key) then `DeployUninstaller()` (copies `UFileUninstaller.exe` next to the app).
  7. Progress 100 % "Setup complete" → `SendInstallFinish(true,"")`; if app not already running → `LaunchApp()`.
  8. On exception → `SendInstallFinish(false,"failed")`. Cancellation path → `SendAbortFinish("aborted")` / `ReportCancellation()`.
- **`EndpointReporter.BuildDeployJson`** (RVA 0x2D04): builds `{"you_id":<machineGuid>,"build_os":<OS build>,"file_version":<assembly version>,"rerun":<bool>,"your_power":<powerProfile>}` and POSTs it to `https://alyclick.com/get_u`; the response stream is copied to a `MemoryStream` and returned as ZIP bytes.
- **`EndpointReporter.PostJson`** (RVA 0x2EC8): POSTs JSON to `https://alyclick.com/u_flow_done`; used by `SendInstallFinish` (`error_occurred`, `error_msg`) and `SendAbortFinish` (`closed_by_user=true`).
- **`MachineProfile.GenerateDeploymentChecksum`** (RVA 0x26E8): `you_id = SHA256( UTF8( volumeSerialUInt32.ToString() + "-" + windowsDirFileTime.ToString() ) )`; returns `""` if `ValidateSystemCompatibility` fails.
- **`MachineProfile.GetPowerProfile`** (RVA 0x2958): bitmask `(ProcessorThrottle>0)<<3 | (ThermalControl>0)<<2 | (SystemS3>0)<<1 | (LidPresent>0)`, formatted `"X"` — a hardware/VM fingerprint.
- **`SetupOrchestrator.IsAppRunning`** (RVA 0x2308): enumerates `GetProcessesByName("UFile")` and compares each `MainModule.FileName` to the full path of `InstallDir\UFile.exe` (OrdinalIgnoreCase).
- **UI (`ShellWindow`)**: WelcomePanel → ProgressPanel; `StartSetup` runs `Execute` on a background thread and marshals progress/closure via `Dispatcher.BeginInvoke`; closing the window before completion shows an exit overlay and reports `closed_by_user`.
- **C2 / protocol**: plain HTTPS POST with `Content-Type: application/json`, custom JSON (not a standard API). No TLS pinning, no user-agent customization observed (default .NET). The install callback is a one-shot `_finishSent` guard (Interlocked.CompareExchange).

### 5.1 Corroborating public analysis

Public analysis of the same SHA-256 (blog.lukeacha.com, 2026-10-30, "YAPA: UFile hides a Chrome Search Hijacker") shows the ZIP delivered by `alyclick.com/get_u` installs `UFile.exe` (SHA-256 `6a915d4c09939d9c2e872e84a0ebeaf3fd753af5029e2474b28065f61b2c1aaf`), which then retrieves an encrypted stage from `api.catchasail.com/u_session_grant` → `/u_bundle_acquire`, AES-CBC-decrypts it in memory (key = SHA256(install date), IV = MD5(current time), date string `yyyyMMddss`), and loads the 3.32 MB .NET assembly `AutomationPref` (SHA-256 `afcc8b57df4cdc503646fc593688be57e180961592381f9248f8d2d77183a42bc`) via `Assembly.Load`. That stage rewrites Chrome `Preferences`/`Secure Preferences` to set a server-supplied search provider (`catchasail.com/u_partner_cfg`, observed `trai.eepsearch.com`), kills/restarts Chrome, and reports to `catchasail.com/u_close_ping2`.

### 5.2 Captured payload analysis (current live build)

- `UFile.exe` (v21.3.0.5, x64 .NET WPF) is a **PDF utility** (split / convert / rotate via QPDF; Word interop). Full metadata dump shows 34 types / 317 methods and **no network, crypto, reflection-load, process-injection, or persistence APIs**. MemberRef scan found no `Http*`, `Web*`, `Assembly.Load`, `AES`, `MD5`, or `Process` usage. It is signed with the same FAIRLIE LIMITED EV certificate and the Authenticode signature verifies OK.
- `UFileUninstaller.exe` is a clean uninstaller: resolves `%LOCALAPPDATA%\Programs\UFile` from the HKCU uninstall key, deletes the Desktop and Start-Menu shortcuts, deletes the uninstall key, and removes the install directory (5 retries, 500 ms apart). No network or injection behavior.
- `Tools/qpdf/qpdf30.dll` (unsigned, 6.9 MB) contains standard QPDF and OpenSSL symbols (`QPDFJob`, `QPDFCrypto_openssl`, `compute_encryption_key`, etc.); the VC++ runtime DLLs are Microsoft-signed. No suspicious download/execution API was found.
- **Important discrepancy:** the build captured today (`b7e6d1bc…`, v21.3.0.5, compile 2026-08-18) does **not** contain the `DeployService` / `api.catchasail.com` logic described in the public analysis (build `6a915d4c…`). The campaign's second stage is therefore either rotated/A-B tested per victim, or was changed after the public report. The first-stage installer itself is unchanged and still malicious: it downloads and installs whatever the server returns.
- The `AddressOfEntryPoint = 0` / empty import table in `UFile.exe` is **normal for x64 C# assemblies** (the CLR loader stub is omitted on x64; Windows passes the image to the CLR via the COM descriptor). It is not an evasion trick.

## 6. Dynamic Analysis

- **Controlled network capture performed (approved):** the installer's exact request was replayed to the live server and the payload captured.
  - Request: `POST https://alyclick.com/get_u`, `Content-Type: application/json`, body `{"you_id":...,"build_os":...,"file_version":"19.0.7.8","rerun":"false","your_power":"0"}`.
  - Response: `HTTP/2 200`, `Content-Type: application/zip`, `Content-Disposition: attachment; filename="UFile.zip"`, 4,305,945 bytes.
  - Captured and analyzed in the sandbox (see §5.2).
- **Full Wine execution not performed:** the analysis image ships Wine 8.0 but no .NET Framework 4.8 prefix, and the sample is a WPF GUI app; a `winetricks dotnet48` install plus Xvfb would be required. Static IL analysis already fully reconstructed the installer behavior, so dynamic execution was not necessary for the verdict.
- **Observed (static reconstruction) behavior timeline:** parse args → show WelcomePanel → user clicks Next → background thread runs `Execute` → POST fingerprint to `/get_u` → extract ZIP to `%LOCALAPPDATA%\Programs\UFile` → create Desktop + Start-Menu shortcuts → write HKCU uninstall key → copy `UFileUninstaller.exe` → POST result to `/u_flow_done` → launch `UFile.exe`.

## 7. Indicators of Compromise (IOCs)

**Network**
- `alyclick.com` — payload C2 (`/get_u`, `/u_flow_done`)
- `api.catchasail.com` — second-stage C2 (`/u_session_grant`, `/u_bundle_acquire`, `/u_status_digest`)
- `catchasail.com` — stage telemetry/config (`/u_install_start`, `/u_partner_cfg`, `/u_ext`, `/u_close_ping2`)
- `trai.eepsearch.com` — observed malicious search provider
- `quickbrowse.co` / `quickbrowse.co/search/?chnm3=w64cjbu7` — observed search intermediary
- `goyoufile.com` — observed UFile landing page (ad-driven)
- `homemade-gifts-made-easy.com` — observed advertising origin (not C2)

**Host**
- Install path: `%LOCALAPPDATA%\Programs\UFile\` (`UFile.exe`, `UFileUninstaller.exe`)
- Shortcuts: `Desktop\UFile.lnk`, `%APPDATA%\Microsoft\Windows\Start Menu\Programs\UFile.lnk`
- Registry: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UFile` (values DisplayName, UninstallString, InstallLocation, Publisher, DisplayVersion, DisplayIcon, NoModify=1, NoRepair=1)
- Filenames: `UFileSetup.exe` / `ufile.exe`, `UFile.exe`, `UFileUninstaller.exe`, `UFile.lnk`
- Stage constants observed in public analysis: `youfiles_id.txt`, `youfiles_backup`, `U_File`, hardcoded AppID `1786867306138976`

**Other**
- Certificate: FAIRLIE LIMITED, serial `641DA2847A22364E02640605`, SHA1 `B486151303A89351C7AD52775C7A6D2B2E505E41`, email `myro@fairlie.xyz`
- Hashes: installer SHA-256 `6bb5a82d9acd6d846d5ebd928ec8eec8c0ac67cf7a76d3c6b0e225169fd382e3`; captured payload ZIP SHA-256 `134d4217051d9e98e63604d26f934500054fb55c60c82a98a6c343030665e2f1`; current `UFile.exe` SHA-256 `b7e6d1bcd44f55c6f4586e2ccc02e846b53fae54cffc31e389a71db0a8aa0231`; current `UFileUninstaller.exe` SHA256 `a2041e48000177411bc3c0397de637a8bc049601c081f3cf72a4a93747ab67eb`; public-analysis installed `UFile.exe` SHA-256 `6a915d4c09939d9c2e872e84a0ebeaf3fd753af5029e2474b28065f61b2c1aaf`; recovered stage SHA-256 `afcc8b57df4cdc503646fc593688be57e180961592381f9248f8d2d77183a42bc` / MD5 `3290292ab1a2f512a1938fdfbb710720`

## 8. Capabilities & MITRE ATT&CK Mapping

| Observed capability | ATT&CK technique | Evidence |
|---------------------|------------------|----------|
| Downloads additional payload from C2 | T1105 Ingress Tool Transfer | `DownloadPayload` → POST `alyclick.com/get_u`, ZIP to memory |
| Application-layer web protocol for C2/telemetry | T1071.001 | HTTPS POST JSON to `/get_u`, `/u_flow_done` |
| System information discovery | T1082 | OS build, volume serial, Windows install time, power capabilities |
| Process discovery | T1057 | `Process.GetProcessesByName("UFile")` |
| Creates shortcuts (user-visible launch points) | T1547.001 (adjacent; not Run keys) | Desktop + Start Menu `.lnk` |
| Registry modification (uninstall metadata) | T1112 (adjacent) | HKCU `...\Uninstall\UFile` |
| Signed binary abuse / reputation bypass | T1553.003 (adjacent) | Valid GlobalSign EV cert for FAIRLIE LIMITED |
| Second-stage in-memory .NET load (separate sample) | T1027.002 / T1620 | public analysis of installed `UFile.exe` |
| Browser search hijack (separate stage) | T1547.001 / T1176 | Chrome `Preferences`/`Secure Preferences` rewrite |

## 9. Risk Assessment & Recommendations

- **Damage potential**: moderate-high. The installer is a server-controlled dropper: whatever the C2 returns gets installed, signed, and launched. The build captured on 2026-11-12 is currently a benign-looking PDF utility, but the same infrastructure previously served a Chrome-search-hijacker stage (`AutomationPref`) that rewrites Chrome preferences and can disable extensions. The payload can be swapped at any time.
- **Stealth**: high. WPF UI mimics a legitimate PDF utility; network traffic is simple HTTPS POST; machine ID and telemetry are plausibly deniable as analytics; the binary carries a valid EV signature.
- **Persistence**: limited in this stage (shortcuts + uninstall key). The installed app's persistence mechanisms were not observed in the current build.
- **Propagation**: user-driven install from ad redirects; no self-propagation.
- **Containment/eradication**:
  - Block `alyclick.com`, `catchasail.com`, `trai.eepsearch.com`, `quickbrowse.co`, `goyoufile.com` at DNS/proxy/EDR.
  - Quarantine `%LOCALAPPDATA%\Programs\UFile\`, delete the two `UFile.lnk` shortcuts and the `HKCU\...\Uninstall\UFile` key.
  - Report the FAIRLIE LIMITED EV certificate to GlobalSign (abuse@globalsign.com) and to Microsoft (SmartScreen/Defender) for revocation/blacklisting.
  - Reset Chrome `Preferences`/`Secure Preferences` (or the profile) and verify default search provider + extensions.
- **Detection opportunities**:
  - YARA: `UFile_Installer_Generic` and `FAIRLIE_EV_Cert_Indicators` rules (URLs, uninstall key, cert subject).
  - Network: POSTs to `/get_u` or `/u_flow_done` with JSON keys `you_id`, `build_os`, `your_power`, `file_version`.
  - Host: files under `%LOCALAPPDATA%\Programs\UFile\`, uninstall key, shortcuts, and the certificate thumbprint.
  - EDR: `GetProcessesByName("UFile")` + `MainModule.FileName` comparison pattern.

## 10. Artifacts & Reproduction

- Case directory: `case/ID-183250/` (local analysis workspace)
  - `samples/ID-183250.zip` — original archive (untouched, `:ro` in sandbox)
  - `samples/UFile_get_u.zip` — captured live payload
  - `output/extracted/ufile.exe` — extracted sample
  - `output/triage.txt`, `output/dotnet.txt`, `output/methods.txt`, `output/il.txt` — raw analysis output
  - `output/signature.der`, `output/signature_pkcs7.der`, `output/certs.pem`, `output/certs.txt`, `output/cert_0*.pem` — Authenticode material
  - `output/resources/` — extracted icons, version info, manifest
  - `output/capture/get_u_headers.txt`, `output/payload/` — captured payload and extracted files
  - `output/payload_triage_UFile.txt`, `output/dotnet_UFile.txt`, `output/il_uninstaller.txt` — payload analysis
  - `work/triage.py`, `work/dotnet_analyze.py`, `work/il_disasm.py`, `work/sig_extract.py`, `work/payload_triage.py`, `work/ufile_rules.yar`
- Sandbox: `re-full:latest` (Debian + Wine + dnfile/pefile/yara-python), `--network none --cap-drop ALL --security-opt no-new-privileges:true --user 1000:1000`.
- Reproduction: mount case dir, run `python3 work/triage.py`, `python3 work/dotnet_analyze.py`, `python3 work/il_disasm.py`; extract signature with `work/sig_extract.py` and parse with `openssl pkcs7 -inform DER`.

## 11. Appendix

- Open questions:
  - The actual second-stage `AutomationPref` assembly was not captured (the current payload does not fetch it); public analysis provides its hash and behavior.
  - Whether the FAIRLIE LIMITED certificate is fraudulently obtained, stolen, or a legitimate but abused EV cert was not determined.
  - Exact `alyclick.com` infrastructure/IPs and hosting were not resolved (Cloudflare front; no direct origin resolution).
- Recommended next steps:
  - Re-capture the payload periodically to detect rotation back to the malicious `DeployService` build.
  - Certificate abuse reporting and threat-intel correlation.
- External reference: "YAPA: UFile hides a Chrome Search Hijacker", blog.lukeacha.com, 2026-10-30 — same SHA-256, corroborates all first-stage findings and provides the second-stage chain.
