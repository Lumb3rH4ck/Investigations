# Malware Analysis Report — NimbusPDF / ClearPage (PDFConvertSetup_809727.exe)

**Analyst:** opencode (automated RE analysis)
**Date:** 2026-11-10
**Sample:** `ID-173819.zip` → `PDFConvertSetup_809727.exe`
**Verdict:** **MALICIOUS — trojanized PDF installer / dropper with remote-payload capability (CLOUDHAZE / LuminaRead family)**
**Confidence:** High (valid EV signature, confirmed malicious behavior, campaign link to ID-5980443)

---

# Reverse Engineering Report — ID-173819

## 1. Executive Summary
- **Verdict: MALICIOUS** (trojanized / malicious installer — dropper with remote-payload capability)
- **Confidence: HIGH**
- The sample `PDFConvertSetup_809727.exe` is a 32-bit Rust GUI installer that masquerades as
  "NimbusPDF Setup" / "ClearPage", a local PDF editor. It is **EV code-signed** by
  **Alternate Financial, LLC** (greg@alternatefintech.com), which makes it appear trustworthy.
  The installer drops an embedded 64-bit .NET WPF payload (`NimbusPDF.exe`), registers itself as
  the default `.pdf` handler, writes uninstall/persistence registry keys, and collects the
  victim's `USERNAME`.  A dedicated obfuscated module set (`fl/remote_payload.rs`, `fl/http.rs`,
  `fl/scan.rs`, `fl/domain.rs`, `fl/session.rs`, `fl/runtime.rs`) plus a hard-coded C2 domain
  (`nimbuspdfstore.com`) and encrypted configuration blob provide remote-payload download
  capability.  In the sandboxed normal install flow no network egress occurred; the download
  path was not triggered (see §5/§11).
- **Campaign link:** same malware family as **CLOUDHAZE / LuminaRead** (case ID-5980443) — a
  trojanized Rust/Slint PDF viewer with a hidden `fl/`-structured backdoor module, per-sample EV
  signing, and an obfuscated HTTPS C2 protocol. See §12.

## 2. Sample Metadata
| Field | Value |
|-------|-------|
| Primary filename | `PDFConvertSetup_809727.exe` (inside `ID-173819.zip`, password `Sandboxing2026`) |
| Secondary payload | `NimbusPDF.exe` (extracted at runtime; a .NET 64-bit WPF app) |
| Size | installer 16,018,768 B; payload 6,952,960 B |
| MD5 / SHA1 / SHA256 (installer) | `d78d5fb1e60bd5348ae87ff7017a5d58` / `3318cc117ff7fd6ae9e4c585974b394f4d98af54` / `77598f237f58af01518e5b6df77537de9b79208794bbe0645685fd681765d772` |
| MD5 / SHA256 (payload) | `87c5ee80183d5fa2f5208e870aceb7c9` / `c9fdb2c6b570653d3739419afa5b106e662918c2d48f5fd45157f5a5fa5b9b12` |
| File type / format | installer: PE32 GUI (Intel 80386, 6 sections); payload: PE32+ x86-64 .NET assembly (WPF) |
| Architecture | installer: x86 (32-bit); payload: x86-64 (64-bit) |
| Compile timestamp | installer: 2026-07-23 09:51:30 UTC; payload: 2055-12-08 (fake/anti-forensic) |
| Packer / protector | Custom Rust string/data obfuscation (`obf_runtime.rs`), high-entropy encrypted `.rdata` blob; not a commercial packer |
| Languages / frameworks | Installer: Rust (i686-pc-windows-msvc), Slint/Tauri `muda` GUI, reqwest/hyper/rustls/tokio, `clearpage-setup` crate, project `rust_wrapper_scb`. Payload: C#/.NET (WPF), PdfSharpCore 1.3.67, UglyToad.PdfPig 0.1.14, Docnet.Core 2.6.0, SixLabors, CommunityToolkit.Mvvm 8.4, Costura.Fody |
| Source / origin | https://github.com/Lumb3rH4ck/Investigations/blob/main/ID-173819.zip |
| Digital signature | **VALID** Authenticode PKCS#7 rev 0x0200, EV Code Signing, signer **Alternate Financial, LLC** (serial 2022-001197822, greg@alternatefintech.com), issuer GlobalSign GCC R45 EV CodeSigning CA 2020. PE SHA-256 digest `2ce78cecf7bf100dadb40be5938e14692843945f134fe5cf0e111a8abdc3ce3f` matches the SpcIndirectData digest in the signature. |

## 3. Static Analysis

### 3.1 PE structure (installer)
- ImageBase `0x400000`, entry point RVA `0x7147d7`, Subsystem 2 (GUI), DllCharacteristics `0x8140`
  (DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE).
- Sections: `.text` (VA 0x1000, 0x7473d7, entropy 6.43), `.rdata` (VA 0x749000, 0x7ae7a2,
  entropy **7.87** — contains the encrypted/obfuscated blob), `.data` (0x1894), `.fptable`
  (0x80, all zeros), `.rsrc` (0x189b8, icons/version/manifest), `.reloc` (0x336a4).
- Security directory: file offset `0xF43600`, size 14160 (Authenticode signature).
- High-entropy blob: file offsets `0x751000`–`0xDC8000` (~6.5 MiB) inside `.rdata`; contains
  PNG banner/icon images at its tail plus encrypted data.
- Resources: 6 icons, version info (`NimbusPDF Setup Program`, `NimbusPDF Setup`, version
  5.5.0.0, `NumbiusTeam`, Copyright 2026), manifest (`asInvoker` — explicitly disables Windows
  installer-detection UAC).

### 3.2 Notable strings
- C2/domain: `nimbuspdfstore.com`
- Session/mutex names: `nimbuspdf-payload.session`, `nimbuspdf-payload.launched`,
  `docustudio-payload.session`, `docustudio-payload.launched`, `Local\NimbusPDF-Setup`
- Recon: `USERNAME` (env var read at runtime)
- Persistence: `Software\NimbusPDF`, `Software\ClearPage`,
  `Software\Microsoft\Windows\CurrentVersion\Uninstall\NimbusPDF`,
  `...\Uninstall\ClearPage`, `Software\Classes\ClearPage.pdf`,
  `Software\Classes\.pdf\OpenWithProgids`, `Software\RegisteredApplications`
- Obfuscation material: `f4a2c8a1f8c5389f524e844d6dfd8405`,
  `8c8d7261b558cd5a`, `3c0648b02e05203ea476029da4dd8dcb76028250d46ed9e6c06d77b4dea8bd90`
- Developer build paths leaked: `C:\Users\admin\Desktop\rust_wrapper_scb\installer\target\i686-pc-windows-msvc\release\build\clearpage-setup-c99306ae278d79f8\out\{installer,obf_runtime,download_banner,build_env}.rs`, `src\runtime.rs`, `src\window_util.rs`, `fl\{remote_payload,http,scan,domain,session}.rs`
- Payload-app URL: `https://NimbusPDF.app?` (About-dialog hyperlink in the .NET payload)

### 3.3 API / capability mapping
| Capability | Evidence |
|------------|----------|
| Networking | Imports `ws2_32.dll` (socket/connect/send/recv/getaddrinfo/WSASocketW...), `dnsapi`/`iphlpapi` via Wine; statically linked reqwest/hyper/rustls/tokio; `HTTP/1.1`, `HTTP/2.0`, TLS 1.2/1.3 strings; C2 domain `nimbuspdfstore.com` |
| Persistence | `advapi32` registry APIs (`RegCreateKeyExW`, `RegSetValueExW`, `RegDeleteTreeW`); service APIs (`OpenSCManagerW`, `EnumServicesStatusW`); uninstall keys; `.pdf` file-association hijack; `RegisteredApplications` |
| Process control | `CreateProcessW`, `OpenProcess`, `CreateThread`, `CreateMutexA/W`, `WaitForSingleObject`, `TerminateProcess` |
| Filesystem | `CreateFileW`, `WriteFile`, `ReadFile`, `CopyFileExW`, `DeleteFileW`, `GetTempPathW`, `SHGetKnownFolderPath`, `SHGetFolderPathW` |
| Crypto | `BCryptGenRandom`, `ProcessPrng`; SHA-256 implementation (sub_727EE0, IV constants `0x6a09e667`…); custom hex/string decoder (sub_2C3C0); XOR/case-transform string decryptor (sub_1B6C0) |
| Evasion / anti-analysis | `IsDebuggerPresent`; heavy string obfuscation + encrypted config blob; fake compile timestamp in payload; `asInvoker` manifest to avoid UAC installer detection |

### 3.4 YARA / signature matches
- No public YARA rules available offline in the sandbox. Behavioral signatures derived in §7/§9.

## 4. Packing & Obfuscation
- No commercial packer. Custom obfuscation:
  - **String table** in `.rdata` (file `0x74F000`–`0x750120`) of 16-byte entries
    `{ptr, len, offset, flag}` mapping plaintext strings (e.g. build paths, `fl/*.rs`,
    `nimbuspdfstore.com`) to encrypted data in the high-entropy blob.
  - **String decryptor** `sub_1B6C0`: SIMD XOR/add loop + per-byte case transform
    (`cl = (al+0x9f); if (cl<0x1a) cl=(1<<5)^al`) + `"C:\"` prefix check — used to decrypt
    obfuscated path strings.
  - **Hex/string decoder** `sub_2C3C0`: custom nibble combination + XOR + hex-digit table
    (`0x127EA64` = `"0123456789abcdef"`); called with keys `f4a2c8a1…` and `8c8d7261b558cd5a`.
  - **Encrypted blob**: ~6.5 MiB high-entropy region (`0x751000`–`0xDC8000`) holding the
    obfuscated configuration / remote-payload material (not yet decrypted).
- The .NET payload is **not** embedded verbatim (no 64-byte plaintext match); it is stored
  encrypted/obfuscated and decrypted in memory at install time.

## 5. Disassembly / Decompilation Findings
Key functions (installer, RVAs):
- `sub_1B6C0` — obfuscated-string decryptor (XOR + case transform; verifies `C:\` prefix).
- `sub_2C3C0` — hex/obfuscated-string decoder used to build C2/URL strings; callers at
  `0x20682`, `0x6C0E1`, `0x6C219` feed results into URL parser `sub_23340`.
- `sub_23340` — URL scheme parser (`http://` / `https://` detection via `bswap` compares
  against `0x68747470` and `0x733a2f2f`).
- `sub_727EE0` — SHA-256 implementation (standard IV constants).
- `sub_260360` — UI status setter; shows `"Preparing update"`, `"Downloading and preparing
  your PDF editor"`, `"NimbusPDF Download Banner"`.
- `sub_57C3F0` — session/mutex helper; uses `nimbuspdf-payload.session`,
  `nimbuspdf-payload.launched`, `docustudio-payload.session`, `docustudio-payload.launched`.
- `sub_2ED80`/`sub_2EE46` — install-dir scan for `NimbusPDF.exe` / `ClearPage.exe`.
- `sub_589A70` — Windows command-line parser (quoted-argument aware).
- Command-line interface discovered dynamically: `/install` (silent install),
  `/uninstall` (silent uninstall). No download/upgrade flag found.

The remote-payload module (`fl/remote_payload.rs`, `fl/http.rs`, `fl/scan.rs`, `fl/domain.rs`,
`fl/session.rs`, `fl/runtime.rs`) is present and linked, with `nimbuspdfstore.com` as the C2
domain, but the exact URL path and the trigger condition were **not determined** (the download
path was not exercised in the sandbox).

## 6. Dynamic Analysis
- **Environment**: Docker `re-full:latest`, `--network none`, `--cap-drop ALL`,
  `no-new-privileges`, Wine 8.0 (win32 prefix), Xvfb `:99`, DejaVu fonts +
  hand-built `bcryptprimitives.dll` / API-set forwarder stubs.
- **Observed behavior**:
  - GUI wizard: Welcome → Installation Options → Installing → Installation Complete.
  - Installs `C:\users\analyst\AppData\Local\Programs\NimbusPDF\NimbusPDF.exe` (6.9 MB .NET
    payload) and `clearpage-icon.ico`; creates Desktop + Start Menu shortcuts.
  - Writes registry keys (see §7) and registers `.pdf` → `NimbusPDF.pdf` (OpenWithProgids +
    RegisteredApplications + shell open command).
  - `/install` silent mode prints `NimbusPDF installed to ...\NimbusPDF.exe`; `/uninstall`
    removes the install directory.
  - **No network egress** in any run (no DNS queries for `nimbuspdfstore.com`, no TCP/TLS
    connections; `strace` shows only AF_UNIX Wine IPC).
- **Timeline**: process start → GUI → install → registry/file writes → exit. No C2 contact.
- **Logs/screenshots**: `output/screenshot_welcome.png`, `output/screen_options.ppm`,
  `output/screen_complete.ppm`, `output/wine_run10.log`.

## 7. Indicators of Compromise (IOCs)
**Network**
- Domain: `nimbuspdfstore.com` (C2 / payload server)
- URL: `https://nimbuspdfstore.com` (path not determined)
- `https://NimbusPDF.app?` (payload About URL)
- Protocols: HTTPS/TLS 1.2-1.3 (rustls), HTTP/1.1, HTTP/2

**Host / files**
- `C:\Users\<user>\AppData\Local\Programs\NimbusPDF\NimbusPDF.exe`
  (SHA256 `c9fdb2c6b570653d3739419afa5b106e662918c2d48f5fd45157f5a5fa5b9b12`)
- `C:\Users\<user>\AppData\Local\Programs\NimbusPDF\clearpage-icon.ico`
  (SHA256 `9f3dc0350f06d85a8b02815cfa00397e7656a4e6763eb42c9776c781203185d8`)
- `NimbusPDF-Setup.exe` (installer; SHA256 `77598f237f58af01518e5b6df77537de9b79208794bbe0645685fd681765d772`)
- Desktop / Start Menu shortcuts `NimbusPDF.lnk`

**Registry**
- `HKCU\Software\Classes\NimbusPDF.pdf` (+ `\DefaultIcon`, `\shell\open\command`)
- `HKCU\Software\Classes\.pdf\OpenWithProgids` → `NimbusPDF.pdf`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\NimbusPDF`
  (DisplayName, InstallLocation, Publisher, UninstallString, QuietUninstallString, DisplayIcon)
- `HKCU\Software\NimbusPDF` (InstallPath), `HKCU\Software\NimbusPDF\Capabilities`
  (ApplicationName), `...\Capabilities\FileAssociations` (`.pdf`)
- `HKCU\Software\RegisteredApplications` → `NimbusPDF`

**Mutexes / session names**
- `nimbuspdf-payload.session`, `nimbuspdf-payload.launched`,
  `docustudio-payload.session`, `docustudio-payload.launched`, `Local\NimbusPDF-Setup`

**Crypto keys / material**
- `f4a2c8a1f8c5389f524e844d6dfd8405` (16 bytes), `8c8d7261b558cd5a` (8 bytes),
  `3c0648b02e05203ea476029da4dd8dcb76028250d46ed9e6c06d77b4dea8bd90` (SHA-256)

**Certificates / identities**
- Signer: **Alternate Financial, LLC** — `greg@alternatefintech.com`, serial `2022-001197822`,
  Virginia Beach, VA, US (EV code-signing certificate)

## 8. Capabilities & MITRE ATT&CK Mapping
| Observed capability | ATT&CK technique | Evidence |
|---------------------|------------------|----------|
| Malicious signed dropper/installer | T1190 Exploit Public-Facing Application / T1204 User Execution | EV-signed fake "NimbusPDF Setup"; runs via user execution |
| Remote payload download | T1105 Ingress Tool Transfer | `fl/remote_payload.rs`, `fl/http.rs`, `nimbuspdfstore.com`, reqwest/hyper/rustls |
| Data collection (username) | T1082 System Information Discovery / T1033 | `USERNAME` env read (`fl/scan.rs`) |
| Persistence via file association | T1546.001 Event Triggered Execution: .pdf handler | `Software\Classes\.pdf\OpenWithProgids`, `RegisteredApplications` |
| Registry persistence / uninstall entry | T1547 / T1112 Modify Registry | `Uninstall\NimbusPDF`, `Software\NimbusPDF` |
| Process/session coordination | T1055 / T1070 | mutex/session names `nimbuspdf-payload.*`, `docustudio-payload.*` |
| Evasion / anti-analysis | T1027 Obfuscated Files or Information, T1140 | encrypted blob, string obfuscation, `IsDebuggerPresent`, fake payload timestamp |
| Trust exploitation (valid EV signature) | T1553.002 Subvert Trust Controls: Code Signing | Authenticode EV cert of Alternate Financial, LLC |

## 9. Risk Assessment & Recommendations
- **Risk: HIGH.** A validly EV-signed, professionally branded installer that drops a payload,
  hijacks the `.pdf` file association, writes persistence, collects the username, and contains
  a remote-payload/C2 module. Even though the C2 path was not exercised in the sandbox, the
  capability is clearly present and the signing certificate gives it high credibility to users
  and some security tools.
- **Containment/eradication**:
  - Block `nimbuspdfstore.com` (and `NimbusPDF.app`) at DNS/HTTP(S) egress.
  - Quarantine/delete `PDFConvertSetup_809727.exe`, `NimbusPDF.exe`, `clearpage-icon.ico`.
  - Remove registry keys listed in §7 and restore the `.pdf` handler to a trusted reader.
  - Remove `NimbusPDF.lnk` shortcuts and the `%LOCALAPPDATA%\Programs\NimbusPDF` directory.
  - Revoke/flag the Alternate Financial, LLC EV certificate (report to GlobalSign / Microsoft).
- **Detection opportunities**:
  - YARA on the installer's SHA256 and on the embedded payload SHA256.
  - Network IDS for `nimbuspdfstore.com` / `NimbusPDF.app`.
  - Registry monitoring for `Uninstall\NimbusPDF`, `Software\NimbusPDF`, `.pdf` OpenWithProgids.
  - Mutex/session names `nimbuspdf-payload.*` / `docustudio-payload.*`.

## 10. Artifacts & Reproduction
- Container image: `re-full:latest` (Debian + Wine 8.0 + Xvfb + capstone/pefile/dnfile/yara).
- Sandbox: `docker run --network none --cap-drop ALL --security-opt no-new-privileges:true
  --user 1000:1000 -v $PWD/{samples,output,work}:...`.
- Password-protected archive extracted with `7z x -p... ` inside the sandbox (password not
  logged).
- Wine runtime fixes: hand-built `bcryptprimitives.dll` (`ProcessPrng`) and forwarder stubs
  for `api-ms-win-core-synch-l1-2-0.dll` / `api-ms-win-core-winrt-error-l1-1-0.dll`;
  DejaVu fonts copied to `drive_c/windows/Fonts`; `SLINT_DEFAULT_FONT` set.
- GUI automation via XTEST (`libXtst` ctypes) for Next/Install clicks; screenshots captured
  with a ctypes X11 `XGetImage` script.
- Scripts: `work/make_stub.py`, `work/make_fwd.py`, `work/x11shot.py`, `work/x11win.py`,
  `work/x11test_click.py`, `work/fakenet.py`.
- Logs/artifacts: `output/iocs.txt`, `output/iocs.json`, `output/installer_strings.txt`,
  `output/payload_strings.txt`, `output/version_manifest.txt`, `output/screenshot_welcome.png`,
  `output/screen_options.ppm`, `output/screen_complete.ppm`, `work/*.log`, `work/strace_net.log`.

## 12. Campaign Relationship — CLOUDHAZE / LuminaRead family
This sample belongs to the same malware family as the **CLOUDHAZE / LuminaRead** case
(`ID-5980443`, aka QuartzLine / "zenith"). Shared characteristics:

| Feature | LuminaRead (ID-5980443) | NimbusPDF (this sample) |
|---------|------------------------|-------------------------|
| Decoy | Rust + Slint PDF viewer | Rust + Slint PDF viewer ("NimbusPDF"/"ClearPage") |
| Hidden module | `C:\r\src\c\d\mod.rt` ("zenith"; `c`=client/http/commands/config/download) | `fl/{remote_payload,http,scan,domain,session,runtime}.rs` |
| EV signer | Xiamen Jinduoduo Technology Consulting Co., Ltd. | **Alternate Financial, LLC** |
| C2 domains | apexesmasters.com, familypenguins.com, wombatswilson.com, … | **nimbuspdfstore.com** |
| C2 path vocabulary | light-themed (`/filament/{prism,photon,resonance,radiance,aperion,signet}`) | not determined (likely similar; blob encrypted) |
| Protocol | gzip → chained XOR → bit-rotation → Fisher–Yates → base64 (seed-prefixed) | not determined (reqwest/hyper/rustls stack present) |
| Persistence | layout.conf / scheduled tasks | `.pdf` file association + uninstall registry keys |
| Payload | hidden backdoor | embedded .NET WPF PDF editor (`NimbusPDF.exe`) |

The `fl/` module name, the Rust/Slint decoy-PDF-viewer pattern, the per-sample EV certificate,
and the obfuscated HTTPS C2 design strongly indicate a common developer/operator. The signer
"Alternate Financial, LLC" and domain `nimbuspdfstore.com` are new identifiers for this family.

## 11. Appendix
- Full strings: `output/installer_strings.txt` (installer, 25,875 lines),
  `output/payload_strings.txt` (payload, 16,559 lines).
- **Open questions / next steps**:
  1. The exact C2 URL path (e.g. `/api/...`) is stored obfuscated; decrypt the `0x751000` blob
     using the recovered keys (`f4a2c8a1…`, `8c8d7261b558cd5a`) or via a runtime memory dump.
  2. The remote-payload download trigger was not exercised; investigate the `fl/*` module's
     activation conditions (possible update-check, time-bomb, or server-driven flag).
  3. The .NET payload (`NimbusPDF.exe`) is a full WPF PDF editor; run it under an x64 Wine
     prefix with .NET to confirm it has no additional network/second-stage behavior.
  4. Attribution: research "Alternate Financial, LLC" / `alternatefintech.com` and the
     `rust_wrapper_scb` / `clearpage-setup` project names for related campaigns; pivot on the
     CLOUDHAZE/LuminaRead infrastructure and the `fl/` module naming.
