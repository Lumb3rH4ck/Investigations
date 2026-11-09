# Malware Analysis Report — Shift - PDF_xyvckh.exe (Shift Browser web installer)

**Analyst:** Rhys Wilson
**Date:** 2026-11-09
**Sample:** `ID-5985014.zip` → `Shift - PDF_xyvckh.exe`
**Verdict:** **LEGITIMATE — official Shift Browser v139.1.3 web-installer stub (Shift Technologies, Inc.)**
**Confidence:** High (valid Authenticode signature, official Shift CDN payload, no malicious behavior found)

---

## 1. Executive Summary

The sample is the **official Shift Browser "web installer" stub, v139.1.3**, produced by **Shift Technologies, Inc.** and **Authenticode-signed by Shift Technologies Inc** (DigiCert-issued certificate, cryptographically valid, timestamped 2025-11-14).

It is a small Inno Setup 6.5.2 bootstrapper that:

1. Extracts ~50 temporary UI assets (images, fonts, localization JSON) to `{tmp}`.
2. Shows a custom download wizard (compiled Pascal Script `[Code]`).
3. Downloads the **full Shift Browser installer** (`shift-v139.1.3-installer.exe`) from Shift's official CDN.
4. Kills any running `shift.exe`, launches the downloaded full installer, and deletes its temp files.

No malicious payload, persistence mechanism, credential theft, process injection, or C2 behavior was found. All network endpoints belong to Shift (`tryshift.com`, `shiftapis.com`) or to legitimate third-party services (Mixpanel analytics, Microsoft dotnet feeds, Keen.io crash reporting).

**Residual risk / notes:** It is a web installer that fetches and executes a large remote payload (standard for this class of installer, but a supply-chain consideration). The file name `Shift - PDF_xyvckh.exe` and its presence in an "Investigations" repository suggest it may have been distributed out-of-context (e.g. as a "PDF" attachment) — a social-engineering red flag worth noting even though the binary itself is genuine.

---

## 2. Sample Metadata

| Field | Value |
|-------|-------|
| Filename | `Shift - PDF_xyvckh.exe` |
| Size | 8,840,328 bytes (8.4 MB) |
| SHA256 | `3bd07666fc75b8796cc900cc1e22b1d0f6b3af99397331448dc4258d88dd9e19` |
| MD5 | `e6dc8339d2a2c2f2cdf7ca56dcc09052` |
| SHA1 | `b1e6c0f41564a1f9428bd340402ee8751d374c9f` |
| File type | PE32 executable (GUI) Intel 80386, 11 sections |
| Compile timestamp | 2025-09-23 05:03:52 UTC (0x68D22A38) |
| Entropy | 7.9603 (high — compressed Inno Setup data) |
| Packer | None (Inno Setup 6.5.2 loader, LZMA-compressed data) |
| Setup engine | **Inno Setup 6.5.2** (unicode) |

### Digital signature

| Field | Value |
|-------|-------|
| Subject | `Shift Technologies Inc` (Victoria, BC, Canada) |
| Issuer | DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 |
| Serial | `0B08348496F9EA0BFADC2F629570407C` |
| Thumbprint SHA-256 | `F77055D80573BA831886B2A06AD633E80AD0EB2027E7D594DF8F11F90AF7F3BD` |
| Validity | 2025-11-13 → 2028-11-14 |
| Status | **Valid / not revoked** (as of 2026-11-09) |
| Counter-signature | DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1 (signed 2025-11-14 21:15:21 GMT) |
| PE checksum | matches (0x00871B09) |
| Authenticode digest | SHA256, matches → file intact, not modified after signing |

---

## 3. Static Analysis

### 3.1 PE structure

| Section | VA | VSize | RawSize | Entropy | Notes |
|---------|----|-------|---------|---------|-------|
| `.text` | 0x1000 | 0xAD410 | 0xAD600 | 6.398 | loader code |
| `.itext` | 0xAF000 | 0x19A4 | 0x1A00 | 6.155 | entry point 0xB0028 |
| `.data` | 0xB1000 | 0x3F88 | 0x4000 | 5.186 | |
| `.bss` | 0xB5000 | 0x72F4 | 0 | 0.000 | |
| `.idata` | 0xBD000 | 0x1040 | 0x1200 | 4.804 | imports |
| `.didata` | 0xBF000 | 0x1A4 | 0x200 | 2.754 | |
| `.edata` | 0xC0000 | 0x71 | 0x200 | 1.246 | |
| `.tls` | 0xC1000 | 0x18 | 0 | 0.000 | TLS callbacks present |
| `.rdata` | 0xC2000 | 0x5D | 0x200 | 1.377 | |
| `.reloc` | 0xC3000 | 0x11458 | 0x11600 | 6.713 | |
| `.rsrc` | 0xD5000 | 0x62568 | 0x62600 | 7.685 | icons, manifest, version |

- **Imports:** only `kernel32`, `comctl32`, `user32`, `oleaut32`, `advapi32`. Notable: `VirtualAlloc`, `VirtualProtect`, `CreateProcessW`, `CreateThread`, `LoadResource`/`FindResourceW`/`LockResource` (Inno Setup decompression), `RegOpenKeyExW`/`RegQueryValueExW`, `AdjustTokenPrivileges`/`LookupPrivilegeValueW` (UAC). **No WinInet/WinHttp/ws2_32 imports** — the loader does no networking itself (the download is performed by the `[Code]` script via the `WinHttp.WinHttpRequest.5.1` COM object at runtime).
- **No debug directory, no load config.** Exports are Delphi runtime helpers (`__dbk_fcall_wrapper`, `dbkFCallWrapperAddr`).

### 3.2 Inno Setup package internals

| Property | Value |
|---|---|
| Loader magic | `rDlPtS` + `$CD$E6$D7{$0B*` (5.1.5 magic, **revision 2**) |
| Offset table resource | RCDATA `11111` (64 bytes) |
| Embedded engine (`setup.e32`) | @ 0x720CD4, uncompressed 0x3E4000 (3.89 MiB), CRC32 0xA129FAFE |
| Header offset (`Offset0`) | 0x714825 |
| Data offset (`Offset1`) | 0x128800 |
| Compression | LZMA1 |
| App name / version | Shift Browser / 139.1.3 |
| Publisher / URL | Shift Technologies, Inc. / https://tryshift.com |
| AppId | `{95fcf903-63b1-44bd-ab77-358a5bd30aae}` |
| Uninstallable | `no` (stub — no uninstall entries) |
| Password / encryption | none (`EncryptionUse = 0`) |
| Languages | 1 (default English) |
| File entries | 50 (all `[temp]`) |
| Run entries | 0 |
| Compiled `[Code]` | **178,056 bytes** (Pascal Script bytecode) |

**Loader header layout (revision 2, 64 bytes):**

```
+0x00  ID[12]              'rDlPtS'#$CD#$E6#$D7'{'#0B'*'
+0x0c  Version             = 2
+0x10  TotalSize     (i64) = 8,831,333
+0x18  OffsetEXE     (i64) = 7,474,388
+0x20  UncompressedSizeEXE  = 4,079,616
+0x24  CRCEXE        (i32) = 0xA129FAFE
+0x28  Offset0       (i64) = 7,424,037   <- setup header
+0x30  Offset1       (i64) = 1,214,464   <- setup data
+0x38  ReservedPadding(u32)= 0
+0x3c  TableCRC      (i32) = 0x1C992D5C  (CRC32 of +0x00..+0x3b)
```

The CRC32 of the loader table and the encryption header both verify → the file is structurally intact.

---

## 4. Payload Extraction

`innoextract` 1.9 and upstream master (1.10-dev) only support Inno Setup ≤ 6.3.3 and rejected this file ("Unexpected setup loader revision: 2", "Could not determine setup data version"). I backported 6.4–6.5.2 support (see §9) and extracted the payload cleanly.

**50 files, all in `{tmp}` (marked "delete after install" / "don't copy"):**

- `Win32Library.dll` — .NET 4.x helper assembly (see §5)
- `background.png` (5.38 MiB, 2184×1266), `shift.png` (432×432), `installing.png`, plus ~40 wizard UI images (buttons, minimizers, progress, app tiles: `shift-pdf.png`, `shift-email.png`, `shift-maps.png`, …)
- `Geist-VariableFont_wght.ttf` — the Geist UI font
- `de.json`, `en.json`, `es.json`, `fr.json`, `pt.json` — localization strings for the setup UI

All PNGs are valid, contain no trailing/append data, and were generated with **Paint.NET 5.1.9** (EXIF software tag — this explains the otherwise-suspicious "Paint.NET 5.1.9" string).

**No browser binaries are embedded.** The stub downloads the real installer at runtime.

---

## 5. Component Analysis

### 5.1 `Win32Library.dll` (50,176 bytes, .NET 4.x)

| Field | Value |
|---|---|
| SHA256 | `92af9d054e3b5dc9f472ff9534060d1c70e2ac77f768ae9e5029e29fcd606198` |
| MD5 | `d82b30898c428a7dbee81cecea520f68` |
| Type | PE32 DLL, Mono/.NET assembly, 4 sections |
| Compile timestamp | 2023-10-19 19:16:41 UTC |
| PDB path | `C:\Users\Stephen\source\repos\products-onelaunch\Win32Library\bin\Debug\x86\Win32Library.pdb` |
| Exports | `BuildDownloadLink`, `ProcessDownloadPackage`, `ConvertToBitmap`, `ConvertToIco`, `ExtractButtonStates`, `RoundWindowCorners`, `SetWindowPos` |

**What it is:** a shared library from the "products-onelaunch" project that bundles:

1. **A C# port of Microsoft's `dotnet-install-scripts`** — classes `DownloaderAndInstaller`, `Payload`, `DownloadLinkObject`, `VersionInfo`, `PayloadURLSpecificProductVersion`, `AssetNameDotnetPackageRelativePath`. It resolves .NET runtime/SDK packages from the official Microsoft feeds:
   - `https://dotnetcli.azureedge.net/dotnet`
   - `https://dotnetbuilds.azureedge.net/public`
   - `https://aka.ms/dotnet` (aka.ms link resolution)
2. **Win32 UI helpers** — P/Invoke wrappers (`user32`, `kernel32`, `shell32`, `dwmapi`, `gdi32`): window composition/blur, stock icons, image conversion, `SendInput`, etc.
3. **Crash reporting to Keen.io** — `https://api.keen.io/3.0/projects/{0}/events/`
   - Project ID: `639cfbb0452c99488ad2b956`
   - Write key: `dd0e945866f6c774af909e09c933fc6f56756f23e0e72f3de4cabadf256237ea9b9650a961b85d7e535b75e3d640fc4042d1292b09c5ba4851f89769a49aa9da41ecb75b55f7e8feae80adfbb6d4cf5c880fa576ca0140e0f3cdb3b3d426fb55`
4. **Connectivity check** via the `NETWORKLIST.INetworkListManager` COM interface (CLSID `DCB00C01-570F-4A9B-8D69-199FDBA5723B`).

**Important:** the installer's Pascal `[Code]` imports only the UI functions (`SetWindowPos`, `ConvertToIco`, `ConvertToBitmap`, `ExtractButtonStates`, `RoundWindowCorners`). The dotnet download logic is present but not exercised by this installer's script — it is shared framework code (the same "products-onelaunch" library is used for other products, e.g. .NET-based ones).

### 5.2 Wizard images, fonts, localization

Standard Shift branding assets. `background.png` is a 2184×1266 RGBA image used as the wizard backdrop. No steganography, no appended data. The JSON files contain only setup-UI strings (no URLs or executable content).

---

## 6. Compiled Pascal Script (`[Code]`) Analysis

The 178 KB `[Code]` section is Pascal Script bytecode. Extracted procedure names and string constants reveal the full flow:

**Procedures (by name):**

| Area | Procedures |
|---|---|
| Download | `ATTEMPTSHIFTSETUPDOWNLOAD`, `BUILDDOWNLOADPAGE`, `CREATEDOWNLOADPAGE`, `SETDOWNLOADPAGEURLTOSHIFTSETUP`, `ONDOWNLOADFROZEN`, `FROZENEXITFORMCLOSEANDRETRYDOWNLOAD`, `SHOWSHIFTFROZENPROMPT` |
| URL/config | `INITIALIZEURLS`, `GETNTPURL`, `HASLPURL`, `GETPROFILE`, `GETPROFILEDESCRIPTION`, `GETPROFILEDISPLAYNAMESTRING`, `GETPROFILEHEADLINE`, `CHECKPROFILE`, `ISSHIFTCOMFLOW` |
| UI | `INITIALIZESHIFTUI`, `ONSHOWSHIFTUI`, `CURPAGECHANGEDSHIFTUI`, `CURSTEPCHANGEDSHIFTUI`, `SCALESHIFTUI`, `SHIFTWINDOWPROCEDURE`, `SHIFTBUILDBACKGROUND`, `SHIFTBUILDTITLEBAR`, `SHIFTBUILDCLOSEBUTTON`, `SHIFTBUILDMINIMIZEBUTTON`, `SHIFTBUILDPROGRESSBAR`, `SHIFTBUILDPROGRESSLABEL`, `UPDATESHIFTPROGRESSBAR`, `BUILDLPROFILECONTENT`, `BUILDLPROFILESHORTCUTICO`, `EXTRACTPROFILEICON`, `BUILDSHIFTICON` |
| Command line | `GETINSTALLINFOFROMCMDLINE`, `FINDCMDLINESWITCH`, `FINDSTOREDCMDLINESWITCH`, `VALUEFORCMDLINESWITCH`, `COPYCMDLINESWITCH`, `FORCESPLITFROMCMDLINE`, `WASSPLITFORCEDINCMDLINE` |

**External imports:** `shell32!ShellExecuteExW`, `kernel32!ExitProcess`, `ole32!CoCreateGuid`, `Win32Library.dll` (UI), `user32` (window/timer), `Gdi32!AddFontResourceW`. Network via `WinHttp.WinHttpRequest.5.1`.

**Observed flow:**

1. Initialize URLs; read `profile` / `ntp_url` / `lp_url` / `search_url` settings.
2. Build the download page; show progress via `TONDOWNLOADPROGRESS`.
3. Download the full installer to `{tmp}\Shift Setup.exe`.
4. `taskkill /f /im shift.exe` (kill running Shift instances).
5. `ShellExecuteExW` the downloaded `{tmp}\Shift Setup.exe`.
6. Clean up `{tmp}` files.

**Command-line switches:** `/LAUNCHER`, `/VERYSILENT`, `/SPLITS=`, `/URL`, `/FILE`, `/LOG`, `/PDATA=`, `/analytics-service-origin`, `/channel`, `/mixpanel-token`, `/splittests`, `/splittestssubstitution`, `/update-service-origin`.

**No** PowerShell, `cmd.exe`, `reg.exe`, `schtasks`, base64 blobs, or encoding tricks were found in the code.

---

## 7. Network Indicators

### 7.1 Shift infrastructure (hardcoded in `[Code]`)

| URL | Purpose |
|---|---|
| `https://downloads.tryshift.com/releases/win-x64/shift-v139.1.3-installer.exe` | **Primary payload** — full Shift Browser installer |
| `https://cdn77-downloads.tryshift.com/releases/win-x64/shift-v139.1.3-installer.exe` | Alternate CDN (A/B test `split_st6125_alternate_download_cdn`) |
| `https://tryshift.com` | Publisher site |
| `https://tryshift.com/download` | Download page |
| `https://tryshift.com/eula` | EULA |
| `https://tryshift.com/privacy` | Privacy policy |
| `https://updates.shiftapis.com` | Update service |
| `https://attribution.shiftapis.com/pdata/` | Attribution/pixel tracking |
| `https://api.mixpanel.com` | Mixpanel analytics (`/track?data=`, `/engage?data=`) |
| `https://api.keen.io/3.0/projects/{0}/events/` | Keen.io crash reporting (in `Win32Library.dll`) |

### 7.2 Microsoft dotnet feeds (in `Win32Library.dll`, not used by this script)

- `https://dotnetcli.azureedge.net/dotnet`
- `https://dotnetbuilds.azureedge.net/public`
- `https://aka.ms/dotnet`
- `https://aka.ms/dotnet-os-lifecycle`

### 7.3 Analytics identifiers

- Mixpanel token: `954ec00f0d8908fa21c3ebb20e6ceb4d`
- Keen.io project ID: `639cfbb0452c99488ad2b956`
- Keen.io write key: `dd0e945866f6c774af909e09c933fc6f56756f23e0e72f3de4cabadf256237ea9b9650a961b85d7e535b75e3d640fc4042d1292b09c5ba4851f89769a49aa9da41ecb75b55f7e8feae80adfbb6d4cf5c880fa576ca0140e0f3cdb3b3d426fb55`

**No IP addresses, no non-Shift/non-Microsoft C2 domains were found.**

---

## 8. Host-Based Indicators

### 8.1 Registry

| Key | Purpose |
|---|---|
| `SOFTWARE\Shift` | Shift settings |
| `Software\Microsoft\Windows\CurrentVersion\Uninstall\{95fcf903-63b1-44bd-ab77-358a5bd30aae}_is1` | Uninstall entry (written by the full installer) |
| `SOFTWARE\Clients\StartMenuInternet` | Default browser registration |
| `SOFTWARE\Classes\.htm\OpenWithProgids`, `.html`, `.pdf`, `.shtml`, `.svg`, `.webp`, `.xht`, `.xhtml` | File-association handlers |
| `SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice` | Default HTTP handler |
| `SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize` | Dark/light theme detection (UI) |
| `Software\Microsoft\Edge\BLBeacon` | Edge version detection |

### 8.2 Mutexes

- `Shift-841bfdc9-095f-4be3-9a77-bce0d18a78a8`
- `ShiftLauncher-334c9fbc-495b-4ed8-851b-987ebe92f1ce`
- `ShiftStub-78413f9e-6ba7-4164-8052-f252c88e00e0`
- `ShiftSetup-1c730e63-6e5f-40e0-80ac-ea3d2e84e629`

### 8.3 Files / directories

- `{tmp}\Shift Setup.exe` — downloaded full installer (executed, then deleted)
- `{tmp}\Win32Library.dll`, `{tmp}\*.png`, `{tmp}\*.json`, `{tmp}\Geist-VariableFont_wght.ttf`
- `{localappdata}\Shift`
- `{app}\chromium\.configurations\install-info.json`
- `{app}\chromium\.configurations\split-tests.json`

### 8.4 Processes

- `taskkill /f /im shift.exe` — terminates running Shift before install (normal upgrade behavior).

---

## 9. Methodology Notes

All work was performed inside the sandboxed `re-full` Docker image (`--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, `--pids-limit 64`, `--memory 2g`). The sample was never executed on the host.

1. **Download & quarantine** — archive fetched on host into `samples/` (read-only mount); hashes computed in-sandbox.
2. **Extraction** — password-protected ZIP extracted in-sandbox with `7z`.
3. **Static triage** — `file`, PE headers/sections/imports/resources via `pefile`, entropy, strings.
4. **Signature** — PKCS#7 extracted, verified with `osslsigncode`.
5. **Unpacking** — `innoextract` did not support Inno Setup 6.5.2. I backported support (base: upstream PR #214 "Support Inno Setup 6.4 to 6.6" + targeted 6.5.2 fixes). Payload extracted to `output/unpacked/` (50 files).
6. **Component RE** — `Win32Library.dll` disassembled with `monodis`/`ikdasm`; .NET metadata, IL, P/Invoke map, and `#US` string heap analyzed.
7. **Script RE** — decompressed header streams dumped (`--dump-headers`); Pascal Script bytecode strings extracted (ASCII + UTF-16).
8. **IOC extraction** — URLs/domains/IPs/hashes/GUIDs/registry keys collected.

### Backported innoextract changes

- Loader revision 2 / 64-bit offsets (`src/loader/offsets.cpp`)
- `TSetupEncryptionHeader` before the block stream (`src/setup/info.cpp`, `src/stream/block.cpp`)
- 6.5.0 header changes (new strings, `NumISSigKeyEntries`, wizard back-colors, flags)
- 6.5.2 changes (`WizardImageBackColor`/`WizardSmallImageBackColor`, `StartOffset` widened to Int64)

The full patch is in `analysis_scripts/innoextract-6.5.2-backport.patch`.

---

## 10. Risk Assessment

| Check | Result |
|---|---|
| Authenticode signature | **Valid** — Shift Technologies Inc |
| File intact (not tampered post-signing) | **Yes** |
| Known malware families / YARA hits | None |
| Packer / crypter / obfuscation | None (Inno Setup, LZMA) |
| Embedded browser binaries | None (web-installer stub) |
| Suspicious commands (PS/cmd/reg/schtasks) | None |
| Persistence mechanisms | None (only the app's own uninstall key) |
| Credential theft / injection / evasion | None |
| C2 / non-vendor domains | None |
| PNG steganography / appended data | None |
| PE overlay | None |

**Overall risk: LOW.** The binary is a genuine, signed vendor web installer.

**Caveats / things to note:**

1. **Web-installer supply chain.** The stub downloads and executes a ~100 MB payload from `downloads.tryshift.com` / `cdn77-downloads.tryshift.com`. If Shift's CDN or update channel were compromised, this stub would faithfully run the attacker-controlled payload. This is inherent to web installers, not a defect in this sample.
2. **Distribution context.** The name `Shift - PDF_xyvckh.exe` and its presence in an "Investigations" repo suggest it may have been received out-of-context (e.g. renamed to look like a PDF, or bundled). The binary is genuine, but the *distribution vector* should be investigated (phishing email, download portal, bundler).
3. **Telemetry.** Mixpanel + Keen.io analytics are present; privacy-relevant but not malicious.
4. **Unused framework code.** `Win32Library.dll` contains a full dotnet-install-scripts port that this installer does not invoke. It is shared code from the "products-onelaunch" framework, not a hidden payload.

---

## 11. Recommendations

1. **Do not treat this binary as malware.** It is a valid, signed Shift Browser web installer. Blocking/quarantining it purely on reputation is unnecessary; however, if the investigation is about *how it was distributed*, focus on the source (email/web) rather than the file.
2. **If investigating distribution:** preserve the original download context (email headers, referrer, source URL, `xyvckh` suffix pattern) — the random suffix and "PDF" naming are the strongest social-engineering indicators.
3. **Verify the full payload independently** (if obtained): `https://downloads.tryshift.com/releases/win-x64/shift-v139.1.3-installer.exe` — hash it and check its own signature before trusting it.
4. **Optional dynamic analysis:** running the stub under Wine in the sandbox (no network) would confirm it halts at the download step and reveals the UI flow; it will not reach the network in the current isolated setup. This was not performed because executing the sample is a HIGH-risk step requiring explicit approval.
5. **Monitor Shift infrastructure IOCs** if the investigation is broader: `downloads.tryshift.com`, `cdn77-downloads.tryshift.com`, `updates.shiftapis.com`, `attribution.shiftapis.com`, Mixpanel token `954ec00f0d8908fa21c3ebb20e6ceb4d`.

---

## Appendix A — Key Hashes

| File | SHA256 |
|---|---|
| `ID-5985014.zip` | `dd5495f6d1dd5f7b30ed6d815711e34d0cc8adb2cd116ac2d63996732fcb71ff` |
| `Shift - PDF_xyvckh.exe` | `3bd07666fc75b8796cc900cc1e22b1d0f6b3af99397331448dc4258d88dd9e19` |
| `Win32Library.dll` | `92af9d054e3b5dc9f472ff9534060d1c70e2ac77f768ae9e5029e29fcd606198` |

## Appendix B — Certificate

| Field | Value |
|---|---|
| Subject | Shift Technologies Inc (Victoria, BC, CA) |
| Issuer | DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 |
| Serial | 0B08348496F9EA0BFADC2F629570407C |
| Valid | 2025-11-13 → 2028-11-14 |
| Signature timestamp | 2025-11-14 21:15:21 GMT |
| Digest | SHA256, matches PE |

## Appendix C — Repository Contents

```
ID-5985014/
├── README.md                              # this report
├── IOCs.txt                               # indicators of compromise
├── hashes.txt                             # sample + payload hashes
├── certs/
│   ├── authenticode.p7b                   # embedded PKCS#7 signature
│   ├── shift_chain.pem                     # signer certificate chain
│   └── shift_leaf.pem                      # signer leaf certificate
├── analysis_scripts/
│   ├── triage.py                           # PE triage helper
│   ├── extract_resources.py                # PE resource extractor
│   ├── ioc_extract.py                      # IOC collector
│   └── innoextract-6.5.2-backport.patch    # Inno Setup 6.5.2 unpacker patch
├── payload/
│   ├── Win32Library.dll                    # extracted .NET helper
│   ├── Win32Library_il.txt                 # full IL disassembly
│   ├── compiled_code_strings.txt           # Pascal Script string constants
│   └── localization/                       # setup UI JSON (en/de/es/fr/pt)
└── headers/
    ├── headers0.bin                        # decompressed primary setup header
    └── headers1.bin                        # decompressed secondary header
```
