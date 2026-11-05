# Malware Analysis Report — LuminaRead_1.3994.39.exe (CLOUDHAZE)

**Analyst:** Lumb3rH4ck (opencode sandboxed RE session)
**Date:** 2026-11-05
**Sample:** `ID-5980443.zip` → `LuminaRead_1.3994.39.exe`
**Verdict:** **MALICIOUS — CLOUDHAZE backdoor (Mandiant: CLOUDHAZE; aka QuartzLine / "zenith")**
**Confidence:** High (100/100 Hybrid Analysis, 48/100 Joe Sandbox, confirmed by ANY.RUN / Expel / Rogue Authority / Fraunhofer FKIE)

---

## 1. Executive Summary

The sample is a **trojanized, fully functional Windows PDF viewer** ("LuminaRead") written in Rust with the Slint GUI toolkit. The viewer is a **lure**: it works, so victims keep it installed. Hidden inside is a backdoor module (authored as **"zenith"**) that:

- Writes a persistent machine identifier to `%LOCALAPPDATA%\LuminaRead\layout.conf` (disguised as viewer settings).
- Checks in with a hard-coded C2 server over HTTPS using a custom obfuscated protocol (gzip → chained XOR → bit-rotation → seeded Fisher–Yates shuffle → base64).
- Accepts remote tasking: **arbitrary command execution** via hidden `cmd /C`, and **Chromium browser-profile tampering** (read/replace profile files, force-kill and relaunch the browser with `--user-data-dir`).
- Persists via scheduled tasks and stages follow-on payloads (Chrome history uploader, Caira RAT, IronBark).

The binary is **EV code-signed** by "Xiamen Jinduoduo Technology Consulting Co., Ltd." (Sectigo EV Code Signing CA R36). The signature is currently **valid** (unlike the QuartzLine cert, which was revoked), which is why three samples had **zero AV detections** at time of analysis.

**Distribution:** Google Display malvertising (586 ads from two verified advertisers on calendar/template sites), targeting US users searching for things like consent forms or wallpapers — not PDF tools. Redirectors lead to AWS S3 download buckets.

**This analysis went further:** the sample was executed in the sandbox against a
loopback fake-TLS C2. The live check-in was captured and **decrypted**, yielding
the campaign ID `ZRBMRQJVPLAFWCILSE`, the persistent machine UUID
`9e7504de-8c13-427c-9e7a-9ee610c2b9e4`, and the telemetry schema (§6.4). The
full protocol was reversed from the binary (§6.5).

**Bottom line:** This is a real, working backdoor. The visible app is a decoy. Treat any host that ran it as compromised: the operator can execute commands and has access to browser profiles/sessions.

---

## 2. Sample Metadata

| Field | Value |
|-------|-------|
| Filename | `LuminaRead_1.3994.39.exe` (also seen as `downloads_LuminaRead_1.6431.48.exe`, `LuminaRead_1.2240.96.exe`, `LuminaRead_1.4999.27.exe`, `LuminaRead_1.9857.87.exe`) |
| Size | 8,386,072 bytes (8.0 MB) |
| MD5 | `99fb98fb9d20292790d103c9bbacd825` |
| SHA1 | `3e498102afc2938de7a493db060f17dc233633ae` |
| SHA256 | `7e71e072fbf39e4aaebad71c0e9e3443f9a4455faf687eb87264019cac342c31` |
| SHA512 | `baeb44e993470a68aef5293d0f559289a07ac53a9227c6dc690b9220166e79bd4a759a1c9b5e23176064f135918cbe7c3f884db04e7571b53ba83ccbafd16945` |
| File type | PE32+ executable (GUI) x86-64, Windows |
| Timestamp | 3047799734 → **2066-07-31** (forged/future date) |
| Image base | 0x1764e0000 (unusually high) |
| Entry point | RVA 0x3a7ec0 |
| Checksum | valid (0x0080d9e3) |
| Packer | None (entropy 6.76; normal for Rust) |
| GUI framework | Slint 1.16.1 (Rust) |
| PDF engine | Custom `parsers\parser2` (Rust) + fontique/skrifa/harfrust/tiny-skia/resvg |
| HTTP stack | reqwest/hyper 1.9.0/hyper-util 0.1.20/tokio 1.52.1, SOCKS4/5 proxy support |
| TLS | Windows Schannel via secur32/crypt32 (native-tls) |
| Build | GitHub Actions runner (`C:\Users\runneradmin\.cargo\...`), project `.\apps\luminaread\`, workspace root `C:\r\` |
| Version resource | **DispatchView** Document Viewer, CompanyName **Lynx Labs**, FileVersion 9.19.1737.36, OriginalFilename `dispatchview.exe` |

**Identity mismatch (red flag):** signer = *Xiamen Jinduoduo Technology Consulting Co., Ltd.*, version resource = *DispatchView / Lynx Labs*, UI = *LuminaRead*. Three different names.

### Digital signature

| Field | Value |
|-------|-------|
| Subject | `CN="Xiamen Jinduoduo Technology Consulting Co., Ltd.", O="Xiamen Jinduoduo Technology Consulting Co., Ltd.", S=Fujian Sheng, C=CN, SERIALNUMBER=91350206MA8T36LL6G` |
| Issuer | Sectigo Public Code Signing CA EV R36 |
| Serial | `00D25F883C5D74CE4399BFC29D85EF3263` |
| Thumbprint SHA-256 | `4184F429EA40513117FA8603E87F770B0881370E1BEA0965236152234711AEA3` |
| Validity | 2026-03-09 → 2027-03-09 |
| Status | **Valid / not revoked** (as of 2026-11-05) |
| Counter-signature | Sectigo Public Time Stamping Signer R36 (signed 2026-03-27) |

---

## 3. Static Analysis

### 3.1 PE structure

| Section | VA | VSize | RawSize | Entropy | Notes |
|---------|----|-------|---------|---------|-------|
| `.text` | 0x1000 | 0x50a016 | 0x50a200 | 6.53 | 5.3 MB of code |
| `.rdata` | 0x50c000 | 0x2ca604 | 0x2ca800 | 6.54 | strings/resources |
| `.data` | 0x7d7000 | 0x15d8 | 0x1400 | 0.82 | |
| `.pdata` | 0x7d9000 | 0x18ab0 | 0x18c00 | 6.24 | exception table |
| `.tls` | 0x7f2000 | 0x921 | 0xa00 | 0.01 | TLS directory + 1 callback |
| `_RDATA` | 0x7f3000 | 0x444 | 0x600 | 2.97 | |
| `.rsrc` | 0x7f4000 | 0x4e08 | 0x5000 | 4.92 | icon, version, manifest |
| `.reloc` | 0x7f9000 | 0x7788 | 0x7800 | 5.47 | |

- DLL characteristics `0x8160`: ASLR, NX, **Control Flow Guard (CFG)**, Terminal Server aware.
- No exports.
- TLS callback at `0x1767951e0` is standard Rust std runtime init (not malicious).

### 3.2 Resources

- `RT_ICON` (1), `RT_GROUP_ICON` (1), `RT_VERSION` (1), `RT_MANIFEST` (1).
- Manifest: `DispatchView.Version`, `asInvoker` execution level, PerMonitorV2 DPI, UTF-8 active code page, Common-Controls 6.0.0.0 dependency.
- Version info: **DispatchView / Lynx Labs** (mismatched branding).

### 3.3 Imports of interest

| DLL | Functions | Capability |
|-----|-----------|-----------|
| `ws2_32.dll` | WSAStartup, socket, connect, send, recv, getaddrinfo, ioctlsocket | HTTPS C2 |
| `secur32.dll` | InitializeSecurityContextW, DecryptMessage, EncryptMessage | TLS/Schannel |
| `crypt32.dll` | CertOpenStore, CertVerifyCertificateChainPolicy | cert validation |
| `bcrypt.dll` / `bcryptprimitives.dll` | BCryptGenRandom, ProcessPrng | RNG (protocol seeds) |
| `advapi32.dll` | RegOpenKeyExW, RegQueryValueExW, GetTokenInformation, SystemFunction036 | registry, token, RNG |
| `kernel32.dll` | CreateProcessW, CreateMutexA, CreateFileMappingW, ReadProcessMemory, VirtualProtectEx, OpenProcess | process creation/injection primitives |
| `user32.dll` | GetAsyncKeyState, GetKeyboardState, GetRawInputData, RegisterRawInputDevices, SetWindowDisplayAffinity, SendInput | input capture / anti-screen-capture |
| `gdi32.dll` | BitBlt, CreateDIBSection | screen capture |
| `ole32.dll` / `combase.dll` | CoCreateInstance, CoCreateFreeThreadedMarshaler | OLE |
| `pdh.dll` | PdhAddEnglishCounterW, PdhCollectQueryData | performance counters |
| `ntdll.dll` | NtQueryInformationProcess, NtQuerySystemInformation | system info / anti-debug |

### 3.4 App strings / decoy UI

The binary contains a complete, polished UI text set for "LuminaRead" (welcome guide, keyboard shortcuts, zoom/search/invert features, supported formats). It also contains a **loader-style init sequence**:

```
Preparing environment... Loading core libraries... Checking certificates...
Initializing render pipeline... Configuring layout engine... Applying display settings...
Verifying workspace... Completing initialization...
```

### 3.5 Embedded source paths (leaked)

```
.\apps\luminaread\target\release\build\luminaread-a5bc15d229c9941b\out\main_window.rs
src\renderer.rs
src\app.rs
src\config.rs
src\http.rs
src\commands.rs
src\register.rs
src\profile.rs
C:\r\src\h\e.rs
C:\r\src\h\register.rs
C:\r\src\b\f\profile.rs
C:\r\src\b\f\e.rs
C:\r\src\c\http.rs
C:\r\src\c\commands.rs
C:\r\src\c\config.rs
C:\r\src\c\mod.rt      <-- one-char edit of mod.rs (anti-string-detection)
C:\r\src\c\d\mod.rt    <-- download module
```

The `C:\r\` tree is the hidden backdoor ("zenith"): `c` = client (http/commands/config/download), `h` = handler (register), `b` = browser/profile.

### 3.6 Config / C2 vocabulary found in `.rdata`

```
filament  prism  photon  resonance  radiance  condenser  wavelength  spectrum
luminary  refract  diffuse  talc  layout.conf  LuminaRead
ZRBMRQJVPLAFWCILSE            <-- campaign ID (18 chars, cf. QuartzLine QNPVXZGJYUSLTREHK)
LR51 LR52 LR53 LR54 LR55 LR56 LR57   <-- build/generation markers
DUPMWKXRNTGHLQPJSZYMKWNRGXLQMPUD    <-- 32-char seed/key material
G4WK7RM2XP5JT9BV3NH6QF8LD1SW4CN7FR2Y <-- 34-char seed/key material
VXKMPBNRWTQFLHDJCYMZ... (200+ chars) <-- encoded/obfuscated blob
```

Telemetry schema keys: `standard, os, Target, windows, osArch, timezone, UTC, schemaRevision, 1.0, enlist, survey, witness, herald, presto, ledger, cadence, manifest, courier` and event keys `event, Scope, notice, release, Stream, current, session, Kind, local, format, Revision, directives, gateway, depot, seal, verbose, aftermath, aperion, signet`.

### 3.7 Update / network module

- CLI flags: `--update-check`, `--update-view`.
- `--user-data-dir=` (Chromium profile relaunch).
- `Content-Type: text/plain` request header; **no User-Agent** (unusual).
- Error strings: `No URLs provided`, `Invalid download`, `Invalid UTF8`.
- Callback/event names: `register_setup`, `update_pre_download`, `update_post_download`.
- SOCKS proxy support (`socks4`, `socks4a`, `s5`, `socks5h`) and Windows system-proxy detection (`Software\Microsoft\Windows\CurrentVersion\Internet Settings`).
- `LOCALAPPDATA` used to build the config path.

---

## 4. Packing / Obfuscation

- **Not packed.** Entropy is normal (6.76) and code is readable.
- **Anti-string-detection:** one-character edits to embedded Rust source paths (`mod.rs` → `mod.rt`, `main.rs` → `main_window.rs`/`main.rj` in other builds). This defeats YARA/code-similarity rules that match standard paths.
- **Protocol obfuscation** (not cryptography): gzip → chained XOR (`key[9]=0xB7`, previous byte, seed bytes) → per-byte `rol((seed+i)&7)` → seeded Fisher–Yates shuffle (LCG `s=s*mult+inc`, `j=s%(i+1)`, `s0=seed^len`) → prepend `0x5A` + 4-byte seed → base64. Fully reversible; seed travels with the message. See §6.5.
- **Decoy:** the app is a real, working PDF viewer.

---

## 5. Disassembly / Decompilation Findings

Key functions (VA, image base 0x1764e0000):

| VA | Function | Purpose |
|----|----------|---------|
| `0x176694600` | config builder | Builds the config/identity structure (filament, LuminaRead, campaign ID, layout.conf, theme names) |
| `0x1766923ec`–`0x176692783` | config keys | `auto_update`, `telemetry`, `clientinfo`, `session`, `protocol v3`, `region`, `stack` |
| `0x176748fd7` | update/client | HTTP client: iterates URL list, `Content-Type: text/plain`, handles `No URLs provided` |
| `0x176748e00`–`0x176749700` | update module | `register_setup`, `update_pre_download`, `update_post_download` callbacks |
| `0x176752543`–`0x176752c4a` | config path | Builds `%LOCALAPPDATA%\<Brand>\layout.conf` |
| `0x17674a100`–`0x17674a500` | commands | Command protocol fields: `index`, `com`, `success`, `ec`, `durst1`, `st1`, `st2`, `trunc1`, `trunc2`, `err` |
| `0x176756400`–`0x176756800` | browser/profile | `userName`, `uid`, `appId`, `pns`, `bpr`, `wvls`, `ilup`, `DefaultProfile`, `PName`, `EM`, `EA`, `LS`, `TN`, `SS`, `AP`, `SACGZ` |
| `0x176752b00`–`0x176752d6a` | env/paths | `LOCALAPPDATA`, `USERPROFILE`, `AppData`, `Program Files` |
| `0x176748000`–`0x1767480d0` | profile format | `DefaultProfile Offset PName Offset EM Offset EA Offset LS Offset TN SS AP SACGZ context source` |
| `0x1764f1678` | CLI | `--update-check` handling |
| `0x1764eac32` | CLI | `--update-view` handling |

The config structure is a key/value blob written to `layout.conf`; the machine/campaign ID (`ZRBMRQJVPLAFWCILSE`) and light-themed theme names (`filament`, `radiance`, `luminary`, `refract`, `diffuse`) are stored there. The same light-themed vocabulary is reused as C2 URL path components.

---

## 6. Dynamic Analysis (from public sandboxes and vendor reporting)

> Local dynamic execution in the sandbox was **not performed** (see §9 — awaiting approval). Behavior below is from Joe Sandbox, ANY.RUN, Hybrid Analysis, Expel, and Rogue Authority.

### 6.1 Execution flow

1. User downloads `LuminaRead_1.<version>.exe` from a malicious ad funnel (Google Ads → redirector → AWS S3).
2. A fake "document authentication" page may precede it (e.g., `crematoriomascotas.com.ar/candcpm/...html`, branded "Welcome to LuminaRead", harvesting business email).
3. The viewer opens (decoy) while the hidden module:
   - Writes `%LOCALAPPDATA%\LuminaRead\layout.conf` (222 bytes, ASCII; MD5 `7e4e1555fcdc8af2e4278bbb6f1f23ce`).
   - Checks in to `https://<c2>/filament/<path>` with no User-Agent.
   - Receives `{"lignite":{"update":false},"schist":{"success":true}}` ("nothing to do") in all decrypted public runs.
4. Persistence: copies itself to `%LOCALAPPDATA%\<Brand>\<brand>.exe`, registers hourly scheduled task `<Brand>UpdateCheck`.
5. Later stages (observed in customer environments, not public sandboxes):
   - `chrome-history-summarizer-v0.0.1.exe` — uploads Chrome history to S3.
   - `quartzline_takeover_carrier.exe` / `hosthealth.exe` — self-deleting stagers.
   - `deployApp.ps1` → `caira.exe` (second-stage RAT) + `CairaServiceCheck` task.
   - `updater-helper.exe` → IronBark (third stage) + `IronbarkUpdateCheck` task.
   - Chrome killed (`taskkill /F`) and relaunched with `--hide-crash-restore-bubble --restore-last-session --user-data-dir=...`; default search/new-tab changed to attacker domains.

### 6.2 C2 protocol

- HTTPS POST to `/filament/<path>` (LuminaRead generation).
- Body: gzip → chained XOR (fixed key + per-message seed) → bit rotation → seeded Fisher–Yates shuffle → base64.
- Check-in fields: implant version, campaign ID, tag, program path, machine ID.
- Very low polling frequency (one check-in, then silent for the rest of a 10-minute capture).

### 6.3 Observed network (Joe Sandbox, this exact hash)

```
https://apexesmasters.com/filament/prismL1iw
https://familypenguins.com/filament/prism
https://familypenguins.com/filament/prismt&qw
https://wombatswilson.com/filament/prismA1lww
https://familypenguins.com/filament/photon
https://familypenguins.com/filament/resonance
https://eagle.sterlingwaters.com/...  (phishing)
https://foxbamboo.com/...            (malvertising)
```

### 6.4 Live C2 capture and decryption (this analysis)

The sample was executed in the sandbox against a loopback-only fake TLS server
(`familypenguins.com` → 127.0.0.1). Two check-in POSTs were captured:

```
POST /filament/aperion   content-type: text/plain   (no User-Agent)
POST /filament/signet    content-type: text/plain   (no User-Agent)
```

The bodies are base64 of `[0x5A][seed(4 LE)][obfuscated payload]`. The payload
was recovered by patching the Fisher-Yates shuffle to the identity permutation
and brute-forcing the single XOR key byte. Decrypted JSON:

**`/filament/aperion`** (check-in / heartbeat):
```json
{"clientMode":"standard","dispatch":"survey","locale":"en-US",
 "nextal":"ZRBMRQJVPLAFWCILSE","osArch":"x64","osTarget":"windows",
 "schemaRevision":"1.0","timezone":"UTC",
 "warden":"9e7504de-8c13-427c-9e7a-9ee610c2b9e4"}
```

**`/filament/signet`** (status report):
```json
{"clientMode":"standard","eventScope":"notice","formatRevision":"standard",
 "herald":"ZRBMRQJVPLAFWCILSE","ledger":"Invalid symbol 123, offset 0.",
 "presto":"K7R","releaseStream":"current","sessionKind":"local",
 "witness":"9e7504de-8c13-427c-9e7a-9ee610c2b9e4"}
```

Field decoding:
- `nextal` / `herald` = **campaign ID** `ZRBMRQJVPLAFWCILSE` (matches the
  string embedded in `.rdata`).
- `warden` / `witness` = persistent machine/session UUID. Verified identical
  (`9e7504de-8c13-427c-9e7a-9ee610c2b9e4`) across two separate runs on the same
  host — usable for tracking. It is *not* the same as the `compass` UUID stored
  in `layout.conf`.
- `dispatch` / `eventScope` = event type (`survey` / `notice`).
- `presto` = short status tag (`K7R`).
- `ledger` = status/error string; here it is a base64 decode error from the
  implant parsing the (fake) server reply.
- `clientMode`, `formatRevision`, `releaseStream`, `sessionKind`, `locale`,
  `osArch`, `osTarget`, `schemaRevision`, `timezone` = telemetry schema fields.

### 6.5 C2 protocol (reversed from the binary)

Message = `[key[8]=0x5A] || [seed: 4 bytes LE] || shuffle(rotate(xor(gzip(JSON))))`, then base64.

1. **gzip** — manual header `1f 8b 08 00 00 00 00 00 00 03`, deflate body.
2. **chained XOR** — `d[0] ^= key[9] ^ (seed & 0xff)`;
   `d[i] ^= d[i-1] ^ (i & 0xff) ^ ((seed >> (8*(i & 3))) & 0xff)`.
   For LuminaRead, `key[9] = 0xB7` (QuartzLine used `0xD7`).
3. **bit rotation** — `d[i] = rol(d[i], (seed + i) & 7)`.
4. **Fisher–Yates shuffle** — index array `[0..n-1]`, LCG state
   `s = s * multiplier + increment` (32-bit), `j = s % (i+1)`, swap `v[i]`, `v[j]`,
   starting `s = seed ^ n`. The multiplier/increment live in a runtime key
   structure (`state + 0xc28`); they are not static constants.
5. **seed** — 4 random bytes from `ProcessPrng` (bcryptprimitives.dll).

The 0x5A prefix and the per-message seed are what make each body look different.

---

## 7. Indicators of Compromise (IOCs)

### 7.1 Sample hashes

| SHA256 | Role |
|--------|------|
| `7e71e072fbf39e4aaebad71c0e9e3443f9a4455faf687eb87264019cac342c31` | **This sample** (LuminaRead_1.3994.39 / 1.6431.48) |
| `921eb55037b19e1642ed60c4b95686a52b3d58ce58985b09a7573a77ba4395b2` | LuminaRead_1.9857.87 |
| `7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3` | QuartzLine original installer (paperline.exe) |
| `25ea334b75beede8dcab4c4460313c3013c35e55c16cd066231d80ecfe4c0653` | quartzline.exe (newer build) |
| `069fd1e710b341fbe92337116779e6b50a40408f55f6547252cd2c05fe9c0527` | chrome-history-summarizer-v0.0.1.exe |
| `d287a970294d54db5ab3ac5f7e9525c303b9aceac7117b165385c5655717333b` | quartzline_takeover_carrier.exe |
| `4c073764737e96fecf9d3e28384b2db628446c512c2df3696689d0c5e045b811` | deployApp.ps1 |
| `74aaa6b54133bbb2e77b2ae874e9900a907c269058f798a0a1197288ba1f7124` | caira.exe (2nd stage RAT) |
| `3c813ea19ff2e3e2cf566ec69753ba637bb243b4b4e8416dc8ebf68e93016a1d` | hosthealth.exe |
| `0fa4082c6fda0c2885eade0e4f63a2abfeaa26581f903e6784682f5fbd9d0d77` | updater-helper.exe |
| `f4e255dfdf3d23774b0067797cac0f986f1690abbeec217eb60029dcaa7425f8` | IronBark installer |
| `835800058050be37366478c662f73d7fcb93a2669e44f98664546fbc8ee6c7ca` | ironbark.exe (3rd stage) |
| `8644bb2ba39ddad352e82cc8fc827986940dec126527ed1cb6fa532e002bea86` | leafdesk.exe (LeafDesk/Canvex build) |
| `7e4e1555fcdc8af2e4278bbb6f1f23ce` (MD5) | layout.conf dropped file |

### 7.2 C2 / infrastructure domains

| Domain | Role |
|--------|------|
| `apexesmasters.com` | LuminaRead C2 |
| `familypenguins.com` | LuminaRead C2 |
| `wombatswilson.com` | LuminaRead C2 |
| `maximalmaxing.com` | CLOUDHAZE C2 |
| `dreamscometrue.vip` | CLOUDHAZE C2 |
| `heatindexgreg.com` | CLOUDHAZE C2 |
| `lightiswinning.top` | CLOUDHAZE C2 |
| `spaceporcupines.com` | CLOUDHAZE C2 |
| `westbeavers.com` | QuartzLine C2 |
| `motherotters.com` | QuartzLine C2 |
| `healskills.com` | QuartzLine C2 |
| `tabbyottercub.com` | Caira C2 |
| `flawlessgradecheered.com` | Caira C2 |
| `topsmagnificentgrade.com` | Caira C2 |
| `commonhedgehogs.com` | IronBark C2 |
| `eagle.sterlingwaters.com` | phishing / payload |
| `foxbamboo.com` | malvertising |
| `pinkexploratorysearch.com` | Chrome search/new-tab hijack |
| `smallerbestsearch.com` | Chrome search/new-tab hijack |
| `searchedvictoryresults.com` | Chrome search/new-tab hijack |
| `yourtopsearchers.com` | search hijack |
| `thankyou.molehawks.com` | post-install page (QuartzLine) |
| `thankyou.charlottedetector.com` | post-install page (IronBark) |

### 7.3 C2 URL paths

```
/filament/prism...      /filament/photon...     /filament/resonance...
/filament/radiance...   /filament/prism          /filament/resonance
/quarry/vein            /quarry/deposit          /quarry/stratum
/quarry/gravel          /quarry/bedrock          /quarry/sandstone
/quarry/seam            /quarry/geode            /quarry/talc
/mosaic/anchor          /mosaic/shoal            /mosaic/current
/mosaic/harbor          /grove/heartwood         /grove/phloem
/grove/barkline         /pluto/zen               /pluto/oak
/piglet/trestle         /windlass
```

### 7.4 Delivery / redirect

| Indicator | Role |
|-----------|------|
| `beatramiro.com` | malvertising redirector |
| `softwareslizards.com` | ad redirect |
| `purplepandagroup.com` | IronBark ad redirect |
| `royalproductive.com` | IronBark ad redirect |
| `biggerworldclassstandard.com` | IronBark payload delivery |
| `guessgooseberries.com` | IronBark install reporting |
| `duskhollow.s3.us-east-2.amazonaws.com` | installer delivery |
| `chrome-history-backup.s3.us-east-2.amazonaws.com` | browser data upload |
| `alberfine.s3.us-east-2.amazonaws.com` | caira.exe delivery |
| `leolin15.s3.us-east-2.amazonaws.com` | hosthealth.exe delivery |
| `tidefern.s3.us-east-2.amazonaws.com` | IronBark installer delivery |
| `crematoriomascotas.com.ar` | fake LuminaRead auth page |

### 7.5 Host artifacts

```
%LOCALAPPDATA%\LuminaRead\layout.conf          (machine ID / config)
%LOCALAPPDATA%\LuminaRead\LuminaRead.exe       (persistent copy)
%LOCALAPPDATA%\QuartzLine\terrain.dat          (QuartzLine machine ID, "zenith=")
%LOCALAPPDATA%\QuartzLine\quartzline.exe
%LOCALAPPDATA%\Caira\caira.exe
%LOCALAPPDATA%\IronBark\ironbark.exe
%LOCALAPPDATA%\HostHealthCache\
%LOCALAPPDATA%\DevicePerfCache\
```

### 7.6 Scheduled tasks

```
<Brand>UpdateCheck                 %LOCALAPPDATA%\<Brand>\<brand>.exe --update-check [--uid=<id>]
CairaServiceCheck                  %LOCALAPPDATA%\Caira\caira.exe --check
IronbarkUpdateCheck                %LOCALAPPDATA%\IronBark\ironbark.exe --update-check
HostHealthCacheCheck-<32 hex>      (stager, self-deletes)
HostHealthCacheCleanup-<32 hex>    (stager, self-deletes)
```

### 7.7 Certificates

| Signer | Serial | Status |
|--------|--------|--------|
| Xiamen Jinduoduo Technology Consulting Co., Ltd. | `00D25F883C5D74CE4399BFC29D85EF3263` | **Valid** (LuminaRead) |
| Guangzhou Guoying Communication Technology Co., Ltd. | `1b56cb4e99fb9444645a1ce7ffc0a46b` | Revoked "Privilege Withdrawn" (QuartzLine) |
| Amir Dow | — | Revoked (IronBark) |

---

## 8. Capabilities & MITRE ATT&CK Mapping

| Observed capability | ATT&CK | Evidence |
|---------------------|--------|----------|
| Masquerading as legitimate PDF viewer | T1036.005 | "LuminaRead"/"DispatchView" branding, working PDF parser |
| Valid EV code signature | T1553.002 | Sectigo EV cert |
| Hidden module alongside decoy | T1027.002 | "zenith" backdoor in `C:\r\` |
| Persistent machine ID in config file | T1078 / T1546 | `layout.conf`, `terrain.dat` |
| Scheduled task persistence | T1053.005 | `<Brand>UpdateCheck`, CairaServiceCheck, IronbarkUpdateCheck |
| HTTPS C2 with custom obfuscation | T1071.001 / T1573 | `/filament/*`, gzip+XOR+shuffle+base64 |
| Command execution (hidden cmd /C) | T1059.003 | `commands.rs`, `cmd.exe /C` |
| Chromium profile read/replace | T1176 / T1539 | `profile.rs`, `--user-data-dir` |
| Browser force-close + relaunch | T1176 | `taskkill /F`, `--hide-crash-restore-bubble` |
| Chrome search/new-tab hijack | T1539 | pinkexploratorysearch.com etc. |
| Input capture (raw input, key state) | T1056.001 | GetAsyncKeyState, GetRawInputData, RegisterRawInputDevices |
| Screen capture | T1113 | BitBlt, CreateDIBSection |
| Anti-debug / guard pages | T1622 | VirtualProtect, `IsDebuggerPresent` patterns |
| VM/sandbox detection | T1497 | volume info, machine GUID, software policies |
| Follow-on payload staging | T1105 | Caira RAT, IronBark, history uploader |
| Credential/session exposure | T1555 | browser profile access, Chrome relaunch |

---

## 9. Risk Assessment & Recommendations

### Risk: **CRITICAL**

- Working backdoor with remote command execution and browser-profile access.
- Valid EV signature → bypasses SmartScreen and many AV/EDR reputation checks.
- Low network footprint → hard to detect; sandboxes often score it clean.
- Persistence via scheduled tasks survives file deletion.
- Follow-on stages include a RAT and browser data theft.

### Recommended actions

1. **Isolate** any host that executed the sample.
2. **Remove persistence first** (scheduled tasks), then processes, then files:
   - Delete tasks: `<Brand>UpdateCheck`, `CairaServiceCheck`, `IronbarkUpdateCheck`, `HostHealthCache*`.
   - Remove `%LOCALAPPDATA%\LuminaRead`, `\QuartzLine`, `\Quartz`, `\Caira`, `\IronBark`, `\HostHealthCache`, `\DevicePerfCache`.
3. **Treat browser-stored passwords, cookies, and sessions as exposed** — reset credentials and sign out active sessions for affected users.
4. **Block** the C2 domains, URL paths (`/filament/*`, `/quarry/*`, `/mosaic/*`, `/grove/*`, `/pluto/*`, `/piglet/*`), and sample hashes at DNS/proxy/EDR.
5. **Hunt** for:
   - `layout.conf` / `terrain.dat` with a machine-ID line.
   - HTTPS POSTs with **no User-Agent** to the C2 paths.
   - A non-browser process running `cmd.exe /C` or `taskkill /F` on Chrome then relaunching with `--user-data-dir`.
   - The Xiamen Jinduoduo certificate thumbprint `4184F429EA40513117FA8603E87F770B0881370E1BEA0965236152234711AEA3`.
6. **Report** the cert to Sectigo / CertGraveyard (abused EV cert).
7. **Do not trust** the "valid signature" — the signer is unrelated to the product.

---

## 10. Artifacts & Reproduction

All analysis was performed inside the local Docker sandbox (`re-full` image, `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, sample mounted read-only). No sample execution on the host.

Case directory: `~/Work/re-analysis/ID-5980443/`
- `samples/ID-5980443.zip` — original password-protected archive
- `output/extracted/LuminaRead_1.3994.39.exe` — extracted sample
- `output/static_triage.txt` — PE headers, sections, imports, strings
- `output/deep_static.txt` — version info, UTF-16 strings, app strings
- `output/resources/` — extracted icon, version, manifest
- `output/resources_out.txt` — resource dump, IPs, entropy
- `output/xref_out.txt`, `output/xref_disasm.txt`, `output/disasm2.txt` — xref/disassembly
- `output/update_disasm.txt` — update module disassembly
- `output/crate_strings.txt`, `output/c2_config.txt` — C2/config vocabulary
- `work/` — analysis scripts (`pe_triage.py`, `deep_static.py`, `xref.py`, `annotate.py`, `dump_va.py`, `resources.py`, `dump_regions.py`)
- `output/iocs.txt`, `output/iocs.json` — machine-readable IOCs
- `output/decrypted_checkin.json` — decrypted live C2 check-in
- `output/certs/` — extracted Authenticode certificate: `Xiamen_Jinduoduo_leaf.pem`/`.der`, `authenticode-chain.p7b`, `chain.pem`, `indicators.txt`
- `output/https_requests.log` — captured fake-C2 HTTP requests
- `output/dns.log` — captured DNS queries (C2 domain discovery)
- `output/strace.log` — syscall trace showing connect() to the C2
- `work/LuminaRead_patched.exe` — analysis copy with the shuffle patched to identity
- `work/dns_server.py`, `work/https_server.py`, `work/add_cert.sh` — fake C2 setup
- `work/patch_identity.py`, `work/decrypt2.py` — protocol reversal / decryption

### Key sandbox commands used

```bash
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
  --user 1000:1000 \
  -v "$PWD/samples:/samples:ro" -v "$PWD/output:/output" -v "$PWD/work:/work" \
  --entrypoint /bin/bash re-full:latest -c '<analysis command>'
```

---

## 11. Appendix

### 11.1 Sources

- ANY.RUN / Mandiant: CLOUDHAZE campaign (LinkedIn, 2026-10-19/20)
- Expel: "QuartzLine: A working PDF viewer with a backdoor inside" (2026-10-15, updated 2026-10-21)
- Rogue Authority: "A signed PDF viewer that quietly takes orders: the QuartzLine 'zenith' backdoor" (2026-10-09)
- Fraunhofer FKIE Malpedia: `win.cloudhaze`
- Joe Sandbox: analysis 1968673 (this exact hash)
- Hybrid Analysis: `malicious_confidence_100%`, score 100/100
- CrowdStrike CQL / HuntPack: QuartzLine (CLOUDHAZE) hunt queries
- isMalicious: CLOUDHAZE IOC set

### 11.2 Detection-evasion notes

- Sandbox scores were low (ANY.RUN 5/100, Joe 48/100) because the decoy app behaves normally and the server sent no tasks during analysis windows.
- The backdoor polls very rarely; short sandbox runs see only one check-in.
- One-character source-path edits (`mod.rt`, `main_window.rs`) defeat string-based rules.
- Valid EV cert defeats reputation checks.

### 11.3 Open questions / next steps

- **Dynamic analysis was performed** (see §6.4/§6.5): the sample was run in the
  sandbox against a loopback fake-TLS C2, the check-in was captured and
  decrypted, and `layout.conf` was recovered. All work stayed inside the
  `re-full` container (`--network none` except loopback, caps dropped).
- The real LCG multiplier/increment used by the Fisher–Yates shuffle are in a
  runtime key structure (`state+0xc28`); they were not recovered statically.
  The check-in was decrypted by patching the shuffle to the identity
  permutation (analysis-only patch on a copy in `work/`).
- The exact Chromium profile files targeted by the browser-tampering tasking
  are unknown (server-supplied; never observed in public runs).
- The `warden`/`witness` UUID is a persistent machine identifier (stable across
  runs), but it differs from the `compass` UUID in `layout.conf`; the derivation
  between the two is unknown.
- No live tasking was observed (the real C2 sent "nothing to do" in all public
  reports; our fake server also received only the two check-ins).
