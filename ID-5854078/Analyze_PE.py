#!/usr/bin/env python3
"""
Analyze_PE.py - Comprehensive PE (Windows executable) file analysis.
Works for .exe, .dll, .sys, .ocx, .scr, and other PE-format files.

Usage:
    python3 Analyze_PE.py <file>              # Full analysis
    python3 Analyze_PE.py <file> --quick      # Quick scan
    python3 Analyze_PE.py <file> --strings    # Strings only
    python3 Analyze_PE.py <file> --imports    # Imports only
    python3 Analyze_PE.py <file> --sections   # Sections only
    python3 Analyze_PE.py <file> --resources  # Resources only
    python3 Analyze_PE.py <file> --yara       # YARA rule matching
"""

import sys
import os
import math
import hashlib
import datetime
from pathlib import Path

try:
    import pefile
except ImportError:
    print("Error: pefile not installed. Run: pip install pefile")
    sys.exit(1)


def entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    for f in freq:
        if f:
            p = f / len(data)
            ent -= p * math.log2(p)
    return ent


def file_hashes(filepath):
    """Calculate file hashes."""
    data = Path(filepath).read_bytes()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def analyze_header(pe):
    """Analyze PE header information."""
    header = {}
    header["machine"] = f"0x{pe.FILE_HEADER.Machine:04x}"
    header["machine_type"] = {
        0x14c: "i386 (x86)",
        0x8664: "AMD64 (x64)",
        0x1c0: "ARM",
        0xaa64: "ARM64",
    }.get(pe.FILE_HEADER.Machine, "Unknown")
    header["sections"] = pe.FILE_HEADER.NumberOfSections
    header["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    try:
        header["compile_time"] = datetime.datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp
        ).isoformat()
    except (ValueError, OSError):
        header["compile_time"] = "Invalid"

    opt = {}
    opt["entry_point"] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}"
    opt["image_base"] = f"0x{pe.OPTIONAL_HEADER.ImageBase:08x}"
    opt["subsystem"] = {
        1: "Native",
        2: "Windows GUI",
        3: "Windows Console",
        5: "OS/2 Console",
        7: "POSIX Console",
        9: "Windows CE GUI",
        10: "EFI Application",
        11: "EFI Boot Service Driver",
        12: "EFI Runtime Driver",
        13: "EFI ROM",
        14: "XBox",
        16: "Windows Boot Application",
    }.get(pe.OPTIONAL_HEADER.Subsystem, f"Unknown ({pe.OPTIONAL_HEADER.Subsystem})")
    opt["dll_characteristics"] = f"0x{pe.OPTIONAL_HEADER.DllCharacteristics:04x}"

    opt["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    opt["is_system"] = bool(pe.FILE_HEADER.Characteristics & 0x1000)

    return {"header": header, "optional": opt}


def analyze_sections(pe):
    """Analyze PE sections."""
    sections = []
    for s in pe.sections:
        name = s.Name.decode("utf-8", errors="replace").strip("\x00")
        data = s.get_data()
        ent = entropy(data)
        flags = []
        chars = s.Characteristics
        if chars & 0x20000000:
            flags.append("EXECUTE")
        if chars & 0x40000000:
            flags.append("READ")
        if chars & 0x80000000:
            flags.append("WRITE")
        if chars & 0x20:
            flags.append("CODE")
        if chars & 0x40:
            flags.append("INITIALIZED_DATA")
        if chars & 0x80:
            flags.append("UNINITIALIZED_DATA")

        suspicious = []
        if ent > 7.0:
            suspicious.append("HIGH_ENTROPY")
        if (chars & 0x20000000) and (chars & 0x40000000) and (chars & 0x80000000):
            suspicious.append("RWX")
        if name in ["UPX0", "UPX1", ".aspack", ".ndata"]:
            suspicious.append("PACKER_SECTION")

        sections.append({
            "name": name,
            "virtual_address": f"0x{s.VirtualAddress:08x}",
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(ent, 4),
            "characteristics": f"0x{chars:08x}",
            "flags": flags,
            "suspicious": suspicious,
        })
    return sections


def analyze_imports(pe):
    """Analyze imported DLLs and functions."""
    imports = []
    suspicious_apis = [
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "NtWriteVirtualMemory", "NtCreateThreadEx",
        "NtQueueApcThread", "SetThreadContext", "NtSetContextThread",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
        "WinHttpReadData", "WinHttpWriteData",
        "URLDownloadToFile", "URLDownloadToCacheFile", "URLOpenStream",
        "HttpOpenRequest", "HttpSendRequest", "InternetOpen", "InternetConnect",
        "InternetOpenUrl", "InternetReadFile",
        "CreateProcess", "CreateProcessA", "CreateProcessW", "ShellExecute",
        "ShellExecuteEx", "WinExec", "CreateProcessAsUser", "CreateProcessWithLogon",
        "RegSetValue", "RegCreateKey", "RegOpenKey", "RegDeleteKey",
        "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptDeriveKey",
        "CryptGenKey", "CryptImportKey",
        "CreateMutex", "OpenMutex",
        "SetWindowsHookEx", "CallNextHookEx", "UnhookWindowsHookEx",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "FindResource", "LoadResource", "SizeofResource", "LockResource",
        "GetAsyncKeyState", "SetCursorPos", "GetKeyState",
        "OpenProcess", "TerminateProcess", "ReadProcessMemory",
        "MapViewOfSection", "UnmapViewOfSection", "NtMapViewOfSection",
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
        "AllocateAndInitializeSid", "CheckTokenMembership",
    ]

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            found_suspicious = []
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("utf-8", errors="replace")
                    funcs.append(name)
                    for api in suspicious_apis:
                        if api.lower() in name.lower():
                            found_suspicious.append(name)
                else:
                    funcs.append(f"ord#{imp.ordinal}")

            imports.append({
                "dll": dll,
                "functions": funcs,
                "count": len(funcs),
                "suspicious": list(set(found_suspicious)),
            })

    return imports


def analyze_exports(pe):
    """Analyze exported functions."""
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("utf-8", errors="replace") if exp.name else f"ord#{exp.ordinal}"
            exports.append({
                "name": name,
                "ordinal": exp.ordinal,
                "address": f"0x{exp.address:08x}",
            })
    return exports


def analyze_resources(pe):
    """Analyze PE resources."""
    resources = []

    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_id = type_entry.id
            type_names = {
                1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU",
                5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT",
                9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
                12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION",
                17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD",
                21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
            }
            type_name = type_names.get(type_id, f"UNKNOWN({type_id})")

            if hasattr(type_entry, "directory"):
                for name_entry in type_entry.directory.entries:
                    if hasattr(name_entry, "directory"):
                        for lang_entry in name_entry.directory.entries:
                            data_rva = lang_entry.data.struct.OffsetToData
                            size = lang_entry.data.struct.Size
                            data = pe.get_data(data_rva, size)
                            ent = entropy(data)

                            suspicious = []
                            if ent > 7.0:
                                suspicious.append("HIGH_ENTROPY")
                            if size > 100000:
                                suspicious.append("LARGE_RESOURCE")

                            resources.append({
                                "type": type_name,
                                "id": name_entry.id,
                                "name": str(name_entry.name) if name_entry.name else None,
                                "size": size,
                                "entropy": round(ent, 4),
                                "suspicious": suspicious,
                            })

    return resources


def analyze_debug(pe):
    """Analyze debug directory."""
    debug = []
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            debug.append({
                "type": entry.struct.Type,
                "timestamp": entry.struct.TimeDateStamp,
                "size": entry.struct.SizeOfData,
            })
    return debug


def analyze_tls(pe):
    """Analyze TLS callbacks."""
    tls = None
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        tls = {
            "start": f"0x{pe.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData:08x}",
            "end": f"0x{pe.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData:08x}",
            "callbacks": f"0x{pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:08x}",
        }
    return tls


def analyze_signatures(pe):
    """Check for digital signatures."""
    if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
        return [{"type": entry.struct.wRevision, "size": entry.struct.cbCertData}
                for entry in pe.DIRECTORY_ENTRY_SECURITY]
    return []


def analyze_all(filepath):
    """Perform complete PE analysis."""
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return None

    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError as e:
        print(f"Error: Not a valid PE file: {e}")
        return None

    result = {
        "file": filepath,
        "hashes": file_hashes(filepath),
        "is_valid_pe": True,
        "header": analyze_header(pe),
        "sections": analyze_sections(pe),
        "imports": analyze_imports(pe),
        "exports": analyze_exports(pe),
        "resources": analyze_resources(pe),
        "debug": analyze_debug(pe),
        "tls": analyze_tls(pe),
        "signatures": analyze_signatures(pe),
    }

    pe.close()
    return result


def print_analysis(result, verbose=False):
    """Print formatted analysis results."""
    if not result:
        return

    print("=" * 70)
    print(f"PE Analysis: {result['file']}")
    print("=" * 70)

    # Hashes
    h = result["hashes"]
    print(f"\n[Hashes]")
    print(f"  MD5:    {h['md5']}")
    print(f"  SHA1:   {h['sha1']}")
    print(f"  SHA256: {h['sha256']}")
    print(f"  Size:   {h['size']:,} bytes")

    # Header
    hdr = result["header"]["header"]
    opt = result["header"]["optional"]
    print(f"\n[Header]")
    print(f"  Machine:     {hdr['machine_type']}")
    print(f"  Type:        {'DLL' if opt['is_dll'] else 'EXE'}")
    print(f"  Sections:    {hdr['sections']}")
    print(f"  Timestamp:   {hdr['compile_time']}")
    print(f"  Entry Point: {opt['entry_point']}")
    print(f"  Image Base:  {opt['image_base']}")
    print(f"  Subsystem:   {opt['subsystem']}")

    # Sections
    print(f"\n[Sections]")
    for s in result["sections"]:
        sus = f" [!] {', '.join(s['suspicious'])}" if s["suspicious"] else ""
        print(f"  {s['name']:10} VA:{s['virtual_address']} VS:{s['virtual_size']:#x} "
              f"Raw:{s['raw_size']:#x} E:{s['entropy']:.2f}{sus}")

    # Imports
    total_imports = sum(i["count"] for i in result["imports"])
    all_suspicious = set()
    for imp in result["imports"]:
        for s in imp["suspicious"]:
            all_suspicious.add(s)

    print(f"\n[Imports] ({total_imports} functions from {len(result['imports'])} DLLs)")
    if all_suspicious:
        print(f"  Suspicious APIs: {', '.join(sorted(all_suspicious))}")
    if verbose:
        for imp in result["imports"]:
            print(f"  {imp['dll']} ({imp['count']} functions)")
            if imp["suspicious"]:
                print(f"    [!] {', '.join(imp['suspicious'])}")

    # Exports
    if result["exports"]:
        print(f"\n[Exports] ({len(result['exports'])} functions)")
        for exp in result["exports"][:20]:
            print(f"  {exp['name']} (ord:{exp['ordinal']}) {exp['address']}")
        if len(result["exports"]) > 20:
            print(f"  ... and {len(result['exports'])-20} more")

    # Resources
    high_ent_res = [r for r in result["resources"] if r["suspicious"]]
    print(f"\n[Resources] ({len(result['resources'])} entries)")
    if high_ent_res:
        print(f"  High entropy/large resources:")
        for r in high_ent_res:
            print(f"    {r['type']} size={r['size']:,} entropy={r['entropy']:.2f}")

    # TLS
    if result["tls"]:
        print(f"\n[TLS Callbacks] (anti-debug)")
        print(f"  Callbacks at: {result['tls']['callbacks']}")

    # Signatures
    if result["signatures"]:
        print(f"\n[Digital Signatures] ({len(result['signatures'])} found)")
    else:
        print(f"\n[Digital Signatures] NONE - unsigned executable")

    # Debug
    if result["debug"]:
        print(f"\n[Debug Info] ({len(result['debug'])} entries)")

    print("\n" + "=" * 70)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="PE File Analysis Tool")
    parser.add_argument("file", help="PE file to analyze")
    parser.add_argument("--quick", action="store_true", help="Quick scan")
    parser.add_argument("--strings", action="store_true", help="Strings only")
    parser.add_argument("--imports", action="store_true", help="Imports only")
    parser.add_argument("--sections", action="store_true", help="Sections only")
    parser.add_argument("--resources", action="store_true", help="Resources only")
    parser.add_argument("--yara", help="YARA rules file to match")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.strings:
        os.system(f"strings -n 6 {args.file} | head -100")
        return

    if args.yara:
        try:
            import yara
            rules = yara.compile(filepath=args.yara)
            matches = rules.match(args.file)
            print(f"YARA matches: {matches}")
        except ImportError:
            print("yara-python not installed")
        return

    result = analyze_all(args.file)
    if result:
        print_analysis(result, args.verbose)


if __name__ == "__main__":
    main()
