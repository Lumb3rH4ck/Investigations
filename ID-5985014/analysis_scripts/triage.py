#!/usr/bin/env python3
import sys, os, math, hashlib, struct
import pefile

path = sys.argv[1]
print(f"[*] Analyzing: {path}")
print(f"[*] Size: {os.path.getsize(path)} bytes")

with open(path, "rb") as f:
    data = f.read()
print(f"[*] MD5:    {hashlib.md5(data).hexdigest()}")
print(f"[*] SHA1:   {hashlib.sha1(data).hexdigest()}")
print(f"[*] SHA256: {hashlib.sha256(data).hexdigest()}")

# entropy
def entropy(b):
    if not b:
        return 0.0
    counts = [0]*256
    for x in b:
        counts[x] += 1
    e = 0.0
    n = len(b)
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e
print(f"[*] Overall entropy: {entropy(data):.4f}")

pe = pefile.PE(data=data, fast_load=False)
print("\n=== PE HEADERS ===")
print(f"Machine:            0x{pe.FILE_HEADER.Machine:04x}")
print(f"NumberOfSections:   {pe.FILE_HEADER.NumberOfSections}")
print(f"TimeDateStamp:      {pe.FILE_HEADER.TimeDateStamp} ({pe.FILE_HEADER.dump_dict().get('TimeDateStamp',{}).get('Value','?')})")
print(f"PointerToSymbolTable: 0x{pe.FILE_HEADER.PointerToSymbolTable:x}")
print(f"NumberOfSymbols:    {pe.FILE_HEADER.NumberOfSymbols}")
print(f"SizeOfOptionalHeader: {pe.FILE_HEADER.SizeOfOptionalHeader}")
print(f"Characteristics:    0x{pe.FILE_HEADER.Characteristics:04x}")

print("\n=== OPTIONAL HEADER ===")
oh = pe.OPTIONAL_HEADER
print(f"Magic:              0x{oh.Magic:04x}")
print(f"AddressOfEntryPoint: 0x{oh.AddressOfEntryPoint:x}")
print(f"ImageBase:          0x{oh.ImageBase:x}")
print(f"SectionAlignment:   0x{oh.SectionAlignment:x}")
print(f"FileAlignment:      0x{oh.FileAlignment:x}")
print(f"SizeOfImage:        0x{oh.SizeOfImage:x}")
print(f"SizeOfHeaders:      0x{oh.SizeOfHeaders:x}")
print(f"Subsystem:          {oh.Subsystem}")
print(f"DllCharacteristics: 0x{oh.DllCharacteristics:04x}")
print(f"NumberOfRvaAndSizes: {oh.NumberOfRvaAndSizes}")
print(f"CheckSum:           0x{oh.CheckSum:08x}")
print(f"LoaderFlags:        0x{oh.LoaderFlags:x}")

print("\n=== SECTIONS ===")
print(f"{'Name':<10} {'VMA':>10} {'VSz':>10} {'RawPtr':>10} {'RawSz':>10} {'Ent':>7} {'Chars':>10}")
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1', 'replace')
    sec_data = s.get_data()
    print(f"{name:<10} 0x{s.VirtualAddress:08x} 0x{s.Misc_VirtualSize:08x} 0x{s.PointerToRawData:08x} 0x{s.SizeOfRawData:08x} {entropy(sec_data):7.3f} 0x{s.Characteristics:08x}")

print("\n=== IMPORTS ===")
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('latin1', 'replace')
        print(f"\n  [{dll}]")
        for imp in entry.imports:
            if imp.name:
                print(f"    {imp.name.decode('latin1','replace')}")
            else:
                print(f"    Ordinal #{imp.ordinal}")
else:
    print("  (none)")

print("\n=== DELAYED IMPORTS ===")
if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        dll = entry.dll.decode('latin1', 'replace')
        print(f"\n  [{dll}]")
        for imp in entry.imports:
            if imp.name:
                print(f"    {imp.name.decode('latin1','replace')}")
else:
    print("  (none)")

print("\n=== EXPORTS ===")
if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print(f"  {sym.name}")
else:
    print("  (none)")

print("\n=== RESOURCES ===")
if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        print(f"  Type: {rtype.id if rtype.id is not None else rtype.name}")
        if hasattr(rtype, "directory"):
            for rid in rtype.directory.entries:
                print(f"    ID/Name: {rid.id if rid.id is not None else rid.name}")
                if hasattr(rid, "directory"):
                    for lang in rid.directory.entries:
                        off = lang.data.struct.OffsetToData
                        size = lang.data.struct.Size
                        print(f"      Lang: {lang.id} offset=0x{off:x} size=0x{size:x}")
                        rdata = pe.get_data(off, size)
                        print(f"      Entropy: {entropy(rdata):.4f}  head: {rdata[:64].hex()}")
else:
    print("  (none)")

print("\n=== TLS CALLBACKS ===")
if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    print(f"  StartAddressOfRawData: 0x{tls.StartAddressOfRawData:x}")
    print(f"  EndAddressOfRawData:   0x{tls.EndAddressOfRawData:x}")
    print(f"  AddressOfIndex:        0x{tls.AddressOfIndex:x}")
    print(f"  AddressOfCallBacks:    0x{tls.AddressOfCallBacks:x}")
else:
    print("  (none)")

print("\n=== DEBUG DIRECTORY ===")
if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
    for d in pe.DIRECTORY_ENTRY_DEBUG:
        print(f"  Type: {d.struct.Type}, TimeDateStamp: {d.struct.TimeDateStamp}")
        if hasattr(d, "entry") and d.entry:
            try:
                print(f"    PdbFileName: {d.entry.PdbFileName}")
            except Exception:
                pass
else:
    print("  (none)")

print("\n=== LOAD CONFIG ===")
if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
    lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    for attr in dir(lc):
        if not attr.startswith("_") and attr not in ("dump", "dump_dict", "get_field", "get_file_offset", "__dict__", "__weakref__", "__doc__", "__module__"):
            try:
                v = getattr(lc, attr)
                if isinstance(v, int):
                    print(f"  {attr}: 0x{v:x}")
            except Exception:
                pass
else:
    print("  (none)")

print("\n=== VERSION INFO ===")
if hasattr(pe, "VS_VERSIONINFO"):
    try:
        for fi in pe.FileInfo:
            for f in fi:
                if hasattr(f, "StringTable"):
                    for st in f.StringTable:
                        for k, v in st.entries.items():
                            print(f"  {k.decode('latin1','replace')}: {v.decode('latin1','replace')}")
    except Exception as e:
        print(f"  (error: {e})")
else:
    print("  (none)")

pe.close()
print("\n[*] Done")
