import pefile

pe = pefile.PE("MDE_File_Sample_173ca697f0387c389dbf4cf635dc9bf3345c0f48/balloons.exe")

print("=== PE Header ===")
print(f"Machine: {pe.FILE_HEADER.Machine:#x}")
print(f"Sections: {pe.FILE_HEADER.NumberOfSections}")
print(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
print(f"Entry Point: {pe.OPTIONAL_HEADER.AddressOfEntryPoint:#x}")
print(f"Image Base: {pe.OPTIONAL_HEADER.ImageBase:#x}")
print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
print(f"DLL Characteristics: {pe.OPTIONAL_HEADER.DllCharacteristics:#x}")

print("\n=== Sections ===")
for s in pe.sections:
    name = s.Name.decode().strip('\x00')
    print(f"  {name:10} VA:{s.VirtualAddress:#10x} VS:{s.Misc_VirtualSize:#10x} Raw:{s.SizeOfRawData:#10x} Char:{s.Characteristics:#10x}")

print("\n=== Imports ===")
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode()
        funcs = [i.name.decode() if i.name else f"ord#{i.ordinal}" for i in entry.imports[:8]]
        print(f"  {dll}: {', '.join(funcs)}")
        if len(entry.imports) > 8:
            print(f"    ... and {len(entry.imports)-8} more")

print("\n=== Resources ===")
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries[:10]:
        name = entry.name if entry.name else f"ID:{entry.id}"
        print(f"  {name}")

print("\n=== Debug Info ===")
if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
    for entry in pe.DIRECTORY_ENTRY_DEBUG:
        print(f"  Type: {entry.struct.Type}, TimeDateStamp: {entry.struct.TimeDateStamp}")

print("\n=== TLS Callbacks ===")
if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
    print(f"  TLS directory present: {pe.DIRECTORY_ENTRY_TLS.struct}")
