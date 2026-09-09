import pefile
import struct
import math

pe = pefile.PE('/workspace/UpdaterSetup.exe')

print('=== PE Header ===')
print(f'Machine: 0x{pe.FILE_HEADER.Machine:04x} (x64)')
print(f'Number of Sections: {pe.FILE_HEADER.NumberOfSections}')
print(f'TimeDateStamp: {pe.FILE_HEADER.TimeDateStamp}')

print('\n=== Sections ===')
for section in pe.sections:
    name = section.Name.decode().strip('\x00')
    entropy = section.get_entropy()
    print(f'  {name:10s} VA: 0x{section.VirtualAddress:08x} RawSize: 0x{section.SizeOfRawData:08x} Entropy: {entropy:.4f}')

print('\n=== Imports ===')
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    suspicious_dlls = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode()
        funcs = [i.name.decode() if i.name else f'ord_{i.ordinal}' for i in entry.imports]
        # Categorize
        susp = []
        for f in funcs:
            fl = f.lower()
            if any(kw in fl for kw in ['virtualalloc', 'virtualprotect', 'writeprocess', 'createremethread', 'ntqueue', 'rtlmovememory']):
                susp.append(f)
            elif any(kw in fl for kw in ['createprocess', 'winexec', 'shellexecute', 'createuserprocess']):
                susp.append(f)
            elif any(kw in fl for kw in ['regsetvalue', 'regcreatekey', 'regopenkey']):
                susp.append(f)
            elif any(kw in fl for kw in ['internet', 'url', 'http', 'wininet', 'winhttp']):
                susp.append(f)
            elif any(kw in fl for kw in ['crypt', 'encrypt', 'decrypt', 'hash', 'bcrypt']):
                susp.append(f)
            elif any(kw in fl for kw in ['socket', 'connect', 'send', 'recv', 'wsa']):
                susp.append(f)
        if susp:
            suspicious_dlls[dll] = susp
    
    print(f'  Total DLLs imported: {len(pe.DIRECTORY_ENTRY_IMPORT)}')
    print(f'\n  Suspicious APIs:')
    for dll, apis in suspicious_dlls.items():
        print(f'    {dll}: {", ".join(apis[:15])}')

print('\n=== Digital Signature ===')
if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
    print(f'  Security entries: {len(pe.DIRECTORY_ENTRY_SECURITY)}')
    for i, entry in enumerate(pe.DIRECTORY_ENTRY_SECURITY[:3]):
        print(f'  Entry {i}: type={entry.struct.wRevision}')

# Full file entropy
with open('/workspace/UpdaterSetup.exe', 'rb') as f:
    data = f.read()
freq = [0]*256
for b in data: freq[b] += 1
ent = -sum((f/len(data))*math.log2(f/len(data)) for f in freq if f)
print(f'\nFull file entropy: {ent:.4f}/8.0')

# Check for embedded PE
print('\n=== Embedded PE files ===')
idx = 0
while True:
    idx = data.find(b'MZ', idx)
    if idx == -1:
        break
    if idx + 64 < len(data):
        pe_offset_offset = idx + 0x3C
        if pe_offset_offset + 4 <= len(data):
            pe_offset = struct.unpack_from('<I', data, pe_offset_offset)[0]
            if pe_offset > 0 and pe_offset < 0x10000 and idx + pe_offset + 4 < len(data):
                if data[idx + pe_offset:idx + pe_offset + 4] == b'PE\x00\x00':
                    print(f'  Found embedded PE at offset 0x{idx:06x}')
    idx += 1

# Chrome updater specific strings
print('\n=== Chrome Updater Components ===')
strings_raw = data.decode('latin-1', errors='replace')
components = set()
for line in strings_raw.split('\x00'):
    if line.startswith('..\\..\\chrome\\updater'):
        # Extract component name
        parts = line.split('\\')
        if len(parts) > 4:
            comp = parts[-1].replace('.cc', '')
            components.add(comp)
for comp in sorted(components):
    print(f'  {comp}')

pe.close()
