import pefile, struct, math

pe = pefile.PE('/workspace/updater_inner.exe')

print('=== Inner Updater PE ===')
print(f'Machine: 0x{pe.FILE_HEADER.Machine:04x} (x64)')
print(f'Sections: {pe.FILE_HEADER.NumberOfSections}')
print(f'Timestamp: {pe.FILE_HEADER.TimeDateStamp}')

for section in pe.sections:
    name = section.Name.decode().strip('\x00')
    entropy = section.get_entropy()
    print(f'  {name:10s} RawSize: 0x{section.SizeOfRawData:08x} Entropy: {entropy:.4f}')

print(f'\nImports ({len(pe.DIRECTORY_ENTRY_IMPORT)} DLLs):')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    funcs = [i.name.decode() if i.name else f'ord_{i.ordinal}' for i in entry.imports[:8]]
    print(f'  {dll}: {", ".join(funcs)}')

with open('/workspace/updater_inner.exe', 'rb') as f:
    data = f.read()

idx = data.find(bytes([0x37,0x7a,0xbc,0xaf,0x27,0x1c]))
if idx != -1:
    print(f'\nNested 7z archive at offset 0x{idx:06x}')
    header = data[idx:idx+32]
    next_offset = int.from_bytes(header[12:20], 'little')
    next_size = int.from_bytes(header[20:28], 'little')
    print(f'  Next header offset: 0x{next_offset:x}, size: 0x{next_size:x}')

idx = 0
while True:
    idx = data.find(b'MZ', idx)
    if idx == -1:
        break
    if idx + 64 < len(data):
        pe_off = struct.unpack_from('<I', data, idx + 0x3C)[0]
        if 0 < pe_off < 0x10000 and idx + pe_off + 4 < len(data):
            if data[idx + pe_off:idx + pe_off + 4] == b'PE\x00\x00':
                print(f'  Embedded PE at 0x{idx:06x}')
    idx += 1

pe.close()
