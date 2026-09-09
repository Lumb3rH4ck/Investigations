import pefile
import struct
import sys
import os

pe = pefile.PE('/workspace/OneStart_sandbox.exe')

print("=== Extracting Resources ===")

output_dir = '/tmp/extracted'
os.makedirs(output_dir, exist_ok=True)

if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.name:
            print(f"\nResource directory: {entry.name}")
        else:
            print(f"\nResource directory ID: {entry.id}")
        
        if hasattr(entry, 'directory'):
            for e2 in entry.directory.entries:
                if hasattr(e2, 'directory'):
                    for e3 in e2.directory.entries:
                        data_rva = e3.data.struct.OffsetToData
                        size = e3.data.struct.Size
                        data = pe.get_data(data_rva, size)
                        
                        # Determine type
                        type_name = None
                        if hasattr(entry, 'name'):
                            type_name = str(entry.name)
                        else:
                            type_name = str(entry.id)
                        
                        name = f"type{type_name}_id{e2.id}"
                        if hasattr(e2, 'name') and e2.name:
                            name = str(e2.name)
                        
                        out_path = os.path.join(output_dir, f"{name}_{e3.id}.bin")
                        with open(out_path, 'wb') as f:
                            f.write(data)
                        print(f"  Extracted: {name}_{e3.id}.bin ({size} bytes)")
                        
                        # Detect file type
                        if data[:2] == b'MZ':
                            print(f"    -> PE/EXE file detected!")
                        elif data[:4] == b'\x89PNG':
                            print(f"    -> PNG image")
                        elif data[:3] == b'\xff\xd8\xff':
                            print(f"    -> JPEG image")
                        elif data[:4] == b'PK\x03\x04':
                            print(f"    -> ZIP archive")
                        elif b'BSJB' in data[:100]:
                            print(f"    -> .NET assembly")
                        elif data[:1] == b'{' or data[:1] == b'[':
                            try:
                                text = data[:200].decode('utf-8', errors='replace')
                                if 'http' in text.lower() or 'url' in text.lower():
                                    print(f"    -> Possible config/JSON: {text[:100]}")
                            except:
                                pass

print("\n=== Parsing .NET User Strings for URLs ===")
# Find the #US heap
bsjb = pe.get_data_rva(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
if bsjb:
    offset = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress
    # Parse metadata streams
    abs_offset = pe.get_offset_from_rva(offset)
    
    # Read BSJB header
    off = abs_offset + 4  # Skip signature
    off += 2 + 2  # Version
    off += 4  # Reserved
    version_len = struct.unpack_from('<I', pe.__data__, off)[0]; off += 4
    off += version_len
    off = (off + 3) & ~3
    off += 2  # Flags
    streams_count = struct.unpack_from('<H', pe.__data__, off)[0]; off += 2
    
    for _ in range(streams_count):
        stream_offset = struct.unpack_from('<I', pe.__data__, off)[0]; off += 4
        stream_size = struct.unpack_from('<I', pe.__data__, off)[0]; off += 4
        name_start = off
        while pe.__data__[off] != 0:
            off += 1
        stream_name = pe.__data__[name_start:off].decode('utf-8', errors='replace')
        off += 1
        off = (off + 3) & ~3
        
        if stream_name == '#US':
            # Parse user strings heap
            us_offset = abs_offset + stream_offset + 1  # Skip first byte
            us_end = abs_offset + stream_offset + stream_size
            
            while us_offset < us_end:
                length, us_offset = read_compressed_uint(pe.__data__, us_offset)
                if length == 0:
                    continue
                actual_len = length - 1 if length > 0 else 0
                try:
                    s = pe.__data__[us_offset:us_offset+actual_len].decode('utf-16-le', errors='replace')
                    if any(kw in s.lower() for kw in ['http', 'url', 'download', 'install', 'omaha', 'api', 'domain', 'setup', 'exe', 'config']):
                        print(f"  [{us_offset:06x}] {s[:200]}")
                except:
                    pass
                us_offset += length

def read_compressed_uint(data, offset):
    if data[offset] & 0x80 == 0:
        return data[offset], offset + 1
    elif data[offset] & 0xC0 == 0x80:
        val = ((data[offset] & 0x3F) << 8) | data[offset+1]
        return val, offset + 2
    elif data[offset] & 0xE0 == 0xC0:
        val = ((data[offset] & 0x1F) << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3]
        return val, offset + 4
    return 0, offset + 1

print("\n=== Searching for embedded PE files ===")
data = pe.__data__
idx = 0
while True:
    idx = data.find(b'MZ', idx)
    if idx == -1:
        break
    # Check if it's a valid PE
    if idx + 64 < len(data):
        pe_offset_offset = idx + 0x3C
        if pe_offset_offset + 4 <= len(data):
            pe_offset = struct.unpack_from('<I', data, pe_offset_offset)[0]
            if pe_offset > 0 and pe_offset < 0x10000 and idx + pe_offset + 4 < len(data):
                if data[idx + pe_offset:idx + pe_offset + 4] == b'PE\x00\x00':
                    print(f"  Found embedded PE at offset 0x{idx:06x}")
                    # Try to determine size
                    size_offset = idx + pe_offset + 20  # OptionalHeader offset
                    if size_offset + 4 <= len(data):
                        opt_size = struct.unpack_from('<H', data, size_offset + 20)[0]  # SizeOfImage
                        print(f"    SizeOfImage: 0x{opt_size:x}")
    idx += 1

print("\n=== Searching for URLs in raw binary ===")
url_patterns = [b'http://', b'https://']
for pattern in url_patterns:
    idx = 0
    while True:
        idx = data.find(pattern, idx)
        if idx == -1:
            break
        end = idx
        while end < len(data) and data[end] not in (0, 0x20, 0x0a, 0x0d, 0x22, 0x27, 0x3c, 0x3e):
            end += 1
        url = data[idx:end].decode('utf-8', errors='replace')
        print(f"  [{idx:06x}] {url}")
        idx = end

pe.close()
