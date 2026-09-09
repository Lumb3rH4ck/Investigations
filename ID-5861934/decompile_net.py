import struct
import sys

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

with open('/workspace/OneStart_sandbox.exe', 'rb') as f:
    data = f.read()

# Find BSJB signature
bsjb_offset = data.find(b'BSJB')
if bsjb_offset == -1:
    print("No .NET metadata found")
    sys.exit(1)

print(f".NET metadata at offset 0x{bsjb_offset:06x}")

# Parse BSJB header
off = bsjb_offset
off += 4  # Signature
major_version = struct.unpack_from('<H', data, off)[0]; off += 2
minor_version = struct.unpack_from('<H', data, off)[0]; off += 2
print(f"Metadata version: {major_version}.{minor_version}")

off += 4  # Reserved
version_len = struct.unpack_from('<I', data, off)[0]; off += 4
version_str = data[off:off+version_len].decode('utf-8', errors='replace').rstrip('\x00')
off += version_len
# Align to 4 bytes
off = (off + 3) & ~3
print(f"Runtime version: {version_str}")

off += 2  # Flags
streams_count = struct.unpack_from('<H', data, off)[0]; off += 2
print(f"Number of streams: {streams_count}")

# Parse stream headers
for i in range(streams_count):
    stream_offset = struct.unpack_from('<I', data, off)[0]; off += 4
    stream_size = struct.unpack_from('<I', data, off)[0]; off += 4
    name_start = off
    while data[off] != 0:
        off += 1
    stream_name = data[name_start:off].decode('utf-8', errors='replace')
    off += 1
    # Align to 4 bytes
    off = (off + 3) & ~3
    
    abs_offset = bsjb_offset + stream_offset
    print(f"\nStream #{i}: '{stream_name}' offset=0x{abs_offset:06x} size=0x{stream_size:06x}")
    
    if stream_name == '#~':
        # Parse ~Stream (tables stream)
        s_off = abs_offset
        s_off += 4  # Reserved
        s_off += 1  # Major version
        s_off += 1  # Minor version
        heap_sizes = data[s_off]; s_off += 1
        s_off += 1  # Reserved
        valid = struct.unpack_from('<Q', data, s_off)[0]; s_off += 8
        sorted = struct.unpack_from('<Q', data, s_off)[0]; s_off += 8
        
        # Count bits set in valid
        valid_bits = bin(valid).count('1')
        print(f"  Heap sizes: 0x{heap_sizes:02x} (strings={heap_sizes&0x1}, guid={heap_sizes&0x2}, blob={heap_sizes&0x4})")
        print(f"  Valid tables: {valid_bits}")
        
        # Read row counts for each valid table
        row_counts = []
        for j in range(valid_bits):
            rc = struct.unpack_from('<I', data, s_off)[0]; s_off += 4
            row_counts.append(rc)
        
        # Table names in order
        table_names = [
            'Module', 'TypeRef', 'TypeDef', 'FieldPtr', 'Field', 'MethodPtr',
            'Method', 'ParamPtr', 'Param', 'InterfaceImpl', 'MemberRef', 'Constant',
            'CustomAttribute', 'FieldMarshal', 'DeclSecurity', 'ClassLayout',
            'FieldLayout', 'StandAloneSig', 'EventMap', 'EventPtr', 'Event',
            'PropertyMap', 'PropertyPtr', 'Property', 'MethodSemantics', 'MethodImpl',
            'ModuleRef', 'TypeSpec', 'ImplMap', 'FieldRVA', 'ENCLog', 'ENCMap',
            'Assembly', 'AssemblyProcessor', 'AssemblyOS', 'AssemblyRef',
            'AssemblyRefProcessor', 'AssemblyRefOS', 'File', 'ExportedType',
            'ManifestResource', 'NestedClass', 'GenericParam', 'MethodSpec',
            'GenericParamConstraint'
        ]
        
        valid_idx = 0
        for j in range(64):
            if valid & (1 << j):
                name = table_names[j] if j < len(table_names) else f'Table{j}'
                print(f"  {name}: {row_counts[valid_idx]} rows")
                valid_idx += 1
        
    elif stream_name == '#Strings':
        # Parse strings heap
        s_off = abs_offset + 1  # Skip first byte
        strings_found = []
        while s_off < abs_offset + stream_size:
            length, new_off = read_compressed_uint(data, s_off)
            if length == 0:
                s_off = new_off
                continue
            try:
                s = data[new_off:new_off+length].decode('utf-8', errors='replace')
                if len(s) > 3 and any(c.isalpha() for c in s):
                    strings_found.append((new_off, s))
            except:
                pass
            s_off = new_off + length
        
        # Filter for interesting strings
        interesting = []
        keywords = ['http', 'url', 'download', 'install', 'omaha', 'analytics', 'config', 'domain', 'api', 'endpoint', 'track', 'log', 'report', 'event', 'impression', 'uninstall', 'changelog', 'terms', 'privacy', 'about']
        for offset_s, s in strings_found:
            lower = s.lower()
            if any(kw in lower for kw in keywords):
                interesting.append((offset_s, s))
        
        print(f"  Total strings: {len(strings_found)}")
        print(f"  Interesting strings:")
        for off_s, s in interesting[:50]:
            print(f"    0x{off_s:06x}: {s[:120]}")
    
    elif stream_name == '#US':
        # User strings heap
        s_off = abs_offset + 1  # Skip first byte
        user_strings = []
        while s_off < abs_offset + stream_size:
            length, new_off = read_compressed_uint(data, s_off)
            if length == 0:
                s_off = new_off
                continue
            # US heap strings have a trailing byte
            actual_len = length - 1 if length > 0 else 0
            try:
                s = data[new_off:new_off+actual_len].decode('utf-16-le', errors='replace')
                if len(s) > 2 and any(c.isalpha() for c in s):
                    user_strings.append((new_off, s))
            except:
                pass
            s_off = new_off + length
        
        # Filter for interesting
        keywords = ['http', 'url', 'download', 'install', 'omaha', 'analytics', 'config', 'domain', 'api', 'endpoint', 'track', 'log', 'report', 'event', 'impression', 'uninstall', 'changelog', 'terms', 'privacy', 'about', 'onestart', 'setup', 'stub']
        interesting = []
        for offset_s, s in user_strings:
            lower = s.lower()
            if any(kw in lower for kw in keywords):
                interesting.append((offset_s, s))
        
        print(f"  Total user strings: {len(user_strings)}")
        print(f"  Interesting user strings:")
        for off_s, s in interesting[:50]:
            print(f"    0x{off_s:06x}: {s[:120]}")
    
    elif stream_name == '#GUID':
        guid_count = stream_size // 16
        print(f"  GUID count: {guid_count}")
        for g in range(min(guid_count, 5)):
            guid = data[abs_offset + g*16:abs_offset + g*16 + 16]
            print(f"  GUID[{g}]: {guid.hex()}")
    
    elif stream_name == '#Blob':
        print(f"  Blob heap size: {stream_size} bytes")
