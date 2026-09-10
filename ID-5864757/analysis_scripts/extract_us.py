import struct
import pefile

pe = pefile.dnPE("/sample.exe") if False else pefile.PE("/sample.exe")

# Get metadata location
for dd in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    if dd.name == "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR":
        cli = pe.get_data(dd.VirtualAddress, 24)
        meta_rva = struct.unpack_from("<I", cli, 8)[0]
        meta_size = struct.unpack_from("<I", cli, 12)[0]
        break

raw_offset = pe.get_offset_from_rva(meta_rva)
meta = pe.__data__[raw_offset:raw_offset+meta_size]

# Parse header
ver_len = struct.unpack_from("<H", meta, 8)[0]
off = 12 + ver_len + 4  # skip magic, version, flags
stream_count = struct.unpack_from("<H", meta, off)[0]
off += 4

# Find streams
for _ in range(min(stream_count, 20)):
    s_rva = struct.unpack_from("<I", meta, off)[0]
    s_size = struct.unpack_from("<I", meta, off+4)[0]
    name_start = off + 8
    name_end = meta.find(b'\x00', name_start)
    s_name = meta[name_start:name_end].decode('ascii', errors='replace')
    name_len = ((name_end - name_start + 1) + 3) & ~3
    off += 8 + name_len
    
    if s_name == "#US":
        # User Strings heap - contains all string literals
        abs_off = raw_offset + s_rva
        heap = pe.__data__[abs_off:abs_off+s_size]
        
        print(f"#US Heap: {s_size} bytes")
        print("=" * 60)
        
        # Parse US heap entries
        # Format: first byte = encoding flags, then compressed length, then data
        pos = 0
        strings_found = []
        while pos < len(heap):
            if pos + 1 > len(heap):
                break
            first_byte = heap[pos]
            if first_byte == 0:
                pos += 1
                continue
            
            # Decode compressed length
            if first_byte < 0x80:
                length = first_byte
                data_start = pos + 1
            elif first_byte < 0xC0:
                if pos + 2 > len(heap):
                    break
                length = ((first_byte & 0x3F) << 8) | heap[pos+1]
                data_start = pos + 2
            else:
                if pos + 4 > len(heap):
                    break
                length = ((first_byte & 0x1F) << 24) | (heap[pos+1] << 16) | (heap[pos+2] << 8) | heap[pos+3]
                data_start = pos + 4
            
            if length == 0:
                pos = data_start
                continue
            
            if data_start + length > len(heap):
                break
            
            raw_str = heap[data_start:data_start+length]
            
            # Check for trailing type marker byte
            has_extra = length > 0 and raw_str[-1] in (0x01, 0xE0)
            if has_extra:
                raw_str = raw_str[:-1]
                length -= 1
            
            # Try to decode as UTF-16-LE (with ANSI fallback)
            try:
                decoded = raw_str.decode('utf-16-le', errors='replace')
                if decoded.strip() and any(c.isprintable() for c in decoded):
                    strings_found.append(decoded)
            except:
                pass
            
            pos = data_start + length + (1 if has_extra else 0)
        
        # Print all strings
        print(f"\nTotal strings in #US heap: {len(strings_found)}")
        print()
        
        # Print all
        for s in sorted(strings_found, key=lambda x: (len(x) > 200, len(x))):
            if len(s) < 300:
                print(f"  {s}")

