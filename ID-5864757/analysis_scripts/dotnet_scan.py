import pefile
import re
import struct

pe = pefile.PE("/samples/sample.exe")

# Find .NET metadata
cli_rva = None
for dd in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    if dd.name == "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR":
        cli_data = pe.get_data(dd.VirtualAddress, 24)
        meta_rva = struct.unpack_from("<I", cli_data, 8)[0]
        meta_size = struct.unpack_from("<I", cli_data, 12)[0]
        break

raw_offset = pe.get_offset_from_rva(meta_rva)
meta = pe.__data__[raw_offset:raw_offset+meta_size]

print(f"Metadata: {len(meta)} bytes at RVA {meta_rva:#x}")
print(f"First 32 bytes: {meta[:32].hex()}")
print()

# Search for stream names
print("=== Stream Signatures ===")
for name in [b'#~', b'#Strings', b'#US', b'#GUID', b'#Blob']:
    idx = 0
    count = 0
    while count < 5:
        idx = meta.find(name, idx)
        if idx == -1:
            break
        context = meta[max(0,idx-8):min(len(meta), idx+32)]
        print(f"  {name.decode():12s} at {idx:#06x}: {context.hex()[:80]}")
        idx += 1
        count += 1

print()

# Extract all readable strings from metadata region
ascii_strs = re.findall(b'[\x20-\x7e]{8,}', meta)
print(f"Total ASCII strings in metadata: {len(ascii_strs)}")

# Type/Method names
print("\n=== .NET Type/Method Names ===")
type_names = [s.decode('ascii') for s in ascii_strs if 
    any(kw in s for kw in [b'TXTconverter', b'Installer', b'View', b'Service', b'Helper', b'Constants', b'Model', b'Command'])]
for s in sorted(set(type_names)):
    print(f"  {s}")

print("\n=== Suspicious Names ===")
sus_names = [s.decode('ascii') for s in ascii_strs if 
    any(kw in s.lower() for kw in [b'install', b'download', b'registry', b'machineguid', b'shell', b'exec',
     b'process', b'command', b'payload', b'base64', b'crypt', b'inject', b'persist', b'startup'])]
for s in sorted(set(sus_names)):
    print(f"  {s}")

# Also do full binary scan for base64 blocks
print("\n=== Full Binary Base64 Blocks ===")
full = pe.__data__
full_str = bytes(full) if not isinstance(full, bytes) else full
b64_blocks = re.findall(b'[A-Za-z0-9+/]{40,}={0,2}', full_str)
for b in sorted(set(b64_blocks)):
    print(f"  {b[:60].decode('latin-1')}...")

# PowerShell indicators
print("\n=== PowerShell Indicators ===")
ps = [s.decode('ascii', errors='replace') for s in ascii_strs if 
    any(kw in s.lower() for kw in [b'invoke', b'iex', b'scriptblock', b'runspace', b'pipeline', b'get-', b'set-', b'new-object', b'net.webclient'])]
for s in sorted(set(ps)):
    print(f"  {s}")

