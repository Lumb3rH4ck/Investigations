import pefile
import math

pe = pefile.PE('/workspace/OneStart_sandbox.exe')

print('=== PE Header ===')
print(f'Machine: 0x{pe.FILE_HEADER.Machine:04x}')
print(f'Number of Sections: {pe.FILE_HEADER.NumberOfSections}')
print(f'TimeDateStamp: {pe.FILE_HEADER.TimeDateStamp}')

print('\n=== Sections ===')
for section in pe.sections:
    name = section.Name.decode().strip('\x00')
    entropy = section.get_entropy()
    print(f'  {name:10s} VA: 0x{section.VirtualAddress:08x} RawSize: 0x{section.SizeOfRawData:08x} Entropy: {entropy:.4f}')

print('\n=== Imports ===')
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode()
        funcs = [i.name.decode() if i.name else f'ord_{i.ordinal}' for i in entry.imports]
        print(f'  {dll}: {", ".join(funcs)}')

print('\n=== .NET CLR Info ===')
if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
    print(f'  Version: {clr.struct.MajorRuntimeVersion}.{clr.struct.MinorRuntimeVersion}')

# Full file entropy
with open('/workspace/OneStart_sandbox.exe', 'rb') as f:
    data = f.read()
freq = [0]*256
for b in data: freq[b] += 1
ent = -sum((f/len(data))*math.log2(f/len(data)) for f in freq if f)
print(f'\nFull file entropy: {ent:.4f}/8.0')

pe.close()
