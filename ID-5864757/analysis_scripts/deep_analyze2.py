import dnfile
import struct

pe = dnfile.dnPE("/sample.exe")

print("=" * 70)
print("  DEEP .NET ANALYSIS - ID-5864757 (Round 2)")
print("=" * 70)
print()

# TypeDef - show all types
print("=== ALL TYPES ===")
for row in pe.net.mdtables.TypeDef:
    name = row.TypeName.value
    ns = row.TypeNamespace.value
    full = f"{ns}.{name}" if ns else name
    flags = row.Flags if hasattr(row, 'Flags') else 0
    # Only show our app types
    if 'TXTconverter' in full or 'Installer' in full:
        print(f"  {full}")

print()
print("=== ALL METHODS (interesting) ===")
for row in pe.net.mdtables.MethodDef:
    name = row.Name.value
    if any(kw in name.lower() for kw in ['install', 'download', 'start', 'execute', 'run', 'shell', 'process', 'registry', 'machine', 'payload', 'invoke', 'timer', 'load', 'main', 'begin', '.ctor', '.cctor', 'dispose', 'finalize', 'onload', 'onstartup', 'install']):
        # Get RVA - it's stored differently in dnfile
        rva = row.Rva if hasattr(row, 'Rva') else 0
        if isinstance(rva, int):
            rva_val = rva
        else:
            rva_val = rva.value if hasattr(rva, 'value') else 0
        
        # Try to get method body
        il_preview = ""
        if rva_val > 0:
            try:
                data = pe.get_data(rva_val, 16)
                if data:
                    # Check tiny header (first 2 bits = 10)
                    if len(data) >= 1 and (data[0] & 0x03) == 0x02:
                        code_size = data[0] >> 2
                        il_preview = data[1:1+min(code_size, 24)].hex()
                    elif len(data) >= 12 and (data[0] & 0x03) == 0x03:
                        flags_fat = struct.unpack_from("<H", data, 0)[0]
                        header_size = (flags_fat >> 12) * 4
                        code_size = struct.unpack_from("<I", data, 4)[0]
                        il_preview = data[header_size:header_size+min(code_size, 24)].hex()
            except:
                il_preview = "error"
        
        print(f"  {name}")
        if il_preview:
            print(f"    IL: {il_preview}")

print()
print("=== MEMBER REFERENCES (External Method Calls) ===")
for row in pe.net.mdtables.MemberRef:
    name = row.Name.value
    if any(kw in name.lower() for kw in ['download', 'install', 'execute', 'shell', 'process', 'registry', 'create', 'invoke', 'begininvoke', 'downloadstring', 'downloadfile', 'frombase64', 'memorystream', 'deflate', 'gzip', 'socket', 'connect', 'send', 'recv', 'bind', 'listen', 'accept', 'get', 'post', 'put', 'delete', 'head', 'options', 'add', 'remove', 'clear', 'close', 'dispose', 'abort', 'sleep', 'exit', 'kill', 'terminate', 'suspend', 'resume', 'wait', 'lock', 'unlock', 'enter', 'leave', 'trycatch', 'throw', 'exception', 'error', 'log', 'write', 'read', 'open', 'save', 'delete', 'copy', 'move', 'rename', 'exists', 'get', 'set']):
        # Get the class that owns this member ref
        cls = ""
        if hasattr(row, 'Class') and row.Class:
            cls_row = row.Class
            if hasattr(cls_row, 'row_index'):
                cls = f"#{cls_row.row_index}"
            else:
                cls = str(type(cls_row).__name__)
        print(f"  {name} (Class: {cls})")

print()
print("=== TYPE REFERENCES (External Types Used) ===")
for row in pe.net.mdtables.TypeRef:
    name = row.TypeName.value
    ns = row.TypeNamespace.value
    full = f"{ns}.{name}" if ns else name
    if any(kw in full.lower() for kw in ['system.net', 'system.io', 'system.security', 'system.cryptography', 'system.diagnostics', 'system.threading', 'system.componentmodel', 'system.runtime', 'system.reflection', 'system.text', 'system.xml', 'system.linq', 'system.collections', 'microsoft.win32', 'registry', 'file', 'path', 'directory', 'stream', 'memory', 'crypto', 'network', 'web', 'http', 'socket', 'process', 'diagnostics', 'threading', 'task', 'async', 'await', 'delegate', 'event', 'timer', 'callback', 'proxy', 'download', 'upload', 'install']):
        print(f"  {full}")

print()
print("=== FIELDS ===")
for row in pe.net.mdtables.Field:
    name = row.Name.value
    if any(kw in name.lower() for kw in ['url', 'endpoint', 'server', 'host', 'port', 'path', 'install', 'download', 'machine', 'guid', 'key', 'token', 'password', 'credential', 'config', 'setting', 'callback', 'proxy', 'timeout', 'retry', 'attempt', 'count', 'max', 'min', 'default', 'value', 'flag', 'debug', 'verbose', 'silent', 'hidden', 'visible', 'enabled', 'disabled']):
        print(f"  {name}")

print()
print("=== PARAMETERS ===")
for row in pe.net.mdtables.Param:
    name = row.Name.value
    if name and any(kw in name.lower() for kw in ['url', 'path', 'file', 'name', 'data', 'buffer', 'size', 'count', 'index', 'key', 'value', 'flag', 'option', 'config', 'setting', 'param', 'arg']):
        print(f"  {name}")

