#!/usr/bin/env python3
import os, sys, hashlib
import pefile

path = sys.argv[1]
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)

pe = pefile.PE(path)
print(f"[*] Extracting resources from {path}")

def sanitize(n):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in str(n))

if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        rtype_name = rtype.name if rtype.name is not None else str(rtype.id)
        for rid in rtype.directory.entries:
            rid_name = rid.name if rid.name is not None else str(rid.id)
            for lang in rid.directory.entries:
                off = lang.data.struct.OffsetToData
                size = lang.data.struct.Size
                data = pe.get_data(off, size)
                fname = f"res_{sanitize(rtype_name)}_{sanitize(rid_name)}_{lang.id}.bin"
                with open(os.path.join(outdir, fname), "wb") as f:
                    f.write(data)
                print(f"  {fname}  size={size} sha256={hashlib.sha256(data).hexdigest()[:16]}...")
pe.close()
print("[*] Done")
