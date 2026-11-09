#!/usr/bin/env python3
import re, glob, os, hashlib

files = [
    "/output/extracted/Shift - PDF_xyvckh.exe",
    "/output/headers/headers0.bin",
    "/output/headers/headers1.bin",
    "/output/unpacked/tmp/Win32Library.dll",
]

url_re = re.compile(rb"https?://[^\s\"'<>\\)]+", re.I)
dom_re = re.compile(rb"[a-zA-Z0-9][a-zA-Z0-9.-]{2,63}\.(?:com|net|org|io|ru|cn|xyz|top|cc|biz|info|co|me|tv|us|uk|de|fr|es|pt|app|dev|cloud|api)", re.I)
ip_re = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
hex_re = re.compile(rb"\b[0-9a-fA-F]{32}\b")
hex64_re = re.compile(rb"\b[0-9a-fA-F]{64}\b")
hex128_re = re.compile(rb"\b[0-9a-fA-F]{128,}\b")
guid_re = re.compile(rb"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")
mutex_re = re.compile(rb"Shift[A-Za-z]?-?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.I)
reg_re = re.compile(rb"(?:SOFTWARE|HKEY|HKLM|HKCU|HKCR|HKU|HKCC)[\\A-Za-z0-9_]+", re.I)

out = []
for f in files:
    if not os.path.exists(f):
        continue
    d = open(f, "rb").read()
    # also UTF-16 decode
    try:
        u16 = d.decode("utf-16-le", "ignore").encode("latin1", "ignore")
    except Exception:
        u16 = b""
    combined = d + b"\n" + u16
    out.append(f"\n########## {os.path.basename(f)} ({len(d)} bytes) ##########")
    for name, rx in [("URL", url_re), ("DOMAIN", dom_re), ("IP", ip_re),
                     ("MD5", hex_re), ("SHA256", hex64_re), ("HEX128+", hex128_re),
                     ("GUID", guid_re), ("MUTEX", mutex_re), ("REGKEY", reg_re)]:
        matches = sorted(set(m.group(0).decode("latin1", "replace") for m in rx.finditer(combined)))
        if matches:
            out.append(f"  [{name}] ({len(matches)})")
            for m in matches[:80]:
                out.append(f"    {m}")

text = "\n".join(out)
open("/output/iocs.txt", "w").write(text)
print(text)
