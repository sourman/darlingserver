#!/usr/bin/env python3
"""Userspace vm_map sends COPY_SEND (19). The kernel server stub is generated
with KERNEL_SERVER, so its type check only accepts MOVE_SEND (17). Accept both.
"""
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
needle = "kern_return_t __MIG_check__Request__mach_vm_map_external_t("
start = text.find(needle)
if start < 0:
    sys.exit("mach_vm_map_external type check not found")
end = text.find("_Xmach_vm_map_external", start + len(needle))
chunk = text[start:end]
old = "In0P->object.disposition != 17"
new = "(In0P->object.disposition != 17 && In0P->object.disposition != 19)"
if old not in chunk:
    if new in chunk:
        sys.exit(0)
    sys.exit("disposition check not found")
chunk = chunk.replace(old, new, 1)
path.write_text(text[:start] + chunk + text[end:])
