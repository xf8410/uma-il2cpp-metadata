#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELF 概况（libil2cpp.so 这种被改过分段的 build 用）

    python3 tools/elf_info.py metadata-YYYYMMDD/libil2cpp.so

输出：文件大小/sha256、ELF 头、全部 section（名称/偏移/虚拟地址/大小/标志）、
最后一个 section 之后是否有"附加数据"（这个 build 的 hook payload 就在那里）。
"""
import struct
import sys
import hashlib


def main(path):
    d = open(path, "rb").read()
    print("file    : %s" % path)
    print("size    : %d" % len(d))
    print("sha256  : %s" % hashlib.sha256(d).hexdigest())
    if d[:4] != b"\x7fELF":
        raise SystemExit("不是 ELF 文件")
    ei_class, ei_data = d[4], d[5]
    print("class   : %s" % ("ELF64" if ei_class == 2 else "ELF32"))
    print("endian  : %s" % ("LE" if ei_data == 1 else "BE"))
    if ei_class != 2 or ei_data != 1:
        raise SystemExit("只处理 ELF64 小端")
    (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
     _phentsize, _phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
        "<HHIQQQIHHHHHH", d, 16)
    print("type    : 0x%X  machine: 0x%X (%s)  entry: 0x%X"
          % (e_type, e_machine, {0xB7: "AArch64", 0x28: "ARM"}.get(e_machine, "?"), e_entry))
    print("sections: %d  (shoff=0x%X, shentsize=%d)" % (e_shnum, e_shoff, e_shentsize))

    secs = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        (name, stype, flags, addr, off, size, _link, _info, _align, _entsize) = \
            struct.unpack_from("<IIQQQQIIQQ", d, base)
        secs.append([name, stype, flags, addr, off, size])
    strtab_off = secs[e_shstrndx][4]

    def sname(n):
        p = strtab_off + n
        e = d.find(b"\x00", p)
        return d[p:e].decode("ascii", "replace")

    print("\n%-4s %-20s %-12s %-12s %-12s %s" % ("idx", "name", "offset", "vaddr", "size", "flags"))
    last_end = 0
    for i, (_n, stype, flags, addr, off, size) in enumerate(secs):
        nm = sname(_n) if stype != 8 else ""
        fl = ("W" if flags & 1 else "-") + ("A" if flags & 2 else "-") + ("X" if flags & 4 else "-")
        print("%-4d %-20s 0x%-10X 0x%-10X 0x%-10X %s" % (i, nm, off, addr, size, fl))
        if stype != 8 and size:
            last_end = max(last_end, off + size)

    print("\nlast section end : 0x%X" % last_end)
    print("trailing data    : %d B (0x%X ~ 0x%X)"
          % (len(d) - last_end, last_end, len(d)))
    if len(d) > last_end:
        tail = d[last_end:]
        hits = [s for s in (b"ELF_HOOK_", b"stub_") if s in tail]
        print("tail markers     : %s" % (b", ".join(hits) or b"none"))

    for i, (_n, stype, flags, addr, off, size) in enumerate(secs):
        if sname(_n) == "il2cpp":
            print("\nil2cpp section   : off=0x%X vaddr=0x%X size=0x%X (%d MB)"
                  % (off, addr, size, size // 1024 // 1024))


if __name__ == "__main__":
    main(sys.argv[1])