#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELF 概况（libil2cpp.so 这种被改过分段的 build 用）

    python3 tools/elf_info.py metadata-YYYYMMDD/libil2cpp.so

重点：不只报「最后一段之后的尾巴」，还会报**所有未被任何 section 覆盖的区间**。
这条 build 的 hook payload 就藏在中段空隙里（.shstrtab 之后、.hash 之前），
只看「trailing data」会漏掉它（踩过一次）。
"""
import struct
import sys
import hashlib


def main(path):
    d = open(path, "rb").read()
    n = len(d)
    print("file    : %s" % path)
    print("size    : %d (0x%X)" % (n, n))
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

    def sname(x):
        p = strtab_off + x
        e = d.find(b"\x00", p)
        return d[p:e].decode("ascii", "replace")

    print("\n%-4s %-20s %-12s %-12s %-12s %s" % ("idx", "name", "offset", "vaddr", "size", "flags"))
    for i, (_n, stype, flags, addr, off, size) in enumerate(secs):
        nm = "" if stype == 8 else sname(_n)
        fl = ("W" if flags & 1 else "-") + ("A" if flags & 2 else "-") + ("X" if flags & 4 else "-")
        print("%-4d %-20s 0x%-10X 0x%-10X 0x%-10X %s" % (i, nm, off, addr, size, fl))

    # --- 覆盖分析：文件里所有不属于任何 section 的区间 ---
    spans = []
    for (_n, stype, _f, _a, off, size) in secs:
        if stype != 8 and size:
            spans.append((off, off + size))
    spans.sort()
    gaps = []
    cur = 0
    for s, e in spans:
        if s > cur:
            gaps.append((cur, s))
        cur = max(cur, e)
    if cur < n:
        gaps.append((cur, n))

    print("\n=== 未覆盖区间（不属于任何 section）===")
    if not gaps:
        print("  无：整个文件都被 section 覆盖")
    total = 0
    for s, e in gaps:
        blk = d[s:e]
        hits = [m for m in (b"ELF_HOOK_", b"stub_", b"MetadataCache", b"il2cpp_init")
                if m in blk]
        total += e - s
        print("  0x%X ~ 0x%X  %d B  markers=%s"
              % (s, e, e - s, b",".join(hits) or b"none"))
    print("  合计 %d B (%.1f%% of file)" % (total, 100.0 * total / n))

    for i, (_n, stype, flags, addr, off, size) in enumerate(secs):
        if sname(_n) == "il2cpp":
            print("\nil2cpp section   : off=0x%X vaddr=0x%X size=0x%X (%.1f MiB)"
                  % (off, addr, size, size / 1048576.0))


if __name__ == "__main__":
    main(sys.argv[1])