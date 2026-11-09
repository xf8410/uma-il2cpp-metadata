#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分析 ELF 里不属于任何 section 的区间（hook payload 所在）

    python3 tools/payload_info.py metadata-YYYYMMDD/libil2cpp.so

只详写「最大的那个未覆盖区间」（以及带 hook 标记的区间），其余只给一行摘要，
避免输出过长。对目标区间给出：hex 头、u64/u32 视图、可读字符串、指针候选。
"""
import struct
import sys

MARKERS = (b"ELF_HOOK_", b"stub_", b"MetadataCache", b"il2cpp_init")
MAX_STR = 60
MAX_PTR = 25


def load_sections(d):
    (_t, _m, _v, _e, _phoff, shoff, _f, _eh, _ph, _phn,
     shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
    secs = []
    for i in range(shnum):
        b = shoff + i * shentsize
        (nm, stype, flags, addr, off, size, _l, _i, _a, _es) = \
            struct.unpack_from("<IIQQQQIIQQ", d, b)
        secs.append({"name": nm, "type": stype, "flags": flags,
                     "addr": addr, "off": off, "size": size})
    strtab = secs[shstrndx]["off"]
    for s in secs:
        p = strtab + s["name"]
        e = d.find(b"\x00", p)
        s["sname"] = d[p:e].decode("ascii", "replace") if s["type"] != 8 else ""
    return secs


def in_vaddr(secs, v):
    for s in secs:
        if s["type"] == 8 or not s["size"]:
            continue
        if s["addr"] <= v < s["addr"] + s["size"]:
            return s["sname"]
    return None


def runs(blk, minlen=4):
    out, i, n = [], 0, len(blk)
    while i < n:
        j = i
        while j < n and 32 <= blk[j] < 127:
            j += 1
        if j - i >= minlen:
            out.append((i, blk[i:j].decode("ascii")))
        i = j + 1
    return out


def main(path):
    d = open(path, "rb").read()
    n = len(d)
    secs = load_sections(d)

    spans = sorted((s["off"], s["off"] + s["size"]) for s in secs
                   if s["type"] != 8 and s["size"])
    gaps, cur = [], 0
    for a, b in spans:
        if a > cur:
            gaps.append((a, b))
        cur = max(cur, b)
    if cur < n:
        gaps.append((cur, n))

    print("file: %s  size: %d" % (path, n))
    print("未覆盖区间 %d 处，合计 %d B" % (len(gaps), sum(b - a for a, b in gaps)))
    for a, b in gaps:
        blk = d[a:b]
        mk = [m.decode() for m in MARKERS if m in blk]
        print("  0x%X~0x%X  %6d B  %s" % (a, b, b - a, ",".join(mk) or "-"))

    target = max(gaps, key=lambda g: g[1] - g[0]) if gaps else None
    for a, b in gaps:
        if any(m in d[a:b] for m in MARKERS) and (b - a) > (target[1] - target[0]) * 0.2:
            target = (a, b)
            break
    if not target:
        return
    a, b = target
    blk = d[a:b]
    print("\n" + "=" * 70)
    print("重点区间 0x%X ~ 0x%X  (%d B)" % (a, b, b - a))
    print("head:", blk[:96].hex(" "))

    print("\n-- u64 视图（前 16 个）--")
    for i in range(0, min(len(blk), 128) - 8, 8):
        v = struct.unpack_from("<Q", blk, i)[0]
        tag = in_vaddr(secs, v) or ""
        print("  +0x%04X  0x%016X %s" % (i, v, ("-> " + tag) if tag else ""))

    print("\n-- u32 视图（前 16 个）--")
    for i in range(0, min(len(blk), 64) - 4, 4):
        v = struct.unpack_from("<I", blk, i)[0]
        tag = in_vaddr(secs, v) or ""
        print("  +0x%04X  0x%08X %s" % (i, v, ("-> " + tag) if tag else ""))

    rs = runs(blk)
    print("\n-- 可读字符串 %d 条（前 %d）--" % (len(rs), MAX_STR))
    for off, s in rs[:MAX_STR]:
        print("  +0x%05X  %s" % (off, s))

    ptrs = [(i, struct.unpack_from("<Q", blk, i)[0]) for i in range(0, len(blk) - 8, 8)]
    ptrs = [(i, v, in_vaddr(secs, v)) for i, v in ptrs if in_vaddr(secs, v)]
    print("\n-- 指针候选 %d / %d 槽位（前 %d）--" % (len(ptrs), len(blk) // 8, MAX_PTR))
    for off, v, sec in ptrs[:MAX_PTR]:
        print("  +0x%05X  -> 0x%X (%s)" % (off, v, sec))


if __name__ == "__main__":
    main(sys.argv[1])