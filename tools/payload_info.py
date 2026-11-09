#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分析 ELF 里不属于任何 section 的区间（hook payload 所在）

    python3 tools/payload_info.py metadata-YYYYMMDD/libil2cpp.so

输出：每个未覆盖区间的范围/大小、hex 头部、可读字符串（带偏移）、
以及"看起来像指针"的 8 字节值（能映射回本 so 的 vaddr），
用来判断这块到底是「字符串表 + 配置」还是「含代码/指针表」。
"""
import struct
import sys

MIN_GAP = 512


def load_sections(d):
    (e_type, e_machine, _v, _entry, _phoff, e_shoff, _f, _eh, _ph, _phn,
     e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
    secs = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        (nm, stype, flags, addr, off, size, _l, _i, _a, _es) = \
            struct.unpack_from("<IIQQQQIIQQ", d, b)
        secs.append({"name": nm, "type": stype, "flags": flags,
                     "addr": addr, "off": off, "size": size})
    strtab = secs[e_shstrndx]["off"]
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


def printable_runs(blk, minlen=4):
    out = []
    i, n = 0, len(blk)
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
            gaps.append((cur, a))
        cur = max(cur, b)
    if cur < n:
        gaps.append((cur, n))

    print("file: %s  size: %d" % (path, n))
    print("未覆盖区间 %d 处，合计 %d B\n" % (len(gaps), sum(b - a for a, b in gaps)))

    for a, b in gaps:
        blk = d[a:b]
        print("=" * 70)
        print("GAP 0x%X ~ 0x%X  (%d B)" % (a, b, b - a))
        print("head:", blk[:64].hex(" "))
        if b - a < MIN_GAP:
            continue

        runs = printable_runs(blk)
        print("strings: %d 条（≥4 字符）" % len(runs))
        for off, s in runs[:40]:
            print("   +0x%06X  %s" % (off, s))

        # 指针候选：8 字节对齐、值落在本 so 的 vaddr 范围内
        ptrs = []
        for i in range(0, len(blk) - 8, 8):
            v = struct.unpack_from("<Q", blk, i)[0]
            sec = in_vaddr(secs, v)
            if sec:
                ptrs.append((i, v, sec))
        print("pointer-like: %d / %d 个 8 字节槽位" % (len(ptrs), len(blk) // 8))
        for off, v, sec in ptrs[:20]:
            print("   +0x%06X  -> 0x%X (%s)" % (off, v, sec))

        # 4 字节指针候选（armv7 风格或压缩表）
        p32 = []
        for i in range(0, len(blk) - 4, 4):
            v = struct.unpack_from("<I", blk, i)[0]
            if v > 0x10000:
                sec = in_vaddr(secs, v)
                if sec:
                    p32.append((i, v, sec))
        if p32:
            print("u32 pointer-like: %d 个，前 10：" % len(p32))
            for off, v, sec in p32[:10]:
                print("   +0x%06X  -> 0x%X (%s)" % (off, v, sec))
    print("\n== 结论提示：若某 GAP 里 pointer-like 密集，说明是函数指针/跳转表；"
          "只有字符串没有指针，说明是名字表（hook 框架的符号名）==")


if __name__ == "__main__":
    main(sys.argv[1])