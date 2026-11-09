#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 libil2cpp.so 里找 Il2CppCodeRegistration / methodPointers 表

    python3 tools/find_registration.py <libil2cpp.so> <global-metadata.fixed.dat> [--write-rva out.tsv]

思路（不依赖标准布局，因为这个 build 是自定义的）：
  1. 从 metadata 算出几个"特征计数"：类型数、方法数、字段数、字面量数；
  2. 在 so 的数据段里扫这个数值（u64/u32 都试）；
  3. 对每个命中点，把相邻字段当指针解出来，验证它指向的数组：
     长度为该计数、且**绝大多数元素都落在本 so 的段内**（尤其是可执行段）——
     满足就说明找到了指针表（methodPointers / types 数组之类）；
  4. 若确认是方法指针表，可选写出 idx -> 地址 的 tsv。
"""
import struct
import sys


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


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    so_path, meta_path = sys.argv[1], sys.argv[2]
    out_tsv = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--write-rva" else None

    d = open(so_path, "rb").read()
    secs = load_sections(d)

    # vaddr -> (file_off, size, sname)
    vmap = []
    for s in secs:
        if s["type"] != 8 and s["size"] and s["addr"]:
            vmap.append((s["addr"], s["addr"] + s["size"], s["off"], s["sname"], s["flags"]))

    def resolve(v, need=1):
        for a, b, off, nm, fl in vmap:
            if a <= v < b and v + need <= b:
                return off + (v - a), nm, fl
        return None

    # 特征计数（从 metadata 算）
    m = open(meta_path, "rb").read()
    sanity, version = struct.unpack_from("<Ii", m, 0)
    if sanity != 0xFAB11BAF:
        raise SystemExit("metadata sanity 不对")
    pairs = struct.unpack_from("<62i", m, 8)

    def sec(i):
        return pairs[2 * i], pairs[2 * i + 1]

    counts = {}
    counts[sec(0)[1] // 8] = "stringLiterals"
    counts[sec(5)[1] // 32] = "methods"
    counts[sec(11)[1] // 12] = "fields"
    counts[sec(19)[1] // 88] = "types"
    counts[sec(21)[1] // 64] = "assemblies"
    counts = {k: v for k, v in counts.items() if k > 100}
    print("metadata 计数:", counts)
    print("so: %s  %d B  sections=%d" % (so_path, len(d), len(secs)))

    # 扫描范围：可写数据段 + rodata
    targets = [s for s in secs if s["sname"] in (".data", ".data.rel.ro", ".rodata", ".got")]
    print("扫描段:", [s["sname"] for s in targets])

    hits = []
    for s in targets:
        base, off0, size = s["addr"], s["off"], s["size"]
        blk = d[off0:off0 + size]
        for width, fmt in ((8, "<Q"), (4, "<I")):
            step = width
            for i in range(0, len(blk) - width, step):
                v = struct.unpack_from(fmt, blk, i)[0]
                if v in counts:
                    hits.append((s, base + i, off0 + i, v, counts[v], width))
    print("候选命中 %d 个" % len(hits))

    best = None
    for (s, vaddr, foff, cnt, cname, width) in hits:
        print("\n--- %s +0x%X (file 0x%X)  值=%d (%s)  宽度=%d"
              % (s["sname"], vaddr - s["addr"], foff, cnt, cname, width))
        for delta, pwidth in ((width, 8), (width, 4), (-width, 8), (-width, 4)):
            pf = foff + delta
            if not (0 <= pf < len(d) - pwidth):
                continue
            p = struct.unpack_from("<Q" if pwidth == 8 else "<I", d, pf)[0]
            if p == 0:
                continue
            r = resolve(p, need=min(cnt * pwidth, 8))
            if not r:
                print("   ptr@%+d = 0x%X  (不在段内)" % (delta, p))
                continue
            arr_off, arr_sec, arr_fl = r
            n = min(cnt, 400000)
            valid = 0
            exec_hits = 0
            for k in range(n):
                q = arr_off + k * pwidth
                if q + pwidth > len(d):
                    break
                e = struct.unpack_from("<Q" if pwidth == 8 else "<I", d, q)[0]
                if e == 0:
                    continue
                rr = resolve(e, need=1)
                if rr:
                    valid += 1
                    if rr[2] & 4:
                        exec_hits += 1
            ratio = 100.0 * valid / n if n else 0
            print("   ptr@%+d = 0x%X -> %s@0x%X, 数组 %d 项, 有效 %.1f%%, 指向可执行段 %.1f%%"
                  % (delta, p, arr_sec, arr_off, n, ratio, 100.0 * exec_hits / n if n else 0))
            if ratio > 90 and cname == "methods" and pwidth == 8:
                best = (arr_off, n, ratio)

    if best and out_tsv:
        arr_off, n, ratio = best
        with open(out_tsv, "w", encoding="utf-8") as f:
            f.write("method_index\taddress\n")
            for k in range(n):
                e = struct.unpack_from("<Q", d, arr_off + k * 8)[0]
                f.write("%d\t0x%X\n" % (k, e))
        print("\n已写出 %s（%d 行，有效率 %.1f%%）" % (out_tsv, n, ratio))
    elif not best:
        print("\n没找到可信的方法指针表（ratio>90%）。下一步：把候选表地址、"
              "以及 il2cpp 段里 codegen 模块的 vtable 一并 dump 出来人工核对。")


if __name__ == "__main__":
    main()