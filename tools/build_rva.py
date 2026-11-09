#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 method index -> 代码地址 映射（RVA）

    python3 tools/build_rva.py <libil2cpp.so> <global-metadata.fixed.dat> <out.tsv>

依据（本 build 实测）：
  · 每个程序集在 .data.rel.ro 有一个 40 字节的 codegen module：
        +0x00 char* moduleName
        +0x08 u64   methodPointerCount
        +0x10 void** methodPointers
        +0x18 u64   (另一组 count)
        +0x20 void** (另一组 ptr)
  · metadata 里 images[].typeStart/typeCount 圈定了每个程序集的类型区间，
    类型的 method_count 前缀和给出该程序集在方法表里的全局起始索引。
  · 两者对得上（count == metadata 算出的方法数）→ 映射成立。

校验：每个 module 的 methodPointerCount 必须等于 metadata 推算的方法数；
      并且 methodPointers 里绝大多数必须落在可执行段。
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
        secs.append({"name": nm, "type": stype, "flags": flags, "addr": addr,
                     "off": off, "size": size})
    strtab = secs[shstrndx]["off"]
    for s in secs:
        p = strtab + s["name"]
        e = d.find(b"\x00", p)
        s["sname"] = d[p:e].decode("ascii", "replace") if s["type"] != 8 else ""
    return secs


def main():
    so_path, meta_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    d = open(so_path, "rb").read()
    m = open(meta_path, "rb").read()
    secs = load_sections(d)
    segs = [(s["addr"], s["addr"] + s["size"], s["off"], s["sname"], s["flags"])
            for s in secs if s["type"] != 8 and s["size"] and s["addr"]]

    def v2o(v, need=1):
        for a, b, off, nm, fl in segs:
            if a <= v < b and v + need <= b:
                return off + (v - a), nm, fl
        return None

    def o2v(o):
        for a, b, off, nm, fl in segs:
            if off <= o < off + (b - a):
                return a + (o - off), nm, fl
        return None

    sanity, version = struct.unpack_from("<Ii", m, 0)
    if sanity != 0xFAB11BAF:
        raise SystemExit("metadata sanity 不对")
    pairs = struct.unpack_from("<62i", m, 8)

    def sec(i):
        return pairs[2 * i], pairs[2 * i + 1]

    def ms(idx):
        p = sec(2)[0] + idx
        e = m.find(b"\x00", p)
        return m[p:e].decode("utf-8", "replace")

    # --- metadata: 每个类型的方法数、每个程序集的方法区间 ---
    toff, tn = sec(19)[0], sec(19)[1] // 88
    t_mcount = [struct.unpack_from("<I", m, toff + i * 88 + 0x40)[0] & 0xFFFF
                for i in range(tn)]
    prefix = [0] * (tn + 1)
    for i in range(tn):
        prefix[i + 1] = prefix[i] + t_mcount[i]

    io, isz = sec(20)
    images = []
    for i in range(isz // 40):
        b = io + i * 40
        ni, _ai, ts, tc = struct.unpack_from("<IIii", m, b)
        nm = ms(ni)
        mstart = prefix[ts] if 0 <= ts <= tn else 0
        mcount = prefix[min(ts + tc, tn)] - mstart
        images.append((nm, ts, tc, mstart, mcount))
    print("images=%d 方法数合计=%d（metadata methods=%d）"
          % (len(images), sum(x[4] for x in images), sec(5)[1] // 32))

    # --- so: 按名字找 codegen module ---
    targets = [s for s in secs if s["sname"] in (".data.rel.ro", ".data")]
    mods = {}
    for nm, _ts, _tc, _st, _mc in images:
        p = d.find(nm.encode() + b"\x00")
        if p < 0:
            continue
        vo = o2v(p)
        if not vo:
            continue
        vaddr = vo[0]
        for s in targets:
            blk = d[s["off"]:s["off"] + s["size"]]
            i = blk.find(struct.pack("<Q", vaddr))
            while i >= 0:
                if i % 8 == 0:
                    base = s["off"] + i
                    cnt, ptr = struct.unpack_from("<QQ", d, base + 8)
                    if 0 < cnt < 400000 and v2o(ptr, need=8):
                        mods[nm] = (cnt, ptr)
                        break
                i = blk.find(struct.pack("<Q", vaddr), i + 1)
            if nm in mods:
                break

    print("定位到 codegen module: %d/%d" % (len(mods), len(images)))

    ok = 0
    total = 0
    rows = []
    for nm, _ts, _tc, mstart, mcount in images:
        if nm not in mods:
            continue
        cnt, ptr = mods[nm]
        total += 1
        if cnt == mcount:
            ok += 1
        r = v2o(ptr, need=cnt * 8)
        if not r:
            continue
        arr = r[0]
        exec_hits = 0
        for k in range(cnt):
            e = struct.unpack_from("<Q", d, arr + k * 8)[0]
            if e == 0:
                continue
            rr = v2o(e)
            if rr:
                if rr[2] & 4:
                    exec_hits += 1
                rows.append((mstart + k, e))
        print("  %-40s count=%-6d md=%-6d %s  code=%.1f%%"
              % (nm, cnt, mcount, "OK" if cnt == mcount else "MISMATCH",
                 100.0 * exec_hits / max(cnt, 1)))

    print("\ncount 与 metadata 完全一致: %d/%d" % (ok, total))
    rows.sort()
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("method_index\taddress\n")
        for idx, a in rows:
            f.write("%d\t0x%X\n" % (idx, a))
    print("写出 %s：%d 行（占 metadata 方法数的 %.1f%%）"
          % (out_path, len(rows), 100.0 * len(rows) / (sec(5)[1] // 32)))


if __name__ == "__main__":
    main()