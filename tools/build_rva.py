#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 method index -> 代码地址 映射 + 抽样验证 + 地址反查 + 小结

    python3 tools/build_rva.py <libil2cpp.so> <global-metadata.fixed.dat> <out.tsv>

依据（本 build 实测）：
  · 每个程序集在 .data.rel.ro 有一个 40 字节的 codegen module：
        +0x00 char* moduleName
        +0x08 u64   methodPointerCount      (+0x10 void** methodPointers)
        +0x18 u64   (另一组 count)          (+0x20 void** 另一组 ptr)
  · metadata images[].typeStart/typeCount + 类型 method_count 前缀和
    给出每个程序集在方法表里的全局起始索引与数量。

三级定位（逐层兜底）：
  1) 名字 → 结构字段 (count, ptr)，要求 count == metadata 推算值、指针多为代码；
  2) 名字失败 → 用 count 值在 .data.rel.ro 里反查；
  3) 都失败 → 全量扫描「连续 code pointer 数组」，用数组长度 == count 匹配。

输出：主 tsv（method_index -> address） + 同目录 so_rva_summary.txt（小结，手机上可直接看）
"""
import struct
import sys
import os


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


PROLOG = {0xD503233F: "pacibsp", 0xD503237F: "paciasp", 0xD503201F: "nop",
          0x910003FD: "mov x29,sp"}


def prologue_kind(w):
    if w in PROLOG:
        return PROLOG[w]
    if (w & 0xFFC07FFF) == 0xA9807BFD:
        return "stp x29,x30,[sp,#-n]!"
    if (w & 0xFF800000) == 0xD1000000:
        return "sub sp,sp,#n"
    if w == 0:
        return "ZERO"
    return "other"


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

    if d[:4] != b"\x7fELF" or struct.unpack_from("<I", m, 0)[0] != 0xFAB11BAF:
        raise SystemExit("输入不对")
    pairs = struct.unpack_from("<62i", m, 8)

    def sec(i):
        return pairs[2 * i], pairs[2 * i + 1]

    str_off, str_size = sec(2)

    def ms(idx):
        if idx < 0 or idx >= str_size:
            return ""
        p = str_off + idx
        e = m.find(b"\x00", p)
        return m[p:e].decode("utf-8", "replace")

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
        mstart = prefix[ts] if 0 <= ts <= tn else 0
        images.append([ms(ni), ts, tc, mstart, prefix[min(ts + tc, tn)] - mstart])
    total_md = sec(5)[1] // 32
    print("images=%d  方法数合计=%d  metadata methods=%d"
          % (len(images), sum(x[4] for x in images), total_md))

    targets = [s for s in secs if s["sname"] in (".data.rel.ro", ".data")]

    def grab(base, cnt_off, ptr_off, cw, pw):
        cnt = struct.unpack_from("<Q" if cw == 8 else "<I", d, base + cnt_off)[0]
        ptr = struct.unpack_from("<Q" if pw == 8 else "<I", d, base + ptr_off)[0]
        return cnt, ptr

    def code_ratio(cnt, ptr, limit=4000):
        r = v2o(ptr, need=min(cnt * 8, 16))
        if not r:
            return None
        arr = r[0]
        n = min(cnt, limit)
        hit = 0
        for k in range(n):
            q = arr + k * 8
            if q + 8 > len(d):
                break
            e = struct.unpack_from("<Q", d, q)[0]
            if e:
                rr = v2o(e, need=4)
                if rr and (rr[2] & 4):
                    hit += 1
        return 100.0 * hit / n if n else 0.0

    def by_name(nm):
        pat = nm.encode() + b"\x00"
        out, p, seen = [], d.find(pat), 0
        while p >= 0 and seen < 6:
            vo = o2v(p)
            if vo:
                vaddr = vo[0]
                for s in targets:
                    blk = d[s["off"]:s["off"] + s["size"]]
                    i = blk.find(struct.pack("<Q", vaddr))
                    k = 0
                    while i >= 0 and k < 4:
                        if i % 4 == 0:
                            base = s["off"] + i
                            for co, po, cw, pw in ((8, 16, 8, 8), (8, 16, 4, 8),
                                                   (8, 12, 4, 4), (8, 20, 8, 8),
                                                   (16, 24, 8, 8)):
                                try:
                                    cnt, ptr = grab(base, co, po, cw, pw)
                                except struct.error:
                                    continue
                                sc = code_ratio(cnt, ptr) if 0 < cnt < 400000 else None
                                if sc is not None:
                                    out.append([cnt, ptr, sc,
                                                "%s+0x%X" % (s["sname"], base - s["off"])])
                        i = blk.find(struct.pack("<Q", vaddr), i + 1)
                        k += 1
            p = d.find(pat, p + 1)
            seen += 1
        return out

    def by_count(mcount):
        for s in targets:
            blk = d[s["off"]:s["off"] + s["size"]]
            needle = struct.pack("<Q", mcount)
            i, k = blk.find(needle), 0
            while i >= 0 and k < 40:
                if i % 8 == 0:
                    base = s["off"] + i
                    for co, po in ((0, 8), (-8, 0)):
                        try:
                            cnt, ptr = grab(base, co, po, 8, 8)
                        except (struct.error, ValueError):
                            continue
                        sc = code_ratio(cnt, ptr) if 0 < cnt < 400000 else None
                        if sc is not None and sc > 50:
                            return [[cnt, ptr, sc,
                                     "%s+0x%X(count-scan)" % (s["sname"], base - s["off"])]]
                i = blk.find(needle, i + 1)
                k += 1
        return []

    def scan_code_arrays(minlen=64):
        out = []
        for s in targets:
            off0, size = s["off"], s["size"]
            i, start, cnt = 0, -1, 0
            while i + 8 <= size:
                v = struct.unpack_from("<Q", d, off0 + i)[0]
                r = v2o(v, need=4) if v else None
                if r and (r[2] & 4):
                    if start < 0:
                        start, cnt = i, 0
                    cnt += 1
                else:
                    if cnt >= minlen:
                        out.append((s, off0 + start, cnt))
                    start, cnt = -1, 0
                i += 8
            if cnt >= minlen:
                out.append((s, off0 + start, cnt))
        return out

    rows, resolved, unresolved, mods = [], [], [], []
    for nm, _ts, _tc, mstart, mcount in images:
        if mcount <= 0:
            resolved.append((nm, 0, ""))
            continue
        cands = by_name(nm) or by_count(mcount)
        exact = [c for c in cands if c[0] == mcount and c[2] > 80]
        if exact:
            best = max(exact, key=lambda c: c[2])
            mods.append((nm, mstart, mcount, best[3], best[2]))
            resolved.append((nm, mcount, best[3]))
            for k in range(mcount):
                e = struct.unpack_from("<Q", d, v2o(best[1])[0] + k * 8)[0]
                if e:
                    rows.append((mstart + k, e))
        else:
            unresolved.append([nm, mstart, mcount])

    print("\n-- 第 3 级：全量扫 code pointer 数组（长度 == 方法数）--")
    arrays = scan_code_arrays()
    by_len = {}
    for s, off, ln in arrays:
        by_len.setdefault(ln, []).append((s, off))
    print("发现连续 code pointer 段 %d 个，长度分布前 8：%s"
          % (len(arrays), sorted(((l, len(v)) for l, v in by_len.items()),
                                 key=lambda x: -x[0])[:8]))

    still = []
    for nm, mstart, mcount in unresolved:
        got = by_len.get(mcount)
        if not got:
            still.append((nm, mcount))
            continue
        s, off = got[0]
        mods.append((nm, mstart, mcount, "%s+0x%X(array-scan)" % (s["sname"], off - s["off"]), 100.0))
        for k in range(mcount):
            e = struct.unpack_from("<Q", d, off + k * 8)[0]
            if e:
                rows.append((mstart + k, e))
        print("  %-42s md=%-6d → 数组匹配成功 @%s+0x%X"
              % (nm, mcount, s["sname"], off - s["off"]))

    rows.sort()
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("method_index\taddress\n")
        for idx, a in rows:
            f.write("%d\t0x%X\n" % (idx, a))
    cov = 100.0 * len(rows) / total_md
    print("\n写出 %s：%d 行（覆盖 %.1f%%）" % (out_path, len(rows), cov))

    # ---- 抽样验证 ----
    kinds, bad, sample = {}, 0, rows[::max(1, len(rows) // 200)][:200] if rows else []
    for idx, a in sample:
        r = v2o(a, need=4)
        if not r:
            bad += 1
            continue
        k = prologue_kind(struct.unpack_from("<I", d, r[0])[0])
        kinds[k] = kinds.get(k, 0) + 1
    tot = max(1, sum(kinds.values()))
    print("\n抽样验证 %d 个地址：" % len(sample))
    for k, v in sorted(kinds.items(), key=lambda x: -x[1]):
        print("   %-22s %d (%.1f%%)" % (k, v, 100.0 * v / tot))

    # ---- 地址反查示例 ----
    mo = sec(5)[0]
    samples = []
    for idx, a in rows[:10]:
        b = mo + idx * 32
        ni, dt = struct.unpack_from("<II", m, b)
        tok = struct.unpack_from("<I", m, b + 0x14)[0]
        pc = struct.unpack_from("<I", m, b + 0x1C)[0] >> 16
        tb = toff + dt * 88
        tnt = ms(struct.unpack_from("<I", m, tb)[0])
        tns = ms(struct.unpack_from("<I", m, tb + 4)[0])
        samples.append("0x%-9X %s::%s(%d)  token=0x%08X  #%d"
                       % (a, (tns + "." + tnt) if tns else tnt, ms(ni), pc, tok, idx))
    print("\n地址反查示例：")
    for s in samples:
        print("   " + s)

    # ---- 小结文件 ----
    sd = os.path.dirname(os.path.abspath(out_path))
    with open(os.path.join(sd, "so_rva_summary.txt"), "w", encoding="utf-8") as f:
        f.write("RVA 映射小结\n")
        f.write("============\n")
        f.write("metadata 方法总数 : %d\n" % total_md)
        f.write("已映射方法数      : %d (%.1f%%)\n" % (len(rows), cov))
        f.write("程序集            : %d 个，成功 %d，失败 %d\n"
                % (len(images), len(images) - len(still), len(still)))
        f.write("映射地址越界      : %d\n" % bad)
        f.write("\n未定位的程序集：\n")
        for nm, mc in still:
            f.write("  %-42s md=%d\n" % (nm, mc))
        f.write("\nARM64 序言抽样（%d 个地址）：\n" % len(sample))
        for k, v in sorted(kinds.items(), key=lambda x: -x[1]):
            f.write("  %-22s %d (%.1f%%)\n" % (k, v, 100.0 * v / tot))
        f.write("\n反查示例：\n")
        for s in samples:
            f.write("  %s\n" % s)
        f.write("\n模块定位方式（前 20 个）：\n")
        for nm, mstart, mcount, where, sc in mods[:20]:
            f.write("  %-42s md=%-6d code=%5.1f%%  %s\n" % (nm, mcount, sc, where))
    print("\n小结已写入 %s" % os.path.join(sd, "so_rva_summary.txt"))


if __name__ == "__main__":
    main()