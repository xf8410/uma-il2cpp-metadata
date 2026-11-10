#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 method index -> 代码地址 映射，并顺带做抽样验证 + 地址反查示例

    python3 tools/build_rva.py <libil2cpp.so> <global-metadata.fixed.dat> <out.tsv>

依据（本 build 实测）：
  · 每个程序集在 .data.rel.ro 有一个 40 字节的 codegen module：
        +0x00 char* moduleName
        +0x08 u64   methodPointerCount      (+0x10 void** methodPointers)
        +0x18 u64   (另一组 count)          (+0x20 void** 另一组 ptr)
  · metadata images[].typeStart/typeCount + 类型 method_count 前缀和
    给出每个程序集在方法表里的全局起始索引与数量。
  · 候选判定：module 的 count 必须等于 metadata 推算的方法数，且指针数组
    绝大多数落在可执行段；名字匹配失败的再用「count 值」反查兜底。
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


PROLOG = {
    0xD503233F: "pacibsp", 0xD503237F: "paciasp", 0xD503201F: "nop",
    0x910003FD: "mov x29,sp",
}


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

    # ---- metadata: 每个程序集的方法区间 ----
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
        images.append((ms(ni), ts, tc, mstart,
                       prefix[min(ts + tc, tn)] - mstart))
    total_md = sec(5)[1] // 32
    print("images=%d  方法数合计=%d  metadata methods=%d"
          % (len(images), sum(x[4] for x in images), total_md))

    targets = [s for s in secs if s["sname"] in (".data.rel.ro", ".data")]

    def grab(base, cnt_off, ptr_off, cw, pw):
        fmt_c = "<Q" if cw == 8 else "<I"
        fmt_p = "<Q" if pw == 8 else "<I"
        cnt = struct.unpack_from(fmt_c, d, base + cnt_off)[0]
        ptr = struct.unpack_from(fmt_p, d, base + ptr_off)[0]
        return cnt, ptr

    def score(cnt, ptr):
        """返回 (是否可用, 预计代码指针比例)"""
        if not (0 < cnt < 400000):
            return None
        r = v2o(ptr, need=min(cnt * 8, 16))
        if not r:
            return None
        arr = r[0]
        n = min(cnt, 4000)
        hit = 0
        for k in range(n):
            e = struct.unpack_from("<Q", d, arr + k * 8)[0] if arr + k * 8 + 8 <= len(d) else 0
            if e:
                rr = v2o(e)
                if rr and (rr[2] & 4):
                    hit += 1
        return 100.0 * hit / n if n else 0.0

    def candidates(nm):
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
                            for cnt_off, ptr_off, cw, pw in (
                                    (8, 16, 8, 8), (8, 16, 4, 8),
                                    (8, 12, 4, 4), (8, 20, 8, 8),
                                    (16, 24, 8, 8)):
                                try:
                                    cnt, ptr = grab(base, cnt_off, ptr_off, cw, pw)
                                except struct.error:
                                    continue
                                sc = score(cnt, ptr)
                                if sc is not None:
                                    out.append((cnt, ptr, sc,
                                                "%s+0x%X" % (s["sname"], base - s["off"])))
                        i = blk.find(struct.pack("<Q", vaddr), i + 1)
                        k += 1
            p = d.find(pat, p + 1)
            seen += 1
        return out

    def by_count(mcount):
        """名字匹配失败时，用 count 值在 .data.rel.ro 里反查"""
        for s in targets:
            blk = d[s["off"]:s["off"] + s["size"]]
            needle = struct.pack("<Q", mcount)
            i = blk.find(needle)
            k = 0
            while i >= 0 and k < 20:
                if i % 8 == 0:
                    base = s["off"] + i
                    for cnt_off, ptr_off in ((0, 8), (-8, 0)):
                        try:
                            cnt, ptr = grab(base, cnt_off, ptr_off, 8, 8)
                        except struct.error:
                            continue
                        sc = score(cnt, ptr)
                        if sc is not None and sc > 50:
                            return [(cnt, ptr, sc, "%s+0x%X(count-scan)"
                                     % (s["sname"], base - s["off"]))]
                i = blk.find(needle, i + 1)
                k += 1
        return []

    rows, ok, miss = [], 0, []
    for nm, _ts, _tc, mstart, mcount in images:
        best, why = None, ""
        if mcount > 0:
            cands = candidates(nm) or by_count(mcount)
            exact = [c for c in cands if c[0] == mcount and c[2] > 80]
            if exact:
                best = max(exact, key=lambda c: c[2])
                ok += 1
            else:
                bad = [c for c in cands if c[0] != mcount]
                if bad:
                    best = max(bad, key=lambda c: c[2])
                    why = "COUNT-MISMATCH"
                miss.append(nm)
        if not best:
            print("  %-42s md=%-6d 未定位" % (nm, mcount))
            continue
        cnt, ptr, sc, where = best
        print("  %-42s md=%-6d cnt=%-6d code=%5.1f%% @%s %s"
              % (nm, mcount, cnt, sc, where, why or "OK"))
        r = v2o(ptr, need=min(cnt * 8, 8))
        if not r:
            continue
        arr = r[0]
        n = cnt if cnt == mcount else min(cnt, mcount)
        for k in range(n):
            e = struct.unpack_from("<Q", d, arr + k * 8)[0]
            if e:
                rows.append((mstart + k, e))

    print("\n模块对齐成功 %d/%d；未定位 %d 个" % (ok, len(images), len(miss)))
    rows.sort()
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("method_index\taddress\n")
        for idx, a in rows:
            f.write("%d\t0x%X\n" % (idx, a))
    print("写出 %s：%d 行（覆盖 metadata 方法数 %.1f%%）"
          % (out_path, len(rows), 100.0 * len(rows) / total_md))

    # ---- 抽样验证：地址处的 ARM64 序言 ----
    if rows:
        step = max(1, len(rows) // 200)
        kinds = {}
        bad = 0
        for idx, a in rows[::step][:200]:
            r = v2o(a, need=4)
            if not r:
                bad += 1
                continue
            w = struct.unpack_from("<I", d, r[0])[0]
            k = prologue_kind(w)
            kinds[k] = kinds.get(k, 0) + 1
        print("\n抽样验证 %d 个地址（每 %d 个取 1）：" % (min(200, len(rows[::step])), step))
        for k, v in sorted(kinds.items(), key=lambda x: -x[1]):
            print("   %-22s %d" % (k, v))
        good = sum(v for k, v in kinds.items() if k not in ("ZERO",))
        print("   非零字节比例 %.1f%%；映射地址越界 %d" % (100.0 * good / max(1, sum(kinds.values())), bad))

        # ---- 地址反查示例 ----
        print("\n地址反查示例（method_index -> 类::方法）：")
        mo, _mn = sec(5)
        for idx, a in rows[:5]:
            b = mo + idx * 32
            ni = struct.unpack_from("<I", m, b)[0]
            dt = struct.unpack_from("<I", m, b + 4)[0]
            tok = struct.unpack_from("<I", m, b + 0x14)[0]
            pc = struct.unpack_from("<I", m, b + 0x1C)[0] >> 16
            tb = toff + dt * 88
            tn_name = ms(struct.unpack_from("<I", m, tb)[0])
            tns = ms(struct.unpack_from("<I", m, tb + 4)[0])
            full = (tns + "." + tn_name) if tns else tn_name
            print("   0x%-9X %s::%s(%d)  token=0x%08X  #%d"
                  % (a, full, ms(ni), pc, tok, idx))


if __name__ == "__main__":
    main()