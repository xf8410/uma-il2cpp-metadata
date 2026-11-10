#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 method index -> 代码地址 映射 + 抽样验证 + 地址反查 + 小结

    python3 tools/build_rva.py <libil2cpp.so> <global-metadata.fixed.dat> <out.tsv>

三级定位（逐层兜底）：
  1) 名字 → 结构字段 (count, ptr)：count == metadata 推算值且指针多为代码；
  2) 名字失败 → 用 count 值在 .data.rel.ro 反查；
  3) 都失败 → 全量扫描「连续 code pointer 数组」，用数组长度 == count 匹配。
"""
import os
import struct
import sys
import traceback


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
    dn = len(d)
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

    def u64(o):
        return struct.unpack_from("<Q", d, o)[0] if 0 <= o and o + 8 <= dn else None

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
        arr, n, hit = r[0], min(cnt, limit), 0
        for k in range(n):
            e = u64(arr + k * 8)
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
                    i, k = blk.find(struct.pack("<Q", vaddr)), 0
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
                            return [[cnt, ptr, sc, "%s+0x%X(count-scan)"
                                     % (s["sname"], base - s["off"])]]
                i = blk.find(needle, i + 1)
                k += 1
        return []

    def scan_code_arrays(minlen=64):
        out = []
        for s in targets:
            off0, size = s["off"], s["size"]
            i, start, cnt = 0, -1, 0
            while i + 8 <= size:
                v = u64(off0 + i)
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

    rows, mods, still = [], [], []

    def emit(arr_off, mstart, mcount):
        for k in range(mcount):
            e = u64(arr_off + k * 8)
            if e:
                rows.append((mstart + k, e))

    for nm, _ts, _tc, mstart, mcount in images:
        if mcount <= 0:
            continue
        exact = [c for c in (by_name(nm) or by_count(mcount))
                 if c[0] == mcount and c[2] > 80]
        if exact:
            best = max(exact, key=lambda c: c[2])
            r = v2o(best[1])
            if r:
                emit(r[0], mstart, mcount)
                mods.append((nm, mcount, best[2], best[3]))
                continue
        still.append([nm, mstart, mcount])

    print("\n-- 第 3 级：全量扫 code pointer 数组 --")
    arrays = scan_code_arrays()
    by_len = {}
    for s, off, ln in arrays:
        by_len.setdefault(ln, []).append((s, off))
    print("发现连续 code pointer 段 %d 个；长度 top: %s"
          % (len(arrays), sorted(((l, len(v)) for l, v in by_len.items()),
                                 key=lambda x: -x[0])[:6]))

    left = []
    for nm, mstart, mcount in still:
        got = by_len.get(mcount)
        if not got:
            left.append([nm, mcount])
            continue
        s, off = got[0]
        emit(off, mstart, mcount)
        mods.append((nm, mcount, 100.0, "%s+0x%X(array-scan)" % (s["sname"], off - s["off"])))
        print("  %-42s md=%-6d -> 数组匹配 @%s+0x%X"
              % (nm, mcount, s["sname"], off - s["off"]))

    rows.sort()
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("method_index\taddress\n")
        for idx, a in rows:
            f.write("%d\t0x%X\n" % (idx, a))
    cov = 100.0 * len(rows) / total_md
    print("\n写出 %s：%d 行（覆盖 %.1f%%）" % (out_path, len(rows), cov))

    sd = os.path.dirname(os.path.abspath(out_path))
    lines = ["RVA 映射小结", "============",
             "metadata 方法总数 : %d" % total_md,
             "已映射方法数      : %d (%.1f%%)" % (len(rows), cov),
             "程序集            : %d 个，成功 %d，失败 %d"
             % (len(images), len(images) - len(left), len(left)),
             "", "未定位的程序集："]
    for nm, mc in left:
        lines.append("  %-42s md=%d" % (nm, mc))

    try:
        kinds, bad = {}, 0
        sample = rows[::max(1, len(rows) // 200)][:200]
        for idx, a in sample:
            r = v2o(a, need=4)
            if not r:
                bad += 1
                continue
            k = prologue_kind(struct.unpack_from("<I", d, r[0])[0])
            kinds[k] = kinds.get(k, 0) + 1
        tot = max(1, sum(kinds.values()))
        lines += ["", "ARM64 序言抽样（%d 个地址，越界 %d）：" % (len(sample), bad)]
        for k, v in sorted(kinds.items(), key=lambda x: -x[1]):
            lines.append("  %-22s %d (%.1f%%)" % (k, v, 100.0 * v / tot))

        mo = sec(5)[0]
        samples = []
        for idx, a in rows[:10]:
            b = mo + idx * 32
            ni, dt = struct.unpack_from("<II", m, b)
            tok = struct.unpack_from("<I", m, b + 0x14)[0]
            pc = struct.unpack_from("<I", m, b + 0x1C)[0] >> 16
            if 0 <= dt < tn:
                tb = toff + dt * 88
                tnt = ms(struct.unpack_from("<I", m, tb)[0])
                tns = ms(struct.unpack_from("<I", m, tb + 4)[0])
                full = (tns + "." + tnt) if tns else tnt
            else:
                full = "<dt=%d>" % dt
            samples.append("0x%-9X %s::%s(%d)  token=0x%08X  #%d"
                           % (a, full, ms(ni), pc, tok, idx))
        lines += ["", "地址反查示例："] + ["  " + s for s in samples]
        lines += ["", "模块定位方式（前 20）："]
        for nm, mc, sc, where in mods[:20]:
            lines.append("  %-42s md=%-6d code=%5.1f%%  %s" % (nm, mc, sc, where))
        for s in samples:
            print("   " + s)
    except Exception:
        lines += ["", "!!! 分析阶段异常：", traceback.format_exc()]

    with open(os.path.join(sd, "so_rva_summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("小结已写入 %s" % os.path.join(sd, "so_rva_summary.txt"))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        try:
            sd = os.path.dirname(os.path.abspath(sys.argv[3]))
            os.makedirs(sd, exist_ok=True)
            with open(os.path.join(sd, "so_rva_summary.txt"), "w", encoding="utf-8") as f:
                f.write("!!! 脚本异常退出\n" + traceback.format_exc())
        except Exception:
            pass
        traceback.print_exc()
        raise