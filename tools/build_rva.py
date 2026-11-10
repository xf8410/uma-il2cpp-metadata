#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""method index -> 代码地址 映射 + 地址质量复验 + 反查 + 小结

    python3 tools/build_rva.py <libil2cpp.so> <global-metadata.fixed.dat> <out.tsv>

定位策略（逐层兜底）：
  1) 程序集名 → codegen module 字段 (count, ptr)，count 必须等于 metadata 推算值；
  2) 名字失败 → 用 count 值在数据段反查；
  3) 仍失败 → 全量扫「连续 code pointer 数组」，长度 == count；
  4) 最后 → 滑动窗口匹配（允许 null 空洞），覆盖数组里夹着 null 的情况。
"""
import bisect
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


def prologue_kind(w):
    if w in (0xD503233F, 0xD503237F):
        return "pacibsp/paciasp"
    if w == 0xD503201F:
        return "nop"
    if (w & 0xFF800000) == 0xD1000000:
        return "sub sp,sp,#n"
    if (w & 0xFFFFFC1F) == 0x910003FD:
        return "mov x29,sp"
    if (w & 0x3B000000) == 0x29000000 and (w & 0xC00) == 0xC00:
        return "stp/str pre-index"
    if (w & 0x3B000000) == 0x29000000:
        return "stp/str offset"
    if (w & 0xFFFFFC1F) in (0xD61F0200, 0xD61F0220):
        return "br x16/x17 (thunk)"
    if (w & 0x9F000000) == 0x90000000:
        return "adrp (PLT stub?)"
    if w == 0:
        return "ZERO"
    return "other"


def main():
    so_path, meta_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    d = open(so_path, "rb").read()
    m = open(meta_path, "rb").read()
    dn = len(d)
    secs = load_sections(d)
    segs = sorted((s["addr"], s["addr"] + s["size"], s["off"], s["sname"], s["flags"])
                  for s in secs if s["type"] != 8 and s["size"] and s["addr"])
    addrs = [x[0] for x in segs]

    def v2o(v, need=1):
        i = bisect.bisect_right(addrs, v) - 1
        if i < 0:
            return None
        a, b, off, nm, fl = segs[i]
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

    def is_code_ptr(v):
        if not v:
            return False
        r = v2o(v, need=4)
        return bool(r and (r[2] & 4))

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

    def grab(base, co, po, cw, pw):
        cnt = struct.unpack_from("<Q" if cw == 8 else "<I", d, base + co)[0]
        ptr = struct.unpack_from("<Q" if pw == 8 else "<I", d, base + po)[0]
        return cnt, ptr

    def code_ratio(cnt, ptr, limit=4000):
        r = v2o(ptr, need=min(cnt * 8, 16))
        if not r:
            return None
        arr, n, hit = r[0], min(cnt, limit), 0
        for k in range(n):
            if is_code_ptr(u64(arr + k * 8)):
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

    rows, mods, still = [], [], []

    def emit(arr_off, mstart, mcount):
        got = 0
        for k in range(mcount):
            e = u64(arr_off + k * 8)
            if e:
                rows.append((mstart + k, e))
                got += 1
        return got

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

    # ---- 允许 null 空洞的滑动窗口匹配（收尾用）----
    print("\n-- 滑动窗口匹配（允许 null 空洞，供未定位程序集使用）--")
    counts = sorted({c for _n, _s, c in still})
    wins = {}
    if counts:
        for s in targets:
            off0, size = s["off"], s["size"]
            nslot = size // 8
            pre = [0] * (nslot + 1)
            acc = 0
            for i in range(nslot):
                if is_code_ptr(u64(off0 + i * 8)):
                    acc += 1
                pre[i + 1] = acc
            for c in counts:
                if c > nslot:
                    continue
                best, bi = -1, -1
                for i in range(0, nslot - c + 1):
                    v = pre[i + c] - pre[i]
                    if v > best:
                        best, bi = v, i
                ratio = 100.0 * best / c
                if ratio >= 90.0 and (c not in wins or ratio > wins[c][0]):
                    wins[c] = (ratio, s, off0 + bi * 8)
        for c in counts:
            if c in wins:
                r, s, off = wins[c]
                print("  count=%-6d 最佳窗口 %s+0x%X  有效 %.1f%%" % (c, s["sname"], off - s["off"], r))

    left = []
    for nm, mstart, mcount in still:
        if mcount in wins:
            r, s, off = wins[mcount]
            n = emit(off, mstart, mcount)
            mods.append((nm, mcount, r, "%s+0x%X(window)" % (s["sname"], off - s["off"])))
            print("  %-42s md=%-6d → 窗口匹配，写入 %d 条" % (nm, mcount, n))
        else:
            left.append([nm, mcount])

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
        sample = rows[::max(1, len(rows) // 300)][:300]
        for idx, a in sample:
            r = v2o(a, need=4)
            if not r:
                bad += 1
                continue
            k = prologue_kind(struct.unpack_from("<I", d, r[0])[0])
            kinds[k] = kinds.get(k, 0) + 1
        tot = max(1, sum(kinds.values()))
        lines += ["", "地址质量复验（%d 个抽样地址，越界 %d）：" % (len(sample), bad)]
        for k, v in sorted(kinds.items(), key=lambda x: -x[1]):
            lines.append("  %-24s %d (%.1f%%)" % (k, v, 100.0 * v / tot))

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
        lines += ["", "模块定位方式（前 24）："]
        for nm, mc, sc, where in mods[:24]:
            lines.append("  %-42s md=%-6d %6.1f%%  %s" % (nm, mc, sc, where))
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