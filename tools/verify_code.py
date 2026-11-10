#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编抽样验证 + XOR 0x97 加密区间的精细定位 + 解密复验

    pip install capstone
    python3 tools/verify_code.py <libil2cpp.so> <global-metadata.fixed.dat> <methods_rva.tsv>

流程：
  1) 抽样 200 个 RVA，反汇编判定是「明文代码 / XOR 0x97 加密 / 长函数 / 解不开」；
  2) 对 AX 段按 **256 字节** 粒度算 capstone 覆盖率，判定每个窗口是明文还是加密
     （覆盖率 = 被成功解码的字节比例；加密数据原样解释时覆盖率很低）；
  3) 合并相邻窗口 → 写 code_xor97_pages.txt；
  4) 在内存里按该表解密，再对同一批地址复验，输出解密前后的成功率对比。
"""
import os
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    raise SystemExit("需要 capstone: pip install capstone")

MAX_INSN = 400
XOR_KEY = 0x97
WIN = 256


def load_sections(d):
    (_t, _m, _v, _e, _phoff, shoff, _f, _eh, _ph, _phn,
     shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
    secs = []
    for i in range(shnum):
        b = shoff + i * shentsize
        (nm, stype, flags, addr, off, size, _l, _i, _a, _es) = \
            struct.unpack_from("<IIQQQQIIQQ", d, b)
        secs.append((stype, flags, addr, off, size))
    return secs


def run_code(md, code, addr, limit=MAX_INSN):
    n, first = 0, []
    for insn in md.disasm(code, addr):
        if n < 6:
            first.append("%s %s" % (insn.mnemonic, insn.op_str))
        n += 1
        if insn.mnemonic.startswith("ret"):
            return True, n, first
        if insn.mnemonic == "b" and not insn.op_str.startswith("#"):
            return True, n, first
        if n >= limit:
            break
    return False, n, first


def coverage(md, blk):
    total = len(blk) - (len(blk) % 4)
    if total <= 0:
        return 0.0
    got = 0
    for insn in md.disasm(blk, 0):
        got += insn.size
    return got / total


def main():
    so_path, meta_path, tsv = sys.argv[1], sys.argv[2], sys.argv[3]
    d = open(so_path, "rb").read()
    secs_all = load_sections(d)
    secs = [s for s in secs_all if s[0] != 8 and s[4] and s[2]]
    ax = sorted((s[2], s[3], s[4]) for s in secs if s[1] & 4)   # (vaddr, off, size)

    def v2o(v, need=1):
        for _t, _f, a, off, size in secs:
            if a <= v < a + size and v + need <= a + size:
                return off + (v - a), size - (v - a)
        return None, 0

    rows = []
    with open(tsv, encoding="utf-8") as f:
        next(f, None)
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) == 2:
                rows.append((int(p[0]), int(p[1], 16)))
    if not rows:
        raise SystemExit("tsv 为空")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    def classify(buf, addr):
        off, avail = v2o(addr, need=4)
        if off is None:
            return None, 0, []
        code = buf[off:off + min(avail, MAX_INSN * 4)]
        ok, n, first = run_code(md, code, addr)
        if ok:
            return "ret", n, first
        if n == 0:
            if code[:64] == b"\x00" * 64:
                return "zero_page", 0, []
            if run_code(md, bytes(b ^ XOR_KEY for b in code), addr)[0]:
                return "xor97", n, []
            return "undecodable", 0, []
        return ("truncated" if n >= MAX_INSN else "no_return"), n, first

    sample = rows[::max(1, len(rows) // 200)][:200]
    stats, examples, bad_examples = {}, [], []
    for idx, addr in sample:
        verdict, n, first = classify(d, addr)
        if verdict is None:
            stats["bad_offset"] = stats.get("bad_offset", 0) + 1
            continue
        stats[verdict] = stats.get(verdict, 0) + 1
        if verdict in ("xor97", "undecodable") and len(bad_examples) < 5:
            off, _ = v2o(addr, need=4)
            bad_examples.append((addr, idx, verdict, d[off:off + 16].hex(" ")))
        if verdict == "ret" and len(examples) < 3:
            examples.append((addr, idx, n, first))

    total = sum(stats.values()) or 1
    print("抽样 %d 个地址（共 %d 条映射）" % (len(sample), len(rows)))
    for k in ("ret", "xor97", "truncated", "no_return", "zero_page", "undecodable", "bad_offset"):
        if stats.get(k):
            print("  %-12s %4d (%.1f%%)" % (k, stats[k], 100.0 * stats[k] / total))

    # ---------- 精细加密区间（256B 窗口）----------
    print("\n精细扫描（%d 字节窗口，AX 段共 %.1f MiB）：" % (WIN, sum(s[2] for s in ax) / 1048576.0))
    enc_ranges, n_win = [], 0
    for vaddr, off, size in ax:
        p = 0
        while p + WIN <= size:
            blk = d[off + p: off + p + WIN]
            n_win += 1
            c_p = coverage(md, blk)
            if c_p < 0.90:
                c_e = coverage(md, bytes(b ^ XOR_KEY for b in blk))
                if c_e >= 0.90 and c_e - c_p > 0.30:
                    if enc_ranges and enc_ranges[-1][1] == off + p:
                        enc_ranges[-1][1] = off + p + WIN
                    else:
                        enc_ranges.append([off + p, off + p + WIN])
            p += WIN
    enc_bytes = sum(b - a for a, b in enc_ranges)
    ax_bytes = sum(s[2] for s in ax) or 1
    print("  窗口 %d 个；判定为加密 %d 段，共 %.2f MiB（%.1f%% of AX）"
          % (n_win, len(enc_ranges), enc_bytes / 1048576.0, 100.0 * enc_bytes / ax_bytes))
    for a, b in enc_ranges[:10]:
        print("    0x%X ~ 0x%X  (%d B)" % (a, b, b - a))

    sd = os.path.dirname(os.path.abspath(tsv))
    with open(os.path.join(sd, "code_xor97_pages.txt"), "w", encoding="utf-8") as f:
        f.write("# start\tend\t(AX 段里按 XOR 0x97 加密的代码区间)\n")
        for a, b in enc_ranges:
            f.write("0x%X\t0x%X\n" % (a, b))

    # ---------- 内存解密后复验 ----------
    buf = bytearray(d)
    for a, b in enc_ranges:
        buf[a:b] = bytes(x ^ XOR_KEY for x in buf[a:b])
    after = {}
    for idx, addr in sample:
        verdict, _n, _f = classify(bytes(buf), addr)
        if verdict is None:
            continue
        after[verdict] = after.get(verdict, 0) + 1
    ok_before = stats.get("ret", 0)
    ok_after = after.get("ret", 0)
    print("\n解密后复验（同一批 %d 个地址）：" % len(sample))
    for k in ("ret", "xor97", "truncated", "no_return", "undecodable", "zero_page"):
        if after.get(k):
            print("  %-12s %4d (%.1f%%)" % (k, after[k], 100.0 * after[k] / total))
    print("  走到 ret 的比例：解密前 %d (%.1f%%) → 解密后 %d (%.1f%%)"
          % (ok_before, 100.0 * ok_before / total, ok_after, 100.0 * ok_after / total))
    left = after.get("undecodable", 0) + after.get("zero_page", 0)
    print("  仍解不开：%d (%.1f%%)" % (left, 100.0 * left / total))

    print("\n正常样例：")
    for addr, idx, n, first in examples:
        print("  0x%X  #%d  %d 条指令" % (addr, idx, n))
        for s in first:
            print("     " + s)
    if bad_examples:
        print("\n加密/异常样例：")
        for addr, idx, verdict, hx in bad_examples:
            print("  0x%-9X #%-7d %-12s %s" % (addr, idx, verdict, hx))


if __name__ == "__main__":
    main()