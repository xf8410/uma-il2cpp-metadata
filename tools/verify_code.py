#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编抽样验证 + XOR 0x97 加密代码页的确定性定位

    pip install capstone
    python3 tools/verify_code.py <libil2cpp.so> <global-metadata.fixed.dat> <methods_rva.tsv>

1) 抽样反汇编：能否在 N 条指令内走到 ret / 尾调用 → 判断地址是否为函数入口；
2) 页级覆盖率：对每个 4KB 页分别按「原样」和「XOR 0x97」反汇编，用
   「被成功解码的字节比例」判定该页是否加密（capstone 遇到解不了的字节会跳过，
   明文代码覆盖率≈100%，加密代码原样解释时覆盖率很低）。结果写 code_xor97_pages.txt。
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

    # ---------- 1) 抽样反汇编 ----------
    sample = rows[::max(1, len(rows) // 200)][:200]
    stats, examples, bad_examples = {}, [], []
    for idx, addr in sample:
        off, avail = v2o(addr, need=4)
        if off is None:
            stats["bad_offset"] = stats.get("bad_offset", 0) + 1
            continue
        code = d[off:off + min(avail, MAX_INSN * 4)]
        ok, n, first = run_code(md, code, addr)
        if ok:
            verdict = "ret"
        elif n == 0:
            verdict = "zero_page" if code[:64] == b"\x00" * 64 else \
                ("xor97" if run_code(md, bytes(b ^ XOR_KEY for b in code), addr)[0]
                 else "undecodable")
            if len(bad_examples) < 4:
                bad_examples.append((addr, idx, verdict, code[:16].hex(" ")))
        elif n >= MAX_INSN:
            verdict = "truncated"
        else:
            verdict = "no_return"
        stats[verdict] = stats.get(verdict, 0) + 1
        if len(examples) < 3:
            examples.append((addr, idx, n, verdict, first))

    total = sum(stats.values()) or 1
    print("抽样 %d 个地址（共 %d 条映射）" % (len(sample), len(rows)))
    for k in ("ret", "xor97", "truncated", "no_return", "zero_page", "undecodable", "bad_offset"):
        if stats.get(k):
            print("  %-12s %4d (%.1f%%)" % (k, stats[k], 100.0 * stats[k] / total))

    # ---------- 2) 页级覆盖率判定加密 ----------
    print("\n页级覆盖率扫描（AX 段共 %.1f MiB）：" % (sum(s[2] for s in ax) / 1048576.0))
    enc_pages = []
    n_pages = 0
    for vaddr, off, size in ax:
        p = 0
        while p + 4096 <= size:
            blk = d[off + p: off + p + 4096]
            c_p = coverage(md, blk)
            if c_p < 0.90:
                c_e = coverage(md, bytes(b ^ XOR_KEY for b in blk))
                if c_e >= 0.90 and c_e - c_p > 0.30:
                    enc_pages.append(off + p)
            n_pages += 1
            p += 4096

    ranges = []
    for off in sorted(enc_pages):
        if ranges and off == ranges[-1][1]:
            ranges[-1][1] = off + 4096
        else:
            ranges.append([off, off + 4096])
    enc_bytes = sum(b - a for a, b in ranges)
    ax_bytes = sum(s[2] for s in ax) or 1
    print("  扫描 %d 页；加密页 %d 页，占 AX 的 %.1f%%（%.2f MiB）"
          % (n_pages, len(enc_pages), 100.0 * enc_bytes / ax_bytes, enc_bytes / 1048576.0))
    print("  加密区间 %d 段，前 12 段：" % len(ranges))
    for a, b in ranges[:12]:
        print("    0x%X ~ 0x%X  (%d B)" % (a, b, b - a))

    # ---------- 3) 用 RVA 表复验：加密页里的方法解密后能否走到 ret ----------
    page_set = set(enc_pages)
    chk_plain = chk_xor = 0
    for idx, addr in rows[::max(1, len(rows) // 3000)][:20000]:
        off, avail = v2o(addr, need=4)
        if off is None or (off & ~0xFFF) not in page_set:
            continue
        code = d[off:off + MAX_INSN * 4]
        if run_code(md, code, addr)[0]:
            chk_plain += 1
        if run_code(md, bytes(b ^ XOR_KEY for b in code), addr)[0]:
            chk_xor += 1
    print("  加密页内的抽样方法：原样可解 %d，XOR 0x97 后解到 ret %d" % (chk_plain, chk_xor))

    sd = os.path.dirname(os.path.abspath(tsv))
    with open(os.path.join(sd, "code_xor97_pages.txt"), "w", encoding="utf-8") as f:
        f.write("# start\tend\t(XOR 0x97 加密的 4KB 代码页)\n")
        for a, b in ranges:
            f.write("0x%X\t0x%X\n" % (a, b))

    print("\n正常样例：")
    for addr, idx, n, verdict, first in examples:
        print("  0x%X  #%d  %d 条指令 -> %s" % (addr, idx, n, verdict))
        for s in first:
            print("     " + s)
    if bad_examples:
        print("\n异常样例：")
        for addr, idx, verdict, hx in bad_examples:
            print("  0x%-9X #%-7d %-12s %s" % (addr, idx, verdict, hx))


if __name__ == "__main__":
    main()