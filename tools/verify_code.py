#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编抽样验证 + 加密代码页定位（XOR 0x97）

    pip install capstone
    python3 tools/verify_code.py <libil2cpp.so> <global-metadata.fixed.dat> <methods_rva.tsv>

两段输出（同时写盘，供仓库留档）：
  1) 抽样反汇编：能否在 N 条指令内走到 ret / 尾调用 → 判断地址是否为函数入口；
  2) 加密页识别：对同批地址分别按「原样」和「XOR 0x97」反汇编，
     按 4KB 页多数票判定该页是否加密，输出区间到 code_xor97_pages.txt。
"""
import os
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    raise SystemExit("需要 capstone: pip install capstone")

MAX_INSN = 400


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
    """返回 (是否走到返回/尾调用, 指令数, 前 6 条)"""
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


def main():
    so_path, meta_path, tsv = sys.argv[1], sys.argv[2], sys.argv[3]
    d = open(so_path, "rb").read()
    secs_all = load_sections(d)
    secs = [s for s in secs_all if s[0] != 8 and s[4] and s[2]]
    ax = sorted((s[2], s[2] + s[4]) for s in secs if s[1] & 4)

    def v2o(v, need=1):
        for _t, _f, a, off, size in secs:
            if a <= v < a + size and v + need <= a + size:
                return off + (v - a), size - (v - a)
        return None, 0

    def in_ax(v):
        for a, b in ax:
            if a <= v < b:
                return True
        return False

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
    stats = {}
    examples, bad_examples = [], []
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
            verdict = "zero_page" if code[:64] == b"\x00" * 64 else "undecodable"
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
    for k in ("ret", "truncated", "no_return", "zero_page", "undecodable", "bad_offset"):
        if stats.get(k):
            print("  %-12s %4d (%.1f%%)" % (k, stats[k], 100.0 * stats[k] / total))
    print("判定为函数入口: %d/%d = %.1f%%" % (stats.get("ret", 0), total,
                                       100.0 * stats.get("ret", 0) / total))

    # ---------- 2) 加密页识别 ----------
    print("\n加密页识别（对同一批地址，原样 vs XOR 0x97）：")
    votes = {}
    n_ax = 0
    for idx, addr in rows[::max(1, len(rows) // 4000)][:20000]:
        if not in_ax(addr):
            continue
        off, avail = v2o(addr, need=4)
        if off is None:
            continue
        code = d[off:off + MAX_INSN * 4]
        ok_p, _, _ = run_code(md, code, addr, 200)
        ok_e, _, _ = run_code(md, bytes(b ^ 0x97 for b in code), addr, 200)
        v = votes.setdefault(off & ~0xFFF, [0, 0])
        v[0] += 1 if ok_p else 0
        v[1] += 1 if ok_e else 0
        n_ax += 1

    enc = sorted(p for p, (a, b) in votes.items() if b > a and b >= 2)
    plain = [p for p, (a, b) in votes.items() if a >= b]
    ranges = []
    for p in enc:
        if ranges and p == ranges[-1][1]:
            ranges[-1][1] = p + 4096
        else:
            ranges.append([p, p + 4096])
    enc_bytes = sum(b - a for a, b in ranges)
    ax_bytes = sum(b - a for a, b in ax) or 1
    print("  参与判定地址 %d；加密页 %d、明文页 %d" % (n_ax, len(enc), len(plain)))
    print("  加密区间 %d 段，共 %d B（%.1f%% of AX，%.2f MiB）"
          % (len(ranges), enc_bytes, 100.0 * enc_bytes / ax_bytes, enc_bytes / 1048576.0))
    for a, b in ranges[:12]:
        print("    0x%X ~ 0x%X  (%d B)" % (a, b, b - a))

    sd = os.path.dirname(os.path.abspath(tsv))
    with open(os.path.join(sd, "code_xor97_pages.txt"), "w", encoding="utf-8") as f:
        f.write("# start\tend\t(XOR 0x97 加密的代码页)\n")
        for a, b in ranges:
            f.write("0x%X\t0x%X\n" % (a, b))

    print("\n正常样例：")
    for addr, idx, n, verdict, first in examples:
        print("  0x%X  #%d  %d 条指令 -> %s" % (addr, idx, n, verdict))
        for s in first:
            print("     " + s)
    if bad_examples:
        print("\n异常样例（地址 -> 前 16 字节）：")
        for addr, idx, verdict, hx in bad_examples:
            print("  0x%-9X #%-7d %-12s %s" % (addr, idx, verdict, hx))


if __name__ == "__main__":
    main()