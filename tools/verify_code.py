#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 capstone 反汇编抽样地址，验证「这些地址确实是函数入口」

    pip install capstone
    python3 tools/verify_code.py <libil2cpp.so> <global-metadata.fixed.dat> <methods_rva.tsv>

判据：从目标地址反汇编，能在 N 条指令内遇到 `ret` 或尾调用 `b <addr>` → 判为入口。
反汇编不出任何指令时进一步区分：
  · zero_page   —— 目标处是全 0（代码被抠掉/占位）
  · undecodable —— 非 0 但解不开（多半说明映射指错了地方）
"""
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


def main():
    so_path, meta_path, tsv = sys.argv[1], sys.argv[2], sys.argv[3]
    d = open(so_path, "rb").read()
    secs = [s for s in load_sections(d) if s[0] != 8 and s[4] and s[2]]

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

    sample = rows[::max(1, len(rows) // 200)][:200]
    stats = {}
    examples, bad_examples = [], []
    for idx, addr in sample:
        off, avail = v2o(addr, need=4)
        if off is None:
            stats["bad_offset"] = stats.get("bad_offset", 0) + 1
            continue
        code = d[off:off + min(avail, MAX_INSN * 4)]
        n, verdict, first = 0, "truncated", []
        for insn in md.disasm(code, addr):
            if n < 6:
                first.append("%s %s" % (insn.mnemonic, insn.op_str))
            n += 1
            if insn.mnemonic.startswith("ret"):
                verdict = "ret"
                break
            if insn.mnemonic == "b" and not insn.op_str.startswith("#"):
                verdict = "tailcall_b"
                break
            if n >= MAX_INSN:
                break
        if n == 0:
            verdict = "zero_page" if code[:64] == b"\x00" * 64 else "undecodable"
            if len(bad_examples) < 4:
                bad_examples.append((addr, idx, verdict, code[:16].hex(" ")))
        stats[verdict] = stats.get(verdict, 0) + 1
        if len(examples) < 3:
            examples.append((addr, idx, n, verdict, first))

    total = sum(stats.values()) or 1
    print("抽样 %d 个地址（共 %d 条映射）" % (len(sample), len(rows)))
    for k in ("ret", "tailcall_b", "truncated", "zero_page", "undecodable", "bad_offset"):
        if stats.get(k):
            print("  %-12s %4d (%.1f%%)" % (k, stats[k], 100.0 * stats[k] / total))
    ok = stats.get("ret", 0) + stats.get("tailcall_b", 0)
    print("判定为函数入口: %d/%d = %.1f%%" % (ok, total, 100.0 * ok / total))
    print("其中「反汇编不出指令」明细: zero_page=%d, undecodable=%d"
          % (stats.get("zero_page", 0), stats.get("undecodable", 0)))

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