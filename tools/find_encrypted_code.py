#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""定位「磁盘上被 XOR 0x97 加密的代码页」

    pip install capstone
    python3 tools/find_encrypted_code.py <libil2cpp.so> <methods_rva.tsv> <outdir>

方法：从 RVA 表里取样方法地址，分别按「原样」和「XOR 0x97」用 capstone 反汇编，
看哪种解释能走到 `ret`/尾调用。按 4KB 页统计多数票，输出加密页区间。

产物：
  <outdir>/code_xor97_pages.txt   —— 加密页区间（offsetStart offsetEnd，hex）
  <outdir>/so_codecrypt.txt       —— 统计与结论
"""
import os
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    raise SystemExit("需要 capstone: pip install capstone")

MAX_INSN = 300
SAMPLE_EVERY = 8


def load_sections(d):
    (_t, _m, _v, _e, _phoff, shoff, _f, _eh, _ph, _phn,
     shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
    secs = []
    for i in range(shnum):
        b = shoff + i * shentsize
        (nm, stype, flags, addr, off, size, _l, _i, _a, _es) = \
            struct.unpack_from("<IIQQQQIIQQ", d, b)
        secs.append({"type": stype, "flags": flags, "addr": addr,
                     "off": off, "size": size})
    return secs


def reaches_ret(md, code, addr):
    n = 0
    for insn in md.disasm(code, addr):
        n += 1
        if insn.mnemonic.startswith("ret"):
            return True, n
        if insn.mnemonic == "b" and not insn.op_str.startswith("#"):
            return True, n
        if n >= MAX_INSN:
            break
    return (n > 0 and False), n


def main():
    so_path, tsv, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    d = open(so_path, "rb").read()
    dn = len(d)
    secs = [s for s in load_sections(d) if s["type"] != 8 and s["size"] and s["addr"]]
    ax = [s for s in secs if s["flags"] & 4]
    axaddr = sorted((s["addr"], s["addr"] + s["size"]) for s in ax)

    def v2o(v, need=1):
        for s in secs:
            if s["addr"] <= v < s["addr"] + s["size"] and v + need <= s["addr"] + s["size"]:
                return s["off"] + (v - s["addr"])
        return None

    def in_ax(v):
        for a, b in axaddr:
            if a <= v < b:
                return True
        return False

    rows = []
    with open(tsv, encoding="utf-8") as f:
        next(f, None)
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) == 2:
                rows.append(int(p[1], 16))
    if not rows:
        raise SystemExit("rva 表为空")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    page_vote = {}   # page_off -> [plain_ok, enc_ok]
    n_sample = 0
    for a in rows[::SAMPLE_EVERY][:20000]:
        if not in_ax(a):
            continue
        off = v2o(a, need=4)
        if off is None:
            continue
        raw = d[off:off + MAX_INSN * 4]
        ok_p, _ = reaches_ret(md, raw, a)
        dec = bytes(b ^ 0x97 for b in raw)
        ok_e, _ = reaches_ret(md, dec, a)
        pg = off & ~0xFFF
        v = page_vote.setdefault(pg, [0, 0])
        v[0] += 1 if ok_p else 0
        v[1] += 1 if ok_e else 0
        n_sample += 1

    enc_pages = sorted(p for p, (a, b) in page_vote.items() if b > a and b >= 2)
    plain_pages = sorted(p for p, (a, b) in page_vote.items() if a >= b)
    # 合并相邻页
    ranges = []
    for p in enc_pages:
        if ranges and p == ranges[-1][1]:
            ranges[-1][1] = p + 4096
        else:
            ranges.append([p, p + 4096])

    ax_bytes = sum(b - a for a, b in axaddr)
    enc_bytes = sum(b - a for a, b in ranges)
    lines = ["代码加密分析（XOR 0x97）", "========================",
             "抽样方法地址 : %d" % n_sample,
             "判定为加密页 : %d 页（%.1f%% of AX）" % (len(enc_pages), 100.0 * enc_bytes / ax_bytes),
             "判定为明文页 : %d 页" % len(plain_pages),
             "加密区间     : %d 段，共 %d B (%.1f MiB)"
             % (len(ranges), enc_bytes, enc_bytes / 1048576.0),
             "", "前 20 段加密区间："]
    for a, b in ranges[:20]:
        lines.append("  0x%X ~ 0x%X  (%d B)" % (a, b, b - a))

    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "code_xor97_pages.txt"), "w", encoding="utf-8") as f:
        f.write("# start\tend\t(xor 0x97)\n")
        for a, b in ranges:
            f.write("0x%X\t0x%X\n" % (a, b))
    with open(os.path.join(outdir, "so_codecrypt.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()