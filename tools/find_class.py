#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按方法 idx 找出它所属的类，反汇编这个类的全部方法，抓 mov 立即数与字符串引用

    pip install capstone
    python3 tools/find_class.py <libil2cpp.so> <methods_rva.tsv> <methods.tsv> <types.tsv> <outdir> <idx,idx,...>

methods.tsv 表头: decl_type_index  name  token  param_count（行序 = 方法 idx）
methods_rva.tsv: idx \t RVA(hex)
"""
import os
import re
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    raise SystemExit("需要 capstone: pip install capstone")

MAX_INSN = 120


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
    so_path, rva_tsv, meth_tsv, type_tsv, outdir = sys.argv[1:6]
    want_idx = [int(x) for x in sys.argv[6].split(",") if x.strip()]
    os.makedirs(outdir, exist_ok=True)

    d = open(so_path, "rb").read()
    secs = [s for s in load_sections(d) if s[4] and s[2] and s[0] != 8]

    def v2o(v, need=1):
        for _t, _f, a, off, size in secs:
            if a <= v < a + size and v + need <= a + size:
                return off + (v - a)
        return None

    rva = {}
    with open(rva_tsv, encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2 and p[0].isdigit():
                try:
                    rva[int(p[0])] = int(p[1], 16)
                except ValueError:
                    pass

    # methods.tsv: 第一行表头，之后每行一个方法（行序 = idx）
    meths = []
    with open(meth_tsv, encoding="utf-8", errors="replace") as f:
        header = f.readline()
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2 and p[0].isdigit():
                meths.append((int(p[0]), p[1]))
    print("methods.tsv 行数 %d（表头：%s）" % (len(meths), header.strip()))

    tnames = {}
    with open(type_tsv, encoding="utf-8", errors="replace") as f:
        hdr = f.readline()
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2 and p[0].isdigit():
                tnames[int(p[0])] = p[1]
    print("types.tsv 行数 %d（表头：%s）" % (len(tnames), hdr.strip()))

    md = Cs(CS_ARCH_AARCH64 if hasattr(Cs, "CS_ARCH_AARCH64") else CS_ARCH_ARM64, CS_MODE_ARM)

    for idx in want_idx:
        if idx >= len(meths):
            print("idx %d 超出 methods.tsv" % idx)
            continue
        tdecl, nm = meths[idx]
        tname = tnames.get(tdecl, "?")
        print("\n##### idx=%d  %s  ->  类[%d] %s" % (idx, nm, tdecl, tname))
        members = [(i, m) for i, (t, m) in enumerate(meths) if t == tdecl]
        print("    该类方法 %d 个" % len(members))
        out = ["=== idx=%d %s  类[%d] %s ===" % (idx, nm, tdecl, tname)]
        for i, m in members:
            v = rva.get(i)
            tag = " <== 目标" if i == idx else ""
            out.append("\n--- idx=%d %s RVA=%s%s ---" % (i, m, ("0x%X" % v) if v else "无", tag))
            if v is None:
                continue
            off = v2o(v, need=16)
            if off is None:
                continue
            k = 0
            for insn in md.disasm(d[off:off + MAX_INSN * 4], v):
                k += 1
                if k > MAX_INSN:
                    break
                out.append("  0x%-10X %-8s %s" % (insn.address, insn.mnemonic, insn.op_str))
                if insn.mnemonic in ("ret",) and k > 8:
                    break
        path = os.path.join(outdir, "class-%d.txt" % idx)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print("    -> %s" % path)


if __name__ == "__main__":
    main()