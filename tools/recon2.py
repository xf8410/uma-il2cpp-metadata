#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""侦察 v2：用 capstone detail 模式定位「引用校验字符串」的代码

    python3 tools/recon2.py <dir-with-libs> [libtersafe2.so|libtprt.so]
"""
import os
import struct
import sys

import capstone.arm64 as A64
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

KEYS = [b"libmain", b"libil2cpp", b"libunity", b"crc", b"md5", b"sha", b"hash",
        b"verify", b"signature", b"cert", b"tamper", b"code_size", b"ano_cert",
        b"self_sys", b"mrpcs", b"app_ver"]


def sections(d):
    (_, _, _, _, _, shoff, _, _, _, _, shentsize, shnum, shstrndx) = \
        struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
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


def find_strings(d, secs):
    out = []
    for s in secs:
        if s["type"] == 8 or not s["size"] or not s["addr"]:
            continue
        blk = d[s["off"]:s["off"] + s["size"]]
        i = 0
        while i < len(blk):
            j = i
            while j < len(blk) and 32 <= blk[j] < 127:
                j += 1
            if 4 <= j - i <= 160:
                txt = blk[i:j]
                low = txt.lower()
                if any(k in low for k in KEYS):
                    out.append((s["addr"] + i, txt.decode("ascii", "replace")))
            i = j + 1
    return out


def main():
    root = sys.argv[1]
    name = sys.argv[2] if len(sys.argv) > 2 else "libtersafe2.so"
    d = open(os.path.join(root, name), "rb").read()
    secs = sections(d)
    strs = find_strings(d, secs)
    want = {va: t for va, t in strs}
    print("## %s  size=%.2f MiB  关键字符串 %d" % (name, len(d) / 1048576.0, len(strs)))
    for va, t in strs:
        print("   0x%-8X %s" % (va, t[:110]))

    text = [s for s in secs if s["flags"] & 4 and s["size"]]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    hits = []
    for s in text:
        code = d[s["off"]:s["off"] + s["size"]]
        pages = {}
        for insn in md.disasm(code, s["addr"]):
            ops = insn.operands
            if insn.mnemonic == "adrp" and len(ops) == 2:
                rd = insn.reg_name(ops[0].reg)
                pages[rd] = ops[1].imm
                continue
            if insn.mnemonic in ("mov", "orr") and len(ops) == 2 and ops[1].type == A64.ARM64_OP_REG:
                rd, rs = insn.reg_name(ops[0].reg), insn.reg_name(ops[1].reg)
                if rs in pages:
                    pages[rd] = pages[rs]
            for op in ops:
                if op.type == A64.ARM64_OP_MEM:
                    base = insn.reg_name(op.mem.base)
                    if base in pages:
                        tgt = pages[base] + op.mem.disp
                        if tgt in want:
                            hits.append((insn.address, want[tgt], insn.mnemonic))
            if insn.mnemonic == "add" and len(ops) == 3 and ops[2].type == A64.ARM64_OP_IMM:
                base = insn.reg_name(ops[1].reg)
                if base in pages:
                    tgt = pages[base] + ops[2].imm
                    if tgt in want:
                        hits.append((insn.address, want[tgt], "add"))

    print("\n## 引用命中 %d 处" % len(hits))
    for a, t, mn in hits:
        print("   0x%-8X %-4s -> %s" % (a, mn, t[:88]))

    done = set()
    for a, t, mn in hits:
        if len(done) >= 4:
            break
        if a in done:
            continue
        done.add(a)
        print("\n--- 上下文 @0x%X  (%s) ---" % (a, t[:50]))
        so = [s for s in text if s["addr"] <= a < s["addr"] + s["size"]][0]
        start = max(so["addr"], a - 0x60)
        off = so["off"] + (start - so["addr"])
        for insn in md.disasm(d[off:off + 0x140], start):
            print("   0x%X  %-8s %s%s" % (insn.address, insn.mnemonic, insn.op_str,
                                          "   <<<" if insn.address == a else ""))


if __name__ == "__main__":
    main()