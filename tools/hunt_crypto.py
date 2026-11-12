#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编 il2cpp 里的加解密方法，抽取 key/IV 线索

    pip install capstone
    python3 tools/hunt_crypto.py <libil2cpp.so> <methods_rva.tsv> <targets.tsv> [outdir]

targets.tsv : idx \t name

每个方法单独写 <outdir>/<idx>-<name>.txt：
  * 前 200 条指令
  * adrp/add、adrp/ldr 落点后 64 字节（hex + ASCII）
  * 落点附近 4 KiB 内可打印串
stdout 只输出摘要（日志不至于太长被截断）。
"""
import os
import re
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    raise SystemExit("需要 capstone: pip install capstone")

MAX_INSN = 200
WIN = 64


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


def ascii_of(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def main():
    so_path, rva_tsv, targets_tsv = sys.argv[1], sys.argv[2], sys.argv[3]
    outdir = sys.argv[4] if len(sys.argv) > 4 else "crypto-hunt"
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

    targets_list = []
    with open(targets_tsv, encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2 and p[0].strip().isdigit():
                targets_list.append((int(p[0]), p[1].strip()))

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    print("rva %d 条，目标 %d 个" % (len(rva), len(targets_list)))

    for idx, nm in targets_list:
        v = rva.get(idx)
        if v is None:
            print("[%d] %s 无 RVA" % (idx, nm))
            continue
        off = v2o(v, need=16)
        if off is None:
            print("[%d] %s RVA 0x%X 不可映射" % (idx, nm, v))
            continue

        out = ["=== [%d] %s  RVA=0x%X  file=0x%X ===" % (idx, nm, v, off)]
        code = d[off:off + MAX_INSN * 4]
        pending, targets, n = {}, [], 0
        for insn in md.disasm(code, v):
            n += 1
            if n > MAX_INSN:
                break
            out.append("  0x%-10X %-8s %s" % (insn.address, insn.mnemonic, insn.op_str))
            if insn.mnemonic == "adrp":
                try:
                    reg, imm = insn.op_str.split(", ")
                    pending[reg] = int(imm, 0)
                except ValueError:
                    pass
            elif insn.mnemonic in ("add", "ldr") and pending:
                m = re.match(r"^(\w+), (\w+), #(0x[0-9a-fA-F]+)$", insn.op_str)
                if m and m.group(2) in pending:
                    targets.append(pending[m.group(2)] + int(m.group(3), 0))
        out.append("\n--- 共 %d 条指令，数据引用 %d 个 ---" % (n, len(targets)))

        seen = set()
        for t in targets:
            if t in seen:
                continue
            seen.add(t)
            to = v2o(t, need=8)
            if to is None:
                continue
            blob = d[to:to + WIN]
            out.append("-> 0x%-10X %s" % (t, blob[:32].hex(" ")))
            out.append("   %s" % ascii_of(blob))
            seg = d[max(0, to - 2048):to + 2048]
            for s in re.findall(rb"[ -~]{8,}", seg)[:5]:
                out.append("   str: %s" % s.decode("latin-1"))

        path = os.path.join(outdir, "%d-%s.txt" % (idx, re.sub(r"[^\w.-]", "_", nm)))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print("[%d] %-18s RVA=0x%-9X 指令 %d，引用 %d -> %s"
              % (idx, nm, v, n, len(seen), path))

    cand = set(m.group(0) for m in re.finditer(rb"[A-Za-z0-9+/=]{32}", d))
    with open(os.path.join(outdir, "thirty-two-char-strings.txt"), "w", encoding="utf-8") as f:
        for c in sorted(cand)[:400]:
            f.write(c.decode("latin-1") + "\n")
    print("32 字符候选 %d 条 -> %s/thirty-two-char-strings.txt" % (len(cand), outdir))


if __name__ == "__main__":
    main()