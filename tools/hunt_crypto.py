#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编 il2cpp 里的加解密方法，抽取 key/IV 线索

    pip install capstone
    python3 tools/hunt_crypto.py <libil2cpp.so> <methods_rva.tsv> <methods.tsv> [名字正则]

methods_rva.tsv  : idx \t RVA(hex)
methods.tsv      : idx \t ... \t name        （最后一段当方法名）

对每个命中方法：
  1) 反汇编前 256 条指令（打印前 40 条）；
  2) 收集 adrp/add、adrp/ldr 的落点，把落点后 64 字节按 hex + ASCII 打出来
     （key/IV/常量表通常就在这些位置）；
  3) 全量统计命中数，便于换正则再跑。
"""
import re
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    raise SystemExit("需要 capstone: pip install capstone")

MAX_INSN = 256
WIN = 64

DEFAULT_RE = r"^(DecryptRJ256|EncryptRJ256|DecryptAcb|CreateKey|Decrypt|Encrypt)$"


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
    so_path, rva_tsv, meth_tsv = sys.argv[1], sys.argv[2], sys.argv[3]
    pat = re.compile(sys.argv[4] if len(sys.argv) > 4 else DEFAULT_RE)

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

    names = {}
    with open(meth_tsv, encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2 and p[0].isdigit():
                nm = p[-1].strip()
                if nm:
                    names[int(p[0])] = nm

    hits = sorted((i, n) for i, n in names.items() if pat.search(n))
    print("methods.tsv 名字 %d 个，methods_rva.tsv %d 条，命中 %d 个"
          % (len(names), len(rva), len(hits)))

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    for idx, nm in hits[:12]:
        v = rva.get(idx)
        if v is None:
            print("\n[%d] %s  —— 无 RVA，跳过" % (idx, nm))
            continue
        off = v2o(v, need=16)
        if off is None:
            print("\n[%d] %s  RVA=0x%X 不在可映射段，跳过" % (idx, nm, v))
            continue
        code = d[off:off + MAX_INSN * 4]
        print("\n===== [%d] %s   RVA=0x%X  file=0x%X =====" % (idx, nm, v, off))

        targets, n, pending = [], 0, {}
        for insn in md.disasm(code, v):
            n += 1
            if n > MAX_INSN:
                break
            if n <= 40:
                print("  0x%-10X %-8s %s" % (insn.address, insn.mnemonic, insn.op_str))
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
        print("  ...（共 %d 条指令）" % n)

        seen = set()
        for t in targets[:16]:
            if t in seen:
                continue
            seen.add(t)
            to = v2o(t, need=8)
            if to is None:
                continue
            blob = d[to:to + WIN]
            txt = "".join(chr(b) if 32 <= b < 127 else "." for b in blob)
            print("  -> 0x%-10X %s" % (t, blob[:32].hex(" ")))
            print("     %s" % txt)

    print("\n提示：RJ256 的 key/IV 是 32 字节常量，看 -> 行里成片规律/可打印的字节。")


if __name__ == "__main__":
    main()