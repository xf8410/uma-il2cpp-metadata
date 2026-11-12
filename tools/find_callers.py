#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 .so 里找 BL 到指定 RVA 的调用点，并反汇编调用点前后的代码

    pip install numpy capstone
    python3 tools/find_callers.py <libil2cpp.so> <outdir> <目标RVA,逗号分隔>

用途：定位谁在调用 DecryptRJ256 / DecryptAcb 之类的方法 —— key/IV 就在调用点当参数传进去。
输出：<outdir>/callers-<RVA>.txt
"""
import os
import re
import struct
import sys

import numpy as np

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    raise SystemExit("需要 capstone: pip install capstone")

BACK = 40          # 从调用点往前反汇编多少条指令
FWD = 8            # 调用点之后再看几条


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
    so_path, outdir = sys.argv[1], sys.argv[2]
    wanted = [int(x, 0) for x in sys.argv[3].split(",") if x.strip()]
    os.makedirs(outdir, exist_ok=True)

    d = open(so_path, "rb").read()
    secs = load_sections(d)
    exec_secs = [s for s in secs if (s[1] & 4) and s[4] and s[2]]

    def v2o(v, need=1):
        for _t, _f, a, off, size in secs:
            if a <= v < a + size and v + need <= a + size and size:
                return off + (v - a)
        return None

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    for T in wanted:
        lines = ["=== 调用 0x%X 的地方 ===" % T]
        found = 0
        for _t, _f, va, off, size in exec_secs:
            n4 = (size // 4) * 4
            arr = np.frombuffer(d[off:off + n4], dtype="<u4").astype(np.int64)
            isbl = (arr & 0xFC000000) == 0x94000000
            idx = np.nonzero(isbl)[0]
            if idx.size == 0:
                continue
            w = arr[idx]
            imm = w & 0x3FFFFFF
            imm = np.where(imm >= 0x2000000, imm - 0x4000000, imm)
            addrs = va + idx * 4
            tgts = addrs + (imm << 2)
            hit = idx[tgts == T]
            for h in hit[:40]:
                call_addr = int(va + h * 4)
                call_off = v2o(call_addr, need=4)
                if call_off is None:
                    continue
                found += 1
                start = call_addr - BACK * 4
                start_off = v2o(start, need=4)
                if start_off is None:
                    start, start_off = call_addr, call_off
                blob = d[start_off:call_off + FWD * 4]
                lines.append("\n--- 调用点 0x%X（前面 %d 条指令）---" % (call_addr, BACK))
                k = 0
                for insn in md.disasm(blob, start):
                    if k >= BACK + FWD:
                        break
                    mark = " <<<" if insn.address == call_addr else ""
                    lines.append("  0x%-10X %-8s %s%s"
                                 % (insn.address, insn.mnemonic, insn.op_str, mark))
                    k += 1
                # 附近 1 KiB 的串
                seg = d[max(0, start_off - 1024):call_off + 1024]
                for s in re.findall(rb"[ -~]{8,}", seg)[:5]:
                    lines.append("   str: %s" % s.decode("latin-1"))
        lines.insert(0, "共 %d 处调用" % found)
        path = os.path.join(outdir, "callers-%X.txt" % T)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print("0x%X -> %d 处调用 -> %s" % (T, found, path))


if __name__ == "__main__":
    main()