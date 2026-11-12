#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""找 BL/B（直接调用与尾调用）到指定 RVA 的位置，并打印自检计数

    pip install numpy capstone
    python3 tools/find_callers2.py <libil2cpp.so> <outdir> <目标RVA,逗号分隔>

自检：会打印全 .so 的 BL 总数、B 总数，以及每个目标命中的调用点。
用途：若 0 命中，说明该方法只能通过函数指针/虚表调用（il2cpp 很常见）。
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

BACK = 40
FWD = 8


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
    total_bl = total_b = 0
    hits_map = {T: [] for T in wanted}

    for _t, _f, va, off, size in exec_secs:
        n4 = (size // 4) * 4
        arr = np.frombuffer(d[off:off + n4], dtype="<u4").astype(np.int64)
        addrs = va + np.arange(arr.size, dtype=np.int64) * 4

        isbl = (arr & 0xFC000000) == 0x94000000
        isb = (arr & 0xFC000000) == 0x14000000
        total_bl += int(isbl.sum())
        total_b += int(isb.sum())

        for mask, sel in ((0x94000000, isbl), (0x14000000, isb)):
            idx = np.nonzero(sel)[0]
            if idx.size == 0:
                continue
            imm = arr[idx] & 0x3FFFFFF
            imm = np.where(imm >= 0x2000000, imm - 0x4000000, imm)
            tgts = addrs[idx] + (imm << 2)
            for T in wanted:
                h = idx[tgts == T]
                for x in h[:40]:
                    hits_map[T].append(int(addrs[x]))

    print("自检：可执行段 BL 总数 %d，B 总数 %d" % (total_bl, total_b))

    for T in wanted:
        hits = sorted(set(hits_map[T]))
        lines = ["=== 调用/跳转到 0x%X：%d 处 ===" % (T, len(hits))]
        for call_addr in hits[:40]:
            call_off = v2o(call_addr, need=4)
            if call_off is None:
                continue
            start = call_addr - BACK * 4
            start_off = v2o(start, need=4)
            if start_off is None:
                start, start_off = call_addr, call_off
            blob = d[start_off:call_off + FWD * 4]
            lines.append("\n--- 0x%X ---" % call_addr)
            k = 0
            for insn in md.disasm(blob, start):
                if k >= BACK + FWD:
                    break
                mark = " <<<" if insn.address == call_addr else ""
                lines.append("  0x%-10X %-8s %s%s"
                             % (insn.address, insn.mnemonic, insn.op_str, mark))
                k += 1
            seg = d[max(0, start_off - 1024):call_off + 1024]
            for s in re.findall(rb"[ -~]{8,}", seg)[:5]:
                lines.append("   str: %s" % s.decode("latin-1"))
        path = os.path.join(outdir, "callers-%X.txt" % T)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print("0x%X -> %d 处 -> %s" % (T, len(hits), path))


if __name__ == "__main__":
    main()