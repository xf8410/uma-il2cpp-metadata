#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地解密 libil2cpp.so 的代码区间（按 code_xor97_pages.txt）

    python3 tools/decrypt_so.py <libil2cpp.so> <code_xor97_pages.txt> <out.so>

说明：这份 so 里每 64KB 有一段（约 0x2050~0x5F50）代码在磁盘上是 XOR 0x97 的，
共约 17.61 MiB（24.2% 的 AX 段）。解密后再丢给 IDA / Ghidra / Il2CppInspector，
反汇编才是真实的指令。

区间表由 tools/verify_code.py 在 CI 里自动生成（256 字节粒度 + capstone 覆盖率判定）。
"""
import sys


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    src, pages, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    d = bytearray(open(src, "rb").read())
    n = 0
    total = 0
    with open(pages, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = line.split()
            if len(p) < 2:
                continue
            a, b = int(p[0], 0), int(p[1], 0)
            if not (0 <= a < b <= len(d)):
                print("跳过越界区间 0x%X~0x%X" % (a, b))
                continue
            d[a:b] = bytes(x ^ 0x97 for x in d[a:b])
            n += 1
            total += b - a
    open(dst, "wb").write(d)
    print("解密 %d 段，共 %.2f MiB -> %s" % (n, total / 1048576.0, dst))


if __name__ == "__main__":
    main()