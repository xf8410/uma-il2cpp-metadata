#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 dex 末尾追加 N 个 0 字节，并更新 file_size / signature / checksum。

    python3 tools/dex_pad.py <file.dex> [n=4]

用途：语义完全不变的"最小改动"探针，用来测 TP 的校验覆盖范围：
- 末尾追加后仍能进游戏 ⇒ TP 只校验文件前缀/头部，不是整文件哈希 ⇒ 后面还有戏
- 也黑屏           ⇒ TP 对整文件做哈希（或至少覆盖到尾部）⇒ 这条路封死
"""
import hashlib
import struct
import sys
import zlib


def main():
    path = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    with open(path, "rb") as f:
        b = bytearray(f.read())
    if b[:4] != b"dex\n":
        raise SystemExit("不是 dex")
    old_size = struct.unpack_from("<I", b, 0x20)[0]
    b += b"\x00" * n
    struct.pack_into("<I", b, 0x20, len(b))
    b[12:32] = b"\0" * 20
    b[12:32] = hashlib.sha1(bytes(b[32:])).digest()
    struct.pack_into("<I", b, 8, zlib.adler32(bytes(b[12:])) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(bytes(b))
    print("补齐 %d 字节: file_size %d -> %d" % (n, old_size, len(b)))


if __name__ == "__main__":
    main()