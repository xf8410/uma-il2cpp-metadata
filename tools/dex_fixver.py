#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 dex 头部版本改成目标版本，并重算 signature(SHA-1) 与 checksum(adler32)。

    python3 tools/dex_fixver.py <file.dex> [037]

为什么需要：baksmali/smali 2.5.2 默认产出 dex 035，而国服 classes3.dex 原本是 037。
035 的规范里「接口里带代码的方法（Java 8 default method）」是非法的，本包 classes3.dex
有 13 个这种方法（Lkotlin/time/TimeSource;、Lokhttp3/CookieJar;、
Lkotlinx/coroutines/flow/SharingStarted; 等），ART 在装载这些类时会验证失败，
表现为启动黑屏（进程不死）。037 与 035 的指令集完全相同，只差这几个语法许可，
所以只改版本号 + 重算两处校验即可，不需要重排任何内容。

dex 头布局：
  0x00 magic      "dex\n035\0"（版本就在 0x04..0x07）
  0x08 checksum   adler32(bytes[0x0C:])
  0x0C signature  sha1(bytes[0x20:])
"""
import hashlib
import struct
import sys
import zlib


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    path = sys.argv[1]
    want = (sys.argv[2] if len(sys.argv) > 2 else "037").encode()
    with open(path, "rb") as f:
        b = bytearray(f.read())
    if b[:4] != b"dex\n":
        raise SystemExit("不是 dex 文件: %s" % path)
    old = bytes(b[4:8]).decode("latin1")
    b[4:8] = want[:3] + b"\0"
    b[8:12] = b"\0\0\0\0"
    b[12:32] = b"\0" * 20
    sig = hashlib.sha1(bytes(b[32:])).digest()
    b[12:32] = sig
    ck = zlib.adler32(bytes(b[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", b, 8, ck)
    with open(path, "wb") as f:
        f.write(bytes(b))
    print("dex 版本 %r -> %s, checksum %08x, signature %s..." % (old, b[4:8].decode("latin1"), ck, sig.hex()[:8]))


if __name__ == "__main__":
    main()