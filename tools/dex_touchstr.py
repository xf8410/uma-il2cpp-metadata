#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 dex 里把一个「日志类字符串」改掉 1 个字符，长度不变、偏移不动，再重算校验。

    python3 tools/dex_touchstr.py <file.dex> [dry]

用途：做一个"语义几乎不变、但不是 smali 重组产物"的探针。
- 若游戏也黑屏 ⇒ ART 不会因为改个日志字符串就挂，说明是 TP 对 dex 字节做了拦截
- 若能跑    ⇒ dex 内容改动本身没问题，黑屏出在 smali 重组出来的 dex 上

选串规则：ASCII、长度 >= 16、含 error/fail/warn、不是类/方法描述符（不以 L ( [ 开头）。
改动：把第 3 个字符换成同大小写的相邻字母，长度不变。
"""
import hashlib
import struct
import sys
import zlib


def uleb(b, o):
    r = s = 0
    while True:
        c = b[o]
        o += 1
        r |= (c & 0x7F) << s
        if not (c & 0x80):
            return r, o
        s += 7


def main():
    path = sys.argv[1]
    dry = len(sys.argv) > 2 and sys.argv[2] == "dry"
    with open(path, "rb") as f:
        b = bytearray(f.read())
    if b[:4] != b"dex\n":
        raise SystemExit("不是 dex")
    u32 = lambda o: struct.unpack_from("<I", b, o)[0]
    str_n, str_off = u32(56), u32(60)
    target = None
    for i in range(str_n):
        data_off = u32(str_off + i * 4)
        _, p = uleb(b, data_off)
        end = b.index(b"\x00", p)
        raw = bytes(b[p:end])
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(s) < 16 or not s.isascii():
            continue
        if s[0] in "L([":
            continue
        low = s.lower()
        if not ("error" in low or "fail" in low or "warn" in low):
            continue
        c = s[2]
        if not c.isalpha():
            continue
        new = ("f" if c.lower() == "e" else "e") if c.islower() else ("F" if c.upper() == "E" else "E")
        cand = s[:2] + new + s[3:]
        if cand == s:
            continue
        target = (i, p, s, cand, raw)
        break
    if not target:
        raise SystemExit("没找到合适的字符串")
    i, p, old, new, raw = target
    nb = new.encode("utf-8")
    assert len(nb) == len(raw), "长度必须一致"
    print("字符串 #%d: %r -> %r" % (i, old, new))
    if dry:
        return
    b[p:p + len(nb)] = nb
    b[12:32] = b"\0" * 20
    b[12:32] = hashlib.sha1(bytes(b[32:])).digest()
    struct.pack_into("<I", b, 8, zlib.adler32(bytes(b[12:])) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(bytes(b))
    print("已写回并重算 signature/checksum")


if __name__ == "__main__":
    main()