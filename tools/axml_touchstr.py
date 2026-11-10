#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在二进制 AndroidManifest.xml 里做一个等长的 ASCII 字符串替换。

    python3 tools/axml_touchstr.py <AndroidManifest.xml> 2.0.5 2.0.9

只做字节替换，长度必须一致（AXML 的 string pool 索引/偏移才不会被破坏）。
AXML 的池可能是 UTF-8 也可能是 UTF-16LE，两种都试（本包的 manifest 是 UTF-16LE）。

用途：测「TP 是否校验 AndroidManifest.xml」这个单一变量。
比如把 versionName 2.0.5 → 2.0.9：对逻辑零影响，但文件字节变了。
- 还能进游戏 ⇒ manifest 不被校验
- 也黑屏   ⇒ manifest 也在校验范围内
"""
import sys


def main():
    path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
    if len(old) != len(new):
        raise SystemExit("必须等长替换")
    with open(path, "rb") as f:
        b = bytearray(f.read())
    total = 0
    for enc, name in (("utf-8", "UTF-8"), ("utf-16-le", "UTF-16LE")):
        pat = old.encode(enc)
        rep = new.encode(enc)
        n = bytes(b).count(pat)
        if n:
            b = bytearray(bytes(b).replace(pat, rep))
            print("%s: 替换 %d 处 %r -> %r" % (name, n, old, new))
            total += n
    if not total:
        raise SystemExit("没找到可替换的字符串（可能池里是别的编码或形式）")
    with open(path, "wb") as f:
        f.write(bytes(b))
    print("输出 %d 字节" % len(b))


if __name__ == "__main__":
    main()