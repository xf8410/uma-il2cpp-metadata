#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 APK 里删除指定后缀的 entry（默认 libtersafe2.so），其它 entry 原样复制

    python3 tools/remove_entry.py <in.apk> <out.apk> [关键词]
"""
import sys
import zipfile


def main():
    src, dst = sys.argv[1], sys.argv[2]
    key = sys.argv[3] if len(sys.argv) > 3 else "libtersafe2.so"
    removed = []
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for it in zin.infolist():
            if key in it.filename:
                removed.append(it.filename)
                continue
            ni = zipfile.ZipInfo(it.filename, date_time=it.date_time)
            ni.compress_type = it.compress_type
            ni.external_attr = it.external_attr
            ni.create_system = it.create_system
            zout.writestr(ni, zin.read(it.filename))
    print("removed:", removed)
    print("entries kept:", len(zipfile.ZipFile(dst).namelist()))


if __name__ == "__main__":
    main()