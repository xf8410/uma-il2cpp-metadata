#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按程序集名找 Il2CppCodeGenModule（方法指针表就在每个 module 里）

    python3 tools/find_modules.py <libil2cpp.so> <global-metadata.fixed.dat>

v27+ 之后 methodPointers 不是全局一张表，而是每个 codegen module 一张。
module 结构大致是 { const char* moduleName; ...; Il2CppMethodPointer* methodPointers;
                    ...; int32 methodPointerCount; ... }

做法：
  1. 从 metadata 的 images 表取 73 个程序集名（"Assembly-CSharp.dll" 之类）；
  2. 在 so 里定位这些字符串的 vaddr；
  3. 在数据段里找「u64 == 该 vaddr」的位置 = module 结构里 moduleName 字段；
  4. 把结构前后 8 个 u64 dump 出来分类：指向可执行段(代码)、指向数据段、小整数(计数)；
  5. 若模组数×计数加总 ≈ metadata 方法数，则说明找对了。
"""
import struct
import sys


def load_sections(d):
    (_t, _m, _v, _e, _phoff, shoff, _f, _eh, _ph, _phn,
     shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
    secs = []
    for i in range(shnum):
        b = shoff + i * shentsize
        (nm, stype, flags, addr, off, size, _l, _i, _a, _es) = \
            struct.unpack_from("<IIQQQQIIQQ", d, b)
        secs.append({"name": nm, "type": stype, "flags": flags, "addr": addr,
                     "off": off, "size": size})
    strtab = secs[shstrndx]["off"]
    for s in secs:
        p = strtab + s["name"]
        e = d.find(b"\x00", p)
        s["sname"] = d[p:e].decode("ascii", "replace") if s["type"] != 8 else ""
    return secs


def main():
    so_path, meta_path = sys.argv[1], sys.argv[2]
    d = open(so_path, "rb").read()
    m = open(meta_path, "rb").read()
    secs = load_sections(d)

    segs = [(s["addr"], s["addr"] + s["size"], s["off"], s["sname"], s["flags"])
            for s in secs if s["type"] != 8 and s["size"] and s["addr"]]

    def v2o(v, need=1):
        for a, b, off, nm, fl in segs:
            if a <= v < b and v + need <= b:
                return off + (v - a), nm, fl
        return None

    def o2v(o):
        for a, b, off, nm, fl in segs:
            if off <= o < off + (b - a):
                return a + (o - off), nm, fl
        return None

    pairs = struct.unpack_from("<62i", m, 8)

    def sec(i):
        return pairs[2 * i], pairs[2 * i + 1]

    def ms(idx):
        p = sec(2)[0] + idx
        e = m.find(b"\x00", p)
        return m[p:e].decode("utf-8", "replace")

    io, isz = sec(20)
    n_img = isz // 40
    names = []
    for i in range(n_img):
        nm = ms(struct.unpack_from("<I", m, io + i * 40)[0])
        if nm:
            names.append(nm)
    print("images: %d，示例: %s" % (len(names), names[:5]))

    # 字符串 -> 文件偏移
    name_off = {}
    for nm in names:
        pat = nm.encode() + b"\x00"
        p = d.find(pat)
        if p < 0:
            continue
        v = o2v(p)
        if v:
            name_off[nm] = (p, v[0])

    print("在 so 里定位到 %d/%d 个程序集名字符串" % (len(name_off), len(names)))

    # 数据段里找指向这些字符串的 u64
    targets = [s for s in secs if s["sname"] in (".data", ".data.rel.ro", ".rodata")]
    print("扫描段:", [s["sname"] for s in targets])

    total_count = 0
    found = 0
    for nm, (foff, vaddr) in sorted(name_off.items()):
        occ = []
        for s in targets:
            blk = d[s["off"]:s["off"] + s["size"]]
            start = 0
            while True:
                i = blk.find(struct.pack("<Q", vaddr), start)
                if i < 0:
                    break
                if i % 8 == 0:
                    occ.append((s, s["off"] + i))
                start = i + 1
        if not occ:
            continue
        found += 1
        print("\n== %s   str@0x%X  结构候选 %d" % (nm, vaddr, len(occ)))
        for s, off in occ[:2]:
            print("   in %s +0x%X:" % (s["sname"], off - s["off"]))
            for k in range(-2, 6):
                q = off + k * 8
                if not (0 <= q < len(d) - 8):
                    continue
                v = struct.unpack_from("<Q", d, q)[0]
                r = v2o(v)
                if v and v < 0x100000 and not r:
                    kind = "int?=%d" % v
                elif r:
                    kind = ("%s%s" % ("CODE:" if r[2] & 4 else "", r[1]))
                else:
                    kind = ""
                print("     %+3d  0x%016X %s" % (k, v, kind))

    print("\n找到 %d/%d 个 module 结构" % (found, len(names)))
    print("提示：若每个 module 附近出现「CODE:il2cpp / CODE:.text」的指针 + 一个小整数，"
          "那对就是 methodPointers 指针与 methodPointerCount；把所有 module 的计数加总应接近 metadata 方法数。")


if __name__ == "__main__":
    main()