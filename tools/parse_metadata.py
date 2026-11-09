#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""uma-il2cpp-metadata / parse_metadata.py

解析《闪耀！优俊少女》(syyjsn) 2.0.5 的 global-metadata.fixed.dat。
实测：Unity 2020.3.49f1，metadata 头部被改写，且每 64KB 块内 +0x1000~+0x4FFF
(16KB) 整段 XOR 0x66 —— .fixed 已还原这两处。

关键：表结构是**自定义紧凑布局**，不是标准 v27
    typeDefinition   88 B   name@+0x00 ns@+0x04 method_count(u16)@+0x40
                            field_count(u16)@+0x44 token@+0x54
    methodDefinition 32 B   name@+0x00 declType@+0x04 token@+0x14
                            (iflags@+0x1C)>>16 == parameterCount
    fieldDefinition  12 B   name@+0x00 typeIndex@+0x04 token@+0x08
    所有 *Start 字段被删除 → 起点用计数前缀和还原。

用法:
    python3 parse_metadata.py <fixed.dat> <outdir>
    python3 parse_metadata.py <fixed.dat> --check
"""
import struct
import sys
import os

SANITY = 0xFAB11BAF
# 头部 0x08 起 31 组 (offset, size)
SEC = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties",
    "methods", "parameterDefaultValues", "fieldDefaultValues",
    "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters",
    "fields", "genericParameters", "genericParameterConstraints",
    "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
    "interfaceOffsets", "typeDefinitions", "images", "assemblies",
    "metadataUsageLists", "metadataUsagePairs", "fieldRefs",
    "referencedAssemblies", "attributeData", "attributeDataRange",
    "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
    "exportedTypeDefinitions",
]
TYPE_STRIDE = 88
METHOD_STRIDE = 32
FIELD_STRIDE = 12


class Meta:
    def __init__(self, path):
        self.path = path
        self.d = open(path, "rb").read()
        self.size = len(self.d)
        sanity, self.version = struct.unpack_from("<Ii", self.d, 0)
        if sanity != SANITY:
            raise SystemExit("sanity=0x%08X，文件未做异或还原" % sanity)
        pairs = struct.unpack_from("<62i", self.d, 8)
        self.sec = {n: (pairs[2 * i], pairs[2 * i + 1]) for i, n in enumerate(SEC)}

    def u32(self, off):
        return struct.unpack_from("<I", self.d, off)[0]

    def s(self, idx):
        if idx < 0 or idx >= self.sec["string"][1]:
            return ""
        p = self.sec["string"][0] + idx
        e = self.d.find(b"\x00", p, p + 4096)
        if e < 0:
            e = p + 64
        return self.d[p:e].decode("utf-8", "replace")

    def rows(self, name, stride):
        off, size = self.sec[name]
        return off, size // stride

    # ---------------- 自检 ----------------
    def check(self):
        out = []
        out.append("file      : %s" % self.path)
        out.append("size      : %d" % self.size)
        out.append("sanity    : 0xFAB11BAF ok, version=%d" % self.version)
        # 段连续性
        prev_end = None
        holes = 0
        for name in SEC:
            off, sz = self.sec[name]
            if sz <= 0:
                continue
            if prev_end is not None and off != prev_end:
                holes += 1
                out.append("  ! gap before %s: 0x%X -> 0x%X" % (name, prev_end, off))
            prev_end = off + sz
        out.append("sections  : %d, gaps=%d, last_end=0x%X (file=0x%X)"
                   % (len(SEC), holes, prev_end or 0, self.size))
        out.append("last sec ends at EOF: %s" % (prev_end == self.size))
        # 计数一致性
        toff, tn = self.rows("typeDefinitions", TYPE_STRIDE)
        moff, mn = self.rows("methods", METHOD_STRIDE)
        foff, fn = self.rows("fields", FIELD_STRIDE)
        sum_m = sum(self.u32(toff + i * TYPE_STRIDE + 0x40) & 0xFFFF for i in range(tn))
        sum_f = sum(self.u32(toff + i * TYPE_STRIDE + 0x44) & 0xFFFF for i in range(tn))
        out.append("types     : %d" % tn)
        out.append("methods   : %d (sum method_count=%d, %s)"
                   % (mn, sum_m, "OK" if sum_m == mn else "MISMATCH"))
        out.append("fields    : %d (sum field_count=%d, %s)"
                   % (fn, sum_f, "OK" if sum_f == fn else "MISMATCH"))
        # token 单调性
        bad = 0
        prev = -1
        for i in range(0, mn, max(1, mn // 5000)):
            t = self.u32(moff + i * METHOD_STRIDE + 0x14)
            if t < prev:
                bad += 1
            prev = t
        out.append("method token monotonic: %s" % ("OK" if bad == 0 else "breaks=%d" % bad))
        return "\n".join(out), (sum_m == mn and sum_f == fn)


def dump(md, outdir):
    os.makedirs(outdir, exist_ok=True)
    toff, tn = md.rows("typeDefinitions", TYPE_STRIDE)
    moff, mn = md.rows("methods", METHOD_STRIDE)
    foff, fn = md.rows("fields", FIELD_STRIDE)

    types = []
    for i in range(tn):
        b = toff + i * TYPE_STRIDE
        nm, ns = md.s(md.u32(b)), md.s(md.u32(b + 4))
        types.append((nm, ns, md.u32(b + 0x40) & 0xFFFF,
                      md.u32(b + 0x44) & 0xFFFF, md.u32(b + 0x54)))

    with open(os.path.join(outdir, "types.tsv"), "w", encoding="utf-8") as f:
        f.write("index\ttoken\tfull_name\n")
        for i, (nm, ns, _mc, _fc, tok) in enumerate(types):
            f.write("%d\t0x%08X\t%s\n" % (i, tok, (ns + "." + nm) if ns else nm))

    # 方法：按声明类型分组输出（不重复类型名，省一半体积）
    with open(os.path.join(outdir, "methods.tsv"), "w", encoding="utf-8") as f:
        f.write("decl_type_index\tname\ttoken\tparam_count\n")
        for i in range(mn):
            b = moff + i * METHOD_STRIDE
            f.write("%d\t%s\t0x%08X\t%d\n" % (
                md.u32(b + 4), md.s(md.u32(b)), md.u32(b + 0x14),
                md.u32(b + 0x1C) >> 16))

    # 字段：用 field_count 前缀和还原归属
    pos = 0
    with open(os.path.join(outdir, "fields.tsv"), "w", encoding="utf-8") as f:
        f.write("type_index\tname\ttoken\n")
        for ti, (_nm, _ns, _mc, fc, _tok) in enumerate(types):
            for _ in range(fc):
                b = foff + pos * FIELD_STRIDE
                f.write("%d\t%s\t0x%08X\n" % (ti, md.s(md.u32(b)), md.u32(b + 8)))
                pos += 1

    # 字符串字面量（第 0 块 16KB 是另一套加密，长度不可信 → 过滤）
    loff, lsize = md.sec["stringLiteral"]
    doff, dsize = md.sec["stringLiteralData"]
    with open(os.path.join(outdir, "string_literals.txt"), "w", encoding="utf-8") as f:
        for i in range(lsize // 8):
            ln, di = struct.unpack_from("<Ii", md.d, loff + i * 8)
            if 0 < ln <= 4096 and 0 <= di and di + ln <= dsize:
                f.write("%s\n" % md.d[doff + di:doff + di + ln].decode("utf-8", "replace"))
    return tn, mn, fn, pos


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    md = Meta(sys.argv[1])
    if "--check" in sys.argv:
        text, ok = md.check()
        print(text)
        sys.exit(0 if ok else 1)
    outdir = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else "out"
    tn, mn, fn, pos = dump(md, outdir)
    assert pos == fn, "字段归属行数 %d != 字段表行数 %d" % (pos, fn)
    print("wrote %s: types=%d methods=%d fields=%d" % (outdir, tn, mn, fn))


if __name__ == "__main__":
    main()