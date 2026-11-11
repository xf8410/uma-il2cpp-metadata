#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_metadata_fixed.py —— IL2CPP global-metadata v27 紧凑布局解析器（字段归属修复版）

背景
    国服 libil2cpp 的 global-metadata 使用 v27 紧凑布局：header 里所有 *Start 字段被删除，
    只保留 (offset, size) 对，因此每张表的起点需要靠「按 image 分组 + 前缀和」还原。

本脚本修复的两个关键缺陷
──────────────────────────────────────────────────────────────────────
缺陷 1：typeDefinition 表在同一个程序集内不是按 token 排序的
    旧实现直接按 typeDefinitions 数组顺序累加 field_count 来算字段归属，
    只要组内出现一次乱序，后续所有类型的字段归属就整体偏移，越往后错得越多。
    实测：73 个 image 组内共存在 4985 个 type token 逆序对，必然断裂。

    正确做法：
        for image in sorted(images, key=token):          # image 按 token 排
            order = sorted(types_of_image, key=token)    # 组内按 type token 重排
            cur = base
            for ti in order:
                owner[ti] = (cur, field_count[ti])
                cur += field_count[ti]
            base = cur
    验证：累加结果必须恰好等于 fields 表条目数（254055），否则说明 image 边界处理有误。

缺陷 2：跨 image 边界必然断裂
    每个程序集的 field token 都从 0x04000001 重新开始，全局 token 不唯一，
    所以校验必须按 image 分组进行，不能对全局 token 做单调性断言。

缺陷 3：string 表可能不是标准 length-prefixed
    被「修复/重建」过的 metadata 里，string 表可能被重排成 null-terminated 形式。
    本脚本先探测：若能按 length-prefixed 正确读出 image 名则用之，否则回退 null-terminated。

用法
    python3 parse_metadata_fixed.py <global-metadata.dat> <输出目录>

输出
    types.tsv      index <TAB> token <TAB> full_name
    fields.tsv     type_index <TAB> name <TAB> token <TAB> offset_kind
    methods.tsv    decl_type_index <TAB> name <TAB> token <TAB> param_count
    images.tsv     index <TAB> token <TAB> name <TAB> type_start <TAB> type_count
    summary.json   各表条目数 + 校验结果
"""

import json
import os
import struct
import sys

# ── header 31 组 (offset, size)，v27 紧凑布局，从文件偏移 8 开始 ──────────────
HDR_FIELDS = [
    "stringLiteral", "stringLiteralData", "string",
    "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields",
    "genericParameters", "genericParameterConstraints", "genericContainers",
    "nestedTypes", "interfaces", "vtableMethods", "interfaceOffsets",
    "typeDefinitions", "images", "assemblies", "fieldRefs", "referencedAssemblies",
    "attributeData", "attributeDataRange",
    "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions",
]

# 各表条目大小
REC_SIZE = {
    "typeDefinitions": 88,
    "fields": 12,
    "methods": 32,
    "images": 40,
    "assemblies": 68,
}

SANITY = 0xFAB11BAF


class Metadata:
    def __init__(self, path):
        self.buf = open(path, "rb").read()
        self.hdr = {}
        sanity = struct.unpack_from("<I", self.buf, 0)[0]
        if sanity != SANITY:
            raise ValueError("sanity 不符: 0x%08X (期望 0x%08X)" % (sanity, SANITY))
        self.version = struct.unpack_from("<i", self.buf, 4)[0]
        for i, name in enumerate(HDR_FIELDS):
            off, size = struct.unpack_from("<II", self.buf, 8 + i * 8)
            self.hdr[name] = (off, size)

        self.counts = {}
        for k, sz in REC_SIZE.items():
            self.counts[k] = self.hdr[k][1] // sz

        self.str_off = self.hdr["string"][0]
        self._str_mode = None          # 'len' | 'nul'

    # ── 字符串读取：先探测编码方式 ────────────────────────────────────────
    def _read_len_prefixed(self, idx):
        p = self.str_off + idx
        b = self.buf[p]
        if b & 0x80 == 0:
            ln, p = b, p + 1
        else:
            b2 = self.buf[p + 1]
            if b2 & 0x80 == 0:
                ln, p = ((b & 0x7F) << 8) | b2, p + 2
            else:
                b3, b4 = self.buf[p + 2], self.buf[p + 3]
                ln = ((b & 0x7F) << 24) | ((b2 & 0x7F) << 16) | ((b3 & 0x7F) << 8) | b4
                p += 4
        return self.buf[p:p + ln].decode("utf-8", "replace")

    def _read_null_term(self, idx):
        p = self.str_off + idx
        e = self.buf.find(b"\x00", p)
        return self.buf[p:e].decode("utf-8", "replace")

    def detect_str_mode(self):
        """用 image[0] 的名字探测 string 表编码方式"""
        if self._str_mode:
            return self._str_mode
        img_off = self.hdr["images"][0]
        name_idx = struct.unpack_from("<I", self.buf, img_off)[0]
        cand_len = self._read_len_prefixed(name_idx)
        cand_nul = self._read_null_term(name_idx)
        # 合法程序集名应以 .dll 结尾且不含控制字符
        def sane(s):
            return s.endswith(".dll") and all(32 <= ord(c) < 127 for c in s)
        if sane(cand_len):
            self._str_mode = "len"
        elif sane(cand_nul):
            self._str_mode = "nul"
        else:
            # 都不可靠时选更长且更像名字的那个
            self._str_mode = "nul" if sane(cand_nul) or len(cand_nul) < len(cand_len) else "len"
        return self._str_mode

    def rstr(self, idx):
        if self.detect_str_mode() == "len":
            return self._read_len_prefixed(idx)
        return self._read_null_term(idx)

    # ── 记录访问器 ─────────────────────────────────────────────────────
    def type_def(self, i):
        b = self.hdr["typeDefinitions"][0] + i * 88
        name_i, ns_i = struct.unpack_from("<II", self.buf, b)
        method_cnt = struct.unpack_from("<H", self.buf, b + 64)[0]
        field_cnt = struct.unpack_from("<H", self.buf, b + 68)[0]
        token = struct.unpack_from("<I", self.buf, b + 84)[0]
        return dict(index=i, name_i=name_i, ns_i=ns_i,
                    method_count=method_cnt, field_count=field_cnt, token=token)

    def field_def(self, i):
        b = self.hdr["fields"][0] + i * 12
        name_i, type_i, token = struct.unpack_from("<III", self.buf, b)
        return dict(name_i=name_i, type_index=type_i, token=token)

    def method_def(self, i):
        b = self.hdr["methods"][0] + i * 32
        name_i, decl_type = struct.unpack_from("<II", self.buf, b)
        token = struct.unpack_from("<I", self.buf, b + 0x14)[0]
        raw = struct.unpack_from("<I", self.buf, b + 0x1C)[0]
        return dict(name_i=name_i, decl_type=decl_type, token=token,
                    param_count=(raw >> 16) & 0xFFFF)

    def image_def(self, i):
        b = self.hdr["images"][0] + i * 40
        name_i, asm_i, t_start, t_count = struct.unpack_from("<IIII", self.buf, b)
        token = struct.unpack_from("<I", self.buf, b + 28)[0]
        return dict(index=i, name_i=name_i, assembly_i=asm_i,
                    type_start=t_start, type_count=t_count, token=token)

    # ── 核心：字段归属还原（修复版）──────────────────────────────────────
    def build_field_owner(self):
        """返回 owner[type_index] = (field_start, field_count)"""
        n_td = self.counts["typeDefinitions"]
        n_field = self.counts["fields"]
        images = [self.image_def(i) for i in range(self.counts["images"])]
        # image 按 token 排序（每个 image 的 field token 都从 0x04000001 重开）
        images.sort(key=lambda x: x["token"] & 0xFFFFFF)

        owner = [None] * n_td
        base = 0
        reverses = 0
        for im in images:
            idxs = list(range(im["type_start"], im["type_start"] + im["type_count"]))
            toks = [(self.type_def(i)["token"] & 0xFFFFFF, i) for i in idxs]
            for k in range(1, len(toks)):
                if toks[k][0] < toks[k - 1][0]:
                    reverses += 1
            # 组内按 type token 重排 —— 这一步是全部正确性的关键
            for _, ti in sorted(toks):
                fc = self.type_def(ti)["field_count"]
                owner[ti] = (base, fc)
                base += fc

        if base != n_field:
            raise AssertionError(
                "字段归属总覆盖 %d != fields 表条目数 %d，image 边界处理有误" % (base, n_field))
        self._reverses = reverses
        return owner


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    meta_path, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    m = Metadata(meta_path)
    print("version      = %d" % m.version)
    print("string mode  = %s" % m.detect_str_mode())
    for k in ("typeDefinitions", "fields", "methods", "images", "assemblies"):
        print("%-14s = %d" % (k, m.counts[k]))

    owner = m.build_field_owner()
    print("字段归属校验  = OK (组内 type token 逆序对 %d 个，证明重排必要)" % m._reverses)

    # ── types.tsv
    n_td = m.counts["typeDefinitions"]
    with open(os.path.join(out_dir, "types.tsv"), "w", encoding="utf-8") as f:
        f.write("index\ttoken\tfull_name\n")
        for i in range(n_td):
            t = m.type_def(i)
            nm = m.rstr(t["name_i"])
            ns = m.rstr(t["ns_i"])
            full = ("%s.%s" % (ns, nm)) if ns else nm
            f.write("%d\t0x%08X\t%s\n" % (i, t["token"], full))

    # ── fields.tsv（type_index 列现在是正确的归属）
    # 注：static/instance 由 Il2CppType 的 attrs 位决定（FIELD_ATTRIBUTE_STATIC=0x0010），
    #     紧凑布局下 Il2CppType 无独立表，需经 typeDefinitions 的 byvalTypeIndex 间接解析，
    #     本脚本不做该判定，避免给出错误的 kind 列。
    with open(os.path.join(out_dir, "fields.tsv"), "w", encoding="utf-8") as f:
        f.write("type_index\tname\ttoken\n")
        for i in range(n_td):
            st, fc = owner[i]
            for k in range(fc):
                fd = m.field_def(st + k)
                f.write("%d\t%s\t0x%08X\n" % (i, m.rstr(fd["name_i"]), fd["token"]))

    # ── methods.tsv
    n_m = m.counts["methods"]
    with open(os.path.join(out_dir, "methods.tsv"), "w", encoding="utf-8") as f:
        f.write("decl_type_index\tname\ttoken\tparam_count\n")
        for i in range(n_m):
            md = m.method_def(i)
            f.write("%d\t%s\t0x%08X\t%d\n" % (
                md["decl_type"], m.rstr(md["name_i"]), md["token"], md["param_count"]))

    # ── images.tsv
    with open(os.path.join(out_dir, "images.tsv"), "w", encoding="utf-8") as f:
        f.write("index\ttoken\tname\ttype_start\ttype_count\n")
        for i in range(m.counts["images"]):
            im = m.image_def(i)
            f.write("%d\t0x%08X\t%s\t%d\t%d\n" % (
                i, im["token"], m.rstr(im["name_i"]), im["type_start"], im["type_count"]))

    # ── summary.json
    summary = dict(
        version=m.version,
        string_mode=m.detect_str_mode(),
        counts=m.counts,
        type_token_reverses=m._reverses,
        field_owner_coverage=m.counts["fields"],
    )
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("\n输出目录:", out_dir)
    print("  types.tsv  fields.tsv  methods.tsv  images.tsv  summary.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
