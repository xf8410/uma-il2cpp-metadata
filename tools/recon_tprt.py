#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""侦察 libtprt.so / libtersafe2.so：找「校验 libmain 并杀进程」的代码

    python3 tools/recon_tprt.py <dir-with-extracted-libs> > report

做法：
  1. 列出 section 布局与关键字符串（libmain / hash / md5 / sha / verify / integrity ...）
  2. 对每个关键字符串，扫描 .text 里 adrp+add 组合解析出的目标地址，
     若命中该字符串 → 该处很可能就是校验代码，把它前后 40 条指令反汇编出来
  3. 顺带报告 libtprt 的导入函数（open/read/kill/raise/fopen/fstat ...）
"""
import struct
import sys
import os

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

KEYS = [b"libmain", b"libmain.so", b"hash", b"Hash", b"md5", b"MD5", b"sha1", b"sha256",
        b"verify", b"Verify", b"integrity", b"checksum", b"signature", b"crc",
        b"libil2cpp", b"libunity", b"tamper", b"packed", b"elf"]


def sections(d):
    (_, _, _, _, _, shoff, _, _, _, _, shentsize, shnum, shstrndx) = \
        struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
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


def find_strings(d, secs):
    """返回 [(vaddr, text)]，只保留含关键字的 ASCII 串"""
    out = []
    for s in secs:
        if s["type"] == 8 or not s["size"] or not s["addr"]:
            continue
        blk = d[s["off"]:s["off"] + s["size"]]
        i = 0
        while i < len(blk):
            j = i
            while j < len(blk) and 32 <= blk[j] < 127:
                j += 1
            if 4 <= j - i <= 120:
                txt = blk[i:j]
                low = txt.lower()
                if any(k.lower() in low for k in KEYS):
                    out.append((s["addr"] + i, txt.decode("ascii")))
            i = j + 1
    return out


def main():
    root = sys.argv[1]
    for name in ("libtprt.so", "libtersafe2.so"):
        path = os.path.join(root, name)
        if not os.path.exists(path):
            print("## %s 不存在" % name)
            continue
        d = open(path, "rb").read()
        secs = sections(d)
        print("=" * 78)
        print("## %s  (%.2f MiB)" % (name, len(d) / 1048576.0))
        for s in secs:
            if s["type"] != 8 and s["size"]:
                fl = ("W" if s["flags"] & 1 else "-") + ("A" if s["flags"] & 2 else "-") + \
                     ("X" if s["flags"] & 4 else "-")
                print("   [%-18s] off=0x%-8X size=0x%-8X %s" % (s["sname"], s["off"], s["size"], fl))

        hits = find_strings(d, secs)
        print("\n   关键字符串 %d 条（前 40）：" % len(hits))
        for va, t in hits[:40]:
            print("     0x%-8X %s" % (va, t[:100]))

        # 反汇编 .text，找 adrp+add 指向这些字符串的指令
        text = [s for s in secs if s["flags"] & 4 and s["size"]]
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        want = {}
        for va, t in hits:
            want[va] = t
        pages = {}
        for va in want:
            pages.setdefault(va & ~0xFFF, []).append(va)

        found = []
        for s in text:
            code = d[s["off"]:s["off"] + s["size"]]
            last_adrp = {}
            for insn in md.disasm(code, s["addr"]):
                mn, ops = insn.mnemonic, insn.op_str
                if mn == "adrp":
                    try:
                        rd, imm = ops.split(", ")
                        page = int(imm, 0)
                        last_adrp[rd] = page
                    except Exception:
                        pass
                elif mn in ("add", "ldr") and "," in ops:
                    try:
                        parts = [x.strip() for x in ops.split(",")]
                        rd, rn = parts[0], parts[1]
                        if rn in last_adrp and len(parts) >= 3:
                            off = int(parts[2].lstrip("#"), 0)
                            tgt = last_adrp[rn] + off
                            if tgt in want:
                                found.append((insn.address, want[tgt]))
                    except Exception:
                        pass
        print("\n   引用关键字符串的指令 %d 处（前 25）：" % len(found))
        for a, t in found[:25]:
            print("     0x%-8X -> %s" % (a, t[:80]))

        # 把前 3 处上下文反汇编出来
        for a, t in found[:3]:
            print("\n   --- 上下文 @0x%X (%s) ---" % (a, t[:40]))
            so = [s for s in text if s["addr"] <= a < s["addr"] + s["size"]][0]
            start = a - 0x40
            code = d[so["off"] + (start - so["addr"]): so["off"] + (start - so["addr"]) + 0x100]
            for insn in md.disasm(code, start):
                mark = " <<<" if insn.address == a else ""
                print("     0x%X  %-8s %s%s" % (insn.address, insn.mnemonic, insn.op_str, mark))


if __name__ == "__main__":
    main()