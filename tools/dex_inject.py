#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dex 注入流水线：把 Hachimi 从 dex 里拉起来，完全不碰 lib/

    python3 tools/dex_inject.py <game.apk> <libhachimi.so> <outdir>

步骤：
  1. apktool d 解包
  2. 找到 LAUNCHER activity，往它的 onCreate 开头插 invoke-static Lcom/dsh/Shim;->load
  3. Java 编译一个 Shim 类（javac + d8）→ classes3.dex
  4. libhachimi.so 放到 assets/dsh/
  5. apktool b 打包 + 追加 classes3.dex
（签名交给调用方）
"""
import os
import re
import subprocess
import sys


def sh(cmd, log, cwd=None):
    log.append("$ " + " ".join(cmd))
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    tail = "\n".join(p.stdout.splitlines()[-8:])
    log.append(tail)
    return p.returncode


JAVA_SRC = r'''
package com.dsh;
import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
public final class Shim {
    public static void load(Context ctx) {
        try {
            File dir = ctx.getCodeCacheDir();
            if (dir == null) dir = ctx.getFilesDir();
            File out = new File(dir, "libhachimi.so");
            InputStream in = ctx.getAssets().open("dsh/libhachimi.so");
            FileOutputStream fo = new FileOutputStream(out);
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) > 0) fo.write(buf, 0, n);
            fo.close(); in.close();
            System.load(out.getAbsolutePath());
        } catch (Throwable t) {
            android.util.Log.e("DSH", "Shim.load failed: " + t, t);
        }
    }
}
'''


def patch_smali(path, log):
    src = open(path, encoding="utf-8").read()
    lines = src.splitlines()
    idx = None
    for i, ln in enumerate(lines):
        if ln.startswith(".method") and " onCreate(" in ln + " ":
            idx = i
            break
    if idx is None:
        for i, ln in enumerate(lines):
            if ln.startswith(".method"):
                idx = i
                break
    if idx is None:
        log.append("smali: 没有方法可插")
        return False
    # 找到 .locals/.registers 行
    j = idx + 1
    while j < len(lines) and not lines[j].strip().startswith((".locals", ".registers")):
        j += 1
    if j >= len(lines):
        log.append("smali: 没找到 .locals")
        return False
    ins = "    invoke-static {p0}, Lcom/dsh/Shim;->load(Landroid/content/Context;)V"
    lines.insert(j + 1, ins)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    log.append("smali: 已插入到 %s 的第 %d 行（方法 %s）" % (path, idx + 1, lines[idx][:60]))
    return True


def find_activity(dec, log):
    man = os.path.join(dec, "AndroidManifest.xml")
    t = open(man, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r'<activity[^>]*android:name="([^"]+)"(.*?)</activity>', t, re.S):
        name, body = m.group(1), m.group(2)
        if "android.intent.action.MAIN" in body and "LAUNCHER" in body:
            log.append("activity: " + name)
            return name
    log.append("activity: 未找到 LAUNCHER（fallback 用第一个 activity）")
    m = re.search(r'<activity[^>]*android:name="([^"]+)"', t)
    return m.group(1) if m else None


def main():
    apk, so, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
    log = []

    dec = "dec"
    if sh(["apktool", "d", "-f", "-o", dec, apk], log) != 0 and not os.path.isdir(dec):
        print("\n".join(log))
        raise SystemExit("apktool d 失败")

    act = find_activity(dec, log)
    if not act:
        print("\n".join(log))
        raise SystemExit("找不到 activity")
    rel = act.replace(".", "/") + ".smali"
    cands = [os.path.join(dec, "smali", rel), os.path.join(dec, "smali_classes2", rel)]
    for root, _dirs, files in os.walk(dec):
        if rel.split("/")[-1] in files and "smali" in os.path.basename(root).split("_")[0] + "_":
            cands.append(os.path.join(root, rel.split("/")[-1]))
    target = next((c for c in cands if os.path.isfile(c)), None)
    if not target:
        print("\n".join(log))
        raise SystemExit("找不到 activity 的 smali 文件")
    if not patch_smali(target, log):
        print("\n".join(log))
        raise SystemExit("smali 插桩失败")

    # assets 放 so
    adir = os.path.join(dec, "assets", "dsh")
    os.makedirs(adir, exist_ok=True)
    open(os.path.join(adir, "libhachimi.so"), "wb").write(open(so, "rb").read())
    log.append("assets: 已放 dsh/libhachimi.so (%d B)" % os.path.getsize(so))

    # 编译 Shim
    android_home = os.environ.get("ANDROID_HOME", "/usr/local/lib/android/sdk")
    jars = []
    for base in (os.path.join(android_home, "platforms"),):
        if os.path.isdir(base):
            jars = [os.path.join(base, d, "android.jar") for d in sorted(os.listdir(base))]
    aj = jars[-1] if jars else ""
    log.append("android.jar: " + aj)
    tools = os.path.join(android_home, "build-tools")
    d8 = ""
    if os.path.isdir(tools):
        for d in sorted(os.listdir(tools)):
            p = os.path.join(tools, d, "d8")
            if os.path.isfile(p):
                d8 = p
    log.append("d8: " + d8)

    os.makedirs("src/com/dsh", exist_ok=True)
    os.makedirs("cls", exist_ok=True)
    os.makedirs("dexout", exist_ok=True)
    open("src/com/dsh/Shim.java", "w").write(JAVA_SRC)
    sh(["javac", "-source", "8", "-target", "8", "-bootclasspath", aj,
        "-d", "cls", "src/com/dsh/Shim.java"], log)
    sh([d8, "--lib", aj, "--min-api", "24", "--output", "dexout", "cls/com/dsh/Shim.class"], log)
    if not os.path.isfile("dexout/classes.dex"):
        print("\n".join(log))
        raise SystemExit("d8 没产出 classes.dex")
    log.append("classes3.dex: %d B" % os.path.getsize("dexout/classes.dex"))

    # 打包
    base = os.path.join(outdir, "base.apk")
    if sh(["apktool", "b", dec, "-o", base], log) != 0:
        print("\n".join(log))
        raise SystemExit("apktool b 失败")
    final = os.path.join(outdir, "with-dex.apk")
    open(final, "wb").write(open(base, "rb").read())
    rc = sh(["zip", "-q", "-0", os.path.abspath(final), os.path.abspath("dexout/classes.dex"),
             "-j"], log)
    # zip 追加时用文件名 classes3.dex：改名后追加
    import shutil
    shutil.copy("dexout/classes.dex", "classes3.dex")
    sh(["zip", "-q", "-0", os.path.abspath(final), "classes3.dex"], log)
    log.append("final: %s (%d B)" % (final, os.path.getsize(final)))
    print("\n".join(log))


if __name__ == "__main__":
    main()