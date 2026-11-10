#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dex 注入 v5（一次到位）

    python3 tools/dex_inject5.py <game.apk> <libhachimi.so> <outdir>

同时做四件事：
  1) 日志写 /sdcard/Android/media/<包名>/dsh_shim.log（应用自己的媒体目录，必可写、DSH 可读）
  2) 双插桩：launcher Activity 的 onCreate + <application> 类的 onCreate
  3) Shim 类塞进现有 classes3.dex（不额外加 dex；用 baksmali 反编译 shim dex 再合并 smali）
  4) 资源 / lib/ / 其它 dex 一律不动
"""
import os
import re
import shutil
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET

A = "{http://schemas.android.com/apk/res/android}"
SHIM = r'''
package com.dsh;
import android.content.Context;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
public final class Shim {
    private static File pick(Context ctx) {
        try {
            File d = new File("/sdcard/Android/media/" + ctx.getPackageName());
            d.mkdirs();
            File f = new File(d, "dsh_shim.log");
            new FileOutputStream(f, true).close();
            return f;
        } catch (Throwable t) { return null; }
    }
    private static void w(File f, String s) {
        Log.i("DSH", s);
        if (f == null) return;
        try { FileOutputStream fo = new FileOutputStream(f, true); fo.write((s + "\n").getBytes("UTF-8")); fo.close(); } catch (Throwable ignored) {}
    }
    public static void load(Context ctx) {
        File lf = pick(ctx);
        w(lf, "=== Shim.load enter pkg=" + ctx.getPackageName() + " caller=" + ctx.getClass().getName());
        try {
            File dir = ctx.getCodeCacheDir();
            if (dir == null) dir = ctx.getFilesDir();
            File out = new File(dir, "libhachimi.so");
            InputStream in = ctx.getAssets().open("dsh/libhachimi.so");
            FileOutputStream fo = new FileOutputStream(out);
            byte[] b = new byte[1 << 16];
            int n; long total = 0;
            while ((n = in.read(b)) > 0) { fo.write(b, 0, n); total += n; }
            fo.close(); in.close();
            w(lf, "copied " + total + " -> " + out);
            System.load(out.getAbsolutePath());
            w(lf, "System.load OK");
        } catch (Throwable t) {
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            w(lf, "FAILED: " + sw.toString());
        }
    }
}
'''


def sh(cmd, log, cwd=None):
    log.append("$ " + " ".join(cmd))
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log.append("\n".join(p.stdout.splitlines()[-5:]))
    return p.returncode


def targets(man):
    """返回 (launcher_activity, application_class)"""
    root = ET.fromstring(man)
    app = root.find("application")
    appname = app.get(A + "name") if app is not None else None

    def has_launcher(node):
        for f in node.findall("intent-filter"):
            acts = {a.get(A + "name") for a in f.findall("action")}
            cats = {c.get(A + "name") for c in f.findall("category")}
            if "android.intent.action.MAIN" in acts and "android.intent.category.LAUNCHER" in cats:
                return True
        return False

    launcher = None
    for act in app.findall("activity"):
        n = act.get(A + "name") or ""
        if n and not n.startswith("android.") and has_launcher(act):
            launcher = n
            break
    if not launcher:
        for al in app.findall("activity-alias"):
            if has_launcher(al):
                launcher = al.get(A + "targetActivity")
                break
    return launcher, appname


def patch_smali(path, log, app_class=False):
    txt = open(path, encoding="utf-8").read()
    m = re.search(r'^\.super (L[^;]+;)', txt, re.M)
    sup = m.group(1) if m else ("Landroid/app/Application;" if app_class else "Landroid/app/Activity;")
    call = "    invoke-static {p0}, Lcom/dsh/Shim;->load(Landroid/content/Context;)V"
    pat = (r'\.method[^\n]* onCreate\(\)V' if app_class
           else r'\.method[^\n]* onCreate\(Landroid/os/Bundle;\)V')
    if re.search(pat, txt):
        lines = txt.splitlines()
        for i, ln in enumerate(lines):
            if re.search(pat, ln):
                j = i + 1
                while j < len(lines) and not lines[j].strip().startswith((".locals", ".registers")):
                    j += 1
                lines.insert(j + 1, call)
                open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
                log.append("  ✓ 已存在 onCreate，插入调用: " + os.path.basename(path))
                return
    if app_class:
        add = ("\n.method public onCreate()V\n    .locals 0\n" + call +
               "\n    invoke-super {p0}, %s->onCreate()V\n    return-void\n.end method\n" % sup)
    else:
        add = ("\n.method protected onCreate(Landroid/os/Bundle;)V\n    .locals 0\n" + call +
               "\n    invoke-super {p0, p1}, %s->onCreate(Landroid/os/Bundle;)V\n    return-void\n.end method\n" % sup)
    open(path, "a", encoding="utf-8").write(add)
    log.append("  ✓ 追加 onCreate 覆写: " + os.path.basename(path) + " (super=%s)" % sup)


def main():
    apk, so, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
    log = []

    if sh(["apktool", "d", "-f", "-o", "dec", apk], log) != 0:
        print("\n".join(log)); raise SystemExit("apktool d 失败")
    man = open("dec/AndroidManifest.xml", encoding="utf-8", errors="replace").read()
    launcher, appcls = targets(man)
    log.append("launcher=%s  application=%s" % (launcher, appcls))
    if not launcher and not appcls:
        print("\n".join(log)); raise SystemExit("两个插桩点都没找到")

    # Shim 放到 classes3 的 smali 目录
    dexdir = "smali_classes3" if os.path.isdir("dec/smali_classes3") else "smali"
    idx = "classes3.dex" if dexdir == "smali_classes3" else "classes.dex"

    android_home = os.environ.get("ANDROID_HOME", "/usr/local/lib/android/sdk")
    plats = os.path.join(android_home, "platforms")
    aj = [os.path.join(plats, d, "android.jar") for d in sorted(os.listdir(plats))
          if os.path.isfile(os.path.join(plats, d, "android.jar"))][-1]
    bt = os.path.join(android_home, "build-tools")
    d8 = [os.path.join(bt, d, "d8") for d in sorted(os.listdir(bt))
          if os.path.isfile(os.path.join(bt, d, "d8"))][-1]

    os.makedirs("src/com/dsh", exist_ok=True); os.makedirs("cls", exist_ok=True)
    os.makedirs("dexout", exist_ok=True); os.makedirs("shim_smali", exist_ok=True)
    open("src/com/dsh/Shim.java", "w").write(SHIM)
    sh(["javac", "-nowarn", "-source", "8", "-target", "8", "-bootclasspath", aj,
        "-d", "cls", "src/com/dsh/Shim.java"], log)
    sh([d8, "--lib", aj, "--min-api", "24", "--output", "dexout", "cls/com/dsh/Shim.class"], log)
    if not os.path.isfile("dexout/classes.dex"):
        print("\n".join(log)); raise SystemExit("Shim dex 失败")

    if not os.path.isfile("baksmali.jar"):
        sh(["curl", "-sSL", "-o", "baksmali.jar",
            "https://github.com/baksmali/smali/releases/download/v2.5.2/baksmali-2.5.2.jar"], log)
    sh(["java", "-jar", "baksmali.jar", "disassemble", "dexout/classes.dex", "-o", "shim_smali"], log)
    if not os.path.isdir("shim_smali/com/dsh"):
        print("\n".join(log)); raise SystemExit("baksmali 没产出 Shin smali")
    dst = os.path.join("dec", dexdir, "com", "dsh")
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree("shim_smali/com/dsh", dst)
    log.append("Shim smali 已并入 %s" % dexdir)

    # 插桩
    for cls, isapp in ((launcher, False), (appcls, True)):
        if not cls:
            continue
        rel = cls.replace(".", "/") + ".smali"
        p = os.path.join("dec", dexdir, rel)
        if not os.path.isfile(p):
            found = None
            for d in sorted(os.listdir("dec")):
                if d == "smali" or d.startswith("smali_classes"):
                    q = os.path.join("dec", d, rel)
                    if os.path.isfile(q):
                        found = q
                        break
            p = found
        if p and os.path.isfile(p):
            patch_smali(p, log, isapp)
            if "com/dsh" not in p:
                need = os.path.dirname(p)
                _ = need
        else:
            log.append("  ! 找不到 smali: %s" % cls)

    if not os.path.isfile("smali.jar"):
        sh(["curl", "-sSL", "-o", "smali.jar",
            "https://github.com/baksmali/smali/releases/download/v2.5.2/smali-2.5.2.jar"], log)
    if sh(["java", "-jar", "smali.jar", "assemble", os.path.join("dec", dexdir), "-o", "patched.dex"], log) != 0:
        print("\n".join(log)); raise SystemExit("smali assemble 失败")
    log.append("patched %s: %d B" % (idx, os.path.getsize("patched.dex")))

    final = os.path.join(outdir, "patched.apk")
    shutil.copy(apk, final)
    st = "stage"
    shutil.rmtree(st, ignore_errors=True)
    os.makedirs(os.path.join(st, "assets", "dsh"))
    shutil.copy("patched.dex", os.path.join(st, idx))
    shutil.copy(so, os.path.join(st, "assets", "dsh", "libhachimi.so"))
    rc = sh(["zip", "-q", "-0", os.path.abspath(final), idx, "assets/dsh/libhachimi.so"], log, cwd=st)
    log.append("zip rc=%d  final=%d B" % (rc, os.path.getsize(final)))
    print("\n".join(log))


if __name__ == "__main__":
    main()