#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dex-only 注入：改 dex，不动资源、不动 lib/

    python3 tools/dex_inject2.py <game.apk> <libhachimi.so> <outdir>

思路：
  1) apktool d 只用来反编译 smali（不重建资源，绕开 aapt 对腾讯非法资源名的报错）
  2) 给 LAUNCHER activity 补一个 onCreate 覆写：先 Shim.load(this) 再 super.onCreate
  3) Shim 用 Java 写，javac+d8 编成独立 dex（classesN.dex 追加）
  4) 用 smali.jar 把被改动的那个 dex 目录重新汇编，替换回原 APK
  5) assets/dsh/libhachimi.so 追加
  6) 其余（resources.arsc、lib/、AndroidManifest）一律保持原样
"""
import os
import re
import shutil
import subprocess
import sys
import zipfile


def sh(cmd, log, cwd=None):
    log.append("$ " + " ".join(cmd))
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log.append("\n".join(p.stdout.splitlines()[-6:]))
    return p.returncode


SHIM_JAVA = r'''
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
            byte[] b = new byte[1 << 16];
            int n;
            while ((n = in.read(b)) > 0) fo.write(b, 0, n);
            fo.close(); in.close();
            System.load(out.getAbsolutePath());
        } catch (Throwable t) {
            android.util.Log.e("DSH", "Shim.load failed: " + t, t);
        }
    }
}
'''


def find_launcher(manifest_text):
    """返回 LAUNCHER activity 的类名"""
    acts = re.findall(r'<activity\b[^>]*?android:name="(?!android\.)([^"]+)"[^>]*>(.*?)</activity>',
                      manifest_text, re.S)
    for cls, body in acts:
        if "android.intent.action.MAIN" in body and "android.intent.category.LAUNCHER" in body:
            return cls
    # 再看 activity-alias
    for m in re.finditer(r'<activity-alias\b[^>]*?android:name="([^"]+)"[^>]*?android:targetActivity="([^"]+)"', manifest_text):
        return m.group(2)
    return None


def patch_class(path, log):
    txt = open(path, encoding="utf-8").read()
    sup = re.search(r'^\.super (L[^;]+;)', txt, re.M)
    sup = sup.group(1) if sup else "Landroid/app/Activity;"
    has_oncreate = ".method" in txt and re.search(r'\.method[^\n]* onCreate\(Landroid/os/Bundle;\)V', txt)
    if has_oncreate:
        lines = txt.splitlines()
        for i, ln in enumerate(lines):
            if re.search(r'\.method[^\n]* onCreate\(Landroid/os/Bundle;\)V', ln):
                j = i + 1
                while j < len(lines) and not lines[j].strip().startswith((".locals", ".registers")):
                    j += 1
                lines.insert(j + 1, "    invoke-static {p0}, Lcom/dsh/Shim;->load(Landroid/content/Context;)V")
                open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
                log.append("smali: 已有 onCreate，插入调用")
                return sup
    # 没有 onCreate：追加一个覆写
    method = (
        "\n.method protected onCreate(Landroid/os/Bundle;)V\n"
        "    .locals 0\n"
        "    invoke-static {p0}, Lcom/dsh/Shim;->load(Landroid/content/Context;)V\n"
        "    invoke-super {p0, p1}, %s->onCreate(Landroid/os/Bundle;)V\n"
        "    return-void\n"
        ".end method\n" % sup
    )
    open(path, "a", encoding="utf-8").write(method)
    log.append("smali: 追加 onCreate 覆写（super=%s）" % sup)
    return sup


def main():
    apk, so, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
    log = []

    if sh(["apktool", "d", "-f", "-o", "dec", apk], log) != 0 or not os.path.isdir("dec"):
        print("\n".join(log)); raise SystemExit("apktool d 失败")

    cls = find_launcher(open("dec/AndroidManifest.xml", encoding="utf-8", errors="replace").read())
    log.append("launcher: %s" % cls)
    if not cls:
        print("\n".join(log)); raise SystemExit("找不到 launcher activity")

    rel = cls.replace(".", "/") + ".smali"
    target = None
    dexdir = None
    for d in sorted(os.listdir("dec")):
        if d == "smali" or d.startswith("smali_classes"):
            p = os.path.join("dec", d, rel)
            if os.path.isfile(p):
                target, dexdir = p, d
                break
    if not target:
        print("\n".join(log)); raise SystemExit("找不到 launcher 的 smali")

    patch_class(target, log)
    idx = "classes.dex" if dexdir == "smali" else dexdir.replace("smali_", "") + ".dex"

    # 汇编被改动的 dex
    smali_jar = "smali.jar"
    if not os.path.isfile(smali_jar):
        sh(["curl", "-sSL", "-o", smali_jar,
            "https://github.com/baksmali/smali/releases/download/v2.5.2/smali-2.5.2.jar"], log)
    if sh(["java", "-jar", smali_jar, "assemble", os.path.join("dec", dexdir), "-o", "patched.dex"], log) != 0:
        print("\n".join(log)); raise SystemExit("smali assemble 失败")
    log.append("patched %s: %d B" % (idx, os.path.getsize("patched.dex")))

    # Shim dex
    android_home = os.environ.get("ANDROID_HOME", "/usr/local/lib/android/sdk")
    plats = os.path.join(android_home, "platforms")
    aj = [os.path.join(plats, d, "android.jar") for d in sorted(os.listdir(plats))
          if os.path.isfile(os.path.join(plats, d, "android.jar"))][-1]
    bt = os.path.join(android_home, "build-tools")
    d8 = [os.path.join(bt, d, "d8") for d in sorted(os.listdir(bt))
          if os.path.isfile(os.path.join(bt, d, "d8"))][-1]
    os.makedirs("src/com/dsh", exist_ok=True); os.makedirs("cls", exist_ok=True); os.makedirs("dexout", exist_ok=True)
    open("src/com/dsh/Shim.java", "w").write(SHIM_JAVA)
    sh(["javac", "-nowarn", "-source", "8", "-target", "8", "-bootclasspath", aj,
        "-d", "cls", "src/com/dsh/Shim.java"], log)
    sh([d8, "--lib", aj, "--min-api", "24", "--output", "dexout", "cls/com/dsh/Shim.class"], log)
    if not os.path.isfile("dexout/classes.dex"):
        print("\n".join(log)); raise SystemExit("Shim dex 失败")

    # 现有 dex 数量 → 新的追加名
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
    ndex = len([n for n in names if re.fullmatch(r"classes\d*\.dex", n)])
    shim_name = "classes2.dex" if ndex == 1 else "classes%d.dex" % (ndex + 1)
    log.append("现有 dex=%d，Shim 作为 %s" % (ndex, shim_name))

    final = os.path.join(outdir, "patched.apk")
    shutil.copy(apk, final)
    shutil.copy("patched.dex", idx)
    shutil.copy("dexout/classes.dex", shim_name)
    os.makedirs("assets/dsh", exist_ok=True)
    shutil.copy(so, "assets/dsh/libhachimi.so")
    os.makedirs("assets_dsh_tmp", exist_ok=True)
    shutil.copy(so, "assets_dsh_tmp/libhachimi.so")

    # 用 zip 更新原 APK：替换被改的 dex + 追加 Shim dex 和 assets
    ziptmp = "stage"
    shutil.rmtree(ziptmp, ignore_errors=True)
    os.makedirs(os.path.join(ziptmp, "assets", "dsh"))
    shutil.copy(idx, os.path.join(ziptmp, idx))
    shutil.copy(shim_name, os.path.join(ziptmp, shim_name))
    shutil.copy(so, os.path.join(ziptmp, "assets", "dsh", "libhachimi.so"))
    rc = sh(["zip", "-q", "-0", os.path.abspath(final),
             idx, shim_name, "assets/dsh/libhachimi.so"], log, cwd=ziptmp)
    log.append("zip rc=%d" % rc)
    log.append("final: %s (%d B)" % (final, os.path.getsize(final)))
    print("\n".join(log))


if __name__ == "__main__":
    main()