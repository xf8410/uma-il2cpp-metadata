#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dex_inject2 + 带日志的 Shim（写 /sdcard/Download/dsh_shim.log）

复用 dex_inject2 的全流程，只替换：
  · SHIM_JAVA：加载每一步都写盘，异常全量打印
  · find_launcher：XML 解析（同 dex_inject3）
"""
import sys
import xml.etree.ElementTree as ET

import dex_inject2 as base

SHIM_JAVA = r'''
package com.dsh;
import android.content.Context;
import android.util.Log;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
public final class Shim {
    private static File pick(Context ctx) {
        File f = new File("/sdcard/Download/dsh_shim.log");
        try { new FileOutputStream(f, true).close(); return f; } catch (Throwable ignored) {}
        try {
            File g = new File(ctx.getExternalFilesDir(null), "dsh_shim.log");
            new FileOutputStream(g, true).close();
            return g;
        } catch (Throwable ignored) {}
        return null;
    }
    private static void w(File f, String s) {
        Log.i("DSH", s);
        if (f == null) return;
        try { FileOutputStream fo = new FileOutputStream(f, true); fo.write((s + "\n").getBytes("UTF-8")); fo.close(); } catch (Throwable ignored) {}
    }
    public static void load(Context ctx) {
        File lf = pick(ctx);
        w(lf, "=== Shim.load enter, pkg=" + ctx.getPackageName());
        try {
            File dir = ctx.getCodeCacheDir();
            if (dir == null) dir = ctx.getFilesDir();
            w(lf, "dir=" + dir);
            File out = new File(dir, "libhachimi.so");
            InputStream in = ctx.getAssets().open("dsh/libhachimi.so");
            FileOutputStream fo = new FileOutputStream(out);
            byte[] b = new byte[1 << 16];
            int n; long total = 0;
            while ((n = in.read(b)) > 0) { fo.write(b, 0, n); total += n; }
            fo.close(); in.close();
            w(lf, "copied " + total + " bytes -> " + out);
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

ANDROID = "{http://schemas.android.com/apk/res/android}"


def find_launcher(manifest_text):
    try:
        root = ET.fromstring(manifest_text)
    except Exception:
        return None
    app = root.find("application")
    if app is None:
        return None

    def has_launcher(node):
        for f in node.findall("intent-filter"):
            acts = {a.get(ANDROID + "name") for a in f.findall("action")}
            cats = {c.get(ANDROID + "name") for c in f.findall("category")}
            if "android.intent.action.MAIN" in acts and "android.intent.category.LAUNCHER" in cats:
                return True
        return False

    for act in app.findall("activity"):
        name = act.get(ANDROID + "name") or ""
        if name and not name.startswith("android.") and has_launcher(act):
            return name
    for al in app.findall("activity-alias"):
        if has_launcher(al):
            return al.get(ANDROID + "targetActivity")
    return None


base.SHIM_JAVA = SHIM_JAVA
base.find_launcher = find_launcher

if __name__ == "__main__":
    base.main()
    sys.exit(0)