#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dex_inject2 的修正版：只替换「找 launcher」的逻辑

原因：原实现用正则跨 activity 匹配，误把微信支付页 WXPayEntryActivity 当 launcher。
这里改成用 XML 解析：只有自身 intent-filter 里同时含 MAIN + LAUNCHER 的 activity 才算。
"""
import sys
import xml.etree.ElementTree as ET

import dex_inject2 as base


def find_launcher(manifest_text):  # noqa: D103
    ANDROID = "{http://schemas.android.com/apk/res/android}"
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


base.find_launcher = find_launcher

if __name__ == "__main__":
    base.main()
    sys.exit(0)