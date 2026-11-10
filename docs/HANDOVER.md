# 交接文档：闪耀优俊少女（国服）2.0.5 Hachimi 注入

> 最后更新：2026-11-10 21:4x（UTC+8）
> 仓库：`xf8410/uma-il2cpp-metadata`（私有）
> 目标：**无 root 给国服客户端注入 Hachimi，实现加速/性能调整**

---

## 一、一句话结论

**无 root 的 APK 注入在国服 2.0.5 上被卡在「`lib/` 目录完整性校验」这一层。**
`lib/` 之外的改动（dex、assets、任意资源）**完全不被拦截**；但一旦改/换/新增 `lib/` 下任何 `.so`，进程会在 1~12 秒内被 **SIGKILL 静默杀死**（无异常、无堆栈、无信号）。
因此唯一还没走通的是「在不碰 `lib/` 的前提下把 Hachimi 加载起来」——dex 注入方案已推进到能打包，但**启动黑屏、日志未落盘，尚未定位**。

---

## 二、实验记录（全部是实测，非推测）

| # | 版本 | 改了什么 | 结果 | APK sha256 / 大小 |
|---|---|---|---|---|
| — | 原版 | 官方包 | ✅ 正常 | — |
| 1 | control-repack | 只重打包 + 重签名，**内容零改动** | ✅ **能登录、能进数据下载页、能玩** | `b58ae9e7…` 251,854,416 B |
| 2 | hachimi-patched（首版） | 混源 proxy（arm64 用 Edge、v7a 用上游）+ 误塞 Zygisk 版 `libhachimi.so`，全量重压 | ❌ 10 秒崩（且包体膨胀到 511 MB） | `9aa1f519…` |
| 3 | hachimi-patched（修正） | 仅 Edge proxy 替换 `libmain.so` | ❌ 10 秒+ 崩 | `55a5a295…` 277,302,985 B |
| 4 | v2 | `libmain.so` ← Unity2020 版 `libhachimi.so`（自带 `JNI_OnLoad`） | ❌ 1~3 秒崩，**但能看到 Hachimi GUI（v0.14.0-5ea0359）** | `05b0431c…` 282,021,672 B |
| 5 | v3 | 自编崩溃钩子 proxy（信号处理 + 看门狗） | ❌ 10~12 秒静默死；日志证明 `JNI_OnLoad` 正常返回 `65542` | `d596178e…` / `66c25ce7…` |
| 6 | v4 | 同 proxy **不加载 Hachimi**（dlopen 失败回落原版） | ❌ 10 秒静默死 | `22c673b0…` 251,891,399 B |
| 7 | v5 | `libmain.so` = 原版字节 **+1 个 `\0`**（功能不变） | ❌ **1 秒崩** | `8cf2a755…` 251,870,820 B |
| 8 | v6 | `libbili.so` 末位 +1 字节 | ❌ 12 秒崩（死在登录页） | `130077bf…` 251,899,492 B |
| 9 | v7 | **新增**一个 5,512 B 空 so，已有文件全不动 | ❌ 12 秒崩 | `9c50952f…` 251,870,894 B |
| 10 | v8 | 改 `kotlin-tooling-metadata.json`（+1 换行，非 lib） | ✅ **不崩** | `49453645…` 251,854,436 B |
| 11 | dex-inject 系列 | dex 注入 + `assets/dsh/libhachimi.so`（不碰 `lib/`） | ⚠️ 能打包签名成功，**启动黑屏**，Shim 日志未落盘 | 见 `dex-inject*-status.txt` |
| 12 | remove-tp 系列 | 删除 `libtersafe2.so` | ⏳ **未跑成**（YAML heredoc 坑，已修成 `remove-tp2`，待验证） | — |

**结论推导**：
- 4/5/6/7 → 只要 `libmain` 被改就死（v5 最干净：只多 1 字节、代码未变）
- 8/9 → 不只 `libmain`，`libbili`、甚至"多一个文件"也会死 ⇒ 校验覆盖整个 `lib/`
- 10 → `lib/` 之外**不受影响** ⇒ dex/assets 路线理论可行
- 11 → dex 路线能过打包，但启动黑屏（两个可能：① 插桩点没被汇编进包；② smali 重组破坏了 dex）

---

## 三、关键技术发现（可复用）

### 1. 国服 metadata 已被完整还原
`metadata-20261110/`：
- `global-metadata.fixed.dat` 32,248,932 B（原文件头部被污染，每 64 KB 块内 16 KB 页 XOR 0x66，已解）
- `libil2cpp.so.gz` + sha256
- `dump/types.tsv` 32,080 条
- `dump/methods.tsv` 213,983 条（paramCount 在 `+0x1C>>16`）
- `dump/fields.tsv` 254,055 条（含所属类）
- `dump/methods_rva.tsv` 207,419 条（RVA 映射成功率 96.9%）
- `dump/string_literals.txt` 26,385 条
- `dump/code_xor97_pages.txt` 1,215 段加密代码区间
- 元数据是**紧凑布局**（无 `*Start` 数组）、typeDefinition 88 B、methodDefinition 32 B、fieldDefinition 12 B

### 2. Hachimi 版本对应关系（重要）
- `Hachimi-Hachimi/Hachimi`（JP/主线，Unity 2022）→ 提供 `libmain-arm64-v8a.so` proxy（15 MB，只导出 `JNI_OnLoad`）
- `Hachimi-Hachimi/Hachimi-Unity2020`（分支 `2020`，**支持 CN/TW**）→ **只发 Zygisk 包**，release note 原文：
  > Initial pre-release with support for Global, CN and TW!
  > **Zygisk support on Android (CN and TW only)**
- 该分支 Android 产物 `lib/arm64-v8a/libhachimi.so` = 15,068,464 B，导出 `JNI_OnLoad` + `zygisk_module_entry` + `zygisk_companion_entry`
  ⇒ **可以直接改名当 `libmain.so` 用**（实测能让 Hachimi GUI 出现）
- 仓库里这个包全是 **prerelease**，所以 `gh release download` 必须显式给 tag，不能用默认「latest」

### 3. 反作弊结构
- `libtprt.so`（1.61 MB）：全混淆，ELF hook 载体，`libmain.so` 依赖它
- `libtersafe2.so`（5.04 MB）：**校验器**，含 `!%s, size:%d, crc:%08x`、`!tcj,name:%s md5:%s,size:%d`、`ver:%s app_ver:%s code_size:%s crc:%s`、`ano_cert_md5`、`hash_cache`、`self_sys`
- **OLLVM 控制流平坦化 + 加密跳转表**（`eor` 算下标 → `ldr x8,[x26,…]` → `br x8`），静态 patch 校验点不现实
- 侦察报告：`recon-tprt.txt` / `recon2-tprt.txt` / `recon-dynsym.txt`；脚本 `tools/recon_tprt.py`、`tools/recon2.py`

### 4. 其它环境事实
- 包名 `com.bilibili.umamusu`；Unity 2020.3.49f1；metadata v27
- 手机：ColorOS，无 root，Shizuku 未授权（ColorOS 限制 adb 权限，需在开发者选项关「禁止权限监控」）
- `/sdcard/Android/data/*` DSH 不可读；`/sdcard/Android/media/<包名>/` **可读可写**（游戏进程也能写）
- 每次换签名重装 → uid 变化 → 旧 `/sdcard/Download/dsh_crash.log` 会因属主变化写不进去（要用 media 目录）

---

## 四、仓库结构

```
.github/workflows/
  dump.yml                metadata 解析全流程（已产出 metadata-20261110/）
  hachimi-apk.yml         官方「libmain 替换」注入（含 proxy 选取、原位替换 entry）
  hachimi-apk-v2/v3/v4/v5 各实验变体（见上表）
  control-apk.yml         只重签名的对照组（关键基准）
  add-so-test.yml         只新增 so（v7）
  touch-asset-test.yml    改非 lib 文件（v8，关键证据）
  inspect-hachimi.yml     拆 Zygisk 包、读 customize.sh
  inspect-so.yml          导出符号对比
  recon-tprt.yml / recon-tprt2.yml / recon-dynsym.yml   反作弊侦察
  dex-inject.yml           ❌ 已废弃（YAML heredoc 坑）
  dex-inject2/3/…/10.yml   dex 注入迭代（10 = 日志+双插桩+Shim 并入 classes3）
  remove-tp.yml            ❌ 失败（heredoc）
  remove-tp2.yml           ⏳ 待验证（改用 tools/remove_entry.py）
  publish-tests.yml        把 artifact 汇总发布到 Release
tools/
  parse_metadata.py elf_info.py payload_info.py find_registration.py find_modules.py
  build_rva.py verify_code.py find_encrypted_code.py decrypt_so.py
  recon_tprt.py recon2.py
  crashproxy/proxy.c       崩溃钩子 proxy（信号 + 看门狗 + 抄 Hachimi 日志）
  dex_inject.py dex_inject2.py dex_inject3.py dex_inject4.py dex_inject5.py
  remove_entry.py          删除 APK 内指定 entry
docs/
  HACHIMI_INJECT.md HANDOVER.md（本文） so_hook_更正.md
可用产物 Release：
  tag=v0.14.0。      原版 APK + zygisk-hachimi2020 模块
  tag=tests-20261110-1103  各次实验 APK
  tag=builds          最新构建（dex-inject / no-tp / dex-repack）
```

---

## 五、下一步（按优先级）

1. **跑通 `remove-tp2`（删 `libtersafe2.so`）**
   - 游戏能跑 → TP 是唯一看门人，被摘掉后 `libmain` 就自由了 → 直接回到 v2 的方案（Hachimi 已能加载）
   - 启动就崩 → 游戏/登录 SDK 依赖 TP，此路不通
2. **查 `dex-repack-control` 失败原因**（对照 A：只重组 `classes3.dex` 不改代码）
   - 若重组就黑屏 → 换 dexlib2 做「原地字节码插入」，不要整包 smali 重组
   - 若重组正常 → 检查插桩是否落在被汇编的同一个 `smali_classesN` 目录（`tools/dex_inject5.py` 已有双插桩，但补丁可能写到别的目录）
3. **dex 注入黑屏定位**
   - Shim 日志已改写到 `/sdcard/Android/media/com.bilibili.umamusu/dsh_shim.log`（DSH 可读）
   - 若仍无日志 ⇒ 代码没被执行 ⇒ 回到第 2 步验证 dex 重组本身
4. **备选（确定可行）**：解锁 BL → 刷 Magisk/KernelSU → 装现成 Zygisk 模块，Hachimi 全部功能（含加速）可用

---

## 六、踩过的坑（省时间）

- **YAML heredoc**：`run: |` 块里内嵌 Python heredoc，正文顶格会破坏 block scalar ⇒ 一律挪进 `tools/*.py`
- **`gh release download` 默认取 latest**：本仓 latest 可能是自动生成的 `tests-*`/`builds`，必须先 `gh release list` 遍历找带目标文件的 tag
- **`gh release list --json assets` 过滤**在旧版 gh 上返回空 ⇒ 用遍历法
- **重打包体积**：不要全量解压重压（251 MB → 511 MB）；用 `zip -0` 原位替换 entry，再 `zipalign -p -f 4`
- **签名**：每次临时 keystore ⇒ 只能卸载重装；要覆盖更新就得固定 keystore 进仓库
- **`zip -0` 替换后必须 zipalign**，否则 `extractNativeLibs=false` 的包加载 .so 会失败
- **Shim 日志路径**：`/sdcard/Download` 在换签名重装后不可写（uid 变了），用 `/sdcard/Android/media/<包名>/`
- **`apktool b` 在这包上必挂**：`res/drawable-anydpi-v21/$gsg_message_item_*.xml` 是腾讯 SDK 的非法资源名，aapt 直接报错 ⇒ 只重汇编 dex，不重建资源

---

## 七、给接手的人

- 需要**能读写 `/sdcard/Android/media/<包名>/`** 的调试通道（DSH 可以；第三方文件管理器需要 SAF 授权）
- 想拿崩溃栈的最快方式：开 **Shizuku**（免 root）后 `adb_shell logcat -d`；ColorOS 需在开发者选项关闭「禁止权限监控」
- 所有实验都可以在 CI 里复现：推一个 `*.yml` 就会自动构建、签名，并把产物发布到 `builds` Release
- 关键判断基准永远是 **`control-apk.yml`（只重签名）**：它必须能玩，否则说明当次的打包链路本身有问题