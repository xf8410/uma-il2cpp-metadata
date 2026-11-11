# 容器路线进展（2026-11-11）

> 承接 `docs/PROGRESS-2026-11-10.md`。11-10 的结论是：改 APK（lib/dex）会被客户端一致性校验拦死。
> 本文记录另一条路：**虚拟化容器**（无 root、不改 APK，把游戏加载进宿主进程后注入）。

---

## 1. 为什么是容器

Android 上「无 root 把代码注入别人进程」只有三条入口：
1. `ptrace` —— 需要 root 或同 uid，SELinux 直接禁止 shell 跨域 ptrace
2. `JDWP` —— 需要 `android:debuggable`，等于改 manifest
3. 宿主进程托管 —— 容器把 guest 的 dex/so 加载进**自己的进程**

所以容器不是"绕路"，是唯一可行形态。选型：`ALEX5402/NewBlackbox`（486★，仍在维护，README 声称支持到 Android 14，实测 16 能在本机启动）。

---

## 2. 本机构建链（已跑通，产物在 Release `builds`）

`.github/workflows/blackbox-build.yml`：clone 上游 → 打补丁 → **JDK 21 + NDK 29.0.13846066 + platforms;android-36** → `assembleDebug` → 发布。
（上游 `app/build.gradle` 要求 Java 21、`ndkVersion 29.0.13846066`；缺一个都编不过。）

已打过的补丁（都在这个 workflow 里，用 python 锚点替换）：

| # | 补丁 | 作用 |
|---|---|---|
| 1 | manifest 加 `MANAGE_EXTERNAL_STORAGE` | **关键**：只给 appops 不够，没声明依旧 `Permission denied` 读 `/sdcard` |
| 2 | `WebViewProxy` 里把 guest Context 换成宿主 Context | 修容器内 WebView |
| 3 | `BActivityThread` 里 `System.load("/sdcard/Download/libhachimi.so")` | **Hachimi 注入点** |
| 4 | `App.onCreate` 自动导入 + 自动启动 | 测试不用点屏幕 |
| 5 | `strings.xml` 中文化 + `AppsRepository` 完整堆栈日志 | 中文界面 + 可诊断 |

---

## 3. 实测得到的关键结论

1. **BlackBox 能在 Android 16 上运行**，但官方 release 的"支持 Android 16"只覆盖了启动层。
2. **容器内 WebView 全局不可用**（连 `https://example.com` 都失败，报 `net::ERR_CACHE_MISS`），
   而同一个测试 App 在容器外完全正常。
3. 根因：容器数据目录里**从来没有 `app_webview*`**（`run-as top.niunaijun.blackbox` 里全盘搜索为空），
   Chromium 初始化失败。把 WebView 的 Context 换成宿主 Context 后，日志里出现
   `HTTP Cache size is: 20971520`，`ERR_CACHE_MISS` 计数归 0。
4. **修好后游戏能走完**：点击屏幕 → 连接中 → 启动游戏 → **弹出 bilibili 手机号/密码登录框**。
5. 另一个坑：`installPackageAsUser(File)` 传 `/sdcard/...` 路径会失败（返回 `success=false`），
   而传**已安装包名** `installPackageAsUser("com.bilibili.umamusu", 0)` 成功。

---

## 4. 当前卡点

最后一个包 `bb-hachimi-1111-0329.apk`（含 Hachimi 注入补丁）已构建成功，
但手机上 **`pm install` 连续超时**（`pm install`、分块 install-create/commit 都卡在 commit），
`pm install` 一个 9KB 测试包却正常 ⇒ PackageManager 状态已乱，**需要重启手机**才能继续安装。

---

## 5. 重启后的下一步（按顺序）

1. 装 `bb-hachimi-1111-0329.apk`，`appops set top.niunaijun.blackbox MANAGE_EXTERNAL_STORAGE allow`
2. `appops set ... ACTIVATE_VPN ignore`（否则每次启动都弹 VPN 授权）
3. 确保 `/sdcard/Download/libhachimi.so` 存在（15,068,464 B，来自
   `zygisk-hachimi2020-v0.14.0-5ea0359-release.zip` 的 `lib/arm64-v8a/libhachimi.so`）
4. 启动 BlackBox → 自动导入 + 启动游戏 → 看 `logcat | grep BB_INJECT`：
   - `hachimi loaded in guest` ⇒ 注入成功，接着看 Hachimi 悬浮窗
   - `hachimi load failed` ⇒ 看堆栈（大概率是 SELinux 或路径不可读）
5. 成功后要验证：游戏能否正常登录、TP 是否检测容器（目前在容器里已经过了协议页，未过登录）

---

## 6. 相关产物

| 文件 | 说明 |
|---|---|
| `blackbox-build.yml` | 完整构建流水线（含全部补丁） |
| `bb-hachimi-1111-0329.apk` | 带 Hachimi 注入的容器（最新） |
| `bb-pkg-1111-0320.apk` | 只有自动导入、无注入（对照） |
| `webview-test.yml` | 最小 WebView 测试 App（区分容器内外） |
| `/sdcard/Download/orig.apk` | 原版国服 APK（容器自动导入用） |
| `/sdcard/Download/libhachimi.so` | Hachimi 模块的 arm64 库 |