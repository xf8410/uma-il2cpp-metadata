# 问题总结：赛马娘国服（闪耀！优俊少女）无 root 逆向现状

> 生成时间：2026-11-13　设备：Android 16（OPPO/ColorOS）
> 仓库：`xf8410/uma-il2cpp-metadata`

---

## 0. 目标与当前卡点

**最终目标**
拿到国服客户端从 CDN 下载的 **加密 AssetBundle**（游戏内路径 `Persistent/dat/XX/HASH`），
验证 [UmaViewer 的方案](https://github.com/katboi01/UmaViewer/blob/master/Assets/Scripts/AssetBundleDecryptor.cs)
（**前 256 字节明文，从第 256 字节起 `data[i] ^= Keys[i % Keys.Length]`**），解出资源。

**当前卡点**
在**无 root** 的手机上，拿不到任何一个「真实下载 URL 路径」，也拿不到任何一个密文文件。
本地所有能读到的文件都已是明文（见 §1），加密只存在于「CDN 下发 → 写入 App 内部存储」这一环。

---

## 1. 已经确认完成的事（可复用的既有成果）

| 项 | 结论 | 证据 |
|---|---|---|
| `libil2cpp.so`（arm64） | **已解密**（XOR 0x97 全解） | 129,667,848 B；297,859 个 256B 窗口扫描，加密段 **0**；抽样 200 入口 92.5% 直接 `ret` |
| `global-metadata.dat` | **已修好** | 头 `AF 1B B1 FA`，版本 27，32,248,932 B |
| `master.mdb` | **明文 SQLite**，无需解密 | 头 `SQLite format 3`，熵 2.16，45,879,296 B |
| APK 内 `assets/bin/Data/*`（2809 个） | **明文** Unity SerializedFile | 内含 `2020.3.49f1`、`HorseShoeBadgeIcon` |
| `lib/armeabi-v7a/libil2cpp.so` | **完全明文**（不用解） | ARM32 AL 条件位占 63–67%，XOR-0x97 假设为 0% |
| `lib/arm64-v8a/libil2cpp.so`（APK 内） | 加密态（即已解的那份） | 4MB 窗口 ret 密度 0% / 1.15% / 0.59% / 0% |
| 加解密方法定位 | 已定位 RVA | `DecryptAcb@0x1BD2F88`、`Decrypt@0x1BD2EF8`、`DecryptRJ256@0x27B5618`、实体 `0x27B56EC` |
| `DecryptAcb` 内常量 | `0x0017D207B5350050`（`eor` 到参数后写对象 +0x30） | 反汇编 |
| 资源 CDN 主机 | **`static.biligame.net`** | Reqable 实测：游戏 40 秒内建 **62+ 个 CONNECT**；DNS = 阿里云 CDN `47.246.20.196~203` |
| 国服网关主机 | `l1/l2/le1/l1-bak-prod-bili-gs-uma.bilibiligame.net` | APK config 里 grep 出；`l2-prod`=218.12.76.150/156，与实测 socket 218.12.76.158 同段 |

---

## 2. 已排除的方向（**含排除理由，避免重复踩**）

| # | 方向 | 为什么排除 | 证据 |
|---|---|---|---|
| 1 | **抓 `logcat` 拿下载 URL** | 游戏根本不打 URL | 游戏进程（pid 19265）全缓冲区只有 **172 行**日志，`grep http/bili-gs-uma/dat/` 全空 |
| 2 | **读外部存储的下载产物** | 下载不落外部 | `/sdcard/Android/data/com.bilibili.umamusu/` 里 >512KB 的文件只有一份**加密的** `global-metadata.dat`（头 `94 43 72 12`）和 mono 资源；`cache/` 只有 UnityShaderCache；`files/log_buma` 空 |
| 3 | **猜 CDN 路径直接拉** | 路径是 hash，猜不中 | 在 `static.biligame.net` 上试了 15 条（`/`、`/dl/`、`/resources/`、`/uma/`、JP 的 `/dl/resources/Generic/3U/<hash>` …）→ `/` 403，其余全 404（阿里云 605B HTML 错误页） |
| 4 | **直接请求 `bili-gs-uma` 网关** | 是鉴权网关，不是静态 CDN | 任意路径都返回同一个 **220 字节 `application/x-msgpack`**（实际是 Base64 文本，解出约 165B 加密信封），响应头 `via: CHN-HElangfang-…`（bilibili CDN 边缘） |
| 5 | **JP 的 akamai CDN** | 域名已废 | `prd-storage-umamusume.akamaized.net` 在**手机和 GitHub Actions runner 上都** `curl: (6) Could not resolve host` |
| 6 | **静态调用图找 key/IV** | il2cpp 走函数指针 | 全 so 扫 **2,373,281 条 BL / 484,567 条 B**；`DecryptRJ256` 实体只被自己的壳跳转 1 次、`DecryptAcb` 只被 `Decrypt` 尾调用 1 次；扫自己（`0x16378B0`）命中 80 处证明扫描器没问题 |
| 7 | **同类方法里找 key** | key 是参数传入 | 反汇编 `DecryptRJ256` 所属类（types idx 3923）全部方法，只有字符串拼接/转发，没有 key/IV 常量 |
| 8 | **Il2CppDumper 出 dump.cs** | 保护型 registration | v6.7.46 能识别 metadata **v27 → 27.1**，搜到 CodeRegistration `0x7469708` / MetadataRegistration `0x746A1F0`，随后 `Il2Cpp.Init` **`System.OverflowException`**，日志有 `find .init_proc` / `This file may be protected` |
| 9 | **用户证书 + MITM 解游戏 TLS**（大概率） | targetSdk 30 不信任用户证书 | Reqable「开发者」页原文：用户证书需**应用自己配置信任**；且实测装证书后**把我自己（DSH）的 `api.deepseek.com` 拦挂**，模型请求全失败 → 已被用户卸载 |
| 10 | **NetGuard 抓域名** | 只能给域名，给不了路径 | 域名我们已经知道了（`static.biligame.net`），缺的是 URL path |
| 11 | **运行日志/异常里找 URL** | 同上 | 无 |
| 12 | **`run-as` / 备份读内部存储** | 非 debug 包 | `dataDir=/data/user/0/com.bilibili.umamusu`，Shizuku(shell uid 2000) 读不了；非 debuggable 无法 `run-as` |

---

## 3. 还没排除、但需要额外条件的路线

| 路线 | 需要什么 | 可行性/风险 |
|---|---|---|
| **A. Reqable 白名单 + 用户证书**（只代理游戏） | 已配好白名单（免费版名单只能 1 个 app）；证书需重装一次 | **最低成本，尚未验证**：若游戏没做 pinning 且信任用户证书，就能看到 `GET https://static.biligame.net/<path>`；若游戏只走系统信任库，则只会看到 CONNECT |
| **B. 系统 CA**（Magisk 模块 / 直接写系统 cacerts） | **root** | 成功率高；`/system/etc/security/cacerts` + `/apex/com.android.conscrypt/cacerts` |
| **C. frida-gadget 重打包注入** | 破签名校验 + 过 ACE（`libtprt`/`libtersafe2`，还会连 `anticheatexpert.com`） | 理论可行、风险高（封号/闪退）；好处是能直接 hook `UnityWebRequest`/`CriMana` 拿明文 URL |
| **D. APK 重打包 + `network_security_config` 信任用户证书** | 同上，且要改 manifest | 只要能过签名校验就能 MITM；比 C 轻 |
| **E. root 直接读内部存储** | root | 最直接：拷 `Persistent/dat/XX/HASH` 出来就能验 XOR 方案 |
| **F. 换环境做**（PC 模拟器 / 云手机 / DMM 版） | 一台电脑或云机 | 避开手机全部限制，可直接拿 `Persistent/dat` |
| **G. 自己写 metadata 解析器**（不用 Il2CppDumper） | 已解密的 so + metadata | 只能拿类型/字段/字符串，**拿不到调用点**，对"找 URL"帮助有限 |

---

## 4. 给其他 AI 的精确技术参数（问的时候必须带上）

```
平台：Android 16（ColorOS），无 root，可用 Shizuku（adb shell 权限，uid 2000）
被逆向目标：com.bilibili.umamusu（闪耀！优俊少女），versionName 2.0.5 / versionCode 11220，targetSdk 30
引擎：Unity + il2cpp，global-metadata 版本 27（IL2CPP 27.1），assets 里 Unity 版本字符串 2020.3.49f1
已有成果：
  - libil2cpp.so（arm64，129,667,848 B）已完全解密（XOR 0x97），metadata 已修复（头 AF 1B B1 FA，v27）
  - 32 位 armeabi-v7a 的 libil2cpp.so 本来就是明文
已知加密对象：CDN 下载的 AssetBundle，游戏内路径 .../Persistent/dat/XX/HASH（HASH 为 32 位）
  公开方案：前 256 字节明文，从第 256 字节起循环 XOR（key 长度未知，UmaViewer 的 AssetBundleDecryptor）
已知网络事实：
  - 资源 CDN 域名 = static.biligame.net（阿里云 CDN，47.246.20.x）；实测游戏 40 秒内建 62+ 个 CONNECT
  - 静态 GET 猜路径全部 404；`/` 是 403
  - 另有登录网关 l1/l2/le1-prod-bili-gs-uma.bilibiligame.net：任意路径都返回 220B Base64 加密信封（需登录签名）
  - JP 的 akamai CDN 域名已废（DNS 解析失败）
已排除：logcat 无 URL、外部存储无产物、静态调用图追不到 key（il2cpp 走函数指针）、
        Il2CppDumper 在 Init 阶段 OverflowException（保护型 registration）、
        不装 root 时用户证书对 targetSdk≥24 的应用默认不生效
```

---

## 5. 可直接粘给其他 AI 的提问模板

### 模板 A（首选：要可执行方案）

> 我在做「赛马娘国服（com.bilibili.umamusu，2.0.5/11220，Unity + il2cpp v27，targetSdk 30）」的逆向。
> 设备是 Android 16、**没有 root**、只有 Shizuku 的 adb shell 权限。
> 我已经完成了：arm64 的 libil2cpp.so 完全解密（XOR 0x97）、global-metadata 修复（v27，头 AF 1B B1 FA），
> 32 位 so 本来就是明文；`master.mdb` 是明文 SQLite；APK 内 assets 也都是明文。
>
> 现在要拿的是**游戏从 CDN 下载的加密 AssetBundle**（游戏内 `Persistent/dat/XX/HASH`，
> 公开资料说格式是「前 256 字节明文 + 其后循环 XOR」）。
> 已知资源 CDN 域名是 `static.biligame.net`（阿里云 CDN），但它对任意猜的路径都回 404/403；
> 另有登录网关 `*-prod-bili-gs-uma.bilibiligame.net`，任意路径回同一个 220B 加密信封。
> 已排除：logcat 里没有 URL；`Android/data` 外部目录没有资源；下载文件在 `/data/user/0/<包名>/`（读不到）；
> Il2CppDumper 在 `Il2Cpp.Init` 阶段 OverflowException；静态调用图追不到 key（il2cpp 走函数指针）。
>
> 请给出**在无 root、只有 Shizuku 的前提下**，能拿到「真实资源 URL path」或「任意一个密文文件」的具体方案，
> 按「可行性 / 操作步骤 / 需要的额外条件 / 会被 ACE（libtprt、libtersafe2、anticheatexpert.com）发现的风险」排序。
> 不要泛泛而谈，每条方案请给到「具体用什么工具、点哪一步、命令或代码」的粒度。

### 模板 B（专问注入）

> Android 16、无 root、有 Shizuku（shell uid）、目标 App 是 targetSdk 30 的 Unity il2cpp 游戏（有腾讯 ACE：
> libtprt / libtersafe2，联网检测 anticheatexpert.com）。我想在 App 进程内 hook
> `UnityWebRequest` / `CriMana` / `AssetBundle.LoadFromFile` 来打印真实请求 URL 和资源路径。
>
> 请分三类回答：
> 1) **完全无 root**：frida-gadget 重打包注入（需要改签名，ACE 会怎么检测？有没有办法只改
>    `lib/<abi>/` 加一个 gadget 而不动 dex？）、LSPatch/免 root Xposed 之类能不能覆盖到 native hook？
> 2) **半 root / Shizuku 能力边界**：Shizuku 能不能 attach 到别的进程、能不能读 `/data/user/0/<pkg>`？
> 3) **不动 App 的旁路**：不改 APK 的前提下，有没有办法让 App 的 HTTPS 请求落到我能解密的地方
>    （用户证书 + network_security_config 无效时怎么办）？
>
> 对每条给：需要改什么文件、签名校验/完整性校验怎么绕、ACE 检测点、失败时怎么回退。

### 模板 C（专问证书/TLS）

> 目标 App：Android 14+ 设备上的 **release 包**，targetSdk 30，自己实现的 OkHttp/UnityWebRequest。
> 我装的是用户 CA（Reqable），MITM 后只看到 `CONNECT host:443`，看不到路径。
> 问题：在不 root 的前提下，有没有办法让 targetSdk≥24 的应用信任用户 CA？
> （不要回答"改 network_security_config 重打包"以外没有其他办法，如果只有这一条，请说明重打包签名校验怎么处理，
> 以及有没有"只 patch resources.arsc/manifest 而不动 dex 从而避开签名校验"的实际案例。）

---

## 6. 一句话现状

> 代码层已经全部解密完成；卡在**资源层**——加密的 AssetBundle 只在 App 内部存储里，
> 没有 root 就读不到，而没有它就无法验证 XOR 方案、也无法反推 key。
> 无 root 下最后的希望是「白名单 + 用户证书」能看到 URL，否则只能上 root / 重打包 / 换环境。