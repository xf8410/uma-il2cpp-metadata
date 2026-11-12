# 解密线索台账（2026-11-12）

> 目标：在 libil2cpp 代码解密完成之后，继续找「别的东西」解密。
> 结论先行：**手上的材料已经没有密文了**；剩下真正加密的目标都需要外部样本。

## 1. 已确认明文（不需要再解）

| 对象 | 结论 | 依据 |
|---|---|---|
| `metadata-*/libil2cpp.dec.so.gz` → 129,667,848 B | 明文 | AX 段 72.7 MiB / 297,859 个 256B 窗口，XOR 0x97 加密段 **0**；抽样 200 个入口 92.5% 直接 `ret` |
| `metadata-*/global-metadata.fixed.dat` | 明文 | 头 `AF 1B B1 FA`，版本 27 |
| `master.mdb`（45,879,296 B） | 明文 SQLite | 头 `SQLite format 3`，熵 2.16 |
| 日服 APK `assets/bin/Data/*`（3937 个） | 明文 SerializedFile | 内含 `2022.3.62f2`、`_TripleMaskMap` 等字符串 |
| 国服 APK `assets/bin/Data/*`（251 MB base.apk，2948 条 assets） | 明文 SerializedFile | 内含 `2020.3.49f1`、`HorseShoeBadgeIcon` 等字符串 |
| `assets/PreinResource/*.acb` | 明文 CRI 容器 | 头 `@UTF` |
| `libs/*.so`（34 个） | 全明文 | 熵 0.72–5.93（加密块应 ≈7.9），`libil2cpp` 5.01 |

国服 APK 位置（Shizuku shell 可读）：
`/data/app/~~cJED2GB88de7kFc7UOJ1Xg==/com.bilibili.umamusu-sf23qJOZ3qmE4ubgv8yAmQ==/base.apk`

## 2. 仍然加密的是哪几类

1. **CDN 下载的 AssetBundle**（`Persistent/dat/XX/HASH`）
   方案见 [UmaViewer AssetBundleDecryptor.cs](https://github.com/katboi01/UmaViewer/blob/master/Assets/Scripts/AssetBundleDecryptor.cs)：
   **前 256 字节明文**，从第 256 字节起 `data[i] ^= Keys[i % Keys.Length]`（循环 XOR）。
   工具链：[UmaDecryptor](https://0xcjy.github.io/posts/UmaDecryptor.html)。
2. **PC/DMM 版 `master.mdb`**：SQLCipher（客户端里有 `sqlite3mc_config_cipher`，idx 26521）。
3. **下载的音频 `.awb`**：内部 HCA 流可能带 56-bit key（客户端有 `DecryptAcb`，idx 23341）。

## 3. 已拿到的代码坐标（idx 来自 methods.tsv 行序）

| 方法 | idx | RVA | 备注 |
|---|---|---|---|
| `DecryptAcb` | 23341 | 0x1BD2F88 | 内含 64 位常量 **0x0017D207B5350050**，`eor` 到参数后写对象 +0x30 |
| `Decrypt` | 24024 | 0x1BD2EF8 | 主体只是尾调用 `DecryptAcb` |
| `EncryptRJ256` | 26000/26001 | 0x27B4FF4 | 壳 → 实体 0x27B50C8 |
| `DecryptRJ256` | 26002/26003 | 0x27B5618 | 壳 → 实体 0x27B56EC |
| `CreateKey` | 26004 | — | RJ256 的 key/IV 构造 |
| 所属类 | — | types.tsv idx 3923 | 该类成员已全部反汇编：`classhunt/class-*.txt` |

## 4. 死路（别再重复踩）

- **静态调用图追不到 key**：全 so 扫过 2,373,281 条 `BL` / 484,567 条 `B`；`DecryptRJ256` 实体只有 1 处跳转（它自己的壳），`DecryptAcb` 只有 1 处（`Decrypt` 尾调用）。外部全部走 il2cpp 函数指针/虚表 → 必须靠 dump.cs 或动态调试。
- **JP CDN 已废**：`prd-storage-umamusume.akamaized.net` 在手机和 GitHub runner 上都 `curl: (6) Could not resolve host`。
- **国服 CDN 域名未知**：`libil2cpp.so` / `libnative.so` / `libunity.so` 里 grep 不到任何 CDN 域名。
- **Il2CppDumper v6.7.46**：能识别 metadata v27 → 27.1，搜到 CodeRegistration `0x7469708` / MetadataRegistration `0x746A1F0`，随后 `Il2Cpp.Init` 里 `System.OverflowException`（日志有 `find .init_proc` / `This file may be protected`）。net6 包在 8.x 上需 `DOTNET_ROLL_FORWARD=LatestMajor`。

## 5. 下一步（按性价比）

1. **拿一个密文样本**（最关键，没有密文就无法验证任何方案）：
   - 让国服客户端跑一次资源下载，用 Shizuku `logcat -d` 抓 `dat/XX/HASH` 的 URL；
   - 或解析国服 APK 里的 config 序列化文件取资源基址；
   - 或从 PC/DMM 版 `Persistent/dat/` 拷几个文件。
2. 有样本后：用 `tools/` 里的脚本 + UmaViewer 的 256 字节方案验证，并用已知明文反推 key 周期。
3. 若目标是 API 报文（RJ256）：需要能跑的 dump.cs，或用 Frida 在运行时打印 `DecryptRJ256` 的三个参数。

## 6. 仓库内现有工具

| 文件 | 用途 |
|---|---|
| `tools/verify_code.py` | 抽样反汇编 + 256B 窗口定位 XOR 0x97 段 + 内存解密复验 |
| `tools/hunt_crypto.py` | 按 idx 名单反汇编加解密方法，导出数据引用/字符串 |
| `tools/find_callers.py` / `find_callers2.py` | 扫 `BL`/`B` 找调用点（含自检计数） |
| `tools/find_class.py` | 按 idx 反汇编所属类的全部方法 |
| `.github/workflows/crypto-hunt.yml` | 跑 hunt_crypto，产物在 `crypto-hunt/` |
| `.github/workflows/callers-hunt2.yml` | 跑 find_callers2，产物在 `callers2/` |
| `.github/workflows/class-hunt.yml` | 跑 find_class，产物在 `classhunt/` |
| `.github/workflows/il2cppdump-keys2.yml` | Il2CppDumper + dump.cs 抓取（目前卡在 overflow） |