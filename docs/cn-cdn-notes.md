# 国服（bilibili）CDN / 资源获取笔记（2026-11-12）

## 1. 主机与路径（从国服 APK 的 config 资源里 grep 出来）

```
https://l1-bak-prod-bili-gs-uma.bilibiligame.net
https://l1-prod-bili-gs-uma.bilibiligame.net
https://l2-prod-bili-gs-uma.bilibiligame.net
https://le1-prod-bili-gs-uma.bilibiligame.net
```

路径模板（同一批字符串里）：

```
resource_server_cf
resource_server_ingame
resource_server_login
resource_version
resources/Android/assetbundles/
resources/Generic/
resources/Manifest/
```

## 2. 探活结果（CI `cn-cdn-probe2`）

- `https://l1-prod-bili-gs-uma.bilibiligame.net/` → **200，`application/x-msgpack`，220 字节**
- 试过的 9 条路径（含 `/resources/Manifest/Android/manifest.json`、`/resources/Generic/3U/<hash>`、`/dl/resources/...`）
  **全部返回同样的 200 + 220 字节** → 这是 **API 网关的默认响应**，不是静态 CDN；
  路径必须精确且带鉴权，随便拼路径拿不到内容。
- 结论：资源服务器地址是**登录后由服务器下发**的（config 里那三个 `resource_server_*` 键就是给登录响应用的），
  未登录状态下无法直接猜出 CDN。

## 3. 国服 APK 的内部结构（Shizuku shell 可读，base.apk 251,850,328 B）

```
/data/app/~~cJED2GB88de7kFc7UOJ1Xg==/com.bilibili.umamusu-sf23qJOZ3qmE4ubgv8yAmQ==/base.apk
```

| 条目 | 结论 |
|---|---|
| `assets/bin/Data/*`（2809 个，解出 254 MB） | **明文** Unity SerializedFile（含 `2020.3.49f1`、`HorseShoeBadgeIcon`） |
| `assets/bin/Data/Managed/Metadata/global-metadata.dat` | 32,248,932 B（与修复版同尺寸，仍是加密态） |
| `lib/arm64-v8a/libil2cpp.so` | **加密态**：4 MB 窗口 ret 密度 0% / 1.15% / 0.59% / 0% → 与已解密的 dec.so 一致 |
| `lib/armeabi-v7a/libil2cpp.so` | **完全明文**：ARM32 AL 条件位（高字节 E0–EF）占 63–67%，XOR-0x97 假设为 0% |
| `assets/__tpinfo.tsd` | 4,497 B（腾讯保护信息，未分析） |
| `assets/cri_auth`、`assets/fase_random.cell` | 各 256 B（CRI 鉴权/随机种子，未分析） |

数据目录：`/data/user/0/com.bilibili.umamusu`（内部存储，**无 root 读不到**）。

## 4. 下载中的实测（2026-11-12 11:50，游戏真的在下载）

- 游戏版本：**2.0.5**（versionCode 11220, targetSdk 30）
- `/proc/net/tcp` 里的 HTTPS 远端（下载中，按连接数）：

| 远端 IP | 连接数 |
|---|---|
| 218.12.76.158 | 16 |
| 221.194.141.157 | 10 |
| 42.236.90.180 | 4 |
| 114.250.41.232 | 2 |
| 119.188.175.46 | 2 |

- DNS 比对（CI `cdn-host-id`）：
  - `l1-prod` / `le1-prod` / `l1-bak-prod` → `155.102.176.81~88`
  - **`l2-prod` → `218.12.76.150/156`** ← 与实测 218.12.76.158 **同段**，资源走 l2-prod
- 在 `l2-prod` 上再试 8 条路径：**仍然全部 200 + 220 字节 msgpack** →
  说明该网段对任意路径都回统一的网关响应，**必须带会话/签名头**，静态 GET 拿不到资源。

## 5. 游戏的外部存储里到底有什么（下载中实测）

`/sdcard/Android/data/com.bilibili.umamusu/`（11:37 才被创建）：

```
cache/UnityShaderCache/*            （Unity 着色器缓存，明文）
files/il2cpp/Metadata/global-metadata.dat   32,248,932 B，头 94 43 72 12…
files/il2cpp/etc/mono/...            （mono 配置）
files/il2cpp/Resources/*.dll-resources.dat
files/log_buma/                     （空）
files/MiPushLog/、files/lpfi/、files/notifications.bin
```

- 那个 32 MB 的 `global-metadata.dat` 头是 `94 43 72 12 …` = **加密态**（和 APK 里那份一模一样），
  游戏只是把它复制到外部，**解密在内存里做**。
- 外部目录里 **没有任何资源缓存**（>512 KB 的文件只有上面这两个）；
  `logcat` 里也 **没有下载 URL**（Unity 不打这个日志）。

## 6. 结论

- 本地能拿到的全部是明文；**唯一还加密的是 CDN 下载的 `Persistent/dat/XX/HASH`**，落在内部存储。
- 无 root 时，下不下得动都拿不到密文：外部目录不留、logcat 不打 URL、网关要鉴权。
- 剩下可行的只有：① root / Magisk 后直接读 `/data/user/0/com.bilibili.umamusu/...`；
  ② root + MITM 代理（装用户 CA）抓 HTTPS URL；
  ③ 有 PC/DMM 版的话拷 `Persistent/dat/` 里的文件。