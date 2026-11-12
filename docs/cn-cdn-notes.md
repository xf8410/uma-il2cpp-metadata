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

数据目录：`/data/user/0/com.bilibili.umamusu`（内部存储，**无 root 读不到**）；
外部 `Android/data/com.bilibili.umamusu` **不存在**（证明资源没有落到外部存储）。

## 4. 结论

- 本地能拿到的全部是明文；**唯一还加密的是 CDN 下载的 `Persistent/dat/XX/HASH`**。
- 要拿到它，只有两条路：① 登录游戏触发下载 → 抓 logcat 里的 URL 再去拉；② root/提权直接读 `/data/user/0/...`。
- 已尝试：后台启动国服客户端（成功启动），停在通知权限系统弹窗，`screen_tap` 无效（系统弹窗在别的窗口），
  继续操作需要占用用户主屏或由用户手动点一次。