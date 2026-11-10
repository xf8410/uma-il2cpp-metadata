# Hachimi 注入打包（不 root）

## 原理

Hachimi 在 Android 上的加载方式：**替换游戏自己的 `libmain.so`**，由它 `dlopen` 起 `libhachimi.so`。
所以只要把这两个文件塞进 APK 的 `lib/arm64-v8a/`，重新打包、对齐、签名，就能直接安装——
**不需要 Magisk / root**，代价是签名变了，每次游戏更新都得重打一次。

```
原版 APK
  ├─ lib/arm64-v8a/libmain.so      ← 换成 Hachimi 提供的版本
  ├─ lib/arm64-v8a/libhachimi.so   ← 新增
  └─ 其它原样保留
        ↓ zip（.so/.arsc 不压缩）
        ↓ zipalign -p -f 4
        ↓ apksigner（v2+v3，自签名）
注入版 APK（可直接安装）
```

## 放什么进来

```
apk-20261110/
  syyjsn_2.0.5.11220.09221715_....apk     ← 原版游戏安装包（任意文件名，取第一个 .apk）
hachimi-<版本>/
  .../libhachimi.so                       ← 国服那版 Hachimi 的 release 解包内容
  .../libmain.so                          ← 同一 release 里给 ARM64 用的 libmain
```

> 必须是**支持国服/Unity2020 的 Hachimi 版本**。新版不认国服，插件 API 也可能不同。

## 跑

推上去后 `.github/workflows/hachimi-apk.yml` 自动执行：

1. 找 `apk-*/*.apk`，找 `libhachi*.so` + `libmain.so`
2. 解包 → 替换/新增 → 重打包（`.so` 与 `resources.arsc` 保持不压缩）
3. `zipalign -p -f 4`（`.so` 页对齐，`extractNativeLibs=false` 需要）
4. `apksigner` 自签名（v2+v3），并 `verify`
5. 产出 **artifact：`hachimi-patched-apk`**

没放输入时流程会**跳过并保持绿色**，不会污染 CI。

## 装

1. **先卸载原版游戏**（签名不同，覆盖安装会失败）
2. 装 artifact 里的 `*-hachimi.apk`
3. 首次启动后 Hachimi 会初始化配置/插件目录

## 不 root 的限制

| 项 | 说明 |
|---|---|
| 每次游戏更新 | 要重新注入打包（新版 APK 的 `libmain.so` 会变） |
| 签名 | 自签名，和官方不同 → 必须卸载重装；账号数据在服务器侧，不受影响 |
| 存档 | 游戏存档在服务器/`Android/data`，卸载前留意本地缓存 |
| 系统级 hook | 没有，全部在应用进程内，系统不受影响 |

## 插件（下一步）

Hachimi 跑起来之后，插件是独立 `.so`，放到 Hachimi 的插件目录即可，运行时加载。
插件入口是 `hachimi_init(vtable, version)`，通过 vtable 提供的
`il2cpp_get_assembly_image / il2cpp_get_class / il2cpp_get_method` **按名字**解析方法——
所以 `metadata-20261110/dump/` 里的类型名/方法名/参数数就是写插件时的符号表。

国服 2.0.5 已核对的 hook 目标（名字与日服一致）：

```
StandaloneSimulator.RaceRandom            #6577   GetRandom × 4 重载（其中一个 paramCount=2）
Gallop.SingleModeRaceRandomProgram        #26908
Gallop.WorkSingleModeData                 #8972
SingleModeStoryData / SupportCardEffectTable / SingleModeSkillNeedPoint / SingleModeHintGain
RaceRandomProgramArray                     ← 国服没有（改名或已移除）
```