# 国服育成静态槽定位（WorkSingleModeData）

> 这个文件夹集中存放「国服 IL2CPP 静态槽定位」这条线的**全部进度、报告和结论**，全部为可直接阅读的明文（.md / .json），不含压缩包和二进制。

**最后更新：2026-11-12**

---

## 一句话结论

国服游戏里「当前是不是在育成中」这个状态（`isPlaying`），在内存里的位置已经**完全定位并交叉验证**：从游戏自己的单例对象一路摸过去，`WorkSingleModeData + 0x19` 这一个字节就是它，而且**全程序集只有一个写入口、一个读出口**——挂住这两条指令就能 100% 覆盖，不存在漏网的旁路写入。

打个比方：以前要找「这个玩家有没有在育成」，等于在一栋楼里挨个房间翻；现在拿到了门牌号——先找到楼（`WorkDataManager`），再找到那个固定的抽屉（`+0x58`），抽屉里第三格里就是开关（`+0x19`）。

---

## 核心结论：四步寻址链

```
Il2CppClass(WorkDataManager) + 0xB8   → static_fields          （类信息里的静态字段区）
static_fields[0]                       → WorkDataManager 实例   （Singleton<T>._instance）
WorkDataManager + 0x58                 → WorkSingleModeData 实例（育成数据本体）
WorkSingleModeData + 0x19 (1 字节)     → isPlaying              （是否在育成中）
```

四个环节都有独立的指令级证据，不是推理出来的：

| 环节 | 证据方法 | 地址 |
|---|---|---|
| 第 1→2 步 | `Singleton<T>.get_Instance` 泛型共享版 | `0x14BD694` |
| 第 3 步（读） | `WorkDataManager.get_SingleMode` | `0x3BEF274` |
| 第 3 步（写） | `WorkDataManager..ctor` 里的 `str x20,[x19,#88]` | `0x3BEF8BC` |
| 第 3 步（旁证） | 5 个写入点全部走 `ldr x0,[x0,#88]` | — |

`0x58 = 88` 这个偏移有**三条互相独立的证据**指向同一个结论。

---

## `isPlaying` 的读写点：唯一性

| 方向 | 方法 | 地址 | 指令 |
|---|---|---|---|
| 写 | `set_IsPlaying` | `0x3895FA0` | `strb` |
| 读 | `get_IsPlaying` | `0x3895F48` | `ldrb` |

扫描范围是 `WorkSingleModeData` 的全部 320 个方法（abs_idx 67087–67406），并跟踪了 `this` 寄存器被搬到 x19/x20 的情况（这一步不做会漏掉一半）。

**五个写入调用点**（全库扫 `bl 0x3895FA0`，恰好 5 处，结构完全一致）：

| RVA | 所属方法 | 写入值 | 语义 |
|---|---|---:|---|
| `0x4BF111C` | `SingleModeChangeViewManager::StartSingleMode` | 1 | 开始育成 |
| `0x4BF0930` | `SingleModeChangeViewManager::GoSingleModeView` | 1 | 跳转育成界面 |
| `0x357502C` | `SingleModeUtils::ClearPlayData` | 0 | 清理游玩数据 |
| `0x34D73F8` | `<FinalizeView>d__19::MoveNext` | 0 | 结束界面协程 |
| `0x3462FE0` | `<EndView>d__65::MoveNext` | 0 | 退出界面协程 |

2 个写 true、3 个写 false，语义全部对上。

---

## 整表可信度的锚点

```
get_Character @ 0x3896290:
    ldr x0, [x0, #48]     ; +0x30
    ret
```

只有两条指令，干净得不能再干净。`+0x30` 与字段表 idx=5 `<Character>k__BackingField` 精确吻合。

因为 `_isPlaying`(0x19)、`_totalTurnNum`(0x2C)、`_scenarioIdList`(0x88)、`_cachedRewardEventId`(0x190) 这些偏移和 `Character` 出自**同一张反汇编扫描**，这一条就把整张 61 字段表的可信度锚住了。

---

## 这个文件夹里有什么

| 文件 | 内容 |
|---|---|
| `报告.md` | 完整技术报告，10 章。解析器修复、单例链四条证据、61 字段表、WorkDataManager 槽表、内存扫描方案、未决项、复现步骤、读写点唯一性、fields.tsv 缺陷、Frida 探针说明 |
| `字段表.md` | `WorkSingleModeData` 61 个字段的偏移对照表，带语义分组，方便查 |
| `进度.md` | 时间线：每一步做了什么、卡在哪、怎么解的、还剩什么没做 |
| `附-校验清单.md` | 上机前该检查什么、怎么判断探针跑对了、哪些还没验证 |
| `data/work_single_mode_offsets.json` | 结构化数据：单例链、类布局、61 字段全表、WorkDataManager 关键槽位 |

代码不放在这里，保持原位置：

| 文件 | 用途 |
|---|---|
| `../tools/parse_metadata_fixed.py` | 修复版 metadata 解析器 |
| `../tools/probe/uma_probe.js` | Frida 运行时验证探针 |

---

## 进度快照

| 阶段 | 状态 |
|---|---|
| metadata 解密还原 | ✅ 完成 |
| metadata 解析器缺陷修复（字段归属错位） | ✅ 完成 |
| SO 代码段 XOR 0x97 全量解密 | ✅ 完成（49,129/49,143 方法可反汇编） |
| 单例链定位 | ✅ 完成，四条独立证据 |
| 61 字段偏移表 | ✅ 完成，锚点校验通过 |
| `isPlaying` 读写点唯一性 | ✅ 完成，1 写 1 读 |
| 5 个写入点语义 | ✅ 完成，2 真 3 假 |
| 仓库 `fields.tsv` 重建覆盖 | ⬜ **未做**（旧版 type_index 列是错的，见 `进度.md`） |
| Frida 探针真机运行 | ⬜ **未做**（当前环境无 Android 设备/模拟器） |

---

## 必须说清的限制

**没有真机跑过。**

当前环境没有 Android 设备，也没有模拟器。`uma_probe.js` 只完成了**静态交付和逻辑校验**：

- 59 个实例字段名与 metadata 逐字一致 ✅
- RVA 与 `methods_rva.tsv` 一致 ✅
- 探针逻辑走查通过 ✅
- 真机运行时布局比对 ❌ **没做**

探针上机后第 3 步（字段偏移自校验）预期输出「一致 59 / 59」。如果出现差异，第一件要查的事是：**游戏版本和这次分析的 `libil2cpp.dec.so` 是不是同一版**。

---

## 已知缺陷（必须知道，不然会踩）

1. **仓库里 `metadata-20261110/dump/fields.tsv` 的 `type_index` 列是错的**。旧解析器按 typeDefinitions 数组顺序累加 field_count，组内乱序后整体偏移。`WorkSingleModeData`(idx=8972) 那里偏了 **170 个字段**。用 `tools/parse_metadata_fixed.py` 重跑才能得到正确结果。
2. **这份 metadata 的 string 表是 null-terminated，不是标准 v27 的 length-prefixed**。按标准读会把 `mscorlib.dll` 的 `m`(0x6D=109) 当成长度，读出一串拼接名。修复版解析器已加编码自动探测。
3. **typeDefinition 组内不是按 token 排序的**，实测 4985 个逆序对。重排不是优化，是必需步骤。

---

## 怎么复现

```bash
# 1) 重新 dump metadata（会修正字段归属）
python3 tools/parse_metadata_fixed.py

# 2) 跑探针（需要真机 + Frida）
frida -U -f com.bilibili.umamusu -l tools/probe/uma_probe.js
```

报告第 7 章有完整的反汇编复现步骤和五个「必读坑位」，尤其是 `adrp` 的 `immlo` 在 `bits[30:29]` 这条——漏掉会让所有槽地址落到代码段，看起来像"槽里存的是 ARM64 指令"。

---

*数据源：国服 `com.bilibili.umamusu` 2.0.5.11220.09221715 · Unity 2020.3.49f1 · metadata v27*
