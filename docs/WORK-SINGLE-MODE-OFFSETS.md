# 国服 IL2CPP 静态槽定位报告

**目标**：为「扫内存版黑板」提供稳定的结构体锚点——从国服 `libil2cpp`（XOR 0x97 全量解密后）反推出 `Gallop.WorkSingleModeData` 的完整实例布局，并打通 `单例 → 管理器 → 育成数据` 的运行时寻址链。

**结论**：链路已闭合，三个锚点全部有独立指令级证据。

```
Il2CppClass(WorkDataManager) + 0xB8   → static_fields
static_fields[0]                       → WorkDataManager 实例（Singleton<T>._instance）
WorkDataManager + 0x58                 → WorkSingleModeData 实例
WorkSingleModeData + 0x19 (byte)       → isPlaying
WorkSingleModeData + 0x2C (int32)      → totalTurnNum
```

---

## 1. metadata 解析器修复

### 1.1 根因

`typeDefinition` 表在**同一程序集内不是按 token 排序**，而 `fields` 表**严格按 token 排序**。原先用「按数组顺序累加 `field_count`」求 `fieldStart`，只要某处乱序，后续归属整体偏移一位，跨 image 边界更必然断裂（每个程序集的 field token 都从 `0x04000001` 重新开始）。

### 1.2 修复算法

```
for each image (73 个程序集):
    idxs = [typeStart, typeStart+typeCount)
    idxs.sort(key = typeDef.token)          # 组内按 type token 重排
    for i in idxs:
        fieldStart[i] = 全局游标;  全局游标 += fieldCount[i]
        methodStart[i] = 全局游标M; 全局游标M += methodCount[i]
```

### 1.3 验证结果

| 指标 | 值 | 状态 |
|---|---|---|
| 字段总分配 | 254,055 | 与 `fields` 表 size/12 完全一致 |
| 方法总分配 | 213,983 | 与 `methods` 表 size/32 完全一致 |
| 组内 type token 逆序 | 0 处 | 通过 |
| 跨 image 断裂 | 0 处 | 通过 |

修复后 `Gallop.WorkSingleModeData`（idx=8972, token=0x02000AC2）读出 61 个字段，全部为私有字段与自动属性 backing field，语义完全正常。

### 1.4 关键结构布局（实测）

| 结构 | 大小 | 关键偏移 |
|---|---|---|
| typeDefinition | 88 B | +0 nameIndex, +4 namespaceIndex, +20 parentIndex, +64 method_count(u16), +68 field_count(u16), +84 token |
| imageDefinition | 40 B | +0 nameIndex, +8 typeStart, +12 typeCount, +28 token |
| fieldDefinition | 12 B | +0 nameIndex, +4 typeIndex（**Il2CppType 索引，可 > 类型总数**）, +8 token |
| methodDefinition | 32 B | +0 nameIndex, +0x14 token, +0x1C 高 16 位 = param_count |

---

## 2. 单例链与运行时寻址

### 2.1 证据一：`Singleton<T>.get_Instance` 泛型共享版 @ `0x14BD694`

```asm
0x14bd6a0  ldr  x20,[x0,#24]      ; MethodInfo->klass
0x14bd6a8  ldrb x8,[x20,#306]     ; klass->initialized (0x132)
0x14bd6b4  bl   0x15cf24c         ; il2cpp_class_init
0x14bd6b8  ldr  x8,[x20,#192]     ; klass->rgctx_data (0xC0)
0x14bd6bc  ldr  x20,[x8,#0]       ; 泛型共享上下文
...
0x14bd76c  ldr  x8,[x19,#184]     ; klass->static_fields (0xB8)  ★
0x14bd774  ldr  x0,[x8,#0]        ; static_fields[0] = _instance  ★
0x14bd778  ret
```

`Il2CppClass` 实测布局：`+0x10 name`、`+0xB8 static_fields`、`+0xC0 rgctx_data`、`+0x132 initialized`。

`Singleton<T>` 只有一个静态字段 `_instance`（token `0x04017D08`），因此在 `static_fields` 中的偏移为 **0**。

### 2.2 证据二：`WorkDataManager.get_SingleMode` @ `0x3BEF274`

```asm
ldr x0,[x0,#0x58]
ret
```

→ `<SingleMode>k__BackingField`（token `0x04004102`）位于 **WorkDataManager + 0x58**。

同源相邻字段：`get_TrainedCharaData` = +0x50、`get_AutoPlayData` = +0x210、`get_IdleSingleModeData` = +0x218。

### 2.3 证据三：`WorkDataManager..ctor` 内的对象创建 @ `0x3BEF8A0`

```asm
0x3bef8a0  adrp x8,0x7682000
0x3bef8a4  ldr  x8,[x8,#3776]     ; 0x7682EC0  元数据槽
0x3bef8a8  ldr  x0,[x8,#0]
0x3bef8ac  bl   0x163797c         ; 对象创建入口
0x3bef8b0  mov  x1,sp
0x3bef8b4  mov  x20,x0
0x3bef8b8  bl   0x38a5668         ; WorkSingleModeData..ctor  ★
0x3bef8bc  str  x20,[x19,#88]     ; WorkDataManager + 0x58 = <SingleMode>  ★
```

相邻 `str [x19,#72]`(+0x48)、`#80`(+0x50)、`#88`(+0x58)、`#96`(+0x60) 与 getter 表完全吻合。

### 2.4 证据四：36 个 `get_IsPlaying` 调用点模式统一

```
adrp xN,<page>; ldr xN,[xN,#200]; ldr x0,[xN,#0]
bl   0x14bd694          ; Singleton<WorkDataManager>.get_Instance
cbz  w0,...
ldr  x0,[x0,#88]        ; +0x58 → WorkSingleModeData
cbz  w0,...
bl   0x3895f48          ; get_IsPlaying
```

---

## 3. `WorkSingleModeData` 完整字段偏移表（61 字段）

基址 = WorkSingleModeData 实例指针。`大小` 来自 getter/setter 的访存宽度；`证据` 列出实测的读写方法。

| # | 字段 | 偏移 | 大小 | 证据方法 |
|---:|---|---|---:|---|
| 0 | PLAY_TIMING_TYPE_NUM | — | — | static const，无实例槽 |
| 1 | `_storyInfoListDic` | 0x010 | 8 | .ctor / Apply / ClearAllPlayingData / GetFinalTurn |
| 2 | `_isExistPlayingData` | 0x018 | 1 | get_/SetIsExistPlayingData |
| 3 | `_isPlaying` | 0x019 | 1 | get_/set_IsPlaying |
| 4 | `_totalTurnNum` | 0x02C | 4 | .ctor / ApplyTurnNum / GetCurrentTurn / ClearAllPlayingData |
| 5 | `<Character>k__BackingField` | 0x030 | 8 | get_/set_Character |
| 6 | `_raceConditions` | 0x038 | 8 | .ctor / Apply / GetCurrentMasterTurn |
| 7 | `_homeInfo` | 0x040 | 8 | .ctor / Apply / ApplyArcDataSet / ApplyCommandResponse |
| 8 | `_addMusicId` | 0x058 | 4 | get_AddMusicId / ClearAddMusicId |
| 9 | `_state` | 0x05C | 8 | get_State / SetState |
| 10 | `_playingState` | 0x070 | 8 | get_PlayingState |
| 11 | `_scenarioIdList` | 0x088 | 8 | .ctor（str x?, [x19,#0x88]） |
| 12 | `_difficultyInfoList` | 0x090 | 8 | .ctor / get_DifficultyInfoList / ApplyDifficultyInfo |
| 13 | `_changeParameterInfo` | 0x098 | 8 | .ctor / Apply / ApplyCharacterChangeParam |
| 14 | `_raceHistoryInfoList` | 0x0A0 | 8 | .ctor / GetCountableRaceHistoryInfoList / GetDegreeType |
| 15 | `<WinSaddleArray>k__BackingField` | 0x0A8 | 8 | get_/set_WinSaddleArray / get_WinCount |
| 16 | `GroupLogPool` | 0x0B0 | 8 | .ctor / ClearGroupLog / CompleteAdditiveSystemLog |
| 17 | LOG_INFO_MAX | — | — | static const，无实例槽 |
| 18 | `_isStepTurn` | 0x0B8 | 8 | get_/set_IsStepTurn |
| 19 | `<IsStepTurnByStory>k__BackingField` | 0x0C4 | 8 | get_/set_IsStepTurnByStory |
| 20 | `<IsDisplayedRouteClear>k__BackingField` | 0x0D0 | 8 | get_/set_IsDisplayedRouteClear |
| 21 | `<IsForceChangeViewMonthStartView>k__BackingField` | 0x0DC | 8 | get_/set_ |
| 22 | `<SelectedTrainingCommandId>k__BackingField` | 0x0F8 | 4 | get_/set_SelectedTrainingCommandId |
| 23 | `<RentalCount>k__BackingField` | 0x10C | 4 | get_/set_RentalCount |
| 24 | `_prevFreeRentalTime` | 0x130 | 8 | get_IsEnableFreeRental / UpdateFreeRentalTime |
| 25 | `_successionEventInfo` | 0x138 | 8 | get_SuccessionEventInfoData |
| 26 | `<RaceStartResultInfoData>k__BackingField` | 0x140 | 8 | .ctor / get_ / ApplyArcDataSet / IsAbroadTurn |
| 27 | `RacePieceCampaignInfoList` | 0x148 | 8 | .ctor / IsLimitApplyedRacePieceCampaign |
| 28 | `StoryEventBonusDict` | 0x150 | 8 | .ctor / get_StoryEventTotalBonus / UpdateStoryEventBonus |
| 29 | `<ResumeFactorSelect>k__BackingField` | 0x158 | 8 | get_/set_ResumeFactorSelect |
| 30 | `<SkillUpgradeFactorSelect>k__BackingField` | 0x160 | 8 | get_/set_SkillUpgradeFactorSelect |
| 31 | `_fixedTurnCharaSeed` | 0x168 | 8 | get_FixedTurnCharaSeed / GetDressColorIdFixedTurn |
| 32 | `_raceRewardLimitMoreInfoList` | 0x180 | 8 | .ctor / get_RaceRewardLimitMoreInfoList |
| 33 | `EventChoiceRewardDict` | 0x188 | 8 | .ctor / ApplyEventChoiceRewardData / ClearEventChoiceRewardData |
| 34 | `_cachedRewardEventId` | 0x190 | 4 | HasEventChoiceRewardInfoCache / Apply / Clear |
| 35 | `_defaultRunningStyleArray` | 0x198 | 8 | .ctor / get_DefaultRunningStyleArray / GetCardRunningStyle |
| 36 | `<IsUmaplan>k__BackingField` | 0x1A0 | 8 | get_/set_IsUmaplan |
| 37 | `_logAdditiveBuffer` | 0x1B0 | 8 | .ctor / AdditiveSystemLog / ClearLog / CompleteAdditiveSystemLog |
| 38 | `<SkillFilterSetting>k__BackingField` | 0x1B8 | 8 | .ctor / get_SkillFilterSetting |
| 39 | `_autoPlayCustomPlanArray` | 0x1C0 | 8 | get_AutoPlayCustomPlanArray / ApplyAutoPlayCustomPlanData |
| 40 | `_autoPlaySelectedPlanId` | 0x1C8 | 8 | get_/set_AutoPlaySelectedPlanId（内部 int 在 0x1D8） |
| 41 | `<AutoPlaySelectScenario>k__BackingField` | 0x1DC | 8 | get_/set_AutoPlaySelectScenario |
| 42 | `<AutoPlayModifyPreferenceSkillIds>` | 0x1F0 | 8 | get_/set_ |
| 43 | `<AutoPlayModifyPreferenceFactorGroups>` | 0x1F8 | 8 | get_/set_ |
| 44 | `<AutoPlayModifyPreferenceBlueFactorGroups>` | 0x200 | 8 | get_/set_ |
| 45 | `<AutoPlayEventOption>k__BackingField` | 0x208 | 8 | get_/set_ |
| 46 | `<AutoPlayRaceContinue>k__BackingField` | 0x21C | 8 | get_/set_ |
| 47 | `<AutoPlayFactorContinue>k__BackingField` | 0x228 | 8 | get_/set_ |
| 48 | `<AutoPlayFatnessFactorContinue>k__BackingField` | 0x234 | 8 | get_/set_ |
| 49 | `<AutoPlayModifyPreferenceSuccessionForemost>` | 0x240 | 8 | get_/set_ |
| 50 | `<AutoPlayModifyPreferenceSuccessionSecondary>` | 0x248 | 8 | get_/set_ |
| 51 | `<AutoPlayModifyPreferenceSuccessionBorrow>` | 0x250 | 8 | get_/set_ |
| 52 | `<AutoPlaySuccessionRental>k__BackingField` | 0x258 | 8 | get_/set_ |
| 53 | `<AutoPlayFitnessContinue>k__BackingField` | 0x264 | 8 | get_/set_ |
| 54 | `<AutoPlayAutoTimes>k__BackingField` | 0x280 | 4 | get_/set_AutoPlayAutoTimes |
| 55 | `<AutoPlaySupportCardOption>k__BackingField` | 0x284 | 8 | get_/set_ |
| 56 | `<AutoPlayJustFullSupportCard>k__BackingField` | 0x298 | 8 | get_/set_ |
| 57 | `<AutoPlaySkillLearnPause>k__BackingField` | 0x2A4 | 8 | get_/set_ |
| 58 | `<AutoPlayVenusModifyPreference>k__BackingField` | 0x2C0 | 4 | get_/set_ |
| 59 | `<AutoPlayVenusModifyFragmentAttributes>` | 0x2C8 | 8 | get_/set_ |
| 60 | `<AutoPlayVenusUseDirectSpirit>` | 0x2D0 | 8 | get_/set_ |

**辅助偏移**（struct 属性内部字段，非独立 metadata 字段）：
`0x024`(int, master turn 相关)、`0x048`、`0x050`、`0x060`、`0x068`、`0x06C`、`0x080`、`0x0C0`、`0x0CC`、`0x0D8`、`0x0E0`、`0x0E4`、`0x110`、`0x178`、`0x1A8`、`0x1E8`、`0x218`、`0x224`、`0x230`、`0x23C`、`0x260`、`0x26C`、`0x278`、`0x294`、`0x2A0`、`0x2AC`、`0x2D8`。

---

## 4. `WorkDataManager` 字段槽表（68 项）

`WorkDataManager`（idx=8603, token=0x02000984）共 66 个 backing field + 67 个方法，全部为 `get_*` 与 `.ctor`（**没有 `set_SingleMode`**，外部只能读）。

`..ctor` @ `0x3BEF43C`（945 条指令）内的 `adrp → ldr → ldr → bl(object_new) → bl(ctor) → str [x19,#off]` 模式，一次性提取出 68 组「字段偏移 / 类元数据槽 / 构造函数」：

| 偏移 | 元数据槽（.got） | 构造函数 | 偏移 | 元数据槽（.got） | 构造函数 |
|---:|---|---|---:|---|---|
| 0x010 | 0x075B7B58 | 0x04C578C0 | 0x118 | 0x07691FA0 | 0x04785A44 |
| 0x018 | 0x07662C80 | 0x03BEFFE4 | 0x120 | 0x0767CBE8 | 0x03C3E554 |
| 0x020 | 0x07607950 | 0x047839E0 | 0x128 | — | 0x04514070 |
| 0x028 | 0x075E9548 | 0x03C3FB34 | 0x130 | 0x076551A8 | 0x048A2808 |
| 0x030 | 0x075F8830 | 0x04788AD8 | 0x138 | 0x075D6678 | 0x04784F48 |
| 0x038 | 0x075F32B0 | 0x03BF0094 | 0x140 | 0x075DE7C8 | 0x03BF0438 |
| 0x040 | 0x07644940 | 0x04514858 | 0x148 | 0x075CB688 | 0x03C41930 |
| 0x048 | 0x0768C548 | 0x0450B4C0 | 0x150 | 0x075B9BE0 | 0x0489F3CC |
| 0x050 | 0x07664F58 | 0x04C4F200 | 0x158 | 0x07691F50 | 0x04C543A4 |
| **0x058** | **0x07682EC0** | **0x038A5668** | 0x160 | 0x075C8418 | 0x04C54BF4 |
| 0x060 | 0x07660B18 | 0x04514E9C | 0x168 | 0x07660408 | 0x0451BA98 |
| 0x068 | 0x076205F8 | 0x0450FB20 | 0x170 | 0x076A79C8 | 0x0450CEA4 |
| 0x070 | 0x07606FE0 | 0x04789C7C | 0x178 | 0x075F82B0 | 0x04C5A0B4 |
| 0x078 | 0x075E4390 | 0x03BF014C | 0x180 | 0x075E33B0 | 0x0477CA14 |
| 0x080 | 0x0760D188 | 0x0451750C | 0x188 | 0x0767A1A8 | 0x04781320 |
| 0x088 | 0x07609350 | 0x04514070 | 0x190 | 0x075D9D00 | 0x0477D914 |
| 0x090 | 0x076C1550 | 0x0478D6BC | 0x198 | 0x07661358 | 0x04C50748 |
| 0x098 | 0x076317B0 | 0x03BEA95C | 0x1A0 | 0x075A8750 | 0x03BF05B0 |
| 0x0A0 | 0x07611EC0 | 0x04C55AB8 | 0x1A8 | 0x07616608 | 0x03BF0628 |
| 0x0A8 | 0x0762F780 | 0x03BF0308 | 0x1B0 | 0x07628420 | 0x03C47714 |
| 0x0B0 | 0x07691720 | 0x04508308 | 0x1B8 | 0x07636EF8 | 0x04520970 |
| 0x0B8 | 0x07680850 | 0x0450E8C4 | 0x1C0 | 0x075FC7E0 | 0x03BEDF1C |
| 0x0C0 | 0x0760B6A0 | 0x04779DB0 | 0x1C8 | 0x07620A98 | 0x04512854 |
| 0x0C8 | 0x0762F4B0 | 0x04C4E0E0 | 0x1D0 | — | 0x028F4BE4 |
| 0x0D0 | 0x076B3710 | 0x03BF03C0 | 0x1D8 | 0x075B2A38 | 0x04517A30 |
| 0x0D8 | 0x075CD890 | 0x048A38EC | 0x1E0 | 0x075D4458 | 0x04514E94 |
| 0x0E0 | 0x076B85B8 | 0x03C40C40 | 0x1E8 | 0x07632070 | 0x0451C020 |
| 0x0E8 | 0x07618418 | 0x0451D444 | 0x1F0 | 0x0763C7B8 | 0x04C570D8 |
| 0x0F0 | 0x075D9328 | 0x03BEF148 | 0x1F8 | 0x07685150 | 0x03BF0A68 |
| 0x0F8 | 0x075E19E8 | 0x04509484 | 0x200 | 0x07610C78 | 0x04516750 |
| 0x100 | 0x07640440 | 0x0450E05C | 0x208 | 0x075B85A8 | 0x04C5247C |
| 0x108 | 0x07664628 | 0x047792BC | 0x210 | 0x075E05A8 | 0x048A60F8 |
| 0x110 | 0x076BE3F0 | 0x0450D1D8 | 0x218 | 0x076A7DD0 | 0x0450A044 |

> 全部槽落在 `.got`（`0x75A58A8 – 0x76C9410`），该区间实测为纯指针表（1023/1024 项为 `0x07xxxxxx` 段内地址）。`0x128`、`0x1D0` 两项不是 new-object 模式（无元数据槽），属其他赋值路径。
>
> **注意**：`0x07682EC0` 槽内指向 `0x07B36B78`，该地址是 **Il2CppType 数组**（每 8 字节一项，索引步进），不是 `Il2CppClass` 本体。它是 `il2cpp_codegen_initialize_method` 一类的元数据入口，不能直接当 klass 指针解引用。

---

## 5. 内存扫描方案

### 5.1 方案 A：单例链（推荐，稳定性最高）

```c
// 1) 定位 WorkDataManager 的 Il2CppClass
//    方式一：il2cpp_class_from_name(image, "Gallop", "WorkDataManager")
//    方式二：扫 .rodata/metadata string 找 "WorkDataManager"，再扫内存找
//            Il2CppClass 结构里 +0x10 (name) == 该字符串地址 的对象
Il2CppClass* k = find_class("Gallop", "WorkDataManager");

// 2) 取静态字段区
void* static_fields = *(void**)((char*)k + 0xB8);

// 3) Singleton<T>._instance 是唯一静态字段，偏移 0
void* workDataManager = *(void**)static_fields;

// 4) 育成数据
void* singleMode = *(void**)((char*)workDataManager + 0x58);

// 5) 读状态
uint8_t isPlaying   = *(uint8_t*)((char*)singleMode + 0x19);
int32_t totalTurn   = *(int32_t*)((char*)singleMode + 0x2C);
```

### 5.2 方案 B：堆扫描（不依赖单例，适合注入早期）

```c
// 1) 拿到 WorkSingleModeData 的 Il2CppClass（同上 find_class）
// 2) 扫堆，找首字段 == 该 klass 的对象（IL2CPP 对象头即 klass 指针）
for (addr in heap_ranges) {
    if (*(void**)addr == klass_WorkSingleModeData) {
        // addr 就是 WorkSingleModeData 实例起点
    }
}
```

### 5.3 校验位

| 检查项 | 期望 |
|---|---|
| `singleMode + 0x19` | 0 或 1（isPlaying，1 字节） |
| `singleMode + 0x2C` | 0 ≤ n ≤ 数百（totalTurnNum） |
| `singleMode + 0x30` | 可解引用的 Character 对象指针 |
| `singleMode + 0x58` | 0 或有效 int32（addMusicId） |
| `singleMode + 0x1A0` | 0 或 1（isUmaplan） |

命中 3 项以上即可确认命中。

---

## 6. 未决项

1. **`0x07682EC0` 槽的精确语义**：槽内 → `0x07B36B78`（Il2CppType 数组基址），`ldr x0,[x8,#0]` 取数组首项后送入 `0x163797C`（`b 0x15D0100` 的 thunk）。该槽可作为「WorkSingleModeData 类型元数据」的定位入口，但不是 `Il2CppClass*` 直指。需要在 IDA 里跟 `0x15D0100` 确认它是否为 `il2cpp_codegen_initialize_method`。
2. **`0x024` / `0x048` / `0x080` / `0x110` / `0x178` / `0x1E8` 等辅助偏移**：均为 struct 属性内部字段或编译器对齐空隙，metadata 中无独立字段名，用途待按调用方语义命名。
3. **`_autoPlaySelectedPlanId`（0x1C8）与 0x1D8**：getter 同时访问两者，推断 0x1C8 为 8 字节容器、0x1D8 为其内部 int32，需运行期验证。

---

## 7. 复现

```bash
# 1) 解 metadata（需已修复的 typeDefinition 排序）
python3 meta.py                 # 生成 types.tsv / fields / methods 视图

# 2) 反汇编（ARM64 手写解码器，含 adrp immlo 修正）
python3 dis.py                  # trace_this() 跟踪 x0 搬运链

# 3) 提取
python3 extract.py --class Gallop.WorkSingleModeData --max-window 400
python3 extract.py --ctor 0x3BEF43C --pattern new-object
```

**关键坑位**（后续复用必读）：

1. `adrp` 的 imm 是 **`(immhi<<2) | immlo`**，`immlo` 在 `bits[30:29]`。漏掉 `immlo` 会让所有槽地址落到代码段，看起来像"槽里存的是 ARM64 指令"。
2. `ldr x19,[x19,#off]` 之后必须把 x19 移出 this 集合，否则链式访问全被误记为直接字段（实测噪声从 246 个偏移降到 97 个）。
3. 属性 getter 若带 metadata 初始化包装器（`adrp/ldrb/mov/movz/bl il2cpp_codegen_initialize_runtime_metadata`），真实字段访问在 300 条指令之后，扫描窗口需 ≥ 400。
4. `fieldDefinition.typeIndex` 是 **Il2CppType 索引**（实测可达 77372），不能拿去查 typeDefinitions 表。
5. `methods_rva.tsv` 的键是 **method 全局索引（abs_idx）**，不是 token。

---

*生成日期：2026-11-11 · 数据源：国服 libil2cpp（XOR 0x97 全量解密，49,129/49,143 方法可反汇编）+ global-metadata.dat（修复后 254,055 字段全对）*
