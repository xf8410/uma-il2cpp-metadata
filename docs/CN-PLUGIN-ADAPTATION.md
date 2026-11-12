# 国服 SO 插件适配蓝图（日服 libhachimi_ura → 国服 2.0.5）

> 生成：2026-11-12 　依据：festa 仓 `so/hachimi_ura_plugin/src/lib.rs`（26,451 行）× 本仓
> `metadata-20261110/dump/`（国服修复版符号表）全量核对。
> 结论先行：**核心数据链全通，无需碰 hachimi 框架；数据层按国服 2022 年老结构重写训练读取路径；
> 剧本代码砍到国服已开的 7 个；12 处日服包名硬编码要换。**

---

## 一、国服客户端画像（适配的前提）

| 项 | 国服 2.0.5 | 日服（festa 主线） |
|---|---|---|
| 剧本 | **7 个**：URA(1)/TeamRace(2)/Live(3)/Free(4)/Venus(5)/Arc(6)/Sport(7) | 15 个（到祭典杯） |
| 进度锚 | ≈ 日服 2022 年初结构（Sport 杯后、Cook 杯前） | 日服 2026（686+） |
| 训练数据 | **老结构**：`WorkSingleModeHomeInfo` + `SingleModeCommandInfo`（纯字段 DTO） | 新结构：`WorkSingleModeHomeInfoData` + 服务化（`SingleModeTrainingCommandService` 等） |
| ObscuredInt | ✅ 有（`CodeStage.AntiCheat.ObscuredTypes.ObscuredInt`，与日服同款） | 有 |
| metadata | v27（修复版已产出） | v31 |
| Unity | 2020.3.49f1 | 2022 |

## 二、符号核对结果（逐项实测）

### 2.1 类：核心 12 个全在，缺的 11 个全是「国服没开的剧本」

✅ **可用（find_class 直达）**：`Gallop.WorkDataManager` / `WorkSingleModeData` / `WorkSingleModeCharaData` / `StoryManager` / `StoryChoiceController`
✅ **可用（short_name）**：`Evaluation` / `TrainedCharaData` / `WorkTrainedCharaData` / `SingleModeMainTrainingCuttController` / `SuccessionCharaInfo`（国服无命名空间版） / `Enum`

✗ **国服缺失（正常，国服没开）**：`WorkSingleModeScenarioRamen(+DataSet)`（拉面14）、`ObscuredSingleModeBreeders*` ×3（种马13）、`SingleModeSkillLearningModel`（后期重构）、`WorkSingleModeHomeInfoData`（新结构名）、`SingleModeSkillData` / `SingleModeTrainingCommandService` / `SingleModeTrainingFailureRateService`（服务化重构产物）、`SingleModeWinsSaddle`（国服无 Gallop 命名空间版，有裸名 `SingleModeWinsSaddle`——**改用 short_name 解析即可**）

### 2.2 方法：83/178 直达，缺的 95 个全是剧本 getter / 服务化方法

关键缺失模式（全部**不用找替代，直接删对应代码**）：
- `get_Ramen` / `get_ScenarioRamen` / `get_WorkScenarioRamen`（拉面，国服无）
- `get_ScenarioBreeders` / `get_WorkScenarioBreeders` / Breeders 系全部（种马，国服无）
- `get_Cook` / `get_Mecha` / `get_Legend` / `get_Onsen` / `get_Pioneer`（剧本 8-12，国服无）
- `get_CommandInfoArray` / `get_TrainingExecInfoArray` / `get_TrainingLevelInfoArray` / `get_ParamsIncDecInfoArray`（**新结构训练读法——国服走老路径，见 §三**）
- `get_HintGain` / `get_NeedSkillPoint` 系（日服后期服务）

**国服自己就有、日服插件同名在用的**：`FixedTurnCharaSeed`（✅ 国服 `WorkSingleModeData.get_FixedTurnCharaSeed` 在）、`get_ScenarioId` / `get_Month` / `get_Half` / `get_Character` / `get_HomeInfo` / `get_SelectedTrainingCommandId`

## 三、训练数据新路径（与日服差异最大的一块）

```
日服（festa 现行）:
  WorkSingleModeData.get_HomeInfoData() → WorkSingleModeHomeInfoData
    .get_CommandInfoArray() → 训练命令[]（属性 getter 一步到位）

国服（老结构，msgpack DTO 纯字段）:
  WorkSingleModeData.get_HomeInfo() → WorkSingleModeHomeInfo
    .GetTrainingCommandTurnInfos()   ← 方法调用（非属性）
    或 .get_TurnInfoListDic()
  SingleModeHomeInfo.command_info_array → SingleModeCommandInfo[]
    字段（7 个）:
      command_type / command_id / is_enable /
      training_partner_array / tips_event_partner_array /
      params_inc_dec_info_array   ← 5维增量+SP+体力消耗全在这（ParamsIncDecInfo[]）
      failure_rate
```

重写要点：
1. `params_inc_dec_info_array` 每项是 `ParamsIncDecInfo`（类型枚举+增量值）——拆包成 5 维增益 + skill_pt + vital_cost，字段语义对齐日服 `/summary` 的 trainings 块
2. `training_partner_array` 对齐 partners（人头数）
3. DTO 是**字段不是属性**——读取用 il2cpp field offset（vtable 的 `il2cpp_get_field_offset` 类接口），不是 call_getter

## 四、支援卡 / 技能 / 五维（核对通过，改法）

| /summary 块 | 国服来源（WorkSingleModeCharaData） | 备注 |
|---|---|---|
| stats 五维+上限 | `get_Speed/Stamina/Power/Guts/Wiz` + `get_Max*` + `get_DefaultMax*` | 直读 ✓ |
| vital | `get_Hp` / `get_MaxHp` | 日服叫 Vital 国服叫 Hp，**映射改名** |
| motivation | `get_Motivation` | ✓ |
| skill_point / fan | `get_SkillPoint` / `get_FanCount` | ✓ |
| proper 适性 10 项 | `get_ProperDistance*` ×4 / `get_ProperGround*` ×2 / `get_ProperRunningStyle*` ×4 | 全 ✓ |
| max_stats | `get_Max*`（国服直接有 Max getter，比日服还省事） | ✓ |
| skills | `get_AcquiredSkillList` / `get_SkillTipsList` / `get_EvaluationList` | ✓ |
| buffs | `get_CharaEffectIdArray` | ✓ |
| support_cards | `get_EquipSupportCardArray` + `get_CardData/get_CardId` | ✓ |
| scenario 进度 | `get_ScenarioProgress` / `get_ScenarioId` + 剧本子对象 7 个 | 保留 7 剧本分支 |

## 五、代码改造点位清单（按文件位置）

| # | 位置（lib.rs） | 改法 |
|---|---|---|
| 1 | 12 处 `/sdcard/Android/media/jp.co.cygames.umamusume/...` 与 `/data/data/jp.co.cygames.umamusume/...` | 换 `com.bilibili.umamusume`；建议改成常量 `PKG`（一处定义） |
| 2 | phase2 训练读取（HomeInfoData 路径） | 按 §三 重写（field offset + DTO 数组遍历） |
| 3 | Ramen/Breeders/festa 剧本分支（`WorkSingleModeScenarioRamen*`、`sid==13/14/15` 分支） | 整段删除或 `#[cfg]` 关掉，留 7 剧本 |
| 4 | `scenario_id → 名称` 映射表 | 砍到 1-7 |
| 5 | `SingleModeTrainingCommandService/FailureRateService` 引用 | 删（国服训练命令里直接有 failure_rate 字段） |
| 6 | `SingleModeWinsSaddle` | find_class → find_class_by_short_name |
| 7 | `hachimi_init_v3` 入口 / HTTP / push / config / ObscuredInt / GUI | **原样保留**（框架层国服通用） |
| 8 | `signup_plaintext.rs` / `auth_capture.rs` / `protocol_send_discovery.rs`（日服协议嗅探） | 国服 B 服登录协议不同——先关掉（#[cfg(feature="jp")]），后续单独适配 |

## 六、加载方案（无 root + 改签包的边界）

**改国服游戏 APK 的路已被实测判死**（HANDOVER §一：`lib/` 完整性校验 SIGKILL、dex 黑屏 fail-closed）。
「改签包」的正确形态是**改容器的包，不改游戏的包**：

```
BlackBox 容器 App（随便改签——是自己的 App）
  └─ System.load("/sdcard/Download/libhachimi.so")   ← 注入点已打补丁（BActivityThread）
      └─ Hachimi 框架（zygisk-hachimi2020 v0.14.0，Unity2020 兼容版）
          └─ 插件目录运行时加载 libhachimi_ura_cn.so   ← 本蓝图产物，不碰游戏 APK
              └─ vtable 按名字 resolve（国服符号表核对已过）
```

当前卡点（非技术死墙）：手机 PackageManager 状态乱 → **重启手机**后按 CONTAINER-PROGRESS §5 清单走：
装 `bb-hachimi-1111-0329.apk` → appops 两条 → 确认 `/sdcard/Download/libhachimi.so` → 启动看 `BB_INJECT` → 验证 Hachimi 悬浮窗 + TP 是否检测容器。

## 七、下一步（顺序）

1. 【用户】重启手机 → 容器路线验证（§六清单）——这是插件能不能跑的前提
2. 【AI】按 §五 改造 `hachimi_ura_plugin` → 产出 `libhachimi_ura_cn.so`（aarch64）
3. 【AI】构建流（国服版 Cargo feature `cn`）+ 符号 smoke 测试（加载即 dump 7 剧本类存在性）
4. 【联合】容器内实机验证 /summary 输出 → 对齐 festa App（NativeEngine 收 18766 不用动）
