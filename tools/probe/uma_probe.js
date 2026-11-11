/**
 * uma_probe.js —— 赛马娘国服 WorkSingleModeData 静态槽运行时验证探针
 *
 * 目标
 *   1. 用 IL2CPP 导出 API 完全动态地走一遍「类 → 静态字段 → 单例 → WorkSingleModeData」链路，
 *      不硬编码任何对象地址（只硬编码方法 RVA 用于打点）。
 *   2. 用 il2cpp_field_get_offset 反向自校验静态反汇编提取的 59 个实例字段偏移，
 *      一致即证明整张偏移表可信。
 *   3. 在唯一写入点 set_IsPlaying 与唯一读取点 get_IsPlaying 打点，
 *      记录 isPlaying 真实读写时序 + 每次变化时的完整状态快照。
 *
 * 用法
 *   frida -U -f <包名> -l uma_probe.js --no-pause
 *   frida -U -n <进程名> -l uma_probe.js
 *   附加后自动：模块定位 → 类解析 → 59 字段自校验 → 单例链解析 → 打点
 *   手动快照：Frida REPL 执行  rpc.exports.dump()
 *
 * 目标版本
 *   libil2cpp（解密后 dec.so 129,667,848 B）
 *   metadata v27 紧凑布局：typeDefinition=32080, methods=213983, fields=254055, images=73
 *   主程序集 umamusume.dll（typeStart=6168, typeCount=25910）
 *   WorkSingleModeData : idx=8972  token=0x02000AC2  field_count=61（含 2 个 static const）
 *   WorkDataManager    : idx=8603  token=0x02000984  field_count=66
 *
 * 静态分析文档：国服静态槽定位报告.md
 */
'use strict';

// ════════════════════════════════════════════════════════════════════════
// 一、59 个实例字段偏移（字段名逐字取自 metadata，已与反汇编交叉验证）
//     token 区间 0x04004661..0x0400469D，严格连续无缺口
//     另有 2 个 static const 不占实例偏移：PLAY_TIMING_TYPE_NUM(0x04004661)、LOG_INFO_MAX(0x04004672)
// ════════════════════════════════════════════════════════════════════════
const FIELDS = {
  '_storyInfoListDic':                                0x010,
  '_isExistPlayingData':                              0x018,
  '_isPlaying':                                       0x019,   // ★ 全库唯一读写点
  '_totalTurnNum':                                    0x02C,   // 修正：原候选 0x24
  '<Character>k__BackingField':                       0x030,   // get_Character = ldr x0,[x0,#48];ret ✓
  '_raceConditions':                                  0x038,
  '_homeInfo':                                        0x040,
  '_addMusicId':                                      0x058,
  '_state':                                           0x05C,
  '_playingState':                                    0x070,
  '_scenarioIdList':                                  0x088,   // 修正：原候选 0x80
  '_difficultyInfoList':                              0x090,
  '_changeParameterInfo':                             0x098,
  '_raceHistoryInfoList':                             0x0A0,
  '<WinSaddleArray>k__BackingField':                  0x0A8,
  'GroupLogPool':                                     0x0B0,   // 新增识别：原以为 static
  '_isStepTurn':                                      0x0B8,
  '<IsStepTurnByStory>k__BackingField':               0x0C4,
  '<IsDisplayedRouteClear>k__BackingField':           0x0D0,
  '<IsForceChangeViewMonthStartView>k__BackingField': 0x0DC,
  '<SelectedTrainingCommandId>k__BackingField':       0x0F8,
  '<RentalCount>k__BackingField':                     0x10C,
  '_prevFreeRentalTime':                              0x130,
  '_successionEventInfo':                             0x138,
  '<RaceStartResultInfoData>k__BackingField':         0x140,
  'RacePieceCampaignInfoList':                        0x148,
  'StoryEventBonusDict':                              0x150,
  '<ResumeFactorSelect>k__BackingField':              0x158,
  '<SkillUpgradeFactorSelect>k__BackingField':        0x160,
  '_fixedTurnCharaSeed':                              0x168,
  '_raceRewardLimitMoreInfoList':                     0x180,
  'EventChoiceRewardDict':                            0x188,
  '_cachedRewardEventId':                             0x190,   // 修正：原候选 0x178
  '_defaultRunningStyleArray':                        0x198,
  '<IsUmaplan>k__BackingField':                       0x1A0,
  '_logAdditiveBuffer':                               0x1B0,
  '<SkillFilterSetting>k__BackingField':              0x1B8,
  '_autoPlayCustomPlanArray':                         0x1C0,
  '_autoPlaySelectedPlanId':                          0x1C8,
  '<AutoPlaySelectScenario>k__BackingField':          0x1DC,
  '<AutoPlayModifyPreferenceSkillIds>k__BackingField':        0x1F0,
  '<AutoPlayModifyPreferenceFactorGroups>k__BackingField':    0x1F8,
  '<AutoPlayModifyPreferenceBlueFactorGroups>k__BackingField':0x200,
  '<AutoPlayEventOption>k__BackingField':             0x208,
  '<AutoPlayRaceContinue>k__BackingField':            0x21C,
  '<AutoPlayFactorContinue>k__BackingField':          0x228,
  '<AutoPlayFatnessFactorContinue>k__BackingField':   0x234,
  '<AutoPlayModifyPreferenceSuccessionForemost>k__BackingField':  0x240,
  '<AutoPlayModifyPreferenceSuccessionSecondary>k__BackingField': 0x248,
  '<AutoPlayModifyPreferenceSuccessionBorrow>k__BackingField':    0x250,
  '<AutoPlaySuccessionRental>k__BackingField':        0x258,
  '<AutoPlayFitnessContinue>k__BackingField':         0x264,
  '<AutoPlayAutoTimes>k__BackingField':               0x280,
  '<AutoPlaySupportCardOption>k__BackingField':       0x284,
  '<AutoPlayJustFullSupportCard>k__BackingField':     0x298,
  '<AutoPlaySkillLearnPause>k__BackingField':         0x2A4,
  '<AutoPlayVenusModifyPreference>k__BackingField':   0x2C0,
  '<AutoPlayVenusModifyFragmentAttributes>k__BackingField': 0x2C8,
  '<AutoPlayVenusUseDirectSpirit>k__BackingField':    0x2D0,
};

// static const（不占实例偏移，仅登记，供命名对照）
const STATIC_CONSTS = ['PLAY_TIMING_TYPE_NUM', 'LOG_INFO_MAX'];

// ════════════════════════════════════════════════════════════════════════
// 二、单例链常量（四条独立证据闭合）
//   Il2CppClass(WorkDataManager) + 0xB8 → static_fields
//   static_fields[0]                    → WorkDataManager 实例（Singleton<T> 基类的 _instance）
//   WorkDataManager + 0x58              → <SingleMode> WorkSingleModeData
//   WorkSingleModeData + 0x19 (byte)    → _isPlaying
// ════════════════════════════════════════════════════════════════════════
const CHAIN = {
  CLASS_STATIC_FIELDS: 0xB8,   // Il2CppClass::static_fields（0xC0 是 rgctx_data，别搞混）
  WDM_SINGLE_MODE:     0x58,   // WorkDataManager::<SingleMode>k__BackingField
  WSM_IS_PLAYING:      0x19,   // byte
  WSM_IS_EXIST:        0x18,   // byte
  WSM_TOTAL_TURN:      0x2C,   // int32
  WSM_STATE:           0x5C,   // int32（enum）
  WSM_PLAYING_STATE:   0x70,   // int32（enum）
  WSM_CHARACTER:       0x30,   // 引用
  WSM_SCENARIO_IDS:    0x88,   // List<int>
  WSM_DIFFICULTY:      0x90,   // List
  WSM_LOG_ADDITIVE:    0x1B0,  // List<string>
};

// ════════════════════════════════════════════════════════════════════════
// 三、方法 RVA（libil2cpp 文件虚拟地址，运行时 = module.base + RVA）
// ════════════════════════════════════════════════════════════════════════
const RVA = {
  set_IsPlaying:                0x3895FA0,  // 唯一写入点
  get_IsPlaying:                0x3895F48,  // 唯一读取点
  get_Character:                0x3896290,  // ldr x0,[x0,#48]; ret（验证锚点）
  Singleton_getInstance_shared: 0x14BD694,
  WorkSingleModeData_ctor:      0x38A5668,
  WorkDataManager_ctor:         0x3BEF43C,
};

// ════════════════════════════════════════════════════════════════════════
// 四、set_IsPlaying 的全部 5 个调用点（静态扫全库 bl，无遗漏）
//     2 处写 true，3 处写 false；全部经 Singleton<WorkDataManager>.get_Instance → +0x58
// ════════════════════════════════════════════════════════════════════════
const CALLERS = {
  0x4BF111C: { owner: 'Gallop.SingleModeChangeViewManager::StartSingleMode',  value: true,  desc: '开始育成' },
  0x4BF0930: { owner: 'Gallop.SingleModeChangeViewManager::GoSingleModeView', value: true,  desc: '跳转育成界面' },
  0x357502C: { owner: 'Gallop.SingleModeUtils::ClearPlayData',                value: false, desc: '清理游玩数据' },
  0x34D73F8: { owner: '<FinalizeView>d__19::MoveNext',                        value: false, desc: '结束界面协程' },
  0x3462FE0: { owner: '<EndView>d__65::MoveNext',                             value: false, desc: '退出界面协程' },
};

// ════════════════════════════════════════════════════════════════════════
// 五、基础设施
// ════════════════════════════════════════════════════════════════════════
const TAG = '[uma-probe]';
const log = (...a) => console.log(TAG, ...a);

function findIl2cppModule() {
  for (const n of ['libil2cpp.so', 'libunity.so', 'libmain.so', 'libGame.so']) {
    const m = Process.findModuleByName(n);
    if (m && m.findExportByName('il2cpp_domain_get')) return m;
  }
  for (const m of Process.enumerateModules()) {
    try { if (m.findExportByName('il2cpp_domain_get')) return m; } catch (e) {}
  }
  return null;
}

const MOD = findIl2cppModule();
if (!MOD) throw new Error('未找到含 il2cpp 导出的模块，请确认已注入游戏进程');
const BASE = MOD.base;
log('模块:', MOD.name, '基址:', BASE, '大小:', MOD.size);

function api(name) {
  const p = MOD.findExportByName(name) || Module.findExportByName(null, name);
  if (!p) throw new Error('缺少导出符号: ' + name);
  return p;
}

const IL = {
  domain_get:                  new NativeFunction(api('il2cpp_domain_get'), 'pointer', []),
  domain_get_assemblies:       new NativeFunction(api('il2cpp_domain_get_assemblies'), 'pointer', ['pointer', 'pointer']),
  assembly_get_image:          new NativeFunction(api('il2cpp_assembly_get_image'), 'pointer', ['pointer']),
  image_get_name:              new NativeFunction(api('il2cpp_image_get_name'), 'pointer', ['pointer']),
  class_from_name:             new NativeFunction(api('il2cpp_class_from_name'), 'pointer', ['pointer', 'pointer', 'pointer']),
  class_get_field_from_name:   new NativeFunction(api('il2cpp_class_get_field_from_name'), 'pointer', ['pointer', 'pointer']),
  field_get_offset:            new NativeFunction(api('il2cpp_field_get_offset'), 'int32', ['pointer']),
  class_get_static_field_data: new NativeFunction(api('il2cpp_class_get_static_field_data'), 'pointer', ['pointer']),
  thread_attach:               new NativeFunction(api('il2cpp_thread_attach'), 'pointer', ['pointer']),
};

// Il2CppString: +0x10 length(int32), +0x14 UTF-16 chars
function readCsString(p) {
  if (!p || p.isNull()) return null;
  try {
    const len = p.add(0x10).readS32();
    if (len <= 0 || len > 512) return null;
    return p.add(0x14).readUtf16String(len);
  } catch (e) { return null; }
}

function findClass(ns, name) {
  const domain = IL.domain_get();
  const sizePtr = Memory.alloc(8);
  const arr = IL.domain_get_assemblies(domain, sizePtr);
  const n = Number(sizePtr.readU64());
  const nsBuf = Memory.allocUtf8String(ns);
  const nmBuf = Memory.allocUtf8String(name);
  const hits = [];
  for (let i = 0; i < n; i++) {
    const asm = arr.add(i * 8).readPointer();
    if (asm.isNull()) continue;
    const img = IL.assembly_get_image(asm);
    if (img.isNull()) continue;
    const k = IL.class_from_name(img, nsBuf, nmBuf);
    if (!k.isNull()) hits.push({ klass: k, image: img, imageName: readCsString(IL.image_get_name(img)) });
  }
  return hits;
}

// ════════════════════════════════════════════════════════════════════════
// 六、59 字段偏移自校验
// ════════════════════════════════════════════════════════════════════════
function verifyOffsets() {
  log('══════ 59 实例字段偏移自校验 ══════');
  const hits = findClass('Gallop', 'WorkSingleModeData');
  if (hits.length === 0) { log('✗ 未找到 Gallop.WorkSingleModeData'); return null; }
  const { klass, imageName } = hits[0];
  log('命中类:', imageName, 'klass =', klass);

  let ok = 0; const mismatch = [], missing = [];
  const names = Object.keys(FIELDS);
  for (const nm of names) {
    const f = IL.class_get_field_from_name(klass, Memory.allocUtf8String(nm));
    if (f.isNull()) { missing.push(nm); continue; }
    const real = IL.field_get_offset(f);
    if (real === FIELDS[nm]) ok++;
    else mismatch.push({ name: nm, static: FIELDS[nm], runtime: real });
  }
  log(`一致 ${ok} / ${names.length}`);
  if (missing.length) { log(`✗ 运行时不存在 (${missing.length}):`); missing.forEach(n => log('    ' + n)); }
  if (mismatch.length) {
    log(`✗ 偏移不符 (${mismatch.length}):`);
    mismatch.forEach(m => log(`    ${m.name}  静态=0x${m.static.toString(16)}  运行时=0x${m.runtime.toString(16)}`));
  }
  if (ok === names.length) log('✓ 全表一致，静态反汇编提取的偏移完全可信');
  return { klass, ok, mismatch, missing };
}

// ════════════════════════════════════════════════════════════════════════
// 七、单例链
// ════════════════════════════════════════════════════════════════════════
function resolveSingleton() {
  log('══════ 单例链解析 ══════');
  const wdm = findClass('Gallop', 'WorkDataManager');
  if (wdm.length === 0) { log('✗ 未找到 Gallop.WorkDataManager'); return null; }
  const WDM = wdm[0].klass;
  log('WorkDataManager klass =', WDM, '(', wdm[0].imageName, ')');

  const sf = IL.class_get_static_field_data(WDM);
  log('static_fields 基址 =', sf);
  if (sf.isNull()) { log('✗ static_fields 为空（类未初始化）'); return null; }

  const inst = sf.readPointer();
  log('static_fields[0] (WorkDataManager 实例) =', inst);
  if (inst.isNull()) { log('✗ 实例为空，可能还没进过育成界面'); return null; }

  const wsm = inst.add(CHAIN.WDM_SINGLE_MODE).readPointer();
  log('WorkDataManager + 0x58 (<SingleMode>) =', wsm);
  if (wsm.isNull()) { log('✗ WorkSingleModeData 为空，可能还没进过育成界面'); return null; }

  const wsmHits = findClass('Gallop', 'WorkSingleModeData');
  if (wsmHits.length) {
    const objKlass = wsm.readPointer();
    log('WSM 对象头 klass =', objKlass, ' 期望 =', wsmHits[0].klass,
        objKlass.equals(wsmHits[0].klass) ? '✓ 匹配' : '✗ 不匹配');
  }
  return wsm;
}

// ════════════════════════════════════════════════════════════════════════
// 八、状态快照
// ════════════════════════════════════════════════════════════════════════
function dumpState(wsm, label) {
  if (!wsm || wsm.isNull()) { log(label || '', 'WSM = null'); return; }
  try {
    const isPlaying = wsm.add(CHAIN.WSM_IS_PLAYING).readU8();
    const isExist   = wsm.add(CHAIN.WSM_IS_EXIST).readU8();
    const turn      = wsm.add(CHAIN.WSM_TOTAL_TURN).readS32();
    const state     = wsm.add(CHAIN.WSM_STATE).readS32();
    const pstate    = wsm.add(CHAIN.WSM_PLAYING_STATE).readS32();
    const chara     = wsm.add(CHAIN.WSM_CHARACTER).readPointer();
    const scen      = wsm.add(CHAIN.WSM_SCENARIO_IDS).readPointer();
    const diff      = wsm.add(CHAIN.WSM_DIFFICULTY).readPointer();
    const logbuf    = wsm.add(CHAIN.WSM_LOG_ADDITIVE).readPointer();
    const size = (p) => { if (!p || p.isNull()) return '-'; try { return String(p.add(0x18).readS32()); } catch (e) { return '?'; } };
    log(`${label || '[state]'} isPlaying=${isPlaying} isExist=${isExist} turn=${turn} state=${state} playingState=${pstate}`);
    log(`         Character=${chara}  scenarioIds=${size(scen)}  difficulty=${size(diff)}  logBuffer=${size(logbuf)}`);
  } catch (e) { log(label || '', '读取异常:', e.message); }
}

// ════════════════════════════════════════════════════════════════════════
// 九、读写探针
// ════════════════════════════════════════════════════════════════════════
const hookCount = { set: 0, get: 0 };

function installHooks() {
  log('══════ 安装读写探针 ══════');
  const setAddr = BASE.add(RVA.set_IsPlaying);
  const getAddr = BASE.add(RVA.get_IsPlaying);

  Interceptor.attach(setAddr, {
    onEnter(args) {
      hookCount.set++;
      const self = args[0];
      const val = (args[1].toInt32() & 0xFF) !== 0;
      let callerRva = null, callerInfo = null;
      try {
        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        for (const a of bt) {
          const rva = a.sub(BASE).toUInt32();
          if (CALLERS[rva]) { callerRva = rva; callerInfo = CALLERS[rva]; break; }
        }
      } catch (e) {}
      const ci = callerInfo ? `[${callerInfo.desc}] ${callerInfo.owner}` : '(未知调用者)';
      log(`[SET #${hookCount.set}] isPlaying -> ${val}   this=${self}`);
      log(`       调用者: ${ci}${callerRva ? ' @RVA 0x' + callerRva.toString(16) : ''}`);
      dumpState(self, '       ');
    }
  });
  log('✓ set_IsPlaying 已挂 @', setAddr, `(RVA 0x${RVA.set_IsPlaying.toString(16)})`);

  Interceptor.attach(getAddr, {
    onLeave(retval) {
      hookCount.get++;
      if (hookCount.get <= 20 || hookCount.get % 500 === 0) {
        log(`[GET #${hookCount.get}] isPlaying = ${retval.toInt32() & 0xFF}`);
      }
    }
  });
  log('✓ get_IsPlaying 已挂 @', getAddr, `(RVA 0x${RVA.get_IsPlaying.toString(16)})`);
}

// ════════════════════════════════════════════════════════════════════════
// 十、手动接口
// ════════════════════════════════════════════════════════════════════════
rpc.exports = {
  dump() {
    const wsm = resolveSingleton();
    dumpState(wsm, '[manual]');
    log('统计: set', hookCount.set, '次, get', hookCount.get, '次');
    return { set: hookCount.set, get: hookCount.get };
  },
  verify() {
    const r = verifyOffsets();
    return r ? { ok: r.ok, total: Object.keys(FIELDS).length, mismatch: r.mismatch.length, missing: r.missing.length } : null;
  }
};

// ════════════════════════════════════════════════════════════════════════
// 十一、启动
// ════════════════════════════════════════════════════════════════════════
function boot() {
  log('════════ uma-probe 启动 ════════');
  log(`字段表 ${Object.keys(FIELDS).length} 项 | 调用点 ${Object.keys(CALLERS).length} 个 | 模块 ${MOD.name}`);
  verifyOffsets();
  const wsm = resolveSingleton();
  dumpState(wsm, '[初始]');
  installHooks();
  log('════════ 就绪，进育成界面观察输出 ════════');
  log('提示：Frida REPL 执行  rpc.exports.dump()  可随时手动快照');
}

setTimeout(() => {
  try { IL.thread_attach(IL.domain_get()); } catch (e) { log('thread_attach 跳过:', e.message); }
  try { boot(); } catch (e) { log('✗ 启动失败:', e.message, e.stack); }
}, 500);
