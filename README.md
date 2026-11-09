# 赛马娘 IL2CPP 元数据仓

放的是游戏的 **global-metadata.dat**——Unity 打包后留下的「符号表」。

## 一句话解释这文件是干什么的

Unity 把游戏代码编译成机器码之后，类名、方法名、字段名这些东西不会留在机器码里，而是单独抽出来存进 `global-metadata.dat`。
所以你想知道「这个方法叫什么、属于哪个类、参数是什么」，只能查这个文件。

逆向工具（Il2CppDumper、hachimi、各类 mod 加载器）全靠它把机器码地址翻译回人类能看懂的符号。

## ⚠ 两点重要更正（实测，别按旧说法用）

### 1）修的不只是头部，段数据也动过

原版这个文件被加固过，**两处**：

- 头部 `sanity`/`version` 被改写（不是 `0xFAB11BAF`）；
- 文件按 64KB 分块，**每块内 `+0x1000 ~ +0x4FFF`（16KB）整段 XOR 0x66**，约 25% 的字节被翻过。

`.fixed` 版把这两处都还原了。所以「段数据一个字节没动」的说法不对——正相反，不还原那 25% 的字节，任何工具读出来都是乱的。

还原脚本：

```python
d = bytearray(open('global-metadata.dat','rb').read()); N = len(d)
for p in range(N // 4096 + 1):
    if p == 0 or (p % 16) in (1, 2, 3, 4):
        for i in range(p*4096, min(p*4096+4096, N)):
            d[i] ^= 0x66
d[0:4] = (0xFAB11BAF).to_bytes(4,'little')
d[4:8] = (27).to_bytes(4,'little')
```

已验证：最后一段 `0x1EC0470 + 0xFF4 = 0x1EC1464 = 32,248,932`，正好等于文件大小——段连续到文件尾，无空洞无截断。

### 2）标准 Il2CppDumper 会解错结构

这个 build 是 **Unity 2020.3.49f1**（不是 2021.3/2022；metadata v27 对应 2020.2+，
2021.3 是 v29、2022 是 v31），而且表结构是**自定义紧凑布局**：

| 表 | 本 build | 标准 v27 |
|---|---|---|
| typeDefinition | 88 B（`method_count`@+0x40、`field_count`@+0x44、token@+0x54） | 108 B |
| methodDefinition | 32 B（参数个数 = `dword@+0x1C >> 16`，打包在 iflags 高 16 位） | 40~56 B |
| fieldDefinition | 12 B | 12 B ✓ |

**所有 `*Start` 字段被删掉了**，起点靠 `field_count`/`method_count` 前缀和还原。
所以 `Il2CppDumper <so> <dat>` 能跑通但类型/方法/字段结构会对不上（名字能看、归属全乱）。
本仓的 `tools/parse_metadata.py` 就是按实测布局写的。

## 当前收录

| 目录 | 文件 | 大小 | md5 |
|---|---|---|---|
| `metadata-20261110/` | `global-metadata.fixed.dat` | 32,248,932 B | `04f80ea24734afd6bfff982ee3040765` |

## 自动解析（GitHub Actions）

推入/更新 `metadata-*/global-metadata.fixed.dat` 就会自动跑 `.github/workflows/dump.yml`：

1. `tools/parse_metadata.py --check` 自检（段连续到尾部、计数和 = 表行数、token 单调）→ `metadata-*/dump_check.txt`
2. 解析 → `metadata-*/dump/`

| 输出 | 行数 | 列 |
|---|---|---|
| `dump/types.tsv` | 32,080 | index / token / 全名 |
| `dump/methods.tsv` | 213,983 | 声明类型索引 / 方法名 / token / 参数个数 |
| `dump/fields.tsv` | 254,055 | 所属类型索引 / 字段名 / token |
| `dump/string_literals.txt` | 26,385 | 字符串字面量 |

本地跑：

```bash
python3 tools/parse_metadata.py metadata-20261110/global-metadata.fixed.dat --check
python3 tools/parse_metadata.py metadata-20261110/global-metadata.fixed.dat metadata-20261110/dump
```

已知损失：第 0 块 `0x1000~0x4FFF` 那 16KB 是另一套加密（非 0x66），
对应约 2016 条字面量拿不回来；类型/方法/字段全量完好。

## 版本配对

数据必须和 `libil2cpp.so` 来自**同一次游戏版本**。
对应 so 在 `xf8410/uma-ref-hub` 的 `raw/so-20261106/`，和本 metadata（11-10）差 4 天——
如果中间游戏更新过，符号会对不上，重配。

另：`libil2cpp.so` 本身也有加固——`.text` 只有 5MB，游戏代码在 71MB 的自定义 `il2cpp` 段里，
文件尾部（`.shstrtab` 之后约 467KB，不属于任何段）还有一块 ELF hook payload，
字符串含 `ELF_HOOK_LoadMetadataFile` / `ELF_HOOK_MetadataCache_Register`。
要拿代码地址（RVA）得先处理这块。

## 目录约定

每次游戏大更新，元数据都会变。新版本按日期开新目录，**老版本不删**——排查历史问题时要能对照。

```
metadata-YYYYMMDD/
  global-metadata.fixed.dat
  dump_check.txt   # 自动生成的自检结果
  dump/            # 自动生成的解析结果
  说明.md          # 该版本实测信息
```

## 注意

游戏资源，**仓库私有**。别外传。