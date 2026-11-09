# 赛马娘 IL2CPP 逆向基础文件

这个仓放两样东西：**`global-metadata.dat`（符号表）** 和 **`libil2cpp.so`（代码本体）**。

两个必须配对。少一个，逆向工具都跑不起来。

## 这两个文件是干什么的

Unity 打包游戏时，C# 代码被编译成机器码塞进 `libil2cpp.so`，但类名、方法名、字段名这些「人类能看懂的东西」不会留在机器码里——它们被单独抽出来存进 `global-metadata.dat`。

所以：

- `libil2cpp.so` = **代码**，一堆地址和指令
- `global-metadata.dat` = **名字**，告诉工具「0x12345 这个位置是 `MasterData.GetCard()`」

逆向工具（Il2CppDumper、hachimi、各种 mod 加载器）全靠这两个配合，才能把地址翻译回人类能看懂的符号。

## 当前收录

| 目录 | 内容 | 大小 | 说明 |
|---|---|---|---|
| `metadata-20261110/` | `global-metadata.fixed.dat` | 32,248,932 B | metadata 版本 27 |
| `libil2cpp-20261110/` | `libil2cpp.so.gz` | 38,612,513 B | 解压后 129,667,848 B，ARM aarch64 |

**这两个是同一次游戏版本，配套使用。**

## 为什么 metadata 叫 `.fixed`

原版这个文件被加固过——头部字段被改坏了，直接丢给工具会报「invalid metadata」。
`.fixed` 版是把头部修回正常值的版本，工具能正常读。

**修的是头部，不是内容。** 段数据一个字节没动。

## 为什么 so 存成 `.gz`

**GitHub 单文件上限 100 MB，解压后 123.66 MiB 超了。** 推不上去，所以原样保留 gz。

## 怎么用

```bash
# 1. 解压 so
gzip -dc libil2cpp-20261110/libil2cpp.so.gz > libil2cpp.so
md5sum libil2cpp.so
# 期望 3f9909afaa1a415840d690d9f69ea7de

# 2. 跑 dump
Il2CppDumper libil2cpp.so metadata-20261110/global-metadata.fixed.dat ./output
```

跑完 `output/` 里会有：

- `dump.cs` —— 所有类和方法签名，用编辑器打开就能搜
- `script.json` —— 给 IDA / Ghidra 用的符号脚本
- `stringliteral.json` —— 所有字符串字面量及其地址

## 第一次用必须做的验证

**这两个文件是不是真配对，只有一个办法能确认：实际跑一遍 dump。**

跑通了、`dump.cs` 内容完整、没有大量「method not found」警告 —— 才算配对成功。

配错版本的表现是：dump 能跑完但符号乱七八糟，或者中途报错退出。**别在没验证的情况下直接拿去改代码。**

## 目录约定

每次游戏大更新，这两个文件都会变。新版本按日期开新目录，**老版本不删**——排查历史问题时要能对照。

```
metadata-YYYYMMDD/
  global-metadata.fixed.dat
  说明.md          # 该版本实测信息：大小、md5、各段偏移
libil2cpp-YYYYMMDD/
  libil2cpp.so.gz
  说明.md          # 该版本实测信息：大小、md5、架构、段布局
```

## 注意

游戏资源，**仓库私有**。别外传。
