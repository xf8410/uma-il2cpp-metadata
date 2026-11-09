# 赛马娘 IL2CPP 元数据仓

放的是游戏的 **global-metadata.dat**——Unity 打包后留下的「符号表」。

## 一句话解释这文件是干什么的

Unity 把游戏代码编译成机器码之后，类名、方法名、字段名这些东西不会留在机器码里，而是单独抽出来存进 `global-metadata.dat`。
所以你想知道「这个方法叫什么、属于哪个类、参数是什么」，只能查这个文件。

逆向工具（Il2CppDumper、hachimi、各类 mod 加载器）全靠它把机器码地址翻译回人类能看懂的符号。

## 为什么叫 `.fixed`

原版这个文件被加固过——头部字段被改坏了，直接丢给工具会报「invalid metadata」。
`.fixed` 版是把头部修回正常值的版本，工具能正常读。

**修的是头部，不是内容。** 段数据一个字节没动。

## 当前收录

| 目录 | 文件 | 大小 | md5 | metadata 版本 |
|---|---|---|---|---|
| `metadata-20261110/` | `global-metadata.fixed.dat` | 32,248,932 B | `04f80ea24734afd6bfff982ee3040765` | 27 |

版本 27 对应 Unity 2021.3 / 2022 LTS。

## 怎么用

```bash
# Il2CppDumper 标准用法
Il2CppDumper <libil2cpp.so> <global-metadata.dat> <输出目录>
```

两个文件必须**同一次游戏版本**。配错版本会解析出乱七八糟的符号，比没有还糟。

对应的 so 在另一个仓：`xf8410/uma-ref-hub` 的 `raw/so-20261106/`。

## 目录约定

每次游戏大更新，元数据都会变。新版本按日期开新目录，**老版本不删**——排查历史问题时要能对照。

```
metadata-YYYYMMDD/
  global-metadata.fixed.dat
  说明.md          # 该版本的实测信息：大小、md5、各段偏移、来源
```

## 注意

游戏资源，**仓库私有**。别外传。
