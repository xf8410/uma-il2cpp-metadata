# 更正：hook 壳没有被去掉，它藏在段间空隙里

> 起因：`so_check.txt` 旧版输出 `trailing data: 1540 B` + `tail markers: none`，
> 有人据此得出「文件尾部的 hook 壳被去掉了」。**这个结论是错的**，错在只看
> 「文件末尾到最后一个 section 之间」的字节。

## 事实（`so_check.txt` 新版实测，run 42712166115）

这份 `libil2cpp.so`（sha256 `19e68c4e…351aac3` 系同一份字节）里，
**不属于任何 section 的区间有 13 处，合计 96,234 B**，其中关键的一处是：

```
0x7B91D46 ~ 0x7BA4470   75,562 B
markers = ELF_HOOK_, stub_, MetadataCache, il2cpp_init
```

也就是说 hook payload 完整地留在这儿，具体位置：

| 区段 | 说明 |
|---|---|
| `0x7B91D46` | `.shstrtab` 结束（`.data` 也在这里结束） |
| `0x7B91D46 ~ 0x7BA4470` | **未被任何 section 覆盖的 75,562 B，hook payload** |
| `0x7BA4470` | `.dynamic` 起始 |
| `0x7BA4640` | `.hash` 起始（注意：`section 2` 被放到了文件末尾附近） |
| `0x7BA8D04` | `.hash` 结束 = 最后一个 section 的结束 |
| `0x7BA8D04 ~ 0x7BA9308` | 1540 B = 24×64 段头表(1536) + 4 B 对齐 |

`ELF_HOOK_BRIDGE_MetadataCache_Register` 在文件偏移 `129,634,009 = 0x7BA0ED9`，
正好落在这段空隙里（`0x7B91D46 < 0x7BA0ED9 < 0x7BA4470`）。

## 为什么会被误判

`.hash`（section idx 2）的 offset 是 `0x7BA4640`，放在文件最尾部附近。
于是「最后 section 结束位置」被算成 `0x7BA8D04`，`size - 0x7BA8D04 = 1540`，
看起来干干净净。而中间那块 75 KB 因为**后面还有 section**，被漏掉了。

正确的算法是「求所有 section 覆盖区间的并集，再取补集」——`tools/elf_info.py`
已按这个改了（commit `f0802460`），`so_check.txt` 现在直接列「未覆盖区间」。

## 连带修正

- 本仓早期文档写的「尾部 `.shstrtab` 之后约 **467 KB**」也是错的，
  实际未覆盖区是 **75,562 B**（我先前把 `size - .shstrtab_end` 当成了壳的大小）。
- 「和 11-06 那份差别只有一处（壳被去掉）」这个判断不成立：
  这份 11-10 的文件里壳仍在。要比较两份，应该比 `sha256` 或比未覆盖区间的 hash，
  不能只比「尾部有没有尾巴」。

## 影响

metadata 的运行时解密入口（`ELF_HOOK_LoadMetadataFile` 那一套）**仍然存在**，
所以：

- 那 16 KB 高强度加密块的正确还原路径没变——还是得在这块 payload 里找；
- 拿代码地址（RVA）的计算量没变，仍然要处理 67.9 MiB 的 `il2cpp` 段，
  而不是「壳去掉了就轻松了」。