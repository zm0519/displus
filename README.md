# displus — Wireshark DIS 协议中文化解析插件

displus 是 Wireshark 的 Lua 插件，面向分布式交互仿真(Distributed Interactive Simulation，DIS，IEEE 1278.1)协议，在保留内置英文解析树的基础上，提供**补全**与**中文化**两层增强：

- **补全** —— 内置解析器(`packet-dis.c`)缺失 body 解析的 PDU(后勤、实体管理、雷场、碰撞-弹性、属性等)，按标准补全逐字段解析；
- **中文化** —— 所有字段标签以「中文 (English)」对照形式展示，显示过滤器前缀 `displus.*`。

解析语义与内置解析器逐字段一致，中英两棵树并排显示，可直接对照验证。

## 特性

- **双树并排**：每包先调用内置 `dis` 解析器生成英文树(`dis.*`，Info 列与显示过滤器保持现状)，再追加完整中文树(`displus.*`)；
- **完整字段树覆盖 50+ 种 PDU**，其余类型以正确中文名 + 原始字节兜底；
- **枚举全量中译**：国家码 279 项、平台类别按域五张表、Appearance 与能力(Capabilities)位解码覆盖全部种类/域；
- **健壮性**：头部三向长度校验、截断防护、变长记录数护栏，畸形包不崩溃。

## 安装

### 一键部署(推荐)

```powershell
powershell -File tools\deploy.ps1
```

脚本将 `displus.lua` 复制到 `%APPDATA%\Wireshark\plugins\`，模块目录复制到 `%APPDATA%\Wireshark\plugins\displus_mod\`。

### 手动安装

1. 复制 `displus.lua` → `%APPDATA%\Wireshark\plugins\`；
2. 复制 `modules\` → `%APPDATA%\Wireshark\plugins\displus_mod\`；
3. 在 Wireshark 中按 **Ctrl+Shift+L** 重载，或重启 Wireshark。

> ⚠️ 若曾对 UDP 3000 设置「Decode As → DIS」，请删除该绑定，否则会绕过本插件。

开发迭代：改动源码后先运行 `tools\deploy.ps1` 再重载(模块只从部署位加载)。临时调试可用：

```bash
tshark -X lua_script:D:\projects\displus\displus.lua -r xxx.pcap -V
```

## 使用

插件接管 UDP 3000 端口(可在偏好中修改)。偏好位置：**编辑 → 首选项 → 协议 → DIS 全解**。

| 偏好 | 默认 | 说明 |
|---|---|---|
| 监听端口 | 3000 | 须与内置 dis 端口一致 |
| 显示内置英文树 | 开 | 关闭则只剩中文树 |
| 生成中文树 | 开 | 关闭则只剩英文树 |

## 样例抓包

仓库附带 [samples/all_pdus.pcap](samples/all_pdus.pcap)，覆盖全部完整字段树的 53 个 PDU 类型(每类一包)，可直接用 Wireshark 打开对照中英两棵树。由 `python -I tools/gen_all_pdus.py` 重新生成。

## 覆盖范围

以下 PDU 类型为**完整字段树**(逐字段中文解析)：

| 协议族 | PDU 类型 | 内容 |
|---|---|---|
| 实体信息/交互 | 1、4、66、67、72 | 实体状态 / 碰撞 / 碰撞-弹性 / 实体状态更新 / 属性 |
| 作战 | 2、3 | 开火 / 爆炸 |
| 后勤 | 5–10 | 服务请求 / 再补给 / 修理 |
| 仿真管理 | 11–22、51–62、73 | 含可靠(R)系列与应用控制 |
| 无线电通信 | 25、26、27、31、32 | 发射机 / 信号 / 接收机 / 内通 |
| 分布发射再生 | 23、24、28、29 | 电磁发射 / 照射器 / IFF / 水声 |
| 实体管理 | 33–36 | 聚合状态 / IsGroupOf / 转移所有权 / IsPartOf |
| 雷场 | 37 | 雷场状态 |
| 合成环境 | 41 | 环境过程 |

其余类型(30、38–40、42–50、63–65、68–71 等)以正确中文名 + 原始字节兜底，头部三向长度校验仍生效。

## 架构

路由器 + 双树模型：

```
UDP:3000 → displus 路由器
            ├─ 内置 dis 解析器 → 英文树(dis.*)
            └─ 中文字段树(displus.*)
```

模块按协议族分目录，族内每 PDU 一个文件，族内共享字段放该族 `shared.luamod`：

```
modules/
├─ common.luamod        加载器 / 跨包上下文 / 注册表
├─ enums_core.luamod    核心枚举 + 头部解析
├─ enums_data.luamod    大枚举表(v37 中译)
├─ country.luamod       国家表(279 项)
├─ records.luamod       跨族公共记录
├─ entity/              实体信息族
├─ warfare/             作战族
├─ logistics/           后勤族
├─ siman/               仿真管理族
├─ radio/               无线电通信族
├─ emission/            分布发射再生族
├─ mgmt/                实体管理族
├─ minefield/           雷场族
└─ synthenv/            合成环境族
```

## 性能

双树全开约 57 µs/包(Lua 双解析开销)。5 万包回放约 3.3s(双树)vs 0.5s(无插件)。常规演习流量(数百~数千 PDU/s)无感；超大流量或长时间抓包建议在偏好中关闭一棵树。

## 参考标准

- **IEEE 1278.1-2012** —— DIS 应用协议
- **SISO-REF-010 v37** —— 仿真互操作枚举注册表
- **Wireshark v4.6.9 `packet-dis.c`** —— 内置解析器对照基准

## 目录结构

```
displus.lua            入口(路由器 / 偏好 / 模块加载)
modules\               模块(按协议族分目录)
samples\               样例抓包(all_pdus.pcap)
tools\                 部署/生成脚本
```

## 许可证

本项目以 [GNU General Public License v2.0 或更高版本(GPL-2.0-or-later)](LICENSE)发布。
