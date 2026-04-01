# LinIR

**Linux/macOS 应急响应与取证采集工具**

[English](README_EN.md) | [功能清单与评分规则](FEATURES.md)

---

## 简介

LinIR 是一个单二进制、零依赖的取证分诊工具，专为**已失陷或低可信主机环境**设计。直接从内核接口和文件系统结构采集进程、网络、持久化和完整性证据——不依赖目标机上安装的任何命令。

**核心原则：** 不调用外部命令 · 零信任环境 · 多源交叉验证 · 证据优先于结论 · 静态单文件

---

## 快速开始

```bash
# 完整采集（最常用）
sudo ./linir collect

# 带 YARA + 分诊包
sudo ./linir collect --yara-rules /opt/yara-rules/ --bundle

# IOC 在线监控
sudo ./linir watch --iocs ./iocs.txt

# Web 仪表盘
sudo ./linir gui

# 环境可信度评估
sudo ./linir preflight --format text
```

---

## 命令参考

### 全局参数（适用于所有子命令）

| 参数 | 短写 | 说明 | 默认值 |
|---|---|---|---|
| `--output-dir` | `-o` | 输出目录 | `.` |
| `--format` | | `json` / `text` / `csv` / `both` / `all` | `both` |
| `--bundle` | | 生成 tar.gz 分诊包 | 关闭 |
| `--force` | | 预检失败也继续 | 关闭 |
| `--verbose` | `-v` | 详细日志 | 关闭 |
| `--quiet` | `-q` | 抑制标准输出 | 关闭 |
| `--timeout` | | 全局超时（秒） | `300` |

### 子命令一览

| 命令 | 说明 | 专属参数 |
|------|------|----------|
| `collect` | 完整采集流程 | `--hash-processes` `--collect-env` `--yara-rules <path>` |
| `preflight` | 仅环境可信度评估 | 无 |
| `process` | 仅进程采集 | `--hash-processes` `--collect-env` |
| `network` | 仅网络连接采集 | 无 |
| `persistence` | 仅持久化枚举 | 无 |
| `integrity` | 跨数据源完整性检查 | 无 |
| `yara` | YARA 扫描 | `--rules <path>`(必填) `--target <path>` `--proc-linked` |
| `bundle` | 等价 `collect --bundle` | 无 |
| `watch` | IOC 在线监控 | 见下方 |
| `gui` | Web 仪表盘 | `--host <addr>` `--port <num>` |

### watch 专属参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--iocs <path>` | IOC 列表文件（必填） | — |
| `--duration <秒>` | 监控时长，0=无限 | `0` |
| `--interval <秒>` | 轮询间隔 | `1` |
| `--json` | 输出 JSONL | 关闭 |
| `--text` | 输出文本 | 开启 |
| `--bundle` | 输出事件 bundle | 关闭 |
| `--whitelist <path>` | 白名单 | 无 |
| `--max-events <n>` | 每分钟最大事件数 | `0` |
| `--yara-rules <path>` | YARA 规则 | 无 |
| `--iface <name>` | 网络接口 | 自动 |

### gui 专属参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--host` | 监听地址（`0.0.0.0` 允许外部访问） | `127.0.0.1` |
| `--port` | HTTP 端口 | `18080` |

---

## 采集能力

| 维度 | Linux 数据源 | macOS 数据源 |
|------|-------------|-------------|
| **自检** | `/proc/self/exe`、`/proc/self/maps`、环境变量 | 同左 |
| **进程** | `/proc/<pid>/stat`、`cmdline`、`exe`、`fd/*`、`maps` | `sysctl kern.proc.all` + `proc_pidpath` + `KERN_PROCARGS2` |
| **网络** | `/proc/net/tcp*`、`udp*`、`raw*`、`unix` + inode→PID 映射 + `/proc/<pid>/comm` | `proc_pidfdinfo` + `sysctl pcblist_n` 双源合并 |
| **持久化** | systemd、crontab、shell profile、SSH、ld.so.preload、rc.local | LaunchDaemons/Agents、cron、shell profile、SSH |
| **完整性** | 进程/网络/文件/模块视图交叉验证、kernel taint | 进程/网络/文件视图交叉验证 |
| **YARA** | 纯 Go 引擎，支持 condition 子集（any/all/N of、逻辑运算、偏移匹配、filesize） | 同左 |

自动标记：exe_deleted、exe_in_tmp、webserver_spawned_shell、fake_kernel_thread、orphan_connection、suspicious_port、reverse_shell、pipe_to_shell 等。

---

## IOC 在线监控

### 三层监控模式（自动选择）

| 层级 | Linux | macOS | 特点 |
|---|---|---|---|
| 层 1 | conntrack netlink 事件驱动 | BPF /dev/bpf（TCP SYN + UDP） | 零遗漏，需 root |
| 层 2 | /proc/net/nf_conntrack | — | RST 保留 ~10s |
| 层 3 | /proc/net/tcp 轮询 | proc_pidfdinfo + sysctl 轮询 | 通用回退 |

### PID 解析

- **快速定向查找**：/proc/net/tcp 找 inode → 从高 PID 搜索 /proc/<pid>/fd/（~10-50ms）
- **多次重试**：Linux 4次×50ms，macOS 1次
- **pending 队列**：PID=0 暂存等轮询补全（5 元组索引匹配），5 秒超时
- **进程名回退**：进程退出但 `/proc/<pid>/comm` 已采集

### 去重

基于完整 5 元组 + IOC 值。每个真实连接独立事件。PID=0 使用 5 秒短窗口。

### IOC 文件格式

```
# 注释行
1.2.3.4
10.0.0.1 c2,apt28
evil.example.com
```

### 白名单文件格式

```
process:sshd
path:/usr/lib/systemd/
ioc:8.8.8.8
```

---

## 评分体系

**设计原则：** 单点低分 · 组合高分 · confidence 分离 · YARA 4 级分层 · suppress 机制

### Collect 评分（主机整体风险）

| 指标 | 基础分 | 组合/上下文 | 严重度 |
|---|---|---|---|
| exe 在临时目录 | +10 | +联网 +10，+interpreter +5 | low→medium |
| exe 已删除 | +5 | +联网 +5 | low→medium |
| Web 服务派生 shell | +10 弱 / +25 强 | +网络=强 | medium / high |
| 伪内核线程 | +10 | +联网 +10 | medium→high |
| 持久化在临时目录 | +15 | +激活 +10，+联网 +10 | medium→high |
| ld.so.preload | +15 | +路径异常 +10 | medium→high |
| /dev/tcp 反弹 shell | +25 | +激活 +10 | critical |
| YARA 命中 | +10/+15/+20/+25 | +活跃进程 +5，+临时路径 +5 | 按 severity_hint |
| Rootkit 疑似 | +15 | 主要降 confidence | high |
| 组合项（7 个） | | +10~+15 | high→critical |

**Suppress 机制：** 父进程为包管理器（apt/yum/brew/pip 等）→ 分值减半；exe_deleted 无网络无持久化无 YARA → 不计分；pipe_to_shell 未激活 → 不计分。

**Confidence 分离：** host_trust_low、orphan_connections、process_invisible 不堆分，只降 confidence 并记录到 `integrity_flags`。

### Watch 评分（每个 IOC 命中事件）

| 指标 | 分值 | 说明 |
|---|---|---|
| IOC 命中 | +20 | 基础触发分 |
| exe 在临时目录 | +10 | +interpreter +10 |
| Webshell 强指标 | +25 | |
| 持久化关联 | +10 | +路径异常 +5 |
| YARA 命中 | +10/+15/+20/+25 | 4 级分层 |
| 组合项（6 个） | +5~+15 | IOC+tmp、IOC+persist+YARA 等 |

总分 0-100。严重度：info(0-19) / low(20-39) / medium(40-59) / high(60-79) / critical(80-100)。

> 完整评分规则详见 [FEATURES.md](FEATURES.md)

---

## Capabilities 输出

LinIR 在采集时自动检测并输出平台能力状态，区分"真实无异常"和"采集受限看不到"：

```json
{
  "capabilities": {
    "process_collection": "full",
    "network_collection": "full",
    "pid_attribution": "full",
    "persistence_collection": "full",
    "watch_mode_layer": "layer1",
    "running_privileged": true,
    "platform": "linux"
  }
}
```

---

## 输出格式

| 格式 | 文件名 | 用途 |
|---|---|---|
| JSON | `linir-<主机>-<ID>.json` | SIEM / 自动化分析 |
| 文本 | `linir-<主机>-<ID>.txt` | 人类可读报告 |
| CSV | `linir-<主机>-<ID>-*.csv`（7 个表） | Excel 分析 |
| 分诊包 | `linir-bundle-<主机>-<ID>.tar.gz` | 归档传递 |

---

## GUI 仪表盘

```bash
sudo ./linir gui                    # 本机访问
sudo ./linir gui --host 0.0.0.0     # 局域网访问
```

功能：一键采集 · 风险评分卡片 · 交互式进程/网络/持久化表格 · 评分证据展开 · 完整性检查 · IOC 实时监控（SSE） · YARA 扫描（文件浏览器默认 CWD） · JSON 导出 · 暗色主题

---

## 典型工作流

```bash
# 场景一：快速分诊
scp linir-linux-amd64 root@target:/tmp/linir
ssh root@target '/tmp/linir collect --bundle -o /tmp/evidence'
scp root@target:/tmp/evidence/linir-bundle-*.tar.gz ./

# 场景二：深度扫描
sudo ./linir collect --yara-rules /opt/yara-rules/ --hash-processes --bundle

# 场景三：IOC 监控
sudo ./linir watch --iocs iocs.txt --duration 600 --yara-rules ./rules/ --json

# 场景四：远程 GUI
ssh -L 18080:127.0.0.1:18080 root@target
# target: sudo ./linir gui
# 本地: 浏览器打开 http://127.0.0.1:18080

# 场景五：CSV 分析
sudo ./linir collect --format all -o ./evidence
```

---

## 构建

```bash
git clone https://github.com/dogadmin/LinIR.git && cd LinIR
CGO_ENABLED=0 go build -o linir ./cmd/linir

# 交叉编译
make build-linux          # Linux amd64
make build-darwin-arm64   # macOS Apple Silicon
make build-all            # 全平台
```

### 支持平台

| 平台 | 架构 | 状态 |
|---|---|---|
| **Linux** | amd64, arm64, 386, armv7, mips64le, ppc64le, s390x, riscv64 | 完整 |
| **macOS** | amd64, arm64 | 完整 |
| FreeBSD / OpenBSD / NetBSD | amd64 | 桩 |

---

## 架构

```
linir collect
    ├── 自检 + 预检 + Capabilities 检测
    ├── 进程/网络/持久化/完整性采集
    ├── 进程/网络/持久化分析 + 跨域关联
    ├── YARA 扫描 + 证据评分（suppress + combo）
    └── 输出（JSON/文本/CSV/分诊包）

linir watch --iocs ./iocs.txt
    ├── 三层监控（conntrack/BPF → nf_conntrack → /proc/net/tcp）
    ├── 事件驱动 → ResolveHitPID（重试 + pending 队列）
    ├── 5 元组去重 + 频控 + 白名单
    └── 补采 + 评分 + 输出

linir gui [--host 0.0.0.0]
    ├── HTTP 服务器（go:embed 内嵌资源）
    ├── /api/collect · /api/watch/* · /api/yara/scan
    └── 暗色仪表盘 + IOC 实时 SSE
```

---

## 依赖

所有纯 Go，`CGO_ENABLED=0` 静态编译。

| 依赖 | 用途 |
|---|---|
| `github.com/spf13/cobra` | CLI 框架 |
| `github.com/google/uuid` | 采集 ID |
| `howett.net/plist` | macOS plist |
| `golang.org/x/sys` | syscall |
| `github.com/ti-mo/conntrack` | Linux conntrack |

---

## 已知限制

- macOS 网络偏移：多版本自动探测，不可靠 PID 自动清零
- YARA 子集：不支持完整 PCRE、hex 跳跃、模块、for 表达式
- 非 root：可见性显著受限，受限数据标记 `confidence: low`
- 内核级 rootkit：用户态工具固有局限，建议离线取证

---

## 免责声明

LinIR 按"原样"提供。仅用于授权的安全评估、应急响应和数字取证。只读运行，不修改目标数据。输出需专业人员解读。

---

## 许可证

MIT License

## 贡献

https://github.com/dogadmin/LinIR
