# LinIR

**Linux/macOS 应急响应与取证采集工具**

[English](README_EN.md)

---

## 简介

LinIR 是一个单二进制、零依赖的取证分诊工具，专为**已失陷或低可信主机环境**设计。直接从内核接口和文件系统结构采集进程、网络、持久化和完整性证据——不依赖目标机上安装的任何命令。

**核心原则：** 不调用外部命令 · 零信任环境 · 多源交叉验证 · 证据优先于结论 · 静态单文件

---

## 快速开始

```bash
# 完整采集（最常用）
sudo ./linir collect

# 三维分析（运行态 + 历史残留 + 未来触发 + 统一时间线）
sudo ./linir collect --timeline

# 带 YARA + 分诊包
sudo ./linir collect --yara-rules /opt/yara-rules/ --bundle

# IOC 在线监控
sudo ./linir watch --iocs ./iocs.txt

# Web 仪表盘（含 AI 分析）
sudo ./linir gui
```

---

## 三维状态模型（v0.2.0 新增）

LinIR 不再只回答"现在发生了什么"，而是同时回答三个问题：

| 维度 | 含义 | 典型来源 |
|------|------|----------|
| **Runtime（运行态）** | 此刻正在发生什么 | 进程、连接、活跃持久化、YARA 命中 |
| **Retained（历史残留态）** | 过去留下了什么痕迹 | 文件时间线、持久化变更、deleted exe、认证历史、日志 |
| **Triggerable（可触发态）** | 未来还会触发什么 | 自启动服务、定时任务、KeepAlive/Restart 机制 |

统一时间线将三态事件按时间排序，形成完整的攻击链视图。

```bash
# 独立子命令
sudo ./linir retained --window 48h   # 仅历史残留
sudo ./linir triggerable             # 仅未来触发
sudo ./linir timeline                # 全量时间线

# 与 collect 组合
sudo ./linir collect --with-retained --with-triggerable --timeline
```

---

## 命令参考

### 全局参数

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
| `collect` | 完整采集流程 | `--hash-processes` `--collect-env` `--with-retained` `--with-triggerable` `--timeline` `--retained-window` |
| `retained` | 历史残留态采集 | `--window` |
| `triggerable` | 未来可触发态枚举 | 无 |
| `timeline` | 全量统一时间线 | `--window` |
| `preflight` | 仅环境可信度评估 | 无 |
| `process` | 仅进程采集 | `--hash-processes` `--collect-env` |
| `network` | 仅网络连接采集 | 无 |
| `persistence` | 仅持久化枚举 | 无 |
| `integrity` | 跨数据源完整性检查 | 无 |
| `yara` | YARA 扫描 | `--rules`(必填) `--target` `--proc-linked` |
| `watch` | IOC 在线监控 | `--iocs` `--duration` `--interval` 等 |
| `gui` | Web 仪表盘 | `--host` `--port` |

---

## 采集能力

| 维度 | Linux 数据源 | macOS 数据源 |
|------|-------------|-------------|
| **自检** | `/proc/self/exe`、环境变量、LD_PRELOAD | 同左 + DYLD 检测 |
| **进程** | `/proc/<pid>/stat`、`cmdline`、`exe`、`fd/*`、`maps` | `sysctl kern.proc.all` + `proc_pidpath` + `KERN_PROCARGS2` |
| **网络** | `/proc/net/tcp*`、`udp*`、`raw*`、`unix` + inode→PID | `proc_pidfdinfo` + `sysctl pcblist_n` |
| **持久化** | systemd、crontab、shell profile、SSH、ld.so.preload、rc.local | LaunchDaemons/Agents、cron、shell profile、SSH |
| **完整性** | 进程/网络/文件/模块视图交叉验证、kernel taint | 进程/网络/文件视图交叉验证 |
| **历史残留** | 文件时间线、持久化 mtime/ctime、wtmp/btmp、auth.log、syslog | 文件时间线、plist mtime、system.log |
| **可触发态** | enabled systemd、timers、cron、Restart=always、SSH forced command | RunAtLoad、KeepAlive、StartInterval、cron |
| **YARA** | 纯 Go 引擎，支持 condition 子集 | 同左 |

---

## IOC 在线监控

### 三层监控模式（自动选择）

| 层级 | Linux | macOS | 特点 |
|---|---|---|---|
| 层 1 | conntrack netlink 事件驱动 | BPF /dev/bpf | 零遗漏 |
| 层 2 | /proc/net/nf_conntrack | — | RST 保留 ~10s |
| 层 3 | /proc/net/tcp 轮询 | proc_pidfdinfo + sysctl | 通用回退 |

---

## 评分体系

**设计原则：** 单点低分 · 组合高分 · confidence 分离 · suppress 机制 · 干净系统零分

| 指标 | 基础分 | 组合/上下文 | 严重度 |
|---|---|---|---|
| exe 在临时目录 | +10 | +联网 +10，+interpreter +5 | low→medium |
| exe 已删除（文件真不在） | +5 | +联网 +5 | low→medium |
| Web 服务派生 shell | +10 / +25 | +网络=强 | medium / high |
| 持久化在临时目录 | +15 | +激活 +10，+联网 +10 | medium→high |
| /dev/tcp 反弹 shell | +25 | +激活 +10 | critical |
| YARA 命中 | +10~+25 | +活跃进程 +5 | 按 severity |
| 跨状态组合 | +8~+10 | 需有额外可疑指标 | medium→high |

**Suppress：** 包管理器子进程 → 减半；已删除但文件仍在原路径（包更新）→ 不标记；合法临时路径（systemd-private/snap/go-build 等）→ 不标记。

---

## GUI 仪表盘

```bash
sudo ./linir gui                    # 本机访问
sudo ./linir gui --host 0.0.0.0     # 公网访问
```

功能：
- 一键采集 / 三维分析
- 风险评分卡片 · 交互式表格 · 评分证据展开
- 历史残留 / 未来触发 / 统一时间线 Tab
- **AI 智能分析**（MiniMax M2.5/M2.7）：一键综合分析、预制话术（入侵判定/后门排查/横向移动/数据外泄/持久化分析/处置建议）、多轮对话
- IOC 实时监控（SSE）· YARA 扫描
- JSON / CSV 导出 · API Token 认证 · 暗色主题

---

## 输出格式

| 格式 | 文件名 | 用途 |
|---|---|---|
| JSON | `linir-<主机>-<ID>.json` | SIEM / 自动化 |
| 文本 | `linir-<主机>-<ID>.txt` | 人类可读 |
| CSV | `linir-<主机>-<ID>-*.csv` | Excel 分析 |
| 分诊包 | `linir-bundle-<主机>-<ID>.tar.gz` | 归档 |
| 三维分析 | `linir-analysis-<主机>-<ID>.*` | 含 retained/triggerable/timeline |

---

## 构建

```bash
git clone https://github.com/dogadmin/LinIR.git && cd LinIR
CGO_ENABLED=0 go build -o linir ./cmd/linir
make build-all  # 全平台
```

| 平台 | 架构 | 状态 |
|---|---|---|
| **Linux** | amd64, arm64, 386, armv7, mips64le, ppc64le, s390x, riscv64 | 完整 |
| **macOS** | amd64, arm64 | 完整 |

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
- YARA 子集：不支持完整 PCRE、hex 跳跃、模块
- 非 root：可见性显著受限
- 内核级 rootkit：用户态工具固有局限，建议离线取证

---

## 免责声明

LinIR 按"原样"提供。仅用于授权的安全评估、应急响应和数字取证。只读运行，不修改目标数据。

## 许可证

MIT License

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=dogadmin/LinIR&type=Date)](https://star-history.com/#dogadmin/LinIR&Date)
