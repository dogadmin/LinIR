# LinIR

**Linux/macOS 应急响应与取证采集工具**

[English](README.md)

---

## LinIR 是什么？

LinIR 是一个单二进制、零依赖的取证分诊工具，专为**已失陷或低可信主机环境**设计。它直接从内核接口和文件系统结构采集进程、网络、持久化和完整性证据——不依赖目标机上安装的任何命令。

### 核心问题

当你登录一台可能已被入侵的 Linux 或 macOS 主机时，你不能信任：

- `ps`、`top`、`netstat`、`ss`、`lsof` — 可能已被替换
- `systemctl`、`launchctl`、`crontab` — 输出可能被过滤
- `PATH`、`LD_PRELOAD`、`DYLD_INSERT_LIBRARIES` — 可能被污染
- Shell 别名和函数 — 可能拦截命令
- 动态链接器 — 可能被劫持

**LinIR 的回答：一个都不调用。** 直接读 `/proc`。直接解析 ELF/Mach-O/plist 文件。使用原始 syscall。跨多数据源交叉验证。输出证据，而非结论。

---

## 设计原则

| 原则 | 说明 |
|---|---|
| **不调用外部命令** | 所有采集直接读取内核接口（`/proc`、`/sys`、`sysctl`）和文件系统结构。绝不调用 `ps`、`netstat`、`lsof`、`systemctl`、`launchctl` 或任何 shell 管道。|
| **零信任环境** | 假设 PATH 被污染、LD_PRELOAD 已激活、二进制已被替换。在采集前先自检运行环境。|
| **多源交叉验证** | 对比进程视图、网络视图、文件视图和内核模块视图。不一致即标记为可见性异常。|
| **证据优先于结论** | 输出带有来源归属和可信度的结构化证据。不声称"发现恶意软件"——而是报告"这些数据点存在不一致"。|
| **静态二进制，单文件** | `CGO_ENABLED=0` 静态编译。拖到目标机、运行、采集、离开。无运行时依赖。|

---

## LinIR 采集什么

### 自检与预检

- 自身二进制完整性哈希
- `LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT` 检测
- `DYLD_INSERT_LIBRARIES` 及全系列 `DYLD_*` 检测
- `/etc/ld.so.preload` 内容审计
- `/proc/self/exe` 路径验证、`/proc/self/maps` 非标准库检测
- PATH 污染检测（相对目录、临时目录、任何人可写目录）
- 容器/命名空间/chroot 检测
- 主机可信度评估（high / medium / low）

### 进程采集

| 平台 | 数据源 | 采集内容 |
|---|---|---|
| Linux | `/proc/<pid>/stat`、`status`、`cmdline`、`exe`、`cwd`、`environ`、`fd/*`、`maps` | PID、PPID、进程名、可执行路径、命令行、UID/GID、启动时间、FD 数量、socket inode、映射库 |
| macOS | `sysctl kern.proc.all` + `proc_pidpath`（syscall 336）+ `KERN_PROCARGS2` | PID、PPID、进程名、可执行路径、命令行、UID、启动时间 |

自动标记可疑项：已删除的可执行文件、`/tmp` 中的可执行文件、解释器进程、进程名伪装、伪内核线程。

### 网络采集

| 平台 | 数据源 | 采集内容 |
|---|---|---|
| Linux | `/proc/net/tcp`、`tcp6`、`udp`、`udp6`、`raw`、`raw6`、`unix` + `/proc/<pid>/fd/*` inode 映射 | 协议、本地/远端地址:端口、状态、通过 socket inode 关联 PID |
| macOS | `PROC_PIDLISTFDS` + `PROC_PIDFDSOCKETINFO`（syscall 336）| 协议、本地/远端地址:端口、TCP 状态、直接 PID 关联 |

### 持久化采集

| 类型 | Linux 数据源 | macOS 数据源 |
|---|---|---|
| 服务管理 | systemd 单元文件（`ExecStart`、`User`、`WantedBy`、`Environment`）| LaunchDaemons/Agents plist（`Label`、`Program`、`ProgramArguments`、`RunAtLoad`）|
| 定时任务 | `/etc/crontab`、`/etc/cron.d/*`、`/var/spool/cron/*`、cron.daily/hourly/weekly | 通过 LaunchAgents |
| Shell 配置 | `/etc/profile`、`/etc/bash.bashrc`、`/etc/profile.d/*`、`~/.bashrc`、`~/.zshrc` | `/etc/zshrc`、`~/.zshrc`、`~/.bash_profile` |
| SSH | `~/.ssh/authorized_keys`、`sshd_config` | 同左 |
| 预加载 | `/etc/ld.so.preload` | 配置文件中的 `DYLD_INSERT_LIBRARIES` |
| 启动项 | `/etc/rc.local` | — |

风险标记：`target_in_tmp`（目标在临时目录）、`target_missing`（目标文件缺失）、`downloads_from_network`（网络下载）、`pipe_to_shell`（管道到 shell）、`dev_tcp_reverse_shell`（反弹 shell）、`base64_usage`（base64 编码）、`system_wide_preload`（系统级预加载）、`impersonates_apple`（伪装 Apple 标签）、`forced_command`（SSH 强制命令）、`world_writable`（任何人可写）。

### 完整性与反隐藏检查

- **进程视图不一致**：PPID 引用不存在的进程、exe 已删除、有 cmdline 但 exe 不可读
- **网络视图不一致**：连接无归属进程、PID 不在进程列表中
- **文件视图不一致**：持久化目标文件在磁盘上不存在
- **模块视图不一致**（Linux）：`/proc/modules` 与 `/sys/module` 不一致
- **内核污染**（Linux）：非零 taint 标志逐位解析

### YARA 扫描

内置纯 Go YARA 引擎（不依赖 libyara）。支持的 condition 子集：

```yara
condition: any of them
condition: all of them
condition: 2 of them
condition: $s1 and $s2
condition: $s1 or ($s2 and $s3)
condition: not $s1
condition: #s1 > 3          // 匹配次数
condition: @s1 < 100        // 首次匹配偏移
condition: filesize < 1MB
condition: $s1 at 0         // 精确偏移匹配
condition: $s1 in (0..1024) // 偏移范围匹配
condition: any of ($s*)     // 通配符集合
```

智能目标选择：自动扫描联网进程的可执行文件、持久化目标、以及 `/tmp`、`/var/tmp`、`/dev/shm` 中的文件。

### 评分

加权证据评分模型，内置 14 条规则：

| 指标 | 分值 | 严重度 |
|---|---|---|
| 可执行文件位于 /tmp | +25 | high |
| 解释器有外连 | +20 | medium |
| 持久化目标在临时目录 | +25 | high |
| 系统级 ld.so.preload | +30 | high |
| /dev/tcp 反弹 shell 模式 | +30 | critical |
| YARA 规则命中 | +30 | high |
| 内核模块视图不一致 | +25 | high |
| Rootkit 指标 | +30 | critical |

总分 0-100，严重度分级：info / low / medium / high / critical。

---

## 使用方法

### 完整采集

```bash
# 以 root 运行获取完整可见性
sudo ./linir collect --format json --output-dir ./evidence

# 带 YARA 规则
sudo ./linir collect --format both --yara-rules ./rules/ --output-dir ./evidence

# 即使预检失败也强制采集
sudo ./linir collect --force --bundle
```

### 单独子命令

```bash
sudo ./linir preflight --format json             # 环境可信度评估
sudo ./linir process --hash-processes             # 进程采集
sudo ./linir network --format json                # 网络连接
sudo ./linir persistence                          # 持久化枚举
sudo ./linir integrity                            # 反隐藏检查
sudo ./linir yara --rules ./rules/ --proc-linked  # YARA 扫描（自动目标）
sudo ./linir yara --rules ./rules/ --target /tmp  # YARA 扫描（指定目录）
sudo ./linir bundle --output-dir ./evidence       # 导出分诊包
```

### 全局参数

```
-o, --output-dir string   输出目录（默认 "."）
    --format string        输出格式：json, text, both（默认 "both"）
    --bundle               创建分诊包（tar.gz）
    --force                即使预检失败也继续
-v, --verbose              详细输出
-q, --quiet                抑制非错误输出
    --timeout int          全局超时（秒，默认 300）
```

### 输出格式

1. **JSON**（`linir-<主机名>-<ID>.json`）— 结构化证据，供 SIEM/AI/自动化分析
2. **文本**（`linir-<主机名>-<ID>.txt`）— 人类可读摘要
3. **分诊包**（`linir-bundle-<主机名>-<ID>.tar.gz`）— 按模块拆分的 JSON 归档

---

## 从源码构建

```bash
git clone https://github.com/dogadmin/LinIR.git
cd LinIR

# 为当前平台构建
CGO_ENABLED=0 go build -o linir ./cmd/linir

# 交叉编译
make build-linux          # Linux amd64
make build-linux-arm64    # Linux arm64
make build-darwin          # macOS Intel
make build-darwin-arm64    # macOS Apple Silicon
make build-all             # 全平台
```

### 支持的平台

| 平台 | 架构 | 进程 | 网络 | 持久化 |
|---|---|---|---|---|
| **Linux** | amd64, arm64, 386, armv7, mips64le, ppc64le, s390x, riscv64 | 完整 | 完整 | 完整 |
| **macOS** | amd64, arm64 | 完整 | 完整 | 完整 |
| **FreeBSD** | amd64, arm64 | 桩 | 桩 | 桩 |
| **OpenBSD** | amd64 | 桩 | 桩 | 桩 |
| **NetBSD** | amd64 | 桩 | 桩 | 桩 |

FreeBSD/OpenBSD/NetBSD 可编译运行，但平台特定采集器尚未实现（返回空结果并附错误信息）。

---

## 架构

```
linir collect
    │
    ├── 自检              LD_PRELOAD/DYLD 检测，二进制完整性
    ├── 预检              主机可信度评估，容器检测
    │
    ├── 主机信息采集       主机名，内核，运行时间，命名空间
    ├── 进程采集           /proc 或 sysctl 直接枚举
    ├── 网络采集           /proc/net 或 proc_pidfdinfo 解析
    ├── 持久化扫描         基于文件系统的枚举
    ├── 完整性检查         跨数据源可见性验证
    │
    ├── 进程分析器         父子链，解释器滥用，进程名伪装
    ├── 网络分析器         孤儿连接，可疑端口，原始套接字
    ├── 持久化分析器       目标验证，命令模式匹配
    │
    ├── 跨域关联器         进程↔网络↔持久化关联
    ├── YARA 扫描器        带条件求值的文件扫描
    ├── 证据评分器         14 条规则的加权评分
    │
    └── 输出              JSON + 文本 + 分诊包
```

---

## 已知限制

- **macOS 网络偏移**：`socket_fdinfo` 结构体字段偏移包含两种已知 `vinfo_stat` 大小（128/144 字节）的自动探测。如果 Apple 在未来版本中更改结构体布局，自动探测可能失败（连接将被跳过并标记 `confidence: low`，而非产生错误数据）。
- **YARA 子集**：不支持完整 PCRE 正则、hex 跳跃通配符（`[4-6]`）、模块（pe, elf, math）、`for` 表达式和规则导入。不支持的特性会优雅降级而非崩溃。
- **Hex 通配符 `??`**：当前简化为 `\x00` 匹配。含 `??` 的模式只有在该位置字节恰好为 `0x00` 时才匹配，可能导致漏报。
- **非 root 执行**：非 root 运行会显著降低可见性。受限数据标记为 `confidence: low`。
- **内核级 rootkit**：LinIR 在用户态运行。在内核层面篡改 `/proc` 内容的内核级 rootkit 可以规避检测。建议此类场景通过外部启动介质进行离线取证分析。

---

## 依赖

| 依赖 | 用途 | 需要 CGO |
|---|---|---|
| `github.com/spf13/cobra` | CLI 框架 | 否 |
| `github.com/google/uuid` | 采集 ID 生成 | 否 |
| `howett.net/plist` | macOS plist 解析 | 否 |
| `golang.org/x/sys` | syscall 封装 | 否 |

所有依赖均为纯 Go。通过 `CGO_ENABLED=0` 完全静态编译。

---

## 免责声明

**LinIR 按"原样"提供，不附带任何明示或暗示的保证。** 作者和贡献者不对因使用或误用本工具而产生的任何损害、数据丢失、法律后果或其他责任负责。

**本工具仅用于授权的安全评估、应急响应、数字取证和教育目的。** 用户在任何系统上部署本工具前，须自行确保已获得适当授权。在大多数司法管辖区，未经授权访问计算机系统属于违法行为。

**LinIR 不会修改、删除或更改目标系统上的任何数据。** 它以只读方式运行，通过被动观察内核接口和文件系统结构来采集证据。但在活动系统上运行任何取证工具都可能改变易失性证据（内存、时间戳、进程状态）。用户应了解在线取证的这一固有局限性。

**LinIR 的输出不应被视为系统已被入侵或安全的确定性证明。** 它提供结构化证据和异常指标，需要专业人员解读。可能存在误报和漏报。关键安全决策不应仅基于 LinIR 输出，而应结合额外验证和专家分析。

**作者不支持或鼓励任何非法活动。** 本工具的发布旨在造福安全社区，提升类 Unix 系统上的应急响应能力。

---

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request：https://github.com/dogadmin/LinIR
