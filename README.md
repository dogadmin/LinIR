# LinIR

**Linux/macOS Incident Response & Forensic Collection Tool**

**Linux/macOS 应急响应与取证采集工具**

---

## What is LinIR? / LinIR 是什么？

LinIR is a single-binary, zero-dependency forensic triage tool designed for **compromised or untrusted host environments**. It collects process, network, persistence, and integrity evidence directly from kernel interfaces and filesystem structures — without relying on any commands installed on the target machine.

LinIR 是一个单二进制、零依赖的取证分诊工具，专为**已失陷或低可信主机环境**设计。它直接从内核接口和文件系统结构采集进程、网络、持久化和完整性证据——不依赖目标机上安装的任何命令。

### The Core Problem / 核心问题

When you land on a potentially compromised Linux or macOS host, you cannot trust:

当你登录一台可能已被入侵的 Linux 或 macOS 主机时，你不能信任：

- `ps`, `top`, `netstat`, `ss`, `lsof` — may have been replaced / 可能已被替换
- `systemctl`, `launchctl`, `crontab` — output may be filtered / 输出可能被过滤
- `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` — may be poisoned / 可能被污染
- Shell aliases and functions — may intercept commands / 可能拦截命令
- Dynamic linker — may be hijacked / 动态链接器可能被劫持

**LinIR's answer: don't call any of them.** Read `/proc` directly. Parse ELF/Mach-O/plist files directly. Use raw syscalls. Cross-validate across multiple data sources. Report evidence, not conclusions.

**LinIR 的回答：一个都不调用。** 直接读 `/proc`。直接解析 ELF/Mach-O/plist 文件。使用原始 syscall。跨多数据源交叉验证。输出证据，而非结论。

---

## Design Principles / 设计原则

| Principle | Description |
|---|---|
| **No external commands** | All collection reads kernel interfaces (`/proc`, `/sys`, `sysctl`) and filesystem structures directly. Never calls `ps`, `netstat`, `lsof`, `systemctl`, `launchctl`, or any shell pipeline. |
| **Zero trust environment** | Assumes PATH is poisoned, LD_PRELOAD is active, binaries are replaced. Self-checks its own execution environment before collecting. |
| **Cross-source validation** | Compares process view, network view, file view, and kernel module view. Inconsistencies are flagged as visibility anomalies. |
| **Evidence over verdicts** | Outputs structured evidence with source attribution and confidence levels. Does not claim "malware found" — reports "these data points are inconsistent". |
| **Static binary, single file** | `CGO_ENABLED=0` static compilation. Drop onto target, run, collect, leave. No runtime dependencies. |

| 原则 | 说明 |
|---|---|
| **不调用外部命令** | 所有采集直接读取内核接口（`/proc`、`/sys`、`sysctl`）和文件系统结构。绝不调用 `ps`、`netstat`、`lsof`、`systemctl`、`launchctl` 或任何 shell 管道。|
| **零信任环境** | 假设 PATH 被污染、LD_PRELOAD 已激活、二进制已被替换。在采集前先自检运行环境。|
| **多源交叉验证** | 对比进程视图、网络视图、文件视图和内核模块视图。不一致即标记为可见性异常。|
| **证据优先于结论** | 输出带有来源归属和可信度的结构化证据。不声称"发现恶意软件"——而是报告"这些数据点存在不一致"。|
| **静态二进制，单文件** | `CGO_ENABLED=0` 静态编译。拖到目标机、运行、采集、离开。无运行时依赖。|

---

## What LinIR Collects / LinIR 采集什么

### Self-Check & Preflight / 自检与预检

- Binary self-integrity hash / 自身二进制完整性哈希
- `LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT` detection / 检测
- `DYLD_INSERT_LIBRARIES` and all `DYLD_*` detection / 检测
- `/etc/ld.so.preload` content audit / 内容审计
- `/proc/self/exe` path verification / 路径验证
- `/proc/self/maps` non-standard library detection / 非标准库检测
- PATH poisoning detection (relative dirs, temp dirs, world-writable dirs) / PATH 污染检测
- Container/namespace/chroot detection / 容器/命名空间/chroot 检测
- Host trust level assessment (high/medium/low) / 主机可信度评估

### Process Collection / 进程采集

| Platform | Data Source | What's Collected |
|---|---|---|
| Linux | `/proc/<pid>/stat`, `status`, `cmdline`, `exe`, `cwd`, `environ`, `fd/*`, `maps` | PID, PPID, name, exe path, cmdline, UID/GID, start time, FD count, socket inodes, mapped libraries |
| macOS | `sysctl kern.proc.all` + `proc_pidpath` (syscall 336) + `KERN_PROCARGS2` | PID, PPID, name, exe path, cmdline, UID, start time |

Suspicious flags are automatically set for: deleted executables, executables in `/tmp`, interpreter processes, process name spoofing, fake kernel threads.

自动标记可疑项：已删除的可执行文件、`/tmp` 中的可执行文件、解释器进程、进程名伪装、伪内核线程。

### Network Collection / 网络采集

| Platform | Data Source | What's Collected |
|---|---|---|
| Linux | `/proc/net/tcp`, `tcp6`, `udp`, `udp6`, `raw`, `raw6`, `unix` + `/proc/<pid>/fd/*` inode mapping | Protocol, local/remote addr:port, state, PID association via socket inode |
| macOS | `PROC_PIDLISTFDS` + `PROC_PIDFDSOCKETINFO` (syscall 336) | Protocol, local/remote addr:port, TCP state, direct PID association |

### Persistence Collection / 持久化采集

| Type | Linux Sources | macOS Sources |
|---|---|---|
| Service manager | systemd units: `/etc/systemd/system/`, `/usr/lib/systemd/system/`, etc. Parse `ExecStart`, `User`, `WantedBy`, `Environment` | LaunchDaemons/Agents: `/Library/LaunchDaemons/`, `/Library/LaunchAgents/`, `~/Library/LaunchAgents/`. Parse `Label`, `Program`, `ProgramArguments`, `RunAtLoad` |
| Scheduled tasks | `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`, cron.daily/hourly/weekly scripts | (via LaunchAgents with `StartCalendarInterval`) |
| Shell profiles | `/etc/profile`, `/etc/bash.bashrc`, `/etc/profile.d/*`, `~/.bashrc`, `~/.zshrc` | `/etc/zshrc`, `~/.zshrc`, `~/.bash_profile` |
| SSH | `~/.ssh/authorized_keys`, `sshd_config` | Same |
| Preload | `/etc/ld.so.preload` | `DYLD_INSERT_LIBRARIES` in profiles |
| Boot | `/etc/rc.local` | — |

Risk flags: `target_in_tmp`, `target_missing`, `downloads_from_network`, `pipe_to_shell`, `dev_tcp_reverse_shell`, `base64_usage`, `system_wide_preload`, `impersonates_apple`, `forced_command`, `world_writable`.

### Integrity / Anti-Rootkit Checks / 完整性与反隐藏检查

- **Process view mismatch**: PPID references non-existent process, exe deleted, exe unreadable with cmdline present / 进程视图不一致
- **Network view mismatch**: Connection has no owning process, PID not in process list / 网络视图不一致
- **File view mismatch**: Persistence target file missing from disk / 文件视图不一致
- **Module view mismatch** (Linux): `/proc/modules` vs `/sys/module` inconsistency / 内核模块视图不一致
- **Kernel taint** (Linux): Non-zero taint flags with bit-level decoding / 内核污染标志逐位解析

### YARA Scanning / YARA 扫描

Built-in pure-Go YARA engine (no libyara dependency). Supported condition subset:

内置纯 Go YARA 引擎（不依赖 libyara）。支持的 condition 子集：

```yara
condition: any of them
condition: all of them
condition: 2 of them
condition: $s1 and $s2
condition: $s1 or ($s2 and $s3)
condition: not $s1
condition: #s1 > 3          // match count / 匹配次数
condition: @s1 < 100        // first match offset / 首次匹配偏移
condition: filesize < 1MB
condition: $s1 at 0         // exact offset / 精确偏移
condition: $s1 in (0..1024) // offset range / 偏移范围
condition: any of ($s*)     // wildcard set / 通配符集合
```

Smart target selection: automatically scans executables of networked processes, persistence targets, and files in `/tmp`, `/var/tmp`, `/dev/shm`.

智能目标选择：自动扫描联网进程的可执行文件、持久化目标、以及 `/tmp`、`/var/tmp`、`/dev/shm` 中的文件。

### Scoring / 评分

Weighted evidence scoring model with 14 built-in rules:

加权证据评分模型，内置 14 条规则：

| Indicator | Score | Severity |
|---|---|---|
| Executable in /tmp | +25 | high |
| Interpreter with outbound connection | +20 | medium |
| Persistence target in temp directory | +25 | high |
| System-wide ld.so.preload | +30 | high |
| /dev/tcp reverse shell pattern | +30 | critical |
| YARA rule match | +30 | high |
| Kernel module view mismatch | +25 | high |
| Rootkit indicators | +30 | critical |

Total score 0-100, severity levels: info / low / medium / high / critical.

---

## Usage / 使用方法

### Full Collection / 完整采集

```bash
# Run as root for full visibility / 以 root 运行获取完整可见性
sudo ./linir collect --format json --output-dir ./evidence

# With YARA rules / 带 YARA 规则
sudo ./linir collect --format both --yara-rules ./rules/ --output-dir ./evidence

# Force collection even if preflight fails / 即使预检失败也强制采集
sudo ./linir collect --force --bundle
```

### Individual Subcommands / 单独子命令

```bash
# Environment trust assessment only / 仅环境可信度评估
sudo ./linir preflight --format json

# Process collection only / 仅进程采集
sudo ./linir process --hash-processes --collect-env

# Network connections only / 仅网络连接
sudo ./linir network --format json

# Persistence enumeration only / 仅持久化枚举
sudo ./linir persistence

# Integrity and anti-rootkit checks / 完整性与反隐藏检查
sudo ./linir integrity

# YARA scan with auto target selection / YARA 扫描（自动目标选择）
sudo ./linir yara --rules ./yara-rules/ --proc-linked

# YARA scan on specific directory / YARA 扫描指定目录
sudo ./linir yara --rules ./rules/ --target /tmp

# Export triage bundle / 导出分诊包
sudo ./linir bundle --output-dir ./evidence
```

### Global Flags / 全局参数

```
-o, --output-dir string   Output directory (default ".")
    --format string        Output format: json, text, both (default "both")
    --bundle               Create triage bundle (tar.gz)
    --force                Proceed despite preflight failures
-v, --verbose              Verbose output
-q, --quiet                Suppress non-error output
    --timeout int          Global timeout in seconds (default 300)
```

### Output / 输出

LinIR produces three output formats:

LinIR 生成三种输出格式：

1. **JSON** (`linir-<hostname>-<id>.json`) — Structured evidence for SIEM/AI/automation / 结构化证据，供 SIEM/AI/自动化
2. **Text** (`linir-<hostname>-<id>.txt`) — Human-readable summary / 人类可读摘要
3. **Bundle** (`linir-bundle-<hostname>-<id>.tar.gz`) — Tar archive containing per-section JSON files / 按模块拆分的 JSON 归档

---

## Build from Source / 从源码构建

```bash
git clone https://github.com/dogadmin/LinIR.git
cd LinIR

# Build for current platform / 为当前平台构建
CGO_ENABLED=0 go build -o linir ./cmd/linir

# Cross-compile / 交叉编译
make build-linux        # Linux amd64
make build-linux-arm64  # Linux arm64
make build-darwin        # macOS Intel
make build-darwin-arm64  # macOS Apple Silicon
make build-all           # All platforms
```

### Supported Platforms / 支持的平台

| Platform | Architectures | Process | Network | Persistence |
|---|---|---|---|---|
| **Linux** | amd64, arm64, 386, armv7, mips64le, ppc64le, s390x, riscv64 | Full (/proc) | Full (/proc/net + inode→PID) | Full (systemd, cron, profiles, ssh, rc.local, ld.so.preload) |
| **macOS** | amd64 (Intel), arm64 (Apple Silicon) | Full (sysctl + proc_pidpath) | Full (proc_pidfdinfo) | Full (LaunchDaemons/Agents plist, profiles, ssh) |
| **FreeBSD** | amd64, arm64 | Stub | Stub | Stub |
| **OpenBSD** | amd64 | Stub | Stub | Stub |
| **NetBSD** | amd64 | Stub | Stub | Stub |

FreeBSD/OpenBSD/NetBSD builds compile and run, but platform-specific collectors are not yet implemented (returns empty results with appropriate error messages).

FreeBSD/OpenBSD/NetBSD 可编译运行，但平台特定采集器尚未实现（返回空结果并附错误信息）。

---

## Architecture / 架构

```
linir collect
    │
    ├── Self-Check          LD_PRELOAD/DYLD detection, binary integrity
    ├── Preflight           Host trust assessment, container detection
    │
    ├── Host Collection     Hostname, kernel, uptime, namespace info
    ├── Process Collection  /proc or sysctl direct enumeration
    ├── Network Collection  /proc/net or proc_pidfdinfo parsing
    ├── Persistence Scan    Filesystem-based enumeration
    ├── Integrity Check     Cross-source visibility validation
    │
    ├── Process Analyzer    Parent chain, interpreter abuse, name spoofing
    ├── Network Analyzer    Orphan connections, suspicious ports, raw sockets
    ├── Persistence Analyzer  Target validation, command pattern matching
    │
    ├── Cross-Domain Correlator   Process↔Network↔Persistence linking
    ├── YARA Scanner        File scanning with condition evaluation
    ├── Evidence Scorer     Weighted scoring with 14 rules
    │
    └── Output              JSON + Text + Bundle
```

---

## Project Structure / 项目结构

```
cmd/linir/              Entry point
internal/
  app/                  Orchestrator (selfcheck → preflight → collect → analyze → score → output)
  cli/                  Cobra subcommands (collect, preflight, process, network, persistence, integrity, yara, bundle)
  config/               Runtime configuration
  model/                Unified data models (HostInfo, ProcessInfo, ConnectionInfo, PersistenceItem, etc.)
  collector/
    linux/              /proc-based collectors
    macos/              sysctl/proc_info-based collectors
  selfcheck/            Binary self-integrity verification
  preflight/            Host environment trust assessment
  process/              Post-collection process analysis
  network/              Post-collection network analysis
  persistence/          Post-collection persistence analysis
  integrity/            Cross-source visibility checks, kernel module validation
  correlate/            Cross-domain correlation (process↔network↔persistence)
  score/                Evidence scoring engine
  rule/                 Built-in scoring rule definitions
  yara/                 Pure-Go YARA engine (lexer, parser, AST, evaluator)
  output/               JSON and text output writers
  bundle/               Triage bundle (tar.gz) generator
  report/               Output orchestration
pkg/
  procfs/               /proc filesystem parsers (stat, status, net, maps)
  elfutil/              ELF binary analysis (debug/elf wrapper)
  machoutil/            Mach-O binary analysis (debug/macho wrapper)
  plistutil/            macOS plist parser (howett.net/plist wrapper)
  hashutil/             File hashing (MD5/SHA1/SHA256)
  sysparse/             System file parsers (os-release, crontab, systemd units)
  userutil/             UID→username resolution with caching
  jsonutil/             JSON formatting helpers
```

---

## Known Limitations / 已知限制

- **macOS network offsets**: The `socket_fdinfo` struct field offsets are derived from XNU header analysis and include auto-probing for two known `vinfo_stat` sizes (128/144 bytes). If Apple changes the struct layout in a future macOS version, the auto-probe may fail (connections will be skipped with `confidence: low` rather than producing wrong data).
- **macOS 网络偏移**：`socket_fdinfo` 结构体字段偏移基于 XNU 头文件分析，包含两种已知 `vinfo_stat` 大小（128/144 字节）的自动探测。如果 Apple 在未来版本中更改结构体布局，自动探测可能失败（连接将被跳过并标记 `confidence: low`，而非产生错误数据）。

- **YARA subset**: The built-in YARA engine supports a practical subset of YARA syntax. Full PCRE regex, hex jump wildcards (`[4-6]`), modules (pe, elf, math), `for` expressions, and rule imports are not supported. Unsupported features in rules cause graceful degradation (rule still matches on any string hit) rather than crashes.
- **YARA 子集**：内置 YARA 引擎支持 YARA 语法的实用子集。不支持完整 PCRE 正则、hex 跳跃通配符（`[4-6]`）、模块（pe, elf, math）、`for` 表达式和规则导入。规则中的不支持特性会优雅降级（规则仍按任意字符串命中匹配）而非崩溃。

- **Hex wildcard `??`**: Currently simplified to `\x00` match. Patterns with `??` wildcards will only match if the actual byte at that position happens to be `0x00`. This may cause false negatives.
- **Hex 通配符 `??`**：当前简化为 `\x00` 匹配。含 `??` 通配符的模式只有在该位置字节恰好为 `0x00` 时才匹配。可能导致漏报。

- **Non-root execution**: Running without root privileges significantly reduces visibility. Many `/proc/<pid>/` entries, socket-to-PID mappings, and system persistence paths require root access. LinIR will still run and collect what it can, marking limited-access data with `confidence: low`.
- **非 root 执行**：非 root 运行会显著降低可见性。许多 `/proc/<pid>/` 条目、socket 到 PID 映射和系统持久化路径需要 root 权限。LinIR 仍会运行并采集可获取的数据，受限数据标记为 `confidence: low`。

- **Kernel-level rootkits**: LinIR operates in userspace. A kernel-level rootkit that manipulates `/proc` contents at the kernel level can evade detection. The integrity checker can detect some symptoms (module view mismatches, kernel taint) but cannot guarantee detection of sophisticated kernel rootkits. For such scenarios, offline forensic analysis via external boot media is recommended.
- **内核级 rootkit**：LinIR 在用户态运行。在内核层面篡改 `/proc` 内容的内核级 rootkit 可以规避检测。完整性检查器可以发现部分症状（模块视图不一致、内核污染），但无法保证检测高级内核 rootkit。此类场景建议通过外部启动介质进行离线取证分析。

---

## Dependencies / 依赖

| Dependency | Purpose | CGO Required |
|---|---|---|
| `github.com/spf13/cobra` | CLI framework | No |
| `github.com/google/uuid` | Collection ID generation | No |
| `howett.net/plist` | macOS plist parsing | No |
| `golang.org/x/sys` | syscall wrappers for macOS | No |

All dependencies are pure Go. The binary is fully statically compiled with `CGO_ENABLED=0`.

所有依赖均为纯 Go。二进制通过 `CGO_ENABLED=0` 完全静态编译。

---

## Disclaimer / 免责声明

### English

**LinIR is provided "AS IS" without warranty of any kind, express or implied.** The authors and contributors are not responsible for any damages, data loss, legal consequences, or other liabilities arising from the use or misuse of this tool.

**This tool is intended for authorized security assessments, incident response, digital forensics, and educational purposes only.** Users are solely responsible for ensuring they have proper authorization before deploying this tool on any system. Unauthorized access to computer systems is illegal in most jurisdictions.

**LinIR does not modify, delete, or alter any data on the target system.** It operates in a read-only manner, collecting evidence through passive observation of kernel interfaces and filesystem structures. However, the act of running any forensic tool on a live system may alter volatile evidence (memory, timestamps, process state). Users should be aware of this inherent limitation of live forensics.

**The output of LinIR should not be treated as definitive proof of compromise or security.** It provides structured evidence and anomaly indicators that require professional interpretation. False positives and false negatives are possible. Critical security decisions should not be based solely on LinIR output without additional verification and expert analysis.

**The authors do not endorse or encourage any illegal activities.** This tool is released for the benefit of the security community to improve incident response capabilities on Unix-like systems.

### 中文

**LinIR 按"原样"提供，不附带任何明示或暗示的保证。** 作者和贡献者不对因使用或误用本工具而产生的任何损害、数据丢失、法律后果或其他责任负责。

**本工具仅用于授权的安全评估、应急响应、数字取证和教育目的。** 用户在任何系统上部署本工具前，须自行确保已获得适当授权。在大多数司法管辖区，未经授权访问计算机系统属于违法行为。

**LinIR 不会修改、删除或更改目标系统上的任何数据。** 它以只读方式运行，通过被动观察内核接口和文件系统结构来采集证据。但在活动系统上运行任何取证工具都可能改变易失性证据（内存、时间戳、进程状态）。用户应了解在线取证的这一固有局限性。

**LinIR 的输出不应被视为系统已被入侵或安全的确定性证明。** 它提供结构化证据和异常指标，需要专业人员解读。可能存在误报和漏报。关键安全决策不应仅基于 LinIR 输出，而应结合额外验证和专家分析。

**作者不支持或鼓励任何非法活动。** 本工具的发布旨在造福安全社区，提升类 Unix 系统上的应急响应能力。

---

## License / 许可证

MIT License

---

## Contributing / 贡献

Issues and pull requests are welcome at https://github.com/dogadmin/LinIR.
