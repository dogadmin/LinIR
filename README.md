# LinIR

**Linux/macOS 应急响应与取证采集工具**

[English Documentation](README_EN.md)

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

## 采集能力

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

### 完整性与反隐藏检查

- **进程视图不一致**：PPID 引用不存在的进程、exe 已删除、有 cmdline 但 exe 不可读
- **网络视图不一致**：连接无归属进程、PID 不在进程列表中
- **文件视图不一致**：持久化目标文件在磁盘上不存在
- **模块视图不一致**（Linux）：`/proc/modules` 与 `/sys/module` 不一致
- **内核污染**（Linux）：非零 taint 标志逐位解析

### YARA 扫描

内置纯 Go YARA 引擎（不依赖 libyara）。支持的 condition 子集：

```yara
condition: any of them            // 任意字符串命中
condition: all of them            // 全部字符串命中
condition: 2 of them              // 至少 N 个命中
condition: $s1 and $s2            // 逻辑与
condition: $s1 or ($s2 and $s3)   // 逻辑或 + 括号
condition: not $s1                // 逻辑非
condition: #s1 > 3                // 匹配次数比较
condition: @s1 < 100              // 首次匹配偏移比较
condition: filesize < 1MB         // 文件大小比较
condition: $s1 at 0               // 精确偏移匹配
condition: $s1 in (0..1024)       // 偏移范围匹配
condition: any of ($s*)           // 通配符集合
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

## 命令参考

### 全局参数

以下参数适用于所有子命令：

| 参数 | 短写 | 说明 | 默认值 |
|---|---|---|---|
| `--output-dir` | `-o` | 输出文件保存目录 | `.`（当前目录）|
| `--format` | | 输出格式：`json`、`text`、`csv`、`both`（json+text）、`all`（json+text+csv） | `both` |
| `--bundle` | | 额外生成 tar.gz 分诊包 | 关闭 |
| `--force` | | 即使预检发现高风险也强制继续采集 | 关闭 |
| `--verbose` | `-v` | 输出详细运行日志 | 关闭 |
| `--quiet` | `-q` | 抑制标准输出（仅保留文件输出和错误） | 关闭 |
| `--timeout` | | 全局超时时间（秒），超时后中止采集 | `300` |

---

### `linir collect` — 完整采集

执行全部采集阶段：自检 → 预检 → 进程 → 网络 → 持久化 → 完整性 → 关联分析 → YARA → 评分 → 输出。

**这是最常用的命令，适用于大多数应急响应场景。**

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--hash-processes` | 计算每个进程可执行文件的 SHA256 哈希（较慢，但可用于 IOC 比对） | 关闭 |
| `--collect-env` | 采集进程环境变量（敏感数据，含密钥/token 风险，按需启用） | 关闭 |
| `--yara-rules` | YARA 规则文件或目录路径。指定后自动在采集流程中执行 YARA 扫描 | 无 |

```bash
# 基础用法：完整采集，JSON + 文本双格式输出
sudo ./linir collect

# 输出到指定目录
sudo ./linir collect --output-dir /tmp/evidence

# 仅 JSON 输出 + 生成 tar.gz 分诊包
sudo ./linir collect --format json --bundle

# 携带 YARA 规则扫描
sudo ./linir collect --yara-rules /opt/yara-rules/ --output-dir ./evidence

# 采集进程哈希和环境变量（深度取证模式）
sudo ./linir collect --hash-processes --collect-env

# 主机环境可疑但仍需采集（跳过预检失败中止）
sudo ./linir collect --force --bundle
```

---

### `linir preflight` — 环境可信度评估

仅执行自检和预检阶段。快速判断主机环境是否可信，不进行实际数据采集。

**适用于：在正式采集前先评估主机环境风险。**

无额外参数。

```bash
# 快速评估主机可信度，JSON 输出
sudo ./linir preflight --format json

# 文本输出到屏幕
sudo ./linir preflight --format text
```

输出包含：
- `host_trust_level`：high / medium / low
- PATH 异常、loader 劫持、shell profile 污染、容器检测结果
- 是否建议强制采集（`--force`）

---

### `linir process` — 进程采集与分析

仅采集进程信息。包含自检 → 预检 → 进程枚举 → 进程分析四个阶段。

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--hash-processes` | 计算每个进程可执行文件的 SHA256 | 关闭 |
| `--collect-env` | 采集进程环境变量（最多 50 个/进程） | 关闭 |

```bash
# 基础进程枚举
sudo ./linir process

# 带哈希和环境变量的深度采集
sudo ./linir process --hash-processes --collect-env --format json
```

输出字段：PID、PPID、进程名、可执行路径、命令行、UID/GID、用户名、启动时间、FD 数量、socket inode 列表、映射库摘要、可疑标记（`exe_deleted`、`exe_in_tmp`、`interpreter`、`name_exe_mismatch`、`fake_kernel_thread` 等）。

---

### `linir network` — 网络连接采集与分析

仅采集网络连接信息。

无额外参数。

```bash
sudo ./linir network --format json
```

输出字段：协议（tcp/udp/raw/unix）、地址族（ipv4/ipv6/unix）、本地地址:端口、远端地址:端口、连接状态（ESTABLISHED/LISTEN/TIME_WAIT 等）、socket inode、归属 PID、进程名、可疑标记（`orphan_active_connection`、`raw_socket`、`suspicious_remote_port` 等）、数据来源、可信度。

---

### `linir persistence` — 持久化枚举与分析

仅枚举系统中的持久化机制。

无额外参数。

```bash
sudo ./linir persistence --format json
```

输出字段：类型（systemd/cron/launchd/shell_profile/ssh/rc_local/ld_preload）、文件路径、目标可执行文件、作用域（system/user）、解析字段（ExecStart/schedule/command 等）、风险标记、目标是否存在、可信度。

---

### `linir integrity` — 完整性与反隐藏检查

执行跨数据源的可见性一致性检查。需要先采集进程/网络/持久化数据（自动执行）。

无额外参数。

```bash
sudo ./linir integrity --format json
```

输出字段：
- `rootkit_suspected`：是否疑似存在 rootkit（布尔值）
- `process_view_mismatch`：进程视图不一致项列表
- `network_view_mismatch`：网络视图不一致项列表
- `file_view_mismatch`：文件视图不一致项列表
- `module_view_mismatch`：内核模块视图不一致项列表（Linux）
- `kernel_taint`：内核污染标志值及逐位含义（Linux）
- `recommended_action`：建议操作列表

---

### `linir yara` — YARA 规则扫描

对指定目标执行 YARA 规则扫描。

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--rules` | **必填**。YARA 规则文件路径或目录（自动递归加载 `.yar`/`.yara`/`.rule` 文件） | 无 |
| `--target` | 扫描指定目录下的所有文件 | 无 |
| `--proc-linked` | 智能目标选择：扫描联网进程的可执行文件、持久化引用目标、临时目录中的可执行文件 | 关闭 |

`--target` 和 `--proc-linked` 可同时使用。如果两者都不指定，默认启用 `--proc-linked`。

```bash
# 扫描 /tmp 目录
sudo ./linir yara --rules /opt/yara-rules/ --target /tmp

# 智能目标选择（推荐）
sudo ./linir yara --rules /opt/yara-rules/ --proc-linked

# 同时扫描指定目录和进程关联文件
sudo ./linir yara --rules ./rules/ --target /var/www --proc-linked

# 配合 collect 使用（在完整采集中嵌入 YARA）
sudo ./linir collect --yara-rules /opt/yara-rules/
```

输出字段：规则名、目标类型（file/process-linked-file/persistence-target）、目标路径、规则元信息、命中的字符串 ID 列表、严重度提示、关联 PID。

---

### `linir bundle` — 分诊包导出

执行完整采集后打包为 tar.gz 归档。等价于 `linir collect --bundle`。

无额外参数。

```bash
sudo ./linir bundle --output-dir /tmp/evidence
```

生成的 tar.gz 内包含：
- `host.json` — 主机信息
- `self_check.json` — 自检结果
- `preflight.json` — 预检结果
- `processes.json` — 进程列表
- `connections.json` — 网络连接
- `persistence.json` — 持久化项
- `integrity.json` — 完整性检查
- `yara_hits.json` — YARA 命中
- `score.json` — 评分结果
- `errors.json` — 采集过程中的非致命错误
- `full.json` — 以上全部数据的合并文件

---

### `linir watch` — IOC 在线监控

持续监控主机网络连接，与 IOC 列表实时比对。命中后立即补采进程、二进制、持久化、YARA、完整性上下文，形成结构化、可评分的命中事件。

**核心设计：IOC 命中不是结论，而是触发器。** 命中后拉取运行态上下文，组合评分，再判断风险级别。

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--iocs` | **必填**。IOC 列表文件路径（每行一个 IP 或域名，# 为注释） | 无 |
| `--duration` | 监控总时长（秒），0 表示无限 | `0` |
| `--interval` | 轮询间隔（秒） | `3` |
| `--json` | 输出 JSONL 事件到文件 | 关闭 |
| `--text` | 输出彩色文本到 stdout | 开启 |
| `--bundle` | 每个事件输出独立目录（含 process/persistence/event JSON） | 关闭 |
| `--whitelist` | 白名单文件路径 | 无 |
| `--max-events` | 每分钟最大事件数（0=不限） | `0` |
| `--yara-rules` | YARA 规则路径，命中后扫描进程 exe | 无 |

```bash
# 基础监控
sudo ./linir watch --iocs ./iocs.txt

# 限时 10 分钟，2 秒轮询，输出 JSONL
sudo ./linir watch --iocs ./iocs.txt --duration 600 --interval 2 --json

# 带白名单和 YARA
sudo ./linir watch --iocs ./iocs.txt --whitelist ./whitelist.txt --yara-rules ./rules/

# 每分钟最多 10 个事件（防刷屏）
sudo ./linir watch --iocs ./iocs.txt --max-events 10
```

**IOC 文件格式：**
```
# 注释行
1.2.3.4
10.0.0.1 c2,apt28
evil.example.com
```

**白名单文件格式：**
```
process:sshd
path:/usr/lib/systemd/
ioc:8.8.8.8
```

**命中事件评分模型：**

| 指标 | 分值 | 说明 |
|---|---|---|
| IOC 命中 | +20 | 基础分 |
| exe 在临时目录 | +25 | 二进制可疑 |
| exe 已被删除 | +15 | 二进制异常 |
| 进程关联持久化 | +20 | 多维关联 |
| YARA 规则命中 | +30 | 规则确认 |
| 进程信息不可见 | +20 | 可见性异常 |
| 二进制不存在 | +15 | 文件异常 |

每个事件输出：IOC、连接详情、进程上下文、二进制哈希、持久化关联、YARA 命中、完整性状态、评分、严重度、可信度、证据列表。

**去重机制：** 同一 IOC + 同一 PID + 同一连接在 60 秒窗口内只报一次。

> watch 模式也集成在 GUI 仪表盘中（"IOC 监控"选项卡），支持在浏览器中输入 IOC 列表、实时查看命中事件流。

---

### `linir gui` — Web 可视化仪表盘

启动本地 HTTP 服务器，在浏览器中打开交互式取证仪表盘。所有数据仅在本机（127.0.0.1），不暴露到网络。

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--port` | HTTP 服务器端口 | `18080` |

```bash
# 启动仪表盘
sudo ./linir gui

# 自定义端口
sudo ./linir gui --port 9090
```

启动后自动打开默认浏览器（macOS 用 `open`，Linux 用 `xdg-open`）。如果无法自动打开，手动访问 `http://127.0.0.1:18080`。

**仪表盘功能：**

| 区域 | 功能 |
|---|---|
| **顶栏** | 一键采集按钮、采集状态指示（等待/进行中/完成/失败）、JSON 导出 |
| **概览卡片** | 风险评分（颜色随严重度变化）、主机可信度、进程/连接/持久化/YARA 计数及可疑数 |
| **证据面板** | 逐条列出评分证据：严重度、域、规则名、描述、分值 |
| **进程表** | PID/PPID/用户/进程名/exe/可疑标记，支持搜索过滤 + "仅显示可疑"勾选 |
| **网络表** | 协议/地址端口/状态/PID/进程名/标记，支持搜索 |
| **持久化表** | 类型/路径/目标/作用域/风险标记，高风险行红色高亮 |
| **完整性** | rootkit 疑似、kernel taint、各类视图不一致、建议操作 |
| **预检** | 自检结果、loader/PATH/环境变量/shell profile 异常 |
| **错误** | 采集过程中的非致命错误 |
| **IOC 监控** | 输入 IOC 列表 → 开始/停止监控 → SSE 实时事件流 → 命中表格（时间/严重度/IOC/PID/进程/评分/证据） |

> GUI 基于 `go:embed` 将 HTML/CSS/JS 打包到二进制中，无额外文件。暗色主题，响应式布局，支持移动端浏览器。

---

## 典型工作流

### 场景一：服务器疑似失陷，快速分诊

```bash
# 1. 上传 linir 到目标机（scp/sftp/USB）
scp linir-linux-amd64 root@target:/tmp/linir

# 2. 在目标机上运行完整采集
ssh root@target
chmod +x /tmp/linir
/tmp/linir collect --bundle --output-dir /tmp/evidence

# 3. 取回证据包
scp root@target:/tmp/evidence/linir-bundle-*.tar.gz ./

# 4. 在分析机上查看 JSON 输出
tar xzf linir-bundle-*.tar.gz
cat linir-*/full.json | jq '.score'
```

### 场景二：带 YARA 规则的深度扫描

```bash
sudo ./linir collect \
  --yara-rules /opt/yara-rules/ \
  --hash-processes \
  --collect-env \
  --bundle \
  --output-dir /evidence/$(hostname)-$(date +%Y%m%d)
```

### 场景三：macOS 桌面可视化分析

```bash
# 在 macOS 上直接打开可视化仪表盘
sudo ./linir gui

# 或通过 SSH 转发在远程 Linux 上使用
ssh -L 18080:127.0.0.1:18080 root@target
# 在 target 上执行：
sudo ./linir gui
# 本地浏览器打开 http://127.0.0.1:18080
```

### 场景四：仅检查主机环境是否可信

```bash
./linir preflight --format text
```

输出示例：
```
Host Trust Level:      low
Loader Anomaly:        LD_PRELOAD=/lib/x86_64-linux-gnu/libhook.so
Shell Profile Anomaly: /etc/profile.d/backdoor.sh: 发现可疑模式 'curl ' (network_download)
```

### 场景五：采集 CSV 用 Excel 做进一步分析

```bash
sudo ./linir collect --format all --output-dir ./evidence
# 生成 JSON + 文本 + 7 个 CSV 表格
# CSV 带 UTF-8 BOM，Excel 双击直接打开不乱码
```

### 场景六：IOC 在线监控

```bash
# 准备 IOC 文件
cat > iocs.txt << 'EOF'
1.2.3.4
10.0.0.1 c2
evil.example.com
EOF

# 监控 10 分钟，带 YARA 和白名单
sudo ./linir watch --iocs iocs.txt --duration 600 --yara-rules ./rules/ --json

# 或在 GUI 中操作：打开仪表盘 → IOC 监控选项卡 → 粘贴 IOC → 开始监控
sudo ./linir gui
```

---

## 输出格式

LinIR 支持四种输出格式：

| 格式 | 文件 | 说明 |
|---|---|---|
| **JSON** | `linir-<主机名>-<ID>.json` | 结构化证据，供 SIEM/AI/自动化分析 |
| **文本** | `linir-<主机名>-<ID>.txt` | 人类可读摘要报告 |
| **CSV** | `linir-<主机名>-<ID>-*.csv` | 7 个 CSV 表格，可直接用 Excel/WPS 打开 |
| **分诊包** | `linir-bundle-<主机名>-<ID>.tar.gz` | 按模块拆分的 JSON 归档 |

### CSV 表格说明

CSV 模式生成以下表格（均带 UTF-8 BOM，Excel 直接打开不乱码）：

| CSV 文件 | 内容 |
|---|---|
| `*-summary.csv` | 概览：主机信息、可信度、风险评分、异常汇总 |
| `*-processes.csv` | 进程表：PID、PPID、用户、进程名、exe 路径、命令行、可疑标记 |
| `*-connections.csv` | 连接表：协议、地址端口、状态、PID、进程名、可疑标记 |
| `*-persistence.csv` | 持久化表：类型、路径、目标、风险标记、解析字段 |
| `*-evidence.csv` | 评分证据表：总分 + 逐条证据明细（域、规则、描述、分值） |
| `*-yara.csv` | YARA 命中表：规则名、目标路径、命中字符串、关联 PID |
| `*-integrity.csv` | 完整性表：各类视图不一致、内核 taint、建议操作 |

```bash
# 生成 CSV 用于 Excel 分析
sudo ./linir collect --format csv

# 同时生成全部格式（JSON + 文本 + CSV）
sudo ./linir collect --format all

# JSON + 文本（默认，向后兼容）
sudo ./linir collect --format both
```

### JSON 结构概览

```json
{
  "version": "v0.1.0",
  "tool_name": "linir",
  "collection_id": "a1b2c3d4-...",
  "started_at": "2025-03-31T12:00:00Z",
  "completed_at": "2025-03-31T12:00:05Z",
  "duration_ms": 5123,
  "host": { "hostname": "web-prod-01", "platform": "linux", ... },
  "self_check": { "collection_confidence": "high", ... },
  "preflight": { "host_trust_level": "medium", ... },
  "processes": [ { "pid": 1234, "name": "python3", "suspicious_flags": ["interpreter", "exe_in_tmp"], ... } ],
  "connections": [ { "proto": "tcp", "local_address": "0.0.0.0", "remote_address": "1.2.3.4", "pid": 1234, ... } ],
  "persistence": [ { "type": "cron", "target": "/tmp/update.sh", "risk_flags": ["target_in_tmp"], ... } ],
  "integrity": { "rootkit_suspected": false, "process_view_mismatch": [], ... },
  "yara_hits": [ { "rule": "webshell_php", "target_path": "/var/www/shell.php", ... } ],
  "score": { "total": 65, "severity": "high", "evidence": [...], "summary": "..." },
  "errors": []
}
```

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
    └── 输出              JSON + 文本 + CSV + 分诊包

linir watch --iocs ./iocs.txt
    │
    ├── 加载 IOC 列表       IP + Domain 自动识别
    ├── 主循环（每 N 秒）
    │     ├── 连接快照       复用 network collector
    │     ├── IOC 比对       IP 直匹配
    │     ├── 去重/频控      窗口 + rate limit + 白名单
    │     └── 命中 → 补采    进程 + 二进制 + 持久化 + YARA + 完整性
    └── 输出                彩色文本 / JSONL / 事件 bundle

linir gui
    │
    ├── HTTP 服务器        127.0.0.1:18080，go:embed 内嵌资源
    ├── /api/collect       POST 触发采集，返回 JSON
    ├── /api/watch/*       IOC 监控（启动/停止/SSE 事件流）
    └── 浏览器仪表盘       暗色主题，响应式，交互式表格 + IOC 监控
```

---

## 已知限制

- **macOS 网络偏移**：`socket_fdinfo` 结构体字段偏移包含两种已知 `vinfo_stat` 大小的自动探测。如果 Apple 在未来版本中更改结构体布局，自动探测可能失败（连接将被跳过并标记 `confidence: low`）。
- **YARA 子集**：不支持完整 PCRE 正则、hex 跳跃通配符（`[4-6]`）、模块（pe, elf, math）、`for` 表达式和规则导入。不支持的特性会优雅降级而非崩溃。
- **Hex 通配符 `??`**：当前简化为 `\x00` 匹配，可能导致漏报。
- **非 root 执行**：非 root 运行会显著降低可见性。受限数据标记为 `confidence: low`。
- **内核级 rootkit**：LinIR 在用户态运行，内核级 rootkit 可以规避检测。建议此类场景通过外部启动介质进行离线取证。

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
