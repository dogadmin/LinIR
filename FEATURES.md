# LinIR 功能清单与评分规则

> 版本：v0.0.4 | 更新日期：2026-04-01

---

## 一、命令行工具

### 全局参数

| 参数 | 短写 | 说明 | 默认值 |
|---|---|---|---|
| `--output-dir` | `-o` | 输出目录 | `.` |
| `--format` | | `json` / `text` / `csv` / `both` / `all` | `both` |
| `--bundle` | | 生成 tar.gz 分诊包 | 关闭 |
| `--force` | | 预检失败也继续采集 | 关闭 |
| `--verbose` | `-v` | 详细日志 | 关闭 |
| `--quiet` | `-q` | 抑制标准输出 | 关闭 |
| `--timeout` | | 全局超时（秒） | `300` |

### 子命令

| 命令 | 参数 | 说明 |
|------|------|------|
| `collect` | `--hash-processes`, `--collect-env`, `--yara-rules` | 完整采集（自检→预检→进程→网络→持久化→完整性→关联→YARA→评分→输出） |
| `process` | `--hash-processes`, `--collect-env` | 仅采集进程 |
| `network` | 无 | 仅采集网络连接 |
| `persistence` | 无 | 仅枚举持久化机制 |
| `integrity` | 无 | 跨数据源完整性检查 |
| `preflight` | 无 | 仅执行环境可信度评估 |
| `yara` | `--rules`(必填), `--target`, `--proc-linked` | YARA 规则扫描 |
| `watch` | 见下表 | IOC 在线监控 |
| `bundle` | 无 | 等价 `collect --bundle` |
| `gui` | `--host`, `--port` | Web 可视化仪表盘 |

### watch 参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--iocs` | IOC 列表文件（必填） | 无 |
| `--duration` | 监控时长（秒），0=无限 | `0` |
| `--interval` | 轮询间隔（秒） | `1` |
| `--json` | 输出 JSONL 到文件 | 关闭 |
| `--text` | 输出彩色文本到 stdout | 开启 |
| `--bundle` | 输出事件 bundle 目录 | 关闭 |
| `--whitelist` | 白名单文件 | 无 |
| `--max-events` | 每分钟最大事件数 | `0` |
| `--yara-rules` | YARA 规则路径 | 无 |
| `--iface` | 网络接口（空=自动） | 自动 |

### gui 参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--host` | 监听地址（`0.0.0.0` 允许外部访问） | `127.0.0.1` |
| `--port` | HTTP 端口 | `18080` |

---

## 二、采集能力

### 自检与预检

- 自身二进制完整性哈希
- `LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT` 检测
- `DYLD_INSERT_LIBRARIES` 及全系列 `DYLD_*` 检测
- `/etc/ld.so.preload` 内容审计
- `/proc/self/exe` 路径验证
- PATH 污染检测
- 容器/命名空间/chroot 检测
- 主机可信度评估（high / medium / low）

### 进程采集

| 平台 | 数据源 | 采集内容 |
|---|---|---|
| Linux | `/proc/<pid>/stat`、`status`、`cmdline`、`exe`、`cwd`、`environ`、`fd/*`、`maps` | PID、PPID、进程名、exe 路径、命令行、UID/GID、启动时间、FD 数量、socket inode、映射库 |
| macOS | `sysctl kern.proc.all` + `proc_pidpath` + `KERN_PROCARGS2` | PID、PPID、进程名、exe 路径、命令行、UID、启动时间 |

### 网络采集

| 平台 | 数据源 | 采集内容 |
|---|---|---|
| Linux | `/proc/net/tcp`、`tcp6`、`udp`、`udp6`、`raw`、`raw6`、`unix` + inode→PID 映射 + `/proc/<pid>/comm` 进程名 | 协议、地址:端口、状态、PID、进程名。IPv4-mapped IPv6 自动归一化 |
| macOS | `proc_pidfdinfo`（PID 关联）+ `sysctl pcblist_n`（全局视图） | 协议、地址:端口、TCP 状态、PID + 进程名 |

### 持久化采集

| 类型 | Linux | macOS |
|---|---|---|
| 服务管理 | systemd 单元文件 | LaunchDaemons/Agents plist |
| 定时任务 | crontab、cron.d、cron.daily/hourly/weekly | 同左 |
| Shell 配置 | `/etc/profile`、`/etc/bash.bashrc`、`~/.bashrc`、`~/.zshrc` 等 | `/etc/zshrc`、`~/.zshrc`、`~/.bash_profile` 等 |
| SSH | `authorized_keys`、`sshd_config` | 同左 |
| 预加载 | `/etc/ld.so.preload` | profile 中 `DYLD_INSERT_LIBRARIES` |
| 启动项 | `/etc/rc.local` | — |

### 完整性检查

- 进程视图不一致（PPID 不存在、exe 已删除/不可读）
- 网络视图不一致（连接无归属进程，排除终止态连接）
- 文件视图不一致（持久化目标缺失）
- 模块视图不一致（Linux：`/proc/modules` vs `/sys/module`）
- 内核 taint 状态（Linux）
- Rootkit 综合判定（权重阈值模型）

### YARA 扫描

- 纯 Go 实现，不依赖 libyara
- 支持 condition 子集：`any of them`、`all of them`、`N of them`、逻辑运算、偏移匹配、文件大小、通配符集合
- 按 `severity_hint` 4 级分层：low / medium / high / critical
- 智能目标选择：联网进程 exe、持久化目标、临时目录文件

---

## 三、IOC 在线监控

### 三层监控模式

| 层级 | Linux | macOS | 特点 |
|---|---|---|---|
| 层 1 | conntrack netlink 事件驱动 | BPF /dev/bpf 抓包（TCP SYN + UDP） | 零遗漏，需 root |
| 层 2 | /proc/net/nf_conntrack 轮询 | — | RST 保留 ~10s |
| 层 3 | /proc/net/tcp 轮询 | proc_pidfdinfo + sysctl 轮询 | 通用回退 |

### PID 解析策略

1. **快速定向查找**：`/proc/net/tcp` 找 inode → 从高 PID 向低搜索 `/proc/<pid>/fd/`（~10-50ms）
2. **多次重试**：Linux 4 次 × 50ms 间隔，macOS 1 次（全量扫描太慢）
3. **pending 队列**：PID=0 事件暂存，等下次轮询用 `CollectConnections` 数据补全（5 元组匹配）
4. **超时回退**：5 秒未解析则以 PID=0 发出
5. **ProcessName 回退**：进程已退出但连接上记录了 `/proc/<pid>/comm` 的进程名

### 去重机制

- 基于完整 5 元组（`proto:localAddr:localPort:remoteAddr:remotePort`）+ IOC 值
- 每个真实连接是独立事件
- PID=0 事件使用 5 秒短窗口，不阻塞后续带 PID 的事件
- 频率限制（`--max-events`）+ 白名单过滤

### 观测计数器（WatchMetrics）

| 计数器 | 说明 |
|--------|------|
| `RawEventsTotal` | 平台 watcher 原始事件数 |
| `IOCMatchedTotal` | IOC 匹配命中数 |
| `PIDResolvedImmediate` | 快速解析成功数 |
| `PIDResolvedDeferred` | pending 队列延迟解析成功数 |
| `PIDUnresolved` | 超时未解析数 |
| `OutputEmitted` | 最终输出事件数 |
| `OutputDeduped` | 被去重压制数 |
| `OutputRateLimited` | 被频控压制数 |
| `PendingCurrent` | 当前 pending 队列长度 |
| `EventChannelOverflow` | channel 满溢丢弃数 |

---

## 四、Collect 评分规则

总分 0-100，上限 100。干净系统应得 0 分。

### 严重度分级

| 总分 | 严重度 |
|------|--------|
| 0-19 | info |
| 20-39 | low |
| 40-59 | medium |
| 60-79 | high |
| 80-100 | critical |

### 进程域（process）

| 规则 ID | 触发条件 | 分值 | 严重度 |
|---------|----------|------|--------|
| `exe_in_tmp` | exe 在 `/tmp/`、`/var/tmp/`、`/dev/shm/`、`/private/tmp/` | +10 | low |
| `exe_in_tmp_networked` | exe_in_tmp 且有 ESTABLISHED/SYN_SENT 连接 | +10 | medium |
| `exe_in_tmp_interpreter` | exe_in_tmp 且进程为 bash/sh/zsh/python/perl/ruby/php/node | +5 | medium |
| `exe_deleted` | exe 已从磁盘删除 | +5 | low |
| `exe_deleted_networked` | exe_deleted 且有活跃连接 | +5 | medium |
| `webshell_indicator_strong` | Web 服务（apache/nginx/httpd 等）派生 shell 且有活跃连接 | +25 | high |
| `webshell_indicator_weak` | Web 服务派生 shell，无网络连接 | +10 | medium |
| `fake_kthread` | 进程名 `[xxx]` 但 PPID≠2 | +10 | medium |
| `fake_kthread_networked` | fake_kthread 且有活跃连接 | +10 | high |
| `persistent_networked` | 进程同时关联持久化项和网络连接 | +10 | medium |
| `persistent_networked_abnormal_path` | persistent_networked 且 exe 在临时目录 | +5 | high |

### 网络域（network）

| 规则 ID | 触发条件 | 分值 | 严重度 |
|---------|----------|------|--------|
| `suspicious_port` | 连接到端口 4444（metasploit）或 31337（elite） | +5 | low |
| *(orphan_connections)* | >3 个无归属活跃连接 | **+0** | — |

> orphan_connections 不直接加恶意分，进入 `IntegrityFlags` 并降低 `confidence`。

### 持久化域（persistence）

| 规则 ID | 触发条件 | 分值 | 严重度 |
|---------|----------|------|--------|
| `persist_in_tmp` | 持久化目标在临时目录 | +15 | medium |
| `persist_in_tmp_active` | 上述且目标当前运行 | +10 | high |
| `persist_in_tmp_active_net` | 上述且目标有网络连接 | +10 | high |
| `global_ld_preload_present` | `/etc/ld.so.preload` 存在且非空 | +15 | medium |
| `preload_path_abnormal` | preload 目标在临时目录或不存在 | +10 | high |
| `reverse_shell_strong` | 持久化文件含 `/dev/tcp` 反弹 shell 模式 | +25 | critical |
| `reverse_shell_active` | 上述且目标当前运行 | +10 | critical |
| `pipe_shell` | 持久化文件含 `curl|sh` / `wget|bash` | +8 | low |
| `pipe_shell_active` | 上述且目标当前运行 | +8 | medium |
| `profile_ld_preload` | shell profile 设置 `LD_PRELOAD` | +15 | medium |
| `profile_dyld_insert` | shell profile 设置 `DYLD_INSERT_LIBRARIES` | +15 | medium |
| `systemd_env_ld_preload` | systemd unit Environment 含 `LD_PRELOAD` | +15 | medium |
| `persist_active_net` | 持久化目标运行且联网 | +10 | medium |
| `persist_active_net_abnormal` | 上述且路径异常或命中 YARA | +10 | high |

### 完整性域（integrity）

| 规则 ID | 触发条件 | 分值 | 严重度 | 额外效果 |
|---------|----------|------|--------|----------|
| `rootkit_suspected` | 多项可见性异常权重≥50 | +15 | high | `confidence=low`, IntegrityFlag |
| `module_mismatch` | `/proc/modules` vs `/sys/module` 不一致 | +15 | high | IntegrityFlag |
| `host_trust_low_loader` | 主机可信度 low 且有 loader 劫持 | +10 | medium | — |
| *(host_trust_low)* | 主机可信度 low | **+0** | — | `confidence=low`, IntegrityFlag |

### YARA 域（yara）

| 规则 ID | 触发条件 | 分值 | 严重度 |
|---------|----------|------|--------|
| `yara_hit_critical` | severity_hint=critical | +25 | critical |
| `yara_hit_high` | severity_hint=high | +20 | high |
| `yara_hit_medium` | severity_hint=medium | +15 | medium |
| `yara_hit_low` | 其他/未指定 | +10 | low |
| `yara_on_active_process` | 命中目标为活跃联网进程 | +5 | high |
| `yara_abnormal_path_bonus` | 命中目标在临时目录 | +5 | high |
| `yara_on_persistence_target` | 命中目标为持久化对象 | +5 | high |

### 组合增强项（combo）

| 规则 ID | 触发条件 | 分值 | 严重度 |
|---------|----------|------|--------|
| `combo_tmp_exec_and_yara` | exe_in_tmp + YARA 命中 | +10 | high |
| `combo_tmp_exec_and_persist` | exe_in_tmp + 持久化联网 | +10 | high |
| `combo_deleted_and_persist` | exe_deleted + 持久化 | +10 | high |
| `combo_webshell_and_network` | Webshell 强指标 + 活跃连接 | +10 | critical |
| `combo_preload_and_active_process` | preload 存在 + 路径异常 | +10 | critical |
| `combo_persistence_yara_network` | 持久化 + YARA + 网络 | +15 | critical |
| `combo_rootkit_plus_active_suspicious` | rootkit 嫌疑 + 活跃可疑进程 | +10 | critical |

### Rootkit 判定权重

| 数据源 | 每项权重 |
|--------|----------|
| ProcessViewMismatch | ×10 |
| NetworkViewMismatch（排除终止态） | ×3 |
| FileViewMismatch | ×3 |
| ModuleViewMismatch | ×15 |
| VisibilityAnomalies | ×10 |

- 阈值：≥50 → `RootkitSuspected = true`
- 任何 `ModuleViewMismatch > 0` → 直接 `true`

### Confidence 规则

| 条件 | 效果 |
|------|------|
| `host_trust_low` | confidence → low |
| `rootkit_suspected` | confidence → low |
| orphan_connections > 3 | confidence → medium |

---

## 五、Watch 评分规则

每个 IOC 命中事件独立评分。总分 0-100，严重度分级同 collect。

### 基础规则

| 规则 ID | 触发条件 | 分值 | 严重度 |
|---------|----------|------|--------|
| `ioc_hit` | IOC 命中（每个事件必有） | +20 | medium |

### 进程/二进制域

| 规则 ID | 触发条件 | 分值 | 严重度 |
|---------|----------|------|--------|
| `exe_in_tmp` | 命中进程 exe 在临时目录 | +10 | low |
| `exe_in_tmp_interpreter` | 上述且为 shell/interpreter | +10 | medium |
| `exe_deleted` | 命中进程 exe 已删除 | +5 | low |
| `webshell_strong` | Web 服务器派生 shell | +25 | high |
| `process_invisible` | PID>0 但进程信息不可见 | +5 | low |
| `binary_in_tmp` | 二进制在临时目录 | +10 | low |
| `binary_missing` | 二进制文件不存在 | +5 | low |

### 持久化域

| 规则 ID | 触发条件 | 分值 | 严重度 |
|---------|----------|------|--------|
| `persistence_linked` | 进程关联到持久化项 | +10 | medium |
| `persistence_linked_abnormal` | 持久化目标路径异常 | +5 | high |

### YARA 域

| 规则 ID | severity_hint | 分值 | 严重度 |
|---------|---------------|------|--------|
| `yara_hit_critical` | critical | +25 | critical |
| `yara_hit_high` | high | +20 | high |
| `yara_hit_medium` | medium | +15 | medium |
| `yara_hit_low` | 其他 | +10 | low |
| `yara_on_tmp_binary` | 命中临时目录目标 | +5 | high |

### 组合增强项

| 规则 ID | 触发条件 | 分值 | 严重度 |
|---------|----------|------|--------|
| `combo_ioc_tmp_exec` | IOC + 临时目录执行 | +10 | high |
| `combo_ioc_deleted_exec` | IOC + 已删除 exe | +5 | medium |
| `combo_ioc_persistence` | IOC + 持久化关联 | +10 | high |
| `combo_ioc_yara` | IOC + YARA 高危命中 | +10 | high |
| `combo_ioc_webshell` | IOC + Webshell | +15 | critical |
| `combo_ioc_persist_yara` | IOC + 持久化 + YARA | +15 | critical |

### Watch Confidence 规则

| 条件 | 效果 |
|------|------|
| `host_trust_level = low` | confidence → low |
| 进程信息不可见（PID>0 但 FindProcess 失败） | confidence → medium |
| PID = 0（未解析） | confidence → medium |

---

## 六、进程/网络/持久化可疑标记来源

### 进程标记（SuspiciousFlags）

| 标记 | 设置位置 | 条件 |
|------|----------|------|
| `exe_in_tmp` | collector (Linux/macOS) | exe 在临时目录 |
| `exe_deleted` | collector (Linux) | exe readlink 含 "(deleted)" |
| `interpreter` | collector (macOS) | 进程名为 python/perl/ruby/bash 等 |
| `webserver_spawned_shell` | process analyzer | Web 服务父进程派生 shell 子进程 |
| `fake_kernel_thread` | process analyzer | 进程名 `[xxx]` 但 PPID≠2 |
| `persistent_and_networked` | correlator | 进程关联持久化项且有 ESTABLISHED 连接 |

### 网络标记（SuspiciousFlags）

| 标记 | 设置位置 | 条件 |
|------|----------|------|
| `orphan_active_connection` | network analyzer | PID=0, inode≠0, ESTABLISHED/LISTEN |
| `suspicious_remote_port:metasploit_default` | network analyzer | 远端端口 4444 |
| `suspicious_remote_port:elite_backdoor` | network analyzer | 远端端口 31337 |

### 持久化标记（RiskFlags）

| 标记 | 设置位置 | 条件 |
|------|----------|------|
| `target_in_tmp` | collector | 目标在临时目录 |
| `target_missing` | collector | 目标文件不存在 |
| `system_wide_preload` | collector | `/etc/ld.so.preload` 条目 |
| `dev_tcp_reverse_shell` | collector | 含 `/dev/tcp/` |
| `pipe_to_shell` | collector | curl/wget 管道到 bash/sh |
| `ld_preload_export` | collector | shell profile 含 `export LD_PRELOAD` |
| `dyld_inject_export` | collector | shell profile 含 `export DYLD_INSERT` |
| `ld_preload_in_env` | collector | systemd unit Environment 含 LD_PRELOAD |
| `world_writable` | collector | 文件权限 0002 |
| `forced_command` | collector | SSH authorized_keys 含 command= |
| `loose_permissions` | collector | SSH 文件权限 & 0077 ≠ 0 |
| `target_currently_running` | correlator | 持久化目标正在运行 |
| `target_running_with_network` | correlator | 目标运行且有网络连接 |
| `target_running_from_tmp` | correlator | 目标从临时目录运行 |

---

## 七、输出格式

| 格式 | 文件 | 说明 |
|------|------|------|
| JSON | `linir-<主机>-<ID>.json` | 结构化证据，供 SIEM/AI 分析 |
| 文本 | `linir-<主机>-<ID>.txt` | 人类可读摘要 |
| CSV | `linir-<主机>-<ID>-*.csv` | 7 个 CSV（summary/processes/connections/persistence/evidence/yara/integrity） |
| 分诊包 | `linir-bundle-<主机>-<ID>.tar.gz` | 按模块拆分的 JSON 归档 |

---

## 八、支持平台

| 平台 | 架构 | 进程 | 网络 | 持久化 |
|---|---|---|---|---|
| Linux | amd64, arm64, 386, armv7, mips64le, ppc64le, s390x, riscv64 | 完整 | 完整 | 完整 |
| macOS | amd64, arm64 | 完整 | 完整 | 完整 |
| FreeBSD | amd64, arm64 | 桩 | 桩 | 桩 |
| OpenBSD | amd64 | 桩 | 桩 | 桩 |
| NetBSD | amd64 | 桩 | 桩 | 桩 |

---

## 九、GUI 仪表盘

- 一键采集 + 实时状态
- 风险评分卡片（颜色随严重度变化）
- 主机可信度指示
- 交互式进程/网络/持久化表格（搜索/过滤/可疑高亮）
- 评分证据逐条展开（域、规则、描述、分值）
- 完整性检查结果 + 预检异常
- IOC 监控选项卡（SSE 实时事件流、来源阶段、PID 解析状态标签）
- YARA 扫描（文件浏览器默认 CWD）
- JSON 导出
- 暗色主题，响应式布局，`go:embed` 内嵌

---

## 十、安全设计

- **零系统命令依赖**：IOC watch 主路径无任何 `exec.Command`
- **不调用外部命令**：不调用 ps/netstat/ss/lsof/systemctl/launchctl
- **底层原生接口**：直接读 `/proc`、`sysctl`、`proc_pidfdinfo`、BPF
- **多源交叉验证**：进程/网络/文件/模块视图对比
- **静态编译**：`CGO_ENABLED=0`，单文件，零运行时依赖
