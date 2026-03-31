# LinIR

**Linux/macOS Incident Response & Forensic Collection Tool**

[中文文档](README_CN.md)

---

## What is LinIR?

LinIR is a single-binary, zero-dependency forensic triage tool designed for **compromised or untrusted host environments**. It collects process, network, persistence, and integrity evidence directly from kernel interfaces and filesystem structures — without relying on any commands installed on the target machine.

### The Core Problem

When you land on a potentially compromised Linux or macOS host, you cannot trust:

- `ps`, `top`, `netstat`, `ss`, `lsof` — may have been replaced
- `systemctl`, `launchctl`, `crontab` — output may be filtered
- `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` — may be poisoned
- Shell aliases and functions — may intercept commands
- Dynamic linker — may be hijacked

**LinIR's answer: don't call any of them.** Read `/proc` directly. Parse ELF/Mach-O/plist files directly. Use raw syscalls. Cross-validate across multiple data sources. Report evidence, not conclusions.

---

## Design Principles

| Principle | Description |
|---|---|
| **No external commands** | All collection reads kernel interfaces (`/proc`, `/sys`, `sysctl`) and filesystem structures directly. Never calls `ps`, `netstat`, `lsof`, `systemctl`, `launchctl`, or any shell pipeline. |
| **Zero trust environment** | Assumes PATH is poisoned, LD_PRELOAD is active, binaries are replaced. Self-checks its own execution environment before collecting. |
| **Cross-source validation** | Compares process view, network view, file view, and kernel module view. Inconsistencies are flagged as visibility anomalies. |
| **Evidence over verdicts** | Outputs structured evidence with source attribution and confidence levels. Does not claim "malware found" — reports "these data points are inconsistent". |
| **Static binary, single file** | `CGO_ENABLED=0` static compilation. Drop onto target, run, collect, leave. No runtime dependencies. |

---

## What LinIR Collects

### Self-Check & Preflight

- Binary self-integrity hash
- `LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT` detection
- `DYLD_INSERT_LIBRARIES` and all `DYLD_*` detection
- `/etc/ld.so.preload` content audit
- `/proc/self/exe` path verification and `/proc/self/maps` non-standard library detection
- PATH poisoning detection (relative dirs, temp dirs, world-writable dirs)
- Container / namespace / chroot detection
- Host trust level assessment (high / medium / low)

### Process Collection

| Platform | Data Source | What's Collected |
|---|---|---|
| Linux | `/proc/<pid>/stat`, `status`, `cmdline`, `exe`, `cwd`, `environ`, `fd/*`, `maps` | PID, PPID, name, exe path, cmdline, UID/GID, start time, FD count, socket inodes, mapped libraries |
| macOS | `sysctl kern.proc.all` + `proc_pidpath` (syscall 336) + `KERN_PROCARGS2` | PID, PPID, name, exe path, cmdline, UID, start time |

Suspicious flags automatically set for: deleted executables, executables in `/tmp`, interpreter processes, process name spoofing, fake kernel threads.

### Network Collection

| Platform | Data Source | What's Collected |
|---|---|---|
| Linux | `/proc/net/tcp`, `tcp6`, `udp`, `udp6`, `raw`, `raw6`, `unix` + `/proc/<pid>/fd/*` inode mapping | Protocol, local/remote addr:port, state, PID association via socket inode |
| macOS | `PROC_PIDLISTFDS` + `PROC_PIDFDSOCKETINFO` (syscall 336) | Protocol, local/remote addr:port, TCP state, direct PID association |

### Persistence Collection

| Type | Linux Sources | macOS Sources |
|---|---|---|
| Service manager | systemd units (`ExecStart`, `User`, `WantedBy`, `Environment`) | LaunchDaemons/Agents plist (`Label`, `Program`, `ProgramArguments`, `RunAtLoad`) |
| Scheduled tasks | `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`, cron.daily/hourly/weekly | via LaunchAgents |
| Shell profiles | `/etc/profile`, `/etc/bash.bashrc`, `/etc/profile.d/*`, `~/.bashrc`, `~/.zshrc` | `/etc/zshrc`, `~/.zshrc`, `~/.bash_profile` |
| SSH | `~/.ssh/authorized_keys`, `sshd_config` | Same |
| Preload | `/etc/ld.so.preload` | `DYLD_INSERT_LIBRARIES` in profiles |
| Boot | `/etc/rc.local` | — |

Risk flags: `target_in_tmp`, `target_missing`, `downloads_from_network`, `pipe_to_shell`, `dev_tcp_reverse_shell`, `base64_usage`, `system_wide_preload`, `impersonates_apple`, `forced_command`, `world_writable`.

### Integrity / Anti-Rootkit Checks

- **Process view mismatch**: PPID references non-existent process, exe deleted, exe unreadable with cmdline present
- **Network view mismatch**: Connection has no owning process, PID not in process list
- **File view mismatch**: Persistence target file missing from disk
- **Module view mismatch** (Linux): `/proc/modules` vs `/sys/module` inconsistency
- **Kernel taint** (Linux): Non-zero taint flags with bit-level decoding

### YARA Scanning

Built-in pure-Go YARA engine (no libyara dependency). Supported condition subset:

```yara
condition: any of them
condition: all of them
condition: 2 of them
condition: $s1 and $s2
condition: $s1 or ($s2 and $s3)
condition: not $s1
condition: #s1 > 3          // match count
condition: @s1 < 100        // first match offset
condition: filesize < 1MB
condition: $s1 at 0         // exact offset
condition: $s1 in (0..1024) // offset range
condition: any of ($s*)     // wildcard set
```

Smart target selection: automatically scans executables of networked processes, persistence targets, and files in `/tmp`, `/var/tmp`, `/dev/shm`.

### Scoring

Weighted evidence scoring model with 14 built-in rules:

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

## Usage

### Full Collection

```bash
# Run as root for full visibility
sudo ./linir collect --format json --output-dir ./evidence

# With YARA rules
sudo ./linir collect --format both --yara-rules ./rules/ --output-dir ./evidence

# Force collection even if preflight fails
sudo ./linir collect --force --bundle
```

### Individual Subcommands

```bash
sudo ./linir preflight --format json           # Environment trust assessment
sudo ./linir process --hash-processes           # Process collection
sudo ./linir network --format json              # Network connections
sudo ./linir persistence                        # Persistence enumeration
sudo ./linir integrity                          # Anti-rootkit checks
sudo ./linir yara --rules ./rules/ --proc-linked  # YARA scan (auto targets)
sudo ./linir yara --rules ./rules/ --target /tmp   # YARA scan (specific dir)
sudo ./linir bundle --output-dir ./evidence     # Export triage bundle
```

### Global Flags

```
-o, --output-dir string   Output directory (default ".")
    --format string        Output format: json, text, both (default "both")
    --bundle               Create triage bundle (tar.gz)
    --force                Proceed despite preflight failures
-v, --verbose              Verbose output
-q, --quiet                Suppress non-error output
    --timeout int          Global timeout in seconds (default 300)
```

### Output Formats

1. **JSON** (`linir-<hostname>-<id>.json`) — Structured evidence for SIEM/AI/automation
2. **Text** (`linir-<hostname>-<id>.txt`) — Human-readable summary
3. **Bundle** (`linir-bundle-<hostname>-<id>.tar.gz`) — Tar archive with per-section JSON files

---

## Build from Source

```bash
git clone https://github.com/dogadmin/LinIR.git
cd LinIR

# Build for current platform
CGO_ENABLED=0 go build -o linir ./cmd/linir

# Cross-compile
make build-linux          # Linux amd64
make build-linux-arm64    # Linux arm64
make build-darwin          # macOS Intel
make build-darwin-arm64    # macOS Apple Silicon
make build-all             # All platforms
```

### Supported Platforms

| Platform | Architectures | Process | Network | Persistence |
|---|---|---|---|---|
| **Linux** | amd64, arm64, 386, armv7, mips64le, ppc64le, s390x, riscv64 | Full | Full | Full |
| **macOS** | amd64, arm64 | Full | Full | Full |
| **FreeBSD** | amd64, arm64 | Stub | Stub | Stub |
| **OpenBSD** | amd64 | Stub | Stub | Stub |
| **NetBSD** | amd64 | Stub | Stub | Stub |

---

## Architecture

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
    ├── Correlator          Process↔Network↔Persistence linking
    ├── YARA Scanner        File scanning with condition evaluation
    ├── Evidence Scorer     Weighted scoring with 14 rules
    │
    └── Output              JSON + Text + Bundle
```

---

## Known Limitations

- **macOS network offsets**: The `socket_fdinfo` struct field offsets include auto-probing for two known `vinfo_stat` sizes. If Apple changes the struct layout, the probe may fail (connections skipped with `confidence: low`).
- **YARA subset**: Full PCRE regex, hex jump wildcards (`[4-6]`), modules (pe, elf, math), `for` expressions, and rule imports are not supported. Unsupported features degrade gracefully.
- **Hex wildcard `??`**: Currently simplified to `\x00` match. May cause false negatives.
- **Non-root execution**: Significantly reduced visibility. LinIR marks limited-access data with `confidence: low`.
- **Kernel-level rootkits**: LinIR operates in userspace. Kernel-level rootkits manipulating `/proc` at the kernel level can evade detection. Offline forensic analysis is recommended for such scenarios.

---

## Dependencies

| Dependency | Purpose | CGO |
|---|---|---|
| `github.com/spf13/cobra` | CLI framework | No |
| `github.com/google/uuid` | Collection ID | No |
| `howett.net/plist` | macOS plist parsing | No |
| `golang.org/x/sys` | syscall wrappers | No |

All pure Go. Fully statically compiled with `CGO_ENABLED=0`.

---

## Disclaimer

**LinIR is provided "AS IS" without warranty of any kind, express or implied.** The authors and contributors are not responsible for any damages, data loss, legal consequences, or other liabilities arising from the use or misuse of this tool.

**This tool is intended for authorized security assessments, incident response, digital forensics, and educational purposes only.** Users are solely responsible for ensuring they have proper authorization before deploying this tool on any system. Unauthorized access to computer systems is illegal in most jurisdictions.

**LinIR does not modify, delete, or alter any data on the target system.** It operates in a read-only manner. However, running any forensic tool on a live system may alter volatile evidence (memory, timestamps, process state).

**The output should not be treated as definitive proof of compromise or security.** It provides structured evidence and anomaly indicators that require professional interpretation. False positives and false negatives are possible.

**The authors do not endorse or encourage any illegal activities.** This tool is released for the benefit of the security community.

---

## License

MIT License

## Contributing

Issues and pull requests are welcome at https://github.com/dogadmin/LinIR.
