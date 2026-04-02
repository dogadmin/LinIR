# LinIR

**Linux/macOS Incident Response & Forensic Collection Tool**

[中文文档](README.md)

---

## Overview

LinIR is a single-binary, zero-dependency forensic triage tool for **compromised or untrusted host environments**. It collects process, network, persistence, and integrity evidence directly from kernel interfaces — without calling any commands installed on the target.

**Principles:** No external commands · Zero trust · Cross-source validation · Evidence over verdicts · Static single binary

---

## Quick Start

```bash
sudo ./linir collect                                        # Full collection
sudo ./linir collect --timeline                             # Three-state analysis + timeline
sudo ./linir collect --yara-rules /opt/rules/ --bundle      # With YARA + bundle
sudo ./linir watch --iocs ./iocs.txt                        # IOC monitoring
sudo ./linir gui                                            # Web dashboard with AI analysis
```

---

## Three-Dimensional State Model (v0.2.0)

LinIR answers three questions simultaneously:

| Dimension | Question | Sources |
|-----------|----------|---------|
| **Runtime** | What is happening now? | Processes, connections, active persistence, YARA hits |
| **Retained** | What traces were left behind? | File timeline, persistence changes, deleted exe, auth history, logs |
| **Triggerable** | What will execute next? | Autostart services, scheduled tasks, KeepAlive/Restart mechanisms |

A unified timeline merges all three states into a chronological attack chain view.

```bash
sudo ./linir retained --window 48h    # Historical traces only
sudo ./linir triggerable              # Future execution paths only
sudo ./linir timeline                 # Full unified timeline
sudo ./linir collect --timeline       # All-in-one
```

---

## Command Reference

### Global Flags

| Flag | Short | Description | Default |
|---|---|---|---|
| `--output-dir` | `-o` | Output directory | `.` |
| `--format` | | `json` / `text` / `csv` / `both` / `all` | `both` |
| `--bundle` | | Generate tar.gz triage bundle | off |
| `--force` | | Continue despite preflight failures | off |
| `--verbose` | `-v` | Verbose logging | off |
| `--quiet` | `-q` | Suppress stdout | off |
| `--timeout` | | Global timeout (seconds) | `300` |

### Subcommands

| Command | Description | Extra Flags |
|---------|-------------|-------------|
| `collect` | Full forensic pipeline | `--with-retained` `--with-triggerable` `--timeline` `--retained-window` |
| `retained` | Historical trace collection | `--window` |
| `triggerable` | Future execution path enumeration | — |
| `timeline` | Full unified timeline | `--window` |
| `preflight` | Environment trust check only | — |
| `process` | Process collection only | `--hash-processes` `--collect-env` |
| `network` | Network connections only | — |
| `persistence` | Persistence enumeration only | — |
| `integrity` | Cross-source visibility checks | — |
| `yara` | YARA scanning | `--rules`(required) `--target` `--proc-linked` |
| `watch` | Real-time IOC monitoring | `--iocs` `--duration` `--interval` etc. |
| `gui` | Web dashboard | `--host` `--port` |

---

## Collection Capabilities

| Domain | Linux | macOS |
|--------|-------|-------|
| **Process** | `/proc/<pid>/*` (stat, cmdline, exe, fd, maps) | sysctl + proc_pidpath + KERN_PROCARGS2 |
| **Network** | `/proc/net/tcp*`, `udp*`, `raw*` + inode→PID | proc_pidfdinfo + sysctl pcblist_n |
| **Persistence** | systemd, cron, shell profiles, SSH, ld.so.preload | LaunchDaemons/Agents, cron, profiles, SSH |
| **Integrity** | Process/network/file/module cross-validation, kernel taint | Process/network/file cross-validation |
| **Retained** | File timeline, persistence mtime/ctime, wtmp/btmp, auth.log, syslog | File timeline, plist mtime, system.log |
| **Triggerable** | Enabled systemd, timers, cron, Restart=always, SSH forced command | RunAtLoad, KeepAlive, StartInterval, cron |
| **YARA** | Pure Go engine, condition subset | Same |

---

## IOC Monitoring

| Tier | Linux | macOS |
|---|---|---|
| 1 | conntrack netlink (event-driven) | BPF /dev/bpf (TCP SYN + UDP) |
| 2 | /proc/net/nf_conntrack | — |
| 3 | /proc/net/tcp polling | proc_pidfdinfo + sysctl polling |

---

## Scoring

**Design:** Single-clue low scores · Combo escalation · Confidence separation · Suppress mechanism · Clean system scores zero

| Indicator | Base | Combo | Severity |
|---|---|---|---|
| exe in /tmp | +10 | +networked +10, +interpreter +5 | low→medium |
| exe deleted (file truly gone) | +5 | +networked +5 | low→medium |
| Web shell (strong) | +25 | +network = strong | high |
| Persistence in /tmp | +15 | +active +10, +networked +10 | medium→high |
| /dev/tcp reverse shell | +25 | +active +10 | critical |
| YARA hit | +10~+25 | +active process +5 | by severity |
| Cross-state combo | +8~+10 | Requires additional suspicious indicator | medium→high |

**Suppress:** Package manager child → half score. Deleted exe still at path (package upgrade) → not flagged. Legitimate tmp paths (systemd-private/snap/go-build) → not flagged.

---

## GUI Dashboard

```bash
sudo ./linir gui                    # Local only
sudo ./linir gui --host 0.0.0.0     # Public access
```

Features:
- One-click collection / Three-state analysis
- Risk score cards · Interactive tables · Evidence breakdown
- Retained / Triggerable / Timeline tabs
- **AI Analysis** (MiniMax M2.5/M2.7): One-click comprehensive analysis, preset prompts (intrusion detection, backdoor hunting, lateral movement, data exfiltration, persistence analysis, remediation), multi-turn chat
- IOC real-time monitoring (SSE) · YARA scanning
- JSON / CSV export · API token auth · Dark theme

---

## Output Formats

| Format | File | Use |
|---|---|---|
| JSON | `linir-<host>-<id>.json` | SIEM / automation |
| Text | `linir-<host>-<id>.txt` | Human-readable |
| CSV | `linir-<host>-<id>-*.csv` | Excel analysis |
| Bundle | `linir-bundle-<host>-<id>.tar.gz` | Archive |
| Analysis | `linir-analysis-<host>-<id>.*` | Includes retained/triggerable/timeline |

---

## Build

```bash
git clone https://github.com/dogadmin/LinIR.git && cd LinIR
CGO_ENABLED=0 go build -o linir ./cmd/linir
make build-all  # All platforms
```

| Platform | Architectures | Status |
|---|---|---|
| **Linux** | amd64, arm64, 386, armv7, mips64le, ppc64le, s390x, riscv64 | Full |
| **macOS** | amd64, arm64 | Full |

---

## Dependencies

All pure Go. Fully statically compiled with `CGO_ENABLED=0`.

| Dependency | Purpose |
|---|---|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/google/uuid` | Collection ID |
| `howett.net/plist` | macOS plist parsing |
| `golang.org/x/sys` | syscall wrappers |
| `github.com/ti-mo/conntrack` | Linux conntrack monitoring |

---

## Limitations

- macOS network offsets: multi-version auto-probing, unreliable PIDs auto-zeroed
- YARA subset: no full PCRE, hex jumps, modules
- Non-root: significantly reduced visibility
- Kernel rootkits: userspace limitation, recommend offline forensics

---

## Disclaimer

LinIR is provided "AS IS". For authorized security assessments, incident response, and digital forensics only. Read-only operation.

## License

MIT License

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=dogadmin/LinIR&type=Date)](https://star-history.com/#dogadmin/LinIR&Date)
