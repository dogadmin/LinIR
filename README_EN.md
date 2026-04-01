# LinIR

**Linux/macOS Incident Response & Forensic Collection Tool**

[中文文档](README.md) | [Full Feature List & Scoring Rules](FEATURES.md)

---

## Overview

LinIR is a single-binary, zero-dependency forensic triage tool for **compromised or untrusted host environments**. It collects process, network, persistence, and integrity evidence directly from kernel interfaces — without calling any commands installed on the target.

**Principles:** No external commands · Zero trust · Cross-source validation · Evidence over verdicts · Static single binary

---

## Quick Start

```bash
sudo ./linir collect                                    # Full collection
sudo ./linir collect --yara-rules /opt/rules/ --bundle  # With YARA + bundle
sudo ./linir watch --iocs ./iocs.txt                    # IOC monitoring
sudo ./linir gui                                        # Web dashboard
sudo ./linir preflight --format text                    # Environment check
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
| `collect` | Full forensic pipeline | `--hash-processes` `--collect-env` `--yara-rules` |
| `preflight` | Environment trust check only | — |
| `process` | Process collection only | `--hash-processes` `--collect-env` |
| `network` | Network connections only | — |
| `persistence` | Persistence enumeration only | — |
| `integrity` | Cross-source visibility checks | — |
| `yara` | YARA scanning | `--rules`(required) `--target` `--proc-linked` |
| `bundle` | Equivalent to `collect --bundle` | — |
| `watch` | Real-time IOC monitoring | See below |
| `gui` | Web dashboard | `--host` `--port` |

### watch Flags

| Flag | Description | Default |
|---|---|---|
| `--iocs` | IOC list file (required) | — |
| `--duration` | Monitor duration (seconds), 0=unlimited | `0` |
| `--interval` | Polling interval (seconds) | `1` |
| `--json` | Output JSONL events | off |
| `--text` | Output colored text | on |
| `--bundle` | Per-event bundle directories | off |
| `--whitelist` | Whitelist file | — |
| `--max-events` | Max events/minute | `0` |
| `--yara-rules` | YARA rules for hit scanning | — |
| `--iface` | Network interface | auto |

### gui Flags

| Flag | Description | Default |
|---|---|---|
| `--host` | Listen address (`0.0.0.0` for external) | `127.0.0.1` |
| `--port` | HTTP port | `18080` |

---

## Collection Capabilities

| Domain | Linux | macOS |
|--------|-------|-------|
| **Process** | `/proc/<pid>/*` (stat, cmdline, exe, fd, maps) | sysctl + proc_pidpath + KERN_PROCARGS2 |
| **Network** | `/proc/net/tcp*`, `udp*`, `raw*` + inode→PID | proc_pidfdinfo + sysctl pcblist_n |
| **Persistence** | systemd, cron, shell profiles, SSH, ld.so.preload | LaunchDaemons/Agents, cron, profiles, SSH |
| **Integrity** | Process/network/file/module cross-validation, kernel taint | Process/network/file cross-validation |
| **YARA** | Pure Go engine, condition subset | Same |

---

## IOC Monitoring

### Three-Tier Architecture

| Tier | Linux | macOS |
|---|---|---|
| 1 | conntrack netlink (event-driven) | BPF /dev/bpf (TCP SYN + UDP) |
| 2 | /proc/net/nf_conntrack | — |
| 3 | /proc/net/tcp polling | proc_pidfdinfo + sysctl polling |

**PID Resolution:** Targeted inode lookup (~10-50ms) → retry → pending queue → 5s timeout fallback.

**Dedup:** Full 5-tuple + IOC value. Each real connection is a separate event.

**Domain IOC:** Auto DNS-resolved to IPs at load time.

---

## Scoring

**Design:** Single-clue low scores · Combo escalation · Confidence separation · YARA 4-tier · Suppress mechanism

| Indicator | Base | Combo | Severity |
|---|---|---|---|
| exe in /tmp | +10 | +networked +10, +interpreter +5 | low→medium |
| Web shell (strong) | +25 | +network = strong | high |
| Persistence in /tmp | +15 | +active +10, +networked +10 | medium→high |
| /dev/tcp reverse shell | +25 | +active +10 | critical |
| YARA hit | +10/+15/+20/+25 | +active process +5, +tmp path +5 | by severity_hint |
| Rootkit suspected | +15 | Primarily affects confidence | high |
| 7 combo rules | | +10~+15 | high→critical |

**Suppress:** Parent is package manager → half score. exe_deleted with no network/persistence/YARA → zero score.

**Confidence:** host_trust_low and orphan_connections affect confidence, not score. Recorded in `integrity_flags`.

Score 0-100. Severity: info / low / medium / high / critical.

> Full rules: [FEATURES.md](FEATURES.md)

---

## Output Formats

| Format | File | Use |
|---|---|---|
| JSON | `linir-<host>-<id>.json` | SIEM / automation |
| Text | `linir-<host>-<id>.txt` | Human-readable |
| CSV | `linir-<host>-<id>-*.csv` (7 tables) | Excel analysis |
| Bundle | `linir-bundle-<host>-<id>.tar.gz` | Archive |

---

## GUI Dashboard

```bash
sudo ./linir gui                    # Local only
sudo ./linir gui --host 0.0.0.0     # LAN access
```

Features: One-click collection · Risk score cards · Interactive tables · Evidence breakdown · IOC real-time SSE · YARA scanning · JSON export · Dark theme

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
| FreeBSD / OpenBSD / NetBSD | amd64 | Stub |

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
- YARA subset: no full PCRE, hex jumps, modules, for expressions
- Non-root: significantly reduced visibility, marked `confidence: low`
- Kernel rootkits: userspace limitation, recommend offline forensics

---

## Disclaimer

LinIR is provided "AS IS". For authorized security assessments, incident response, and digital forensics only. Read-only operation. Output requires professional interpretation.

---

## License

MIT License

## Contributing

https://github.com/dogadmin/LinIR
