# LinIR

**Linux/macOS Incident Response & Forensic Collection Tool**

[中文文档](README.md)

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

## Collection Capabilities

### Self-Check & Preflight

- Binary self-integrity hash
- `LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT` detection
- `DYLD_INSERT_LIBRARIES` and all `DYLD_*` detection
- `/etc/ld.so.preload` content audit
- `/proc/self/exe` path verification and `/proc/self/maps` non-standard library detection
- PATH poisoning detection (relative dirs, temp dirs, world-writable dirs)
- Container / namespace / chroot detection
- Host trust level assessment (high / medium / low)

### Process, Network, Persistence, Integrity, YARA, Scoring

See the [Chinese README](README.md) for detailed tables on data sources, collected fields, and risk flags per platform. The capabilities are identical regardless of language.

---

## Command Reference

### Global Flags

These flags apply to all subcommands:

| Flag | Short | Description | Default |
|---|---|---|---|
| `--output-dir` | `-o` | Directory for output files | `.` (current dir) |
| `--format` | | Output format: `json`, `text`, `csv`, `both` (json+text), `all` (json+text+csv) | `both` |
| `--bundle` | | Also generate a tar.gz triage bundle | off |
| `--force` | | Continue collection even if preflight finds high-risk issues | off |
| `--verbose` | `-v` | Verbose logging | off |
| `--quiet` | `-q` | Suppress stdout (keep only file output and errors) | off |
| `--timeout` | | Global timeout in seconds; aborts collection when exceeded | `300` |

---

### `linir collect` — Full Collection

Runs all phases: self-check → preflight → process → network → persistence → integrity → correlation → YARA → scoring → output.

**This is the most common command for incident response.**

| Flag | Description | Default |
|---|---|---|
| `--hash-processes` | Compute SHA256 of each process executable (slow, useful for IOC matching) | off |
| `--collect-env` | Collect process environment variables (sensitive — may contain secrets) | off |
| `--yara-rules` | Path to YARA rule file or directory. Enables YARA scanning in the collection pipeline | none |

```bash
sudo ./linir collect
sudo ./linir collect --format json --bundle --output-dir /tmp/evidence
sudo ./linir collect --yara-rules /opt/yara-rules/ --hash-processes
sudo ./linir collect --force --bundle
```

---

### `linir preflight` — Environment Trust Assessment

Runs only self-check and preflight. Quick assessment of host trustworthiness without data collection.

No additional flags.

```bash
sudo ./linir preflight --format json
sudo ./linir preflight --format text
```

---

### `linir process` — Process Collection

Collects process information only.

| Flag | Description | Default |
|---|---|---|
| `--hash-processes` | Compute SHA256 of each process executable | off |
| `--collect-env` | Collect process environment variables (max 50 per process) | off |

```bash
sudo ./linir process --format json
sudo ./linir process --hash-processes --collect-env
```

---

### `linir network` — Network Connection Collection

Collects network connections only. No additional flags.

```bash
sudo ./linir network --format json
```

---

### `linir persistence` — Persistence Enumeration

Enumerates all persistence mechanisms. No additional flags.

```bash
sudo ./linir persistence --format json
```

---

### `linir integrity` — Integrity & Anti-Rootkit Checks

Cross-source visibility validation. Automatically collects process/network/persistence data first.

No additional flags.

```bash
sudo ./linir integrity --format json
```

---

### `linir yara` — YARA Rule Scanning

| Flag | Description | Default |
|---|---|---|
| `--rules` | **Required.** Path to YARA rule file or directory (recursively loads `.yar`/`.yara`/`.rule`) | none |
| `--target` | Scan all files in the specified directory | none |
| `--proc-linked` | Smart target selection: scan networked process executables, persistence targets, temp directories | off |

If neither `--target` nor `--proc-linked` is specified, `--proc-linked` is enabled by default.

```bash
sudo ./linir yara --rules /opt/yara-rules/ --target /tmp
sudo ./linir yara --rules /opt/yara-rules/ --proc-linked
sudo ./linir yara --rules ./rules/ --target /var/www --proc-linked
```

---

### `linir bundle` — Triage Bundle Export

Runs full collection and packages results as tar.gz. Equivalent to `linir collect --bundle`.

No additional flags.

```bash
sudo ./linir bundle --output-dir /tmp/evidence
```

Bundle contents: `host.json`, `self_check.json`, `preflight.json`, `processes.json`, `connections.json`, `persistence.json`, `integrity.json`, `yara_hits.json`, `score.json`, `errors.json`, `full.json`.

---

### `linir gui` — Web GUI Dashboard

Starts a local HTTP server and opens an interactive forensic dashboard in your default browser. All data stays local (127.0.0.1 only).

| Flag | Description | Default |
|---|---|---|
| `--port` | HTTP server port | `18080` |

```bash
sudo ./linir gui
sudo ./linir gui --port 9090
```

**Dashboard features:**
- Risk score cards with color-coded severity
- Host trust level indicator
- Interactive process/network/persistence tables with search and filter
- Evidence breakdown with per-rule scoring details
- Integrity check results and preflight anomaly visualization
- One-click collection trigger and JSON export from browser
- Dark theme, responsive layout, embedded via `go:embed`

> Works on macOS desktop, Linux with X11/Wayland, or remote via SSH port forwarding (`ssh -L 18080:127.0.0.1:18080 root@target`).

---

### CSV Output

```bash
sudo ./linir collect --format csv    # CSV only
sudo ./linir collect --format all    # JSON + text + CSV
```

Generates 7 CSV files (UTF-8 BOM for Excel compatibility):
`*-summary.csv`, `*-processes.csv`, `*-connections.csv`, `*-persistence.csv`, `*-evidence.csv`, `*-yara.csv`, `*-integrity.csv`.

---

## Typical Workflows

### Scenario 1: Quick triage of a suspected compromised server

```bash
scp linir-linux-amd64 root@target:/tmp/linir
ssh root@target
chmod +x /tmp/linir
/tmp/linir collect --bundle --output-dir /tmp/evidence
exit
scp root@target:/tmp/evidence/linir-bundle-*.tar.gz ./
tar xzf linir-bundle-*.tar.gz && cat linir-*/full.json | jq '.score'
```

### Scenario 2: Deep scan with YARA rules

```bash
sudo ./linir collect \
  --yara-rules /opt/yara-rules/ \
  --hash-processes \
  --collect-env \
  --bundle \
  --output-dir /evidence/$(hostname)-$(date +%Y%m%d)
```

### Scenario 3: Pre-collection environment check

```bash
./linir preflight --format text
```

---

## Build from Source

```bash
git clone https://github.com/dogadmin/LinIR.git && cd LinIR
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

## Known Limitations

- **macOS network offsets**: Includes auto-probing for two known `vinfo_stat` sizes. If Apple changes the struct layout, connections are skipped with `confidence: low`.
- **YARA subset**: Full PCRE, hex jumps, modules, `for` expressions, and imports are not supported. Unsupported features degrade gracefully.
- **Hex `??` wildcard**: Simplified to `\x00` match. May cause false negatives.
- **Non-root**: Significantly reduced visibility. Limited-access data marked `confidence: low`.
- **Kernel rootkits**: LinIR is userspace-only. Kernel-level rootkits can evade detection.

---

## Dependencies

All pure Go. Fully statically compiled with `CGO_ENABLED=0`.

| Dependency | Purpose |
|---|---|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/google/uuid` | Collection ID |
| `howett.net/plist` | macOS plist parsing |
| `golang.org/x/sys` | syscall wrappers |

---

## Disclaimer

**LinIR is provided "AS IS" without warranty of any kind.** The authors are not responsible for any damages arising from use or misuse.

**For authorized security assessments, incident response, and digital forensics only.** Ensure proper authorization before deployment. Unauthorized computer access is illegal.

**LinIR is read-only** — it does not modify target system data. However, running any tool on a live system may alter volatile evidence.

**Output is not definitive proof.** It provides evidence requiring professional interpretation. False positives and negatives are possible.

**The authors do not endorse illegal activities.**

---

## License

MIT License

## Contributing

Issues and PRs welcome at https://github.com/dogadmin/LinIR
