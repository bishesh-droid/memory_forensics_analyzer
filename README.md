# Memory Forensics Analyzer (MFA)

Production-grade memory forensics platform for incident response, malware analysis, and threat hunting. Built for cybersecurity professionals who need automated, intelligent analysis of volatile memory dumps across Windows, Linux, and macOS.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI / REST API / Dashboard               │
├─────────────────────────────────────────────────────────────┤
│                      Analysis Engine                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐ │
│  │ Validator │  │ Profiler │  │ Vol3 Back│  │ Plugin Bus  │ │
│  │ (hash,   │  │ (OS auto │  │ end (JSON│  │ (20+ native │ │
│  │  format) │  │  detect) │  │  + text) │  │  plugins)   │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Detection Engines                         │
│  ┌───────┐  ┌──────────┐  ┌──────────┐  ┌──────┐  ┌─────┐ │
│  │ YARA  │  │ Rootkit  │  │Injection │  │Anomaly│  │ IOC │ │
│  │Scanner│  │ Detector │  │ Detector │  │  ML   │  │Extr.│ │
│  └───────┘  └──────────┘  └──────────┘  └──────┘  └─────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Analysis Modules                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐ │
│  │ Timeline │  │ Process  │  │ Differ-  │  │   String    │ │
│  │ Builder  │  │   Tree   │  │  ential  │  │ Extraction  │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                  Threat Intelligence                         │
│  ┌───────────┐  ┌──────────┐  ┌───────────────────────────┐ │
│  │VirusTotal │  │  MITRE   │  │ AbuseIPDB / AlienVault OTX│ │
│  │  Client   │  │  ATT&CK  │  │   Threat Feed Aggregator  │ │
│  └───────────┘  └──────────┘  └───────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│              Reporting & Export                               │
│  ┌────┐  ┌─────┐  ┌─────┐  ┌──────┐  ┌─────────┐          │
│  │HTML│  │JSON │  │ CSV │  │ STIX │  │ OpenIOC │          │
│  └────┘  └─────┘  └─────┘  └──────┘  └─────────┘          │
├─────────────────────────────────────────────────────────────┤
│                    Enterprise                                │
│  ┌──────┐  ┌─────────┐  ┌──────┐  ┌────────┐  ┌──────────┐│
│  │ RBAC │  │Licensing │  │ SIEM │  │ Distri-│  │  Cloud   ││
│  │      │  │ (3-tier) │  │(CEF/ │  │ buted  │  │Acquisi-  ││
│  │      │  │          │  │ LEEF)│  │Analysis│  │  tion    ││
│  └──────┘  └─────────┘  └──────┘  └────────┘  └──────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Features

### Core Engine
| Feature | Description |
|---------|-------------|
| **Multi-format validation** | Auto-detect raw, VMEM, DMP, LiME, ELF core, VMware, QEMU formats with SHA-256/MD5 integrity hashing |
| **OS profile auto-detection** | Identify Windows (XP → 11), Linux, macOS, FreeBSD from kernel signatures and KDBG scanning |
| **Parallel plugin execution** | ThreadPoolExecutor-based multi-plugin analysis with configurable worker count |
| **Structured JSON output** | All plugins return structured data — no stdout text parsing |

### Forensic Plugins (20+)
| Plugin | Volatility Module | Purpose |
|--------|-------------------|---------|
| `pslist` | `windows.pslist.PsList` | Active process listing |
| `psscan` | `windows.psscan.PsScan` | Pool-tag scan (detects hidden processes) |
| `netscan` | `windows.netscan.NetScan` | Network connections and listeners |
| `dlllist` | `windows.dlllist.DllList` | Loaded DLLs per process |
| `handles` | `windows.handles.Handles` | Open file/registry/mutex handles |
| `cmdline` | `windows.cmdline.CmdLine` | Command-line arguments per process |
| `malfind` | `windows.malfind.Malfind` | Injected code detection (VAD analysis) |
| `ssdt` | `windows.ssdt.SSDT` | System Service Descriptor Table hooks |
| `callbacks` | `windows.callbacks.Callbacks` | Kernel notification callbacks |
| `driverirp` | `windows.driverirp.DriverIrp` | IRP hook detection |
| `modscan` | `windows.modscan.ModScan` | Kernel module enumeration |
| `filescan` | `windows.filescan.FileScan` | Open file objects in memory |
| `hashdump` | `windows.hashdump.Hashdump` | SAM password hash extraction |
| `envars` | `windows.envars.Envars` | Per-process environment variables |
| `svcscan` | `windows.svcscan.SvcScan` | Windows service enumeration |
| `hivelist` | `windows.registry.hivelist` | Registry hive listing |
| `printkey` | `windows.registry.printkey` | Registry key/value extraction |
| `linux_pslist` | `linux.pslist.PsList` | Linux process listing |
| `linux_bash` | `linux.bash.Bash` | Bash command history recovery |
| `linux_lsmod` | `linux.lsmod.Lsmod` | Linux kernel modules |
| `linux_sockstat` | `linux.sockstat.Sockstat` | Linux socket statistics |

### Detection Engines

**YARA Scanner**
- Built-in rules for Mimikatz, Cobalt Strike, Meterpreter, encoded PowerShell, shellcode patterns, suspicious registry keys
- Custom rule directory support (`.yar` / `.yara` files)
- Per-process buffer scanning with PID/process attribution
- Configurable timeout and string limits

**Rootkit Detector**
- **DKOM detection**: Cross-references `pslist` vs `psscan` to find processes hidden via Direct Kernel Object Manipulation
- **SSDT hook detection**: Identifies non-standard handlers in the System Service Descriptor Table
- **Hidden module detection**: Compares `modscan` vs `modules` for unlinked kernel drivers
- **Callback analysis**: Flags kernel callbacks registered by unknown modules
- **IRP hook detection**: Detects driver IRP dispatch table tampering

**Code Injection Detector**
- **Process hollowing**: Detects PE headers (MZ magic) in RWX memory regions, verifies system process image paths
- **DLL injection**: Flags DLLs loaded from `%TEMP%`, `Downloads`, `Desktop`, or with offensive tool names
- **Shellcode detection**: Entropy analysis on executable memory regions (threshold: 7.0 bits/byte)
- **MITRE ATT&CK mapping**: Every finding mapped to techniques (T1055, T1055.001, T1055.003, T1055.012)

**Anomaly Detector (ML-based behavioral analysis)**
- **Parent-child validation**: Verifies expected process genealogy (e.g., `svchost.exe` must be child of `services.exe`)
- **Process count monitoring**: Detects excessive instances of singleton processes (lsass.exe, services.exe)
- **Name masquerading**: Levenshtein distance + known typosquat database (scvhost.exe, isass.exe, etc.)
- **Session ID validation**: System processes must run in session 0
- **Offensive tool detection**: Flags known tools (mimikatz, psexec, bloodhound, rubeus, etc.)
- **Network anomalies**: System processes with unexpected outbound connections, connections to attack ports (4444, 31337, etc.)

**IOC Extractor**
- Regex-based extraction: IPv4, domains, URLs, email addresses, file paths, registry keys, mutex names
- Hash detection: MD5, SHA-1, SHA-256 patterns
- Private IP filtering (RFC 1918)
- Suspicious TLD scoring (.tk, .xyz, .onion → higher confidence)
- STIX 2.1 bundle export

### Analysis Modules

**Timeline Analyzer**
- Unified timeline from process creation/exit, network connections, file objects, services
- CSV and JSON export
- Time range and event type filtering

**Process Tree Builder**
- Parent-child relationship mapping with depth calculation
- Suspicious chain detection (orphaned system processes, deeply nested shells)
- Text (ASCII art) and JSON rendering
- Ancestry tracing for any PID

**Differential Analyzer**
- Compare two memory dumps to identify exactly what changed
- Detects: new/terminated processes, new/closed connections, loaded/unloaded modules, service state changes
- Risk scoring per change category
- Batch comparison for multi-dump incident timelines

**String Extractor**
- ASCII and UTF-16LE extraction with configurable min/max length
- 10 suspicious pattern categories: URLs, IPs, credentials, shell commands, API calls, SQL injection
- Automatic categorization (URL, IP, file path, registry key, email, identifier)
- CSV export with offset and encoding metadata

### Threat Intelligence

| Integration | Capabilities |
|-------------|-------------|
| **VirusTotal** | File hash, IP, domain lookup with SQLite caching (24h TTL), rate limiting (4 req/min) |
| **MITRE ATT&CK** | 20 techniques mapped with tactic/detection/reference. Attack matrix generation from findings |
| **AbuseIPDB** | IP reputation scoring with abuse confidence percentage |
| **AlienVault OTX** | IP, domain, hash lookup against threat pulses with severity classification |

### Reporting

| Format | Output |
|--------|--------|
| **HTML** | Professional dark-themed report with metadata header, classification banners, sortable tables (max 500 rows per section) |
| **JSON** | Machine-readable structured report with full metadata |
| **CSV** | Spreadsheet-compatible section-by-section export |
| **STIX 2.1** | Cyber Threat Intelligence standard bundle with indicators, attack patterns, relationships |
| **OpenIOC** | IOC export compatible with Mandiant/FireEye tooling |

### Case Management
- Case lifecycle: create, update, close with priority levels
- Analyst notes with tagging
- Evidence registration with SHA-256/MD5 integrity verification
- Chain of custody tracking with timestamped audit entries
- Case search by title, description, notes, tags
- Custody report export (court-admissible format)

### Enterprise Features

**Role-Based Access Control (RBAC)**
- 4 built-in roles: Admin, Analyst, Viewer, API
- Permission-based authorization (analyze, scan, report, case_manage, user_manage, config, export, delete)
- Session token authentication + API key authentication
- Password hashing with per-user salts
- Full audit logging

**3-Tier Licensing**
| Tier | Analysts | Dumps/Day | Key Features |
|------|----------|-----------|-------------|
| **Community** | 1 | 5 | Core plugins, process tree, timeline, basic reporting |
| **Professional** | 5 | 50 | + YARA, rootkit, injection, anomaly, IOC, threat intel, STIX, case management, API |
| **Enterprise** | Unlimited | Unlimited | + RBAC, SIEM, distributed analysis, cloud acquisition, multi-tenant, priority support |

- HMAC-SHA256 signed license keys with hardware binding
- Feature gating enforced at runtime

**SIEM Integration**
- Syslog (RFC 5424) with TLS support
- HTTP/JSON webhook
- CEF (Common Event Format) — Splunk, ArcSight
- LEEF (Log Event Extended Format) — QRadar
- Configurable facility and severity mapping

**Distributed Analysis**
- ThreadPoolExecutor-based parallel dump analysis
- Job queue with status tracking (queued → running → complete/failed)
- Batch submission for mass incident response (100+ machines)
- Cross-dump comparison and aggregation

**Memory Acquisition**
| Platform | Tools | Method |
|----------|-------|--------|
| Linux | AVML, LiME, /proc/kcore | Kernel module or userspace capture |
| Windows | WinPmem, DumpIt, RAMCapture | Driver-based full physical memory |
| macOS | osxpmem | Kernel extension |
| AWS | SSM + AVML | Remote command execution via Systems Manager |
| Azure | az vm run-command | Remote script execution |
| GCP | gcloud compute ssh | SSH-based remote capture |

### REST API & Dashboard

**API Endpoints**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/analyze` | Start full analysis on a dump file |
| `GET` | `/analyses` | List all analyses |
| `GET` | `/analyses/{id}` | Get analysis results |
| `POST` | `/analyses/{id}/scan/yara` | Run YARA scan |
| `POST` | `/analyses/{id}/scan/rootkit` | Run rootkit detection |
| `POST` | `/analyses/{id}/scan/injection` | Run injection detection |
| `GET` | `/analyses/{id}/timeline` | Get event timeline |
| `GET` | `/analyses/{id}/process-tree` | Get process tree |
| `GET` | `/analyses/{id}/iocs` | Get extracted IOCs |
| `GET` | `/dashboard` | Web dashboard (auto-refresh) |

- API key authentication via `X-API-Key` header
- Rate limiting (60 req/min per client, 429 + Retry-After)
- CORS configuration
- TLS support

---

## Installation

### Prerequisites
- Python 3.9+
- Volatility 3 (`pip install volatility3`)

### Quick Start

```bash
git clone https://github.com/bisheshbaruah/memory-forensics-analyzer.git
cd memory-forensics-analyzer

python3 -m venv venv
source venv/bin/activate

# Core install
pip install -e .

# Full install (YARA + API)
pip install -e ".[full]"
```

### Environment Setup

```bash
cp .env.example .env
# Edit .env with your API keys:
#   MFA_VT_API_KEY     — VirusTotal (free: 4 req/min)
#   MFA_ABUSEIPDB_KEY  — AbuseIPDB
#   MFA_OTX_KEY        — AlienVault OTX
#   MFA_API_KEY        — API authentication key
```

---

## Usage

### Full Analysis

```bash
# Analyze a Windows memory dump (auto-detects OS, runs all relevant plugins)
mfa analyze -f memory.dmp

# Run specific plugins only
mfa analyze -f memory.dmp -p windows.pslist.PsList windows.netscan.NetScan

# Export results to JSON
mfa analyze -f memory.dmp -o results.json
```

### Detection Scans

```bash
# Run all detection engines
mfa scan -f memory.dmp --all

# Individual scans
mfa scan -f memory.dmp --yara --yara-rules /path/to/rules/
mfa scan -f memory.dmp --rootkit
mfa scan -f memory.dmp --injection
mfa scan -f memory.dmp --anomaly
mfa scan -f memory.dmp --ioc

# Export scan results
mfa scan -f memory.dmp --all -o scan_results.json
```

### Process Tree

```bash
# Text visualization
mfa process-tree -f memory.dmp

# JSON output
mfa process-tree -f memory.dmp --json

# Example output:
# ├─ System (PID:4 PPID:0 Session:------ Threads:53)
# ├─ smss.exe (PID:284 PPID:4 Session:0 Threads:3)
#   ├─ csrss.exe (PID:356 PPID:284 Session:0 Threads:12)
#   ├─ wininit.exe (PID:412 PPID:284 Session:0 Threads:1)
#     ├─ services.exe (PID:460 PPID:412 Session:0 Threads:8)
#       ├─ svchost.exe (PID:612 PPID:460 Session:0 Threads:11)
#       ├─ svchost.exe (PID:704 PPID:460 Session:0 Threads:7)
```

### Timeline

```bash
# Build event timeline
mfa timeline -f memory.dmp -o timeline.json

# CSV export
mfa timeline -f memory.dmp -o timeline.csv --format csv
```

### Differential Analysis

```bash
# Compare before/after dumps
mfa diff --before clean_snapshot.dmp --after infected_snapshot.dmp -o diff.json
```

### String Extraction

```bash
# All strings
mfa strings -f memory.dmp -o strings.csv

# Suspicious only (URLs, IPs, credentials, shell commands)
mfa strings -f memory.dmp --suspicious-only -o suspicious.csv
```

### Report Generation

```bash
# HTML report (professional, dark-themed)
mfa report -f memory.dmp --format html --analyst "Bishesh Baruah" --case-id MFA-2026-001

# JSON report
mfa report -f memory.dmp --format json -o reports/

# CSV report
mfa report -f memory.dmp --format csv
```

### Validation

```bash
mfa validate -f suspect_dump.raw
# File: suspect_dump.raw
# Size: 2048.0 MB
# Format: raw_dump
# SHA-256: a3f1...
# MD5: 7b2c...
# Valid: True
```

### Case Management

```bash
# Create a case
mfa case create --title "Ransomware Incident 2026-06" --analyst "Bishesh" --priority high

# List open cases
mfa case list --status open
```

### Memory Acquisition

```bash
# Capture live memory (auto-detects available tools)
mfa capture

# Specify method
mfa capture --method avml -o /evidence/captures/
```

### REST API

```bash
# Start API server
mfa api --host 0.0.0.0 --port 8443

# With TLS
mfa api --host 0.0.0.0 --port 8443 --ssl-cert cert.pem --ssl-key key.pem

# API usage
curl -X POST http://localhost:8443/analyze \
  -H "X-API-Key: your_key" \
  -H "Content-Type: application/json" \
  -d '{"dump_path": "/evidence/memory.dmp"}'
```

---

## Project Structure

```
memory_forensics_analyzer/
├── memory_forensics_analyzer/
│   ├── __init__.py                 # Package exports
│   ├── main.py                     # CLI entry point (12 commands)
│   ├── utils.py                    # Legacy Volatility output parsers
│   ├── core/
│   │   ├── config.py               # Centralized configuration (8 config sections)
│   │   ├── engine.py               # Analysis engine + Volatility backend
│   │   ├── validator.py            # Dump validation (format, hash, corruption)
│   │   └── profile.py              # OS profile auto-detection
│   ├── plugins/                    # 20+ forensic plugins
│   │   ├── pslist_plugin.py        # Process listing
│   │   ├── psscan_plugin.py        # Pool-tag process scan
│   │   ├── netscan_plugin.py       # Network connections
│   │   ├── dlllist_plugin.py       # Loaded DLLs
│   │   ├── handles_plugin.py       # Open handles
│   │   ├── cmdline_plugin.py       # Command-line args
│   │   ├── malfind_plugin.py       # Code injection detection
│   │   ├── ssdt_plugin.py          # SSDT hooks
│   │   ├── callbacks_plugin.py     # Kernel callbacks
│   │   ├── driverirp_plugin.py     # IRP hooks
│   │   ├── modscan_plugin.py       # Kernel modules
│   │   ├── filescan_plugin.py      # File objects
│   │   ├── hashdump_plugin.py      # Password hashes
│   │   ├── envars_plugin.py        # Environment variables
│   │   ├── svcscan_plugin.py       # Windows services
│   │   ├── hivelist_plugin.py      # Registry hives
│   │   ├── psscan_plugin.py        # Hidden process detection
│   │   └── linux_plugins.py        # Linux: pslist, pstree, lsmod, bash, sockstat
│   ├── detection/
│   │   ├── yara_scanner.py         # YARA engine (7 built-in rules + custom)
│   │   ├── rootkit.py              # DKOM, SSDT hooks, hidden modules
│   │   ├── injection.py            # Hollowing, DLL injection, shellcode
│   │   ├── anomaly.py              # ML behavioral analysis
│   │   └── ioc_extractor.py        # IOC extraction + STIX export
│   ├── analysis/
│   │   ├── timeline.py             # Event timeline builder
│   │   ├── process_tree.py         # Process tree visualization
│   │   ├── differential.py         # Multi-dump comparison
│   │   └── strings.py              # String extraction + categorization
│   ├── intel/
│   │   ├── virustotal.py           # VT API v3 client with caching
│   │   ├── mitre.py                # ATT&CK technique database (20 techniques)
│   │   └── threat_feeds.py         # AbuseIPDB + OTX aggregator
│   ├── reporting/
│   │   ├── reporter.py             # HTML/JSON/CSV report generator
│   │   └── stix_export.py          # STIX 2.1 bundle export
│   ├── case/
│   │   ├── manager.py              # Case lifecycle management
│   │   └── evidence.py             # Chain of custody tracker
│   ├── api/
│   │   └── server.py               # FastAPI REST API + dashboard
│   ├── enterprise/
│   │   ├── rbac.py                 # Role-based access control
│   │   ├── license.py              # 3-tier HMAC-signed licensing
│   │   ├── siem.py                 # Syslog/HTTP/CEF/LEEF connector
│   │   └── distributed.py          # Parallel multi-dump analysis
│   └── acquisition/
│       ├── capture.py              # Live memory capture (Linux/Win/Mac)
│       └── cloud_capture.py        # AWS/Azure/GCP remote capture
├── config/
│   └── default.yaml                # Default configuration template
├── tests/                          # Unit and integration tests
├── setup.py                        # Package configuration
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variable template
└── README.md
```

## Comparison with Existing Tools

| Capability | MFA | Volatility 3 | MemProcFS | Magnet AXIOM | Belkasoft |
|---|---|---|---|---|---|
| **OS Support** | Win/Linux/Mac | Win/Linux/Mac | Win/Linux | Win/Mac/Linux/Mobile | Multi-platform |
| **Plugins** | 20+ | 100+ | 50+ | 200+ | 150+ |
| **Automated Scanning** | YARA + Rootkit + Injection + Anomaly + IOC | Manual plugins | None | ML + signatures | Signatures |
| **Process Tree** | Text + JSON + suspicious flagging | None (plugin) | Windows GUI | Full GUI | Full GUI |
| **Timeline** | Unified multi-source | Plugin | None | Full | Full |
| **Differential Analysis** | Multi-dump comparison | None | None | None | None |
| **Threat Intel** | VT + MITRE + AbuseIPDB + OTX | None | None | VT | VT |
| **Reporting** | HTML/JSON/CSV/STIX | Text/JSON | None | PDF/HTML/CASE | PDF/HTML |
| **Case Management** | Full lifecycle + evidence chain | None | None | Full | Full |
| **API** | REST + Dashboard | None | None | REST | SDK |
| **SIEM** | Syslog/CEF/LEEF/HTTP | None | None | Yes | Yes |
| **Licensing** | Community/Pro/Enterprise | Free/OSS | Free/OSS | ~$3,500/yr | ~$3,000/yr |
| **Cloud Acquisition** | AWS/Azure/GCP | None | None | Cloud option | None |
| **Distributed** | Multi-dump parallel | None | None | None | None |
| **Price** | Free (Community) / TBD | Free | Free | ~$3,500/yr | ~$3,000/yr |

### Key Differentiators
- **Only tool with differential analysis** — compare before/after infection dumps
- **Automated anomaly detection** — parent-child validation, process masquerading, session ID checks (no competitor automates this)
- **API-first architecture** — REST API + web dashboard, not GUI-only
- **4-protocol SIEM integration** — Syslog, HTTP, CEF, LEEF in one tool
- **Cloud-native acquisition** — AWS SSM, Azure CLI, GCP SSH capture support

---

## Configuration

```yaml
# config/default.yaml
volatility_path: "vol"         # Path to Volatility 3 binary
log_level: "INFO"              # DEBUG, INFO, WARNING, ERROR

yara:
  enabled: true
  rules_dir: ""                # Custom YARA rules directory
  timeout: 60                  # Scan timeout (seconds)

threat_intel:
  virustotal_api_key: ""       # VT API key (free tier: 4 req/min)
  abuseipdb_api_key: ""
  otx_api_key: ""

detection:
  anomaly_threshold: 0.7       # Min score to flag as anomalous
  entropy_threshold: 7.0       # Entropy threshold for shellcode detection

api:
  host: "127.0.0.1"
  port: 8443
  api_key: ""                  # Required for API authentication
```

---

## Test Datasets

| Dataset | Size | Source | Purpose |
|---------|------|--------|---------|
| `cridex.vmem` | ~250 MB | [Volatility Wiki](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples) | Banking trojan analysis |
| `stuxnet.vmem` | ~512 MB | Public samples | APT/ICS malware |
| `shylock.vmem` | ~256 MB | Public samples | Banking malware |
| `malware.vmem` | Varies | Custom captures | General malware analysis |
| `MemLabs` | Varies | [MemLabs CTF](https://github.com/stuxnet999/MemLabs) | CTF training challenges |

---

## License

Proprietary. See LICENSE file for terms.

---

## Author

**Bishesh Baruah** — bisheshbaruah56@gmail.com

Built for cybersecurity professionals who need fast, automated, intelligent memory forensics at scale.
