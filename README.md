# 🛡️ CyberX SOC — Unified Cyber-Police Forensics Platform

> **Version:** 2.0.0 | **Made in India 🇮🇳** | For authorized cyber-police forensic investigations only.

CyberX is a full-stack, enterprise browser-based cyber forensics suite that integrates **17+ industry-standard open-source tools & AI engines** into a unified dashboard. The backend is powered by **FastAPI + SQLAlchemy** (Python) with custom analysis wrappers, Random Forest machine learning models, and deep security tool integrations. The frontend is built with **React + Vite**, featuring a cyber dark-mode UI, live investigation dashboards, dynamic forensic report generation, and an embedded **CyberX AI Assistant Chatbot**.

---

## 📁 Project Structure

```
IFSO-CYBER-FORENSICS-PROJECT/
├── backend/                 # FastAPI server (Python)
│   ├── main.py              # All API endpoints & HTML report generator
│   ├── models.py            # SQLAlchemy DB models (investigations table)
│   ├── database.py          # SQLite DB connection (forensics.db)
│   ├── requirements.txt     # Python dependencies
│   ├── .env                 # API keys & configuration
│   ├── Ml Model/            # Random Forest ML Model for Phishing Detection
│   │   └── random_forest_model.pkl
│   ├── wrappers/            # 17 Tool & Engine Wrapper Modules
│   │   ├── ip_resolver_wrapper.py    # Enterprise IP Intelligence Engine
│   │   ├── ml_phishing_wrapper.py    # 29-Feature ML Phishing URL AI
│   │   ├── threat_intel_wrapper.py   # Multi-source Threat Intel & Universal URL Risk
│   │   ├── mobsf_wrapper.py          # MobSF Static & Dynamic Analysis
│   │   ├── ghidra_wrapper.py         # Headless Ghidra Decompiler & Java Exporter
│   │   ├── androguard_wrapper.py     # APK Static & Threat Scoring
│   │   ├── autopsy_wrapper.py        # Sleuth Kit Disk Image Parser
│   │   ├── volatility_wrapper.py     # Volatility 3 Memory Forensics
│   │   ├── brute_wrapper.py          # Multi-Protocol Brute Force Engine
│   │   ├── registry_wrapper.py       # Impacket SAM/SYSTEM NTLM Extractor
│   │   ├── network_wrapper.py        # TShark PCAP Network Parser
│   │   ├── exiftool_wrapper.py       # EXIF Metadata Extractor
│   │   ├── email_wrapper.py          # EML Header & Route Parser
│   │   ├── evtx_wrapper.py           # Windows EVTX Event Log Parser
│   │   ├── stego_wrapper.py          # Steghide Steganography Scanner
│   │   ├── hash_wrapper.py           # John the Ripper Hash Cracker
│   │   ├── yara_wrapper.py           # YARA Rule Pattern Engine
│   │   └── platform_utils.py         # Cross-Platform Binary Resolver & OS Diagnostics
│   ├── rules/               # YARA rule files (.yar / .yara)
│   ├── wordlists/           # Password wordlists (top10000.txt)
│   └── reports/             # Generated PDF & HTML reports
├── frontend/                # React + Vite Forensic UI
│   └── src/
│       ├── App.jsx           # Main App — 17 Analysis Tool Panels
│       ├── CyberChat.jsx     # CyberX AI Assistant Floating Chatbot
│       ├── App.css           # Component styling
│       └── index.css         # Global CyberX Dark Theme & UI System
├── installer/               # One-click installer script
│   └── installer.py
└── plugins/                 # Third-party tool binaries & frameworks
    ├── ghidra_12.1.2_PUBLIC/
    ├── volatility3/
    ├── Mobile-Security-Framework-MobSF/
    ├── yara/
    ├── exiftool/
    ├── john/
    ├── sleuthkit/
    └── RegRipper3.0/
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Python 3.11+ | Backend server & analysis engines | `sudo apt install python3` |
| Node.js 18+ | Frontend React dashboard | `sudo apt install nodejs npm` |
| uv (Python runner) | Fast Python environment runner | `pip install uv` |
| ExifTool | Metadata extraction from files | `sudo apt install exiftool` |
| John the Ripper | Hash & password cracking engine | `sudo apt install john` |
| TShark | Network PCAP packet analysis | `sudo apt install tshark` |
| Steghide | Image steganography detection | `sudo apt install steghide` |
| Volatility 3 | Memory dump analysis | Included in `plugins/volatility3/` |
| MobSF | Mobile security framework | Included in `plugins/Mobile-Security-Framework-MobSF/` |
| Ghidra 12.1.2 | Binary reverse engineering | Included in `plugins/ghidra_12.1.2_PUBLIC/` |
| Sleuth Kit | Disk image forensics engine | `sudo apt install sleuthkit` |
| Java 17+ | Required by Ghidra | `sudo apt install openjdk-17-jdk` |

### 1. Clone & Setup Backend

```bash
cd backend

# Install Python dependencies
uv pip install -r requirements.txt
uv pip install fastapi uvicorn sqlalchemy python-dotenv \
    androguard paramiko pyzipper pikepdf python-whois \
    requests impacket yara-python joblib pandas scikit-learn numpy eml_parser python-evtx

# Configure API keys (optional — many tools work without keys)
cp .env.example .env
nano .env

# Start backend server
uv run --with uvicorn uvicorn main:app --reload
# API available at: http://localhost:8000
```

### 2. Setup & Launch Frontend

```bash
cd frontend
npm install
npm run dev
# Dashboard UI available at: http://localhost:5173
```

### 3. Start MobSF (For APK Dynamic Analysis)

```bash
cd plugins/Mobile-Security-Framework-MobSF
python manage.py runserver 0.0.0.0:8001
```

---

## 🔑 Environment Variables (`.env`)

Located at `backend/.env`:

```env
VIRUSTOTAL_API_KEY=       # VirusTotal file scanning (get free key at virustotal.com)
ABUSEIPDB_API_KEY=        # AbuseIPDB IP reputation (get free key at abuseipdb.com)
SHODAN_API_KEY=           # Shodan host scanning (get key at shodan.io)
ALIENVAULT_API_KEY=       # AlienVault OTX threat intel (get free key at otx.alienvault.com)
MALWAREBAZAAR_API_KEY=    # MalwareBazaar hash lookup (pre-configured)
```

> Keys can also be entered live in the UI for each tool. `.env` serves as defaults.

---

## 🔧 All 17 Analysis Modules — Full Reference

---

### 1. 📷 ExifTool — File Metadata Extractor

**Endpoint:** `POST /analyze/exiftool`

Extracts all embedded metadata from any file type (images, PDFs, Office docs, audio/video, binaries) using the ExifTool command-line engine. Returns data as structured JSON.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Absolute path to a file OR directory |

**Sub-features:**
- **Single File Mode** — Returns all EXIF tags (GPS coordinates, camera model, timestamps, software used, author, copyright, etc.)
- **Directory Scan Mode** — If `file_path` is a folder, recursively scans ALL files inside with `-r` flag and returns a structured list with `total_files_scanned` count

**What it detects:**
- GPS location data embedded in photos
- Original creation date vs. modified date (evidence tampering detection)
- Device/software that created the file
- Hidden author or company name in document metadata
- Camera make/model, lens info, serial numbers

**Example Response (single file):**
```json
{
  "FileName": "photo.jpg",
  "GPSLatitude": "28.6139° N",
  "GPSLongitude": "77.2090° E",
  "CreateDate": "2024:01:15 10:30:00",
  "Make": "Apple",
  "Model": "iPhone 14"
}
```

**Example Response (directory scan):**
```json
{
  "total_files_scanned": 42,
  "all_metadata": [ {...}, {...}, ... ]
}
```

**Requires:** ExifTool installed — `sudo apt install exiftool` (Linux) or download from [exiftool.org](https://exiftool.org) (Windows)

---

### 2. 🔍 YARA — Malware Pattern Scanner

**Endpoint:** `POST /analyze/yara`

Compiles and scans files against custom YARA rule sets to identify malware signatures, suspicious strings, and custom byte-level patterns. Uses the `yara-python` library natively (cross-platform).

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Absolute path to the file to scan |
| `rules_path` | string | Absolute path to a `.yar` or `.yara` rules file |

**How to write YARA rules** (`backend/rules/example.yar`):
```yara
rule DetectMalware {
    meta:
        description = "Detects suspicious strings"
    strings:
        $s1 = "cmd.exe /c"
        $s2 = "powershell -enc"
    condition:
        any of them
}
```

**Response Fields:**
- `matches[].rule` — Name of the matched rule
- `matches[].namespace` — Rule namespace
- `matches[].tags` — Tags attached to the rule
- `matches[].meta` — Rule metadata (author, description, etc.)

**Example Response:**
```json
{
  "matches": [
    {
      "rule": "DetectMalware",
      "namespace": "default",
      "tags": ["malware"],
      "meta": {"description": "Detects suspicious strings"}
    }
  ]
}
```

**Requires:** `pip install yara-python` (on Windows: install Microsoft C++ Build Tools first)

---

### 3. 💾 Disk Image / Autopsy (Sleuth Kit) — Enterprise Forensic Analyzer

**Endpoint:** `POST /analyze/autopsy`

Forensic disk image analysis using Sleuth Kit CLI tools — the same engine that powers the Autopsy GUI. Features an enterprise pipeline with SIEM-compatible JSON logging, memory-efficient file streaming via Python generators, checkpoint recovery, SHA-256 chain-of-custody hashing, and multi-threaded artifact extraction.

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `image_path` | string | — | Path to disk image (.dd, .img, .iso, .E01) |
| `scan_type` | string | `mmls` | Analysis mode (see sub-options below) |

**Sub-Options (`scan_type`):**

| Value | Tool | Description |
|-------|------|-------------|
| `mmls` | `mmls` | List partition table and volume layout |
| `fsstat` | `fsstat` | Show file system type, block size, journal info |
| `fls` | `fls -r` | Recursively list ALL files including deleted ones (truncated to 1000) |
| `timeline` | `fls + mactime` | Generate a full MACB (Modified, Accessed, Created, Born) forensic timeline (truncated to 2000 events) |
| `enterprise` | Full Pipeline | Runs the enterprise DFIR pipeline: streams file manifest via generators, auto-flags suspicious executables >50MB, extracts artifacts via multi-threaded icat, produces SIEM JSON audit logs |

**Enterprise Pipeline Features:**
- **Context Manager lifecycle** — automatic resource cleanup on success or failure
- **Generator-driven file streaming** — processes up to 500,000 entries with constant memory usage
- **Checkpoint recovery** — saves state to `.forensic_checkpoint` files for crash resumption
- **SHA-256 audit trail** — hashes the source image on initialization to protect chain of custody
- **Multi-threaded extraction** — uses `ThreadPoolExecutor` with up to 32 workers for parallel `icat` artifact recovery
- **File categorization** — auto-classifies files as Document, Image, Executable, Database, System, Deleted, Suspicious

**Common Forensic Workflow:**
1. `mmls` → First step to understand disk partition layout
2. `fsstat` → Identify NTFS/FAT32/EXT4 file system details
3. `fls` → Recover deleted files (shown with `*` prefix)
4. `timeline` → Reconstruct attacker's activity over time
5. `enterprise` → Automated anomaly detection and artifact extraction

---

### 4. 🔬 Ghidra — Headless Binary Reverse Engineering

**Endpoint:** `POST /analyze/ghidra`  
**Progress Endpoint:** `GET /analyze/ghidra/progress`

Runs NSA's Ghidra in headless (CLI) mode to auto-analyze a binary executable and extract decompiled C-Code. Features real-time progress tracking, pre-analysis binary metadata extraction (PE/ELF format detection, architecture identification, hash computation), and structured dataclass output.

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `file_path` | string | — | Path to binary (EXE, ELF, DLL, APK, firmware) |
| `extract_code` | boolean | `true` | Set to `true` to extract decompiled C-Code |
| `timeout` | int | `900` | Maximum seconds to wait for Ghidra analysis |

**What it does in the background:**
1. **Pre-analysis binary inspection** — Reads magic bytes to detect format (PE/ELF/Mach-O), detects CPU architecture (x86, x64, ARM, ARM64, MIPS), calculates MD5 + SHA-256 hashes, and extracts PE section tables, import/export lists using `pefile` and `pyelftools`
2. Creates a temporary Ghidra project in the system temp directory
3. Imports the binary and runs Ghidra's full auto-analysis (disassembly, function detection, cross-references)
4. Executes a custom Java extraction script (`export_script.java`) via Ghidra's `DecompInterface`
5. Exports function signatures, entry points, strings, and **full decompiled C-Code** to JSON
6. Reports real-time progress via the `/analyze/ghidra/progress` polling endpoint
7. Cleans up and deletes the temporary project after analysis

**Progress Tracking Response:**
```json
{
  "percent": 65,
  "stage": "Running auto-analysis...",
  "status": "running",
  "timestamp": 1722191234.567
}
```

**Supported Binary Formats:**
- `PE` — Windows executables (.exe, .dll, .sys)
- `ELF` — Linux/Android executables
- `Mach-O` — macOS/iOS binaries
- `Raw Binary` — Firmware, shellcode

**Requires:** Ghidra 12.1.2 installed in `plugins/ghidra_12.1.2_PUBLIC/` + Java 17+

---

### 5. 📱 Androguard — APK Static Analysis & Deep Threat Scoring

**Endpoint:** `POST /analyze/androguard`

Statically analyzes Android APK files without running them. Performs deep threat intelligence analysis including app impersonation detection across 14+ popular apps, permission risk scoring with severity levels, code pattern analysis, network indicator extraction, certificate validation, obfuscation detection, and YARA signature scanning.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to the `.apk` file |

**App Impersonation Detection (14 targets):**

| Brand | Legitimate Package | Threat Score |
|-------|--------------------|-------------|
| WhatsApp | `com.whatsapp`, `com.whatsapp.w4b` | +100 |
| Instagram | `com.instagram.android` | +100 |
| Facebook | `com.facebook.katana`, `com.facebook.orca` | +100 |
| Telegram | `org.telegram.messenger` | +100 |
| Snapchat | `com.snapchat.android` | +100 |
| TikTok | `com.zhiliaoapp.musically` | +100 |
| Netflix | `com.netflix.mediaclient` | +100 |
| PayPal | `com.paypal.android.p2pmobile` | +100 |
| Gmail | `com.google.android.gm` | +100 |
| Twitter | `com.twitter.android` | +90 |
| Spotify | `com.spotify.music` | +90 |
| Amazon | `com.amazon.mShop.android.shopping` | +90 |
| YouTube | `com.google.android.youtube` | +90 |
| Chrome | `com.android.chrome` | +90 |

**Permission Risk Scoring Engine:**

| Permission | Risk Level | Score | Category | What it detects |
|-----------|------------|-------|----------|----------------|
| `BIND_ACCESSIBILITY_SERVICE` | CRITICAL | +35 | System | Keylogging, UI manipulation |
| `SYSTEM_ALERT_WINDOW` | HIGH | +30 | System | Overlay phishing attacks |
| `BIND_DEVICE_ADMIN` | HIGH | +30 | System | Hard-to-uninstall admin apps |
| `READ_SMS` | HIGH | +25 | Privacy | OTP stealing, 2FA bypass |
| `SEND_SMS` | HIGH | +25 | Privacy | Premium SMS fraud |
| `RECEIVE_SMS` | HIGH | +20 | Privacy | Intercept verification codes |
| `REQUEST_INSTALL_PACKAGES` | HIGH | +20 | System | Dropper functionality |
| `READ_CONTACTS` | MEDIUM | +15 | Privacy | Contact data harvesting |
| `READ_CALL_LOG` | MEDIUM | +15 | Privacy | Call history extraction |
| `CAMERA` | MEDIUM | +10 | Surveillance | Spyware camera access |
| `RECORD_AUDIO` | MEDIUM | +10 | Surveillance | Audio eavesdropping |
| `ACCESS_FINE_LOCATION` | MEDIUM | +8 | Surveillance | Precise GPS tracking |

**APK Metadata Extracted:**
- App name, package name, version name/code
- Min SDK, Target SDK, Max SDK versions
- Main activity, activities/services/receivers/providers counts
- DEX file count, file size, MD5/SHA1/SHA256 hashes
- Certificate info: serial number, issuer, subject, validity dates, fingerprints, debug/self-signed flags

**Threat Verdict Thresholds:**
- `> 80` → **MALICIOUS**
- `> 30` → **SUSPICIOUS**
- `≤ 30` → **SAFE**

---

### 6. 📱 MobSF — Full Mobile Security Scan (Static + Dynamic)

**Endpoint:** `POST /analyze/mobsf` (Static)  
**Dynamic Endpoint:** `POST /analyze/mobsf_dynamic`

Full static + optional dynamic analysis of APKs using Mobile Security Framework (MobSF). Features a 9-category weighted risk scoring engine with malicious permission combination detection and automated PDF forensic report generation.

**Requires:** MobSF running at `http://127.0.0.1:8001`

**Input Parameters (Static):**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to `.apk` file |

**Input Parameters (Dynamic):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `file_path` | string | — | Path to `.apk` file |
| `wait_time` | int | `30` | Seconds to wait for dynamic sandbox analysis |

**Malicious Permission Combination Detector:**

| Pattern | Required Permissions | Weight | Risk |
|---------|---------------------|--------|------|
| SMS Malware | `READ_SMS` + `SEND_SMS` + `RECEIVE_SMS` | 25 | Critical |
| Overlay Installer | `SYSTEM_ALERT_WINDOW` + `REQUEST_INSTALL_PACKAGES` | 20 | High |
| Spyware | `READ_CONTACTS` + `READ_CALL_LOG` + `ACCESS_FINE_LOCATION` + `RECORD_AUDIO` | 22 | Critical |
| Financial Malware | `SYSTEM_ALERT_WINDOW` + `READ_SMS` + `RECEIVE_SMS` | 18 | High |
| Complete Control | `READ_PHONE_STATE` + `SYSTEM_ALERT_WINDOW` + `REQUEST_INSTALL_PACKAGES` + `WRITE_SETTINGS` | 20 | Critical |
| Data Exfiltration | `READ_CONTACTS` + `READ_SMS` + `ACCESS_FINE_LOCATION` + `READ_EXTERNAL_STORAGE` | 15 | High |

**Risk Scoring Engine (9 weighted categories):**

| Category | What it checks |
|----------|----------------|
| High Severity Findings | Manifest + code analysis findings |
| Permission Combinations | Dangerous permission patterns (see table above) |
| APKID Malware Analysis | Packers, obfuscators, anti-VM, anti-debug, anti-hook |
| Malware Detection | VirusTotal hits, malware permission patterns |
| Network Security | Cleartext traffic, cert pinning bypass, user CA trust |
| Exported Components | Exported activities, services, receivers, providers (attack surface) |
| Certificate Issues | Expired certs, debug certs, self-signed anomalies |
| Hardcoded Secrets | API keys, passwords, tokens embedded in code |
| Manifest Flags | `debuggable=true`, `allowBackup=true`, missing secure flags |

**Risk Classification:**
- ≥ 75 → **Critical Risk**
- ≥ 60 → **High Risk**
- ≥ 40 → **Medium Risk**
- ≥ 20 → **Low Risk**
- < 20 → **Minimal Risk**

Also downloads and returns a **PDF forensic report** (base64 encoded) from MobSF.

---

### 7. 🧠 Volatility 3 — Memory Dump Analysis

**Endpoint:** `POST /analyze/volatility`

Analyzes Windows/Linux/macOS memory dump files using Volatility 3 with JSON output. Automatically falls back to Linux and macOS plugins if Windows kernel validation fails.

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `file_path` | string | — | Path to memory dump (.raw, .vmem, .mem, .dmp) |
| `scan_type` | string | `info` | Analysis plugin (see sub-options) |

**Sub-Options (`scan_type`):**

| Value | Plugin | Description |
|-------|--------|-------------|
| `info` | `windows.info.Info` | OS version, build, architecture, kernel base address |
| `pslist` | `windows.pslist.PsList` | List all running processes (PID, PPID, name, start time) |
| `malfind` | `windows.malfind.Malfind` | Find injected code / malware in process memory (RWX pages, unlinked DLLs) |
| `netscan` | `windows.netscan.NetScan` | List all active/closed TCP/UDP network connections & remote IPs |
| `cmdline` | `windows.cmdline.CmdLine` | Show command-line arguments of each process |
| `filescan` | `windows.filescan.FileScan` | Scan memory for file handles (find hidden/deleted files) |

**Fallback Support:** If Windows plugins fail with "Unable to validate the plugin requirements", automatically tries:
1. `linux.info.Info`
2. `mac.info.Info`

**Common Forensic Workflow:**
1. Start with `info` — confirm the OS and kernel version
2. Run `pslist` — spot suspicious processes (unusual names, orphaned processes)
3. Run `malfind` — detect code injection and DLL hollowing
4. Run `netscan` — find attacker's C2 (Command & Control) connections
5. Run `cmdline` — see what commands were run by each process
6. Run `filescan` — recover hidden file handles from memory

---

### 8. 🌐 Threat Intelligence OSINT Engine

**Endpoint:** `POST /analyze/threat_intel`

Multi-source threat intelligence lookup for IPs, domains, URLs, and file hashes. Integrates 12 scan types across free and API-key-gated services.

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | — | IP address, domain, URL, or file path |
| `scan_type` | string | `ip` | Lookup type (see sub-options) |
| `api_key` | string | null | Override API key (optional, uses `.env` otherwise) |

---

#### 8a. `ip` — IP Geolocation & ISP Lookup
- **Free, no API key required**
- Provider: `ip-api.com`
- Returns: Country, city, ISP, ASN, organization, lat/lon, reverse DNS

---

#### 8b. `whois` — Domain WHOIS Lookup
- **Free, no API key required**
- Uses `python-whois` library
- Returns: Registrar, creation date, expiration date, name servers, DNSSEC status, domain status, **domain age in days** (auto-calculated)

---

#### 8c. `virustotal` — File Hash Scan *(API Key Required)*
- Target must be a **file path** (auto-hashes with SHA-256)
- Returns: Malicious engine hits, undetected count, reputation score, suggested threat label
- Get key: [virustotal.com](https://www.virustotal.com)

---

#### 8d. `abuseipdb` — IP Abuse Check *(API Key Required)*
- Checks IP against abuse reports from the last 90 days
- Returns: Abuse confidence score (0–100), total reports, country, ISP, usage type
- Get key: [abuseipdb.com](https://www.abuseipdb.com)

---

#### 8e. `shodan` — Internet-Wide Host Scan *(API Key Required)*
- Returns: Open ports, running services, OS, CVE vulnerabilities list
- Get key: [shodan.io](https://www.shodan.io)

---

#### 8f. `malwarebazaar` — Malware Hash Lookup *(API Key in .env)*
- Target must be a **file path** (auto-hashes with SHA-256)
- Returns: Malware family, first seen date, tags, delivery method
- Key pre-configured in `.env`

---

#### 8g. `alienvault` — AlienVault OTX Threat Intel *(API Key Required)*
- Works for both IPs and domains (auto-detects via `ipaddress` module)
- Returns: Pulse count, top 5 threat pulse names, base indicator info
- Get key: [otx.alienvault.com](https://otx.alienvault.com)

---

#### 8h. `safebrowsing` — Google Safe Browsing Check
- **Free, no API key required**
- Uses Google Transparency Report undocumented API
- Returns:
  - `is_safe` — Boolean
  - `is_phishing` — Boolean
  - `contains_malware` — Boolean
  - `installs_unwanted_software` — Boolean
  - `redirects_to_harmful` — Boolean
  - `uncommon_downloads` — Boolean
  - `status_description` — Human-readable status ("Safe", "Unsafe", "Partially Unsafe", etc.)

---

#### 8i. `urlscan` — URLScan.io Domain History
- **Free, no API key required**
- Auto-extracts domain from full URLs before querying
- Returns: Total historical scans, last 5 scan results with screenshots

---

#### 8j. `pulsedive` — Pulsedive Threat Feed
- **Free, no API key required**
- Returns: Risk level (`none`/`low`/`medium`/`high`/`critical`), risk recommended, associated threat names, properties

---

#### 8k. `ml_url_analyzer` — AI Phishing Detector (Machine Learning)
- **Fully offline, no API key required**
- Uses a trained **Random Forest model** (`backend/Ml Model/random_forest_model.pkl`) with **29 URL features**
- Features analyzed:
  - URL length, hostname length, subdirectory count
  - Digit count, special characters, dots, hyphens, underscores
  - Presence of `@`, `?`, `=`, `%` characters
  - Token count, average/longest token length
  - 10 suspicious keyword flags: `login`, `verify`, `update`, `secure`, `account`, `bank`, `paypal`, `signin`, `free`, `bonus`
  - IP address in URL hostname, HTTPS presence, TLD length
  - **Shannon Entropy** of full URL string (measures character randomness)
- Returns: Prediction (`benign`/`phishing`/`malware`/`defacement`), confidence %, per-class probability distribution

**Example Response:**
```json
{
  "ml_analysis": {
    "url": "http://login-verify-account.tk/secure/paypal",
    "prediction": "phishing",
    "confidence": 96.43,
    "class_probabilities": {
      "benign": 1.23,
      "defacement": 0.85,
      "malware": 1.49,
      "phishing": 96.43
    },
    "features_extracted": {
      "url_length": 48,
      "has_login": 1,
      "has_verify": 1,
      "has_paypal": 1,
      "url_entropy": 3.912,
      "..."
    }
  }
}
```

---

#### 8l. `universal_url_validator` — 🔥 All-in-One URL Risk Assessment
- **Runs ALL 5 URL checks simultaneously:**
  1. Local Phishing Tunnel Heuristics
  2. Google Safe Browsing
  3. URLScan.io history
  4. Pulsedive threat feed
  5. WHOIS domain age check
- **Plus: Local Heuristics** — instantly flags known phishing tunnel providers with CRITICAL risk:
  - `trycloudflare.com`, `ngrok.io`, `ngrok-free.app`, `serveo.net`, `loca.lt`, `localhost.run`, `portmap.io`, `pinggy.link`, `zrok.io`, `bore.pub`, `loophole.site`, `localto.net`
- **Aggregated Risk Score (0–100):**

| Signal | Max Contribution |
|--------|-----------------|
| Local Heuristics (tunneling provider detected) | +100 |
| Google Safe Browsing flagged as dangerous | +35 |
| Pulsedive HIGH/CRITICAL risk | +30 |
| Pulsedive MEDIUM risk | +15 |
| Domain age < 180 days | +15 |

- **Final Verdict:**
  - ≥ 75 → **CRITICAL**
  - ≥ 50 → **HIGH**
  - ≥ 25 → **MEDIUM**
  - < 25 → **SAFE**

---

### 9. 🌐 IP Resolver — Enterprise IP Intelligence & Forensics Engine

**Endpoint:** `POST /analyze/ip_resolver`

A high-performance forensic IP investigation engine supporting both IPv4 and IPv6. Performs geolocation, ASN/ISP lookup, reverse DNS anti-spoofing verification, RDAP/WHOIS registry analysis, active port scanning with latency measurement, SSL/TLS certificate inspection, and automated weighted threat risk scoring.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | IPv4 or IPv6 address (e.g. `8.8.8.8` or `2001:4860:4860::8888`) |

**Sub-features & Capabilities:**

**9a. IP Classification & Scope Detection**
- Detects IPv4 vs IPv6 address family
- Classifies as: `Public`, `Private`, `Loopback`, `Link-Local`, `Multicast`, `Reserved`
- Returns `is_private`, `is_loopback`, `is_global`, `is_reserved`, `is_multicast`, `is_link_local` flags
- IPv6 expanded form included

**9b. Reverse DNS (PTR) Anti-Spoofing Verification**
- Performs reverse DNS lookup via `socket.gethostbyaddr()`
- Cross-verifies that the resolved PTR hostname points back to the original IP address
- Sets `ptr_mismatch = true` if forward lookup doesn't match — indicates DNS spoofing or fast-flux network

**9c. HTTPS Geolocation & ASN Lookup (No API Key)**
- **Primary provider:** `ipwho.is` (HTTPS, free)
- **Fallback provider:** `ipinfo.io` (HTTPS, free)
- Returns: Country, country code, region, city, latitude, longitude, timezone, ISP, organization, ASN number, ASN org, Google Maps URL
- Security flags: `is_proxy`, `is_tor`, `is_hosting`, `bogon`

**9d. RDAP / WHOIS & RIR Registry Analysis**
- Queries `rdap.org` over HTTPS
- Returns: Network name, network handle, CIDR block, all CIDR ranges, RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC), country, start/end addresses
- **Automatically extracts abuse contact emails** from RDAP entity vCards

**9e. Active Forensic Port Scanning & Latency**
- Scans 8 common forensic ports on public IPs only:

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 3389 | RDP |
| 8080 | HTTP-ALT |

- Measures socket connect RTT latency in milliseconds for each open port
- Returns fastest RTT as `primary_rtt_ms`

**9f. SSL / TLS Certificate Deep Inspection**
- Automatically triggered when port 443 is open
- Extracts: Subject CN, Issuer CN & Org, Validity dates, up to 10 Subject Alternative Names (SANs), SHA-256 certificate fingerprint, TLS version, cipher suite name

**9g. Weighted Forensics Threat Risk Calculation (0–100)**

| Indicator | Score | Description |
|-----------|-------|-------------|
| Bogon / Reserved IP | +100 | Should not route on public internet |
| Active Tor Exit Node | +60 | Known anonymization endpoint |
| Proxy / VPN endpoint | +40 | Detected via security flags |
| Datacenter / Hosting ASN | +25 | Infrastructure, not residential |
| Reverse DNS (PTR) mismatch | +20 | Forward lookup doesn't match reverse |
| Exposed remote management ports (SSH/RDP/FTP) | +15 | Attack surface risk |

- Risk Levels: **LOW** (`<20`) · **MEDIUM** (`≥20`) · **HIGH** (`≥50`) · **CRITICAL** (`≥75`)

---

### 10. 📡 Network Forensics (PCAP Analysis)

**Endpoint:** `POST /analyze/network`

Analyzes network packet capture files using TShark (Wireshark CLI engine). Cross-platform — auto-detects TShark on both Windows and Linux.

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `file_path` | string | — | Path to `.pcap` or `.pcapng` file |
| `scan_type` | string | `dns` | Analysis mode |

**Sub-Options (`scan_type`):**

| Value | TShark Flags | Description |
|-------|-------------|-------------|
| `dns` | `-T fields -e dns.qry.name -Y "dns.flags.response eq 0"` | Extract all unique DNS query names (deduplicated list of domains contacted) |
| `hierarchy` | `-q -z io,phs` | Show protocol hierarchy tree (% breakdown of protocols used) |
| `endpoints` | `-q -z endpoints,ip` | List all IP endpoints (source/destination IPs with packet/byte counts) |

**Output truncation:** All results capped at 1,000 lines.

**Requires:** TShark installed — `sudo apt install tshark` (Linux) or install [Wireshark](https://www.wireshark.org) on Windows (includes tshark).

---

### 11. 📧 Email Header Analyzer

**Endpoint:** `POST /analyze/email`

Parses `.eml` email files using the `eml_parser` Python library to extract structured email forensic data.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to `.eml` email file |

**What it extracts:**
- Full parsed email header structure (From, To, CC, BCC, Subject, Date)
- Complete email routing path (all `Received:` headers with timestamps)
- Reply-To field and X-Mailer header
- MIME parts tree and attachment metadata
- All datetime values serialized to ISO 8601 format

**Requires:** `pip install eml_parser`

---

### 12. 🪟 Windows Event Log Parser (EVTX)

**Endpoint:** `POST /analyze/evtx`

Parses Windows `.evtx` event log files using the `python-evtx` library with memory-mapped file I/O for efficient processing. Returns raw XML records.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to Windows `.evtx` event log file |

**Processing details:**
- Uses `mmap.mmap()` with `ACCESS_READ` for memory-efficient file reading
- Extracts up to **50 records** per scan (configurable via `max_records`)
- Returns raw XML event data for each record

**Key Security Event IDs to look for:**
- `4624` — Successful login
- `4625` — Failed login attempt
- `4688` — Process creation
- `4648` — Explicit credential logon (RunAs)
- `4720` — User account created
- `4726` — User account deleted

**Requires:** `pip install python-evtx`

---

### 13. 🖼️ Steganography Detector

**Endpoint:** `POST /analyze/stego`

Detects hidden data inside image and audio files using the `steghide` tool's `info` command. Probes the file with an empty passphrase to report whether embedded data exists.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to image/audio file |

**Supported file formats:** BMP, JPEG, AU, WAV (steghide limitation — PNG is not supported)

**Requires:** `sudo apt install steghide` (Linux) or download from [steghide.sourceforge.net](https://steghide.sourceforge.net) (Windows)

---

### 14. 🔑 Hash Cracker (John the Ripper)

**Endpoint:** `POST /analyze/hash`

Cracks password hashes from a hash file using John the Ripper. Runs the main cracking pass first, then uses `--show` to display any cracked passwords.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to a file containing hash string(s) |

**Supported hash types:** Auto-detected by John — MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, and many more

**Response Fields:**
- `crack_log` — Full John the Ripper cracking output
- `results` — `--show` output with cracked password:hash pairs

**Requires:** John the Ripper installed — `sudo apt install john` (Linux) or download from [openwall.com/john](https://www.openwall.com/john/) (Windows)

---

### 15. 💥 Brute Force & Credential Recovery Engine

**Endpoint:** `POST /analyze/brute`

Multi-protocol intelligent brute-force engine for authorized forensic credential recovery. Features smart wordlist mutations, auto hash-type detection, dual-engine cracking (John the Ripper + Python fallback), full audit trails with timestamps, and multi-threaded HTTP attacks.

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `http` | Attack mode (see sub-options) |
| `target` | string | — | URL, hostname, file path, or hash string |
| `username` | string | `admin` | Username to test (for HTTP/SSH/FTP) |
| `username_field` | string | `username` | HTML form field name for username |
| `password_field` | string | `password` | HTML form field name for password |
| `success_string` | string | null | String that appears on successful login |
| `failure_string` | string | `Invalid` | String that appears on failed login |
| `port` | int | null | Port number (defaults: SSH=22, FTP=21) |
| `wordlist_path` | string | null | Custom wordlist file path |
| `hash_type` | string | `auto` | Hash algorithm for hash mode |
| `max_attempts` | int | `1000` | Maximum passwords to try |
| `threads` | int | `8` | Parallel threads (HTTP mode only) |

**Sub-Options (`mode`):**

---

#### 15a. `http` — Web Form Brute Force
- Posts credentials via HTTP POST to a login form
- Multi-threaded with `ThreadPoolExecutor` (configurable thread count)
- Detects success via `success_string` OR absence of `failure_string`
- Returns full audit log with timestamps, HTTP status codes, and per-attempt results

---

#### 15b. `ssh` — SSH Brute Force
- Uses **Paramiko** library with `AutoAddPolicy` for host key handling
- Sequential attempts with 5s connect + 5s banner timeout per try
- Default port: 22

---

#### 15c. `ftp` — FTP Brute Force
- Uses Python's built-in `ftplib.FTP`
- Sequential attempts with 5s connection timeout
- Default port: 21

---

#### 15d. `zip` — Encrypted ZIP Password Recovery
- **Strategy 1:** John the Ripper (C engine, fastest) — tried first when available
- **Strategy 2:** `pyzipper` Python fallback (supports AES-256 encrypted ZIPs)
- Falls back to standard `zipfile` if `pyzipper` not installed

---

#### 15e. `pdf` — Encrypted PDF Password Recovery
- Uses **pikepdf** library
- Sequential attempts — tries each password until `pikepdf.PasswordError` stops

---

#### 15f. `hash` — Intelligent Hash Cracking
- **Auto-detects** hash type from hex string length:
  - 32 chars → MD5
  - 40 chars → SHA1
  - 56 chars → SHA224
  - 64 chars → SHA256
  - 96 chars → SHA384
  - 128 chars → SHA512
- **Strategy 1:** John the Ripper with `--format=raw-{type}` — uses all CPU cores, fastest
- **Strategy 2:** Python `hashlib` fallback — iterates the full wordlist
- Both strategies apply smart mutations

**Smart Wordlist Mutation Engine (applied to all modes):**
- Capitalize first letter (`password` → `Password`)
- Append `123` (`password` → `password123`)
- Append `@123` (`password` → `password@123`)
- Append `!` (`password` → `password!`)
- First letter uppercase + `1` (`password` → `Password1`)
- Leet-speak substitution (`a→@`, `o→0`, `i→1`)

**Wordlist Loading Priority:**
1. Custom wordlist (if provided via `wordlist_path`)
2. `backend/wordlists/top10000.txt` (built-in 10K list)
3. John's built-in list (e.g. `plugins/john/john-*/run/password.lst`)
4. Smart mutations of top 200 words

---

### 16. 🏛️ Windows Registry Hive Cracker

**Endpoint:** `POST /analyze/registry`

Extracts NTLM password hashes from offline Windows SAM/SYSTEM registry hives and cracks them. Uses a two-stage pipeline: Impacket extraction → John the Ripper cracking.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `sam_path` | string | Path to Windows SAM registry hive file |
| `system_path` | string | Path to Windows SYSTEM registry hive file |

**Workflow:**
1. **Impacket `secretsdump`** — Runs `impacket-secretsdump -sam <SAM> -system <SYSTEM> LOCAL` to extract all NTLM hashes
2. **Filters out** empty/blank NTLM hashes (known empty hash: `31d6cfe0d16ae931b73c59d7e0c089c0`)
3. **John the Ripper** (`--format=NT`) — Cracks the extracted NTLM hashes
4. Returns: raw secretsdump output, extracted hash list, John cracking log, and cracked password results

**Partial Success Mode:** If John the Ripper is not installed, returns extracted hashes with a warning so they can be cracked elsewhere.

**How to get SAM/SYSTEM files (from a live Windows system as Administrator):**
```cmd
reg save HKLM\SAM C:\sam.hive
reg save HKLM\SYSTEM C:\system.hive
```

**Requires:** `pip install impacket` + John the Ripper (optional but recommended)

---

### 17. 🤖 CyberX AI Assistant — Interactive Security Chatbot

**Frontend Component:** `CyberChat.jsx` (Floating Drawer)

An embedded, interactive AI copilot built for digital forensics investigators, malware analysts, and security engineers. Powered by OpenRouter API with real-time streaming LLM responses.

**Core Capabilities:**
- **Digital Forensics & DFIR:** Explains memory/disk/network evidence analysis, artifact locations, registry hives, Volatility plugins
- **Malware Analysis & YARA:** Auto-generates custom YARA rules, assists with decompiled C analysis, IOC extraction
- **Threat Intelligence & OSINT:** Interprets IP reputation scores, domain age risk, email header routing anomalies
- **Security Scripting & Automation:** Generates Python, Bash, PowerShell, C/C++, Go scripts
- **Ethical Hacking & CTF:** Walk-through explanations for CTF challenges (crypto, steganography, exploitation)

**UI Features:**
- Floating trigger button with resizable/expandable panel
- Real-time streaming response rendering (SSE)
- Multi-language syntax-highlighted code blocks with one-click **Copy Code** button
- Markdown rendering: bold, lists, inline code, headings, and code fences
- One-click conversation clear/reset
- Custom cybersecurity-focused system prompt

**API:** Uses `https://openrouter.ai/api/v1/chat/completions` with streaming enabled (`stream: true`)

---

## 📊 Investigation History & Printable Reports

**History Endpoint:** `GET /history`

Returns all past investigations stored in the SQLite database (`forensics.db`), ordered newest-first.

**Response fields per record:**

| Field | Description |
|-------|-------------|
| `id` | Auto-increment investigation ID |
| `filename` | Target file/domain/IP analyzed |
| `tool_used` | Which tool was used |
| `status` | `Completed` / `Failed` / `Running` |
| `created_at` | Timestamp |
| `results` | Full JSON results |

---

**Report Endpoint:** `GET /report/{inv_id}` (returns HTML)

Generates a professional, printable HTML forensic investigation report with:
- Case ID formatted as `CX-XXXXXX` (zero-padded)
- Analysis tool badge
- Target filename / IP / domain
- Timestamp in UTC
- Color-coded status indicator (green=Completed, red=Failed, yellow=Running)
- Formatted raw JSON evidence in a dark code block
- **Print to PDF** button using `window.print()`
- Confidential footer branding

---

**Diagnostics Endpoint:** `GET /diagnostics`

Returns the resolved binary paths and OS info for all forensic tools. Useful for verifying that all dependencies (Ghidra, Volatility, SleuthKit, TShark, ExifTool, John, Steghide, Impacket) are correctly installed and discoverable.

---

## 🖥️ Frontend UI Guide

The React frontend (`npm run dev` → `http://localhost:5173`) provides:

### Sidebar Navigation
Tools organized into 4 categories with collapsible sections:
- **Static & Malware** — ExifTool, YARA, Steganography
- **Deep Forensics** — Disk Forensics, Memory Forensics, Network PCAP, Threat Intel OSINT, IP Resolver
- **Mobile & Binaries** — Androguard APK, Ghidra Reverse Engineering, MobSF Mobile Security
- **Logs & Credentials** — Email Phishing, Windows Event Logs, Hash Cracking, Brute Force, Registry Cracking

### UI Features
- 🌙 Dark mode cyber-themed design
- Real-time analysis with animated step-by-step loading indicators
- Color-coded risk scores (green → yellow → red)
- Expandable JSON result viewer
- PDF report download button (MobSF)
- Searchable sidebar filter
- Floating CyberX AI chatbot assistant

---

## 🗄️ Database

Uses **SQLite** (`backend/forensics.db`) via SQLAlchemy ORM.

**Table: `investigations`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | Integer | Auto-increment primary key |
| `filename` | String | Target analyzed |
| `tool_used` | String | Tool name |
| `status` | String | Running / Completed / Failed |
| `results` | Text | JSON-encoded results |
| `created_at` | DateTime | Auto-set on creation |

---

## 📦 Python Dependencies

```txt
fastapi            # Web framework
uvicorn            # ASGI server
sqlalchemy         # ORM / SQLite
python-dotenv      # .env file loader
yara-python        # YARA rule engine
androguard         # APK analysis
paramiko           # SSH brute force
pyzipper           # AES ZIP cracking
pikepdf            # PDF cracking
python-whois       # WHOIS lookups
requests           # HTTP client
impacket           # Registry hash extraction
joblib             # ML model loading
pandas             # Feature extraction
scikit-learn       # Random Forest model
numpy              # Numerical ops
eml_parser         # Email .eml parsing
python-evtx        # Windows EVTX log parsing
```

---

## 🔧 Cross-Platform Support

The `platform_utils.py` module provides centralized cross-platform binary resolution:
- Auto-detects Windows / Linux / macOS
- Searches `PATH`, project `plugins/` directory, `.venv/Scripts/` (Windows) or `.venv/bin/` (Linux)
- Resolves: ExifTool, Steghide, TShark, Volatility, SleuthKit tools (mmls, fls, fsstat, mactime, icat), Ghidra analyzeHeadless, John the Ripper, Impacket secretsdump
- Provides `GET /diagnostics` endpoint to verify all tool paths

---

## ⚠️ Legal Disclaimer

> This tool is built **exclusively for authorized cyber-police forensic investigations**.  
> Unauthorized use against systems you do not own or have explicit written permission to test is **illegal** under the IT Act 2000 (India) and equivalent laws worldwide.  
> The developers accept no liability for misuse.

---

## 👨‍💻 Developer

Built as part of an IFSO (Indian Forensic Science Organization) Cyber Forensics project.  
**Made in India 🇮🇳** | CyberX SOC Platform v2.0
