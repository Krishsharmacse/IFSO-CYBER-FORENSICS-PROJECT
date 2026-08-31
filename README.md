# 🛡️ CyberX SOC — Unified Cyber-Police Forensics Platform

> **Version:** 2.0.0 | **Made in India 🇮🇳** | For authorized cyber-police forensic investigations only.

CyberX is a full-stack, browser-based cyber forensics suite that integrates **15 industry-standard open-source tools** into a single unified dashboard. Backend is built with **FastAPI + SQLAlchemy** (Python), frontend with **React + Vite**.

---

## 📁 Project Structure

```
Cyber Security Project for cyber safe/
├── backend/               # FastAPI server (Python)
│   ├── main.py            # All API endpoints
│   ├── models.py          # SQLAlchemy DB models
│   ├── database.py        # SQLite DB connection
│   ├── requirements.txt   # Python dependencies
│   ├── .env               # API keys config
│   ├── wrappers/          # 17 tool wrapper modules
│   ├── rules/             # YARA rule files
│   ├── wordlists/         # Password wordlists
│   ├── models/            # ML model (random_forest_model.pkl)
│   └── reports/           # Generated PDF reports (static)
├── frontend/              # React + Vite UI
│   └── src/
│       ├── App.jsx         # Main app (all UI components)
│       └── index.css       # Global styles
└── plugins/               # Third-party tool binaries
    ├── ghidra_12.1.2_PUBLIC/
    ├── volatility3/
    ├── Mobile-Security-Framework-MobSF/
    ├── yara/
    ├── exiftool/
    ├── RegRipper3.0/
    └── ...
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Install |
|------|---------|
| Python 3.11+ | `sudo apt install python3` |
| Node.js 18+ | `sudo apt install nodejs npm` |
| uv (Python runner) | `pip install uv` |
| ExifTool | `sudo apt install exiftool` |
| John the Ripper | `sudo apt install john` |
| Tshark | `sudo apt install tshark` |
| Volatility3 | Included in `plugins/volatility3/` |
| MobSF | Included in `plugins/Mobile-Security-Framework-MobSF/` |
| Ghidra 12.1.2 | Included in `plugins/ghidra_12.1.2_PUBLIC/` |
| Sleuth Kit | `sudo apt install sleuthkit` |

### 1. Clone & Setup Backend

```bash
cd backend

# Install Python dependencies
uv pip install -r requirements.txt
uv pip install fastapi uvicorn sqlalchemy python-dotenv \
    androguard paramiko pyzipper pikepdf python-whois \
    requests impacket yara-python joblib pandas scikit-learn numpy

# Configure API keys (optional — some tools work without keys)
cp .env.example .env
nano .env

# Start backend server
uv run --with uvicorn uvicorn main:app --reload
# API available at: http://localhost:8000
```

### 2. Setup Frontend

```bash
cd frontend
npm install
npm run dev
# UI available at: http://localhost:5173
```

### 3. Start MobSF (for APK Dynamic Analysis)

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

## 🔧 All 15 Analysis Modules — Full Reference

---

### 1. 📷 ExifTool — File Metadata Extractor

**Endpoint:** `POST /analyze/exiftool`

Extracts all embedded metadata from any file type (images, PDFs, Office docs, audio/video).

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Absolute path to a file OR directory |

**Sub-features:**
- **Single File Mode** — Returns all EXIF tags (GPS coordinates, camera model, timestamps, software used, author, copyright, etc.)
- **Directory Scan Mode** — If `file_path` is a folder, recursively scans ALL files inside and returns a list

**What it detects:**
- GPS location data embedded in photos
- Original creation date vs. modified date
- Device/software that created the file
- Hidden author or company name
- Evidence tampering (date inconsistencies)

**Example Response:**
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

---

### 2. 🔍 YARA — Malware Pattern Scanner

**Endpoint:** `POST /analyze/yara`

Scans any file against custom YARA rules to detect malware signatures, suspicious strings, or custom patterns.

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
- `matches[].tags` — Tags attached to the rule
- `matches[].meta` — Rule metadata (author, description)

---

### 3. 💾 Disk Image / Autopsy (Sleuth Kit)

**Endpoint:** `POST /analyze/autopsy`

Forensic disk image analysis using Sleuth Kit — the command-line engine behind Autopsy GUI.

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
| `fls` | `fls -r` | Recursively list ALL files including deleted ones |
| `timeline` | `fls + mactime` | Generate a full forensic timeline of file activity |

**Use Cases:**
- `mmls` → First step to understand disk partition layout
- `fsstat` → Identify NTFS/FAT32/EXT4 file system details
- `fls` → Recover deleted files (shown with `*` prefix)
- `timeline` → Reconstruct attacker's activity over time

---

### 4. 🔬 Ghidra — Binary Reverse Engineering

**Endpoint:** `POST /analyze/ghidra`

Runs NSA's Ghidra in headless (CLI) mode to auto-analyze a binary executable and extract decompiled C-Code natively.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to binary (EXE, ELF, DLL, APK, firmware) |
| `extract_code` | boolean| Set to `true` to extract decompiled C-Code (Default: `true`) |

**What it does in the background:**
- Creates a temporary Ghidra project in the system `/tmp/` directory.
- Imports the binary into the project.
- Runs Ghidra's full auto-analysis (disassembly, function detection, cross-references).
- Executes a custom native Java extraction script (`export_script.java`) via Ghidra's `DecompInterface`.
- Exports functions, entry points, strings, and **full decompiled C-Code** to a JSON file.
- Cleans up and completely deletes the temporary project after analysis to save disk space.

**How to run it manually (Without the CyberX backend):**
If you want to run the exact same headless extraction manually from your terminal, use this command:

```bash
# 1. Set where you want the JSON output to be saved
export GHIDRA_EXPORT_PATH="/tmp/ghidra_export.json"

# 2. Run the Ghidra Headless Analyzer
/opt/ghidra/support/analyzeHeadless \
  /tmp/ghidra_project_manual \
  Project_Manual \
  -import "/path/to/your/malware.exe" \
  -overwrite \
  -deleteProject \
  -max-cpu 4 \
  -scriptPath /path/to/folder/containing_your_java_script \
  -postScript export_script.java
```

**Requirements:**
- Ghidra 12.1.2 installed in `plugins/ghidra_12.1.2_PUBLIC/` (or path set via `GHIDRA_HEADLESS` env variable)
- Java 17+ installed (`sudo apt install openjdk-17-jdk`)

---

### 5. 📱 Androguard — APK Static Analysis

**Endpoint:** `POST /analyze/androguard`

Statically analyzes Android APK files without running them. Detects fake apps, suspicious permissions, and spyware patterns.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to the `.apk` file |

**Automated Threat Detection Rules:**

| Check | Condition | Score |
|-------|-----------|-------|
| Fake WhatsApp | Name has "whatsapp" but wrong package | +100 |
| Fake Instagram | Name has "instagram" but wrong package | +100 |
| Fake Facebook | Name has "facebook" but wrong package | +100 |
| Overlay Malware | `SYSTEM_ALERT_WINDOW` permission | +30 |
| SMS Fraud | `SEND_SMS` permission | +20 |
| OTP Stealing | `READ_SMS` permission | +20 |
| Spyware | Both `RECORD_AUDIO` + `CAMERA` | +15 |
| Contact Harvesting | `READ_CONTACTS` | +10 |
| AppLovin Ad SDK | AppLovin in services | +10 |
| Yandex Tracking | AppMetrica in services | +20 |

**Verdict Thresholds:**
- `> 80` → **MALICIOUS**
- `> 30` → **SUSPICIOUS**
- Otherwise → **SAFE**

**Response includes:** app name, package name, version, all permissions, activities, services, receivers, threat score, and threat flags.

---

### 6. 📱 MobSF — Full Mobile Security Scan

**Endpoint:** `POST /analyze/mobsf`  
**Dynamic Endpoint:** `POST /analyze/mobsf_dynamic`

Full static + optional dynamic analysis of APKs using Mobile Security Framework (MobSF).

**Requires:** MobSF running at `http://127.0.0.1:8001`

**Input Parameters (Static):**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to `.apk` file |

**Input Parameters (Dynamic):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `file_path` | string | — | Path to `.apk` file |
| `wait_time` | int | `30` | Seconds to wait for dynamic analysis |

**Risk Scoring Engine (9 weighted categories):**

| Category | Weight | What it checks |
|----------|--------|----------------|
| High Severity Findings | 30% | Manifest + code analysis findings |
| Permission Combinations | 20% | Dangerous permission patterns |
| APKID Malware Analysis | 15% | Packers, obfuscators, anti-analysis |
| Malware Detection | 30% | VirusTotal hits, malware permissions |
| Network Security | 15% | Cleartext traffic, cert pinning bypass |
| Exported Components | 10% | Attack surface (exported activities/services) |
| Certificate Issues | 15% | Expired certs, cert anomalies |
| Hardcoded Secrets | 10% | API keys, passwords in code |
| Manifest Flags | 10% | `debuggable=true`, `backup=true` |

**Malicious Permission Patterns Detected:**

| Pattern | Permissions Required | Risk |
|---------|---------------------|------|
| SMS Malware | READ_SMS + SEND_SMS + RECEIVE_SMS | Critical |
| Overlay Installer | SYSTEM_ALERT_WINDOW + REQUEST_INSTALL_PACKAGES | High |
| Spyware | READ_CONTACTS + READ_CALL_LOG + ACCESS_FINE_LOCATION + RECORD_AUDIO | Critical |
| Financial Malware | SYSTEM_ALERT_WINDOW + READ_SMS + RECEIVE_SMS | High |
| Complete Control | READ_PHONE_STATE + SYSTEM_ALERT_WINDOW + REQUEST_INSTALL_PACKAGES + WRITE_SETTINGS | Critical |
| Data Exfiltration | READ_CONTACTS + READ_SMS + ACCESS_FINE_LOCATION + READ_EXTERNAL_STORAGE | High |

**Risk Classification:**
- ≥ 75 → **Critical Risk**
- ≥ 60 → **High Risk**
- ≥ 40 → **Medium Risk**
- ≥ 20 → **Low Risk**
- < 20 → **Minimal Risk**

Also downloads and returns a **PDF forensic report** (base64 encoded).

---

### 7. 🧠 Volatility — Memory Dump Analysis

**Endpoint:** `POST /analyze/volatility`

Analyzes Windows/Linux/macOS memory dump files using Volatility 3.

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `file_path` | string | — | Path to memory dump (.raw, .vmem, .mem, .dmp) |
| `scan_type` | string | `info` | Analysis plugin (see sub-options) |

**Sub-Options (`scan_type`):**

| Value | Plugin | Description |
|-------|--------|-------------|
| `info` | `windows.info.Info` | OS version, build, architecture, kernel base |
| `pslist` | `windows.pslist.PsList` | List all running processes (PID, PPID, name, start time) |
| `malfind` | `windows.malfind.Malfind` | Find injected code / malware in process memory |
| `netscan` | `windows.netscan.NetScan` | List all active/closed network connections |
| `cmdline` | `windows.cmdline.CmdLine` | Show command-line arguments of each process |
| `filescan` | `windows.filescan.FileScan` | Scan memory for file handles (find hidden files) |

**Fallback Support:** If Windows plugins fail, automatically tries Linux then macOS equivalents for `info`.

**Common Workflow:**
1. Start with `info` — confirm the OS
2. Run `pslist` — spot suspicious processes
3. Run `malfind` — detect code injection
4. Run `netscan` — see attacker's C2 connections
5. Run `cmdline` — see what commands were run

---

### 8. 🌐 Threat Intelligence Engine

**Endpoint:** `POST /analyze/threat_intel`

Multi-source threat intelligence lookup for IPs, domains, URLs, and file hashes.

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | — | IP address, domain, URL, or file path |
| `scan_type` | string | `ip` | Lookup type (see sub-options) |
| `api_key` | string | null | Override API key (optional, uses .env otherwise) |

**Sub-Options (`scan_type`):**

---

#### 8a. `ip` — IP Geolocation & ISP Lookup
- **Free, no API key required**
- Provider: ip-api.com
- Returns: Country, city, ISP, ASN, organization, lat/lon, reverse DNS

---

#### 8b. `whois` — Domain WHOIS Lookup
- **Free, no API key required**
- Returns: Registrar, creation date, expiration date, name servers, DNSSEC status

---

#### 8c. `virustotal` — File Hash Scan *(API Key Required)*
- Target must be a **file path** (auto-hashes with SHA256)
- Returns: Malicious engine hits, undetected count, reputation score, threat label
- Get key: [virustotal.com](https://www.virustotal.com)

---

#### 8d. `abuseipdb` — IP Abuse Check *(API Key Required)*
- Checks IP against abuse reports from the last 90 days
- Returns: Abuse confidence score, total reports, country, ISP, usage type
- Get key: [abuseipdb.com](https://www.abuseipdb.com)

---

#### 8e. `shodan` — Internet-Wide Host Scan *(API Key Required)*
- Returns: Open ports, running services, OS, vulnerabilities (CVEs)
- Get key: [shodan.io](https://www.shodan.io)

---

#### 8f. `malwarebazaar` — Malware Hash Lookup *(API Key in .env)*
- Target must be a **file path** (auto-hashes with SHA256)
- Returns: Malware family, first seen date, tags, delivery method
- Key pre-configured in `.env`

---

#### 8g. `alienvault` — AlienVault OTX Threat Intel *(API Key Required)*
- Works for both IPs and domains
- Returns: Pulse count, threat pulse names, base indicator info
- Get key: [otx.alienvault.com](https://otx.alienvault.com)

---

#### 8h. `safebrowsing` — Google Safe Browsing Check
- **Free, no API key required**
- Uses Google Transparency Report API
- Returns:
  - `is_safe` — Boolean
  - `is_phishing` — Boolean
  - `contains_malware` — Boolean
  - `installs_unwanted_software` — Boolean
  - `redirects_to_harmful` — Boolean
  - `uncommon_downloads` — Boolean
  - `status_description` — Human-readable status

---

#### 8i. `urlscan` — URLScan.io Domain History
- **Free, no API key required**
- Returns: Total historical scans, last 5 scan results with screenshots

---

#### 8j. `pulsedive` — Pulsedive Threat Feed
- **Free, no API key required**
- Returns: Risk level (none/low/medium/high/critical), associated threats, properties

---

#### 8k. `ml_url_analyzer` — AI Phishing Detector
- **Fully offline, no API key required**
- Uses a trained **Random Forest model** with 29 URL features
- Features analyzed:
  - URL length, hostname length, subdirectory count
  - Digit count, special chars, dots, hyphens, underscores
  - Presence of `@`, `?`, `=`, `%` characters
  - Token count, average/longest token length
  - Suspicious keywords: `login`, `verify`, `update`, `secure`, `account`, `bank`, `paypal`, `signin`, `free`, `bonus`
  - IP address in URL, HTTPS presence, TLD length, Shannon entropy
- Returns: Prediction (`benign`/`phishing`/`malware`/`defacement`), confidence %, per-class probabilities

---

#### 8l. `universal_url_validator` — 🔥 All-in-One URL Risk Assessment
- **Runs ALL 5 URL checks simultaneously:**
  1. ML Phishing AI Analysis
  2. Google Safe Browsing
  3. URLScan.io history
  4. Pulsedive threat feed
  5. WHOIS domain age check
- **Plus: Local Heuristics** — instantly flags known phishing tunnel providers:
  - `trycloudflare.com`, `ngrok.io`, `ngrok-free.app`, `serveo.net`, `loca.lt`, `localhost.run`, `portmap.io`, `pinggy.link`, `zrok.io`, `bore.pub`, `loophole.site`, `localto.net`
- **Aggregated Risk Score (0–100):**

| Signal | Max Contribution |
|--------|-----------------|
| Local Heuristics (tunneling provider) | +100 |
| Google Safe Browsing flagged | +35 |
| ML AI prediction (non-benign) | +35 (scaled by confidence) |
| Pulsedive HIGH/CRITICAL risk | +30 |
| Pulsedive MEDIUM risk | +15 |
| Domain age < 180 days | +15 |

- **Final Verdict:**
  - ≥ 75 → **CRITICAL**
  - ≥ 50 → **HIGH**
  - ≥ 25 → **MEDIUM**
  - < 25 → **SAFE**

---

### 9. 📡 Network Forensics (PCAP Analysis)

**Endpoint:** `POST /analyze/network`

Analyzes network packet capture files using TShark (Wireshark CLI).

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `file_path` | string | — | Path to `.pcap` or `.pcapng` file |
| `scan_type` | string | `dns` | Analysis mode |

**Sub-Options (`scan_type`):**

| Value | Description |
|-------|-------------|
| `dns` | Extract all unique DNS query names (deduplicated list of domains contacted) |
| `hierarchy` | Show protocol hierarchy tree (% breakdown of protocols used) |
| `endpoints` | List all IP endpoints (source/destination IPs with packet/byte counts) |

---

### 10. 📧 Email Header Analyzer

**Endpoint:** `POST /analyze/email`

Parses `.eml` email files to extract headers, routing info, and metadata.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to `.eml` email file |

**What it extracts:**
- Sender, recipient, subject, date
- Full email routing path (Received headers)
- Reply-To and X-Mailer fields
- MIME parts and attachments info

---

### 11. 🪟 Windows Event Log Parser (EVTX)

**Endpoint:** `POST /analyze/evtx`

Parses Windows `.evtx` event log files to extract security events.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to Windows `.evtx` event log file |

**Key Event IDs detected:**
- `4624` — Successful login
- `4625` — Failed login attempt
- `4688` — Process creation
- `4648` — Explicit credential logon
- `4720` — User account created
- `4726` — User account deleted

---

### 12. 🖼️ Steganography Detector

**Endpoint:** `POST /analyze/stego`

Detects hidden data inside image files using steghide analysis.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to image file (JPG, PNG, BMP) |

**Requires:** `sudo apt install steghide`

---

### 13. 🔑 Hash Cracker (John the Ripper)

**Endpoint:** `POST /analyze/hash`

Cracks password hashes using John the Ripper.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Path to a file containing the hash string |

**Supported hash types:** MD5, SHA1, SHA224, SHA256, SHA384, SHA512 (auto-detected by length)

---

### 14. 💥 Brute Force & Credential Recovery Engine

**Endpoint:** `POST /analyze/brute`

Multi-protocol intelligent brute-force engine for authorized forensic credential recovery.

**Input Parameters:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `http` | Attack mode (see sub-options) |
| `target` | string | — | URL, hostname, file path, or hash |
| `username` | string | `admin` | Username to test (for HTTP/SSH/FTP) |
| `username_field` | string | `username` | HTML form field name for username |
| `password_field` | string | `password` | HTML form field name for password |
| `success_string` | string | null | String that appears on successful login |
| `failure_string` | string | `Invalid` | String that appears on failed login |
| `port` | int | null | Port number (defaults: SSH=22, FTP=21) |
| `wordlist_path` | string | null | Custom wordlist file path |
| `hash_type` | string | `auto` | Hash algorithm for hash mode |
| `max_attempts` | int | `1000` | Maximum passwords to try |
| `threads` | int | `8` | Parallel threads (HTTP only) |

**Sub-Options (`mode`):**

---

#### 14a. `http` — Web Form Brute Force
- Posts credentials to a login form via HTTP POST
- Multi-threaded (configurable thread count)
- Smart mutations: capitalizes, appends `123`, `@123`, `!`, leet-speak substitutions
- Detects success via `success_string` OR absence of `failure_string`
- Returns full audit log with timestamps and HTTP status codes

---

#### 14b. `ssh` — SSH Brute Force
- Uses **Paramiko** library
- Sequential attempts with 5s timeout per try
- Requires: `pip install paramiko`
- Default port: 22

---

#### 14c. `ftp` — FTP Brute Force
- Uses Python's built-in `ftplib`
- Sequential attempts with 5s timeout
- Default port: 21

---

#### 14d. `zip` — Encrypted ZIP Password Recovery
- First tries **John the Ripper** (C engine, fastest)
- Falls back to **pyzipper** (Python, supports AES-256 ZIPs)
- Requires: `pip install pyzipper`

---

#### 14e. `pdf` — Encrypted PDF Password Recovery
- Uses **pikepdf** library
- Requires: `pip install pikepdf`

---

#### 14f. `hash` — Hash Cracking
- **Auto-detects** hash type from length (MD5=32, SHA1=40, SHA256=64, SHA512=128)
- Strategy 1: **John the Ripper** (uses all CPU cores, fastest)
- Strategy 2: **Python hashlib fallback** (if John not installed)
- Smart mutations applied to wordlist

**Wordlist Strategy (all modes):**
1. Custom wordlist (if provided)
2. `backend/wordlists/top10000.txt`
3. John's built-in list (`/usr/share/john/password.lst`)
4. Smart mutations of top 200 words

---

### 15. 🏛️ Windows Registry Cracker

**Endpoint:** `POST /analyze/registry`

Extracts NTLM password hashes from Windows SAM/SYSTEM registry hives and cracks them.

**Input Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `sam_path` | string | Path to Windows SAM registry hive file |
| `system_path` | string | Path to Windows SYSTEM registry hive file |

**Workflow:**
1. **Impacket secretsdump** — Extracts NTLM hashes from SAM+SYSTEM hive pair
2. Filters out empty/blank NTLM hashes
3. **John the Ripper** (`--format=NT`) — Cracks extracted NTLM hashes
4. Returns: raw dump, extracted hashes, cracked passwords

**How to get SAM/SYSTEM files:**
```
# From a live Windows system (as Administrator):
reg save HKLM\SAM C:\sam.hive
reg save HKLM\SYSTEM C:\system.hive
```

---

## 📊 Investigation History

**Endpoint:** `GET /history`

Returns all past investigations stored in the SQLite database (`forensics.db`), ordered newest-first.

**Response fields per record:**
- `id` — Auto-increment investigation ID
- `filename` — Target file/domain/IP analyzed
- `tool_used` — Which tool was used
- `status` — `Completed` / `Failed` / `Running`
- `created_at` — Timestamp
- `results` — Full JSON results

---

## 🖥️ Frontend UI Guide

The React frontend (`npm run dev` → `http://localhost:5173`) provides:

### Navigation
- **Sidebar** — Click any of the 15 tool icons to open that module
- **History Tab** — View all past investigations with expandable results
- **Each tool** has its own form with all relevant input fields

### UI Features
- 🌙 Dark mode cyber-themed design
- Real-time analysis with loading indicators
- Color-coded risk scores (green → yellow → red)
- Expandable JSON result viewer
- PDF report download button (MobSF)

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
```

---

## ⚠️ Legal Disclaimer

> This tool is built **exclusively for authorized cyber-police forensic investigations**.  
> Unauthorized use against systems you do not own or have explicit written permission to test is **illegal** under the IT Act 2000 (India) and equivalent laws worldwide.  
> The developers accept no liability for misuse.

---

## 👨‍💻 Developer

Built as part of an IFSO  Cyber Forensics project.  
**Made in India 🇮🇳** | CyberX SOC Platform v2.0
live at https://ifso-cyber-forensics-project.vercel.app/
