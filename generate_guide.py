from fpdf import FPDF, XPos, YPos

class PDF(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 20, 'F')
        self.set_font('Helvetica', 'B', 12)
        self.set_text_color(99, 202, 183)
        self.cell(0, 20, '  CyberX Forensics Platform - Installation & Setup Guide',
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-12)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f'CyberX Forensics Platform  |  Page {self.page_no()}', align='C')

    def sec(self, title):
        self.ln(4)
        self.set_fill_color(15, 23, 42)
        self.set_text_color(99, 202, 183)
        self.set_font('Helvetica', 'B', 11)
        self.cell(0, 8, '  ' + title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def sub(self, title):
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(30, 64, 175)
        self.cell(0, 7, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

    def body(self, text):
        self.set_font('Helvetica', '', 9)
        self.multi_cell(0, 5, text)
        self.ln(1)

    def code(self, text):
        self.set_fill_color(30, 41, 59)
        self.set_text_color(134, 239, 172)
        self.set_font('Courier', '', 8)
        self.multi_cell(0, 5, '  ' + text, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def note(self, text):
        self.set_fill_color(254, 243, 199)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(92, 60, 0)
        self.multi_cell(0, 5, '  NOTE: ' + text, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def th(self, cols):
        self.set_fill_color(226, 232, 240)
        self.set_font('Helvetica', 'B', 8)
        for text, w in cols:
            self.cell(w, 6, text, border=1, fill=True)
        self.ln()
        self.set_font('Helvetica', '', 8)

    def tr(self, cols):
        for text, w in cols:
            self.cell(w, 6, str(text), border=1)
        self.ln()


pdf = PDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()

# ── Cover ─────────────────────────────────────────────────────
pdf.set_font('Helvetica', 'B', 20)
pdf.set_text_color(15, 23, 42)
pdf.ln(6)
pdf.cell(0, 12, 'CyberX Forensics Platform', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
pdf.set_font('Helvetica', '', 11)
pdf.set_text_color(99, 102, 241)
pdf.cell(0, 7, 'Complete Installation & Setup Guide', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
pdf.set_font('Helvetica', 'I', 9)
pdf.set_text_color(100, 100, 100)
pdf.cell(0, 6, 'Windows | Linux | macOS', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
pdf.ln(5)

# ── 1. Prerequisites ──────────────────────────────────────────
pdf.sec('1. Prerequisites')

pdf.sub('1.1  Python 3.10+')
pdf.body('Python is required to run the FastAPI backend.')
pdf.code('# Ubuntu / Debian\nsudo apt install python3 python3-pip python3-venv\n\n# macOS (Homebrew)\nbrew install python\n\n# Windows\n# Download from: https://www.python.org/downloads/\n# Tick "Add Python to PATH" during install\npython --version   # verify')

pdf.sub('1.2  Node.js 18+')
pdf.body('Node.js runs the React/Vite frontend.')
pdf.code('# Ubuntu / Debian\ncurl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -\nsudo apt install -y nodejs\n\n# macOS\nbrew install node\n\n# Windows: https://nodejs.org/\nnode --version   # verify')

pdf.sub('1.3  Git')
pdf.code('sudo apt install git   # Linux\n# Windows: https://git-scm.com/download/win')

pdf.sub('1.4  Java 17+ (for Ghidra binary analysis)')
pdf.code('sudo apt install default-jdk   # Linux\n# Windows: https://adoptium.net/\njava -version   # verify')

# ── 2. Project Setup ─────────────────────────────────────────
pdf.sec('2. Project Setup')

pdf.sub('2.1  Clone the Repository')
pdf.code('git clone https://github.com/your-username/cyberx-forensics.git\ncd cyberx-forensics')

pdf.sub('2.2  Backend: Python Virtual Environment')
pdf.code('# Linux / macOS\npython3 -m venv .venv\nsource .venv/bin/activate\npip install -r backend/requirements.txt\n\n# Windows\npython -m venv .venv\n.venv\\Scripts\\activate\npip install -r backend\\requirements.txt')

pdf.sub('2.3  Frontend: Node Packages')
pdf.code('cd frontend\nnpm install\ncd ..')

pdf.sub('2.4  Environment Variables (.env)')
pdf.body('Create backend/.env and add your API keys:')
pdf.code('MALWAREBAZAAR_API_KEY=your_key\nVIRUSTOTAL_API_KEY=your_key\nABUSEIPDB_API_KEY=your_key\nSHODAN_API_KEY=your_key\nALIENVAULT_API_KEY=your_key')
pdf.note('Free keys: virustotal.com | abuseipdb.com | shodan.io | otx.alienvault.com')

# ── 3. System Tools (Linux) ──────────────────────────────────
pdf.add_page()
pdf.sec('3. System Tool Installation - Linux')

pdf.sub('3.1  One-Command Install')
pdf.code('sudo apt update && sudo apt install -y \\\n  exiftool tshark steghide john sleuthkit python3-dev libssl-dev')

pdf.sub('3.2  Volatility 3 (Memory Forensics)')
pdf.code('pip install volatility3\nvol --help   # verify')

pdf.sub('3.3  Ghidra (Binary Reverse Engineering)')
pdf.body('Ghidra is bundled in plugins/ghidra_12.1.2_PUBLIC/')
pdf.code('# Make executable\nchmod +x plugins/ghidra_12.1.2_PUBLIC/support/analyzeHeadless\n\n# Verify\nls plugins/ghidra_12.1.2_PUBLIC/support/analyzeHeadless')
pdf.note('Ghidra requires Java 17+.')

pdf.sub('3.4  impacket (Registry Hash Extraction)')
pdf.code('pip install impacket\nimpacket-secretsdump --help   # verify')

# ── 4. System Tools (Windows) ────────────────────────────────
pdf.sec('4. System Tool Installation - Windows')
pdf.body('Download and install each tool, then add its folder to your system PATH:')
pdf.th([('Tool', 30), ('Download URL', 75), ('Install Notes', 85)])
rows = [
    ('exiftool',    'https://exiftool.org',                      'Rename exiftool(-k).exe to exiftool.exe'),
    ('tshark',      'https://www.wireshark.org',                 'Included in Wireshark installer'),
    ('john',        'https://www.openwall.com/john/',            'Add the run\\ folder to PATH'),
    ('steghide',    'https://steghide.sourceforge.net',          'Add install folder to PATH'),
    ('SleuthKit',   'https://www.sleuthkit.org/sleuthkit/',      'Add bin\\ folder to PATH'),
    ('Volatility3', 'pip install volatility3',                   'Adds vol.exe to .venv\\Scripts\\'),
    ('Java 17',     'https://adoptium.net/',                     'Required for Ghidra'),
]
for r in rows:
    pdf.tr([(r[0], 30), (r[1], 75), (r[2], 85)])

# ── 5. MobSF Setup ───────────────────────────────────────────
pdf.add_page()
pdf.sec('5. MobSF Setup (Mobile Security Framework)')
pdf.body('MobSF performs deep static and dynamic analysis of Android APKs. It runs as a separate server on port 8001.')

pdf.sub('5.1  Start MobSF Server')
pdf.code('cd plugins/Mobile-Security-Framework-MobSF\n\n# First-time setup (Linux/macOS):\n./setup.sh\n\n# Start server:\npython manage.py runserver 0.0.0.0:8001\n\n# Windows:\nsetup.bat\npython manage.py runserver 0.0.0.0:8001')
pdf.note('MobSF must be running BEFORE submitting APK scans from the CyberX dashboard.')

pdf.sub('5.2  Configure the API Key')
pdf.body('1. Open http://localhost:8001 in your browser\n2. Go to Settings -> REST API -> copy the key\n3. Paste it into the wrapper:')
pdf.code('# backend/wrappers/mobsf_wrapper.py\nMOBSF_URL     = "http://127.0.0.1:8001"\nMOBSF_API_KEY = "paste-your-api-key-here"')

pdf.sub('5.3  Static Analysis Pipeline (7 Steps)')
pdf.th([('Step', 12), ('Name', 45), ('Description', 133)])
steps = [
    ('1', 'Connectivity Check',   'Verifies MobSF is reachable before uploading (fail-fast to avoid long waits)'),
    ('2', 'Upload APK',           'Uploads the APK via REST API; MobSF returns a unique file hash'),
    ('3', 'Trigger Scan',         'Starts the MobSF static analysis engine using the file hash'),
    ('4', 'Fetch JSON Report',    'Downloads the full analysis report (manifest, code, cert, permissions, APKID)'),
    ('5', 'Feature Extraction',   'Extracts 11 risk dimensions: severity, permissions, APKID, malware, network, components, certificate, secrets, trackers, APIs, native libs'),
    ('6', 'Risk Score Calc',      'Each dimension gets a 0-100 score; a weighted final score is computed'),
    ('7', 'PDF Report Download',  'MobSF PDF report downloaded and returned as base64 for browser display'),
]
for s in steps:
    pdf.tr([(s[0], 12), (s[1], 45), (s[2], 133)])

pdf.ln(3)
pdf.sub('5.4  Risk Scoring Weights')
pdf.th([('Feature Dimension', 110), ('Weight', 30), ('Max Contribution', 50)])
weights = [
    ('Severity Findings (High/Medium/Low)', '30%', 'High=25pts, Medium=10pts, Low=3pts each'),
    ('Permission Combinations',             '20%', 'Malicious patterns: SMS malware, spyware, etc.'),
    ('Malware Detection (VirusTotal)',       '30%', 'Log-scaled from VT positives count'),
    ('APKID / Anti-Analysis Techniques',    '15%', 'Packer=15-25pts, Anti-VM/Debug=20pts each'),
    ('Network Security',                    '15%', 'Cleartext=20, CertPinBypass=25, TrustUserCA=15'),
    ('Certificate Issues',                  '15%', 'Issues=15pts each, Expired=40pts'),
    ('Exported Components',                 '10%', '5pts per exported activity/service/receiver'),
    ('Hardcoded Secrets',                   '10%', '15pts per found secret'),
    ('Manifest Flags',                      '10%', 'Debuggable=20, Backup=15, No Secure Flag=10'),
]
for w in weights:
    pdf.tr([(w[0], 110), (w[1], 30), (w[2], 50)])

pdf.ln(3)
pdf.sub('5.5  Risk Classification Thresholds')
pdf.th([('Score Range', 30), ('Risk Level', 50), ('Action Required', 110)])
thresholds = [
    ('75 - 100', 'CRITICAL RISK',  'Immediate investigation - likely malware'),
    ('60 - 74',  'HIGH RISK',      'Serious threats detected, do not distribute'),
    ('40 - 59',  'MEDIUM RISK',    'Moderate vulnerabilities, review before use'),
    ('20 - 39',  'LOW RISK',       'Minor issues, considered reasonably safe'),
    ('0  - 19',  'MINIMAL RISK',   'App appears clean and safe'),
]
for t in thresholds:
    pdf.tr([(t[0], 30), (t[1], 50), (t[2], 110)])

pdf.ln(3)
pdf.sub('5.6  Malicious Permission Patterns Detected')
pdf.th([('Pattern Name', 40), ('Permissions Required', 100), ('Risk Weight', 50)])
patterns = [
    ('SMS Malware',     'READ_SMS + SEND_SMS + RECEIVE_SMS',                   '+25 pts'),
    ('Overlay Installer','SYSTEM_ALERT_WINDOW + REQUEST_INSTALL_PACKAGES',     '+20 pts'),
    ('Spyware',         'READ_CONTACTS + READ_CALL_LOG + LOCATION + AUDIO',    '+22 pts'),
    ('Financial Malware','SYSTEM_ALERT_WINDOW + READ_SMS + RECEIVE_SMS',       '+18 pts'),
    ('Device Admin',    'BIND_DEVICE_ADMIN + WRITE_SETTINGS',                  '+15 pts'),
    ('Complete Control','READ_PHONE_STATE + ALERT_WINDOW + INSTALL + SETTINGS','+30 pts'),
    ('Data Exfiltration','READ_CONTACTS + READ_SMS + LOCATION + STORAGE',      '+20 pts'),
]
for p in patterns:
    pdf.tr([(p[0], 40), (p[1], 100), (p[2], 50)])

# ── 6. All 15 Tools ──────────────────────────────────────────
pdf.add_page()
pdf.sec('6. All 15 Analysis Tools - API Reference')
pdf.th([('Endpoint', 55), ('Parameters', 45), ('Engine', 28), ('Description', 62)])
tools = [
    ('/analyze/exiftool',    'file_path',                 'ExifTool',    'Metadata from any file (image, doc, video)'),
    ('/analyze/yara',        'file_path, rules_path',     'YARA',        'Scan file against custom malware rules'),
    ('/analyze/autopsy',     'image_path, scan_type',     'SleuthKit',   'Disk images: mmls/fsstat/fls/timeline'),
    ('/analyze/ghidra',      'file_path',                 'Ghidra',      'Headless binary reverse engineering'),
    ('/analyze/androguard',  'file_path',                 'Androguard',  'APK static: permissions, activities, score'),
    ('/analyze/mobsf',       'file_path',                 'MobSF Static','Deep APK analysis, 9-dimension risk score'),
    ('/analyze/mobsf_dynamic','file_path, wait_time',     'MobSF Dyn.',  'Runtime APK analysis (needs emulator)'),
    ('/analyze/volatility',  'file_path, scan_type',      'Volatility3', 'Memory: info/pslist/malfind/netscan'),
    ('/analyze/threat_intel','target, scan_type, api_key','Multi-source', 'IP/domain: ip/whois/virustotal/shodan/...'),
    ('/analyze/network',     'file_path, scan_type',      'tshark',      'PCAP: dns / hierarchy / endpoints'),
    ('/analyze/email',       'file_path',                 'eml-parser',  'Parse .eml: headers, attachments'),
    ('/analyze/evtx',        'file_path',                 'python-evtx', 'Windows event log EVTX parser'),
    ('/analyze/stego',       'file_path',                 'steghide',    'Hidden data in images/audio'),
    ('/analyze/hash',        'file_path',                 'John Ripper', 'Crack hash files with John the Ripper'),
    ('/analyze/brute',       'mode, target, ...',         'Custom Eng.', 'Brute: http/ssh/ftp/zip/pdf/hash'),
    ('/analyze/registry',    'sam_path, system_path',     'impacket+John','Extract & crack NTLM from SAM/SYSTEM'),
]
for t in tools:
    pdf.tr([(t[0], 55), (t[1], 45), (t[2], 28), (t[3], 62)])

# ── 7. Running ───────────────────────────────────────────────
pdf.add_page()
pdf.sec('7. Running the Platform')

pdf.sub('7.1  Linux / macOS - Quick Start')
pdf.code('# Option A: convenience script\nchmod +x run_linux.sh && ./run_linux.sh\n\n# Option B: manual\n# Terminal 1 - Backend\ncd backend\nuv run --with uvicorn uvicorn main:app --reload --port 8000\n\n# Terminal 2 - Frontend\ncd frontend && npm run dev')

pdf.sub('7.2  Windows - Quick Start')
pdf.code('# Double-click run_windows.bat\n# OR manually in two terminals:\n\n# Terminal 1 - Backend\ncd backend\n..\\.venv\\Scripts\\activate\nuvicorn main:app --reload --port 8000\n\n# Terminal 2 - Frontend\ncd frontend && npm run dev')

pdf.sub('7.3  Service URLs')
pdf.th([('Service', 50), ('URL', 140)])
urls = [
    ('Frontend UI',       'http://localhost:5173'),
    ('Backend API',       'http://localhost:8000'),
    ('API Swagger Docs',  'http://localhost:8000/docs'),
    ('Tool Diagnostics',  'http://localhost:8000/diagnostics'),
    ('MobSF Server',      'http://localhost:8001'),
]
for u in urls:
    pdf.tr([(u[0], 50), (u[1], 140)])

pdf.ln(3)
pdf.sub('7.4  Verify All Tools via Diagnostics Endpoint')
pdf.code('curl http://localhost:8000/diagnostics\n\n# Returns:\n# {\n#   "os": "Linux",\n#   "john": "/usr/sbin/john",\n#   "exiftool": "/usr/bin/exiftool",\n#   "tshark": "/usr/bin/tshark",\n#   "steghide": "/usr/bin/steghide",\n#   "volatility": ".venv/bin/vol",\n#   "ghidra": "plugins/ghidra_12.1.2_PUBLIC/support/analyzeHeadless",\n#   "secretsdump": ".venv/bin/impacket-secretsdump"\n# }')

pdf.sec('8. One-Command Setup Scripts')
pdf.sub('Linux / macOS')
pdf.code('chmod +x setup_linux.sh && ./setup_linux.sh')
pdf.body('This script:\n - Creates the Python virtual environment\n - Installs all pip packages from requirements.txt\n - Runs npm install for the frontend\n - Checks each external tool and prints download links for any that are missing')

pdf.sub('Windows (Run as Administrator)')
pdf.code('setup_windows.bat')
pdf.body('Same as above for Windows. Opens two browser windows with the app after setup.')

# ── Save ─────────────────────────────────────────────────────
out = "/home/krish-sharma/Desktop/Cyber Security Project for cyber safe/CyberX_Installation_Guide.pdf"
pdf.output(out)
print(f"PDF saved: {out}")
