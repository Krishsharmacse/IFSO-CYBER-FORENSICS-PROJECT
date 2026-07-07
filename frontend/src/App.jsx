import React, { useState } from 'react';
import axios from 'axios';
import { Shield, FileText, Camera, HardDrive, Activity, Search, Upload, Play, Terminal, Cpu, Smartphone, Globe, Network, Mail, List, Image, Key, Zap } from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000';

function App() {
  const [activeTab, setActiveTab] = useState('exiftool');
  const [filePath, setFilePath] = useState('');
  const [rulesPath, setRulesPath] = useState('');
  const [volatilityScanType, setVolatilityScanType] = useState('info');
  const [sleuthkitScanType, setSleuthkitScanType] = useState('mmls');
  const [threatIntelScanType, setThreatIntelScanType] = useState('ip');
  const [threatIntelApiKey, setThreatIntelApiKey] = useState('');
  const [networkScanType, setNetworkScanType] = useState('dns');
  const [bruteMode, setBruteMode] = useState('http');
  const [bruteUsername, setBruteUsername] = useState('admin');
  const [bruteUsernameField, setBruteUsernameField] = useState('username');
  const [brutePasswordField, setBrutePasswordField] = useState('password');
  const [bruteFailureStr, setBruteFailureStr] = useState('Invalid');
  const [bruteMaxAttempts, setBruteMaxAttempts] = useState(1000);
  const [brutePort, setBrutePort] = useState('');
  const [systemPath, setSystemPath] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleAnalyze = async () => {
    if (!filePath) return;
    setLoading(true);
    setResults(null);

    try {
      let endpoint = '';
      let payload = { file_path: filePath };

      if (activeTab === 'exiftool') endpoint = '/analyze/exiftool';
      if (activeTab === 'yara') {
        endpoint = '/analyze/yara';
        payload.rules_path = rulesPath;
      }
      if (activeTab === 'autopsy') {
        endpoint = '/analyze/autopsy';
        payload = { image_path: filePath, scan_type: sleuthkitScanType };
      }
      if (activeTab === 'ghidra') {
        endpoint = '/analyze/ghidra';
      }
      if (activeTab === 'androguard') {
        endpoint = '/analyze/androguard';
      }
      if (activeTab === 'mobsf') {
        endpoint = '/analyze/mobsf';
      }
      if (activeTab === 'volatility') {
        endpoint = '/analyze/volatility';
        payload.scan_type = volatilityScanType;
      }
      if (activeTab === 'threat_intel') {
        endpoint = '/analyze/threat_intel';
        payload = { target: filePath, scan_type: threatIntelScanType, api_key: threatIntelApiKey };
      }
      if (activeTab === 'network') {
        endpoint = '/analyze/network';
        payload = { file_path: filePath, scan_type: networkScanType };
      }
      if (activeTab === 'email') endpoint = '/analyze/email';
      if (activeTab === 'evtx') endpoint = '/analyze/evtx';
      if (activeTab === 'stego') endpoint = '/analyze/stego';
      if (activeTab === 'hash') endpoint = '/analyze/hash';
      if (activeTab === 'brute') {
        endpoint = '/analyze/brute';
        payload = {
          mode: bruteMode,
          target: filePath,
          username: bruteUsername,
          username_field: bruteUsernameField,
          password_field: brutePasswordField,
          failure_string: bruteFailureStr,
          max_attempts: parseInt(bruteMaxAttempts) || 1000,
          port: brutePort ? parseInt(brutePort) : null,
        };
      }
      if (activeTab === 'registry') {
        endpoint = '/analyze/registry';
        payload = { sam_path: filePath, system_path: systemPath };
      }

      const res = await axios.post(`${API_BASE}${endpoint}`, payload);
      setResults(res.data);
    } catch (err) {
      setResults({ status: 'Failed', results: { error: err.message } });
    } finally {
      setLoading(false);
    }
  };

  const menuItems = [
    {
      id: 'exiftool', label: 'File Metadata', tool: 'ExifTool', icon: Camera,
      desc: 'Extract hidden EXIF metadata from images, docs & binaries.',
      section: 'File Analysis'
    },
    {
      id: 'yara', label: 'Malware Patterns', tool: 'YARA', icon: Activity,
      desc: 'Scan files with custom YARA rules to detect malware signatures.',
      section: null
    },
    {
      id: 'stego', label: 'Steganography', tool: 'steghide', icon: Image,
      desc: 'Detect hidden payloads inside JPG/WAV/BMP image files.',
      section: null
    },
    {
      id: 'autopsy', label: 'Disk Forensics', tool: 'SleuthKit', icon: HardDrive,
      desc: 'Parse .dd, .E01 (EnCase) disk images. Recover deleted files & timelines.',
      section: 'Disk & Memory'
    },
    {
      id: 'volatility', label: 'Memory Forensics', tool: 'Volatility 3', icon: Terminal,
      desc: 'Analyze RAM dumps for processes, network connections & malware.',
      section: null
    },
    {
      id: 'ghidra', label: 'Reverse Engineering', tool: 'Ghidra', icon: Cpu,
      desc: 'Disassemble & decompile executables to expose malicious logic.',
      section: 'Binary & Mobile'
    },
    {
      id: 'androguard', label: 'APK Static Analysis', tool: 'Androguard', icon: Smartphone,
      desc: 'Decompile Android APKs, extract permissions & Java source code.',
      section: null
    },
    {
      id: 'mobsf', label: 'Mobile Security Scan', tool: 'MobSF', icon: Smartphone,
      desc: 'Deep dynamic & static analysis for Android APKs with PDF report.',
      section: null
    },
    {
      id: 'network', label: 'Network PCAP', tool: 'tshark', icon: Network,
      desc: 'Parse .pcap captures to extract DNS queries, endpoints & protocols.',
      section: 'Network & Threat Intel'
    },
    {
      id: 'threat_intel', label: 'Threat Intelligence', tool: 'OSINT', icon: Globe,
      desc: 'Look up IPs, domains & hashes via AbuseIPDB, VirusTotal & Shodan.',
      section: null
    },
    {
      id: 'email', label: 'Email Phishing', tool: 'eml_parser', icon: Mail,
      desc: 'Decode .eml files to expose hidden sender IPs & routing headers.',
      section: 'Log & Credential Analysis'
    },
    {
      id: 'evtx', label: 'Windows Event Logs', tool: 'python-evtx', icon: List,
      desc: 'Parse Windows .evtx logs to find login attempts & suspicious events.',
      section: null
    },
    {
      id: 'hash', label: 'Hash Cracking', tool: 'John the Ripper', icon: Key,
      desc: 'Brute-force weak password hashes found during an investigation.',
      section: null
    },
    {
      id: 'brute', label: 'Brute Force Attack', tool: 'Python Engine', icon: Zap,
      desc: 'Crack HTTP logins, SSH, FTP, ZIP & PDF files using a 1M password dictionary.',
      section: 'Brute Force'
    },
    {
      id: 'registry', label: 'Windows Registry Crack', tool: 'Impacket+John', icon: Terminal,
      desc: 'Extract NTLM hashes from SAM/SYSTEM hives and crack them.',
      section: null
    },
  ];

  return (
    <div className="dashboard-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="logo">
          <Shield size={28} color="#3b82f6" />
          <span>CyberX Forensics</span>
        </div>

        <div className="nav-menu">
          {menuItems.map((item, idx) => {
            const Icon = item.icon;
            return (
              <React.Fragment key={item.id}>
                {item.section && (
                  <div className="nav-section-label">{item.section}</div>
                )}
                <div
                  className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
                  onClick={() => { setActiveTab(item.id); setResults(null); }}
                >
                  <div className="nav-item-icon"><Icon size={18} /></div>
                  <div className="nav-item-text">
                    <span className="nav-label">{item.label}</span>
                    <span className="nav-desc">{item.desc}</span>
                  </div>
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="header animate-fade-in">
          <h1>{menuItems.find(i => i.id === activeTab)?.label}</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '0.3rem' }}>
            {menuItems.find(i => i.id === activeTab)?.desc}
          </p>
        </header>

        <section className="glass-panel animate-fade-in" style={{ animationDelay: '0.1s' }}>
          <div className="upload-section">
            <Upload className="upload-icon" />
            <h2>Target Artifact / IOC Setup</h2>
            <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>
              Provide the absolute path to the file, or the Target IOC (IP/Domain).
            </p>

            <div className="file-input-wrapper">
              <input
                type="text"
                className="input-field"
                placeholder={
                  activeTab === 'autopsy' ? "/path/to/evidence/image.dd or .E01 (EnCase)" :
                    activeTab === 'ghidra' ? "/path/to/malware/sample.exe" :
                      (activeTab === 'androguard' || activeTab === 'mobsf') ? "/path/to/mobile/app.apk" :
                        activeTab === 'volatility' ? "/path/to/memory/dump.vmem" :
                          (activeTab === 'threat_intel' && threatIntelScanType === 'ip') ? "8.8.8.8" :
                            (activeTab === 'threat_intel' && threatIntelScanType === 'whois') ? "example.com" :
                              (activeTab === 'threat_intel' && (threatIntelScanType === 'virustotal' || threatIntelScanType === 'malwarebazaar')) ? "/path/to/malware.exe" :
                                (activeTab === 'threat_intel' && (threatIntelScanType === 'abuseipdb' || threatIntelScanType === 'shodan' || threatIntelScanType === 'alienvault')) ? "1.1.1.1 or example.com" :
                                  activeTab === 'network' ? "/path/to/capture.pcap" :
                                    activeTab === 'email' ? "/path/to/phishing.eml" :
                                      activeTab === 'evtx' ? "/path/to/Security.evtx" :
                                        activeTab === 'stego' ? "/path/to/suspicious_image.jpg" :
                                          activeTab === 'hash' ? "/path/to/hashes.txt" :
                                            activeTab === 'registry' ? "/path/to/SAM" :
                                              "/path/to/evidence/file.txt"
                }
                value={filePath}
                onChange={(e) => setFilePath(e.target.value)}
              />
            </div>

            {activeTab === 'yara' && (
              <div className="file-input-wrapper" style={{ marginTop: '1rem' }}>
                <input
                  type="text"
                  className="input-field"
                  placeholder="/path/to/rules/malware.yar"
                  value={rulesPath}
                  onChange={(e) => setRulesPath(e.target.value)}
                />
              </div>
            )}

            {activeTab === 'autopsy' && (
              <div className="file-input-wrapper" style={{ marginTop: '1rem' }}>
                <select
                  className="input-field"
                  value={sleuthkitScanType}
                  onChange={(e) => setSleuthkitScanType(e.target.value)}
                  style={{ backgroundColor: 'transparent', color: '#f8fafc', border: 'none', width: '100%', outline: 'none' }}
                >
                  <option value="mmls" style={{ color: '#000' }}>View Partitions (mmls)</option>
                  <option value="fsstat" style={{ color: '#000' }}>File System Info (fsstat)</option>
                  <option value="fls" style={{ color: '#000' }}>List All Files & Deleted (fls)</option>
                  <option value="timeline" style={{ color: '#000' }}>Generate Activity Timeline (mactime)</option>
                </select>
              </div>
            )}

            {activeTab === 'volatility' && (
              <div className="file-input-wrapper" style={{ marginTop: '1rem' }}>
                <select
                  className="input-field"
                  value={volatilityScanType}
                  onChange={(e) => setVolatilityScanType(e.target.value)}
                  style={{ backgroundColor: 'transparent', color: '#f8fafc', border: 'none', width: '100%', outline: 'none' }}
                >
                  <option value="info" style={{ color: '#000' }}>OS Info (windows.info)</option>
                  <option value="pslist" style={{ color: '#000' }}>Process List (windows.pslist)</option>
                  <option value="malfind" style={{ color: '#000' }}>Find Malware Injection (windows.malfind)</option>
                  <option value="netscan" style={{ color: '#000' }}>Network Connections (windows.netscan)</option>
                  <option value="cmdline" style={{ color: '#000' }}>Process Command Lines (windows.cmdline)</option>
                  <option value="filescan" style={{ color: '#000' }}>File Objects in Memory (windows.filescan)</option>
                </select>
              </div>
            )}

            {activeTab === 'threat_intel' && (
              <>
                <div className="file-input-wrapper" style={{ marginTop: '1rem' }}>
                  <select
                    className="input-field"
                    value={threatIntelScanType}
                    onChange={(e) => setThreatIntelScanType(e.target.value)}
                    style={{ backgroundColor: 'transparent', color: '#f8fafc', border: 'none', width: '100%', outline: 'none' }}
                  >
                    <option value="ip" style={{ color: '#000' }}>IP Address Lookup (ip-api)</option>
                    <option value="whois" style={{ color: '#000' }}>Domain WHOIS Lookup</option>
                    <option value="virustotal" style={{ color: '#000' }}>VirusTotal Hash Lookup (Requires File)</option>
                    <option value="malwarebazaar" style={{ color: '#000' }}>MalwareBazaar Hash Lookup (Requires File)</option>
                    <option value="abuseipdb" style={{ color: '#000' }}>AbuseIPDB (Check IP Reputation)</option>
                    <option value="shodan" style={{ color: '#000' }}>Shodan (Scan IP Services)</option>
                    <option value="alienvault" style={{ color: '#000' }}>AlienVault OTX (IP or Domain)</option>
                  </select>
                </div>
                {(threatIntelScanType === 'virustotal' || threatIntelScanType === 'malwarebazaar' || threatIntelScanType === 'abuseipdb' || threatIntelScanType === 'shodan' || threatIntelScanType === 'alienvault') && (
                  <div className="file-input-wrapper" style={{ marginTop: '1rem' }}>
                    <input
                      type="text"
                      className="input-field"
                      placeholder={`Enter your ${threatIntelScanType.toUpperCase()} API Key`}
                      value={threatIntelApiKey}
                      onChange={(e) => setThreatIntelApiKey(e.target.value)}
                    />
                  </div>
                )}
              </>
            )}

            {activeTab === 'network' && (
              <div className="file-input-wrapper" style={{ marginTop: '1rem' }}>
                <select
                  className="input-field"
                  value={networkScanType}
                  onChange={(e) => setNetworkScanType(e.target.value)}
                  style={{ backgroundColor: 'transparent', color: '#f8fafc', border: 'none', width: '100%', outline: 'none' }}
                >
                  <option value="dns" style={{ color: '#000' }}>Extracted DNS Queries (domains)</option>
                  <option value="hierarchy" style={{ color: '#000' }}>Protocol Hierarchy (stats)</option>
                  <option value="endpoints" style={{ color: '#000' }}>IP Endpoints (connections)</option>
                </select>
              </div>
            )}

            {activeTab === 'brute' && (
              <div style={{ width: '100%', maxWidth: '600px', display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
                {/* Mode selector */}
                <select className="input-field" value={bruteMode} onChange={e => setBruteMode(e.target.value)}
                  style={{ backgroundColor: 'rgba(0,0,0,0.3)', color: '#f8fafc', border: '1px solid rgba(65,90,150,0.3)', borderRadius: '0.5rem', padding: '0.75rem 1rem' }}>
                  <option value="http" style={{ color: '#000' }}>🌐 HTTP / Web Login Form</option>
                  <option value="ssh" style={{ color: '#000' }}>🔒 SSH (Secure Shell)</option>
                  <option value="ftp" style={{ color: '#000' }}>📁 FTP (File Transfer)</option>
                  <option value="zip" style={{ color: '#000' }}>🗜️ ZIP File Password</option>
                  <option value="pdf" style={{ color: '#000' }}>📄 PDF File Password</option>
                  <option value="hash" style={{ color: '#000' }}>🔑 Hash Cracking (MD5/SHA)</option>
                </select>

                {/* Username — only for network protocols */}
                {['http', 'ssh', 'ftp'].includes(bruteMode) && (
                  <input className="input-field" type="text" placeholder="Username (e.g. admin)"
                    value={bruteUsername} onChange={e => setBruteUsername(e.target.value)} />
                )}

                {/* HTTP-specific fields */}
                {bruteMode === 'http' && (
                  <>
                    <input className="input-field" type="text" placeholder="Username field name (e.g. username, email)"
                      value={bruteUsernameField} onChange={e => setBruteUsernameField(e.target.value)} />
                    <input className="input-field" type="text" placeholder="Password field name (e.g. password, pass)"
                      value={brutePasswordField} onChange={e => setBrutePasswordField(e.target.value)} />
                    <input className="input-field" type="text" placeholder="Failure string to detect wrong password (e.g. Invalid)"
                      value={bruteFailureStr} onChange={e => setBruteFailureStr(e.target.value)} />
                  </>
                )}

                {/* Port — SSH/FTP */}
                {['ssh', 'ftp'].includes(bruteMode) && (
                  <input className="input-field" type="number" placeholder={`Port (default: ${bruteMode === 'ssh' ? 22 : 21})`}
                    value={brutePort} onChange={e => setBrutePort(e.target.value)} />
                )}

                {/* Max attempts */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <input className="input-field" type="number" placeholder="Max attempts (default: 1000)"
                    value={bruteMaxAttempts} onChange={e => setBruteMaxAttempts(e.target.value)} style={{ flex: 1 }} />
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                    of 1,000,000 in dictionary
                  </span>
                </div>

                <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                  ⚡ Using built-in 1M password dictionary (rockyou-derived). Leave target input above as: URL / host IP / file path / hash string.
                </p>
              </div>
            )}

            {activeTab === 'registry' && (
              <div className="file-input-wrapper" style={{ marginTop: '1rem' }}>
                <input
                  type="text"
                  className="input-field"
                  placeholder="/path/to/SYSTEM"
                  value={systemPath}
                  onChange={(e) => setSystemPath(e.target.value)}
                />
              </div>
            )}

            <button
              className="btn"
              style={{ marginTop: '2rem' }}
              onClick={handleAnalyze}
              disabled={loading || !filePath || (activeTab === 'yara' && !rulesPath)}
            >
              {loading ? (
                <>
                  <Search className="animate-pulse" size={20} /> Analyzing...
                </>
              ) : (
                <>
                  <Play size={20} /> Start Analysis
                </>
              )}
            </button>
          </div>
        </section>

        {results && (
          <section className="glass-panel animate-fade-in" style={{ marginTop: '2rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <h3 style={{ fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Terminal size={20} color="var(--primary)" />
                Analysis Results
              </h3>
              <span className={`badge ${results.status === 'Failed' ? 'failed' : ''}`}>
                {results.status}
              </span>
            </div>

            {results.results?.analysis_verdict && (
              <div style={{
                padding: '1.5rem',
                borderRadius: '0.75rem',
                marginBottom: '1.5rem',
                backgroundColor: results.results.analysis_verdict === 'MALICIOUS' ? 'rgba(239, 68, 68, 0.15)' :
                  results.results.analysis_verdict === 'SUSPICIOUS' ? 'rgba(245, 158, 11, 0.15)' :
                    'rgba(16, 185, 129, 0.15)',
                border: `1px solid ${results.results.analysis_verdict === 'MALICIOUS' ? '#ef4444' :
                  results.results.analysis_verdict === 'SUSPICIOUS' ? '#f59e0b' :
                    '#10b981'}`
              }}>
                <h3 style={{
                  color: results.results.analysis_verdict === 'MALICIOUS' ? '#ef4444' :
                    results.results.analysis_verdict === 'SUSPICIOUS' ? '#f59e0b' :
                      '#10b981',
                  fontSize: '1.25rem',
                  marginBottom: '1rem'
                }}>
                  Threat Verdict: {results.results.analysis_verdict} (Score: {results.results.threat_score}/100)
                </h3>

                {results.results.threat_flags?.length > 0 ? (
                  <ul style={{ paddingLeft: '1.5rem', color: '#f8fafc', lineHeight: '1.8' }}>
                    {results.results.threat_flags.map((flag, idx) => (
                      <li key={idx}>⚠️ {flag}</li>
                    ))}
                  </ul>
                ) : (
                  <p style={{ color: '#10b981' }}>✅ No immediate threats detected in metadata.</p>
                )}
              </div>
            )}

            {results.results?.pdf_report_url && (
              <div style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'center' }}>
                <a
                  href={`${API_BASE}${results.results.pdf_report_url}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn"
                  style={{ backgroundColor: '#ef4444', textDecoration: 'none', display: 'inline-flex', gap: '0.5rem', padding: '1rem 2rem', fontSize: '1.1rem' }}
                >
                  <FileText size={20} /> Download Full PDF Report
                </a>
              </div>
            )}

            <pre className="json-view">
              {JSON.stringify(results.results, null, 2)}
            </pre>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
