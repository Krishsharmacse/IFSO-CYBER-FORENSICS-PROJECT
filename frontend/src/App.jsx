import React, { useState, useEffect } from 'react';
import axios from 'axios';
import CyberChat from './CyberChat';
import CaseManagement from './CaseManagement';
import {
  Shield, FileText, Briefcase, Camera, HardDrive, Activity, Search, Upload, Play,
  Terminal, Cpu, Smartphone, Globe, Network, Mail, List, Image, Key, Zap,
  ChevronDown, ChevronRight, Folder, FolderOpen, RefreshCw, AlertTriangle, CheckCircle, Info,
  Eye, FileCode, Server
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

function App() {
  const [activeTab, setActiveTab] = useState('cases');
  const [activeCaseGlobal, setActiveCaseGlobal] = useState(null);
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
  const [ghidraTimeout, setGhidraTimeout] = useState(900);
  const [ghidraExtractCode, setGhidraExtractCode] = useState(true);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [resultSubTab, setResultSubTab] = useState('dashboard');


  const [sidebarSearch, setSidebarSearch] = useState('');
  const [expandedCategories, setExpandedCategories] = useState({
    static: true,
    deep: true,
    mobile: true,
    logs: true
  });


  const [metadataSearch, setMetadataSearch] = useState('');


  const [loaderMessage, setLoaderMessage] = useState('');
  const [loaderSteps, setLoaderSteps] = useState([]);

  const toggleCategory = (cat) => {
    setExpandedCategories(prev => ({ ...prev, [cat]: !prev[cat] }));
  };


  const categories = [
    {
      id: 'management',
      title: 'Investigation Management',
      icon: Briefcase,
      items: [
        {
          id: 'cases', label: 'Case Management', tool: 'Tracker', icon: Briefcase,
          desc: 'Manage cases, log evidence, and track analysis history.'
        }
      ]
    },

    {
      id: 'static',
      title: 'Static & Malware',
      icon: Folder,
      items: [
        {
          id: 'exiftool', label: 'File Metadata', tool: 'ExifTool', icon: Camera,
          desc: 'Extract hidden EXIF metadata from images, docs & binaries.'
        },
        {
          id: 'yara', label: 'Malware Patterns', tool: 'YARA', icon: Activity,
          desc: 'Scan files with custom YARA rules to detect malware signatures.'
        },
        {
          id: 'stego', label: 'Steganography', tool: 'steghide', icon: Image,
          desc: 'Detect hidden payloads inside JPG/WAV/BMP image files.'
        }
      ]
    },
    {
      id: 'deep',
      title: 'Deep Forensics',
      icon: Folder,
      items: [
        {
          id: 'autopsy', label: 'Disk Forensics', tool: 'SleuthKit', icon: HardDrive,
          desc: 'Parse .dd, .E01 disk images. Recover deleted files.'
        },
        {
          id: 'volatility', label: 'Memory Forensics', tool: 'Volatility 3', icon: Terminal,
          desc: 'Analyze RAM dumps for processes, connections & malware.'
        },
        {
          id: 'network', label: 'Network PCAP', tool: 'tshark', icon: Network,
          desc: 'Parse .pcap captures to extract DNS, endpoints & protocols.'
        },
        {
          id: 'threat_intel', label: 'Threat Intel OSINT', tool: 'OSINT', icon: Globe,
          desc: 'Look up IPs, domains & hashes via abuse lists, VT & Shodan.'
        },
        {
          id: 'ip_resolver', label: 'IP Resolver', tool: 'IP Intelligence', icon: Server,
          desc: 'Fully resolve IPv4 & IPv6: geo, ASN, reverse DNS, ISP & threat flags.'
        }
      ]
    },
    {
      id: 'mobile',
      title: 'Mobile & Binaries',
      icon: Folder,
      items: [
        {
          id: 'androguard', label: 'APK Static Analysis', tool: 'Androguard', icon: Smartphone,
          desc: 'Statically parse APK files, extract permissions, services, and check spoof indicators.'
        },
        {
          id: 'jadx', label: 'APK Decompiler', tool: 'Jadx', icon: FileCode,
          desc: 'Decompile APK files to Java source code.'
        },
        {
          id: 'ghidra', label: 'Reverse Engineering', tool: 'Ghidra Headless', icon: Cpu,
          desc: 'Disassemble & decompile binaries to expose malicious logic.'
        },
        {
          id: 'mobsf', label: 'Mobile Security Scan', tool: 'MobSF Static', icon: Smartphone,
          desc: 'Deep security analysis for Android APKs with PDF reports.'
        }
      ]
    },
    {
      id: 'logs',
      title: 'Logs & Credentials',
      icon: Folder,
      items: [
        {
          id: 'email', label: 'Email Phishing', tool: 'eml_parser', icon: Mail,
          desc: 'Decode .eml files to expose sender IPs & routing headers.'
        },
        {
          id: 'evtx', label: 'Windows Event Logs', tool: 'python-evtx', icon: List,
          desc: 'Parse Windows .evtx logs to find suspicious logon events.'
        },
        {
          id: 'hash', label: 'Hash Cracking', tool: 'John the Ripper', icon: Key,
          desc: 'Brute-force weak hashes (MD5, SHA) with custom wordlists.'
        },
        {
          id: 'brute', label: 'Brute Force Attack', tool: 'Hydra Engine', icon: Zap,
          desc: 'Crack HTTP logins, SSH, FTP, ZIP & PDF files.'
        },
        {
          id: 'registry', label: 'Registry Hive Crack', tool: 'Impacket', icon: Terminal,
          desc: 'Extract and crack NTLM secrets from SAM/SYSTEM hives.'
        }
      ]
    }
  ];


  useEffect(() => {
    let interval;
    if (loading) {
      const messages = {
        exiftool: [
          'Initializing ExifTool wrapper...',
          'Opening file stream...',
          'Parsing binary header bytes...',
          'Extracting tags: GPS, Camera, Author, timestamps...',
          'Formatting metadata keys...'
        ],
        yara: [
          'Loading custom YARA compile rules...',
          'Compiling signature database...',
          'Scanning target binary streams...',
          'Evaluating logic blocks for malware matches...',
          'Generating hit report...'
        ],
        androguard: [
          'Initializing Androguard static engine...',
          'Opening APK zip archive...',
          'Decompressing AndroidManifest.xml data...',
          'Parsing XML namespace tree & declarations...',
          'Extracting app name, package and version parameters...',
          'Analyzing component classes: Activities, Services, Receivers...',
          'Cross-matching permissions against known overlay/malware lists...',
          'Calculating static APK threat risk score...'
        ],
        jadx: [
          'Initializing Jadx decompiler...',
          'Unpacking APK archive...',
          'Decompiling dex bytecode to Java...',
          'Exporting resources and source files...',
          'Completing decompilation process...'
        ],
        mobsf: [
          'Checking MobSF local status on port 8001...',
          'Uploading APK file to analysis container...',
          'Running static analyzers (androguard engine)...',
          'Scanning manifest for dangerous permissions...',
          'Unpacking dex code blocks...',
          'Decompiling APK to Java source...',
          'Running YARA rules over decompiled java resources...',
          'Checking APK certificate signatures...',
          'Querying VirusTotal for hash matches...',
          'Compiling final MobSF analysis report...'
        ],
        network: [
          'Invoking tshark engine...',
          'Reading PCAP packet descriptors...',
          'Parsing DNS queries and response packets...',
          'Building packet protocol hierarchy graphs...',
          'Calculating connection bandwidth & endpoint coordinates...'
        ],
        threat_intel: [
          'Verifying IOC target type...',
          'Connecting to AbuseIPDB reputation API...',
          'Quering VirusTotal malware telemetry...',
          'Querying Shodan network service scanner...',
          'Fetching DNS WHOIS database record...'
        ],
        ip_resolver: [
          'Parsing IP address structure...',
          'Detecting IP version (v4/v6) and classification...',
          'Running forward DNS resolution...',
          'Performing reverse PTR lookup...',
          'Querying ip-api.com geolocation engine...',
          'Fetching ISP, ASN, and organization data...',
          'Supplementing with ipinfo.io intelligence...',
          'Computing threat flags and risk assessment...'
        ],
        default: [
          'Spawning sandbox environment...',
          'Mounting input target file...',
          'Executing forensic utility binaries...',
          'Parsing STDOUT streams to JSON format...',
          'Structuring data models...'
        ]
      };

      const steps = messages[activeTab] || messages.default;
      let idx = 0;
      setLoaderSteps([]);

      setLoaderMessage(steps[0]);
      setLoaderSteps([`> ${steps[0]}`]);

      interval = setInterval(() => {
        idx++;
        if (idx < steps.length) {
          setLoaderMessage(steps[idx]);
          setLoaderSteps(prev => [...prev, `> ${steps[idx]}`]);
        } else {
          setLoaderMessage('Finalizing report structure...');
          setLoaderSteps(prev => [...prev, '> Finalizing report structure...']);
        }
      }, 1200);
    }
    return () => clearInterval(interval);
  }, [loading, activeTab]);

  const handleAnalyze = async () => {
    if (!filePath) return;
    setLoading(true);
    setResults(null);
    setResultSubTab('dashboard');

    try {
      let endpoint = '';
      let payload = { file_path: filePath, case_id: activeCaseGlobal };

      if (activeTab === 'exiftool') endpoint = '/analyze/exiftool';
      if (activeTab === 'yara') {
        endpoint = '/analyze/yara';
        payload.rules_path = rulesPath; payload.case_id = activeCaseGlobal;
      }
      if (activeTab === 'androguard') endpoint = '/analyze/androguard';
      if (activeTab === 'jadx') endpoint = '/analyze/jadx';
      if (activeTab === 'autopsy') {
        endpoint = '/analyze/autopsy';
        payload = { image_path: filePath, scan_type: sleuthkitScanType, case_id: activeCaseGlobal };
      }
      if (activeTab === 'ghidra') {
        endpoint = '/analyze/ghidra';
        payload.extract_code = ghidraExtractCode; payload.case_id = activeCaseGlobal;
        payload.timeout = parseInt(ghidraTimeout) || 900;
      }
      if (activeTab === 'mobsf') endpoint = '/analyze/mobsf';

      if (activeTab === 'volatility') {
        endpoint = '/analyze/volatility';
        payload.scan_type = volatilityScanType; payload.case_id = activeCaseGlobal;
      }
      if (activeTab === 'threat_intel') {
        endpoint = '/analyze/threat_intel';
        payload = { target: filePath, scan_type: threatIntelScanType, api_key: threatIntelApiKey, case_id: activeCaseGlobal };
      }
      if (activeTab === 'network') {
        endpoint = '/analyze/network';
        payload = { file_path: filePath, scan_type: networkScanType, case_id: activeCaseGlobal };
      }
      if (activeTab === 'email') endpoint = '/analyze/email';
      if (activeTab === 'evtx') endpoint = '/analyze/evtx';
      if (activeTab === 'stego') endpoint = '/analyze/stego';
      if (activeTab === 'hash') endpoint = '/analyze/hash';
      if (activeTab === 'brute') {
        payload = {
          file_path: filePath,
          mode: bruteMode,
          target: filePath,
          username: bruteUsername,
          username_field: bruteUsernameField,
          password_field: brutePasswordField,
          failure_string: bruteFailureStr,
          max_attempts: parseInt(bruteMaxAttempts) || 1000,
          port: brutePort ? parseInt(brutePort) : null,
          case_id: activeCaseGlobal
        };
        endpoint = '/analyze/brute';
      }
      if (activeTab === 'registry') {
        endpoint = '/analyze/registry';
        payload = { sam_path: filePath, system_path: systemPath, case_id: activeCaseGlobal };
      }
      if (activeTab === 'ip_resolver') {
        endpoint = '/analyze/ip_resolver';
        payload = { target: filePath, case_id: activeCaseGlobal };
      }

      const axiosTimeout = activeTab === 'ghidra' ? ((parseInt(ghidraTimeout) || 900) + 5) * 1000 : 0;
      const res = await axios.post(`${API_BASE}${endpoint}`, payload, axiosTimeout ? { timeout: axiosTimeout } : {});
      setResults(res.data);
    } catch (err) {
      setResults({ status: 'Failed', results: { error: err.message } });
    } finally {
      setLoading(false);
    }
  };


  const filteredCategories = categories.map(cat => {
    const matchedItems = cat.items.filter(item =>
      item.label.toLowerCase().includes(sidebarSearch.toLowerCase()) ||
      item.desc.toLowerCase().includes(sidebarSearch.toLowerCase()) ||
      item.tool.toLowerCase().includes(sidebarSearch.toLowerCase())
    );
    return { ...cat, items: matchedItems };
  }).filter(cat => cat.items.length > 0);

  return (
    <div className="dashboard-container cyber-grid">
      <div className="scanline"></div>

      { }
      <aside className="sidebar">
        <div className="cyber-corner-tl"></div>
        <div className="cyber-corner-bl"></div>

        <div className="logo glowing-text">
          <Shield size={26} color="#00f0ff" />
          <span>CYBERX</span>
        </div>

        <div className="system-subtitle">
          <span>SEC-OPS</span>
        </div>

        { }
        <div className="sidebar-search">
          <Search size={14} className="search-icon" />
          <input
            type="text"
            placeholder="FILTER FORENSIC ENGINES..."
            value={sidebarSearch}
            onChange={(e) => setSidebarSearch(e.target.value)}
          />
        </div>

        <div className="nav-menu">
          {filteredCategories.map((cat) => {
            const CatIcon = expandedCategories[cat.id] ? FolderOpen : Folder;
            return (
              <div key={cat.id} className="category-group">
                <div className="category-header" onClick={() => toggleCategory(cat.id)}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <CatIcon size={14} style={{ color: 'var(--primary)' }} />
                    <span>{cat.title}</span>
                  </div>
                  {expandedCategories[cat.id] ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                </div>

                {expandedCategories[cat.id] && (
                  <div className="category-items">
                    {cat.items.map(item => {
                      const Icon = item.icon;
                      return (
                        <div
                          key={item.id}
                          className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
                          onClick={() => { setActiveTab(item.id); setResults(null); }}
                        >
                          <Icon size={15} className="item-icon" />
                          <div className="item-info">
                            <div className="item-title">{item.label}</div>
                            <div className="item-subtitle">{item.tool}</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="sidebar-footer">
          <div className="footer-status-grid">
            <div className="status-item">
              <span className="pulse-green"></span>
              <span>HOST: ACTIVE</span>
            </div>
            <div className="status-item">
              <span>PORT: 8000</span>
            </div>
            <div className="status-item security-level">
              <span>LEVEL: 4</span>
            </div>
          </div>
        </div>
      </aside>

      { }
      <main className="main-content">
        { }
        <header className="header animate-fade-in">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h1 className="glowing-text">{categories.flatMap(c => c.items).find(i => i.id === activeTab)?.label}</h1>
              <p className="tool-desc">
                Engine: <strong style={{ color: '#00f0ff' }}>{categories.flatMap(c => c.items).find(i => i.id === activeTab)?.tool}</strong> — {categories.flatMap(c => c.items).find(i => i.id === activeTab)?.desc}
              </p>
            </div>
            {results && (
              <button className="btn btn-secondary" onClick={() => setResults(null)}>
                <RefreshCw size={14} /> Reset Session
              </button>
            )}
          </div>
        </header>

        { }
        <section className="cyber-panel animate-fade-in" style={{ animationDelay: '0.1s' }}>
          <div className="cyber-corner-tl"></div>
          <div className="cyber-corner-tr"></div>
          <div className="cyber-corner-bl"></div>
          <div className="cyber-corner-br"></div>

          {activeTab === 'cases' && <CaseManagement setActiveCaseGlobal={setActiveCaseGlobal} />}
          {activeTab !== 'cases' && <><div className="form-title">
            <Server size={18} style={{ color: 'var(--primary)' }} />
            <h2>Investigation Setup</h2>
          </div>

          <div className="setup-grid">
            <div className="input-block">
              <label>Absolute File/Target Path</label>
              <input
                type="text"
                className="input-field cyber-input"
                placeholder={
                  activeTab === 'ip_resolver' ? "8.8.8.8 or 2001:4860:4860::8888" :
                  activeTab === 'autopsy' ? (sleuthkitScanType === 'deleted_files' ? "D:\\burger or D:\\" : "/path/to/evidence/image.dd or .E01") :
                    activeTab === 'ghidra' ? "/path/to/malware/sample.exe" :
                      activeTab === 'mobsf' || activeTab === 'androguard' || activeTab === 'jadx' ? "/path/to/mobile/app.apk" :
                        activeTab === 'volatility' ? "/path/to/memory/dump.vmem" :
                          (activeTab === 'threat_intel' && threatIntelScanType === 'ip') ? "8.8.8.8" :
                            (activeTab === 'threat_intel' && (threatIntelScanType === 'whois' || threatIntelScanType === 'safebrowsing' || threatIntelScanType === 'urlscan' || threatIntelScanType === 'pulsedive')) ? "example.com" :
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

            { }
            {activeTab === 'yara' && (
              <div className="input-block">
                <label>YARA Rules Path (.yar)</label>
                <input
                  type="text"
                  className="input-field cyber-input"
                  placeholder="/path/to/rules/malware.yar"
                  value={rulesPath}
                  onChange={(e) => setRulesPath(e.target.value)}
                />
              </div>
            )}

            {activeTab === 'ghidra' && (
              <>
                <div className="input-block">
                  <label>Analysis Timeout (seconds)</label>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <input
                      type="number"
                      className="input-field cyber-input"
                      min={60}
                      max={3600}
                      value={ghidraTimeout}
                      onChange={(e) => setGhidraTimeout(e.target.value)}
                      style={{ width: '110px' }}
                    />
                    <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                      {[{ v: 300, label: '5m' }, { v: 600, label: '10m' }, { v: 900, label: '15m' }, { v: 1800, label: '30m' }, { v: 3600, label: '1h' }].map(p => (
                        <button
                          key={p.v}
                          type="button"
                          onClick={() => setGhidraTimeout(p.v)}
                          style={{
                            padding: '0.25rem 0.55rem',
                            fontSize: '0.7rem',
                            fontFamily: 'monospace',
                            borderRadius: '4px',
                            border: `1px solid ${parseInt(ghidraTimeout) === p.v ? 'var(--primary)' : 'rgba(255,255,255,0.12)'}`,
                            background: parseInt(ghidraTimeout) === p.v ? 'rgba(0,240,255,0.12)' : 'transparent',
                            color: parseInt(ghidraTimeout) === p.v ? 'var(--primary)' : 'var(--text-muted)',
                            cursor: 'pointer',
                            transition: 'all 0.15s',
                          }}
                        >{p.label}</button>
                      ))}
                    </div>
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '0.3rem', fontFamily: 'monospace' }}>
                    ⚠ Large binaries (Office, browsers) need 15–60 min. Default: 15 min.
                  </div>
                </div>
                <div className="input-block">
                  <label>Decompile to C Source</label>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    {[{ v: true, label: 'YES — Full Decompile' }, { v: false, label: 'NO — Metadata Only' }].map(opt => (
                      <button
                        key={String(opt.v)}
                        type="button"
                        onClick={() => setGhidraExtractCode(opt.v)}
                        style={{
                          padding: '0.35rem 0.85rem',
                          fontSize: '0.75rem',
                          fontFamily: 'monospace',
                          borderRadius: '4px',
                          border: `1px solid ${ghidraExtractCode === opt.v ? 'var(--primary)' : 'rgba(255,255,255,0.12)'}`,
                          background: ghidraExtractCode === opt.v ? 'rgba(0,240,255,0.12)' : 'transparent',
                          color: ghidraExtractCode === opt.v ? 'var(--primary)' : 'var(--text-muted)',
                          cursor: 'pointer',
                          transition: 'all 0.15s',
                        }}
                      >{opt.label}</button>
                    ))}
                  </div>
                </div>
              </>
            )}

            {activeTab === 'autopsy' && (
              <div className="input-block">
                <label>Disk Extraction Mode</label>
                <select
                  className="input-field select-field cyber-input"
                  value={sleuthkitScanType}
                  onChange={(e) => setSleuthkitScanType(e.target.value)}
                >
                  <option value="mmls">View Partitions (mmls)</option>
                  <option value="fsstat">File System Info (fsstat)</option>
                  <option value="fls">List All Files & Deleted (fls)</option>
                  <option value="timeline">Generate Activity Timeline (mactime)</option>
                  <option value="enterprise">Enterprise Extraction Pipeline</option>
                  <option value="deleted_files">🔍 Find Deleted Files (Live Drive)</option>
                </select>
                {sleuthkitScanType === 'deleted_files' && (
                  <div style={{ fontSize: '0.72rem', color: 'var(--accent)', marginTop: '0.4rem', fontFamily: 'monospace', lineHeight: 1.5 }}>
                    ⚡ Scans a live drive/USB for deleted files via raw volume access.<br />
                    ⚠ Requires backend running as <strong>Administrator</strong>.
                  </div>
                )}
              </div>
            )}

            {activeTab === 'volatility' && (
              <div className="input-block">
                <label>Volatility Analysis Plugin</label>
                <select
                  className="input-field select-field cyber-input"
                  value={volatilityScanType}
                  onChange={(e) => setVolatilityScanType(e.target.value)}
                >
                  <option value="info">OS Info (windows.info)</option>
                  <option value="pslist">Process List (windows.pslist)</option>
                  <option value="malfind">Find Malware Injection (windows.malfind)</option>
                  <option value="netscan">Network Connections (windows.netscan)</option>
                  <option value="cmdline">Process Command Lines (windows.cmdline)</option>
                  <option value="filescan">File Objects in Memory (windows.filescan)</option>
                </select>
              </div>
            )}

            {activeTab === 'threat_intel' && (
              <>
                <div className="input-block">
                  <label>Intel Source / Plugin</label>
                  <select
                    className="input-field select-field cyber-input"
                    value={threatIntelScanType}
                    onChange={(e) => setThreatIntelScanType(e.target.value)}
                  >
                    <option value="ip">IP Address Lookup (ip-api)</option>
                    <option value="whois">Domain WHOIS Lookup</option>
                    <option value="safebrowsing">Google Safe Browsing (URL/Domain)</option>
                    <option value="urlscan">URLScan.io (Sandbox/Phishing)</option>
                    <option value="pulsedive">Pulsedive (Threat Intel)</option>
                    <option value="virustotal">VirusTotal Hash Lookup (Requires File)</option>
                    <option value="malwarebazaar">MalwareBazaar Hash Lookup (Requires File)</option>
                    <option value="abuseipdb">AbuseIPDB (Check IP Reputation)</option>
                    <option value="shodan">Shodan (Scan IP Services)</option>
                    <option value="alienvault">AlienVault OTX (IP/Domain/Hash)</option>
                    <option value="ml_url_analyzer">ML URL Analyzer (Random Forest)</option>
                    <option value="universal_url_validator">Universal URL Threat Analysis (Google + Pulsedive + ML Model)</option>
                  </select>
                </div>
                {(threatIntelScanType === 'virustotal' || threatIntelScanType === 'malwarebazaar' || threatIntelScanType === 'abuseipdb' || threatIntelScanType === 'shodan' || threatIntelScanType === 'alienvault') && (
                  <div className="input-block">
                    <label>{threatIntelScanType.toUpperCase()} Auth Key</label>
                    <input
                      type="text"
                      className="input-field cyber-input"
                      placeholder={`Enter API Key for authorization`}
                      value={threatIntelApiKey}
                      onChange={(e) => setThreatIntelApiKey(e.target.value)}
                    />
                  </div>
                )}
              </>
            )}

            {activeTab === 'network' && (
              <div className="input-block">
                <label>PCAP Output Detail</label>
                <select
                  className="input-field select-field cyber-input"
                  value={networkScanType}
                  onChange={(e) => setNetworkScanType(e.target.value)}
                >
                  <option value="dns">Extracted DNS Queries (domains)</option>
                  <option value="hierarchy">Protocol Hierarchy (stats)</option>
                  <option value="endpoints">IP Endpoints (connections)</option>
                </select>
              </div>
            )}

            {activeTab === 'brute' && (
              <div className="brute-parameters-grid">
                <div className="input-block">
                  <label>Brute Mode</label>
                  <select className="input-field select-field cyber-input" value={bruteMode} onChange={e => setBruteMode(e.target.value)}>
                    <option value="http">🌐 HTTP Login Form</option>
                    <option value="ssh">🔒 SSH (Secure Shell)</option>
                    <option value="ftp">📁 FTP (File Transfer)</option>
                    <option value="zip">🗜️ ZIP File Password</option>
                    <option value="pdf">📄 PDF File Password</option>
                    <option value="hash">🔑 Hash Cracking (MD5/SHA)</option>
                  </select>
                </div>

                {['http', 'ssh', 'ftp'].includes(bruteMode) && (
                  <div className="input-block">
                    <label>Target Account Username</label>
                    <input className="input-field cyber-input" type="text" placeholder="Username (e.g. admin)"
                      value={bruteUsername} onChange={e => setBruteUsername(e.target.value)} />
                  </div>
                )}

                {bruteMode === 'http' && (
                  <>
                    <div className="input-block">
                      <label>Username Field ID</label>
                      <input className="input-field cyber-input" type="text" value={bruteUsernameField} onChange={e => setBruteUsernameField(e.target.value)} />
                    </div>
                    <div className="input-block">
                      <label>Password Field ID</label>
                      <input className="input-field cyber-input" type="text" value={brutePasswordField} onChange={e => setBrutePasswordField(e.target.value)} />
                    </div>
                    <div className="input-block">
                      <label>HTTP Error Detect String</label>
                      <input className="input-field cyber-input" type="text" value={bruteFailureStr} onChange={e => setBruteFailureStr(e.target.value)} />
                    </div>
                  </>
                )}

                {['ssh', 'ftp'].includes(bruteMode) && (
                  <div className="input-block">
                    <label>Custom Port</label>
                    <input className="input-field cyber-input" type="number" placeholder={`Default: ${bruteMode === 'ssh' ? 22 : 21}`}
                      value={brutePort} onChange={e => setBrutePort(e.target.value)} />
                  </div>
                )}

                <div className="input-block">
                  <label>Max Dictionary Attempts</label>
                  <input className="input-field cyber-input" type="number" value={bruteMaxAttempts} onChange={e => setBruteMaxAttempts(e.target.value)} />
                </div>
              </div>
            )}

            {activeTab === 'registry' && (
              <div className="input-block">
                <label>SYSTEM Registry Hive Path</label>
                <input
                  type="text"
                  className="input-field cyber-input"
                  placeholder="/path/to/SYSTEM"
                  value={systemPath}
                  onChange={(e) => setSystemPath(e.target.value)}
                />
              </div>
            )}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.5rem' }}>
            <button
              className="btn btn-primary btn-cyber"
              onClick={handleAnalyze}
              disabled={loading || !filePath || (activeTab === 'yara' && !rulesPath)}
            >
              {loading ? (
                <>
                  <RefreshCw className="animate-spin" size={16} /> ANALYZING NODE...
                </>
              ) : (
                <>
                  <Play size={16} /> EXECUTE ANALYSIS ENGINE
                </>
              )}
            </button>
          </div></>}
        </section>

        { }
        {loading && (
          <section className="cyber-panel animate-fade-in" style={{ marginTop: '2rem', background: '#04070f', border: '1px solid rgba(0, 240, 255, 0.3)' }}>
            <div className="cyber-corner-tl" style={{ borderColor: '#00f0ff' }}></div>
            <div className="cyber-corner-tr" style={{ borderColor: '#00f0ff' }}></div>
            <div className="cyber-corner-bl" style={{ borderColor: '#00f0ff' }}></div>
            <div className="cyber-corner-br" style={{ borderColor: '#00f0ff' }}></div>

            <div className="scanner-laser"></div>

            <div className="terminal-header">
              <div className="terminal-dots">
                <span className="dot red"></span>
                <span className="dot yellow"></span>
                <span className="dot green"></span>
              </div>
              <span className="terminal-title">SYS-OPS</span>
            </div>
            <div className="terminal-body">
              <div className="terminal-logs">
                {loaderSteps.map((step, idx) => (
                  <div key={idx} className="log-line">{step}</div>
                ))}
              </div>
              <div className="terminal-current">
                <span className="prompt">cyberx@soc_core:~#</span>
                <span className="message animate-pulse">{loaderMessage}</span>
              </div>
            </div>
          </section>
        )}

        { }
        {results && (
          <section className="cyber-panel animate-fade-in" style={{ marginTop: '2rem' }}>
            <div className="cyber-corner-tl"></div>
            <div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div>
            <div className="cyber-corner-br"></div>

            <div className="results-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <Terminal size={18} style={{ color: 'var(--primary)' }} />
                <h3>SEC-OPS REPORT NODE</h3>
              </div>
              <div className="tab-buttons">
                <button
                  className={`tab-btn ${resultSubTab === 'dashboard' ? 'active' : ''}`}
                  onClick={() => setResultSubTab('dashboard')}
                >
                  <Eye size={14} /> Tactical Dashboard
                </button>
                <button
                  className={`tab-btn ${resultSubTab === 'json' ? 'active' : ''}`}
                  onClick={() => setResultSubTab('json')}
                >
                  <FileCode size={14} /> RAW STDOUT JSON
                </button>
                <button
                  className="tab-btn"
                  onClick={() => window.open(`${API_BASE}/report/${results.id}`, '_blank')}
                  style={{ background: 'var(--primary)', color: 'var(--bg-dark)' }}
                >
                  <FileText size={14} /> GENERATE REPORT
                </button>
              </div>
            </div>

            { }
            {results.results?.analysis_verdict && (
              <div className={`verdict-banner ${results.results.analysis_verdict.toLowerCase().includes('critical') || results.results.analysis_verdict.toLowerCase().includes('high') || results.results.analysis_verdict.toLowerCase().includes('malicious')
                ? 'danger' : results.results.analysis_verdict.toLowerCase().includes('medium') || results.results.analysis_verdict.toLowerCase().includes('suspicious')
                  ? 'warning' : 'success'
                }`}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <AlertTriangle size={24} />
                  <div>
                    <h4>ANOMALY VERDICT: {results.results.analysis_verdict}</h4>
                    <p>Calculated threat index is at {results.results.threat_score || 0}/100</p>
                  </div>
                </div>
              </div>
            )}

            { }
            {resultSubTab === 'dashboard' && (
              <div className="interactive-report-container animate-fade-in">
                {renderInteractiveReport(activeTab, results.results, metadataSearch, setMetadataSearch, API_BASE)}
              </div>
            )}

            { }
            {resultSubTab === 'json' && (
              <div className="json-container animate-fade-in">
                <pre className="json-view">
                  {JSON.stringify(results.results, null, 2)}
                </pre>
              </div>
            )}
          </section>
        )}
      </main>

      {/* CyberX AI Chatbot */}
      <CyberChat />
    </div>
  );
}


function GhidraReport({ data }) {
  const [activePanel, setActivePanel] = useState('decompiled');
  const [funcSearch, setFuncSearch] = useState('');
  const [strSearch, setStrSearch] = useState('');
  const [importSearch, setImportSearch] = useState('');

  const meta = data?.metadata || {};
  const functions = data?.functions || [];
  const strings = data?.strings || [];
  const ghidraLog = data?.ghidra_log || [];
  const errors = data?.errors || [];
  const warnings = data?.warnings || [];
  const sections = meta.sections || [];
  const imports = meta.imports || [];
  const exports = meta.exports || [];
  const fileSizeMB = meta.file_size ? (meta.file_size / (1024 * 1024)).toFixed(2) : '?';

  const filteredFunctions = functions.filter(f =>
    f.name?.toLowerCase().includes(funcSearch.toLowerCase()) ||
    f.address?.toLowerCase().includes(funcSearch.toLowerCase()) ||
    f.signature?.toLowerCase().includes(funcSearch.toLowerCase())
  );
  const filteredStrings = strings.filter(s => String(s).toLowerCase().includes(strSearch.toLowerCase()));
  const filteredImports = imports.filter(imp => String(imp).toLowerCase().includes(importSearch.toLowerCase()));

  const btnStyle = (id) => ({
    padding: '0.4rem 0.9rem', borderRadius: '4px',
    border: `1px solid ${activePanel === id ? 'var(--primary)' : 'rgba(255,255,255,0.1)'}`,
    background: activePanel === id ? 'rgba(0,240,255,0.12)' : 'transparent',
    color: activePanel === id ? 'var(--primary)' : 'var(--text-muted)',
    cursor: 'pointer', fontFamily: 'monospace', fontSize: '0.75rem',
    fontWeight: activePanel === id ? 'bold' : 'normal',
    letterSpacing: '0.05em', transition: 'all 0.2s',
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

      { }
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '1rem' }}>
        {[
          { label: 'FORMAT', value: meta.format || 'Unknown', color: '#f59e0b' },
          { label: 'ARCHITECTURE', value: meta.architecture || 'Unknown', color: '#00f0ff' },
          { label: 'FUNCTIONS', value: (data?.functions_count || 0).toLocaleString(), color: '#a5b4fc' },
          { label: 'FILE SIZE', value: `${fileSizeMB} MB`, color: '#10b981' },
        ].map(s => (
          <div key={s.label} className="cyber-panel" style={{ padding: '1rem', textAlign: 'center', position: 'relative' }}>
            <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
            <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '0.4rem', fontFamily: 'monospace' }}>{s.label}</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: s.color, fontFamily: 'monospace' }}>{s.value}</div>
          </div>
        ))}
      </div>

      { }
      {(meta.md5 || meta.sha256) && (
        <div className="cyber-panel" style={{ padding: '1rem', position: 'relative' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
          <div style={{ fontSize: '0.75rem', color: '#a5b4fc', fontFamily: 'monospace', marginBottom: '0.75rem', fontWeight: 'bold' }}>🔐 CRYPTOGRAPHIC HASHES</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            {meta.md5 && <div><div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'monospace', marginBottom: '0.2rem' }}>MD5</div><code style={{ fontSize: '0.78rem', color: '#10b981', wordBreak: 'break-all' }}>{meta.md5}</code></div>}
            {meta.sha256 && <div><div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'monospace', marginBottom: '0.2rem' }}>SHA-256</div><code style={{ fontSize: '0.78rem', color: '#10b981', wordBreak: 'break-all' }}>{meta.sha256}</code></div>}
          </div>
          {data?.status && (
            <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>STATUS:</span>
              <span style={{ fontSize: '0.75rem', color: data.success ? '#10b981' : '#ef4444', fontWeight: 'bold', fontFamily: 'monospace' }}>{data.status}</span>
              {data.duration_seconds && <><span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>DURATION:</span><span style={{ fontSize: '0.75rem', color: '#a5b4fc', fontFamily: 'monospace' }}>{data.duration_seconds.toFixed(1)}s</span></>}
            </div>
          )}
        </div>
      )}

      { }
      {errors.length > 0 && (
        <div className="verdict-banner danger" style={{ padding: '0.75rem 1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}><AlertTriangle size={16} /><strong style={{ fontSize: '0.8rem', fontFamily: 'monospace' }}>ANALYSIS ERRORS ({errors.length})</strong></div>
          {errors.map((e, i) => <div key={i} style={{ fontSize: '0.75rem', color: '#fca5a5', fontFamily: 'monospace', marginTop: '0.2rem' }}>• {e}</div>)}
        </div>
      )}
      {warnings.length > 0 && (
        <div className="verdict-banner warning" style={{ padding: '0.75rem 1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}><AlertTriangle size={16} /><strong style={{ fontSize: '0.8rem', fontFamily: 'monospace' }}>WARNINGS ({warnings.length})</strong></div>
          {warnings.slice(0, 5).map((w, i) => <div key={i} style={{ fontSize: '0.75rem', color: '#fde68a', fontFamily: 'monospace', marginTop: '0.2rem' }}>• {w}</div>)}
        </div>
      )}

      { }
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        {[
          { id: 'decompiled', label: `⬡ DECOMPILED C (${data?.functions_count || 0} funcs)` },
          { id: 'functions', label: `⬡ FUNCTIONS (${functions.length})` },
          { id: 'sections', label: `⬡ SECTIONS (${sections.length})` },
          { id: 'imports', label: `⬡ IMPORTS (${imports.length})` },
          { id: 'exports', label: `⬡ EXPORTS (${exports.length})` },
          { id: 'strings', label: `⬡ STRINGS (${strings.length})` },
          { id: 'log', label: `⬡ GHIDRA LOG (${ghidraLog.length})` },
        ].map(p => <button key={p.id} style={btnStyle(p.id)} onClick={() => setActivePanel(p.id)}>{p.label}</button>)}
      </div>

      { }
      {activePanel === 'decompiled' && (
        <div className="cyber-panel" style={{ position: 'relative' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
          <div style={{ padding: '1rem 1.25rem 0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: '#a5b4fc', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: '0.1em' }}>⬡ DECOMPILED C SOURCE (up to 150 functions)</span>
            {data?.decompiled_code && (
              <button onClick={() => navigator.clipboard.writeText(data.decompiled_code)} style={{ background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.3)', color: 'var(--primary)', borderRadius: '4px', padding: '0.25rem 0.6rem', cursor: 'pointer', fontSize: '0.7rem', fontFamily: 'monospace' }}>📋 COPY</button>
            )}
          </div>
          {data?.decompiled_code ? (
            <pre style={{ margin: 0, padding: '0.75rem 1.25rem 1.25rem', color: '#10b981', fontFamily: '"Fira Code","Cascadia Code",monospace', fontSize: '0.82rem', whiteSpace: 'pre-wrap', maxHeight: '70vh', overflow: 'auto', lineHeight: '1.6' }}>{data.decompiled_code}</pre>
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.85rem' }}>
              <Cpu size={32} style={{ display: 'block', margin: '0 auto 0.75rem', opacity: 0.3 }} />
              No decompiled code — Ghidra export script may not have run or analysis failed.
            </div>
          )}
        </div>
      )}

      { }
      {activePanel === 'functions' && (
        <div className="cyber-panel" style={{ position: 'relative' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
          <div style={{ padding: '1rem 1.25rem 0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#a5b4fc', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: '0.1em', whiteSpace: 'nowrap' }}>⬡ EXTRACTED FUNCTIONS</span>
            <div style={{ position: 'relative', flex: 1, maxWidth: '340px' }}>
              <Search size={13} style={{ position: 'absolute', left: '0.6rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input type="text" placeholder="Search name, address, signature..." value={funcSearch} onChange={e => setFuncSearch(e.target.value)} className="filter-input" style={{ paddingLeft: '2rem', width: '100%' }} />
            </div>
          </div>
          {filteredFunctions.length > 0 ? (
            <div className="metadata-table-wrapper" style={{ maxHeight: '65vh', overflow: 'auto', margin: '0 1.25rem 1.25rem' }}>
              <table className="metadata-table">
                <thead><tr><th>#</th><th>ADDRESS</th><th>NAME</th><th>SIZE</th><th>XREFS</th><th>SIGNATURE</th></tr></thead>
                <tbody>
                  {filteredFunctions.map((f, i) => (
                    <tr key={i}>
                      <td style={{ color: 'var(--text-muted)', fontSize: '0.7rem', fontFamily: 'monospace' }}>{i + 1}</td>
                      <td className="prop-name" style={{ fontFamily: 'monospace', color: '#00f0ff', fontSize: '0.78rem' }}>{f.address}</td>
                      <td className="prop-val" style={{ color: f.name?.startsWith('FUN_') ? '#9ca3af' : '#fff', fontWeight: f.name?.startsWith('FUN_') ? 'normal' : 'bold' }}>{f.name}</td>
                      <td className="prop-val" style={{ color: '#a5b4fc', fontFamily: 'monospace' }}>{f.size?.toLocaleString()} B</td>
                      <td className="prop-val" style={{ fontSize: '0.72rem', color: f.xrefs_to?.length > 0 ? '#f59e0b' : 'var(--text-muted)' }}>
                        {f.xrefs_to?.length > 0 ? <span title={f.xrefs_to.join(', ')}>{f.xrefs_to.length} xref{f.xrefs_to.length !== 1 ? 's' : ''}</span> : '—'}
                      </td>
                      <td className="prop-val" style={{ fontSize: '0.72rem', color: '#6b7280', fontFamily: 'monospace', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={f.signature}>{f.signature || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{functions.length === 0 ? 'No functions extracted — Ghidra export script may not have run.' : 'No functions match search.'}</div>
          )}
        </div>
      )}

      { }
      {activePanel === 'sections' && (
        <div className="cyber-panel" style={{ position: 'relative' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
          <div style={{ padding: '1rem 1.25rem 0.75rem' }}><span style={{ fontSize: '0.75rem', color: '#a5b4fc', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: '0.1em' }}>⬡ PE / ELF SECTIONS</span></div>
          {sections.length > 0 ? (
            <div className="metadata-table-wrapper" style={{ maxHeight: '65vh', overflow: 'auto', margin: '0 1.25rem 1.25rem' }}>
              <table className="metadata-table">
                <thead><tr><th>NAME</th><th>VIRTUAL ADDR</th><th>VIRT SIZE</th><th>RAW SIZE</th><th>CHARACTERISTICS</th></tr></thead>
                <tbody>
                  {sections.map((s, i) => (
                    <tr key={i}>
                      <td className="prop-name" style={{ fontFamily: 'monospace', color: '#10b981' }}>{s.name || s.Name || '?'}</td>
                      <td className="prop-val" style={{ fontFamily: 'monospace', color: '#00f0ff', fontSize: '0.78rem' }}>{s.virtual_address || s.address || '?'}</td>
                      <td className="prop-val" style={{ fontFamily: 'monospace' }}>{s.virtual_size?.toLocaleString() || s.size?.toLocaleString() || '?'}</td>
                      <td className="prop-val" style={{ fontFamily: 'monospace' }}>{s.raw_size?.toLocaleString() || '—'}</td>
                      <td className="prop-val" style={{ fontFamily: 'monospace', color: '#f59e0b', fontSize: '0.75rem' }}>{s.characteristics || s.type || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'monospace' }}>No section data extracted.</div>
          )}
        </div>
      )}

      { }
      {activePanel === 'imports' && (
        <div className="cyber-panel" style={{ position: 'relative' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
          <div style={{ padding: '1rem 1.25rem 0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#a5b4fc', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: '0.1em', whiteSpace: 'nowrap' }}>⬡ IMPORTED SYMBOLS ({imports.length})</span>
            <div style={{ position: 'relative', flex: 1, maxWidth: '320px' }}>
              <Search size={13} style={{ position: 'absolute', left: '0.6rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input type="text" placeholder="Filter imports..." value={importSearch} onChange={e => setImportSearch(e.target.value)} className="filter-input" style={{ paddingLeft: '2rem', width: '100%' }} />
            </div>
          </div>
          {filteredImports.length > 0 ? (
            <div style={{ padding: '0 1.25rem 1.25rem', maxHeight: '65vh', overflow: 'auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(280px,1fr))', gap: '0.4rem' }}>
              {filteredImports.map((imp, i) => {
                const parts = String(imp).split('!');
                const dll = parts[0]; const fn = parts[1];
                const danger = /Virtual|WriteProcessMemory|LoadLibrary|CreateRemoteThread|WinExec|ShellExecute|Inject|RegOpenKey/i.test(imp);
                return (
                  <div key={i} style={{ padding: '0.35rem 0.6rem', background: danger ? 'rgba(239,68,68,0.08)' : 'rgba(255,255,255,0.02)', border: `1px solid ${danger ? 'rgba(239,68,68,0.3)' : 'rgba(255,255,255,0.05)'}`, borderRadius: '3px', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    {danger && <AlertTriangle size={11} style={{ color: '#ef4444', flexShrink: 0 }} />}
                    <code style={{ fontSize: '0.72rem', color: danger ? '#fca5a5' : 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {fn ? <><span style={{ color: '#f59e0b' }}>{dll}</span>!<span style={{ color: danger ? '#fca5a5' : '#e5e7eb' }}>{fn}</span></> : imp}
                    </code>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'monospace' }}>No imports found or not a PE file.</div>
          )}
        </div>
      )}

      { }
      {activePanel === 'exports' && (
        <div className="cyber-panel" style={{ position: 'relative' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
          <div style={{ padding: '1rem 1.25rem 0.75rem' }}><span style={{ fontSize: '0.75rem', color: '#a5b4fc', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: '0.1em' }}>⬡ EXPORTED SYMBOLS ({exports.length})</span></div>
          {exports.length > 0 ? (
            <div style={{ padding: '0 1.25rem 1.25rem', maxHeight: '65vh', overflow: 'auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(240px,1fr))', gap: '0.4rem' }}>
              {exports.map((exp, i) => (
                <div key={i} style={{ padding: '0.3rem 0.6rem', background: 'rgba(165,180,252,0.05)', border: '1px solid rgba(165,180,252,0.15)', borderRadius: '3px' }}>
                  <code style={{ fontSize: '0.72rem', color: '#a5b4fc' }}>{exp}</code>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'monospace' }}>No exports found.</div>
          )}
        </div>
      )}

      { }
      {activePanel === 'strings' && (
        <div className="cyber-panel" style={{ position: 'relative' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
          <div style={{ padding: '1rem 1.25rem 0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#a5b4fc', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: '0.1em', whiteSpace: 'nowrap' }}>⬡ EXTRACTED STRINGS (up to 500){meta.strings_count ? ` — ${meta.strings_count.toLocaleString()} total` : ''}</span>
            <div style={{ position: 'relative', flex: 1, maxWidth: '320px' }}>
              <Search size={13} style={{ position: 'absolute', left: '0.6rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input type="text" placeholder="Search strings..." value={strSearch} onChange={e => setStrSearch(e.target.value)} className="filter-input" style={{ paddingLeft: '2rem', width: '100%' }} />
            </div>
          </div>
          {filteredStrings.length > 0 ? (
            <div style={{ padding: '0 1.25rem 1.25rem', maxHeight: '65vh', overflow: 'auto' }}>
              {filteredStrings.map((s, i) => {
                const str = String(s).replace(/^"|"$/g, '');
                const isUrl = /https?:\/\//i.test(str);
                const isCmd = /cmd|powershell|exec|shell|run|exploit/i.test(str);
                const isPath = /\\|\/[a-z]/i.test(str);
                const color = isCmd ? '#ef4444' : isUrl ? '#f59e0b' : isPath ? '#a5b4fc' : '#6b7280';
                return (
                  <div key={i} style={{ display: 'flex', gap: '0.5rem', padding: '0.2rem 0', borderBottom: '1px solid rgba(255,255,255,0.02)', alignItems: 'flex-start' }}>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'monospace', minWidth: '36px' }}>{i + 1}</span>
                    <code style={{ fontSize: '0.78rem', color, wordBreak: 'break-all', lineHeight: '1.5' }}>{str}</code>
                    {(isCmd || isUrl) && <span style={{ fontSize: '0.6rem', padding: '0.1rem 0.35rem', borderRadius: '3px', background: isCmd ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)', color: isCmd ? '#ef4444' : '#f59e0b', whiteSpace: 'nowrap', marginLeft: 'auto', flexShrink: 0 }}>{isCmd ? 'CMD' : 'URL'}</span>}
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'monospace' }}>No strings extracted.</div>
          )}
        </div>
      )}

      { }
      {activePanel === 'log' && (
        <div className="cyber-panel" style={{ position: 'relative' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
          <div style={{ padding: '1rem 1.25rem 0.75rem' }}><span style={{ fontSize: '0.75rem', color: '#a5b4fc', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: '0.1em' }}>⬡ GHIDRA STDOUT LOG (last 20 lines)</span></div>
          <div style={{ padding: '0 1.25rem 1.25rem', maxHeight: '65vh', overflow: 'auto' }}>
            {ghidraLog.length > 0 ? (
              <pre style={{ margin: 0, fontFamily: 'monospace', fontSize: '0.78rem', whiteSpace: 'pre-wrap', lineHeight: '1.7' }}>
                {ghidraLog.map((line, i) => (
                  <div key={i} style={{ color: line.toLowerCase().includes('error') ? '#ef4444' : line.toLowerCase().includes('warn') ? '#f59e0b' : '#9ca3af' }}>{line}</div>
                ))}
              </pre>
            ) : (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'monospace', paddingTop: '1rem' }}>No log output captured.</div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}



function JadxReport({ data }) {
  const [selectedFile, setSelectedFile] = React.useState(null);
  const [treeSearch, setTreeSearch] = React.useState('');
  const [activeTab, setActiveTab] = React.useState('sources');
  const [expandedDirs, setExpandedDirs] = React.useState({});

  const tree = data?.source_tree || [];

  // Build directory tree structure
  const buildDirTree = (files) => {
    const root = {};
    files.forEach(f => {
      const parts = f.path.split('/');
      let node = root;
      parts.forEach((part, idx) => {
        if (idx === parts.length - 1) {
          if (!node.__files) node.__files = [];
          node.__files.push(f);
        } else {
          if (!node[part]) node[part] = {};
          node = node[part];
        }
      });
    });
    return root;
  };

  const filtered = treeSearch
    ? tree.filter(f => f.path.toLowerCase().includes(treeSearch.toLowerCase()))
    : tree;

  const javaFiles = tree.filter(f => f.ext === '.java');
  const xmlFiles  = tree.filter(f => f.ext === '.xml');

  const tabFiles = activeTab === 'sources' ? javaFiles
    : activeTab === 'xml' ? xmlFiles
    : tree;

  const displayFiles = treeSearch
    ? tabFiles.filter(f => f.path.toLowerCase().includes(treeSearch.toLowerCase()))
    : tabFiles;

  const extColor = (ext) => ({
    '.java': '#f59e0b',
    '.xml':  '#60a5fa',
    '.json': '#a78bfa',
    '.kt':   '#f472b6',
    '.smali':'#34d399',
    '.gradle':'#fb923c',
  }[ext] || '#9ca3af');

  const extIcon = (ext) => ({
    '.java': '☕',
    '.xml':  '📄',
    '.json': '{}',
    '.kt':   'K',
    '.smali':'⚙',
    '.gradle':'🐘',
    '.properties':'⚙',
    '.txt': '📝',
  }[ext] || '📄');

  const getLineColor = (line) => {
    const t = line.trim();
    if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return '#6b7280';
    if (/^(import|package)\s/.test(t)) return '#a5b4fc';
    if (/^(public|private|protected|static|final|abstract|class|interface|enum|void|int|String|boolean|return|new|if|else|for|while|try|catch|throws|extends|implements)\b/.test(t)) return '#c084fc';
    if (/^@/.test(t)) return '#fb923c';
    return '#e5e7eb';
  };

  const btnS = (id) => ({
    padding: '0.3rem 0.75rem',
    borderRadius: '4px',
    border: `1px solid ${activeTab === id ? 'var(--primary)' : 'rgba(255,255,255,0.1)'}`,
    background: activeTab === id ? 'rgba(0,240,255,0.12)' : 'transparent',
    color: activeTab === id ? 'var(--primary)' : 'var(--text-muted)',
    cursor: 'pointer', fontFamily: 'monospace', fontSize: '0.72rem',
    transition: 'all 0.2s',
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

      {/* Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
        {[
          { label: 'TOTAL FILES', value: data?.total_files ?? 0, color: '#00f0ff' },
          { label: 'JAVA CLASSES', value: data?.java_count ?? 0, color: '#f59e0b' },
          { label: 'XML RESOURCES', value: data?.xml_count ?? 0, color: '#60a5fa' },
          { label: 'STATUS', value: data?.status || '—', color: '#10b981' },
        ].map(s => (
          <div key={s.label} className="cyber-panel" style={{ padding: '1rem', textAlign: 'center', position: 'relative' }}>
            <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
            <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
            <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', letterSpacing: '0.1em', fontFamily: 'monospace', marginBottom: '0.4rem' }}>{s.label}</div>
            <div style={{ fontSize: '1.3rem', fontWeight: 'bold', color: s.color, fontFamily: 'monospace' }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Output Dir */}
      {data?.output_dir && (
        <div style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: 'var(--text-muted)', padding: '0.5rem 0.75rem', background: 'rgba(0,240,255,0.04)', border: '1px solid rgba(0,240,255,0.12)', borderRadius: '4px' }}>
          <span style={{ color: '#00f0ff' }}>📁 OUTPUT DIR:</span> {data.output_dir}
        </div>
      )}

      {/* Main Explorer + Code View */}
      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '1rem', height: '75vh' }}>

        {/* File Explorer */}
        <div className="cyber-panel" style={{ position: 'relative', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />

          <div style={{ padding: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--primary)', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: '0.1em' }}>⬡ SOURCE EXPLORER</div>
            <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
              <button style={btnS('sources')} onClick={() => setActiveTab('sources')}>☕ Java ({javaFiles.length})</button>
              <button style={btnS('xml')} onClick={() => setActiveTab('xml')}>📄 XML ({xmlFiles.length})</button>
              <button style={btnS('all')} onClick={() => setActiveTab('all')}>All ({tree.length})</button>
            </div>
            <div style={{ position: 'relative' }}>
              <Search size={11} style={{ position: 'absolute', left: '0.5rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Filter files..."
                value={treeSearch}
                onChange={e => setTreeSearch(e.target.value)}
                style={{ width: '100%', paddingLeft: '1.6rem', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '4px', color: '#fff', fontSize: '0.72rem', fontFamily: 'monospace', padding: '0.3rem 0.5rem 0.3rem 1.6rem', boxSizing: 'border-box' }}
              />
            </div>
          </div>

          <div style={{ flex: 1, overflow: 'auto', padding: '0.35rem 0' }}>
            {displayFiles.length === 0 ? (
              <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.75rem' }}>No files found</div>
            ) : (
              displayFiles.map((f, i) => {
                const depth = f.path.split('/').length - 1;
                const isSelected = selectedFile?.path === f.path;
                return (
                  <div
                    key={i}
                    onClick={() => setSelectedFile(f)}
                    style={{
                      padding: `0.28rem 0.75rem 0.28rem ${0.5 + depth * 0.8}rem`,
                      cursor: 'pointer',
                      background: isSelected ? 'rgba(0,240,255,0.12)' : 'transparent',
                      borderLeft: isSelected ? '2px solid var(--primary)' : '2px solid transparent',
                      display: 'flex', alignItems: 'center', gap: '0.4rem',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'rgba(255,255,255,0.04)'; }}
                    onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = 'transparent'; }}
                  >
                    <span style={{ fontSize: '0.7rem', flexShrink: 0 }}>{extIcon(f.ext)}</span>
                    <span style={{ fontSize: '0.7rem', color: isSelected ? 'var(--primary)' : extColor(f.ext), fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }} title={f.path}>
                      {f.name}
                    </span>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', fontFamily: 'monospace', flexShrink: 0 }}>
                      {f.size > 1024 ? `${(f.size/1024).toFixed(0)}K` : `${f.size}B`}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Code Viewer */}
        <div className="cyber-panel" style={{ position: 'relative', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />

          {selectedFile ? (
            <>
              {/* File Tab Bar */}
              <div style={{ padding: '0.5rem 1rem', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexShrink: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', overflow: 'hidden' }}>
                  <span style={{ fontSize: '0.8rem' }}>{extIcon(selectedFile.ext)}</span>
                  <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: extColor(selectedFile.ext), fontWeight: 'bold', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{selectedFile.name}</span>
                  <span style={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>— {selectedFile.path}</span>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', flexShrink: 0 }}>
                  {selectedFile.content && (
                    <button
                      onClick={() => navigator.clipboard.writeText(selectedFile.content)}
                      style={{ background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.25)', color: 'var(--primary)', borderRadius: '4px', padding: '0.2rem 0.55rem', cursor: 'pointer', fontSize: '0.68rem', fontFamily: 'monospace' }}
                    >📋 COPY</button>
                  )}
                  <span style={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'var(--text-muted)', alignSelf: 'center' }}>
                    {selectedFile.content ? `${selectedFile.content.split('\n').length} lines` : 'binary'}
                  </span>
                </div>
              </div>

              {/* Code Body */}
              {selectedFile.content ? (
                <div style={{ flex: 1, overflow: 'auto', display: 'flex' }}>
                  {/* Line Numbers */}
                  <div style={{ padding: '0.75rem 0.5rem', background: 'rgba(0,0,0,0.3)', borderRight: '1px solid rgba(255,255,255,0.05)', textAlign: 'right', userSelect: 'none', flexShrink: 0 }}>
                    {selectedFile.content.split('\n').map((_, i) => (
                      <div key={i} style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'rgba(255,255,255,0.2)', lineHeight: '1.65', minWidth: '32px' }}>{i + 1}</div>
                    ))}
                  </div>
                  {/* Code */}
                  <pre style={{ margin: 0, padding: '0.75rem 1rem', fontFamily: '"Fira Code", "Cascadia Code", monospace', fontSize: '0.8rem', lineHeight: '1.65', flex: 1, overflow: 'visible', whiteSpace: 'pre' }}>
                    {selectedFile.content.split('\n').map((line, i) => (
                      <div key={i} style={{ color: getLineColor(line), minHeight: '1.65em' }}>{line || ' '}</div>
                    ))}
                  </pre>
                </div>
              ) : (
                <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '0.5rem' }}>
                  <span style={{ fontSize: '2rem' }}>🔒</span>
                  <div style={{ color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.8rem' }}>Binary or too large to display inline</div>
                  <div style={{ color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.7rem' }}>Size: {(selectedFile.size / 1024).toFixed(1)} KB</div>
                </div>
              )}
            </>
          ) : (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '1rem' }}>
              <FileCode size={48} style={{ color: 'rgba(0,240,255,0.15)' }} />
              <div style={{ color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.85rem' }}>Select a file from the explorer to view source</div>
              <div style={{ color: 'rgba(255,255,255,0.15)', fontFamily: 'monospace', fontSize: '0.72rem' }}>{tree.length} files decompiled successfully</div>
            </div>
          )}
        </div>
      </div>

      {/* Jadx Log */}
      {data?.log && (
        <div className="cyber-panel" style={{ position: 'relative' }}>
          <div className="cyber-corner-tl" /><div className="cyber-corner-tr" />
          <div className="cyber-corner-bl" /><div className="cyber-corner-br" />
          <div style={{ padding: '0.75rem 1rem', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <span style={{ fontSize: '0.72rem', color: '#a5b4fc', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: '0.1em' }}>⬡ JADX DECOMPILER LOG</span>
          </div>
          <pre style={{ margin: 0, padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.72rem', color: '#6b7280', whiteSpace: 'pre-wrap', maxHeight: '200px', overflow: 'auto', lineHeight: '1.6' }}>
            {data.log}
          </pre>
        </div>
      )}
    </div>
  );
}


function renderInteractiveReport(tool, data, filter, setFilter, apiBase) {
  if (!data) return <p style={{ color: 'var(--text-muted)' }}>No node metadata returned by engine.</p>;
  if (data.error) {
    return (
      <div className="verdict-banner danger">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertTriangle size={18} />
          <span><strong>Analysis Failed:</strong> {data.error}</span>
        </div>
      </div>
    );
  }

  switch (tool) {
    case 'exiftool': {
      const keys = Object.keys(data).filter(k =>
        k.toLowerCase().includes(filter.toLowerCase()) ||
        String(data[k]).toLowerCase().includes(filter.toLowerCase())
      );

      return (
        <div className="report-exif">
          <div className="report-actions">
            <Search size={14} className="filter-icon" />
            <input
              type="text"
              placeholder="Filter metadata keys (GPS, timestamps, metadata tag)..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="filter-input"
            />
          </div>
          <div className="metadata-table-wrapper">
            <table className="metadata-table">
              <thead>
                <tr>
                  <th>METADATA PROPERTY</th>
                  <th>VALUE</th>
                </tr>
              </thead>
              <tbody>
                {keys.length > 0 ? (
                  keys.map(k => (
                    <tr key={k}>
                      <td className="prop-name">{k}</td>
                      <td className="prop-val">{String(data[k])}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="2" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                      No metadata keys match search parameters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      );
    }

    case 'androguard': {
      const score = data.threat_score || 0;
      const circ = 2 * Math.PI * 45;
      const offset = circ - (score / 100) * circ;
      const flags = data.threat_flags || [];
      const perms = data.permissions || [];

      return (
        <div className="report-androguard">
          <div className="mobsf-stats-grid">
            { }
            <div className="stat-card score-gauge-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>THREAT SCORE</h4>
              <div className="gauge-container">
                <svg width="120" height="120" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="45" stroke="rgba(255,255,255,0.05)" strokeWidth="6" fill="transparent" />
                  <circle cx="50" cy="50" r="45"
                    stroke={score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981'}
                    strokeWidth="6"
                    strokeDasharray={circ}
                    strokeDashoffset={offset}
                    strokeLinecap="round"
                    fill="transparent"
                    transform="rotate(-90 50 50)" />
                  <text x="50" y="55" textAnchor="middle" fill="#fff" fontSize="18" fontWeight="bold">
                    {score}
                  </text>
                  <text x="50" y="72" textAnchor="middle" fill="var(--text-muted)" fontSize="8">
                    Risk Index
                  </text>
                </svg>
              </div>
              <span className={`badge ${data.analysis_verdict === 'MALICIOUS' ? 'failed' : data.analysis_verdict === 'SUSPICIOUS' ? 'warning' : 'success'}`} style={{ marginTop: '0.5rem' }}>
                {data.analysis_verdict || 'SAFE'}
              </span>
            </div>

            { }
            <div className="stat-card app-profile-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>APK METADATA</h4>
              <div className="profile-grid">
                <div><span>App Name:</span> <strong>{data.app_name || 'N/A'}</strong></div>
                <div><span>Package:</span> <strong>{data.package || 'N/A'}</strong></div>
                <div><span>Version Name:</span> <strong>{data.version_name || 'N/A'}</strong></div>
                <div><span>Version Code:</span> <strong>{data.version_code || 'N/A'}</strong></div>
                <div><span>Main Activity:</span> <strong>{data.main_activity || 'N/A'}</strong></div>
              </div>
            </div>

            { }
            <div className="stat-card components-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>ANDROID COMPONENTS</h4>
              <div className="components-counter">
                <div className="count-node">
                  <span className="number">{data.activities?.length || 0}</span>
                  <span className="label">Activities</span>
                </div>
                <div className="count-node">
                  <span className="number">{data.services?.length || 0}</span>
                  <span className="label">Services</span>
                </div>
                <div className="count-node">
                  <span className="number">{data.receivers?.length || 0}</span>
                  <span className="label">Receivers</span>
                </div>
                <div className="count-node text-danger">
                  <span className="number highlight-red">{perms.length}</span>
                  <span className="label">Permissions</span>
                </div>
              </div>
            </div>
          </div>

          <div className="mobsf-details-grid" style={{ marginTop: '1.5rem' }}>
            { }
            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>THREAT FLAGS / ANOMALIES ({flags.length})</h4>
              <div className="remediation-list">
                {flags.length > 0 ? (
                  flags.map((flag, idx) => (
                    <div key={idx} className="remediation-item" style={{ borderLeft: '3px solid #ef4444' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <AlertTriangle size={14} className="text-danger" />
                        <span style={{ fontSize: '0.85rem', color: '#fff', fontWeight: 'bold' }}>Detection #{idx + 1}</span>
                      </div>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>{flag}</p>
                    </div>
                  ))
                ) : (
                  <p style={{ color: '#10b981', textAlign: 'center', padding: '1.5rem' }}>
                    <CheckCircle size={24} style={{ display: 'block', margin: '0 auto 0.5rem' }} />
                    No critical risk markers or spoof signatures flagged.
                  </p>
                )}
              </div>
            </div>

            { }
            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>MANIFEST PERMISSIONS</h4>
              <div className="remediation-list" style={{ maxHeight: '250px' }}>
                {perms.length > 0 ? (
                  perms.map((perm, idx) => {
                    const isDangerous = perm.toLowerCase().includes('write_') || perm.toLowerCase().includes('read_') || perm.toLowerCase().includes('send_') || perm.toLowerCase().includes('system_') || perm.toLowerCase().includes('alert');
                    return (
                      <div key={idx} style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '0.4rem 0.5rem',
                        borderBottom: '1px solid rgba(255,255,255,0.02)',
                        fontSize: '0.75rem'
                      }}>
                        <code style={{ color: isDangerous ? '#ef4444' : 'var(--text-muted)' }}>{perm}</code>
                        {isDangerous && <span className="priority-badge p0">High-Risk</span>}
                      </div>
                    );
                  })
                ) : (
                  <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '1rem' }}>No permissions listed in Manifest.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    }

    case 'ghidra':
      return <GhidraReport data={data} />;

    case 'jadx':
      return <JadxReport data={data} />;


    case 'mobsf': {
      const score = data.threat_score || 0;
      const circ = 2 * Math.PI * 45;
      const offset = circ - (score / 100) * circ;
      const mSummary = data.mobsf_summary || {};
      const fSummary = data.feature_summary || {};
      const breakdown = data.risk_breakdown || {};

      return (
        <div className="report-mobsf-dashboard">
          <div className="mobsf-stats-grid">
            { }
            <div className="stat-card score-gauge-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>THREAT SCORE</h4>
              <div className="gauge-container">
                <svg width="120" height="120" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="45" stroke="rgba(255,255,255,0.05)" strokeWidth="6" fill="transparent" />
                  <circle cx="50" cy="50" r="45"
                    stroke={score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981'}
                    strokeWidth="6"
                    strokeDasharray={circ}
                    strokeDashoffset={offset}
                    strokeLinecap="round"
                    fill="transparent"
                    transform="rotate(-90 50 50)" />
                  <text x="50" y="55" textAnchor="middle" fill="#fff" fontSize="18" fontWeight="bold">
                    {score}
                  </text>
                  <text x="50" y="72" textAnchor="middle" fill="var(--text-muted)" fontSize="8">
                    out of 100
                  </text>
                </svg>
              </div>
              <p style={{ fontSize: '0.8rem', textAlign: 'center', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                Weighted threat calculation based on findings, malware and packer signatures
              </p>
            </div>

            { }
            <div className="stat-card app-profile-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>APPLICATION PROFILE</h4>
              <div className="profile-grid">
                <div><span>Name:</span> <strong>{mSummary.app_name || 'N/A'}</strong></div>
                <div><span>Package:</span> <strong>{mSummary.package_name || 'N/A'}</strong></div>
                <div><span>Version:</span> <strong>{mSummary.version || 'N/A'}</strong></div>
                <div><span>Target SDK:</span> <strong>API {mSummary.target_sdk || 'N/A'}</strong></div>
                <div><span>Min SDK:</span> <strong>API {mSummary.min_sdk || 'N/A'}</strong></div>
                <div><span>App Size:</span> <strong>{typeof mSummary.size === 'string' ? mSummary.size : (typeof mSummary.size === 'number' && mSummary.size > 0 ? (mSummary.size / (1024 * 1024)).toFixed(2) + ' MB' : 'N/A')}</strong></div>
              </div>
              {data.pdf_report_url && (
                <div style={{ marginTop: '1.25rem' }}>
                  <a href={`${apiBase}${data.pdf_report_url}`} target="_blank" rel="noopener noreferrer" className="btn btn-pdf" style={{ width: '100%', justifyContent: 'center' }}>
                    <FileText size={16} /> Open Full PDF Forensic Report
                  </a>
                </div>
              )}
            </div>

            { }
            <div className="stat-card components-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>ATTACK SURFACE (EXPORTED)</h4>
              <div className="components-counter">
                <div className="count-node">
                  <span className="number">{fSummary.components?.exported_activities || 0}</span>
                  <span className="label">Activities</span>
                </div>
                <div className="count-node">
                  <span className="number">{fSummary.components?.exported_services || 0}</span>
                  <span className="label">Services</span>
                </div>
                <div className="count-node">
                  <span className="number">{fSummary.components?.exported_receivers || 0}</span>
                  <span className="label">Receivers</span>
                </div>
                <div className="count-node text-danger">
                  <span className="number highlight-red">{fSummary.components?.total || 0}</span>
                  <span className="label">Total Exposed</span>
                </div>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.8rem' }}>
                Exposed components can be launched by any other app on the system.
              </p>
            </div>
          </div>

          <div className="mobsf-details-grid" style={{ marginTop: '1.5rem' }}>
            { }
            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>RISK DIMENSION ANALYSIS</h4>
              <div className="breakdown-list">
                {Object.keys(breakdown).map(k => (
                  <div key={k} className="breakdown-item">
                    <div className="breakdown-lbl">
                      <span>{k.replace('_', ' ').toUpperCase()}</span>
                      <span>{breakdown[k]}%</span>
                    </div>
                    <div className="progress-bar-bg">
                      <div className="progress-fill" style={{
                        width: `${breakdown[k]}%`,
                        backgroundColor: breakdown[k] >= 70 ? '#ef4444' : breakdown[k] >= 40 ? '#f59e0b' : '#10b981'
                      }}></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            { }
            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>REMEDIATION SUGGESTIONS ({data.remediation_suggestions?.length || 0})</h4>
              <div className="remediation-list">
                {data.remediation_suggestions?.length > 0 ? (
                  data.remediation_suggestions.map((r, idx) => (
                    <div key={idx} className="remediation-item">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <span className={`priority-badge ${r.priority.toLowerCase()}`}>{r.priority}</span>
                        <strong style={{ color: '#fff', fontSize: '0.85rem' }}>{r.action}</strong>
                      </div>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{r.details}</p>
                    </div>
                  ))
                ) : (
                  <p style={{ color: '#10b981', textAlign: 'center', padding: '1.5rem' }}>
                    <CheckCircle size={24} style={{ display: 'block', margin: '0 auto 0.5rem' }} />
                    No urgent security remediation actions found.
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    }

    case 'email': {
      if (data.error) return <div className="verdict-banner danger">{data.error}</div>;

      const summary = data.parsed_summary || {};
      const threatFlags = data.threat_flags || [];
      const score = data.threat_score || 0;
      const verdict = data.analysis_verdict || 'ANALYZED';
      const emailData = data.email_data || {};
      const headerObj = emailData.header || {};
      const bodyParts = emailData.body || [];

      const circ = 2 * Math.PI * 45;
      const offset = circ - (score / 100) * circ;

      return (
        <div className="report-email-phishing" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Top Threat & Risk Summary Card */}
          <div className="mobsf-stats-grid">
            {/* Risk Gauge */}
            <div className="stat-card score-gauge-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>PHISHING THREAT INDEX</h4>
              <div className="gauge-container">
                <svg width="120" height="120" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="45" stroke="rgba(255,255,255,0.05)" strokeWidth="6" fill="transparent" />
                  <circle cx="50" cy="50" r="45"
                    stroke={score >= 60 ? '#ef4444' : score >= 30 ? '#f59e0b' : '#10b981'}
                    strokeWidth="6"
                    strokeDasharray={circ}
                    strokeDashoffset={offset}
                    strokeLinecap="round"
                    fill="transparent"
                    transform="rotate(-90 50 50)" />
                  <text x="50" y="55" textAnchor="middle" fill="#fff" fontSize="18" fontWeight="bold">
                    {score}
                  </text>
                  <text x="50" y="72" textAnchor="middle" fill="var(--text-muted)" fontSize="8">
                    Risk Score
                  </text>
                </svg>
              </div>
              <span className={`badge ${score >= 60 ? 'failed' : score >= 30 ? 'warning' : 'success'}`} style={{ marginTop: '0.5rem' }}>
                {verdict}
              </span>
            </div>

            {/* Email Header Overview */}
            <div className="stat-card app-profile-card cyber-panel" style={{ gridColumn: 'span 2' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>EMAIL HEADER INTEL</h4>
              <div className="profile-grid">
                <div><span>Subject:</span> <strong style={{ color: '#00f0ff' }}>{summary.subject || headerObj.subject || 'N/A'}</strong></div>
                <div><span>From (Display):</span> <strong style={{ color: summary.from_display?.includes('<') && summary.from_display?.split('<')[0]?.toLowerCase().includes('paypal') ? '#ef4444' : '#fff' }}>{summary.from_display || headerObj.from || 'N/A'}</strong></div>
                <div><span>From Email:</span> <code>{summary.from_email || headerObj.from || 'N/A'}</code></div>
                <div><span>Reply-To:</span> <code style={{ color: summary.reply_to && summary.reply_to !== 'Same as From' && summary.reply_to !== summary.from_email ? '#ef4444' : '#fff' }}>{summary.reply_to || 'N/A'}</code></div>
                <div><span>To:</span> <span>{Array.isArray(summary.to) ? summary.to.join(', ') : summary.to || 'N/A'}</span></div>
                <div><span>Originating IP:</span> <code style={{ color: '#f59e0b' }}>{summary.originating_ip || 'N/A'}</code></div>
                <div><span>Message-ID:</span> <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>{summary.message_id || 'N/A'}</span></div>
                <div><span>Date:</span> <span>{summary.date || headerObj.date || 'N/A'}</span></div>
              </div>
            </div>
          </div>

          {/* Phishing Red Flags & Indicators */}
          <div className="stat-card cyber-panel">
            <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
            <h4>CRITICAL PHISHING INDICATORS & RED FLAGS ({threatFlags.length})</h4>
            <div className="remediation-list">
              {threatFlags.length > 0 ? (
                threatFlags.map((flag, idx) => (
                  <div key={idx} className="remediation-item" style={{ borderLeft: '3px solid #ef4444', backgroundColor: 'rgba(239,68,68,0.04)', padding: '0.75rem', borderRadius: '4px', marginBottom: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <AlertTriangle size={16} className="text-danger" style={{ color: '#ef4444' }} />
                      <span style={{ fontSize: '0.85rem', color: '#fff', fontWeight: 'bold' }}>Indicator #{idx + 1}</span>
                    </div>
                    <p style={{ fontSize: '0.8rem', color: '#cbd5e1', marginTop: '0.35rem', lineHeight: '1.4' }}>{flag}</p>
                  </div>
                ))
              ) : (
                <div style={{ color: '#10b981', textAlign: 'center', padding: '1.5rem' }}>
                  <CheckCircle size={24} style={{ display: 'block', margin: '0 auto 0.5rem' }} />
                  <span>No explicit phishing red flags or header spoofing indicators detected.</span>
                </div>
              )}
            </div>
          </div>

          {/* Received Mail Server Routing Hops */}
          {summary.received_hops && summary.received_hops.length > 0 && (
            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>MAIL SERVER ROUTING HOPS (RECEIVED HEADERS)</h4>
              <div className="pcap-table-wrapper" style={{ marginTop: '0.75rem' }}>
                <table className="metadata-table">
                  <thead>
                    <tr>
                      <th>HOP #</th>
                      <th>SOURCE / FROM</th>
                      <th>RECEIVING MX / BY</th>
                      <th>PROTOCOL / WITH</th>
                      <th>TIMESTAMP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.received_hops.map((hop, idx) => (
                      <tr key={idx}>
                        <td style={{ fontWeight: 'bold', color: '#00f0ff', fontFamily: 'monospace' }}>#{idx + 1}</td>
                        <td className="prop-val">
                          {Array.isArray(hop.from) ? hop.from.join(' ') : hop.src || 'Unknown'}
                        </td>
                        <td className="prop-val">
                          {Array.isArray(hop.by) ? hop.by.join(', ') : 'Unknown'}
                        </td>
                        <td><code>{hop.with || 'N/A'}</code></td>
                        <td style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>{hop.date || 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Fingerprints & Body Hashes */}
          <div className="mobsf-details-grid">
            {/* Body MIME & Hashes */}
            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>MIME BODY PARTS & CRYPTOGRAPHIC HASHES</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
                {bodyParts.length > 0 ? (
                  bodyParts.map((part, idx) => (
                    <div key={idx} style={{ padding: '0.65rem', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '4px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                        <span style={{ fontSize: '0.75rem', color: '#00f0ff', fontWeight: 'bold' }}>{part.content_type || 'text/plain'}</span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Boundary: {part.boundary || 'N/A'}</span>
                      </div>
                      <div style={{ fontSize: '0.72rem', fontFamily: 'monospace', wordBreak: 'break-all', color: '#a5b4fc' }}>
                        Hash: {part.hash || 'N/A'}
                      </div>
                    </div>
                  ))
                ) : (
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>No MIME body parts found.</p>
                )}
              </div>
            </div>

            {/* Extracted URI & Domain Fingerprints */}
            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>EXTRACTED URIS, DOMAINS & FINGERPRINTS</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
                {summary.extracted_uris && summary.extracted_uris.length > 0 && (
                  <div>
                    <span style={{ fontSize: '0.75rem', color: '#ef4444', fontWeight: 'bold' }}>EXTRACTED TARGET URLS ({summary.extracted_uris.length}):</span>
                    {summary.extracted_uris.map((url, i) => (
                      <div key={i} style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#f87171', background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239,68,68,0.2)', padding: '6px 8px', borderRadius: '4px', marginTop: '4px', wordBreak: 'break-all' }}>
                        🔗 {url}
                      </div>
                    ))}
                  </div>
                )}
                {summary.extracted_domains && summary.extracted_domains.length > 0 && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', color: '#38bdf8', fontWeight: 'bold' }}>SUSPICIOUS DOMAINS ({summary.extracted_domains.length}):</span>
                    {summary.extracted_domains.map((dom, i) => (
                      <div key={i} style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#38bdf8', background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56,189,248,0.2)', padding: '4px 8px', borderRadius: '4px', marginTop: '4px' }}>
                        🌐 {dom}
                      </div>
                    ))}
                  </div>
                )}
                {summary.uri_hashes && summary.uri_hashes.length > 0 && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', color: '#f59e0b', fontWeight: 'bold' }}>URI SHA-256 Hashes ({summary.uri_hashes.length}):</span>
                    {summary.uri_hashes.map((uh, i) => (
                      <div key={i} style={{ fontSize: '0.7rem', fontFamily: 'monospace', color: '#e2e8f0', background: 'rgba(0,0,0,0.3)', padding: '4px 6px', borderRadius: '3px', marginTop: '4px', wordBreak: 'break-all' }}>
                        {uh}
                      </div>
                    ))}
                  </div>
                )}
                {summary.domain_hashes && summary.domain_hashes.length > 0 && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', color: '#a855f7', fontWeight: 'bold' }}>Domain SHA-256 Hashes ({summary.domain_hashes.length}):</span>
                    {summary.domain_hashes.map((dh, i) => (
                      <div key={i} style={{ fontSize: '0.7rem', fontFamily: 'monospace', color: '#e2e8f0', background: 'rgba(0,0,0,0.3)', padding: '4px 6px', borderRadius: '3px', marginTop: '4px', wordBreak: 'break-all' }}>
                        {dh}
                      </div>
                    ))}
                  </div>
                )}
                {(!summary.extracted_uris || summary.extracted_uris.length === 0) && (!summary.uri_hashes || summary.uri_hashes.length === 0) && (
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>No URL or domain hashes extracted from email body.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    }

    case 'evtx': {
      if (data.error) return <div className="verdict-banner danger">{data.error}</div>;

      const records = data.records || [];
      const suspiciousLogons = data.suspicious_logons || [];
      const totalParsed = data.total_records_parsed || records.length;

      return (
        <div className="report-evtx" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Top Summary Panel */}
          <div className="mobsf-stats-grid">
            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>PARSED EVENT LOGS</h4>
              <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#00f0ff', marginTop: '0.5rem', fontFamily: 'monospace' }}>
                {totalParsed}
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Total Records Extracted</span>
            </div>

            <div className="stat-card cyber-panel" style={{ borderLeft: suspiciousLogons.length > 0 ? '4px solid #ef4444' : '4px solid #10b981' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>SUSPICIOUS LOGONS / ANOMALIES</h4>
              <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: suspiciousLogons.length > 0 ? '#ef4444' : '#10b981', marginTop: '0.5rem', fontFamily: 'monospace' }}>
                {suspiciousLogons.length}
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Failed Logons (4625) & Privilege Assignments (4672)</span>
            </div>
          </div>

          {/* Suspicious Logon Events List */}
          {suspiciousLogons.length > 0 && (
            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>CRITICAL EVENT ANOMALIES ({suspiciousLogons.length})</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.75rem' }}>
                {suspiciousLogons.map((item, idx) => (
                  <div key={idx} style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.05)', borderLeft: '3px solid #ef4444', borderRadius: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                      <span style={{ fontWeight: 'bold', color: '#ef4444', fontSize: '0.85rem' }}>Event ID {item.event_id}: {item.type}</span>
                    </div>
                    <pre style={{ margin: 0, fontSize: '0.72rem', fontFamily: 'monospace', color: '#cbd5e1', whiteSpace: 'pre-wrap', background: 'rgba(0,0,0,0.3)', padding: '0.5rem', borderRadius: '3px' }}>
                      {item.xml}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* XML Records List */}
          <div className="stat-card cyber-panel">
            <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
            <h4>EVENT LOG XML RECORDS ({records.length})</h4>
            <div style={{ maxHeight: '450px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.75rem' }}>
              {records.length > 0 ? (
                records.map((xml, idx) => (
                  <div key={idx} style={{ padding: '0.65rem', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.75rem', color: '#00f0ff', fontWeight: 'bold', marginBottom: '0.25rem' }}>Record #{idx + 1}</div>
                    <pre style={{ margin: 0, fontSize: '0.7rem', fontFamily: 'monospace', color: '#a5b4fc', whiteSpace: 'pre-wrap', maxHeight: '120px', overflowY: 'auto' }}>
                      {xml}
                    </pre>
                  </div>
                ))
              ) : (
                <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', padding: '1rem', textAlign: 'center' }}>No EVTX records parsed.</p>
              )}
            </div>
          </div>
        </div>
      );
    }

    case 'hash': {
      if (data.error) return <div className="verdict-banner danger">{data.error}</div>;

      const cracked = data.cracked_passwords || [];
      const uncracked = data.uncracked_hashes || [];
      const total = data.total_hashes || (cracked.length + uncracked.length);
      const recoveryRate = data.recovery_rate || (total > 0 ? ((cracked.length / total) * 100).toFixed(1) : 0);
      const algo = data.detected_type || 'MD5 / SHA';

      return (
        <div className="report-hash-cracking" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Top Summary Cards */}
          <div className="mobsf-stats-grid">
            <div className="stat-card cyber-panel" style={{ borderLeft: '4px solid #10b981' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>CRACKED PASSWORDS</h4>
              <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#10b981', marginTop: '0.5rem', fontFamily: 'monospace' }}>
                {cracked.length} / {total}
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{recoveryRate}% Recovery Rate</span>
            </div>

            <div className="stat-card cyber-panel">
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>DETECTED HASH TYPE</h4>
              <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#00f0ff', marginTop: '0.5rem', fontFamily: 'monospace' }}>
                {algo}
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Auto-detected Format</span>
            </div>
          </div>

          {/* Cracked Passwords Table */}
          <div className="stat-card cyber-panel">
            <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
            <h4>RECOVERED PLAINTEXT PASSWORDS ({cracked.length})</h4>
            <div className="pcap-table-wrapper" style={{ marginTop: '0.75rem' }}>
              <table className="metadata-table">
                <thead>
                  <tr>
                    <th>TARGET HASH</th>
                    <th>CRACKED PLAINTEXT PASSWORD</th>
                    <th>ALGORITHM</th>
                    <th>STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {cracked.length > 0 ? (
                    cracked.map((item, idx) => (
                      <tr key={idx}>
                        <td className="prop-val">
                          <code style={{ fontSize: '0.75rem', color: '#a5b4fc' }}>{item.hash}</code>
                        </td>
                        <td style={{ fontWeight: 'bold', color: '#10b981', fontSize: '0.9rem', fontFamily: 'monospace' }}>
                          🔑 {item.plaintext}
                        </td>
                        <td>
                          <span style={{ background: 'rgba(0,240,255,0.1)', color: '#00f0ff', border: '1px solid rgba(0,240,255,0.3)', padding: '2px 6px', borderRadius: '3px', fontSize: '0.7rem' }}>
                            {item.algorithm || algo}
                          </span>
                        </td>
                        <td>
                          <span className="badge success">CRACKED</span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                        No hashes cracked in this session.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Uncracked Hashes if any */}
          {uncracked.length > 0 && (
            <div className="stat-card cyber-panel" style={{ borderLeft: '4px solid #f59e0b' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>UNCRACKED HASHES ({uncracked.length})</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.5rem' }}>
                {uncracked.map((h, idx) => (
                  <div key={idx} style={{ padding: '0.4rem 0.6rem', background: 'rgba(245,158,11,0.05)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace', color: '#f59e0b' }}>
                    {h}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    }

    case 'network': {
      if (data.error) return <div className="verdict-banner danger">{data.error}</div>;

      return (
        <div className="report-network">
          <h4>PCAP PACKET DUMP ANALYSIS ({data.scan_type || 'parsed'})</h4>
          {Array.isArray(data) ? (
            <div className="pcap-table-wrapper" style={{ marginTop: '1rem' }}>
              <table className="metadata-table">
                <thead>
                  <tr>
                    <th>RESOLVED DOMAIN / TARGET</th>
                    <th>DETAIL / PROTOCOL</th>
                  </tr>
                </thead>
                <tbody>
                  {data.map((item, idx) => (
                    <tr key={idx}>
                      <td className="prop-name" style={{ color: 'var(--primary)' }}>{item.domain || item.target || item.ip || JSON.stringify(item)}</td>
                      <td className="prop-val">{item.count || item.protocol || 'Detected'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <pre className="json-view" style={{ marginTop: '1rem' }}>{JSON.stringify(data, null, 2)}</pre>
          )}
        </div>
      );
    }

    case 'threat_intel': {
      let heuristicsBanner = null;
      if (data.local_heuristics && data.local_heuristics.is_suspicious) {
        const lh = data.local_heuristics;
        heuristicsBanner = (
          <div className="report-intel" style={{ marginBottom: '1.5rem' }}>
            <div className="stat-card cyber-panel" style={{ border: '1px solid #ef4444', background: 'rgba(239, 68, 68, 0.05)', display: 'flex', gap: '1rem', alignItems: 'center' }}>
              <div className="cyber-corner-tl" style={{ borderColor: '#ef4444' }}></div><div className="cyber-corner-tr" style={{ borderColor: '#ef4444' }}></div>
              <div className="cyber-corner-bl" style={{ borderColor: '#ef4444' }}></div><div className="cyber-corner-br" style={{ borderColor: '#ef4444' }}></div>
              <AlertTriangle size={48} style={{ color: '#ef4444', flexShrink: 0 }} />
              <div>
                <h3 style={{ color: '#ef4444', margin: '0 0 0.5rem 0', textShadow: '0 0 10px rgba(239, 68, 68, 0.5)' }}>LOCAL HEURISTICS</h3>
                <div style={{ color: 'var(--text-primary)', marginBottom: '0.25rem' }}><strong>Reason:</strong> {lh.reason}</div>
                <div style={{ color: 'var(--text-muted)' }}><strong>Action:</strong> {lh.recommendation}</div>
              </div>
            </div>
          </div>
        );
      }

      let gsRender = null;
      if (data.google_safebrowsing) {
        const gs = data.google_safebrowsing;
        gsRender = (
          <div className="report-intel">
            <div className="mobsf-stats-grid animate-fade-in" style={{ gap: '1.5rem' }}>
              <div className="stat-card cyber-panel" style={{ flex: 1.5 }}>
                <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
                <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
                <h4>GOOGLE SAFE BROWSING</h4>
                  <div className="profile-grid">
                    <div><span>Target Domain:</span> <strong className="glowing-text">{gs.domain}</strong></div>
                    <div><span>Diagnostic Verdict:</span> <strong style={{ color: gs.is_safe ? '#10b981' : '#ef4444' }}>{gs.status_description}</strong></div>
                    <div><span>Redirects to Harmful:</span> <strong>{gs.redirects_to_harmful ? "YES (DETECTED)" : "NO"}</strong></div>
                    <div><span>Installs Unwanted Software:</span> <strong>{gs.installs_unwanted_software ? "YES (DETECTED)" : "NO"}</strong></div>
                    <div><span>Phishing / Social Engineering:</span> <strong>{gs.is_phishing ? "YES (DETECTED)" : "NO"}</strong></div>
                    <div><span>Contains Malware:</span> <strong>{gs.contains_malware ? "YES (DETECTED)" : "NO"}</strong></div>
                    <div><span>Uncommon Downloads:</span> <strong>{gs.uncommon_downloads ? "YES (DETECTED)" : "NO"}</strong></div>
                  </div>
              </div>

              <div className="stat-card cyber-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
                <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
                <h4>VERDICT INDEX</h4>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', width: '100%', marginTop: '0.75rem' }}>
                  {gs.is_safe ? (
                    <>
                      <CheckCircle size={48} style={{ color: '#10b981', marginBottom: '0.75rem' }} />
                      <span className="badge success" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: '1px solid #10b981', padding: '0.25rem 0.75rem', borderRadius: '4px', fontSize: '0.9rem', fontWeight: 'bold' }}>CLEAR</span>
                      <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.5rem', textAlign: 'center', fontFamily: 'monospace' }}>
                        No malicious indicators active in Google's database.
                      </p>
                    </>
                  ) : (
                    <>
                      <AlertTriangle size={48} style={{ color: '#ef4444', marginBottom: '0.75rem' }} />
                      <span className="badge failed" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid #ef4444', padding: '0.25rem 0.75rem', borderRadius: '4px', fontSize: '0.9rem', fontWeight: 'bold' }}>DANGEROUS</span>
                      <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.5rem', textAlign: 'center', fontFamily: 'monospace' }}>
                        Warning: Google flags this site as unsafe or malicious.
                      </p>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        );
      }

      let mlRender = null;
      if (data.ml_analysis) {
        const ml = data.ml_analysis;
        const isMalicious = ml.prediction !== "benign";
        mlRender = (
          <div className="report-intel">
            <div className="mobsf-stats-grid animate-fade-in" style={{ gap: '1.5rem' }}>
              <div className="stat-card cyber-panel" style={{ flex: 1.5 }}>
                <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
                <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
                <h4>ML URL ANALYZER (RANDOM FOREST)</h4>
                <div className="profile-grid">
                  <div><span>Target URL:</span> <strong className="glowing-text" style={{ wordBreak: 'break-all' }}>{ml.url}</strong></div>
                  <div><span>Prediction:</span> <strong style={{ color: isMalicious ? '#ef4444' : '#10b981', textTransform: 'uppercase' }}>{ml.prediction}</strong></div>
                  <div><span>Confidence:</span> <strong style={{ color: isMalicious ? '#ef4444' : '#10b981' }}>{ml.confidence}%</strong></div>
                  <div style={{ gridColumn: 'span 2', marginTop: '1rem', borderTop: '1px solid rgba(0, 240, 255, 0.2)', paddingTop: '1rem' }}>
                    <h5 style={{ color: 'var(--text-muted)', marginBottom: '0.5rem' }}>CLASS PROBABILITIES:</h5>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span>Benign:</span> <strong style={{ color: '#10b981' }}>{ml.class_probabilities.benign}%</strong>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span>Phishing:</span> <strong style={{ color: '#ef4444' }}>{ml.class_probabilities.phishing}%</strong>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span>Malware:</span> <strong style={{ color: '#ef4444' }}>{ml.class_probabilities.malware}%</strong>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span>Defacement:</span> <strong style={{ color: '#f59e0b' }}>{ml.class_probabilities.defacement}%</strong>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="stat-card cyber-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
                <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
                <h4>AI VERDICT</h4>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', width: '100%', marginTop: '0.75rem' }}>
                  {!isMalicious ? (
                    <>
                      <CheckCircle size={48} style={{ color: '#10b981', marginBottom: '0.75rem' }} />
                      <span className="badge success" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: '1px solid #10b981', padding: '0.25rem 0.75rem', borderRadius: '4px', fontSize: '0.9rem', fontWeight: 'bold' }}>SAFE (BENIGN)</span>
                    </>
                  ) : (
                    <>
                      <AlertTriangle size={48} style={{ color: '#ef4444', marginBottom: '0.75rem' }} />
                      <span className="badge failed" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid #ef4444', padding: '0.25rem 0.75rem', borderRadius: '4px', fontSize: '0.9rem', fontWeight: 'bold' }}>{ml.prediction.toUpperCase()} DETECTED</span>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        );
      }

      let usRender = null;
      if (data.urlscan) {
        const us = data.urlscan;
        usRender = (
          <div className="report-intel">
            <div className="mobsf-stats-grid animate-fade-in" style={{ gap: '1.5rem' }}>
              <div className="stat-card cyber-panel" style={{ flex: 1 }}>
                <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
                <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
                <h4>URLSCAN.IO // SANDBOX ACTIVITY</h4>
                <div className="profile-grid">
                  <div><span>Total Historical Scans:</span> <strong className="glowing-text">{us.total_scans}</strong></div>
                  {us.results && us.results.length > 0 ? (
                    us.results.map((r, i) => (
                      <div key={i} style={{ borderTop: '1px solid rgba(0, 240, 255, 0.2)', paddingTop: '0.5rem', marginTop: '0.5rem', gridColumn: 'span 2' }}>
                        <div><span>Time:</span> <strong>{new Date(r.task.time).toLocaleString()}</strong></div>
                        <div><span>Domain:</span> <strong>{r.page.domain}</strong></div>
                        <div><span>IP Address:</span> <strong>{r.page.ip}</strong></div>
                        <div><span>Server:</span> <strong>{r.page.server}</strong></div>
                        <div><span>Result URL:</span> <a href={r.result} target="_blank" rel="noreferrer" style={{ color: 'var(--accent-primary)', textDecoration: 'none' }}>View Detailed Report ↗</a></div>
                      </div>
                    ))
                  ) : (
                    <div style={{ gridColumn: 'span 2', color: 'var(--text-muted)' }}>No previous sandbox scans found for this target.</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        );
      }

      let pdRender = null;
      if (data.pulsedive) {
        const pd = data.pulsedive;
        const isSafe = pd.risk === "none" || pd.risk === "unknown";
        pdRender = (
          <div className="report-intel">
            <div className="mobsf-stats-grid animate-fade-in" style={{ gap: '1.5rem' }}>
              <div className="stat-card cyber-panel" style={{ flex: 1.5 }}>
                <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
                <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
                <h4>PULSEDIVE // THREAT INTEL</h4>
                {pd.message ? (
                  <div style={{ color: 'var(--text-muted)', fontFamily: 'monospace' }}>{pd.message}</div>
                ) : (
                  <div className="profile-grid">
                    <div><span>Target Indicator:</span> <strong className="glowing-text">{pd.indicator}</strong></div>
                    <div><span>Risk Level:</span> <strong style={{ color: isSafe ? '#10b981' : '#ef4444', textTransform: 'uppercase' }}>{pd.risk}</strong></div>
                    <div><span>Recommended Action:</span> <strong style={{ color: isSafe ? '#10b981' : '#ef4444', textTransform: 'uppercase' }}>{pd.risk_recommended}</strong></div>
                    {pd.threats && pd.threats.length > 0 && (
                      <div style={{ gridColumn: 'span 2' }}><span>Associated Threats:</span> <strong style={{ color: '#ef4444' }}>{pd.threats.join(', ')}</strong></div>
                    )}
                    {pd.properties && pd.properties.geo && (
                      <div style={{ gridColumn: 'span 2', borderTop: '1px solid rgba(0, 240, 255, 0.2)', paddingTop: '0.5rem', marginTop: '0.5rem' }}>
                        <span>Geo-Location:</span> <strong>{pd.properties.geo.country} ({pd.properties.geo.org})</strong>
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="stat-card cyber-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
                <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
                <h4>RISK INDEX</h4>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', width: '100%', marginTop: '0.75rem' }}>
                  {isSafe ? (
                    <>
                      <CheckCircle size={48} style={{ color: '#10b981', marginBottom: '0.75rem' }} />
                      <span className="badge success" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: '1px solid #10b981', padding: '0.25rem 0.75rem', borderRadius: '4px', fontSize: '0.9rem', fontWeight: 'bold' }}>CLEAN</span>
                    </>
                  ) : (
                    <>
                      <AlertTriangle size={48} style={{ color: '#ef4444', marginBottom: '0.75rem' }} />
                      <span className="badge failed" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid #ef4444', padding: '0.25rem 0.75rem', borderRadius: '4px', fontSize: '0.9rem', fontWeight: 'bold' }}>MALICIOUS</span>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        );
      }


      let whoisRender = null;
      if (data.whois_info) {
        const wi = data.whois_info;
        const ageDays = wi.domain_age_days;
        const ageColor = ageDays === null || ageDays === undefined
          ? '#64748b'
          : ageDays < 180 ? '#ef4444'
          : ageDays < 365 ? '#f59e0b'
          : '#10b981';
        const ageLabel = ageDays === null || ageDays === undefined
          ? 'N/A'
          : ageDays < 180 ? `${ageDays} days ⚠ VERY YOUNG`
          : ageDays < 365 ? `${ageDays} days (< 1 year)`
          : `${ageDays} days (${Math.floor(ageDays / 365)} yr${Math.floor(ageDays / 365) > 1 ? 's' : ''})`;
        whoisRender = (
          <div className="report-intel">
            <div className="mobsf-stats-grid animate-fade-in" style={{ gap: '1.5rem' }}>
              <div className="stat-card cyber-panel" style={{ flex: 1 }}>
                <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
                <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
                <h4>WHOIS // DOMAIN REPUTATION</h4>
                <div className="profile-grid">
                  <div><span>Registrar:</span> <strong className="glowing-text">{wi.registrar || 'N/A'}</strong></div>
                  <div><span>Creation Date:</span> <strong>{Array.isArray(wi.creation_date) ? wi.creation_date[0] : wi.creation_date || 'N/A'}</strong></div>
                  <div><span>Expiration Date:</span> <strong>{Array.isArray(wi.expiration_date) ? wi.expiration_date[0] : wi.expiration_date || 'N/A'}</strong></div>
                  <div><span>Domain Age:</span> <strong style={{ color: ageColor }}>{ageLabel}</strong></div>
                  <div><span>DNSSEC:</span> <strong>{wi.dnssec || 'N/A'}</strong></div>
                </div>
              </div>
            </div>
          </div>
        );
      }

      let aggRender = null;
      if (data.aggregated_risk_assessment) {
        const agg = data.aggregated_risk_assessment;
        const color = agg.verdict === "SAFE" ? "#10b981" : agg.verdict === "MEDIUM" ? "#f59e0b" : "#ef4444";
        aggRender = (
          <div className="report-intel" style={{ marginBottom: '1.5rem' }}>
            <div className="mobsf-stats-grid animate-fade-in" style={{ gap: '1.5rem' }}>
              <div className="stat-card cyber-panel" style={{ flex: 1, border: `1px solid ${color}`, background: `rgba(${agg.verdict === "SAFE" ? '16, 185, 129' : '239, 68, 68'}, 0.05)` }}>
                <div className="cyber-corner-tl" style={{ borderColor: color }}></div><div className="cyber-corner-tr" style={{ borderColor: color }}></div>
                <div className="cyber-corner-bl" style={{ borderColor: color }}></div><div className="cyber-corner-br" style={{ borderColor: color }}></div>
                <h3 style={{ color: color, textShadow: `0 0 10px rgba(${agg.verdict === "SAFE" ? '16, 185, 129' : '239, 68, 68'}, 0.5)`, marginBottom: '1rem', textAlign: 'center' }}>
                  UNIVERSAL ALGORITHM VERDICT: {agg.verdict}
                </h3>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '1.5rem' }}>
                  <div style={{ fontSize: '3rem', fontWeight: 'bold', color: color }}>{agg.risk_score}</div>
                  <div style={{ fontSize: '1rem', color: 'var(--text-muted)', marginLeft: '0.5rem', marginTop: '1.5rem' }}>/ 100 RISK SCORE</div>
                </div>

                <div>
                  <h5 style={{ color: 'var(--text-muted)', marginBottom: '0.5rem', borderBottom: '1px solid rgba(0, 240, 255, 0.2)', paddingBottom: '0.5rem' }}>CONTRIBUTING FACTORS:</h5>
                  <ul style={{ listStyleType: 'none', padding: 0, margin: 0 }}>
                    {agg.factors.map((f, i) => (
                      <li key={i} style={{ padding: '0.5rem 0', borderBottom: '1px dashed rgba(0, 240, 255, 0.1)', color: 'var(--text-primary)' }}>
                        <span style={{ color: 'var(--accent-primary)', marginRight: '0.5rem' }}>&gt;</span> {f}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        );
      }

      if (gsRender || mlRender || usRender || pdRender || aggRender || whoisRender) {

        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {heuristicsBanner}
            {aggRender}
            {whoisRender}
            {gsRender}
            {mlRender}
            {usRender}
            {pdRender}
          </div>
        );
      }

      const isIP = data.query || data.ip;

      return (
        <div className="report-intel">
          <div className="mobsf-stats-grid">
            <div className="stat-card cyber-panel" style={{ flex: 1 }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>GEOGRAPHIC REPUTATION</h4>
              <div className="profile-grid">
                <div><span>Target Host:</span> <strong>{data.query || data.ip || 'N/A'}</strong></div>
                <div><span>Country:</span> <strong>{data.country || data.country_name || 'N/A'} ({data.countryCode || 'N/A'})</strong></div>
                <div><span>Region/City:</span> <strong>{data.regionName || data.city || 'N/A'}</strong></div>
                <div><span>ISP / Provider:</span> <strong>{data.isp || data.org || 'N/A'}</strong></div>
                <div><span>Coordinates:</span> <strong>Lat: {data.lat || 'N/A'}, Lon: {data.lon || 'N/A'}</strong></div>
              </div>
            </div>

            <div className="stat-card cyber-panel" style={{ flex: 1 }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>THREAT VERDICT</h4>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                {data.status === 'success' || !data.error ? (
                  <>
                    <CheckCircle size={48} style={{ color: '#10b981', marginBottom: '0.75rem' }} />
                    <span style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>TARGET CLEAR</span>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.25rem', textAlign: 'center' }}>
                      Host verified. No active indicators flagged from local DNS DB lists.
                    </p>
                  </>
                ) : (
                  <>
                    <AlertTriangle size={48} style={{ color: '#ef4444', marginBottom: '0.75rem' }} />
                    <span style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>HOST SUSPICIOUS</span>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.25rem' }}>
                      Warning: Host is categorized as suspicious/malicious.
                    </p>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    }

    case 'yara': {
      const matches = data.matches || [];
      return (
        <div className="report-yara">
          <h4>MATCHED MALWARE PATTERNS ({matches.length})</h4>
          <div className="yara-matches-grid" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
            {matches.length > 0 ? (
              matches.map((match, idx) => (
                <div key={idx} className="yara-match-card cyber-panel" style={{
                  padding: '1rem',
                  borderLeft: '4px solid #ef4444',
                  backgroundColor: 'rgba(239, 68, 68, 0.03)',
                  borderRadius: '0 0.5rem 0.5rem 0'
                }}>
                  <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
                  <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
                  <div style={{ fontWeight: 'bold', fontSize: '1rem', color: '#ef4444' }}>Rule Match: {match.rule}</div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                    File: <code style={{ backgroundColor: 'rgba(0,0,0,0.3)', padding: '2px 4px', borderRadius: '3px' }}>{match.file}</code>
                  </div>
                  {match.meta && (
                    <div style={{ marginTop: '0.5rem', fontSize: '0.8rem' }}>
                      <strong>Rule Meta:</strong>
                      <pre style={{ margin: '0.25rem 0 0 0', whiteSpace: 'pre-wrap', color: '#a5b4fc', fontSize: '0.75rem' }}>{JSON.stringify(match.meta, null, 2)}</pre>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div style={{ textAlign: 'center', color: '#10b981', padding: '2rem', border: '1px dashed rgba(16,185,129,0.3)', borderRadius: '0.5rem' }}>
                <CheckCircle size={32} style={{ display: 'block', margin: '0 auto 0.5rem' }} />
                <span>No YARA rules matched the scanned binary.</span>
              </div>
            )}
          </div>
        </div>
      );
    }

    case 'ip_resolver': {
      const geo = data.geo || {};
      const threat = data.threat_intelligence || {};
      const whoisRdap = data.whois_rdap || {};
      const sslInfo = data.ssl_info || {};
      const openPorts = data.open_ports || [];

      const riskColor = threat.risk_level === 'CRITICAL' || threat.risk_level === 'HIGH'
        ? '#ef4444'
        : threat.risk_level === 'MEDIUM'
          ? '#f59e0b'
          : '#10b981';

      return (
        <div className="report-ip-resolver" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Top Banner: IP, Quick Status & Risk Gauge */}
          <div className="stat-card cyber-panel" style={{ borderLeft: `4px solid ${riskColor}` }}>
            <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>RESOLVED ADDRESS INTEL</div>
                <h2 className="glowing-text" style={{ margin: '0.2rem 0', fontFamily: 'monospace', color: '#00f0ff', fontSize: '1.7rem' }}>
                  {data.ip}
                </h2>
                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.4rem', flexWrap: 'wrap', alignItems: 'center' }}>
                  <span style={{ background: data.version === 'IPv6' ? 'rgba(139, 92, 246, 0.2)' : 'rgba(0, 240, 255, 0.2)', color: data.version === 'IPv6' ? '#a5b4fc' : '#00f0ff', border: `1px solid ${data.version === 'IPv6' ? '#8b5cf6' : '#00f0ff'}`, padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 'bold' }}>
                    {data.version}
                  </span>
                  <span style={{ background: 'rgba(255, 255, 255, 0.05)', color: 'var(--text-main)', border: '1px solid var(--panel-border)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem' }}>
                    TYPE: {data.ip_type}
                  </span>
                  {data.rtt_ms > 0 && (
                    <span style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: '1px solid #10b981', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                      RTT: {data.rtt_ms} ms
                    </span>
                  )}
                  {data.ptr_mismatch && (
                    <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', border: '1px solid #ef4444', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 'bold' }}>
                      ⚠ PTR MISMATCH
                    </span>
                  )}
                  {geo.is_tor && <span style={{ background: 'rgba(239, 68, 68, 0.25)', color: '#ef4444', border: '1px solid #ef4444', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 'bold' }}>TOR EXIT NODE</span>}
                  {geo.is_proxy && <span style={{ background: 'rgba(245, 158, 11, 0.2)', color: '#f59e0b', border: '1px solid #f59e0b', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem' }}>VPN / PROXY</span>}
                  {geo.is_hosting && <span style={{ background: 'rgba(59, 130, 246, 0.2)', color: '#60a5fa', border: '1px solid #3b82f6', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem' }}>DATACENTER</span>}
                </div>
              </div>

              <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>FORENSIC RISK SCORE</div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: riskColor, fontFamily: 'monospace', lineHeight: 1.1 }}>
                  {threat.risk_score || 0} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/ 100</span>
                </div>
                <div style={{ fontSize: '0.8rem', fontWeight: 'bold', color: riskColor, textTransform: 'uppercase', marginTop: '2px' }}>
                  {threat.risk_level || 'LOW'} RISK ({threat.confidence || 'Medium'} Confidence)
                </div>
              </div>
            </div>
          </div>

          {/* Grid section for Geo & Network */}
          <div className="mobsf-stats-grid" style={{ gap: '1.5rem' }}>
            {/* Geolocation */}
            <div className="stat-card cyber-panel" style={{ flex: 1 }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>GEOLOCATION INTEL</h4>
              <div className="profile-grid" style={{ marginTop: '0.75rem' }}>
                <div><span>Country:</span> <strong>{geo.country ? `${geo.country} (${geo.country_code})` : 'N/A'}</strong></div>
                <div><span>Region / State:</span> <strong>{geo.region || 'N/A'}</strong></div>
                <div><span>City:</span> <strong>{geo.city || 'N/A'}</strong></div>
                <div><span>Timezone:</span> <strong>{geo.timezone || 'N/A'}</strong></div>
                <div><span>Coordinates:</span> <strong>{geo.latitude && geo.longitude ? `${geo.latitude}, ${geo.longitude}` : 'N/A'}</strong></div>
                {geo.google_maps_url && (
                  <div>
                    <span>Map View:</span>
                    <a href={geo.google_maps_url} target="_blank" rel="noreferrer" style={{ color: 'var(--primary)', textDecoration: 'none', fontWeight: 'bold', fontSize: '0.8rem' }}>
                      Open Google Maps ↗
                    </a>
                  </div>
                )}
              </div>
            </div>

            {/* Network & ASN */}
            <div className="stat-card cyber-panel" style={{ flex: 1 }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4>NETWORK & ASN BREAKDOWN</h4>
              <div className="profile-grid" style={{ marginTop: '0.75rem' }}>
                <div><span>ISP:</span> <strong className="glowing-text">{geo.isp || 'N/A'}</strong></div>
                <div><span>Organization:</span> <strong>{geo.org || 'N/A'}</strong></div>
                <div><span>ASN Number:</span> <strong style={{ color: 'var(--primary)' }}>{geo.asn_number || 'N/A'}</strong></div>
                <div><span>ASN Name/Org:</span> <strong>{geo.asn_org || 'N/A'}</strong></div>
                <div><span>Domain:</span> <strong>{geo.domain || 'N/A'}</strong></div>
                <div><span>Bogon Address:</span> <strong>{geo.bogon ? 'YES (BOGON)' : 'NO'}</strong></div>
              </div>
            </div>
          </div>

          {/* WHOIS / RDAP & RIR Information */}
          <div className="stat-card cyber-panel">
            <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
            <h4>WHOIS / RDAP & REGISTRY INTEL (RIR)</h4>
            <div className="profile-grid" style={{ marginTop: '0.75rem', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))' }}>
              <div><span>Regional Registry (RIR):</span> <strong style={{ color: '#a5b4fc', textTransform: 'uppercase' }}>{whoisRdap.rir || 'N/A'}</strong></div>
              <div><span>Network Name:</span> <strong>{whoisRdap.network_name || 'N/A'}</strong></div>
              <div><span>CIDR Prefix:</span> <strong style={{ fontFamily: 'monospace', color: 'var(--primary)' }}>{whoisRdap.cidr || 'N/A'}</strong></div>
              <div><span>Handle:</span> <strong>{whoisRdap.handle || 'N/A'}</strong></div>
              {whoisRdap.abuse_emails && whoisRdap.abuse_emails.length > 0 && (
                <div style={{ gridColumn: 'span 2' }}>
                  <span>Abuse Contact Emails:</span>
                  <strong style={{ color: '#ef4444', fontFamily: 'monospace', marginLeft: '0.5rem' }}>
                    {whoisRdap.abuse_emails.join(', ')}
                  </strong>
                </div>
              )}
            </div>
          </div>

          {/* DNS Resolution & PTR Verification */}
          <div className="stat-card cyber-panel">
            <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
            <h4>DNS RESOLUTION & ANTI-SPOOFING PTR CHECK</h4>
            <div className="profile-grid" style={{ marginTop: '0.75rem', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))' }}>
              <div>
                <span>Reverse DNS (PTR):</span>{' '}
                <strong style={{ fontFamily: 'monospace', color: data.ptr_mismatch ? '#ef4444' : '#00f0ff' }}>
                  {data.reverse_dns || 'No PTR Record'}
                </strong>
              </div>
              <div>
                <span>PTR Alignment Verification:</span>{' '}
                <strong style={{ color: data.ptr_mismatch ? '#ef4444' : '#10b981' }}>
                  {data.ptr_mismatch ? 'MISMATCH DETECTED (POTENTIAL SPOOFING)' : 'MATCHED / VALID'}
                </strong>
              </div>
              <div><span>Compressed Notation:</span> <strong style={{ fontFamily: 'monospace' }}>{data.compressed || 'N/A'}</strong></div>
              {data.expanded && <div style={{ gridColumn: 'span 2' }}><span>Expanded IPv6 Notation:</span> <strong style={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all' }}>{data.expanded}</strong></div>}
            </div>
          </div>

          {/* Open Ports & Latency Grid */}
          <div className="stat-card cyber-panel">
            <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
            <h4>ACTIVE SERVICE PORTS & RTT LATENCY</h4>
            {openPorts.length > 0 ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '0.75rem', marginTop: '0.75rem' }}>
                {openPorts.map((p, idx) => (
                  <div key={idx} style={{ background: 'rgba(0, 240, 255, 0.05)', border: '1px solid rgba(0, 240, 255, 0.2)', padding: '0.6rem 0.8rem', borderRadius: '4px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontSize: '0.9rem', fontWeight: 'bold', color: 'var(--primary)', fontFamily: 'monospace' }}>
                        PORT {p.port}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{p.service}</div>
                    </div>
                    <span className="badge success" style={{ fontSize: '0.7rem', padding: '2px 6px' }}>
                      {p.latency_ms} ms
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ marginTop: '0.5rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No standard forensic ports (21, 22, 25, 53, 80, 443, 3389, 8080) responding to TCP probe.
              </div>
            )}
          </div>

          {/* SSL / TLS Certificate Details (if HTTPS port 443 active) */}
          {sslInfo && sslInfo.ssl_enabled && (
            <div className="stat-card cyber-panel" style={{ borderLeft: '4px solid #3b82f6' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4 style={{ color: '#60a5fa' }}>SSL / TLS CERTIFICATE INSPECTION</h4>
              <div className="profile-grid" style={{ marginTop: '0.75rem', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))' }}>
                <div><span>TLS Version:</span> <strong style={{ color: '#60a5fa' }}>{sslInfo.tls_version || 'N/A'}</strong></div>
                <div><span>Cipher Suite:</span> <strong style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{sslInfo.cipher_suite || 'N/A'}</strong></div>
                <div><span>SHA256 Fingerprint:</span> <strong style={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{sslInfo.sha256_fingerprint || 'N/A'}</strong></div>
                <div><span>Issuer Org:</span> <strong>{sslInfo.issuer_org || sslInfo.issuer_cn || 'N/A'}</strong></div>
                <div><span>Subject CN:</span> <strong>{sslInfo.subject_cn || 'N/A'}</strong></div>
                <div><span>Valid Period:</span> <strong style={{ fontSize: '0.75rem' }}>{sslInfo.valid_from} → {sslInfo.valid_to}</strong></div>
              </div>
            </div>
          )}

          {/* Weighted Threat Intelligence Assessment */}
          <div className="stat-card cyber-panel" style={{ borderLeft: `4px solid ${riskColor}` }}>
            <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
            <h4 style={{ color: riskColor }}>WEIGHTED SECURITY RISK REASONS ({threat.reasons ? threat.reasons.length : 0})</h4>
            <ul style={{ marginTop: '0.5rem', paddingLeft: '1.2rem', color: 'var(--text-main)' }}>
              {threat.reasons && threat.reasons.map((reason, idx) => (
                <li key={idx} style={{ margin: '0.35rem 0', fontSize: '0.85rem' }}>
                  <span style={{ color: riskColor, fontWeight: 'bold', marginRight: '0.4rem' }}>&gt;</span>
                  {reason}
                </li>
              ))}
            </ul>
          </div>
        </div>
      );
    }

    case 'brute': {
      const solved = data.success === true || data.status === 'Success';
      return (
        <div className="report-brute">
          <div className="stat-card cyber-panel" style={{
            borderLeft: `4px solid ${solved ? '#10b981' : '#ef4444'}`,
            backgroundColor: solved ? 'rgba(16, 185, 129, 0.03)' : 'rgba(239, 68, 68, 0.03)'
          }}>
            <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
            <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>

            <h4 style={{ color: solved ? '#10b981' : '#ef4444', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              {solved ? <CheckCircle size={18} /> : <AlertTriangle size={18} />}
              CRACK STATUS: {solved ? 'KEY RESOLVED' : 'DICTIONARY EXHAUSTED'}
            </h4>

            <div className="profile-grid" style={{ marginTop: '1rem', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))' }}>
              <div><span>Target node:</span> <strong>{data.target || 'N/A'}</strong></div>
              <div><span>Attempts tried:</span> <strong>{data.attempts_tried || data.attempts || 0}</strong></div>
              {data.username && <div><span>Username node:</span> <strong>{data.username}</strong></div>}
              {solved && data.password && (
                <div style={{ gridColumn: 'span 2', background: 'rgba(16,185,129,0.1)', padding: '0.5rem', borderRadius: '0.25rem', marginTop: '0.5rem' }}>
                  <span style={{ color: '#10b981' }}>Decrypted Password Key:</span>{' '}
                  <strong style={{ fontSize: '1.2rem', color: '#fff', marginLeft: '0.5rem', fontFamily: 'monospace' }}>{data.password}</strong>
                </div>
              )}
            </div>
          </div>
        </div>
      );
    }

    case 'autopsy': {
      // Dedicated view for deleted_files scan results
      const deletedFiles = data.deleted_files || [];
      const summary = data.summary || {};
      const byExt = summary.by_extension || {};
      const hasDeletedResults = deletedFiles.length > 0;

      // Fallback for non-deleted_files modes (partitions, fls, timeline, etc.)
      if (!data.deleted_files && !data.deleted_files_found && data.deleted_files_found !== 0) {
        // Render generic for mmls/fsstat/fls/timeline modes
        const keys = Object.keys(data);
        if (keys.length === 0) return <p style={{ color: 'var(--text-muted)' }}>No data returned.</p>;
        return (
          <div className="report-generic">
            <h4>DISK ANALYSIS RESULTS</h4>
            <div className="metadata-table-wrapper" style={{ marginTop: '1rem' }}>
              <table className="metadata-table">
                <thead><tr><th>FIELD</th><th>VALUE</th></tr></thead>
                <tbody>
                  {keys.map(k => (
                    <tr key={k}>
                      <td className="prop-name">{k.replace(/_/g, ' ').toUpperCase()}</td>
                      <td className="prop-val">
                        {typeof data[k] === 'object' ? (
                          <pre style={{ fontFamily: 'monospace', color: '#a5b4fc', fontSize: '0.75rem', margin: 0 }}>
                            {JSON.stringify(data[k], null, 2)}
                          </pre>
                        ) : String(data[k])}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      }

      return (
        <div className="report-deleted-files">
          {/* Summary Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            <div className="stat-card cyber-panel" style={{ padding: '1.2rem', textAlign: 'center' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#ef4444' }}>{data.deleted_files_found || 0}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.3rem', fontFamily: 'monospace' }}>DELETED FILES FOUND</div>
            </div>
            <div className="stat-card cyber-panel" style={{ padding: '1.2rem', textAlign: 'center' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <div style={{ fontSize: '2rem', fontWeight: 'bold', color: 'var(--primary)' }}>{data.total_files_scanned || 0}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.3rem', fontFamily: 'monospace' }}>TOTAL FILES SCANNED</div>
            </div>
            <div className="stat-card cyber-panel" style={{ padding: '1.2rem', textAlign: 'center' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <div style={{ fontSize: '1.6rem', fontWeight: 'bold', color: '#f59e0b' }}>{summary.total_deleted_size || '0 B'}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.3rem', fontFamily: 'monospace' }}>RECOVERABLE DATA</div>
            </div>
            <div className="stat-card cyber-panel" style={{ padding: '1.2rem', textAlign: 'center' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#a78bfa', fontFamily: 'monospace' }}>{data.drive || '?'}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.3rem', fontFamily: 'monospace' }}>TARGET DRIVE</div>
            </div>
          </div>

          {/* Extension Breakdown */}
          {Object.keys(byExt).length > 0 && (
            <div className="cyber-panel" style={{ padding: '1rem', marginBottom: '1.5rem' }}>
              <div className="cyber-corner-tl"></div><div className="cyber-corner-tr"></div>
              <div className="cyber-corner-bl"></div><div className="cyber-corner-br"></div>
              <h4 style={{ margin: '0 0 0.75rem 0', fontSize: '0.8rem', color: 'var(--primary)', fontFamily: 'monospace' }}>DELETED FILE TYPES</h4>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {Object.entries(byExt).sort((a, b) => b[1] - a[1]).map(([ext, count]) => (
                  <span key={ext} style={{
                    padding: '0.3rem 0.7rem',
                    borderRadius: '4px',
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    color: '#fca5a5',
                    fontSize: '0.72rem',
                    fontFamily: 'monospace',
                  }}>{ext} × {count}</span>
                ))}
              </div>
            </div>
          )}

          {/* Deleted Files Table */}
          {hasDeletedResults ? (
            <div className="metadata-table-wrapper">
              <table className="metadata-table">
                <thead>
                  <tr>
                    <th>FILE NAME</th>
                    <th>PATH</th>
                    <th>INODE</th>
                    <th>SIZE</th>
                    <th>TYPE</th>
                    <th>RECOVER</th>
                  </tr>
                </thead>
                <tbody>
                  {deletedFiles.map((f, i) => (
                    <tr key={i} style={{ background: i % 2 === 0 ? 'rgba(239,68,68,0.04)' : 'transparent' }}>
                      <td className="prop-name" style={{ color: '#fca5a5' }}>
                        {f.is_deleted ? '🗑️ ' : ''}{f.name}
                      </td>
                      <td className="prop-val" style={{ fontSize: '0.7rem', maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.path}</td>
                      <td className="prop-val" style={{ fontFamily: 'monospace', color: '#a78bfa' }}>{f.inode}</td>
                      <td className="prop-val" style={{ fontFamily: 'monospace' }}>
                        {f.size >= 1048576 ? `${(f.size / 1048576).toFixed(1)} MB` :
                         f.size >= 1024 ? `${(f.size / 1024).toFixed(1)} KB` :
                         `${f.size} B`}
                      </td>
                      <td className="prop-val">
                        <span style={{
                          padding: '0.15rem 0.4rem',
                          borderRadius: '3px',
                          fontSize: '0.65rem',
                          background: f.extension === '.exe' || f.extension === '.bat' || f.extension === '.sh' ? 'rgba(239,68,68,0.2)' : 'rgba(99,102,241,0.15)',
                          color: f.extension === '.exe' || f.extension === '.bat' || f.extension === '.sh' ? '#fca5a5' : '#a5b4fc',
                          fontFamily: 'monospace',
                        }}>{f.extension || f.type}</span>
                      </td>
                      <td>
                        <button
                          onClick={async () => {
                            try {
                              const res = await axios.post(`${apiBase}/analyze/autopsy/recover`, {
                                drive_path: data.target_folder,
                                inode: f.inode,
                                output_name: f.name
                              });
                              const r = res.data?.results;
                              if (r?.status === 'Recovered') {
                                alert(`✅ Recovered!\n\nFile: ${r.output_file}\nSize: ${r.size_bytes} bytes\nSHA-256: ${r.sha256}`);
                              } else {
                                alert(`⚠️ ${r?.message || r?.error || 'Recovery failed'}`);
                              }
                            } catch (err) {
                              alert(`❌ Recovery error: ${err.response?.data?.detail || err.message}`);
                            }
                          }}
                          style={{
                            padding: '0.25rem 0.65rem',
                            fontSize: '0.7rem',
                            fontFamily: 'monospace',
                            borderRadius: '4px',
                            border: '1px solid rgba(16, 185, 129, 0.4)',
                            background: 'rgba(16, 185, 129, 0.12)',
                            color: '#6ee7b7',
                            cursor: 'pointer',
                            transition: 'all 0.15s',
                          }}
                          onMouseEnter={e => { e.target.style.background = 'rgba(16, 185, 129, 0.3)'; }}
                          onMouseLeave={e => { e.target.style.background = 'rgba(16, 185, 129, 0.12)'; }}
                        >⬇ Recover</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {data.notice && (
                <div style={{ padding: '0.75rem', fontSize: '0.72rem', color: '#f59e0b', fontFamily: 'monospace', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  ⚠ {data.notice}
                </div>
              )}
            </div>
          ) : (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>✅</div>
              No deleted files found in the scanned area.
            </div>
          )}
        </div>
      );
    }

    default: {
      const keys = Object.keys(data);
      if (keys.length === 0) return <p style={{ color: 'var(--text-muted)' }}>No parseable data fields resolved by engine.</p>;

      return (
        <div className="report-generic">
          <h4>PARSED PROPERTIES</h4>
          <div className="metadata-table-wrapper" style={{ marginTop: '1rem' }}>
            <table className="metadata-table">
              <thead>
                <tr>
                  <th>FIELD</th>
                  <th>VALUE</th>
                </tr>
              </thead>
              <tbody>
                {keys.map(k => (
                  <tr key={k}>
                    <td className="prop-name">{k.replace(/_/g, ' ').toUpperCase()}</td>
                    <td className="prop-val">
                      {typeof data[k] === 'object' ? (
                        <pre style={{ fontFamily: 'monospace', color: '#a5b4fc', fontSize: '0.75rem', margin: 0 }}>
                          {JSON.stringify(data[k], null, 2)}
                        </pre>
                      ) : (
                        String(data[k])
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      );
    }
  }
}

export default App;
