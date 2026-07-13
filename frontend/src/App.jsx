import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Shield, FileText, Camera, HardDrive, Activity, Search, Upload, Play,
  Terminal, Cpu, Smartphone, Globe, Network, Mail, List, Image, Key, Zap,
  ChevronDown, ChevronRight, Folder, FolderOpen, RefreshCw, AlertTriangle, CheckCircle, Info,
  Eye, FileCode, Server
} from 'lucide-react';

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
  const [resultSubTab, setResultSubTab] = useState('dashboard'); // 'dashboard' | 'json'

  // Search and Collapsible Category State
  const [sidebarSearch, setSidebarSearch] = useState('');
  const [expandedCategories, setExpandedCategories] = useState({
    static: true,
    deep: true,
    mobile: true,
    logs: true
  });

  // ExifTool result filter state
  const [metadataSearch, setMetadataSearch] = useState('');

  // Interactive CLI loader state
  const [loaderMessage, setLoaderMessage] = useState('');
  const [loaderSteps, setLoaderSteps] = useState([]);

  const toggleCategory = (cat) => {
    setExpandedCategories(prev => ({ ...prev, [cat]: !prev[cat] }));
  };

  // Grouped Menu Items (Reintegrated Androguard APK Static Analysis)
  const categories = [
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

  // Dynamic console output generator during loading
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
      let payload = { file_path: filePath };

      if (activeTab === 'exiftool') endpoint = '/analyze/exiftool';
      if (activeTab === 'yara') {
        endpoint = '/analyze/yara';
        payload.rules_path = rulesPath;
      }
      if (activeTab === 'androguard') endpoint = '/analyze/androguard';
      if (activeTab === 'autopsy') {
        endpoint = '/analyze/autopsy';
        payload = { image_path: filePath, scan_type: sleuthkitScanType };
      }
      if (activeTab === 'ghidra') {
        endpoint = '/analyze/ghidra';
        payload.extract_code = true;
      }
      if (activeTab === 'mobsf') endpoint = '/analyze/mobsf';

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
        payload = {
          file_path: filePath, // Just to satisfy generic payload structure if needed, though backend looks at target
          mode: bruteMode,
          target: filePath,
          username: bruteUsername,
          username_field: bruteUsernameField,
          password_field: brutePasswordField,
          failure_string: bruteFailureStr,
          max_attempts: parseInt(bruteMaxAttempts) || 1000,
          port: brutePort ? parseInt(brutePort) : null,
        };
        endpoint = '/analyze/brute';
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

  // Filter sidebar based on search query
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

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="cyber-corner-tl"></div>
        <div className="cyber-corner-bl"></div>

        <div className="logo glowing-text">
          <Shield size={26} color="#00f0ff" />
          <span>CYBERX // SOC</span>
        </div>

        <div className="system-subtitle">
          <span>SEC-OPS // TERMINAL DEPLOYMENT</span>
        </div>

        {/* Sidebar Search */}
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
              <span>LEVEL: 4 // SECURED</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {/* Header */}
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

        {/* Input Panel */}
        <section className="cyber-panel animate-fade-in" style={{ animationDelay: '0.1s' }}>
          <div className="cyber-corner-tl"></div>
          <div className="cyber-corner-tr"></div>
          <div className="cyber-corner-bl"></div>
          <div className="cyber-corner-br"></div>

          <div className="form-title">
            <Server size={18} style={{ color: 'var(--primary)' }} />
            <h2>Investigation Setup // Target Parameters</h2>
          </div>

          <div className="setup-grid">
            <div className="input-block">
              <label>Absolute File/Target Path</label>
              <input
                type="text"
                className="input-field cyber-input"
                placeholder={
                  activeTab === 'autopsy' ? "/path/to/evidence/image.dd or .E01" :
                    activeTab === 'ghidra' ? "/path/to/malware/sample.exe" :
                      activeTab === 'mobsf' || activeTab === 'androguard' ? "/path/to/mobile/app.apk" :
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

            {/* Dynamic Inputs Based on Active Tool */}
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
                </select>
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
          </div>
        </section>

        {/* Loading Terminal Animation */}
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
              <span className="terminal-title">SYS-OPS // ANOMALY_ANALYZER.EXE</span>
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

        {/* Results Section */}
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

            {/* Verdict Alert banner */}
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

            {/* Sub-Tab 1: Interactive Dashboard */}
            {resultSubTab === 'dashboard' && (
              <div className="interactive-report-container animate-fade-in">
                {renderInteractiveReport(activeTab, results.results, metadataSearch, setMetadataSearch, API_BASE)}
              </div>
            )}

            {/* Sub-Tab 2: Raw JSON view */}
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
    </div>
  );
}

// ── CUSTOM INTERACTIVE REPORT BUILDER ──────────────────────────────────────────
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
            {/* Score Ring */}
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

            {/* Profile */}
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

            {/* Component Counts */}
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
            {/* Threat Flags */}
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

            {/* Permissions list */}
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

    case 'ghidra': {
      return (
        <div className="report-generic">
          <div className="profile-header" style={{ marginBottom: '1.5rem', borderBottom: '1px solid rgba(0, 240, 255, 0.2)', paddingBottom: '1rem' }}>
            <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--primary)' }}>
              <Cpu size={18} />
              GHIDRA REVERSE ENGINEERING
            </h4>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem' }}>
              <span className="badge warning">{data.metadata?.format || 'Unknown Format'}</span>
              <span className="badge">{data.metadata?.architecture || 'Unknown Arch'}</span>
              <span className="badge">Functions: {data.functions_count || 0}</span>
            </div>
          </div>
          
          {data.decompiled_code ? (
            <div className="code-block-wrapper" style={{ marginTop: '1rem' }}>
              <h5 style={{ color: '#a5b4fc', marginBottom: '0.5rem' }}>Decompiled C-Code Snippets</h5>
              <pre style={{ 
                background: '#0a0a0a', 
                padding: '1rem', 
                borderRadius: '4px', 
                border: '1px solid #333',
                maxHeight: '600px',
                overflow: 'auto',
                color: '#10b981',
                fontFamily: 'monospace',
                fontSize: '0.85rem',
                whiteSpace: 'pre-wrap'
              }}>
                {data.decompiled_code}
              </pre>
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)' }}>No decompiled code extracted.</p>
          )}

          {data.functions && data.functions.length > 0 && (
            <div style={{ marginTop: '2rem' }}>
              <h5 style={{ color: '#a5b4fc', marginBottom: '0.5rem' }}>Extracted Functions (Top 100)</h5>
              <div className="metadata-table-wrapper">
                <table className="metadata-table">
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>Name</th>
                      <th>Signature</th>
                      <th>Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.functions.map((f, i) => (
                      <tr key={i}>
                        <td className="prop-name" style={{ fontFamily: 'monospace' }}>{f.address}</td>
                        <td className="prop-val">{f.name}</td>
                        <td className="prop-val" style={{ fontSize: '0.75rem', color: '#9ca3af', fontFamily: 'monospace' }}>{f.signature}</td>
                        <td className="prop-val">{f.size} bytes</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      );
    }

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
            {/* SVG Score Circle */}
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

            {/* App Profile */}
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
                <div><span>App Size:</span> <strong>{mSummary.size ? (mSummary.size / (1024 * 1024)).toFixed(2) + ' MB' : 'N/A'}</strong></div>
              </div>
              {data.pdf_report_url && (
                <div style={{ marginTop: '1.25rem' }}>
                  <a href={`${apiBase}${data.pdf_report_url}`} target="_blank" rel="noopener noreferrer" className="btn btn-pdf" style={{ width: '100%', justifyContent: 'center' }}>
                    <FileText size={16} /> Open Full PDF Forensic Report
                  </a>
                </div>
              )}
            </div>

            {/* Component Count Card */}
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
            {/* Risk Breakdown progress bars */}
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

            {/* Findings list */}
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
                <h3 style={{ color: '#ef4444', margin: '0 0 0.5rem 0', textShadow: '0 0 10px rgba(239, 68, 68, 0.5)' }}>LOCAL HEURISTICS // {lh.risk_level} RISK DETECTED</h3>
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
                <h4>GOOGLE SAFE BROWSING // SITE DIAGNOSTICS</h4>
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
