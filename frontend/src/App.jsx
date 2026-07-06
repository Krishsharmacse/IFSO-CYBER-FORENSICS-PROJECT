import React, { useState } from 'react';
import axios from 'axios';
import { Shield, FileText, Camera, HardDrive, Activity, Search, Upload, Play, Terminal, Cpu, Smartphone } from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000';

function App() {
  const [activeTab, setActiveTab] = useState('exiftool');
  const [filePath, setFilePath] = useState('');
  const [rulesPath, setRulesPath] = useState('');
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
         payload = { image_path: filePath };
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

      const res = await axios.post(`${API_BASE}${endpoint}`, payload);
      setResults(res.data);
    } catch (err) {
      setResults({ status: 'Failed', results: { error: err.message } });
    } finally {
      setLoading(false);
    }
  };

  const menuItems = [
    { id: 'exiftool', label: 'Metadata (ExifTool)', icon: Camera },
    { id: 'yara', label: 'Malware Scan (YARA)', icon: Activity },
    { id: 'autopsy', label: 'Disk Forensics (Autopsy)', icon: HardDrive },
    { id: 'ghidra', label: 'Reverse Engineering (Ghidra)', icon: Cpu },
    { id: 'androguard', label: 'APK Analysis (Androguard)', icon: Smartphone },
    { id: 'mobsf', label: 'Deep Mobile Scan (MobSF)', icon: Smartphone },
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
          {menuItems.map(item => {
            const Icon = item.icon;
            return (
              <div 
                key={item.id}
                className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
                onClick={() => { setActiveTab(item.id); setResults(null); }}
              >
                <Icon size={20} />
                <span>{item.label}</span>
              </div>
            );
          })}
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="header animate-fade-in">
          <h1>{menuItems.find(i => i.id === activeTab)?.label}</h1>
          <p>Run automated forensic analysis on your artifacts.</p>
        </header>

        <section className="glass-panel animate-fade-in" style={{ animationDelay: '0.1s' }}>
          <div className="upload-section">
            <Upload className="upload-icon" />
            <h2>Target Artifact Setup</h2>
            <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>
              Provide the absolute path to the file or image on your server.
            </p>
            
            <div className="file-input-wrapper">
              <input 
                type="text" 
                className="input-field" 
                placeholder={
                  activeTab === 'autopsy' ? "/path/to/evidence/image.dd" : 
                  activeTab === 'ghidra' ? "/path/to/malware/sample.exe" :
                  (activeTab === 'androguard' || activeTab === 'mobsf') ? "/path/to/mobile/app.apk" :
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
                border: `1px solid ${
                                 results.results.analysis_verdict === 'MALICIOUS' ? '#ef4444' : 
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
