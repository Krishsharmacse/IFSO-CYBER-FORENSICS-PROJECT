import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Briefcase, Plus, Folder, Hash, Clock, FileText, 
  CheckCircle, Shield, AlertTriangle, RefreshCw
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

const CaseManagement = ({ setActiveCaseGlobal }) => {
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [loading, setLoading] = useState(false);
  const [view, setView] = useState('list'); // 'list' | 'detail' | 'create'
  
  // Create Form State
  const [newCase, setNewCase] = useState({ case_id_str: '', title: '', investigator_name: '', description: '' });
  
  // Evidence Form State
  const [evidencePath, setEvidencePath] = useState('');
  
  useEffect(() => {
    fetchCases();
  }, []);

  const fetchCases = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/cases`);
      setCases(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadCaseDetails = async (id) => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/cases/${id}`);
      setSelectedCase(res.data);
      setActiveCaseGlobal(id); // Set the global active case in App.jsx
      setView('detail');
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCase = async () => {
    if(!newCase.case_id_str || !newCase.title || !newCase.investigator_name) return;
    try {
      await axios.post(`${API_BASE}/cases`, newCase);
      setView('list');
      fetchCases();
      setNewCase({ case_id_str: '', title: '', investigator_name: '', description: '' });
    } catch (err) {
      alert("Failed to create case");
    }
  };

  const handleAddEvidence = async () => {
    if(!evidencePath || !selectedCase) return;
    setLoading(true);
    try {
      await axios.post(`${API_BASE}/cases/${selectedCase.case.id}/evidence`, { file_path: evidencePath });
      setEvidencePath('');
      loadCaseDetails(selectedCase.case.id);
    } catch (err) {
      alert("Failed to add evidence. Make sure the absolute path is correct.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cyber-panel animate-fade-in" style={{ minHeight: '80vh', overflowY: 'auto' }}>
      <div className="cyber-corner-tl"></div>
      <div className="cyber-corner-tr"></div>
      <div className="cyber-corner-bl"></div>
      <div className="cyber-corner-br"></div>

      <div className="results-header" style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Briefcase size={22} style={{ color: 'var(--primary)' }} />
          <h2>INVESTIGATION CASE MANAGEMENT</h2>
        </div>
        <div>
          {view === 'detail' && (
            <button className="btn btn-secondary" onClick={() => setView('list')} style={{ marginRight: '1rem' }}>
              Back to Cases
            </button>
          )}
          {view === 'list' && (
            <button className="btn btn-primary btn-cyber" onClick={() => setView('create')}>
              <Plus size={16} /> NEW CASE
            </button>
          )}
        </div>
      </div>

      {loading && <div style={{ color: 'var(--primary)', marginBottom: '1rem' }}><RefreshCw className="animate-spin" size={16} /> Syncing Data...</div>}

      {/* LIST VIEW */}
      {view === 'list' && (
        <div className="grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          {cases.map(c => (
            <div 
              key={c.id} 
              className="stat-card" 
              style={{ cursor: 'pointer', transition: 'all 0.2s' }}
              onClick={() => loadCaseDetails(c.id)}
            >
              <div className="stat-icon"><Folder size={20} /></div>
              <div className="stat-info">
                <div className="stat-value" style={{ fontSize: '1.1rem' }}>{c.case_id_str}</div>
                <div className="stat-label">{c.title}</div>
                <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Investigator: {c.investigator_name} | Status: <span style={{ color: c.status === 'Open' ? 'var(--accent)' : 'var(--success)' }}>{c.status}</span>
                </div>
              </div>
            </div>
          ))}
          {cases.length === 0 && !loading && <div style={{ color: 'var(--text-muted)' }}>No cases found. Create one to begin.</div>}
        </div>
      )}

      {/* CREATE VIEW */}
      {view === 'create' && (
        <div className="setup-grid" style={{ maxWidth: '600px' }}>
          <div className="input-block">
            <label>Case ID</label>
            <input className="input-field cyber-input" type="text" placeholder="CYB-2026-001" value={newCase.case_id_str} onChange={e => setNewCase({...newCase, case_id_str: e.target.value})} />
          </div>
          <div className="input-block">
            <label>Case Title</label>
            <input className="input-field cyber-input" type="text" placeholder="Operation Midnight" value={newCase.title} onChange={e => setNewCase({...newCase, title: e.target.value})} />
          </div>
          <div className="input-block">
            <label>Investigator Name</label>
            <input className="input-field cyber-input" type="text" placeholder="Agent Smith" value={newCase.investigator_name} onChange={e => setNewCase({...newCase, investigator_name: e.target.value})} />
          </div>
          <div className="input-block">
            <label>Description</label>
            <textarea className="input-field cyber-input" rows="4" placeholder="Brief description of the incident..." value={newCase.description} onChange={e => setNewCase({...newCase, description: e.target.value})}></textarea>
          </div>
          <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
            <button className="btn btn-primary btn-cyber" onClick={handleCreateCase}>CREATE CASE</button>
            <button className="btn btn-secondary" onClick={() => setView('list')}>CANCEL</button>
          </div>
        </div>
      )}

      {/* DETAIL VIEW */}
      {view === 'detail' && selectedCase && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
            {/* Case Info */}
            <div style={{ background: 'rgba(0, 0, 0, 0.2)', padding: '1.5rem', borderRadius: '4px', border: '1px solid rgba(0,240,255,0.1)' }}>
              <h3 style={{ color: 'var(--primary)', marginBottom: '0.5rem', fontSize: '1.3rem' }}>{selectedCase.case.case_id_str} : {selectedCase.case.title}</h3>
              <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>{selectedCase.case.description}</p>
              
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div><strong>Investigator:</strong> {selectedCase.case.investigator_name}</div>
                <div><strong>Status:</strong> {selectedCase.case.status}</div>
                <div><strong>Created:</strong> {new Date(selectedCase.case.created_at).toLocaleString()}</div>
                <div><strong>Last Updated:</strong> {new Date(selectedCase.case.updated_at).toLocaleString()}</div>
              </div>
            </div>

            {/* Add Evidence */}
            <div style={{ background: 'rgba(0, 0, 0, 0.2)', padding: '1.5rem', borderRadius: '4px', border: '1px solid rgba(0,240,255,0.1)' }}>
              <h4 style={{ color: 'var(--primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Shield size={16}/> ATTACH EVIDENCE
              </h4>
              <div className="input-block" style={{ marginBottom: '1rem' }}>
                <label>Absolute File Path</label>
                <input 
                  className="input-field cyber-input" 
                  type="text" 
                  placeholder="C:\evidence\suspect.dd" 
                  value={evidencePath} 
                  onChange={e => setEvidencePath(e.target.value)} 
                />
              </div>
              <button className="btn btn-primary btn-cyber" onClick={handleAddEvidence} disabled={loading || !evidencePath} style={{ width: '100%' }}>
                <Hash size={14}/> COMPUTE & ATTACH
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            {/* Evidence List */}
            <div>
              <h4 style={{ color: 'var(--primary)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem', borderBottom: '1px solid rgba(0,240,255,0.1)', paddingBottom: '0.5rem' }}>
                <Folder size={18} /> LOGGED EVIDENCE ({selectedCase.evidence.length})
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {selectedCase.evidence.length === 0 && <span style={{color: 'var(--text-muted)'}}>No evidence attached yet.</span>}
                {selectedCase.evidence.map(ev => (
                  <div key={ev.id} style={{ background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '4px', borderLeft: '3px solid var(--primary)' }}>
                    <div style={{ fontWeight: 'bold', marginBottom: '0.5rem', wordBreak: 'break-all' }}>{ev.file_path}</div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}><CheckCircle size={12} color="var(--success)"/> MD5: {ev.hash_md5}</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.2rem' }}><CheckCircle size={12} color="var(--success)"/> SHA256: {ev.hash_sha256}</div>
                      <div style={{ marginTop: '0.5rem' }}>Logged: {new Date(ev.upload_time).toLocaleString()}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Analysis Timeline */}
            <div>
              <h4 style={{ color: 'var(--accent)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem', borderBottom: '1px solid rgba(255,0,85,0.1)', paddingBottom: '0.5rem' }}>
                <Clock size={18} /> ANALYSIS TIMELINE ({selectedCase.history.length})
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '500px', overflowY: 'auto', paddingRight: '0.5rem' }}>
                {selectedCase.history.length === 0 && <span style={{color: 'var(--text-muted)'}}>No analysis history recorded for this case. Ensure this case is active when running tools.</span>}
                {selectedCase.history.map(hist => (
                  <div key={hist.id} style={{ background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '4px', borderLeft: '3px solid var(--accent)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                      <strong style={{ color: 'var(--accent)', textTransform: 'uppercase' }}>{hist.tool_used}</strong>
                      <span style={{ fontSize: '0.75rem', padding: '0.1rem 0.4rem', background: hist.status === 'Completed' || hist.status === 'Success' ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255,0,85,0.1)', color: hist.status === 'Completed' || hist.status === 'Success' ? 'var(--success)' : 'var(--accent)', borderRadius: '3px' }}>
                        {hist.status}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.85rem', wordBreak: 'break-all', marginBottom: '0.5rem' }}>{hist.filename}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{new Date(hist.created_at).toLocaleString()}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CaseManagement;
