import React, { useState, useRef, useEffect, useCallback } from 'react';
import { X, Send, Bot, User, Trash2, Copy, CheckCheck, Minimize2, Maximize2, Code, Zap } from 'lucide-react';


const SYSTEM_PROMPT = `You are CyberX AI — an elite cybersecurity and coding intelligence assistant embedded in a professional digital forensics platform. You are knowledgeable about:

Cybersecurity: digital forensics, malware analysis, YARA rules, threat intelligence, OSINT, IOC analysis, penetration testing, CTF challenges, cryptography, hash cracking, steganography, network security, PCAP analysis, APK/mobile security, Windows/Linux security, registry analysis, event logs, incident response, threat hunting.

Coding: Python, JavaScript, C/C++, Go, Rust, Bash/PowerShell, security scripting, automation, API integrations, algorithms, debugging, DevSecOps.

Format code with triple backticks and language name. Be precise and technically detailed. Redirect illegal hacking questions to ethical/defensive alternatives.`;

function CodeBlock({ code, lang }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  return (
    <div className="cc-code-block">
      <div className="cc-code-header">
        <span className="cc-code-lang"><Code size={11} /> {lang || 'code'}</span>
        <button className="cc-code-copy" onClick={handleCopy}>
          {copied ? <><CheckCheck size={11} /> Copied!</> : <><Copy size={11} /> Copy</>}
        </button>
      </div>
      <pre className="cc-code-pre"><code>{code}</code></pre>
    </div>
  );
}

function renderInline(text) {
  if (!text) return text;
  return text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={idx} style={{ color: '#00f0ff', fontWeight: 600 }}>{part.slice(2, -2)}</strong>;
    if (part.startsWith('`') && part.endsWith('`')) return <code key={idx} className="cc-inline-code">{part.slice(1, -1)}</code>;
    return part;
  });
}

function renderContent(text) {
  if (!text) return null;
  const lines = text.split('\n');
  const elements = [];
  let inCode = false, codeLang = '', codeLines = [];
  lines.forEach((line, i) => {
    if (line.startsWith('```')) {
      if (!inCode) { inCode = true; codeLang = line.slice(3).trim(); codeLines = []; }
      else { elements.push(<CodeBlock key={i} code={codeLines.join('\n')} lang={codeLang} />); inCode = false; }
    } else if (inCode) {
      codeLines.push(line);
    } else if (line.startsWith('### ')) {
      elements.push(<div key={i} style={{ fontSize: '0.82rem', fontWeight: 700, color: '#00f0ff', margin: '0.5rem 0 0.2rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{line.slice(4)}</div>);
    } else if (line.startsWith('## ')) {
      elements.push(<div key={i} style={{ fontSize: '0.88rem', fontWeight: 700, color: '#a5b4fc', margin: '0.4rem 0 0.2rem' }}>{line.slice(3)}</div>);
    } else if (line.startsWith('- ') || line.startsWith('* ')) {
      elements.push(<div key={i} style={{ display: 'flex', gap: '0.4rem', marginBottom: '0.1rem', paddingLeft: '0.2rem' }}><span style={{ color: '#00f0ff', flexShrink: 0 }}>›</span><span>{renderInline(line.slice(2))}</span></div>);
    } else if (line.trim() === '') {
      elements.push(<div key={i} style={{ height: '0.35rem' }} />);
    } else {
      elements.push(<p key={i} style={{ margin: '0 0 0.2rem', lineHeight: 1.6 }}>{renderInline(line)}</p>);
    }
  });
  if (inCode && codeLines.length > 0) elements.push(<CodeBlock key="last" code={codeLines.join('\n')} lang={codeLang} />);
  return elements;
}

export default function CyberChat() {
  const [isOpen, setIsOpen] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [messages, setMessages] = useState([{
    role: 'assistant', id: 'welcome',
    content: 'CYBERX AI ONLINE.\n\nI am your cybersecurity and coding intelligence assistant. Ask me about:\n\n- **Digital Forensics** — memory, disk, network, APK analysis\n- **Malware Analysis** — YARA rules, reverse engineering, IOCs\n- **Threat Intel** — OSINT, IP reputation, phishing\n- **Coding** — Python, scripting, automation, algorithms\n- **CTF** — exploits, crypto, steganography\n\nHow can I assist your investigation today?'
  }]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const abortRef = useRef(null);

  useEffect(() => { if (isOpen) setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50); }, [messages, isOpen]);
  useEffect(() => { if (isOpen) setTimeout(() => inputRef.current?.focus(), 150); }, [isOpen]);

  const sendMessage = useCallback(async () => {
    const trimmed = input.trim();
    if (!trimmed || isLoading) return;
    const userMsg = { role: 'user', content: trimmed, id: Date.now().toString() };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput('');
    setIsLoading(true);
    setError(null);
    const aId = (Date.now() + 1).toString();
    setMessages(prev => [...prev, { role: 'assistant', content: '', id: aId, streaming: true }]);
    try {
      abortRef.current = new AbortController();
      const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${OPENROUTER_API_KEY}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'http://localhost:5173', 'X-Title': 'CyberX Forensics Platform' },
        body: JSON.stringify({ model: OPENROUTER_MODEL, messages: [{ role: 'system', content: SYSTEM_PROMPT }, ...newMessages.map(m => ({ role: m.role, content: m.content }))], stream: true, temperature: 0.7, max_tokens: 2048 }),
        signal: abortRef.current.signal
      });
      if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error?.message || `API ${res.status}`); }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let acc = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        for (const line of chunk.split('\n')) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6).trim();
            if (data === '[DONE]') continue;
            try { const p = JSON.parse(data); const d = p.choices?.[0]?.delta?.content || ''; if (d) { acc += d; setMessages(prev => prev.map(m => m.id === aId ? { ...m, content: acc } : m)); } } catch (_) { }
          }
        }
      }
      setMessages(prev => prev.map(m => m.id === aId ? { ...m, streaming: false } : m));
    } catch (err) {
      if (err.name === 'AbortError') return;
      setError(err.message || 'Connection failed.');
      setMessages(prev => prev.filter(m => m.id !== aId));
    } finally { setIsLoading(false); }
  }, [input, messages, isLoading]);

  const handleKeyDown = (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } };

  const clearChat = () => {
    if (isLoading && abortRef.current) abortRef.current.abort();
    setMessages([{ role: 'assistant', content: 'Chat cleared. How can I assist?', id: 'reset' }]);
    setIsLoading(false); setError(null);
  };

  const copyMsg = (id, content) => { navigator.clipboard.writeText(content); setCopiedId(id); setTimeout(() => setCopiedId(null), 2000); };

  const quickPrompts = ['Explain YARA rule syntax', 'How to analyze a memory dump?', 'Write a Python port scanner', 'What is APK static analysis?', 'Explain steganography detection', 'How does phishing detection work?'];

  const btnStyle = (active) => ({
    width: '28px', height: '28px', borderRadius: '5px', background: 'transparent',
    border: '1px solid rgba(0,240,255,0.1)', color: '#64748b', cursor: 'pointer',
    display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 0.2s',
    ...(active ? { borderColor: 'rgba(0,240,255,0.4)', color: '#00f0ff' } : {})
  });

  return (
    <>
      {/* FAB */}
      <button id="cyber-chat-fab" onClick={() => setIsOpen(o => !o)} title="CyberX AI" style={{
        position: 'fixed', bottom: '1.75rem', right: '1.75rem', zIndex: 9990, width: '54px', height: '54px',
        borderRadius: '50%', background: isOpen ? 'rgba(239,68,68,0.12)' : 'linear-gradient(135deg,rgba(0,240,255,0.18),rgba(139,92,246,0.18))',
        border: `2px solid ${isOpen ? 'rgba(239,68,68,0.55)' : 'rgba(0,240,255,0.55)'}`,
        color: isOpen ? '#ef4444' : '#00f0ff', cursor: 'pointer', display: 'flex', alignItems: 'center',
        justifyContent: 'center', backdropFilter: 'blur(10px)', flexDirection: 'column', gap: '2px',
        boxShadow: isOpen ? '0 0 20px rgba(239,68,68,0.25)' : '0 0 28px rgba(0,240,255,0.3),0 4px 20px rgba(0,0,0,0.4)',
        transition: 'all 0.3s ease'
      }}>
        {isOpen ? <X size={20} /> : <Bot size={20} />}
        {!isOpen && <span style={{ fontSize: '8px', fontFamily: 'monospace', color: '#00f0ff', fontWeight: 700, letterSpacing: '0.05em' }}>AI</span>}
        {!isOpen && <span style={{ position: 'absolute', top: '-3px', right: '-3px', width: '12px', height: '12px', borderRadius: '50%', background: '#10b981', border: '2px solid #040712', animation: 'ccPulse 2s infinite' }} />}
      </button>

      {/* Panel */}
      {isOpen && (
        <div id="cyber-chat-panel" style={{
          position: 'fixed', bottom: isExpanded ? 0 : '5.5rem', right: isExpanded ? 0 : '1.75rem',
          width: isExpanded ? '100vw' : '420px', height: isExpanded ? '100vh' : '580px',
          zIndex: 9980, display: 'flex', flexDirection: 'column',
          background: 'rgba(4,8,20,0.97)', border: '1px solid rgba(0,240,255,0.18)',
          borderRadius: isExpanded ? 0 : '1rem', backdropFilter: 'blur(20px)',
          boxShadow: '0 0 60px rgba(0,240,255,0.07),0 25px 50px rgba(0,0,0,0.7)',
          overflow: 'hidden', animation: 'ccSlide 0.25s ease', transition: 'all 0.3s'
        }}>
          {/* Corners */}
          {[['0', '0', 'top', 'left'], ['0', '0', 'top', 'right'], ['0', '0', 'bottom', 'left'], ['0', '0', 'bottom', 'right']].map(([t, r, v, h], i) => (
            <div key={i} style={{
              position: 'absolute', [v]: 0, [h]: 0, width: '12px', height: '12px',
              [`border${v.charAt(0).toUpperCase() + v.slice(1)}`]: '2px solid #00f0ff',
              [`border${h.charAt(0).toUpperCase() + h.slice(1)}`]: '2px solid #00f0ff',
              borderRadius: v === 'top' && h === 'left' ? '2px 0 0 0' : v === 'top' && h === 'right' ? '0 2px 0 0' : v === 'bottom' && h === 'left' ? '0 0 0 2px' : '0 0 2px 0',
              zIndex: 1, pointerEvents: 'none'
            }} />
          ))}

          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.65rem 0.9rem', borderBottom: '1px solid rgba(0,240,255,0.13)', background: 'rgba(0,240,255,0.03)', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'linear-gradient(135deg,rgba(0,240,255,0.18),rgba(139,92,246,0.18))', border: '1px solid rgba(0,240,255,0.35)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#00f0ff' }}>
                <Bot size={16} />
              </div>
              <div>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#00f0ff', letterSpacing: '0.1em', fontFamily: 'monospace' }}>CYBERX AI</div>
                <div style={{ fontSize: '0.62rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: isLoading ? '#f59e0b' : '#10b981', display: 'inline-block', animation: isLoading ? 'ccPulse 1s infinite' : 'none' }} />
                  {isLoading ? 'Generating...' : 'nvidia/nemotron-nano-9b · free'}
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.25rem' }}>
              <button onClick={() => setIsExpanded(e => !e)} title="Expand/Minimize" style={btnStyle(false)} onMouseEnter={e => Object.assign(e.currentTarget.style, { borderColor: 'rgba(0,240,255,0.4)', color: '#00f0ff' })} onMouseLeave={e => Object.assign(e.currentTarget.style, { borderColor: 'rgba(0,240,255,0.1)', color: '#64748b' })}>{isExpanded ? <Minimize2 size={13} /> : <Maximize2 size={13} />}</button>
              <button onClick={clearChat} title="Clear" style={btnStyle(false)} onMouseEnter={e => Object.assign(e.currentTarget.style, { borderColor: 'rgba(0,240,255,0.4)', color: '#00f0ff' })} onMouseLeave={e => Object.assign(e.currentTarget.style, { borderColor: 'rgba(0,240,255,0.1)', color: '#64748b' })}><Trash2 size={13} /></button>
              <button onClick={() => setIsOpen(false)} title="Close" style={btnStyle(false)} onMouseEnter={e => Object.assign(e.currentTarget.style, { borderColor: 'rgba(239,68,68,0.4)', color: '#ef4444' })} onMouseLeave={e => Object.assign(e.currentTarget.style, { borderColor: 'rgba(0,240,255,0.1)', color: '#64748b' })}><X size={13} /></button>
            </div>
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.65rem', scrollbarWidth: 'thin', scrollbarColor: 'rgba(0,240,255,0.15) transparent' }}>
            {messages.map(msg => (
              <div key={msg.id} style={{ display: 'flex', gap: '0.45rem', flexDirection: msg.role === 'user' ? 'row-reverse' : 'row', alignItems: 'flex-start' }}>
                <div style={{ width: '26px', height: '26px', borderRadius: '6px', flexShrink: 0, background: msg.role === 'user' ? 'linear-gradient(135deg,rgba(139,92,246,0.25),rgba(59,130,246,0.25))' : 'linear-gradient(135deg,rgba(0,240,255,0.15),rgba(16,185,129,0.15))', border: `1px solid ${msg.role === 'user' ? 'rgba(139,92,246,0.35)' : 'rgba(0,240,255,0.25)'}`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: msg.role === 'user' ? '#a5b4fc' : '#00f0ff' }}>
                  {msg.role === 'user' ? <User size={12} /> : <Bot size={12} />}
                </div>
                <div style={{ maxWidth: '86%', background: msg.role === 'user' ? 'linear-gradient(135deg,rgba(139,92,246,0.12),rgba(59,130,246,0.08))' : 'rgba(255,255,255,0.025)', border: `1px solid ${msg.role === 'user' ? 'rgba(139,92,246,0.22)' : 'rgba(0,240,255,0.1)'}`, borderRadius: msg.role === 'user' ? '1rem 1rem 0.2rem 1rem' : '1rem 1rem 1rem 0.2rem', padding: '0.55rem 0.75rem', fontSize: '0.78rem', color: '#e2e8f0', lineHeight: 1.65, position: 'relative' }}>
                  {msg.role === 'assistant'
                    ? <div>
                      {renderContent(msg.content)}
                      {msg.streaming && <span style={{ display: 'inline-block', width: '7px', height: '13px', background: '#00f0ff', marginLeft: '2px', verticalAlign: 'middle', animation: 'ccBlink 0.8s infinite' }} />}
                      {!msg.streaming && msg.content && (
                        <button onClick={() => copyMsg(msg.id, msg.content)} style={{ display: 'flex', alignItems: 'center', gap: '3px', marginTop: '0.3rem', padding: '2px 6px', borderRadius: '3px', background: 'transparent', border: '1px solid rgba(0,240,255,0.12)', color: '#475569', cursor: 'pointer', fontSize: '0.62rem', transition: 'all 0.2s' }} onMouseEnter={e => Object.assign(e.currentTarget.style, { color: '#00f0ff', borderColor: 'rgba(0,240,255,0.35)' })} onMouseLeave={e => Object.assign(e.currentTarget.style, { color: '#475569', borderColor: 'rgba(0,240,255,0.12)' })}>
                          {copiedId === msg.id ? <><CheckCheck size={10} /> Copied</> : <><Copy size={10} /> Copy</>}
                        </button>
                      )}
                    </div>
                    : <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{msg.content}</p>
                  }
                </div>
              </div>
            ))}
            {error && (
              <div style={{ background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.28)', borderRadius: '0.45rem', padding: '0.45rem 0.7rem', color: '#ef4444', fontSize: '0.72rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>⚠ {error}</span>
                <button onClick={() => setError(null)} style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: '0.9rem', lineHeight: 1 }}>✕</button>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick prompts */}
          {messages.length <= 1 && (
            <div style={{ padding: '0 0.7rem 0.45rem', display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
              {quickPrompts.map((p, i) => (
                <button key={i} onClick={() => { setInput(p); inputRef.current?.focus(); }} style={{ padding: '0.28rem 0.55rem', borderRadius: '4px', fontSize: '0.66rem', background: 'rgba(0,240,255,0.04)', border: '1px solid rgba(0,240,255,0.13)', color: '#64748b', cursor: 'pointer', fontFamily: 'monospace', transition: 'all 0.2s', display: 'flex', alignItems: 'center', gap: '3px' }} onMouseEnter={e => Object.assign(e.currentTarget.style, { background: 'rgba(0,240,255,0.09)', color: '#00f0ff', borderColor: 'rgba(0,240,255,0.32)' })} onMouseLeave={e => Object.assign(e.currentTarget.style, { background: 'rgba(0,240,255,0.04)', color: '#64748b', borderColor: 'rgba(0,240,255,0.13)' })}>
                  <Zap size={10} /> {p}
                </button>
              ))}
            </div>
          )}

          {/* Input */}
          <div style={{ borderTop: '1px solid rgba(0,240,255,0.1)', padding: '0.6rem 0.75rem', background: 'rgba(0,240,255,0.015)', flexShrink: 0 }}>
            <div style={{ display: 'flex', gap: '0.45rem', alignItems: 'flex-end' }}>
              <textarea ref={inputRef} value={input} onChange={e => { setInput(e.target.value); e.target.style.height = 'auto'; e.target.style.height = Math.min(e.target.scrollHeight, 90) + 'px'; }} onKeyDown={handleKeyDown} placeholder="Ask about cyber forensics or coding..." disabled={isLoading} rows={1}
                style={{ flex: 1, resize: 'none', background: 'rgba(255,255,255,0.035)', border: '1px solid rgba(0,240,255,0.18)', borderRadius: '0.45rem', padding: '0.48rem 0.7rem', color: '#e2e8f0', fontSize: '0.78rem', fontFamily: 'inherit', lineHeight: 1.55, outline: 'none', maxHeight: '90px', overflowY: 'auto', scrollbarWidth: 'thin', transition: 'border-color 0.2s' }}
                onFocus={e => e.target.style.borderColor = 'rgba(0,240,255,0.48)'} onBlur={e => e.target.style.borderColor = 'rgba(0,240,255,0.18)'} />
              <button onClick={sendMessage} disabled={!input.trim() || isLoading} style={{ width: '36px', height: '36px', borderRadius: '8px', flexShrink: 0, background: !input.trim() || isLoading ? 'rgba(0,240,255,0.04)' : 'linear-gradient(135deg,rgba(0,240,255,0.18),rgba(139,92,246,0.18))', border: `1px solid ${!input.trim() || isLoading ? 'rgba(0,240,255,0.08)' : 'rgba(0,240,255,0.48)'}`, color: !input.trim() || isLoading ? '#334155' : '#00f0ff', cursor: !input.trim() || isLoading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 0.2s', boxShadow: !input.trim() || isLoading ? 'none' : '0 0 12px rgba(0,240,255,0.18)' }}>
                {isLoading ? <div style={{ width: '13px', height: '13px', border: '2px solid rgba(0,240,255,0.25)', borderTopColor: '#00f0ff', borderRadius: '50%', animation: 'ccSpin 0.8s linear infinite' }} /> : <Send size={14} />}
              </button>
            </div>
            <div style={{ fontSize: '0.59rem', color: '#1e293b', marginTop: '0.3rem', textAlign: 'center', fontFamily: 'monospace' }}>
              Enter to send · Shift+Enter new line · Powered by OpenRouter
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes ccPulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(0.8)}}
        @keyframes ccBlink{0%,100%{opacity:1}50%{opacity:0}}
        @keyframes ccSpin{to{transform:rotate(360deg)}}
        @keyframes ccSlide{from{opacity:0;transform:translateY(14px) scale(0.97)}to{opacity:1;transform:translateY(0) scale(1)}}
        .cc-inline-code{background:rgba(0,240,255,0.08);border:1px solid rgba(0,240,255,0.2);border-radius:3px;padding:1px 5px;font-family:monospace;font-size:0.77em;color:#00f0ff}
        .cc-code-block{margin:0.45rem 0;border-radius:6px;overflow:hidden;border:1px solid rgba(0,240,255,0.18);background:rgba(0,0,0,0.38)}
        .cc-code-header{display:flex;justify-content:space-between;align-items:center;padding:3px 10px;background:rgba(0,240,255,0.055);border-bottom:1px solid rgba(0,240,255,0.1)}
        .cc-code-lang{font-size:0.63rem;color:#00f0ff;font-family:monospace;text-transform:uppercase;letter-spacing:0.05em;display:flex;align-items:center;gap:3px}
        .cc-code-copy{font-size:0.63rem;color:#64748b;background:none;border:1px solid rgba(0,240,255,0.1);padding:2px 7px;border-radius:3px;cursor:pointer;display:flex;align-items:center;gap:3px;transition:all 0.2s;font-family:monospace}
        .cc-code-copy:hover{color:#00f0ff;border-color:rgba(0,240,255,0.38)}
        .cc-code-pre{margin:0;padding:0.65rem 0.9rem;overflow-x:auto;font-size:0.72rem;line-height:1.6;color:#a5b4fc;font-family:'Courier New',monospace;scrollbar-width:thin;scrollbar-color:rgba(0,240,255,0.15) transparent;white-space:pre}
      `}</style>
    </>
  );
}
