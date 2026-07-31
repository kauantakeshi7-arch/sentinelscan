import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Globe, 
  Lock, 
  Unlock, 
  Search, 
  FileText, 
  Database, 
  Mail, 
  Clock, 
  CheckCircle2, 
  XCircle, 
  Info,
  Server,
  Terminal,
  Bug,
  Download,
  List,
  Copy,
  Check
} from 'lucide-react';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [history, setHistory] = useState([]);
  
  // Terminal log state for scanning phase
  const [termLogs, setTermLogs] = useState([]);
  const terminalEndRef = useRef(null);

  // Track active remediation tab for headers (e.g., {'Content-Security-Policy': 'nginx'})
  const [activeRemedTab, setActiveRemedTab] = useState({});
  const [copiedHeader, setCopiedHeader] = useState(null);

  // Load scan history from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('sentinelscan_history');
    if (saved) {
      try {
        setHistory(JSON.parse(saved));
      } catch (e) {
        localStorage.removeItem('sentinelscan_history');
      }
    }
  }, []);

  // Autoscroll terminal
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [termLogs]);

  const simulateTerminalLogs = () => {
    setTermLogs([]);
    const logs = [
      '[~] Resolvendo IP do domínio alvo...',
      '[~] Conectando com a API GeoIP e resolvendo ISP...',
      '[+] IP resolvido: carregando informações de geolocalização...',
      '[~] Iniciando varredura passiva de cabeçalhos...',
      '[!] Analisando ausência de CSP e HSTS...',
      '[~] Conectando soquete TLS/SSL na porta 443...',
      '[+] Soquete seguro conectado: validando cadeia de certificação...',
      '[~] Iniciando testes ativos OWASP Top 10...',
      '[~] Testando injeção ativa SQL Injection (payload: \'?id=1\'\')...',
      '[~] Testando Reflected XSS (payload: \'<sentinel-xss-test>\')...',
      '[~] Procura por vazamento crítico de repositório (/.git/config)...',
      '[~] Testando enumeração de usuários WordPress (/wp-json/wp/v2/users)...',
      '[~] Fuzzing de backups expostos (/backup.sql, /db.sql, /dump.sql)...',
      '[~] Testando vulnerabilidade de Open Redirect (?redirect=https://google.com)...',
      '[~] Checando Verb Tampering (métodos PUT e DELETE)...',
      '[~] Verificando APIs abertas e rotas Swagger (/swagger-ui.html)...',
      '[~] Identificando plataforma CMS (WordPress/Drupal/Joomla) e analisando CVEs...',
      '[~] Escaneando portas TCP administrativas expostas (FTP, SSH, Telnet)...',
      '[+] Varredura de hacking concluída! Compilando relatório final...'
    ];

    let currentLogIndex = 0;
    setTermLogs([logs[0]]);

    const interval = setInterval(() => {
      currentLogIndex++;
      if (currentLogIndex < logs.length) {
        setTermLogs(prev => [...prev, logs[currentLogIndex]]);
      } else {
        clearInterval(interval);
      }
    }, 380);

    return interval;
  };

  const saveToHistory = (scanResult) => {
    const newItem = {
      hostname: scanResult.target.hostname,
      url: scanResult.target.url,
      score: scanResult.overallScore,
      grade: scanResult.grade,
      time: new Date().toLocaleTimeString()
    };

    const filtered = history.filter(item => item.hostname !== newItem.hostname);
    const updated = [newItem, ...filtered].slice(0, 5); // Keep last 5

    setHistory(updated);
    localStorage.setItem('sentinelscan_history', JSON.stringify(updated));
  };

  const handleScan = async (e, targetUrl = null) => {
    if (e) e.preventDefault();
    const queryUrl = targetUrl || url;
    if (!queryUrl.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setActiveTab('overview');

    const logInterval = simulateTerminalLogs();

    try {
      const response = await fetch('http://localhost:5001/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: queryUrl.trim() }),
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || 'Failed to scan target website');
      }

      const data = await response.json();
      setResult(data);
      saveToHistory(data);
      if (!targetUrl) setUrl(data.target.url);
    } catch (err) {
      setError(err.message || 'An error occurred connecting to the scanning server.');
    } finally {
      clearInterval(logInterval);
      setLoading(false);
    }
  };

  const exportJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinelscan_${result.target.hostname}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text, headerName) => {
    navigator.clipboard.writeText(text);
    setCopiedHeader(headerName);
    setTimeout(() => setCopiedHeader(null), 2000);
  };

  const getSeverityClass = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'severity-Critical';
      case 'medium':
        return 'severity-Medium';
      case 'low':
        return 'severity-Low';
      case 'info':
        return 'severity-Info';
      default:
        return 'severity-None';
    }
  };

  // Convert country code to emoji flag
  const getFlagEmoji = (countryCode) => {
    if (!countryCode) return '🌐';
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char => 127397 + char.charCodeAt(0));
    try {
      return String.fromCodePoint(...codePoints);
    } catch (e) {
      return '🌐';
    }
  };

  const strokeDashoffset = result ? 440 - (440 * result.overallScore) / 100 : 440;

  const getScoreColor = (score) => {
    if (score >= 90) return 'var(--color-success)';
    if (score >= 70) return 'var(--color-warning)';
    return 'var(--color-danger)';
  };

  const getPortRiskColor = (risk) => {
    switch (risk?.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'var(--color-danger)';
      case 'medium':
        return 'var(--color-warning)';
      case 'low':
        return 'var(--color-info)';
      default:
        return 'var(--color-success)';
    }
  };

  // Compile counts of findings for severity counters banner
  const getSeverityCounts = () => {
    if (!result) return { critical: 0, high: 0, medium: 0, low: 0, secure: 0 };
    
    let critical = 0, high = 0, medium = 0, low = 0, secure = 0;

    // Headers
    result.sections.headers.findings.forEach(f => {
      if (f.status === 'Missing' || f.status === 'Exposed') {
        if (f.severity === 'Critical') critical++;
        else if (f.severity === 'High') high++;
        else if (f.severity === 'Medium') medium++;
        else if (f.severity === 'Low') low++;
      } else {
        secure++;
      }
    });

    // SSL
    if (!result.sections.ssl.valid) {
      critical++;
    } else {
      result.sections.ssl.issues.forEach(issue => {
        if (issue.includes('expired') || issue.includes('trusted')) high++;
        else medium++;
      });
      if (result.sections.ssl.issues.length === 0) secure++;
    }

    // Exposed files
    result.sections.files.findings.forEach(f => {
      if (f.status === 'Exposed') {
        if (f.severity === 'Critical') critical++;
        else if (f.severity === 'High') high++;
      } else {
        secure++;
      }
    });

    // DNS
    result.sections.dns.spf.issues.forEach(issue => {
      if (issue.includes('No SPF')) high++;
      else medium++;
    });
    result.sections.dns.dmarc.issues.forEach(issue => {
      if (issue.includes('No DMARC')) high++;
      else medium++;
    });
    if (result.sections.dns.spf.present && result.sections.dns.spf.issues.length === 0) secure++;
    if (result.sections.dns.dmarc.present && result.sections.dns.dmarc.issues.length === 0) secure++;

    // Hacking
    result.sections.hacking.findings.forEach(f => {
      if (f.status === 'Vulnerable' || f.status === 'Weak') {
        if (f.severity === 'Critical') critical++;
        else if (f.severity === 'High') high++;
        else if (f.severity === 'Medium') medium++;
      } else {
        secure++;
      }
    });

    // Ports
    result.sections.ports.findings.forEach(f => {
      if (f.status === 'Open' && f.risk !== 'None' && f.risk !== 'Info') {
        if (f.risk === 'Critical') critical++;
        else if (f.risk === 'High') high++;
        else if (f.risk === 'Medium') medium++;
        else if (f.risk === 'Low') low++;
      }
    });

    return { critical, high, medium, low, secure };
  };

  const counts = getSeverityCounts();

  return (
    <div className="app-container">
      <header>
        <div className="logo-container">
          <Shield className="logo-icon" size={32} />
          <h1 className="logo-title">SentinelScan</h1>
          <span className="badge badge-beta">SaaS Protection</span>
        </div>
        {result && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <button onClick={exportJSON} className="btn-scan" style={{ padding: '0.5rem 1rem', fontSize: '0.8rem', background: 'rgba(255,255,255,0.05)', boxShadow: 'none' }}>
              <Download size={14} /> Exportar JSON
            </button>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              <Clock size={16} />
              <span>Varredura: {new Date(result.scanTime).toLocaleTimeString()}</span>
            </div>
          </div>
        )}
      </header>

      <main className="dashboard-grid">
        {/* Left Column */}
        <section>
          <div className="glass-panel search-panel">
            <h2 className="search-title">Escanear Nova URL</h2>
            <form onSubmit={(e) => handleScan(e)} className="search-form">
              <div className="search-input-wrapper">
                <Search className="search-icon" size={20} />
                <input
                  type="text"
                  placeholder="Ex: google.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={loading}
                  className="search-input"
                  required
                />
              </div>
              <button 
                type="submit" 
                disabled={loading} 
                className={`btn-scan ${loading ? 'scanning-pulse' : ''}`}
              >
                {loading ? 'Escaneando...' : 'Iniciar Scan'}
              </button>
            </form>
            {error && (
              <div style={{ marginTop: '1rem', color: 'var(--color-danger)', fontSize: '0.9rem', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <AlertTriangle size={18} />
                <span>{error}</span>
              </div>
            )}
          </div>

          {/* Hosting Intelligence (Server Info) Card */}
          {result && result.serverInfo && (
            <div className="glass-panel sidebar-info" style={{ marginBottom: '1.5rem', padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1rem', marginBottom: '1rem' }}>
                <Server size={16} color="var(--color-accent)" /> Servidor & Hospedagem
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', fontSize: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Endereço IP:</span>
                  <span style={{ fontWeight: 'bold', color: 'var(--text-primary)' }}>{result.serverInfo.ip}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Hospedado em:</span>
                  <span style={{ fontWeight: 'bold', color: 'var(--text-primary)', display: 'flex', gap: '0.25rem', alignItems: 'center' }}>
                    <span>{getFlagEmoji(result.serverInfo.countryCode)}</span>
                    <span>{result.serverInfo.city}, {result.serverInfo.country}</span>
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.2rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Provedor (ISP):</span>
                  <span style={{ fontWeight: 'bold', color: 'var(--color-accent)', textAlign: 'right', maxWidth: '170px', wordBreak: 'break-all' }}>{result.serverInfo.isp}</span>
                </div>
              </div>
            </div>
          )}

          {/* History Panel */}
          {history.length > 0 && !loading && (
            <div className="glass-panel sidebar-info" style={{ marginBottom: '1.5rem', padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1rem' }}>
                <List size={16} /> Histórico Recente
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
                {history.map((item, idx) => (
                  <div 
                    key={idx} 
                    onClick={() => handleScan(null, item.hostname)}
                    style={{ 
                      display: 'flex', 
                      justifyContent: 'space-between', 
                      alignItems: 'center', 
                      padding: '0.65rem 0.85rem', 
                      borderRadius: '8px', 
                      background: 'rgba(255,255,255,0.02)', 
                      border: '1px solid var(--border-color)', 
                      cursor: 'pointer',
                      transition: 'all 0.2s'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.borderColor = 'var(--color-primary)'}
                    onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--border-color)'}
                  >
                    <div>
                      <div style={{ fontSize: '0.85rem', fontWeight: 'bold' }}>{item.hostname}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Horário: {item.time}</div>
                    </div>
                    <span className="badge" style={{ background: getScoreColor(item.score) + '22', color: getScoreColor(item.score), border: `1px solid ${getScoreColor(item.score)}44`, padding: '0.15rem 0.45rem' }}>
                      {item.score}% ({item.grade})
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result && (
            <div className="glass-panel score-panel">
              <div className="score-circle-wrapper">
                <svg width="160" height="160">
                  <circle className="score-circle-bg" cx="80" cy="80" r="70" />
                  <circle 
                    className="score-circle-fill" 
                    cx="80" 
                    cy="80" 
                    r="70" 
                    stroke={getScoreColor(result.overallScore)}
                    strokeDasharray="440"
                    strokeDashoffset={strokeDashoffset}
                  />
                </svg>
                <div className="score-text-center">
                  <span className="score-number" style={{ color: getScoreColor(result.overallScore) }}>
                    {result.overallScore}
                  </span>
                  <span className="score-grade" style={{ color: getScoreColor(result.overallScore) }}>
                    Grau {result.grade}
                  </span>
                  <span className="score-label">Pontuação</span>
                </div>
              </div>

              <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '0.25rem' }}>{result.target.hostname}</h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                Protocolo: {result.target.protocol.toUpperCase().replace(':', '')}
              </p>

              <div className="metrics-summary" style={{ gridTemplateColumns: 'repeat(2, 1fr)' }}>
                <div className="metric-box">
                  <div className="metric-box-val" style={{ color: getScoreColor(result.sections.headers.score) }}>
                    {result.sections.headers.score}%
                  </div>
                  <div className="metric-box-lbl">Cabeçalhos</div>
                </div>
                <div className="metric-box">
                  <div className="metric-box-val" style={{ color: getScoreColor(result.sections.ssl.score) }}>
                    {result.sections.ssl.score}%
                  </div>
                  <div className="metric-box-lbl">Certificado</div>
                </div>
                <div className="metric-box">
                  <div className="metric-box-val" style={{ color: getScoreColor(result.sections.files.score) }}>
                    {result.sections.files.score}%
                  </div>
                  <div className="metric-box-lbl">Diretórios</div>
                </div>
                <div className="metric-box">
                  <div className="metric-box-val" style={{ color: getScoreColor(result.sections.dns.score) }}>
                    {result.sections.dns.score}%
                  </div>
                  <div className="metric-box-lbl">DNS/Email</div>
                </div>
                <div className="metric-box">
                  <div className="metric-box-val" style={{ color: getScoreColor(result.sections.hacking.score) }}>
                    {result.sections.hacking.score}%
                  </div>
                  <div className="metric-box-lbl">Hacking</div>
                </div>
                <div className="metric-box">
                  <div className="metric-box-val" style={{ color: getScoreColor(result.sections.ports.score) }}>
                    {result.sections.ports.score}%
                  </div>
                  <div className="metric-box-lbl">Portas TCP</div>
                </div>
              </div>
            </div>
          )}

          {!result && !loading && (
            <div className="glass-panel sidebar-info">
              <h3>Auditor de Explorações & Hacking</h3>
              <p>Execute simulações ativas de invasão e auditorias de vulnerabilidade OWASP Top 10 para proteger seu domínio contra hackers.</p>
              
              <div className="info-item">
                <Terminal className="info-item-icon" size={18} />
                <div className="info-item-text">
                  <h4>Vulnerabilidades de Injeção</h4>
                  <p>Checa defesas ativas contra SQL Injection (SQLi) e Cross-Site Scripting (XSS).</p>
                </div>
              </div>

              <div className="info-item">
                <Bug className="info-item-icon" size={18} />
                <div className="info-item-text">
                  <h4>Portas e Infraestrutura</h4>
                  <p>Localiza portas de rede expostas como FTP e SSH para evitar acessos não autorizados.</p>
                </div>
              </div>

              <div className="info-item">
                <Lock className="info-item-icon" size={18} />
                <div className="info-item-text">
                  <h4>Guias de Configuração</h4>
                  <p>Disponibiliza receitas copiáveis prontas para Nginx, Apache e IIS.</p>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* Right Column */}
        <section>
          {loading && (
            <div className="glass-panel" style={{ padding: '1.5rem', background: '#0a0915', minHeight: '400px', display: 'flex', flexDirection: 'column', border: '1px solid rgba(139, 92, 246, 0.25)', borderRadius: '16px', boxShadow: '0 8px 32px 0 rgba(0,0,0,0.5)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.5rem', marginBottom: '1rem' }}>
                <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#ef4444' }}></div>
                <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#f59e0b' }}></div>
                <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#10b981' }}></div>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontFamily: 'monospace', marginLeft: '0.5rem' }}>terminal@sentinelscan: ~</span>
              </div>
              <div style={{ flexGrow: 1, fontFamily: 'monospace', fontSize: '0.85rem', color: '#10b981', display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '300px', overflowY: 'auto' }}>
                {termLogs.map((log, idx) => (
                  <div key={idx} style={{ wordBreak: 'break-all' }}>{log}</div>
                ))}
                <div ref={terminalEndRef}></div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'center', marginTop: '1.5rem' }}>
                <div className="cyber-spinner" style={{ width: '36px', height: '36px' }}></div>
              </div>
            </div>
          )}

          {!loading && !result && (
            <div className="glass-panel empty-state">
              <ShieldAlert className="empty-state-icon" size={64} />
              <h3>Nenhum resultado para exibir</h3>
              <p>Digite a URL do site desejado no campo de busca ao lado e clique em <strong>Iniciar Scan</strong> para ver o relatório completo de vulnerabilidades.</p>
            </div>
          )}

          {!loading && result && (
            <div className="glass-panel main-content-panel">
              <div className="tabs-header">
                <button onClick={() => setActiveTab('overview')} className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}>
                  <Globe size={16} /> Geral
                </button>
                <button onClick={() => setActiveTab('hacking')} className={`tab-btn ${activeTab === 'hacking' ? 'active' : ''}`} style={{ fontWeight: 'bold' }}>
                  <Terminal size={16} /> Hacking & Bugs
                </button>
                <button onClick={() => setActiveTab('ports')} className={`tab-btn ${activeTab === 'ports' ? 'active' : ''}`}>
                  <Bug size={16} /> Portas Abertas
                </button>
                <button onClick={() => setActiveTab('headers')} className={`tab-btn ${activeTab === 'headers' ? 'active' : ''}`}>
                  <Server size={16} /> Cabeçalhos HTTP
                </button>
                <button onClick={() => setActiveTab('ssl')} className={`tab-btn ${activeTab === 'ssl' ? 'active' : ''}`}>
                  <Lock size={16} /> SSL / TLS
                </button>
                <button onClick={() => setActiveTab('files')} className={`tab-btn ${activeTab === 'files' ? 'active' : ''}`}>
                  <FileText size={16} /> Diretórios
                </button>
                <button onClick={() => setActiveTab('dns')} className={`tab-btn ${activeTab === 'dns' ? 'active' : ''}`}>
                  <Database size={16} /> DNS & Email
                </button>
              </div>

              <div className="tab-content">
                {/* 1. OVERVIEW TAB WITH SEVERITY BANNER */}
                {activeTab === 'overview' && (
                  <div>
                    {/* Severity Counter Banner */}
                    <div style={{ 
                      display: 'grid', 
                      gridTemplateColumns: 'repeat(5, 1fr)', 
                      gap: '0.5rem', 
                      marginBottom: '1.5rem',
                      background: 'rgba(255,255,255,0.01)',
                      border: '1px solid var(--border-color)',
                      padding: '0.75rem',
                      borderRadius: '12px'
                    }}>
                      <div style={{ textAlign: 'center', borderRight: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: 'var(--color-danger)' }}>{counts.critical}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Crítico</div>
                      </div>
                      <div style={{ textAlign: 'center', borderRight: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: 'var(--color-danger)' }}>{counts.high}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Alto</div>
                      </div>
                      <div style={{ textAlign: 'center', borderRight: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: 'var(--color-warning)' }}>{counts.medium}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Médio</div>
                      </div>
                      <div style={{ textAlign: 'center', borderRight: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: 'var(--color-info)' }}>{counts.low}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Baixo</div>
                      </div>
                      <div style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: 'var(--color-success)' }}>{counts.secure}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Seguro</div>
                      </div>
                    </div>

                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '1.25rem' }}>Resumo de Vulnerabilidades</h3>
                    <div className="findings-container">
                      {(() => {
                        const criticalFindings = [];
                        
                        // Active hacking
                        result.sections.hacking.findings
                          .filter(f => f.status === 'Vulnerable' || f.status === 'Weak')
                          .forEach(f => criticalFindings.push({ header: f.name, severity: f.severity, desc: f.desc, fix: f.fix, section: 'hacking' }));

                        // Ports
                        result.sections.ports.findings
                          .filter(f => f.status === 'Open' && f.risk !== 'None' && f.risk !== 'Info')
                          .forEach(f => criticalFindings.push({ header: `Porta Aberta: ${f.port} (${f.name})`, severity: f.risk, desc: f.desc, fix: 'Feche a porta no firewall ou configure o serviço para escutar apenas localmente (localhost).', section: 'ports' }));

                        // Missing headers
                        result.sections.headers.findings
                          .filter(f => f.status === 'Missing' || f.status === 'Exposed')
                          .forEach(f => criticalFindings.push({ ...f, section: 'headers', type: 'Header missing' }));
                        
                        // SSL
                        if (!result.sections.ssl.valid) {
                          criticalFindings.push({
                            header: 'Certificado SSL Inválido',
                            severity: 'Critical',
                            desc: result.sections.ssl.error,
                            fix: 'Renove seu certificado SSL ou garanta que ele seja emitido por uma autoridade de certificação confiável.',
                            section: 'ssl'
                          });
                        } else {
                          result.sections.ssl.issues.forEach(issue => {
                            criticalFindings.push({
                              header: 'Problema no Certificado SSL',
                              severity: issue.includes('expired') || issue.includes('trusted') ? 'High' : 'Medium',
                              desc: issue,
                              fix: 'Revise suas configurações de TLS/SSL no servidor e instale certificados válidos.',
                              section: 'ssl'
                            });
                          });
                        }

                        // Exposed files
                        result.sections.files.findings
                          .filter(f => f.status === 'Exposed')
                          .forEach(f => criticalFindings.push({ header: f.name, severity: f.severity, desc: f.desc, fix: f.fix, section: 'files' }));

                        // DNS
                        result.sections.dns.spf.issues.forEach(issue => {
                          criticalFindings.push({ header: 'Falha no Registro SPF', severity: issue.includes('No SPF') ? 'High' : 'Medium', desc: issue, fix: 'Adicione um registro TXT com a política de envio SPF para o seu provedor de email.', section: 'dns' });
                        });
                        result.sections.dns.dmarc.issues.forEach(issue => {
                          criticalFindings.push({ header: 'Falha na Política DMARC', severity: issue.includes('No DMARC') ? 'High' : 'Medium', desc: issue, fix: 'Adicione um registro TXT DMARC com as políticas de ação (rejeição, quarentena ou monitoramento).', section: 'dns' });
                        });

                        if (criticalFindings.length === 0) {
                          return (
                            <div className="empty-state" style={{ padding: '2rem' }}>
                              <CheckCircle2 size={48} color="var(--color-success)" style={{ marginBottom: '1rem' }} />
                              <h3>Excelente! Nenhuma vulnerabilidade encontrada.</h3>
                              <p>Seu site passou com sucesso nas configurações básicas de segurança e infraestrutura.</p>
                            </div>
                          );
                        }

                        const severityWeight = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0 };
                        criticalFindings.sort((a, b) => (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0));

                        return criticalFindings.map((finding, idx) => (
                          <div key={idx} className={`finding-card ${getSeverityClass(finding.severity)}`}>
                            <div className="finding-header">
                              <div className="finding-title">
                                {finding.severity === 'Critical' || finding.severity === 'High' ? (
                                  <ShieldAlert size={18} color="var(--color-danger)" />
                                ) : (
                                  <AlertTriangle size={18} color="var(--color-warning)" />
                                )}
                                <span>{finding.header}</span>
                              </div>
                              <span className={`finding-severity severity-bg-${finding.severity}`}>
                                {finding.severity}
                              </span>
                            </div>
                            <div className="finding-body">
                              <p>{finding.desc}</p>
                              {finding.fix && (
                                <div className="finding-recommendation">
                                  <span className="recommendation-lbl">Como mitigar / corrigir:</span>
                                  <p>{finding.fix}</p>
                                </div>
                              )}
                            </div>
                          </div>
                        ));
                      })()}
                    </div>
                  </div>
                )}

                {/* 2. HACKING TAB */}
                {activeTab === 'hacking' && (
                  <div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '0.75rem' }}>Simulações de Hacking e Explorações (Vulnerabilidades Ativas)</h3>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
                      Estes testes simulam ataques ativamente no site para identificar falhas comuns de injeção de código, bypass de segurança de sessão e vazamento de arquivos internos.
                    </p>
                    <div className="findings-container">
                      {result.sections.hacking.findings.map((f, idx) => (
                        <div key={idx} className={`finding-card ${f.status === 'Secure' ? 'severity-None' : getSeverityClass(f.severity)}`}>
                          <div className="finding-header">
                            <div className="finding-title">
                              {f.status === 'Secure' ? (
                                <CheckCircle2 size={18} color="var(--color-success)" />
                              ) : (
                                <XCircle size={18} color="var(--color-danger)" />
                              )}
                              <span>{f.name}</span>
                            </div>
                            <span className={`finding-severity ${f.status === 'Secure' ? 'severity-bg-None' : `severity-bg-${f.severity}`}`}>
                              {f.status === 'Secure' ? 'Seguro' : f.status}
                            </span>
                          </div>
                          <div className="finding-body">
                            {f.status === 'Secure' ? (
                              <p style={{ color: 'var(--text-secondary)' }}>{f.desc}</p>
                            ) : (
                              <>
                                <p>{f.desc}</p>
                                <div className="finding-recommendation">
                                  <span className="recommendation-lbl">Mitigação do Desenvolvedor:</span>
                                  <p>{f.fix}</p>
                                </div>
                              </>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 3. PORTS TAB */}
                {activeTab === 'ports' && (
                  <div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '0.75rem' }}>Portas TCP Escaneadas</h3>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
                      A exposição de portas administrativas ou de transferência de arquivos (como SSH ou FTP) para o público é um vetor primário de ataques por força bruta.
                    </p>
                    <div className="dns-table-wrapper">
                      <table className="dns-table">
                        <thead>
                          <tr>
                            <th>Porta</th>
                            <th>Serviço</th>
                            <th>Status</th>
                            <th>Risco</th>
                            <th>Descrição</th>
                          </tr>
                        </thead>
                        <tbody>
                          {result.sections.ports.findings.map((p, idx) => (
                            <tr key={idx}>
                              <td style={{ fontWeight: 'bold' }}>{p.port}</td>
                              <td>{p.name}</td>
                              <td>
                                <span style={{ 
                                  display: 'inline-flex', 
                                  alignItems: 'center', 
                                  gap: '0.25rem', 
                                  color: p.status === 'Open' ? 'var(--color-danger)' : 'var(--text-secondary)',
                                  fontWeight: p.status === 'Open' ? 'bold' : 'normal'
                                }}>
                                  {p.status === 'Open' ? <ShieldAlert size={14} /> : <CheckCircle2 size={14} />}
                                  {p.status}
                                </span>
                              </td>
                              <td style={{ color: getPortRiskColor(p.risk), fontWeight: 'bold' }}>{p.risk}</td>
                              <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{p.desc}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* 4. HEADERS TAB WITH REMEDIATION CODE TABS */}
                {activeTab === 'headers' && (
                  <div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '1.25rem' }}>Cabeçalhos de Segurança HTTP</h3>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
                      Cabeçalhos HTTP instruem o navegador sobre como se comportar ao interagir com o site. A falta deles expõe os clientes a ataques.
                    </p>
                    <div className="findings-container">
                      {result.sections.headers.findings.map((f, idx) => (
                        <div key={idx} className={`finding-card ${f.status === 'Present' ? 'severity-None' : getSeverityClass(f.severity)}`}>
                          <div className="finding-header">
                            <div className="finding-title">
                              {f.status === 'Present' ? (
                                <CheckCircle2 size={18} color="var(--color-success)" />
                              ) : f.status === 'Exposed' ? (
                                <AlertTriangle size={18} color="var(--color-danger)" />
                              ) : (
                                <XCircle size={18} color="var(--color-danger)" />
                              )}
                              <span>{f.header}</span>
                            </div>
                            <span className={`finding-severity ${f.status === 'Present' ? 'severity-bg-None' : `severity-bg-${f.severity}`}`}>
                              {f.status === 'Present' ? 'Ativo' : f.severity}
                            </span>
                          </div>
                          <div className="finding-body">
                            {f.status === 'Present' ? (
                              <p style={{ wordBreak: 'break-all' }}><strong>Valor:</strong> <code style={{ color: 'var(--color-accent)' }}>{f.value}</code></p>
                            ) : (
                              <>
                                <p>{f.desc}</p>
                                
                                {/* Remediation Config Section */}
                                {f.remediations && (
                                  <div style={{ marginTop: '1rem', border: '1px solid var(--border-color)', borderRadius: '8px', overflow: 'hidden' }}>
                                    <div style={{ display: 'flex', background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border-color)' }}>
                                      {['nginx', 'apache', 'iis'].map(serverType => (
                                        <button 
                                          key={serverType}
                                          onClick={() => setActiveRemedTab(prev => ({ ...prev, [f.header]: serverType }))}
                                          style={{
                                            padding: '0.5rem 1rem',
                                            background: 'none',
                                            border: 'none',
                                            color: (activeRemedTab[f.header] || 'nginx') === serverType ? 'var(--color-accent)' : 'var(--text-secondary)',
                                            fontWeight: 'bold',
                                            fontSize: '0.75rem',
                                            cursor: 'pointer',
                                            borderBottom: (activeRemedTab[f.header] || 'nginx') === serverType ? '2px solid var(--color-accent)' : 'none',
                                            textTransform: 'uppercase'
                                          }}
                                        >
                                          {serverType}
                                        </button>
                                      ))}
                                    </div>
                                    <div style={{ padding: '0.75rem', position: 'relative', background: 'rgba(0,0,0,0.2)' }}>
                                      <code style={{ fontSize: '0.8rem', color: '#f3f4f6', wordBreak: 'break-all', display: 'block', paddingRight: '2rem' }}>
                                        {f.remediations[activeRemedTab[f.header] || 'nginx']}
                                      </code>
                                      <button 
                                        onClick={() => copyToClipboard(f.remediations[activeRemedTab[f.header] || 'nginx'], f.header)}
                                        style={{ position: 'absolute', right: '0.5rem', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
                                        title="Copiar Código"
                                      >
                                        {copiedHeader === f.header ? <Check size={16} color="var(--color-success)" /> : <Copy size={16} />}
                                      </button>
                                    </div>
                                  </div>
                                )}
                                
                                <div className="finding-recommendation">
                                  <span className="recommendation-lbl">Como corrigir:</span>
                                  <p>{f.fix}</p>
                                </div>
                              </>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 5. SSL TAB */}
                {activeTab === 'ssl' && (
                  <div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '1.25rem' }}>Informações e Validação SSL/TLS</h3>
                    
                    {!result.sections.ssl.valid ? (
                      <div className="finding-card severity-Critical">
                        <div className="finding-header">
                          <div className="finding-title">
                            <XCircle size={20} color="var(--color-danger)" />
                            <span>Erro de Conexão SSL</span>
                          </div>
                          <span className="finding-severity severity-bg-Critical">Falha</span>
                        </div>
                        <div className="finding-body">
                          <p>{result.sections.ssl.error}</p>
                        </div>
                      </div>
                    ) : (
                      <div className="ssl-grid">
                        <div className="ssl-stat-card">
                          <div className="ssl-stat-lbl">Status da Conexão</div>
                          <div className="ssl-stat-val" style={{ color: result.sections.ssl.isAuthorized ? 'var(--color-success)' : 'var(--color-danger)', display: 'flex', gap: '0.25rem', alignItems: 'center' }}>
                            {result.sections.ssl.isAuthorized ? (
                              <>
                                <ShieldCheck size={18} /> Certificado Confiável
                              </>
                            ) : (
                              <>
                                <ShieldAlert size={18} /> Não Confiável
                              </>
                            )}
                          </div>
                        </div>

                        <div className="ssl-stat-card">
                          <div className="ssl-stat-lbl">Protocolo / Cifra</div>
                          <div className="ssl-stat-val">
                            {result.sections.ssl.protocol} ({result.sections.ssl.cipher.name})
                          </div>
                        </div>

                        <div className="ssl-stat-card">
                          <div className="ssl-stat-lbl">Tempo de Validade Restante</div>
                          <div className="ssl-stat-val" style={{ color: result.sections.ssl.daysRemaining > 30 ? 'var(--text-primary)' : 'var(--color-warning)' }}>
                            {result.sections.ssl.daysRemaining} dias restantes
                          </div>
                        </div>

                        <div className="ssl-stat-card">
                          <div className="ssl-stat-lbl">Emissor (CA)</div>
                          <div className="ssl-stat-val">
                            {result.sections.ssl.issuer.O || result.sections.ssl.issuer.CN || 'Desconhecido'}
                          </div>
                        </div>

                        <div className="ssl-stat-card" style={{ gridColumn: 'span 2' }}>
                          <div className="ssl-stat-lbl">Assunto / Domínio</div>
                          <div className="ssl-stat-val">
                            {result.sections.ssl.subject.CN || 'Desconhecido'}
                          </div>
                        </div>
                      </div>
                    )}

                    {result.sections.ssl.issues && result.sections.ssl.issues.length > 0 && (
                      <div style={{ marginTop: '1.5rem' }}>
                        <h4 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--color-warning)' }}>Advertências SSL</h4>
                        <div className="findings-container">
                          {result.sections.ssl.issues.map((issue, idx) => (
                            <div key={idx} className="finding-card severity-Medium">
                              <div className="finding-header">
                                <div className="finding-title">
                                  <AlertTriangle size={18} color="var(--color-warning)" />
                                  <span>Problema SSL</span>
                                </div>
                                <span className="finding-severity severity-bg-Medium">Aviso</span>
                              </div>
                              <div className="finding-body">
                                <p>{issue}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 6. EXPOSED FILES TAB */}
                {activeTab === 'files' && (
                  <div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '0.75rem' }}>Vazamento de Arquivos de Configuração</h3>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
                      Atacantes fazem buscas automatizadas em pastas públicas em busca de arquivos de log, chaves de API, arquivos de ambiente (`.env`) ou histórico de desenvolvimento (`.git/`).
                    </p>
                    <div className="findings-container">
                      {result.sections.files.findings.map((file, idx) => (
                        <div key={idx} className={`finding-card ${file.status === 'Found' ? 'severity-None' : getSeverityClass(file.severity)}`}>
                          <div className="finding-header">
                            <div className="finding-title">
                              {file.status === 'Exposed' ? (
                                <XCircle size={18} color="var(--color-danger)" />
                              ) : file.status === 'Found' ? (
                                <CheckCircle2 size={18} color="var(--color-success)" />
                              ) : (
                                <ShieldCheck size={18} color="var(--text-muted)" />
                              )}
                              <span>{file.name}</span>
                            </div>
                            <span className={`finding-severity ${file.status === 'Exposed' ? `severity-bg-${file.severity}` : 'severity-bg-None'}`}>
                              {file.status === 'Exposed' ? 'Exposto' : file.status === 'Found' ? 'Identificado' : 'Protegido'}
                            </span>
                          </div>
                          <div className="finding-body">
                            <p style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                              Caminho testado: <code style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '0.1rem 0.3rem', borderRadius: '4px' }}>{file.path}</code>
                            </p>
                            {file.status === 'Exposed' ? (
                              <>
                                <p>{file.desc}</p>
                                <div className="finding-recommendation">
                                  <span className="recommendation-lbl">Como corrigir:</span>
                                  <p>{file.fix}</p>
                                </div>
                              </>
                            ) : file.status === 'Found' ? (
                              <p>Arquivo público legível. {file.desc}</p>
                            ) : (
                              <p style={{ color: 'var(--text-muted)' }}>O servidor retornou um erro apropriado (por exemplo, 404 ou 403), indicando que o arquivo não está exposto publicamente.</p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 7. DNS TAB */}
                {activeTab === 'dns' && (
                  <div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '1.25rem' }}>DNS e Políticas Anti-Spoofing de Email</h3>
                    
                    {/* SPF Record */}
                    <div className="finding-card" style={{ borderLeft: result.sections.dns.spf.present && result.sections.dns.spf.issues.length === 0 ? '4px solid var(--color-success)' : '4px solid var(--color-warning)', marginBottom: '1.5rem' }}>
                      <h4 style={{ fontWeight: 700, fontSize: '1.05rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        {result.sections.dns.spf.present ? <CheckCircle2 size={18} color="var(--color-success)" /> : <XCircle size={18} color="var(--color-danger)" />}
                        Registro SPF (Sender Policy Framework)
                      </h4>
                      {result.sections.dns.spf.present ? (
                        <p style={{ wordBreak: 'break-all', fontSize: '0.9rem' }}>
                          <strong>Registro Atual:</strong> <code style={{ color: 'var(--color-accent)' }}>{result.sections.dns.spf.value}</code>
                        </p>
                      ) : (
                        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Nenhum registro SPF foi encontrado nos servidores de DNS.</p>
                      )}
                      
                      {result.sections.dns.spf.issues.map((issue, idx) => (
                        <div key={idx} className="finding-recommendation" style={{ marginTop: '0.75rem' }}>
                          <span className="recommendation-lbl" style={{ color: 'var(--color-warning)' }}>Recomendação:</span>
                          <p>{issue}</p>
                        </div>
                      ))}
                    </div>

                    {/* DMARC Record */}
                    <div className="finding-card" style={{ borderLeft: result.sections.dns.dmarc.present && result.sections.dns.dmarc.issues.length === 0 ? '4px solid var(--color-success)' : '4px solid var(--color-warning)', marginBottom: '1.5rem' }}>
                      <h4 style={{ fontWeight: 700, fontSize: '1.05rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        {result.sections.dns.dmarc.present ? <CheckCircle2 size={18} color="var(--color-success)" /> : <XCircle size={18} color="var(--color-danger)" />}
                        Política DMARC (Domain-based Message Authentication)
                      </h4>
                      {result.sections.dns.dmarc.present ? (
                        <p style={{ wordBreak: 'break-all', fontSize: '0.9rem' }}>
                          <strong>Registro Atual:</strong> <code style={{ color: 'var(--color-accent)' }}>{result.sections.dns.dmarc.value}</code>
                        </p>
                      ) : (
                        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Nenhuma política DMARC configurada.</p>
                      )}

                      {result.sections.dns.dmarc.issues.map((issue, idx) => (
                        <div key={idx} className="finding-recommendation" style={{ marginTop: '0.75rem' }}>
                          <span className="recommendation-lbl" style={{ color: 'var(--color-warning)' }}>Recomendação:</span>
                          <p>{issue}</p>
                        </div>
                      ))}
                    </div>

                    {/* MX records table */}
                    <h4 style={{ fontWeight: 700, fontSize: '1.05rem', marginBottom: '0.75rem' }}>Servidores de Email (MX Records)</h4>
                    {result.sections.dns.mx.present ? (
                      <div className="dns-table-wrapper">
                        <table className="dns-table">
                          <thead>
                            <tr>
                              <th>Servidor (Mail Exchange)</th>
                              <th>Prioridade</th>
                            </tr>
                          </thead>
                          <tbody>
                            {result.sections.dns.mx.records.map((rec, idx) => (
                              <tr key={idx}>
                                <td>{rec.exchange}</td>
                                <td>{rec.priority}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="finding-card severity-Medium">
                        <p>Nenhum servidor de e-mail (registro MX) configurado. O domínio não pode receber e-mails diretos.</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
