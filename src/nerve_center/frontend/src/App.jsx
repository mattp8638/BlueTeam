import { useState, useEffect, useRef } from 'react'
import { Shield, Activity, Monitor, AlertTriangle, PlayCircle, Briefcase, X, Terminal, Cpu, Zap } from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts'
import './index.css'

const dummyChartData = [
  { time: '08:00', threats: 12, blocked: 10 },
  { time: '10:00', threats: 15, blocked: 14 },
  { time: '12:00', threats: 8, blocked: 8 },
  { time: '14:00', threats: 35, blocked: 32 },
  { time: '16:00', threats: 20, blocked: 19 },
  { time: '18:00', threats: 10, blocked: 10 },
]

function App() {
  const [activeTab, setActiveTab] = useState('fleet')
  const [apiStatus, setApiStatus] = useState('Checking...')
  
  // Data State
  const [fleetData, setFleetData] = useState([])
  const [siemData, setSiemData] = useState([])
  const [soarData, setSoarData] = useState([])
  const [irData, setIrData] = useState([])

  // Panel State
  const [panelOpen, setPanelOpen] = useState(false)
  const [panelContent, setPanelContent] = useState(null)
  const [telemetryLogs, setTelemetryLogs] = useState([])
  const consoleRef = useRef(null)

  // Ping API
  useEffect(() => {
    fetch('http://127.0.0.1:8000/')
      .then(res => res.json())
      .then(data => setApiStatus(data.status))
      .catch(() => setApiStatus('offline'))
  }, [])

  // Fetch active view data
  useEffect(() => {
    if (activeTab === 'fleet') {
      fetch('http://127.0.0.1:8000/api/fleet').then(res => res.json()).then(setFleetData).catch(console.error)
    } else if (activeTab === 'siem') {
      fetch('http://127.0.0.1:8000/api/siem/alerts').then(res => res.json()).then(setSiemData).catch(console.error)
    } else if (activeTab === 'soar') {
      fetch('http://127.0.0.1:8000/api/soar/playbooks').then(res => res.json()).then(setSoarData).catch(console.error)
    } else if (activeTab === 'ir') {
      fetch('http://127.0.0.1:8000/api/ir/incidents').then(res => res.json()).then(setIrData).catch(console.error)
    }
  }, [activeTab])

  // Telemetry Simulator
  useEffect(() => {
    if (activeTab !== 'siem') return
    const interval = setInterval(() => {
      const logs = [
        { type: 'info', msg: 'Ingesting sysmon event from WIN-DESKTOP-01' },
        { type: 'warn', msg: 'High entropy detected in C:\\Temp\\update.exe' },
        { type: 'crit', msg: 'YARA rule match: Ransomware_WannaCry_Strings' },
        { type: 'info', msg: 'Network connection closed on SRV-EXCHANGE-01' }
      ]
      const newLog = {
        time: new Date().toISOString().split('T')[1].substring(0,8),
        ...logs[Math.floor(Math.random() * logs.length)]
      }
      setTelemetryLogs(prev => [...prev, newLog].slice(-50))
    }, 1500)
    return () => clearInterval(interval)
  }, [activeTab])

  // Auto-scroll telemetry
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [telemetryLogs])

  // Actions
  const handleInvestigate = (agent) => {
    setPanelContent({
      title: `Forensic Package: ${agent.hostname}`,
      details: [
        { label: 'Agent ID', value: agent.id },
        { label: 'Last Seen', value: agent.last_seen },
        { label: 'AV Hits', value: agent.av_hits },
        { label: 'Open Vulns', value: agent.vulns }
      ]
    })
    setPanelOpen(true)
    fetch(`http://127.0.0.1:8000/api/fleet/investigate/${agent.id}`, { method: 'POST' })
  }

  const handleTriage = (alert) => {
    setPanelContent({
      title: `Incident Triage: Alert #${alert.id}`,
      details: [
        { label: 'Timestamp', value: alert.timestamp },
        { label: 'Source', value: alert.source },
        { label: 'Detection Rule', value: alert.rule },
        { label: 'Severity', value: alert.severity }
      ]
    })
    setPanelOpen(true)
    fetch(`http://127.0.0.1:8000/api/siem/triage/${alert.id}`, { method: 'POST' })
  }

  const handleExecuteSOAR = (playbook) => {
    setPanelContent({
      title: `Executing Playbook: ${playbook.name}`,
      details: [
        { label: 'Status', value: 'Initializing DAG execution...' },
        { label: 'Target', value: 'All matching endpoints' }
      ]
    })
    setPanelOpen(true)
    fetch(`http://127.0.0.1:8000/api/soar/execute/${playbook.name}`, { method: 'POST' })
  }

  // Renderers
  const renderSiemDashboard = () => (
    <div className="fade-in">
      <div className="dashboard-grid">
        <div className="widget-half">
          <div className="chart-card glass-panel ai-glow">
            <h3 style={{marginBottom: '1rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px'}}>
              <Cpu className="ai-icon-spin" size={18} /> AI Anomaly Detection (24h)
            </h3>
            <ResponsiveContainer width="100%" height="80%">
              <AreaChart data={dummyChartData}>
                <defs>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-purple)" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="var(--accent-purple)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="var(--text-muted)" />
                <YAxis stroke="var(--text-muted)" />
                <Tooltip contentStyle={{backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--accent-purple)', boxShadow: '0 0 10px rgba(139, 92, 246, 0.3)'}} />
                <Area type="monotone" dataKey="threats" stroke="var(--accent-purple)" fillOpacity={1} fill="url(#colorThreats)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <div className="widget-half">
          <div className="telemetry-console glass-panel" ref={consoleRef}>
            <div style={{display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', color: 'var(--text-muted)', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '8px'}}>
              <Terminal size={14} /> LIVE INGESTION STREAM
            </div>
            {telemetryLogs.map((log, idx) => (
              <div key={idx} className="telemetry-line">
                <span className="log-time">[{new Date().toLocaleTimeString()}]</span>
                <span className="log-info">{JSON.stringify(log)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="table-container glass-panel">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Timestamp</th>
              <th>Source Asset</th>
              <th>Severity</th>
              <th>Detection Rule</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {siemData.map(alert => {
              const isAI = alert.rule && alert.rule.includes("AI_");
              return (
              <tr key={alert.id} className={isAI ? "tr-ai-flagged" : ""}>
                <td style={{fontFamily: 'monospace', color: 'var(--text-muted)'}}>#{alert.id}</td>
                <td style={{color: 'var(--text-muted)', fontSize: '0.9rem'}}>{alert.timestamp}</td>
                <td style={{fontWeight: 600, color: 'var(--text-primary)'}}>{alert.source}</td>
                <td>
                  <span className={`badge ${alert.severity === 'Critical' || alert.severity === 'High' ? 'badge-red' : 'badge-yellow'}`}>
                    {alert.severity.toUpperCase()}
                  </span>
                </td>
                <td>
                  {isAI ? (
                    <div>
                      <span className="ai-badge"><Zap size={12}/> AI DETECTED</span>
                      <div style={{color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '4px'}}>{alert.rule}</div>
                      <div className="confidence-bar-container">
                        <div className="confidence-bar-fill" style={{width: '94%'}}></div>
                      </div>
                    </div>
                  ) : (
                    <span style={{color: 'var(--accent-blue)', fontWeight: 500}}>{alert.rule}</span>
                  )}
                </td>
                <td><button className="btn-action" onClick={() => handleTriage(alert)}>Triage Event</button></td>
              </tr>
            )})}
          </tbody>
        </table>
      </div>
    </div>
  )

  const renderFleetDashboard = () => (
    <div className="fade-in">
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Hostname</th>
              <th>Agent ID</th>
              <th>Last Seen</th>
              <th>AV Hits</th>
              <th>Vulns</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {fleetData.map(agent => (
              <tr key={agent.id}>
                <td>
                  <div className={`status-badge ${agent.status === 'online' ? 'status-green' : 'status-red'}`}>
                    <div className="status-dot-small" style={{backgroundColor: agent.status === 'online' ? 'var(--accent-green)' : 'var(--accent-red)'}}></div>
                    {agent.status.toUpperCase()}
                  </div>
                </td>
                <td style={{fontWeight: 600}}>{agent.hostname}</td>
                <td style={{fontFamily: 'monospace', color: 'var(--text-muted)', fontSize: '0.9rem'}}>{agent.id}</td>
                <td style={{color: 'var(--text-muted)', fontSize: '0.9rem'}}>{agent.last_seen}</td>
                <td>{agent.av_hits > 0 ? <span className="badge badge-red">{agent.av_hits}</span> : <span className="badge badge-gray">0</span>}</td>
                <td>{agent.vulns > 0 ? <span className="badge badge-yellow">{agent.vulns}</span> : <span className="badge badge-gray">0</span>}</td>
                <td><button className="btn-action" onClick={() => handleInvestigate(agent)}>Investigate</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )

  const renderSoarDashboard = () => (
    <div className="fade-in">
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Playbook Name</th>
              <th>Status</th>
              <th>Success Rate</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {soarData.map((pb, idx) => (
              <tr key={idx}>
                <td style={{fontWeight: 600}}>{pb.name}</td>
                <td>
                  <div className={`status-badge ${pb.status === 'active' ? 'status-green' : 'status-red'}`} style={{display: 'inline-flex'}}>
                    <div className="status-dot-small" style={{backgroundColor: pb.status === 'active' ? 'var(--accent-green)' : 'var(--accent-red)'}}></div>
                    {pb.status.toUpperCase()}
                  </div>
                </td>
                <td style={{color: 'var(--accent-blue)', fontWeight: 600}}>{pb.success_rate}</td>
                <td><button className="btn-action" onClick={() => handleExecuteSOAR(pb)}>Execute Now</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )

  return (
    <div className="app-container">
      <div className="hud-overlay"></div>
      {/* Sidebar */}
      <nav className="sidebar">
        <div className="brand">
          <div className="brand-shield"><Shield color="#fff" size={20} /></div>
          <h1>Nerve Center</h1>
        </div>
        <div className="nav-menu">
          <div className={`nav-item ${activeTab === 'fleet' ? 'active' : ''}`} onClick={() => setActiveTab('fleet')}>
            <Monitor size={18} /><span>Agent Fleet</span>
          </div>
          <div className={`nav-item ${activeTab === 'siem' ? 'active' : ''}`} onClick={() => setActiveTab('siem')}>
            <Activity size={18} /><span>SIEM Core</span>
          </div>
          <div className={`nav-item ${activeTab === 'soar' ? 'active' : ''}`} onClick={() => setActiveTab('soar')}>
            <PlayCircle size={18} /><span>SOAR Engine</span>
          </div>
          <div className={`nav-item ${activeTab === 'ir' ? 'active' : ''}`} onClick={() => setActiveTab('ir')}>
            <Briefcase size={18} /><span>IR Tickets</span>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="main-content">
        <header className="topbar">
          <div className="topbar-title">
            {activeTab === 'fleet' && 'Endpoint Fleet Overview'}
            {activeTab === 'siem' && 'Security Information & Event Management'}
            {activeTab === 'soar' && 'Security Orchestration, Automation, & Response'}
            {activeTab === 'ir' && 'Incident Response Management'}
          </div>
          <div className="user-profile">
            <div className="status-badge" style={{
              color: apiStatus === 'online' ? 'var(--accent-green)' : 'var(--accent-red)',
              backgroundColor: apiStatus === 'online' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
              borderColor: apiStatus === 'online' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)'
            }}>
              <div className="status-dot" style={{backgroundColor: apiStatus === 'online' ? 'var(--accent-green)' : 'var(--accent-red)'}}></div>
              API: {apiStatus.toUpperCase()}
            </div>
          </div>
        </header>

        <div className="content-scroll">
          {activeTab === 'fleet' && renderFleetDashboard()}
          {activeTab === 'siem' && renderSiemDashboard()}
          {activeTab === 'soar' && renderSoarDashboard()}
          {activeTab === 'ir' && <p style={{color: 'var(--text-muted)'}}>IR Module Loading...</p>}
        </div>
      </main>

      {/* Sliding Forensic Panel */}
      {panelOpen && <div className="side-panel-overlay" onClick={() => setPanelOpen(false)}></div>}
      <div className={`side-panel ${panelOpen ? 'open' : ''}`}>
        <div className="panel-header">
          <h2 className="panel-title">{panelContent?.title}</h2>
          <button className="close-btn" onClick={() => setPanelOpen(false)}><X size={24} /></button>
        </div>
        <div className="panel-content">
          <h3 style={{marginBottom: '1rem', color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: '8px'}}>
            <AlertTriangle size={18}/> Request Dispatched
          </h3>
          <p style={{color: 'var(--text-muted)', marginBottom: '2rem'}}>
            The FastAPI endpoint successfully processed the POST request. Automated forensic collection is underway.
          </p>
          
          <div className="data-card">
            <div className="data-card-title">Context Data</div>
            {panelContent?.details.map((d, i) => (
              <div key={i} style={{display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '0.5rem'}}>
                <span style={{color: 'var(--text-muted)'}}>{d.label}</span>
                <span style={{fontWeight: 600, color: 'var(--text-primary)'}}>{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
