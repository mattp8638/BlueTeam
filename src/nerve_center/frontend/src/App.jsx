import { useState, useEffect, useRef } from 'react'
import { Shield, Activity, Monitor, AlertTriangle, PlayCircle, Briefcase, X, Terminal, Cpu, Zap, MessageSquare, Send, Search, CheckCircle2, Lock, RefreshCw, User, Filter, ChevronDown, ChevronRight, AlertOctagon, ShieldAlert, CheckSquare } from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
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

  // SIEM Forensics State
  const [selectedSiemAlert, setSelectedSiemAlert] = useState(null)
  const [siemCorrelateInput, setSiemCorrelateInput] = useState('')
  const [siemCorrelateResult, setSiemCorrelateResult] = useState(null)
  const [isCorrelating, setIsCorrelating] = useState(false)
  const [siemDetailTab, setSiemDetailTab] = useState('tree')

  // SOAR Orchestration State
  const [selectedPlaybook, setSelectedPlaybook] = useState(null)
  const [soarHistory, setSoarHistory] = useState([])
  const [selectedHistoryExecution, setSelectedHistoryExecution] = useState(null)
  const [isSimulatingSoar, setIsSimulatingSoar] = useState(false)
  const [soarSimLog, setSoarSimLog] = useState('')
  const [soarSimStep, setSoarSimStep] = useState(null)

  // Antivirus Quarantine State
  const [quarantineData, setQuarantineData] = useState([])
  const [selectedThreat, setSelectedThreat] = useState(null)
  const [isSandboxing, setIsSandboxing] = useState(false)
  const [sandboxReportText, setSandboxReportText] = useState('')

  // AI Chat generation state
  const [isGeneratingChat, setIsGeneratingChat] = useState(false)

  // IR Filter & Workspace States
  const [irSearch, setIrSearch] = useState('')
  const [irFilterStatus, setIrFilterStatus] = useState('ALL')
  const [irFilterSeverity, setIrFilterSeverity] = useState('ALL')
  const [irDetailTab, setIrDetailTab] = useState('diagnosis')
  const [ledgerVerification, setLedgerVerification] = useState(null)
  const [expandedTimelineIndex, setExpandedTimelineIndex] = useState(null)
  const [isDiagnosing, setIsDiagnosing] = useState(false)

  // IR Detail States
  const [selectedTicketId, setSelectedTicketId] = useState(null)
  const [ticketTimeline, setTicketTimeline] = useState([])
  const [newComment, setNewComment] = useState('')
  const [activeApprovals, setActiveApprovals] = useState({})

  const fetchApprovals = () => {
    fetch('http://127.0.0.1:8000/api/soar/approvals')
      .then(res => res.json())
      .then(setActiveApprovals)
      .catch(console.error)
  }

  const handleApproveAction = async (token) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/soar/approve/${token}?analyst_id=analyst_matt`, { method: 'POST' })
      const data = await res.json()
      if (data.status === 'success') {
        fetchApprovals()
        if (selectedTicketId) {
          fetch(`http://127.0.0.1:8000/api/ir/tickets/${selectedTicketId}/timeline`)
            .then(res => res.json())
            .then(setTicketTimeline)
        }
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleDenyAction = async (token) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/soar/deny/${token}?analyst_id=analyst_matt`, { method: 'POST' })
      const data = await res.json()
      if (data.status === 'success') {
        fetchApprovals()
        if (selectedTicketId) {
          fetch(`http://127.0.0.1:8000/api/ir/tickets/${selectedTicketId}/timeline`)
            .then(res => res.json())
            .then(setTicketTimeline)
        }
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleAddComment = async () => {
    if (!newComment.trim() || !selectedTicketId) return
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/ir/tickets/${selectedTicketId}/update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ comment: newComment, author: 'analyst_matt' })
      })
      const data = await res.json()
      if (data.status === 'success') {
        setNewComment('')
        fetch(`http://127.0.0.1:8000/api/ir/tickets/${selectedTicketId}/timeline`)
          .then(res => res.json())
          .then(setTicketTimeline)
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleResolveTicket = async () => {
    if (!selectedTicketId) return
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/ir/tickets/${selectedTicketId}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assignee: 'analyst_matt' })
      })
      const data = await res.json()
      if (data.status === 'success') {
        fetch('http://127.0.0.1:8000/api/ir/incidents')
          .then(res => res.json())
          .then(setIrData)
        fetch(`http://127.0.0.1:8000/api/ir/tickets/${selectedTicketId}/timeline`)
          .then(res => res.json())
          .then(setTicketTimeline)
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleUpdateStatus = async (ticketId, newStatus) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/ir/tickets/${ticketId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus, author: 'analyst_matt' })
      })
      const data = await res.json()
      if (data.status === 'success') {
        fetch('http://127.0.0.1:8000/api/ir/incidents')
          .then(res => res.json())
          .then(setIrData)
        fetch(`http://127.0.0.1:8000/api/ir/tickets/${ticketId}/timeline`)
          .then(res => res.json())
          .then(setTicketTimeline)
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleUpdateSeverity = async (ticketId, newSeverity) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/ir/tickets/${ticketId}/severity`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity: newSeverity, author: 'analyst_matt' })
      })
      const data = await res.json()
      if (data.status === 'success') {
        fetch('http://127.0.0.1:8000/api/ir/incidents')
          .then(res => res.json())
          .then(setIrData)
        fetch(`http://127.0.0.1:8000/api/ir/tickets/${ticketId}/timeline`)
          .then(res => res.json())
          .then(setTicketTimeline)
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleUpdateAssignee = async (ticketId, newAssignee) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/ir/tickets/${ticketId}/assign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assignee: newAssignee, author: 'analyst_matt' })
      })
      const data = await res.json()
      if (data.status === 'success') {
        fetch('http://127.0.0.1:8000/api/ir/incidents')
          .then(res => res.json())
          .then(setIrData)
        fetch(`http://127.0.0.1:8000/api/ir/tickets/${ticketId}/timeline`)
          .then(res => res.json())
          .then(setTicketTimeline)
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleTriggerAIDiagnosis = async (ticketId) => {
    setIsDiagnosing(true)
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/ir/tickets/${ticketId}/diagnose`, { method: 'POST' })
      const data = await res.json()
      if (data.status === 'success') {
        fetch('http://127.0.0.1:8000/api/ir/incidents')
          .then(res => res.json())
          .then(setIrData)
        fetch(`http://127.0.0.1:8000/api/ir/tickets/${ticketId}/timeline`)
          .then(res => res.json())
          .then(setTicketTimeline)
      } else {
        alert(data.message || 'AI Diagnosis failed.')
      }
    } catch (err) {
      console.error(err)
    } finally {
      setIsDiagnosing(false)
    }
  }

  const handleVerifyLedger = async (ticketId) => {
    setLedgerVerification({ loading: true, verified: false, message: 'Verifying cryptographic chain...' })
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/ir/tickets/${ticketId}/verify`)
      const data = await res.json()
      if (data.status === 'success') {
        setLedgerVerification({
          loading: false,
          verified: data.verified,
          message: data.message,
          blockCount: data.block_count,
          rootHash: data.root_hash
        })
      } else {
        setLedgerVerification({
          loading: false,
          verified: false,
          message: 'Error verifying ledger: ' + data.message
        })
      }
    } catch (err) {
      setLedgerVerification({
        loading: false,
        verified: false,
        message: 'Network error verifying ledger.'
      })
      console.error(err)
    }
  }

  useEffect(() => {
    if (selectedTicketId) {
      setLedgerVerification(null)
      setExpandedTimelineIndex(null)
      fetch(`http://127.0.0.1:8000/api/ir/tickets/${selectedTicketId}/timeline`)
        .then(res => res.json())
        .then(setTicketTimeline)
        .catch(console.error)
      fetchApprovals()
    }
  }, [selectedTicketId])

  useEffect(() => {
    if (activeTab === 'ir') {
      fetchApprovals()
      const interval = setInterval(fetchApprovals, 3000)
      return () => clearInterval(interval)
    }
  }, [activeTab, selectedTicketId])


  // Panel State
  const [panelOpen, setPanelOpen] = useState(false)
  const [panelContent, setPanelContent] = useState(null)
  const [telemetryLogs, setTelemetryLogs] = useState([])
  const consoleRef = useRef(null)

  // Chat State
  const [chatOpen, setChatOpen] = useState(false)
  const [chatMessages, setChatMessages] = useState([{role: 'ai', text: 'Hello, I am the Nerve Center AI. How can I assist you with your security operations today?'}])
  const [chatInput, setChatInput] = useState('')

  const handleSendMessage = async (customText = null) => {
    const textToSend = typeof customText === 'string' ? customText : chatInput
    if (!textToSend.trim()) return
    
    const userMsg = { role: 'user', text: textToSend }
    setChatMessages(prev => [...prev, userMsg])
    setChatInput('')
    setIsGeneratingChat(true)

    try {
      const res = await fetch('http://127.0.0.1:8000/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMsg.text })
      })
      const data = await res.json()
      if (data.status === 'ok') {
        setChatMessages(prev => [...prev, { role: 'ai', text: data.response }])
      }
    } catch (err) {
      console.error(err)
      setChatMessages(prev => [...prev, { role: 'ai', text: 'Error connecting to AI backend.' }])
    } finally {
      setIsGeneratingChat(false)
    }
  }

  const handleSendQuickChip = (text) => {
    setChatOpen(true)
    handleSendMessage(text)
  }

  const handleSiemCorrelate = async () => {
    if (!siemCorrelateInput.trim()) return
    setIsCorrelating(true)
    setSiemCorrelateResult(null)
    try {
      const res = await fetch('http://127.0.0.1:8000/api/siem/correlate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_log: siemCorrelateInput })
      })
      const data = await res.json()
      if (data.status === 'success') {
        setSiemCorrelateResult(data.event)
      }
    } catch (err) {
      console.error(err)
    } finally {
      setIsCorrelating(false)
    }
  }

  const handleSimulatePlaybook = async (playbook) => {
    if (!playbook) return
    setIsSimulatingSoar(true)
    setSoarSimLog('[*] Initializing CACAO Playbook Simulator...\n')
    setSoarSimStep('start')
    
    try {
      const target = playbook.name.includes('Malware') ? '10.0.0.15' : '10.0.0.88'
      const res = await fetch('http://127.0.0.1:8000/api/soar/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ playbook_name: playbook.name, target_ip: target })
      })
      const data = await res.json()
      if (data.status === 'success') {
        const steps = data.log.split('\n')
        let currentLog = ''
        for (let i = 0; i < steps.length; i++) {
          await new Promise(resolve => setTimeout(resolve, 800))
          currentLog += steps[i] + '\n'
          setSoarSimLog(currentLog)
          
          const stepLine = steps[i].toLowerCase()
          if (stepLine.includes('verify-entropy') || stepLine.includes('entropy')) {
            setSoarSimStep('verify-entropy')
          } else if (stepLine.includes('evaluate-risk') || stepLine.includes('risk')) {
            setSoarSimStep('evaluate-risk')
          } else if (stepLine.includes('quarantine-file') || stepLine.includes('quarantine')) {
            setSoarSimStep('quarantine-file')
          } else if (stepLine.includes('isolate-host') || stepLine.includes('isolated')) {
            setSoarSimStep('isolate-host')
          } else if (stepLine.includes('check-patch') || stepLine.includes('patch')) {
            setSoarSimStep('check-patch')
          } else if (stepLine.includes('deploy-patch') || stepLine.includes('pushing kb')) {
            setSoarSimStep('deploy-patch')
          } else if (stepLine.includes('verify-mitigation') || stepLine.includes('forensic scan confirms')) {
            setSoarSimStep('verify-mitigation')
          } else if (stepLine.includes('complete') || stepLine.includes('completed successfully')) {
            setSoarSimStep('complete')
          }
        }
        
        // Refresh history list
        fetch('http://127.0.0.1:8000/api/soar/history')
          .then(res => res.json())
          .then(setSoarHistory)
          .catch(console.error)
      }
    } catch (err) {
      console.error(err)
      setSoarSimLog(prev => prev + '\n[Error] Simulation pipeline connection failed.\n')
    } finally {
      setIsSimulatingSoar(false)
    }
  }

  const handleSandboxThreat = async (threat) => {
    if (!threat) return
    setIsSandboxing(true)
    setSandboxReportText('')
    
    const preSteps = [
      "[*] Bootstrapping dynamic sandbox analyzer context...",
      "[*] Mounting virtualized PE32+ host container (Windows 11 Enterprise)...",
      "[*] Setting registry file system filters...",
      "[*] Injecting binary: " + threat.name + " (" + threat.hash.substring(0, 16) + "...)",
      "[*] Triggering payload and hooking Win32 process API callbacks..."
    ]
    
    let tempLog = ''
    for (let i = 0; i < preSteps.length; i++) {
      tempLog += preSteps[i] + '\n'
      setSandboxReportText(tempLog)
      await new Promise(resolve => setTimeout(resolve, 500))
    }

    try {
      const res = await fetch(`http://127.0.0.1:8000/api/av/quarantine/${threat.hash}/sandbox`, { method: 'POST' })
      const data = await res.json()
      if (data.status === 'success') {
        tempLog += "\n[+] Virtual execution completed. Generating behavior matrix:\n\n" + data.report
        setSandboxReportText(tempLog)
        
        // Refresh vault lists
        fetch('http://127.0.0.1:8000/api/av/quarantine')
          .then(res => res.json())
          .then(newList => {
            setQuarantineData(newList)
            const updated = newList.find(t => t.hash === threat.hash)
            if (updated) setSelectedThreat(updated)
          })
          .catch(console.error)
      }
    } catch (err) {
      console.error(err)
      setSandboxReportText(prev => prev + "\n[-] Sandbox virtual hardware interface connection failed.\n")
    } finally {
      setIsSandboxing(false)
    }
  }

  const handleDeleteThreat = async (threat) => {
    if (!threat) return
    if (!confirm(`Are you sure you want to permanently delete quarantined threat '${threat.name}' from target endpoint?`)) return
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/av/quarantine/${threat.hash}/delete`, { method: 'POST' })
      const data = await res.json()
      if (data.status === 'success') {
        setSelectedThreat(null)
        fetch('http://127.0.0.1:8000/api/av/quarantine')
          .then(res => res.json())
          .then(setQuarantineData)
          .catch(console.error)
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleRestoreThreat = async (threat) => {
    if (!threat) return
    if (!confirm(`Are you sure you want to restore file '${threat.name}' from quarantine to its original location?`)) return
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/av/quarantine/${threat.hash}/restore`, { method: 'POST' })
      const data = await res.json()
      if (data.status === 'success') {
        fetch('http://127.0.0.1:8000/api/av/quarantine')
          .then(res => res.json())
          .then(newList => {
            setQuarantineData(newList)
            const updated = newList.find(t => t.hash === threat.hash)
            if (updated) setSelectedThreat(updated)
          })
          .catch(console.error)
      }
    } catch (err) {
      console.error(err)
    }
  }


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
      fetch('http://127.0.0.1:8000/api/soar/history').then(res => res.json()).then(setSoarHistory).catch(console.error)
    } else if (activeTab === 'ir') {
      fetch('http://127.0.0.1:8000/api/ir/incidents').then(res => res.json()).then(setIrData).catch(console.error)
    } else if (activeTab === 'av') {
      fetch('http://127.0.0.1:8000/api/fleet').then(res => res.json()).then(setFleetData).catch(console.error)
      fetch('http://127.0.0.1:8000/api/av/quarantine').then(res => res.json()).then(setQuarantineData).catch(console.error)
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
  }, [activeTab, fleetData, irData])

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

  // Format AI Assistant Messages
  const formatChatMessage = (text) => {
    if (!text) return '';
    return text.split('\n').map((line, idx) => {
      let formatted = line;
      const boldRegex = /\*\*(.*?)\*\*/g;
      let match;
      const parts = [];
      let lastIndex = 0;
      
      while ((match = boldRegex.exec(line)) !== null) {
        parts.push(line.substring(lastIndex, match.index));
        parts.push(<strong key={match.index}>{match[1]}</strong>);
        lastIndex = boldRegex.lastIndex;
      }
      parts.push(line.substring(lastIndex));
      
      return (
        <div key={idx} style={{ marginBottom: '4px', minHeight: '18px' }}>
          {parts.map((p, i) => {
            if (typeof p === 'string') {
              const codeRegex = /`(.*?)`/g;
              let codeMatch;
              const codeParts = [];
              let lastCodeIndex = 0;
              while ((codeMatch = codeRegex.exec(p)) !== null) {
                codeParts.push(p.substring(lastCodeIndex, codeMatch.index));
                codeParts.push(<code key={codeMatch.index} style={{ backgroundColor: 'rgba(0,0,0,0.3)', padding: '2px 4px', borderRadius: '4px', fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{codeMatch[1]}</code>);
                lastCodeIndex = codeRegex.lastIndex;
              }
              codeParts.push(p.substring(lastCodeIndex));
              return codeParts;
            }
            return p;
          })}
        </div>
      );
    });
  };

  // Renderers
  const renderAntivirusDashboard = () => {
    return (
      <div className="ir-workspace fade-in">
        {/* Left Column: Fleet Antivirus agents + Quarantine vault list */}
        <div className="ir-sidebar glass-panel" style={{ width: '45%' }}>
          <div className="ir-sidebar-header">
            <h3>Quarantine Threat Vault</h3>
            <span className="badge badge-red">{quarantineData.filter(t => t.status === 'QUARANTINED').length} active threats</span>
          </div>

          <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1.25rem', flex: 1, overflowY: 'auto' }}>
            {/* Fleet AV Agent Status */}
            <div>
              <h4 style={{ fontSize: '0.85rem', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.5rem', fontWeight: 700, letterSpacing: '0.5px' }}>Fleet Protection Agents</h4>
              <div className="table-container">
                <table className="data-table" style={{ fontSize: '0.75rem' }}>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Host</th>
                      <th>AV Hits</th>
                      <th>Scan</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fleetData.map(agent => (
                      <tr key={agent.id}>
                        <td>
                          <div className={`status-badge ${agent.status === 'online' ? 'status-green' : 'status-red'}`} style={{ fontSize: '0.65rem', padding: '1px 4px' }}>
                            {agent.status.toUpperCase()}
                          </div>
                        </td>
                        <td style={{ fontWeight: 600 }}>{agent.hostname}</td>
                        <td>{agent.av_hits > 0 ? <span className="badge badge-red" style={{ padding: '1px 5px', fontSize: '0.7rem' }}>{agent.av_hits}</span> : '0'}</td>
                        <td>
                          <button 
                            className="btn-action" 
                            style={{ fontSize: '0.7rem', padding: '2px 6px' }} 
                            onClick={() => handleInvestigate(agent)}
                          >
                            Scan
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Quarantined Threat Vault List */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>
              <h4 style={{ fontSize: '0.85rem', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.5rem', fontWeight: 700, letterSpacing: '0.5px' }}>Threat Quarantine Vault</h4>
              <div className="table-container" style={{ flex: 1, overflowY: 'auto' }}>
                <table className="data-table" style={{ fontSize: '0.75rem' }}>
                  <thead>
                    <tr>
                      <th>Filename / Threat</th>
                      <th>Host</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {quarantineData.map((threat, idx) => {
                      const isThreatSelected = selectedThreat?.hash === threat.hash;
                      return (
                        <tr 
                          key={idx} 
                          className={`clickable-tr ${isThreatSelected ? 'selected' : ''}`}
                          onClick={() => {
                            setSelectedThreat(threat);
                            setSandboxReportText(threat.sandbox_report || '');
                          }}
                          style={{ cursor: 'pointer' }}
                        >
                          <td>
                            <div style={{ fontWeight: 600 }}>{threat.name}</div>
                            <div style={{ fontSize: '0.7rem', color: 'var(--accent-purple)' }}>{threat.threat}</div>
                          </td>
                          <td>{threat.hostname}</td>
                          <td>
                            <span className={`badge ${threat.status === 'QUARANTINED' ? 'badge-red animate-pulse' : 'badge-gray'}`} style={{ fontSize: '0.65rem', padding: '1px 4px' }}>
                              {threat.status}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Sandbox terminal + threat controls */}
        <div className="ir-details glass-panel" style={{ width: '55%' }}>
          {selectedThreat ? (
            <div className="ir-details-scroll">
              <div className="ir-details-header" style={{ paddingBottom: '1rem', marginBottom: '1rem' }}>
                <div style={{ flex: 1 }}>
                  <div className="ir-details-id-row">
                    <span className="case-id-badge">THREAT ENVELOPE</span>
                    <span className={`badge ${selectedThreat.status === 'QUARANTINED' ? 'badge-red' : 'badge-gray'}`}>
                      {selectedThreat.status}
                    </span>
                  </div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: '6px 0' }}>{selectedThreat.name}</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    SHA-256: {selectedThreat.hash}
                  </p>
                </div>
                
                <div style={{ display: 'flex', gap: '6px' }}>
                  <button 
                    className="btn-action" 
                    onClick={() => handleSandboxThreat(selectedThreat)}
                    disabled={isSandboxing}
                    style={{ whiteSpace: 'nowrap' }}
                  >
                    {isSandboxing ? 'Analyzing...' : 'Submit to Sandbox'}
                  </button>
                  <button 
                    className="btn-approve-glow" 
                    style={{ background: 'var(--accent-purple)', whiteSpace: 'nowrap' }} 
                    onClick={() => handleRestoreThreat(selectedThreat)}
                  >
                    Restore File
                  </button>
                  <button 
                    className="btn-deny" 
                    style={{ padding: '6px 12px', whiteSpace: 'nowrap' }} 
                    onClick={() => handleDeleteThreat(selectedThreat)}
                  >
                    Delete File
                  </button>
                </div>
              </div>

              {/* Threat Details */}
              <div className="data-card" style={{ marginBottom: '1rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.8rem' }}>
                <div>
                  <div style={{ marginBottom: '4px' }}><span style={{ color: 'var(--text-muted)' }}>Original Path:</span> <code style={{ color: 'white' }}>{selectedThreat.path}</code></div>
                  <div style={{ marginBottom: '4px' }}><span style={{ color: 'var(--text-muted)' }}>Device / Host:</span> <strong>{selectedThreat.hostname} ({selectedThreat.ip})</strong></div>
                </div>
                <div>
                  <div style={{ marginBottom: '4px' }}><span style={{ color: 'var(--text-muted)' }}>Detection Signature:</span> <strong style={{ color: 'var(--accent-red)' }}>{selectedThreat.threat}</strong></div>
                  <div style={{ marginBottom: '4px' }}><span style={{ color: 'var(--text-muted)' }}>Classification Confidence:</span> <strong>{(selectedThreat.confidence * 100).toFixed(0)}%</strong></div>
                </div>
              </div>

              {/* Sandbox terminal window */}
              <div className="playbook-terminal-card" style={{ flex: 1, minHeight: '300px' }}>
                <div className="terminal-header" style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Terminal size={12} />
                    <span>FORENSIC BEHAVIORAL SANDBOX: VM-01</span>
                  </div>
                  <div style={{ display: 'flex', gap: '4px' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#ef4444' }}></span>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#f59e0b' }}></span>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981' }}></span>
                  </div>
                </div>
                <div className="terminal-body font-monospace" style={{ flex: 1, overflowY: 'auto', fontSize: '0.85rem', color: '#10b981', backgroundColor: '#05070f' }}>
                  {sandboxReportText ? (
                    sandboxReportText.split('\n').map((line, idx) => (
                      <div key={idx} style={{ marginBottom: '4px', whiteSpace: 'pre-wrap' }}>{line}</div>
                    ))
                  ) : (
                    <div style={{ color: 'var(--text-muted)' }}>
                      [*] Sandbox is offline.
                      <br />
                      [*] Click \'Submit to Sandbox\' above to initialize VM and run dynamic PE behavioral analysis on {selectedThreat.name}.
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', padding: '2rem', textAlign: 'center' }}>
              <Shield size={48} style={{ color: 'var(--text-muted)', marginBottom: '1rem', opacity: 0.5 }} />
              <h3>Dynamic Malware Analyzer Console</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', maxWidth: '350px', marginTop: '8px' }}>
                Select a threat from the vault list in the left column to view original metadata, trigger file quarantine restore/purge commands, or execute the binary inside a virtualized dynamic sandbox environment.
              </p>
            </div>
          )}
        </div>
      </div>
    );
  }

  const renderIrDashboard = () => {
    const currentTicket = irData.find(t => t.id === selectedTicketId)
    
    // Find active pending SOAR approvals
    const pendingApproval = Object.keys(activeApprovals)
      .map(key => ({ token: key, ...activeApprovals[key] }))
      .find(appr => appr.ticket_id === selectedTicketId && appr.status === 'PENDING')

    // Filter incidents in sidebar
    const filteredIncidents = irData.filter(ticket => {
      const matchesSearch = !irSearch || 
        ticket.title.toLowerCase().includes(irSearch.toLowerCase()) || 
        ticket.id.toLowerCase().includes(irSearch.toLowerCase())
      
      const matchesStatus = irFilterStatus === 'ALL' || 
        ticket.status.toUpperCase() === irFilterStatus
        
      const matchesSeverity = irFilterSeverity === 'ALL' || 
        ticket.severity.toUpperCase() === irFilterSeverity

      return matchesSearch && matchesStatus && matchesSeverity
    })

    // Extract AI Classification & Confidence
    let aiClassification = null
    let aiConfidence = null
    
    const aiDiagnosisEvent = ticketTimeline.find(item => 
      item.action_type === 'AI_DIAGNOSIS' || 
      (item.action_type === 'TICKET_CREATE' && item.payload.ai_diagnosis)
    )
    
    if (aiDiagnosisEvent) {
      if (aiDiagnosisEvent.action_type === 'AI_DIAGNOSIS') {
        aiClassification = aiDiagnosisEvent.payload.classification
        aiConfidence = aiDiagnosisEvent.payload.confidence
      } else {
        const alertPayload = aiDiagnosisEvent.payload
        if (alertPayload.ai_analysis) {
          aiClassification = alertPayload.ai_analysis.classification
          aiConfidence = alertPayload.ai_analysis.confidence
        }
      }
    }
    
    if (!aiClassification && currentTicket && currentTicket.title) {
      const match = currentTicket.title.match(/AI Flagged Threat:\s*([A-Z_]+)\s*\(Confidence:\s*([\d\.]+)%\)/i)
      if (match) {
        aiClassification = match[1].toLowerCase()
        aiConfidence = parseFloat(match[2]) / 100
      }
    }

    const mitrePhases = [
      { id: 'scanning', label: 'Scanning' },
      { id: 'reconnaissance', label: 'Reconnaissance' },
      { id: 'gaining_access', label: 'Initial Access' },
      { id: 'maintaining_access', label: 'Persistence' },
      { id: 'covering_tracks', label: 'Covering Tracks' }
    ]

    // Find playbook data
    const playbookEvent = ticketTimeline.find(item => item.action_type === 'SOAR_PLAYBOOK_GENERATED')
    const playbookMarkdown = playbookEvent ? playbookEvent.payload.playbook_markdown : null
    const playbookName = playbookEvent ? playbookEvent.payload.playbook_name : "Dynamic Containment Playbook"

    // Simple markdown renderer helper
    const renderMarkdownAsHtml = (mdText) => {
      if (!mdText) return <p style={{color: 'var(--text-muted)'}}>No active playbook workflow generated.</p>
      return mdText.split('\n').map((line, idx) => {
        if (line.startsWith('# ')) {
          return <h3 key={idx} className="pb-h1" style={{fontSize: '1.2rem', fontWeight: 700, margin: '12px 0 6px', color: 'white'}}>{line.substring(2)}</h3>
        }
        if (line.startsWith('## ')) {
          return <h4 key={idx} className="pb-h2" style={{fontSize: '1.05rem', fontWeight: 600, margin: '10px 0 4px', color: 'var(--accent-blue)'}}>{line.substring(3)}</h4>
        }
        if (line.startsWith('### ')) {
          return <h5 key={idx} className="pb-h3" style={{fontSize: '0.95rem', fontWeight: 600, margin: '8px 0 4px', color: 'var(--text-primary)'}}>{line.substring(4)}</h5>
        }
        if (line.startsWith('- ')) {
          return <li key={idx} className="pb-bullet" style={{marginLeft: '15px', color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '3px'}}>{line.substring(2)}</li>
        }
        if (line.trim() === '---') {
          return <hr key={idx} className="pb-divider" style={{border: 'none', borderTop: '1px solid var(--border-light)', margin: '12px 0'}} />
        }
        return <p key={idx} className="pb-text" style={{fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '4px'}}>{line}</p>
      })
    }

    return (
      <div className="ir-workspace fade-in">
        {/* Left Pane: Filtered Ticket List */}
        <div className="ir-sidebar glass-panel">
          <div className="ir-sidebar-header">
            <h3>Security Incidents</h3>
            <span className="badge badge-gray">{filteredIncidents.length} / {irData.length}</span>
          </div>
          
          <div className="ir-sidebar-filters">
            <div className="ir-search-container">
              <Search size={14} className="ir-search-icon" />
              <input
                type="text"
                placeholder="Search Cases..."
                value={irSearch}
                onChange={(e) => setIrSearch(e.target.value)}
                className="ir-search-input"
              />
            </div>
            
            <div className="ir-filter-row">
              <div className="filter-select-wrapper">
                <Filter size={10} style={{marginRight: '4px'}} />
                <select 
                  value={irFilterStatus} 
                  onChange={(e) => setIrFilterStatus(e.target.value)}
                  className="filter-select"
                >
                  <option value="ALL">Status: All</option>
                  <option value="OPEN">Open</option>
                  <option value="INVESTIGATING">Investigating</option>
                  <option value="RESOLVED">Resolved</option>
                </select>
              </div>

              <div className="filter-select-wrapper">
                <select 
                  value={irFilterSeverity} 
                  onChange={(e) => setIrFilterSeverity(e.target.value)}
                  className="filter-select"
                >
                  <option value="ALL">Severity: All</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
            </div>
          </div>

          <div className="ir-tickets-list-scroll">
            {filteredIncidents.length === 0 ? (
              <div className="no-tickets-found">No incidents match current filters.</div>
            ) : (
              filteredIncidents.map((ticket, idx) => {
                const isSelected = ticket.id === selectedTicketId
                const isAI = ticket.title && (ticket.title.includes("AI") || ticket.title.includes("Threat"))
                return (
                  <div 
                    key={idx} 
                    className={`ir-ticket-card ${isSelected ? 'selected' : ''}`}
                    onClick={() => setSelectedTicketId(ticket.id)}
                  >
                    <div className="ir-ticket-card-header">
                      <span className={`badge ${
                        ticket.severity === 'Critical' ? 'badge-red font-bold animate-pulse' : 
                        ticket.severity === 'High' ? 'badge-red' : 
                        ticket.severity === 'Medium' ? 'badge-yellow' : 'badge-gray'
                      }`}>
                        {ticket.severity.toUpperCase()}
                      </span>
                      <span className={`status-badge ${
                        ticket.status.toUpperCase() === 'RESOLVED' ? 'status-green' : 'status-red'
                      }`}>
                        {ticket.status.toUpperCase()}
                      </span>
                    </div>
                    <h4 className="ir-ticket-card-title">
                      {isAI && <Cpu size={13} style={{color: 'var(--accent-purple)', marginRight: '5px', display: 'inline'}} className="ai-icon-spin" />}
                      {ticket.title}
                    </h4>
                    <div className="ir-ticket-card-meta">
                      <span style={{fontFamily: 'monospace'}}>ID: {ticket.id.substring(0, 8)}...</span>
                      <span style={{display: 'flex', alignItems: 'center', gap: '3px'}}>
                        <User size={11} /> {ticket.assignee || 'Unassigned'}
                      </span>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Right Pane: Incident Details Workspace */}
        <div className="ir-details glass-panel">
          {currentTicket ? (
            <div className="ir-details-scroll">
              
              {/* Header Info & Metadata Controllers */}
              <div className="ir-details-header">
                <div style={{flex: 1}}>
                  <div className="ir-details-id-row">
                    <span className="case-id-badge">CASE-ID: {currentTicket.id}</span>
                  </div>
                  <h2 style={{fontSize: '1.4rem', fontWeight: 700, margin: '8px 0'}}>{currentTicket.title}</h2>
                  <p style={{color: 'var(--text-muted)', fontSize: '0.8rem'}}>
                    Genesis Timestamp: <span style={{fontFamily: 'monospace'}}>{currentTicket.created_at || 'N/A'}</span>
                  </p>
                </div>
                
                {/* Interactive Select Overrides */}
                <div className="ir-meta-controls">
                  <div className="control-group">
                    <label>Status</label>
                    <select 
                      value={currentTicket.status.toUpperCase()} 
                      onChange={(e) => handleUpdateStatus(currentTicket.id, e.target.value)}
                      className="control-select"
                    >
                      <option value="OPEN">Open</option>
                      <option value="INVESTIGATING">Investigating</option>
                      <option value="RESOLVED">Resolved</option>
                    </select>
                  </div>

                  <div className="control-group">
                    <label>Severity</label>
                    <select 
                      value={currentTicket.severity} 
                      onChange={(e) => handleUpdateSeverity(currentTicket.id, e.target.value)}
                      className="control-select"
                    >
                      <option value="Critical">Critical</option>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                    </select>
                  </div>

                  <div className="control-group">
                    <label>Assignee</label>
                    <select 
                      value={currentTicket.assignee || 'Unassigned'} 
                      onChange={(e) => handleUpdateAssignee(currentTicket.id, e.target.value)}
                      className="control-select"
                    >
                      <option value="Unassigned">Unassigned</option>
                      <option value="analyst_matt">Matt (Me)</option>
                      <option value="analyst_alice">Alice</option>
                      <option value="analyst_bob">Bob</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Workspace Navigation Tabs */}
              <div className="ir-workspace-tabs">
                <button 
                  className={`tab-btn ${irDetailTab === 'diagnosis' ? 'active' : ''}`}
                  onClick={() => setIrDetailTab('diagnosis')}
                >
                  <Cpu size={14} /> Overview & Diagnosis
                </button>
                <button 
                  className={`tab-btn ${irDetailTab === 'ledger' ? 'active' : ''}`}
                  onClick={() => setIrDetailTab('ledger')}
                >
                  <Shield size={14} /> Cryptographic Audit Ledger
                </button>
                <button 
                  className={`tab-btn ${irDetailTab === 'comments' ? 'active' : ''}`}
                  onClick={() => setIrDetailTab('comments')}
                >
                  <MessageSquare size={14} /> Analyst Notes ({ticketTimeline.filter(i => i.action_type === 'TICKET_UPDATE').length})
                </button>
              </div>

              {/* TAB 1 CONTENT: AI Diagnosis & Playbooks */}
              {irDetailTab === 'diagnosis' && (
                <div className="tab-pane-content fade-in" style={{display: 'flex', flexDirection: 'column', gap: '1.5rem'}}>
                  
                  {/* AI Report Card */}
                  <div className="ai-report-flex-card">
                    <div className="ai-gauge-sec">
                      {aiConfidence ? (
                        <div className="gauge-ring-wrapper">
                          <svg width="80" height="80" viewBox="0 0 36 36" className="gauge-svg">
                            <path
                              className="gauge-bg"
                              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                              fill="none"
                              stroke="rgba(255,255,255,0.05)"
                              strokeWidth="3.5"
                            />
                            <path
                              className="gauge-fill-purple"
                              strokeDasharray={`${aiConfidence * 100}, 100`}
                              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                              fill="none"
                              stroke="var(--accent-purple)"
                              strokeWidth="3.5"
                              strokeLinecap="round"
                            />
                          </svg>
                          <div className="gauge-text font-bold">{(aiConfidence * 100).toFixed(0)}%</div>
                        </div>
                      ) : (
                        <div className="no-gauge-placeholder">
                          <ShieldAlert size={32} style={{color: 'var(--text-muted)'}} />
                        </div>
                      )}
                    </div>
                    
                    <div className="ai-diagnosis-details-col" style={{flex: 1}}>
                      <div className="ai-details-header-row">
                        <span className="ai-indicator-chip"><Cpu size={11} className="ai-icon-spin" /> AI Diagnosis Engine</span>
                        <button 
                          className="btn-trigger-diagnose" 
                          onClick={() => handleTriggerAIDiagnosis(currentTicket.id)}
                          disabled={isDiagnosing}
                        >
                          <RefreshCw size={12} className={isDiagnosing ? 'animate-spin' : ''} /> 
                          {isDiagnosing ? 'Running...' : aiClassification ? 'Re-run AI Diagnosis' : 'Run AI Diagnosis'}
                        </button>
                      </div>
                      
                      {aiClassification ? (
                        <div>
                          <h4 style={{fontSize: '1rem', fontWeight: 650, color: 'var(--text-primary)', margin: '6px 0'}}>
                            MITRE ATT&CK Phase Mapped: <span style={{color: 'var(--accent-purple)', textTransform: 'capitalize'}}>{aiClassification.replace(/_/g, ' ')}</span>
                          </h4>
                          <p style={{fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.4}}>
                            The local <code>model.safetensors</code> neural network analyzed the telemetry payload and predicted this classification stage with high-entropy correlation, automatically mapping containment sequences to mitigate the threat vector.
                          </p>
                        </div>
                      ) : (
                        <div>
                          <h4 style={{fontSize: '1rem', fontWeight: 650, color: 'var(--text-muted)', margin: '6px 0'}}>Awaiting AI Diagnosis Scan</h4>
                          <p style={{fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.4}}>
                            This ticket was initialized via static rules or manual triage. Trigger the local Roberta sequence classifier model to execute cognitive forensics.
                          </p>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* MITREATT&CK Phase Pipeline */}
                  {aiClassification && (
                    <div className="mitre-pipeline-container">
                      <div className="pipeline-title">MITRE ATT&CK® Attack Stage Visualization</div>
                      <div className="pipeline-stages">
                        {mitrePhases.map((phase, idx) => {
                          const isActive = aiClassification.toLowerCase() === phase.id
                          return (
                            <div key={idx} className={`pipeline-stage-node ${isActive ? 'active' : ''}`}>
                              <div className="node-dot">
                                {isActive && <div className="node-dot-inner animate-ping"></div>}
                              </div>
                              <span className="node-label">{phase.label}</span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* Playbook Container & Action Approval */}
                  <div className="playbook-mitigation-grid">
                    
                    {/* Intercepted SOAR Action Approval */}
                    <div className="soar-approval-card-wrapper" style={{flex: 1}}>
                      {pendingApproval ? (
                        <div className="approval-card animate-pulse-border">
                          <div className="approval-card-title-row">
                            <AlertTriangle size={18} style={{color: 'var(--accent-yellow)'}} />
                            <span>INTERCEPTED HIGH-RISK ACTION REQUIRE SIGNATURE</span>
                          </div>
                          
                          <p style={{color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '8px 0'}}>
                            The automated AI containment protocol proposed a disruptive host containment block. Execution is paused until manual approval is submitted:
                          </p>
                          
                          <div className="approval-box-details">
                            <div className="details-entry">
                              <span className="detail-lbl">Mitigation Action:</span>
                              <span className="detail-val font-monospace" style={{color: 'var(--accent-red)'}}>{pendingApproval.command}</span>
                            </div>
                            <div className="details-entry">
                              <span className="detail-lbl">Target Domain:</span>
                              <span className="detail-val font-monospace">{pendingApproval.step_id}</span>
                            </div>
                            <div className="details-entry">
                              <span className="detail-lbl">Cryptographic Request Token:</span>
                              <span className="detail-val font-monospace" style={{color: 'var(--accent-blue)'}}>{pendingApproval.token}</span>
                            </div>
                          </div>
                          
                          <div className="approval-actions-flex">
                            <button className="btn-approve-glow" onClick={() => handleApproveAction(pendingApproval.token)}>
                              <CheckCircle2 size={14} /> Approve & Authorize Action
                            </button>
                            <button className="btn-deny-border" onClick={() => handleDenyAction(pendingApproval.token)}>
                              <X size={14} /> Deny & Abort Action
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="no-pending-approvals-card">
                          <CheckSquare size={24} style={{color: 'var(--accent-green)', marginBottom: '8px'}} />
                          <h4>No Pending Gateway Blocks</h4>
                          <p style={{fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px'}}>
                            No high-risk actions are currently paused. The playbook executes low-risk discovery scripts automatically.
                          </p>
                        </div>
                      )}
                    </div>

                    {/* Playbook Terminal Block */}
                    <div className="playbook-terminal-card" style={{flex: 1.2}}>
                      <div className="terminal-header">
                        <Terminal size={12} />
                        <span>COGNITIVE PLAYBOOK ENGINE: {playbookName}</span>
                      </div>
                      <div className="terminal-body font-monospace">
                        {renderMarkdownAsHtml(playbookMarkdown)}
                      </div>
                    </div>

                  </div>

                </div>
              )}

              {/* TAB 2 CONTENT: Merkle Ledger Timelines */}
              {irDetailTab === 'ledger' && (
                <div className="tab-pane-content fade-in" style={{display: 'flex', flexDirection: 'column', gap: '1.5rem'}}>
                  
                  {/* Integrity Audit Trigger Bar */}
                  <div className="ledger-integrity-status-bar">
                    <div className="ledger-integrity-info">
                      <h4 style={{fontSize: '1rem', fontWeight: 650, display: 'flex', alignItems: 'center', gap: '6px'}}>
                        <Lock size={15} style={{color: 'var(--accent-blue)'}} /> Cryptographic Chain Verification Ledger
                      </h4>
                      <p style={{color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '4px'}}>
                        Every step of the incident is hashed sequentially using SHA-256 where <code>H(Block_N) = SHA256(Payload || H(Block_N-1))</code>.
                      </p>
                    </div>
                    <button className="btn-verify-ledger" onClick={() => handleVerifyLedger(currentTicket.id)}>
                      <Shield size={14} style={{marginRight: '6px'}} /> Verify Chain Integrity
                    </button>
                  </div>

                  {/* Verification Result Banner */}
                  {ledgerVerification && (
                    <div className={`ledger-result-banner fade-in ${ledgerVerification.verified ? 'verified-green' : 'failed-red'}`}>
                      {ledgerVerification.loading ? (
                        <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                          <RefreshCw size={16} className="animate-spin" />
                          <span>Executing ledger block mathematical signature audits...</span>
                        </div>
                      ) : ledgerVerification.verified ? (
                        <div style={{display: 'flex', flexDirection: 'column', gap: '6px'}}>
                          <div style={{display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700}}>
                            <CheckCircle2 size={18} />
                            <span>TAMPER-PROOF LEDGER CHAIN VALIDATED</span>
                          </div>
                          <div style={{fontSize: '0.8rem', opacity: 0.9, fontFamily: 'monospace'}}>
                            Verification Status: 100% Secure | Blocks Checked: {ledgerVerification.blockCount} | Root Hash: {ledgerVerification.rootHash}
                          </div>
                        </div>
                      ) : (
                        <div style={{display: 'flex', flexDirection: 'column', gap: '6px'}}>
                          <div style={{display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700}}>
                            <AlertOctagon size={18} />
                            <span>LEDGER CORRUPTION DETECTED</span>
                          </div>
                          <div style={{fontSize: '0.8rem', opacity: 0.9}}>
                            {ledgerVerification.message}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Collapsible Ledger Timeline */}
                  <div className="timeline-section" style={{border: 'none', paddingTop: 0}}>
                    <div className="timeline-list">
                      {ticketTimeline.map((item, idx) => {
                        const isExpanded = expandedTimelineIndex === idx
                        return (
                          <div key={idx} className="timeline-item-wrapper block-card">
                            <div className="timeline-icon-col">
                              <div className={`timeline-icon-badge ${item.action_type}`}>
                                {item.action_type.includes('CREATE') && <Shield size={14} />}
                                {item.action_type.includes('ESCALATE') && <ShieldAlert size={14} />}
                                {item.action_type.includes('UPDATE') && <MessageSquare size={14} />}
                                {item.action_type.includes('APPROVED') && <CheckCircle2 size={14} />}
                                {item.action_type.includes('DENIED') && <X size={14} />}
                                {item.action_type.includes('RESOLVE') && <CheckSquare size={14} />}
                                {item.action_type.includes('ASSIGN') && <User size={14} />}
                                {item.action_type.includes('DIAGNOSIS') && <Cpu size={14} />}
                                {!item.action_type.includes('CREATE') && !item.action_type.includes('ESCALATE') && !item.action_type.includes('UPDATE') && !item.action_type.includes('APPROVED') && !item.action_type.includes('DENIED') && !item.action_type.includes('RESOLVE') && !item.action_type.includes('ASSIGN') && !item.action_type.includes('DIAGNOSIS') && <Activity size={14} />}
                              </div>
                              {idx < ticketTimeline.length - 1 && <div className="timeline-connector-line"></div>}
                            </div>
                            
                            <div className="timeline-content-col" style={{cursor: 'pointer'}} onClick={() => setExpandedTimelineIndex(isExpanded ? null : idx)}>
                              <div className="timeline-item-meta">
                                <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                                  <strong style={{color: 'white', fontSize: '0.95rem'}}>{item.action_type.replace(/_/g, ' ')}</strong>
                                  <span className="block-id-tag">BLOCK #{item.id}</span>
                                </div>
                                <span style={{fontSize: '0.75rem', color: 'var(--text-muted)'}}>{new Date(item.timestamp).toLocaleString()}</span>
                              </div>
                              
                              <div className="timeline-item-body" style={{marginTop: '4px'}}>
                                {item.action_type === 'TICKET_UPDATE' ? (
                                  <p><strong>{item.payload.author}</strong> added comment: <span style={{color: 'var(--text-primary)'}}>"{item.payload.comment}"</span></p>
                                ) : item.action_type === 'TICKET_CREATE' ? (
                                  <div>
                                    <p>Incident Case opened and ledger initialized.</p>
                                    {item.payload.ai_diagnosis && (
                                      <p style={{color: 'var(--accent-purple)', fontStyle: 'italic', marginTop: '4px'}}>
                                        {item.payload.ai_diagnosis}
                                      </p>
                                    )}
                                  </div>
                                ) : item.action_type === 'TICKET_ASSIGN' ? (
                                  <p>Case assigned to <strong>{item.payload.assignee}</strong> by <code>{item.payload.assigned_by}</code>.</p>
                                ) : item.action_type === 'TICKET_SEVERITY_UPDATE' ? (
                                  <p>Severity adjusted to <strong style={{color: 'var(--accent-yellow)'}}>{item.payload.severity}</strong> by <code>{item.payload.updated_by}</code>.</p>
                                ) : item.action_type === 'TICKET_STATUS_UPDATE' ? (
                                  <p>Status changed to <strong style={{color: 'var(--accent-blue)'}}>{item.payload.status}</strong> by <code>{item.payload.updated_by}</code>.</p>
                                ) : item.action_type === 'AI_DIAGNOSIS' ? (
                                  <p>Cognitive diagnosis ran successfully. Mapped MITRE ATT&CK Phase: <strong style={{color: 'var(--accent-purple)', textTransform: 'capitalize'}}>{item.payload.classification}</strong> (Score: {(item.payload.confidence*100).toFixed(1)}%).</p>
                                ) : item.action_type === 'SOAR_ACTION_APPROVED' ? (
                                  <p style={{color: 'var(--accent-green)'}}>Mitigation Approved: <code>{item.payload.action}</code> signed by <strong>{item.payload.approved_by}</strong>.</p>
                                ) : item.action_type === 'SOAR_ACTION_DENIED' ? (
                                  <p style={{color: 'var(--accent-red)'}}>Mitigation Explicitly Denied: <code>{item.payload.action}</code> aborted by <strong>{item.payload.denied_by}</strong>.</p>
                                ) : (
                                  <p>{item.payload.message || JSON.stringify(item.payload)}</p>
                                )}
                              </div>

                              <div className="timeline-hash-badge" style={{marginTop: '8px'}}>
                                <span className="hash-label">Block Hash State:</span>
                                <span className="hash-value" title={item.hash_state}>{item.hash_state.substring(0, 16)}...</span>
                                <ChevronRight size={12} style={{marginLeft: '4px', transform: isExpanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s'}} />
                              </div>

                              {isExpanded && (
                                <div className="raw-block-payload-viewer fade-in" onClick={(e) => e.stopPropagation()}>
                                  <div className="payload-title">Block Metadata Payload</div>
                                  <pre className="font-monospace">{JSON.stringify(item.payload, null, 2)}</pre>
                                  <div className="payload-prev-hash">Previous Hash State: <code>{idx > 0 ? ticketTimeline[idx - 1].hash_state : '0000000000000000000000000000000000000000000000000000000000000000'}</code></div>
                                </div>
                              )}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>

                </div>
              )}

              {/* TAB 3 CONTENT: Analyst updates and comments */}
              {irDetailTab === 'comments' && (
                <div className="tab-pane-content fade-in" style={{display: 'flex', flexDirection: 'column', gap: '1rem'}}>
                  
                  <div className="comments-stream-container">
                    {ticketTimeline.filter(i => i.action_type === 'TICKET_UPDATE').length === 0 ? (
                      <div className="no-comments-placeholder">No analyst comments have been recorded for this case.</div>
                    ) : (
                      ticketTimeline.filter(i => i.action_type === 'TICKET_UPDATE').map((item, idx) => (
                        <div key={idx} className="comment-bubble-wrapper">
                          <div className="comment-avatar">
                            {item.payload.author.substring(8, 10).toUpperCase() || 'AN'}
                          </div>
                          <div className="comment-bubble-body">
                            <div className="comment-bubble-header">
                              <span className="comment-author">{item.payload.author}</span>
                              <span className="comment-time">{new Date(item.timestamp).toLocaleString()}</span>
                            </div>
                            <div className="comment-bubble-text">{item.payload.comment}</div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Updates Form */}
                  <div className="comment-form-section" style={{border: 'none', paddingTop: 0}}>
                    <h4>Submit Signed Analyst Note</h4>
                    <div style={{display: 'flex', gap: '8px', marginTop: '8px'}}>
                      <input
                        type="text"
                        value={newComment}
                        onChange={(e) => setNewComment(e.target.value)}
                        placeholder="Enter manual action details or analysis notes..."
                        style={{flex: 1, padding: '10px 15px', borderRadius: '8px', border: '1px solid var(--border-light)', backgroundColor: 'rgba(0,0,0,0.3)', color: 'white'}}
                        onKeyDown={(e) => e.key === 'Enter' && handleAddComment()}
                      />
                      <button className="btn-action" onClick={handleAddComment} style={{display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap'}}>
                        <Send size={14} /> Add Note
                      </button>
                    </div>
                  </div>
                </div>
              )}

            </div>
          ) : (
            <div style={{display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)'}}>
              <Briefcase size={48} style={{marginBottom: '1rem', opacity: 0.5}} />
              <p>Select an incident ticket from the list to view diagnosis details, approval gates, and cryptographic audit proofs.</p>
            </div>
          )}
        </div>
      </div>
    )
  }

  const renderSiemDashboard = () => {
    const isSelected = selectedSiemAlert !== null;
    
    const getProcessTree = (source) => {
      if (source.includes('EXCHANGE') || source.includes('10.0.0.88') || source.includes('INC-002')) {
        return [
          { name: 'w3wp.exe', pid: 1244, parent: null, user: 'IIS_IUSRS', hash: '8a2b3c4d9f1092... (SHA-256)', path: 'C:\\Windows\\System32\\inetsrv\\w3wp.exe', threat: 'Clean' },
          { name: 'cmd.exe', pid: 3122, parent: 1244, user: 'SYSTEM', hash: 'f5e6d7c80d1982... (SHA-256)', path: 'C:\\Windows\\System32\\cmd.exe', threat: 'Suspicious' },
          { name: 'powershell.exe', pid: 3840, parent: 3122, user: 'SYSTEM', hash: '1a2b3c4d12bb99... (SHA-256)', path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', threat: 'Critical' }
        ];
      }
      return [
        { name: 'services.exe', pid: 640, parent: null, user: 'SYSTEM', hash: '3e4f5a6b0c2e91... (SHA-256)', path: 'C:\\Windows\\System32\\services.exe', threat: 'Clean' },
        { name: 'svchost.exe', pid: 892, parent: 640, user: 'SYSTEM', hash: '7c8d9e0f31a293... (SHA-256)', path: 'C:\\Windows\\System32\\svchost.exe', threat: 'Clean' },
        { name: 'cmd.exe', pid: 4310, parent: 892, user: 'Administrator', hash: 'e5f6a7b8e018a1... (SHA-256)', path: 'C:\\Windows\\System32\\cmd.exe', threat: 'Clean' },
        { name: 'powershell.exe', pid: 5122, parent: 4310, user: 'Administrator', hash: '9b0c1d2eef293a... (SHA-256)', path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', threat: 'Suspicious' },
        { name: 'ransom.dll', pid: 6012, parent: 5122, user: 'Administrator', hash: 'e3b0c44298fc1c... (SHA-256)', path: 'C:\\Windows\\Temp\\ransom.dll', threat: 'Critical' }
      ];
    };

    const getNetworkConnections = (source) => {
      if (source.includes('EXCHANGE') || source.includes('10.0.0.88')) {
        return [
          { local: '10.0.0.88:443', remote: '198.51.100.12:59283', proto: 'TCP', state: 'ESTABLISHED', domain: 'unknown-china-telecom.net', threat: 'High Risk Gateway' },
          { local: '10.0.0.88:80', remote: '10.0.0.15:51922', proto: 'TCP', state: 'CLOSED', domain: 'WIN-DESKTOP-01', threat: 'Internal' }
        ];
      }
      return [
        { local: '10.0.0.15:49822', remote: '185.220.101.4:443', proto: 'TCP', state: 'ESTABLISHED', domain: 'tor-exit-node-04.wan', threat: 'Critical C2 Beacon' },
        { local: '10.0.0.15:139', remote: '10.0.0.88:49210', proto: 'TCP', state: 'ESTABLISHED', domain: 'SRV-EXCHANGE-01', threat: 'SMB Lateral Movement' }
      ];
    };

    const sampleLogs = [
      { label: "Failed Auth Syslog", text: "May 29 08:34:41 agent-001 Logon failed: invalid credentials for user administrator from 192.168.1.45" },
      { label: "Malware Syslog", text: "YARA execution finding: CobaltStrike.C2.Beacon signatures detected in C:\\Users\\Administrator\\Downloads\\cobaltstrike.exe on host SRV-EXCHANGE-01" },
      { label: "Generic Event", text: "Process creation: cmd.exe spawned by explorer.exe with command line arguments '/c whoami'" }
    ];

    return (
      <div className="ir-workspace fade-in">
        {/* Left column: Alerts Table & Live Ingestion stream */}
        <div className="ir-sidebar glass-panel" style={{ width: '45%' }}>
          <div className="ir-sidebar-header">
            <h3>SIEM Alerts Log</h3>
            <span className="badge badge-gray">{siemData.length} alerts</span>
          </div>

          <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem', flex: 1, overflowY: 'auto' }}>
            {/* Live stream */}
            <div className="telemetry-console" ref={consoleRef} style={{ height: '140px', flexShrink: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px', color: 'var(--text-muted)', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '4px', fontSize: '0.75rem' }}>
                <Terminal size={12} /> LIVE INGESTION STREAM
              </div>
              <div style={{ overflowY: 'auto', flex: 1, fontSize: '0.75rem' }}>
                {telemetryLogs.map((log, idx) => (
                  <div key={idx} className="telemetry-line">
                    <span className="log-time">[{log.time || '08:34:41'}]</span>
                    <span className={`log-${log.type}`}>{log.msg}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Alerts list */}
            <div className="table-container" style={{ flex: 1, overflowY: 'auto' }}>
              <table className="data-table" style={{ fontSize: '0.8rem' }}>
                <thead>
                  <tr>
                    <th>Alert Rule</th>
                    <th>Source</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {siemData.map((alert) => {
                    const isAlertSelected = selectedSiemAlert?.id === alert.id;
                    return (
                      <tr 
                        key={alert.id} 
                        className={`clickable-tr ${isAlertSelected ? 'selected' : ''}`}
                        onClick={() => setSelectedSiemAlert(alert)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td>
                          <div style={{ fontWeight: 600 }}>{alert.rule}</div>
                          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{alert.timestamp}</div>
                        </td>
                        <td>{alert.source}</td>
                        <td>
                          <span className={`badge ${alert.severity === 'Critical' || alert.severity === 'High' ? 'badge-red' : 'badge-yellow'}`} style={{ fontSize: '0.7rem', padding: '2px 6px' }}>
                            {alert.severity.toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right column: Forensics Workspace */}
        <div className="ir-details glass-panel" style={{ width: '55%' }}>
          {isSelected ? (
            <div className="ir-details-scroll">
              <div className="ir-details-header" style={{ paddingBottom: '1rem', marginBottom: '1rem' }}>
                <div style={{ flex: 1 }}>
                  <div className="ir-details-id-row">
                    <span className="case-id-badge">ALERT-ID: #{selectedSiemAlert.id}</span>
                    <span className={`badge ${selectedSiemAlert.severity === 'Critical' || selectedSiemAlert.severity === 'High' ? 'badge-red' : 'badge-yellow'}`}>
                      {selectedSiemAlert.severity.toUpperCase()}
                    </span>
                  </div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: '6px 0' }}>{selectedSiemAlert.rule}</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                    Asset target: <strong>{selectedSiemAlert.source}</strong> | Telemetry: <strong>Endpoint Event Log</strong>
                  </p>
                </div>
                
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button className="btn-action" onClick={() => handleTriage(selectedSiemAlert)}>
                    Escalate Event
                  </button>
                  <button className="btn-deny" style={{ padding: '6px 12px' }} onClick={() => setSelectedSiemAlert(null)}>
                    Clear
                  </button>
                </div>
              </div>

              {/* Forensic sub tabs */}
              <div className="ir-workspace-tabs" style={{ marginBottom: '1rem' }}>
                <button 
                  className={`tab-btn ${siemDetailTab === 'tree' ? 'active' : ''}`}
                  onClick={() => setSiemDetailTab('tree')}
                >
                  <Cpu size={12} /> Process Lineage
                </button>
                <button 
                  className={`tab-btn ${siemDetailTab === 'network' ? 'active' : ''}`}
                  onClick={() => setSiemDetailTab('network')}
                >
                  <Activity size={12} /> Network Sockets
                </button>
                <button 
                  className={`tab-btn ${siemDetailTab === 'raw' ? 'active' : ''}`}
                  onClick={() => setSiemDetailTab('raw')}
                >
                  <Terminal size={12} /> Raw OCSF JSON
                </button>
                <button 
                  className={`tab-btn ${siemDetailTab === 'playground' ? 'active' : ''}`}
                  onClick={() => setSiemDetailTab('playground')}
                >
                  <Zap size={12} /> SLM Playground
                </button>
              </div>

              {/* Sub-tab 1: Process lineage tree layout */}
              {siemDetailTab === 'tree' && (
                <div className="tab-pane-content fade-in">
                  <div className="process-tree-container">
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                      Interactive process execution tree hierarchy. Select leaf nodes to review SHA-256 signatures:
                    </div>
                    <div className="process-tree-nodes">
                      {getProcessTree(selectedSiemAlert.source).map((proc, index) => (
                        <div key={index} className="process-tree-node-wrapper">
                          {index > 0 && <div className="process-tree-connector"></div>}
                          <div className={`process-tree-card ${proc.threat.toLowerCase()}`}>
                            <div className="proc-header">
                              <span className="proc-name">{proc.name}</span>
                              <span className="proc-pid">PID {proc.pid}</span>
                            </div>
                            <div className="proc-details">
                              <div><span className="lbl">Path:</span> <span className="val">{proc.path}</span></div>
                              <div><span className="lbl">User:</span> <span className="val">{proc.user}</span></div>
                              <div><span className="lbl">Hash:</span> <span className="val font-monospace">{proc.hash}</span></div>
                            </div>
                            <div className="proc-footer">
                              <span className={`threat-badge ${proc.threat.toLowerCase()}`}>{proc.threat.toUpperCase()}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Sub-tab 2: Network sockets */}
              {siemDetailTab === 'network' && (
                <div className="tab-pane-content fade-in">
                  <div className="network-connections-list">
                    {getNetworkConnections(selectedSiemAlert.source).map((conn, index) => (
                      <div key={index} className="network-connection-card">
                        <div className="conn-hosts-row">
                          <span className="conn-ip local">{conn.local}</span>
                          <span className="conn-arrow">➜</span>
                          <span className={`conn-ip remote ${conn.threat.includes('Critical') || conn.threat.includes('High') ? 'threat-ip' : ''}`}>{conn.remote}</span>
                        </div>
                        <div className="conn-meta-row">
                          <span>Protocol: <strong>{conn.proto}</strong></span>
                          <span>State: <strong style={{ color: conn.state === 'ESTABLISHED' ? 'var(--accent-green)' : 'var(--text-muted)' }}>{conn.state}</strong></span>
                          {conn.domain && <span>Domain: <code>{conn.domain}</code></span>}
                        </div>
                        <div className="conn-verdict-row">
                          <span className={`badge ${conn.threat.includes('Critical') || conn.threat.includes('High') ? 'badge-red' : 'badge-gray'}`}>
                            {conn.threat}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Sub-tab 3: Raw OCSF JSON */}
              {siemDetailTab === 'raw' && (
                <div className="tab-pane-content fade-in">
                  <div className="raw-block-payload-viewer" style={{ marginTop: 0 }}>
                    <div className="payload-title">Raw OCSF Schema Representation</div>
                    <pre className="font-monospace">
{JSON.stringify({
  metadata: {
    product: {
      name: "NerveCenter Agent EDR",
      vendor: "NerveCenter"
    },
    version: "1.1.0"
  },
  class_name: selectedSiemAlert.rule.includes("PowerShell") ? "Process Activity" : "Malware Finding",
  class_id: selectedSiemAlert.rule.includes("PowerShell") ? 1007 : 1001,
  severity: selectedSiemAlert.severity,
  time: selectedSiemAlert.timestamp,
  device: {
    hostname: selectedSiemAlert.source,
    ip: selectedSiemAlert.source.includes("EXCHANGE") ? "10.0.0.88" : "10.0.0.15"
  },
  rule: {
    name: selectedSiemAlert.rule,
    uid: "rule-" + selectedSiemAlert.id
  }
}, null, 2)}
                    </pre>
                  </div>
                </div>
              )}

              {/* Sub-tab 4: Playground inside details */}
              {siemDetailTab === 'playground' && (
                <div className="tab-pane-content fade-in">
                  <div className="log-correlation-card">
                    <h4>Zero-Shot Log Correlation Engine</h4>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
                      Analyze how unstructured proprietary syslogs are dynamically parsed into OCSF fields:
                    </p>
                    
                    <div style={{ display: 'flex', gap: '6px', marginBottom: '8px' }}>
                      {sampleLogs.map((s, idx) => (
                        <button 
                          key={idx} 
                          className="btn-trigger-diagnose" 
                          style={{ fontSize: '0.7rem' }}
                          onClick={() => setSiemCorrelateInput(s.text)}
                        >
                          {s.label}
                        </button>
                      ))}
                    </div>

                    <textarea
                      value={siemCorrelateInput}
                      onChange={(e) => setSiemCorrelateInput(e.target.value)}
                      placeholder="Paste unstructured log text here..."
                      rows="4"
                      className="correlation-textarea"
                    />

                    <button 
                      className="btn-action" 
                      onClick={handleSiemCorrelate} 
                      disabled={isCorrelating}
                      style={{ marginTop: '8px', width: '100%', display: 'flex', justifyContent: 'center', gap: '6px' }}
                    >
                      {isCorrelating ? <RefreshCw className="animate-spin" size={14} /> : <Zap size={14} />}
                      {isCorrelating ? 'Running Zero-Shot SLM...' : 'Correlate Unstructured Log'}
                    </button>

                    {siemCorrelateResult && (
                      <div className="raw-block-payload-viewer" style={{ marginTop: '12px' }}>
                        <div className="payload-title">Zero-Shot Parser Output (Mapped OCSF)</div>
                        <pre className="font-monospace">{JSON.stringify(siemCorrelateResult, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', padding: '2rem', textAlign: 'center' }}>
              <Activity size={48} style={{ color: 'var(--text-muted)', marginBottom: '1rem', opacity: 0.5 }} />
              <h3>Awaiting Forensic Investigation Selection</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', maxWidth: '350px', margin: '8px 0 20px' }}>
                Select a live alert from the left column to run interactive process trees, network mapping, and OCSF schema checks, or paste unstructured strings in the correlator below.
              </p>
              
              <div className="log-correlation-card" style={{ width: '100%', maxWidth: '500px', textAlign: 'left' }}>
                <div className="payload-title" style={{ fontSize: '0.8rem', color: 'var(--accent-purple)' }}><Zap size={12} style={{ display: 'inline', marginRight: '4px' }} /> Quick Log Correlation Playground</div>
                <div style={{ display: 'flex', gap: '6px', marginBottom: '8px' }}>
                  {sampleLogs.map((s, idx) => (
                    <button 
                      key={idx} 
                      className="btn-trigger-diagnose" 
                      style={{ fontSize: '0.7rem' }}
                      onClick={() => setSiemCorrelateInput(s.text)}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>

                <textarea
                  value={siemCorrelateInput}
                  onChange={(e) => setSiemCorrelateInput(e.target.value)}
                  placeholder="Paste unstructured log text here..."
                  rows="3"
                  className="correlation-textarea"
                />

                <button 
                  className="btn-action" 
                  onClick={handleSiemCorrelate} 
                  disabled={isCorrelating}
                  style={{ marginTop: '8px', width: '100%', display: 'flex', justifyContent: 'center', gap: '6px' }}
                >
                  {isCorrelating ? <RefreshCw className="animate-spin" size={14} /> : <Zap size={14} />}
                  {isCorrelating ? 'Running Zero-Shot SLM...' : 'Correlate Unstructured Log'}
                </button>

                {siemCorrelateResult && (
                  <div className="raw-block-payload-viewer" style={{ marginTop: '12px' }}>
                    <div className="payload-title">Zero-Shot Parser Output (Mapped OCSF)</div>
                    <pre className="font-monospace">{JSON.stringify(siemCorrelateResult, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

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

  const renderSoarDashboard = () => {
    const isPlaybookSelected = selectedPlaybook !== null;

    const renderWorkflowNode = (key, node) => {
      const isCurrentStep = soarSimStep === key;
      const isPastStep = !isSimulatingSoar && soarSimStep !== null && (
        soarSimStep === 'complete' ||
        (soarSimStep === 'isolate-host' && key !== 'quarantine-file') ||
        (soarSimStep === 'quarantine-file' && key !== 'isolate-host') ||
        (key === 'verify-entropy' && soarSimStep !== 'verify-entropy' && soarSimStep !== 'start') ||
        (key === 'evaluate-risk' && !['start', 'verify-entropy', 'evaluate-risk'].includes(soarSimStep)) ||
        (key === 'check-patch' && soarSimStep !== 'start' && soarSimStep !== 'check-patch') ||
        (key === 'deploy-patch' && !['start', 'check-patch', 'deploy-patch'].includes(soarSimStep)) ||
        (key === 'verify-mitigation' && ['complete-patch', 'complete'].includes(soarSimStep))
      );

      let statusClass = 'pending';
      if (isCurrentStep) statusClass = 'running';
      else if (isPastStep) statusClass = 'success';

      return (
        <div key={key} className={`cacao-node-card ${node.type} ${statusClass}`}>
          <div className="node-badge">{node.type.toUpperCase()}</div>
          <div className="node-label-title">{node.label}</div>
          <div className="node-cmd"><code>{node.command}</code></div>
          <div className="node-target">Target: {node.target}</div>
          {statusClass === 'running' && <div className="node-pulse-indicator"></div>}
        </div>
      );
    };

    return (
      <div className="ir-workspace fade-in">
        {/* Left pane: playbooks and history */}
        <div className="ir-sidebar glass-panel" style={{ width: '40%' }}>
          <div className="ir-sidebar-header">
            <h3>Playbook Catalog</h3>
            <span className="badge badge-gray">{soarData.length} active</span>
          </div>

          <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem', flex: 1, overflowY: 'auto' }}>
            {/* Playbook list */}
            <div className="table-container" style={{ flexShrink: 0 }}>
              <table className="data-table" style={{ fontSize: '0.8rem' }}>
                <thead>
                  <tr>
                    <th>Playbook Name</th>
                    <th>Status</th>
                    <th>Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {soarData.map((pb, idx) => {
                    const isSelected = selectedPlaybook?.name === pb.name;
                    return (
                      <tr 
                        key={idx} 
                        className={`clickable-tr ${isSelected ? 'selected' : ''}`}
                        onClick={() => {
                          setSelectedPlaybook(pb);
                          setSelectedHistoryExecution(null);
                          setSoarSimLog('');
                          setSoarSimStep(null);
                        }}
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{ fontWeight: 600 }}>{pb.name}</td>
                        <td>
                          <span className={`status-badge ${pb.status === 'active' ? 'status-green' : 'status-red'}`} style={{ fontSize: '0.7rem', padding: '2px 6px' }}>
                            {pb.status.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{pb.success_rate}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Execution history */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1, overflowY: 'auto' }}>
              <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Execution History Log</h4>
              <div className="table-container" style={{ flex: 1, overflowY: 'auto' }}>
                <table className="data-table" style={{ fontSize: '0.75rem' }}>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Playbook</th>
                      <th>Target</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {soarHistory.map((hist, idx) => {
                      const isHistSelected = selectedHistoryExecution?.id === hist.id;
                      return (
                        <tr 
                          key={idx}
                          className={`clickable-tr ${isHistSelected ? 'selected' : ''}`}
                          onClick={() => {
                            setSelectedHistoryExecution(hist);
                            setSelectedPlaybook(null);
                          }}
                          style={{ cursor: 'pointer' }}
                        >
                          <td style={{ fontFamily: 'monospace' }}>{hist.id}</td>
                          <td style={{ fontWeight: 500 }}>{hist.name}</td>
                          <td>{hist.target}</td>
                          <td>
                            <span className={`badge ${hist.status === 'SUCCESS' ? 'badge-green' : hist.status === 'ABORTED' ? 'badge-yellow' : 'badge-red'}`} style={{ fontSize: '0.7rem', padding: '1px 4px' }}>
                              {hist.status}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>

        {/* Right pane: CACAO Visualizer */}
        <div className="ir-details glass-panel" style={{ width: '60%' }}>
          {isPlaybookSelected ? (
            <div className="ir-details-scroll">
              <div className="ir-details-header" style={{ paddingBottom: '1rem', marginBottom: '1rem' }}>
                <div style={{ flex: 1 }}>
                  <div className="ir-details-id-row">
                    <span className="case-id-badge">CACAO WORKFLOW</span>
                    <span className="badge badge-yellow">V2.0 COMPLIANT</span>
                  </div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: '6px 0' }}>{selectedPlaybook.name}</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                    Success Rate: <strong>{selectedPlaybook.success_rate}</strong> | Default Agent Core: <strong>EDR/Vuln Gateway</strong>
                  </p>
                </div>
                
                <button 
                  className="btn-approve-glow animate-pulse-border"
                  onClick={() => handleSimulatePlaybook(selectedPlaybook)}
                  disabled={isSimulatingSoar}
                  style={{ whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  {isSimulatingSoar ? <RefreshCw className="animate-spin" size={14} /> : <PlayCircle size={14} />}
                  {isSimulatingSoar ? 'Simulating Playbook...' : 'Run Simulation'}
                </button>
              </div>

              {/* Graphic Flow Map */}
              <div className="cacao-dag-visualizer">
                <div className="dag-header">CACAO DAG Flow Execution Map</div>
                
                <div className="dag-flow-container">
                  {selectedPlaybook.workflow ? (
                    Object.keys(selectedPlaybook.workflow).map(key => {
                      const node = selectedPlaybook.workflow[key];
                      if (key === 'end') return null;
                      return (
                        <div key={key} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                          {renderWorkflowNode(key, node)}
                          {node.next && node.next !== 'end' && (
                            <div className="dag-flow-line-connector">
                              <span className="arrow-down">▼</span>
                            </div>
                          )}
                        </div>
                      );
                    })
                  ) : (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No workflow steps defined in schema.</div>
                  )}
                </div>
              </div>

              {/* Simulation terminal log */}
              <div className="playbook-terminal-card" style={{ flex: 'none', marginTop: '1rem' }}>
                <div className="terminal-header">
                  <Terminal size={12} />
                  <span>SIMULATION CONSOLE LOG: {selectedPlaybook.name}</span>
                </div>
                <div className="terminal-body font-monospace" style={{ fontSize: '0.8rem', color: '#10b981', maxHeight: '180px' }}>
                  {soarSimLog ? (
                    soarSimLog.split('\n').map((line, idx) => (
                      <div key={idx} style={{ marginBottom: '2px' }}>{line}</div>
                    ))
                  ) : (
                    <div style={{ color: 'var(--text-muted)' }}>Awaiting playbook simulation run... Click \'Run Simulation\' above to test.</div>
                  )}
                </div>
              </div>
            </div>
          ) : selectedHistoryExecution ? (
            <div className="ir-details-scroll">
              <div className="ir-details-header" style={{ paddingBottom: '1rem', marginBottom: '1rem' }}>
                <div>
                  <div className="ir-details-id-row">
                    <span className="case-id-badge">EXECUTION LOG: {selectedHistoryExecution.id}</span>
                    <span className={`badge ${selectedHistoryExecution.status === 'SUCCESS' ? 'badge-green' : 'badge-red'}`}>
                      {selectedHistoryExecution.status}
                    </span>
                  </div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: '6px 0' }}>{selectedHistoryExecution.name}</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                    Triggered at: <strong>{selectedHistoryExecution.started_at}</strong> | Completed: <strong>{selectedHistoryExecution.completed_at}</strong>
                  </p>
                </div>
                <button className="btn-deny" style={{ padding: '6px 12px' }} onClick={() => setSelectedHistoryExecution(null)}>
                  Close Log
                </button>
              </div>

              <div className="playbook-terminal-card" style={{ height: '350px' }}>
                <div className="terminal-header">
                  <Terminal size={12} />
                  <span>HISTORIC RUN LOGS (AUDITABLE LEDGER INTEGRATED)</span>
                </div>
                <div className="terminal-body font-monospace" style={{ height: '100%', fontSize: '0.85rem', color: '#6ee7b7' }}>
                  {selectedHistoryExecution.log.split('\n').map((line, idx) => (
                    <div key={idx} style={{ marginBottom: '4px' }}>{line}</div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', padding: '2rem', textAlign: 'center' }}>
              <PlayCircle size={48} style={{ color: 'var(--text-muted)', marginBottom: '1rem', opacity: 0.5 }} />
              <h3>SOAR Playbook Sandbox</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', maxWidth: '350px', marginTop: '8px' }}>
                Select a playbook from the catalog to visualize its CACAO step-by-step DAG flow diagram and run a simulation sequence, or click an execution log row in the history list to inspect its logs.
              </p>
            </div>
          )}
        </div>
      </div>
    );
  }

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

          <div className={`nav-item ${activeTab === 'av' ? 'active' : ''}`} onClick={() => setActiveTab('av')}>
            <Shield size={18} /><span>Antivirus</span>
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
            {activeTab === 'av' && 'Antivirus Telemetry'}
            {activeTab === 'ir' && 'Incident Response Management'}
          </div>

          <div className="user-profile">
            <button className="chat-toggle-btn" onClick={() => setChatOpen(true)}>
              <MessageSquare size={20} />
            </button>
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
          {activeTab === 'av' && renderAntivirusDashboard()}
          {activeTab === 'ir' && renderIrDashboard()}
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

      {/* AI Chat Panel */}
      {chatOpen && <div className="side-panel-overlay" onClick={() => setChatOpen(false)}></div>}
      <div className={`side-panel ${chatOpen ? 'open' : ''}`} style={{display: 'flex', flexDirection: 'column'}}>
        <div className="panel-header">
          <h2 className="panel-title" style={{display: 'flex', alignItems: 'center', gap: '8px'}}><Zap size={20} color="var(--accent-purple)"/> AI Assistant</h2>
          <button className="close-btn" onClick={() => setChatOpen(false)}><X size={24} /></button>
        </div>
        <div className="panel-content" style={{flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem', overflowY: 'auto'}}>
          {chatMessages.map((msg, idx) => (
            <div key={idx} className={`chat-message ${msg.role === 'user' ? 'chat-message-user' : 'chat-message-ai'}`}>
              <div className="chat-bubble">
                {msg.role === 'ai' ? formatChatMessage(msg.text) : msg.text}
              </div>
            </div>
          ))}
          {isGeneratingChat && (
            <div className="chat-message chat-message-ai">
              <div className="chat-bubble" style={{ display: 'flex', gap: '4px', padding: '12px 16px', alignItems: 'center' }}>
                <span className="dot-blink"></span>
                <span className="dot-blink" style={{ animationDelay: '0.2s' }}></span>
                <span className="dot-blink" style={{ animationDelay: '0.4s' }}></span>
              </div>
            </div>
          )}
        </div>
        
        {/* Quick action chips */}
        <div className="chat-quick-chips" style={{ padding: '0.5rem 1rem', display: 'flex', gap: '6px', flexWrap: 'wrap', borderTop: '1px solid var(--border-light)', backgroundColor: 'rgba(26,29,45,0.7)' }}>
          <button className="btn-trigger-diagnose" style={{ fontSize: '0.7rem', padding: '4px 8px' }} onClick={() => handleSendMessage("Check fleet health")}>Check Fleet Health</button>
          <button className="btn-trigger-diagnose" style={{ fontSize: '0.7rem', padding: '4px 8px' }} onClick={() => handleSendMessage("List SIEM alerts")}>List SIEM Alerts</button>
          <button className="btn-trigger-diagnose" style={{ fontSize: '0.7rem', padding: '4px 8px' }} onClick={() => handleSendMessage("Audit INC-001")}>Audit INC-001</button>
          <button className="btn-trigger-diagnose" style={{ fontSize: '0.7rem', padding: '4px 8px' }} onClick={() => handleSendMessage("Isolate WIN-DESKTOP-01")}>Isolate WIN-DESKTOP-01</button>
        </div>

        <div className="chat-input-area" style={{padding: '1.5rem', borderTop: '1px solid var(--border-light)', display: 'flex', gap: '8px', backgroundColor: 'rgba(26, 29, 45, 0.9)'}}>
          <input
            type="text"
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
            placeholder="Ask AI..."
            style={{flex: 1, padding: '10px 15px', borderRadius: '8px', border: '1px solid var(--border-light)', backgroundColor: 'rgba(0,0,0,0.3)', color: 'white'}}
          />
          <button className="btn-action" style={{padding: '10px'}} onClick={() => handleSendMessage()}>
            <Send size={18} />
          </button>
        </div>
      </div>
    </div>
  )
}

export default App
