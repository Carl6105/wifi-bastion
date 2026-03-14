import { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, 
  LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid,
  Radar, RadarChart, PolarGrid, PolarAngleAxis 
} from 'recharts';
import './Dashbd.css';

const Dashbd = () => {
  const [stats, setStats] = useState({ totalScans: 0, blockedCount: 0, recentThreats: 0 });
  const [history, setHistory] = useState([]);
  const [audit, setAudit] = useState(null);
  const [isAuditing, setIsAuditing] = useState(false);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [historyRes, blockedRes] = await Promise.all([
          fetch('http://127.0.0.1:5000/api/history'),
          fetch('http://127.0.0.1:5000/api/blocked')
        ]);
        const historyData = await historyRes.json();
        const blockedData = await blockedRes.json();
        
        const historyArr = Array.isArray(historyData) ? historyData : [];
        setHistory(historyArr);
        setStats({
          totalScans: historyArr.length,
          blockedCount: Array.isArray(blockedData) ? blockedData.length : 0,
          recentThreats: historyArr.filter(s => s.threats && s.threats.length > 0).length
        });
      } catch (error) { console.error("Stats fetch failed", error); }
    };
    fetchStats();
  }, []);

  // Visual Logic for Graphs
  const trendData = useMemo(() => history.slice(-10).map((s, i) => ({ 
    name: `S${i+1}`, 
    score: s.trust_score || 0,
    threats: s.threats ? s.threats.length : 0
  })), [history]);

  const pieData = [
    { name: 'Secure', value: stats.totalScans - stats.recentThreats },
    { name: 'Threats', value: stats.recentThreats }
  ];

  const radarData = useMemo(() => {
    if (!audit) return [];
    return [
      { subject: 'DNS Safety', A: audit.dns.status === 'Safe' ? 100 : 20 },
      { subject: 'Port Stealth', A: Math.max(0, 100 - (audit.ports.length * 20)) },
      { subject: 'Net History', A: stats.recentThreats === 0 ? 100 : 60 },
      { subject: 'Filter Rules', A: stats.blockedCount > 0 ? 100 : 40 },
      { subject: 'Integrity', A: audit.dns.status === 'Safe' && audit.ports.length === 0 ? 100 : 50 },
    ];
  }, [audit, stats]);

  const COLORS = ['#22c55e', '#ef4444'];

  const runGatewayAudit = async () => {
    setIsAuditing(true);
    try {
      const response = await fetch('http://127.0.0.1:5000/api/gateway_audit');
      const data = await response.json();
      setAudit(data);
    } catch (err) { alert("Audit failed."); }
    finally { setIsAuditing(false); }
  };

  return (
    <div className="page dashboard-container">
      {/* 1. Header Section */}
      <div className="dashboard-header" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2rem', alignItems: 'center' }}>
        <div>
            <div style={{ fontFamily: 'monospace', fontSize: '0.7rem', color: '#64748b', marginBottom: '4px' }}>SYSTEM // CONTROL_CENTER // LIVE_FEED</div>
            <h1 style={{margin: 0}}>Operational Overview</h1>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
            <Link to="/scan"><button className="btn-main">New Scan</button></Link>
            <Link to="/devices"><button className="secondary">Network Map</button></Link>
        </div>
      </div>

      {/* 2. Top Analytics Visual Row */}
      <div className="analytics-visual-row" style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
        <div className="card glass-card" style={{ padding: '1.5rem' }}>
          <small className="chart-label">SECURITY INTEGRITY TREND</small>
          <div style={{ width: '100%', height: '220px', marginTop: '1rem' }}>
            <ResponsiveContainer>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                <XAxis dataKey="name" hide />
                <YAxis hide />
                <Tooltip />
                <Line type="monotone" dataKey="score" stroke="#2563eb" strokeWidth={3} dot={{ r: 4, fill: '#2563eb' }} />
                <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} strokeDasharray="5 5" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card glass-card" style={{ padding: '1.5rem', textAlign: 'center' }}>
          <small className="chart-label">ENV COMPOSITION</small>
          <div style={{ width: '100%', height: '220px' }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie data={pieData} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                  {pieData.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index]} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      

      {/* 3. Original Stats Grid */}
      <div className="stats-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem', marginBottom: '2.5rem' }}>
        <div className="card stat-card total">
          <small>LOGGED SESSIONS</small>
          <h2>{stats.totalScans}</h2>
          <div className="sub-text">Total environment snapshots</div>
        </div>
        <div className="card stat-card threats">
          <small>ACTIVE THREATS</small>
          <h2 style={{ color: stats.recentThreats > 0 ? '#ef4444' : '#22c55e' }}>{stats.recentThreats}</h2>
          <div className="sub-text">Anomalies detected in logs</div>
        </div>
        <div className="card stat-card blocked">
          <small>BLACKLISTED</small>
          <h2>{stats.blockedCount}</h2>
          <div className="sub-text">OS-level hardware filters</div>
        </div>
      </div>

      {/* 4. Gateway Section with Radar Chart */}
      <section className="audit-section card" style={{ padding: '2.5rem', borderRadius: '15px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2.5rem' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.3rem' }}>Gateway Intelligence Audit</h3>
            <p style={{ margin: '4px 0 0 0', fontSize: '0.85rem', color: '#64748b' }}>Multi-vector hardware probe</p>
          </div>
          <button onClick={runGatewayAudit} disabled={isAuditing} className="btn-audit-trigger">
            {isAuditing ? "Probing..." : "Initialize Audit"}
          </button>
        </div>
        
        {audit ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2.5rem', alignItems: 'center' }}>
            <div className="radar-container" style={{ background: '#f8fafc', borderRadius: '12px', padding: '15px' }}>
              <ResponsiveContainer width="100%" height={300}>
                <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
                  <PolarGrid stroke="#e2e8f0" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: '#64748b', fontSize: 11, fontWeight: 700 }} />
                  <Radar name="Gateway" dataKey="A" stroke="#2563eb" fill="#3b82f6" fillOpacity={0.6} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
            

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
              <div className="audit-result-card" style={{ padding: '1.5rem', background: '#f8fafc', borderRadius: '12px', border: '1px solid #f1f5f9' }}>
                <small className="chart-label">DNS Integrity</small>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', margin: '10px 0' }}>
                  <span className={`status-indicator ${audit.dns.status === 'Safe' ? 'status-safe' : 'status-danger'}`}></span>
                  <strong style={{ fontSize: '1.2rem' }}>{audit.dns.status}</strong>
                </div>
                <p style={{ fontSize: '0.85rem', color: '#64748b' }}>{audit.dns.message}</p>
              </div>

              <div className="audit-result-card" style={{ padding: '1.5rem', background: '#f8fafc', borderRadius: '12px', border: '1px solid #f1f5f9' }}>
                <small className="chart-label">Port Exposure</small>
                <div style={{ fontWeight: 'bold', fontSize: '1.2rem', color: audit.ports.length > 0 ? '#ef4444' : '#22c55e', margin: '10px 0' }}>
                  {audit.ports.length > 0 ? `${audit.ports.length} Vulnerable Ports` : 'No Ports Exposed'}
                </div>
                <p style={{ fontSize: '0.85rem', color: '#64748b' }}>Detected: {audit.ports.length > 0 ? audit.ports.join(', ') : 'Standard stealth verified'}</p>
              </div>
            </div>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '4rem', border: '2px dashed #e2e8f0', borderRadius: '12px' }}>
             <p style={{ color: '#94a3b8', fontSize: '1rem' }}>Awaiting manual hardware-level intelligence probe.</p>
          </div>
        )}
      </section>
    </div>
  );
};

export default Dashbd;