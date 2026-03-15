import { useEffect, useState, useMemo, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  AreaChart, Area, LineChart, Line, XAxis, YAxis, Tooltip,
  CartesianGrid, ResponsiveContainer, RadarChart, Radar,
  PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from 'recharts';
import './dashbd.css';

const API = 'http://127.0.0.1:5000/api';

function riskColour(score) {
  if (score >= 80) return '#2d7d6f';
  if (score >= 50) return '#b45309';
  return '#c0392b';
}

const ChartTip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip" style={{ background:'#161b27', border:'1px solid rgba(255,255,255,.1)', padding:'.45rem .7rem', borderRadius:'4px', fontFamily:'IBM Plex Mono, monospace', fontSize:'.68rem', color:'#7e8fa4' }}>
      {payload.map((p,i) => <div key={i} style={{color:p.color}}>{p.name}: <strong style={{color:'#c8d3e0'}}>{p.value}</strong></div>)}
    </div>
  );
};

function LiveClock() {
  const [t, setT] = useState(new Date());
  useEffect(() => { const id = setInterval(() => setT(new Date()), 1000); return () => clearInterval(id); }, []);
  return <span className="td-mono" style={{fontSize:'.6rem', color:'#4a5568'}}>{t.toISOString().replace('T',' ').substring(0,19)} UTC</span>;
}

export default function Dashbd() {
  const [history,    setHistory]    = useState([]);
  const [blocked,    setBlocked]    = useState([]);
  const [alerts,     setAlerts]     = useState([]);
  const [audit,      setAudit]      = useState(null);
  const [isAuditing, setIsAuditing] = useState(false);
  const [loading,    setLoading]    = useState(true);
  const [wsStatus,   setWsStatus]   = useState('disconnected');

  useEffect(() => {
    const load = async () => {
      try {
        const [hR, bR, aR] = await Promise.all([
          fetch(`${API}/history`), fetch(`${API}/blocked`), fetch(`${API}/security_alerts`),
        ]);
        const hJ = await hR.json(); const bJ = await bR.json(); const aJ = await aR.json();
        const arr = j => Array.isArray(j) ? j : Array.isArray(j?.data?.scans) ? j.data.scans : Array.isArray(j?.data?.blocked) ? j.data.blocked : Array.isArray(j?.data?.alerts) ? j.data.alerts : Array.isArray(j?.data) ? j.data : [];
        setHistory(arr(hJ)); setBlocked(arr(bJ)); setAlerts(arr(aJ));
      } catch(e) { console.error(e); } finally { setLoading(false); }
    };
    load();
    try {
      import('socket.io-client').then(({ io }) => {
        const s = io('http://127.0.0.1:5000', { transports:['websocket'] });
        s.on('connect',      () => setWsStatus('connected'));
        s.on('disconnect',   () => setWsStatus('disconnected'));
        s.on('scan_complete',({ networks }) => { if(Array.isArray(networks)) setHistory(p => [...networks,...p].slice(0,200)); });
        s.on('threat_alert', ({ alerts: a }) => { if(Array.isArray(a)) setAlerts(p => [...a,...p].slice(0,50)); });
        return () => s.disconnect();
      }).catch(() => {});
    } catch(_) {}
  }, []);

  const stats = useMemo(() => {
    const threats = history.filter(h => h.threats?.length > 0).length;
    return { total: history.length, threats, clean: history.length - threats, blocked: blocked.length };
  }, [history, blocked]);

  const trendData = useMemo(() =>
    history.slice(0,20).reverse().map((s,i) => ({
      name: `S${i+1}`, score: s.trust_score ?? 0, threats: s.threats?.length ?? 0,
    })), [history]);

  const encData = useMemo(() => {
    const m = {};
    history.forEach(s => { if(s.encryption) m[s.encryption] = (m[s.encryption]||0)+1; });
    return Object.entries(m).sort((a,b)=>b[1]-a[1]);
  }, [history]);

  const radarData = useMemo(() => {
    if(!audit) return [];
    const dns = audit?.data?.dns ?? audit?.dns ?? {};
    const pr  = audit?.data?.port_risk ?? audit?.port_risk ?? {};
    const lvl = (pr?.level||'LOW').toUpperCase();
    const ps  = lvl==='CRITICAL'?10:lvl==='HIGH'?35:lvl==='MEDIUM'?65:95;
    return [
      { s:'DNS',     A: dns.status==='Safe'?100:20 },
      { s:'PORTS',   A: ps },
      { s:'HISTORY', A: stats.threats===0?100:Math.max(10,100-stats.threats*10) },
      { s:'FILTERS', A: stats.blocked>0?85:40 },
      { s:'INTEGRITY',A: dns.status==='Safe'&&ps>60?95:45 },
    ];
  }, [audit, stats]);

  const runAudit = async () => {
    setIsAuditing(true);
    try { const r = await fetch(`${API}/gateway_audit`); setAudit(await r.json()); }
    catch(e) { console.error(e); } finally { setIsAuditing(false); }
  };

  const auditDns  = audit?.data?.dns ?? audit?.dns ?? null;
  const auditPR   = audit?.data?.port_risk ?? audit?.port_risk ?? null;
  const critPorts = audit?.data?.critical_ports_found ?? audit?.critical_ports_found ?? [];

  if(loading) return (
    <div className="load-screen">
      <div className="load-ring" />
      <div className="load-text">Loading telemetry...</div>
    </div>
  );

  return (
    <div className="page-root">
      <header className="pg-header">
        <div>
          <div className="pg-eyebrow">System / Control Center / Overview</div>
          <h1 className="pg-title">Operational Overview</h1>
          <div className="pg-meta">
            <div className={`ws-badge ${wsStatus==='connected'?'ws-badge--live':''}`}>
              <span className={`dot ${wsStatus==='connected'?'dot--live':'dot--off'}`} />
              {wsStatus==='connected'?'Live':'Polling'}
            </div>
            <LiveClock />
          </div>
        </div>
        <div className="pg-header__actions">
          <Link to="/scan"><button className="btn btn--primary">New Scan</button></Link>
          <Link to="/devices"><button className="btn btn--ghost">Device Map</button></Link>
        </div>
      </header>

      <div className="pg-body">
        {/* Stats */}
        <div className="stats-row">
          <div className="stat-cell">
            <span className="stat-cell__val">{stats.total}</span>
            <span className="stat-cell__label">Logged Sessions</span>
          </div>
          <div className="stat-divider" />
          <div className="stat-cell">
            <span className="stat-cell__val" style={{color:stats.threats>0?'#c0392b':'#7e8fa4'}}>{stats.threats}</span>
            <span className="stat-cell__label">With Threats</span>
          </div>
          <div className="stat-divider" />
          <div className="stat-cell">
            <span className="stat-cell__val" style={{color:'#2d7d6f'}}>{stats.clean}</span>
            <span className="stat-cell__label">Clean Scans</span>
          </div>
          <div className="stat-divider" />
          <div className="stat-cell">
            <span className="stat-cell__val" style={{color:stats.blocked>0?'#b45309':'#7e8fa4'}}>{stats.blocked}</span>
            <span className="stat-cell__label">Blacklisted</span>
          </div>
        </div>

        {/* Trend + alerts */}
        <div style={{display:'grid', gridTemplateColumns:'2fr 1fr', gap:'1.25rem'}}>
          <div className="chart-panel">
            <div className="chart-panel__label">
              Security Integrity Trend
              <span className="chart-live">Live</span>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trendData} margin={{top:4,right:4,left:-22,bottom:0}}>
                <defs>
                  <linearGradient id="sg" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#3b7dd8" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#3b7dd8" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="tg" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#c0392b" stopOpacity={0.12}/>
                    <stop offset="95%" stopColor="#c0392b" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,.04)" vertical={false}/>
                <XAxis dataKey="name" tick={{fill:'#4a5568',fontSize:8,fontFamily:'IBM Plex Mono,monospace'}} axisLine={false} tickLine={false}/>
                <YAxis domain={[0,100]} tick={{fill:'#4a5568',fontSize:8}} axisLine={false} tickLine={false}/>
                <Tooltip content={<ChartTip/>}/>
                <Area type="monotone" dataKey="score"   stroke="#3b7dd8" strokeWidth={1.5} fill="url(#sg)" name="Trust"/>
                <Area type="monotone" dataKey="threats" stroke="#c0392b" strokeWidth={1.5} fill="url(#tg)" name="Threats" strokeDasharray="4 3"/>
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="chart-panel">
            <div className="chart-panel__label">
              Alert Feed
              <span className="td-mono" style={{fontSize:'.55rem', color:'#4a5568'}}>{alerts.length} active</span>
            </div>
            <div className="alert-feed">
              {alerts.length === 0 ? (
                <div className="alert-empty">
                  <span className="dot dot--live"/>No active threats
                </div>
              ) : alerts.slice(0,7).map((a,i) => (
                <div key={i} className={`alert-item alert-item--${(a.severity||'low').toLowerCase()}`}>
                  <div className="alert-item__type">{a.type||'ALERT'}</div>
                  <div className="alert-item__msg">{a.message}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Gateway audit */}
        <div className="chart-panel">
          <div className="audit-header">
            <div>
              <div className="chart-panel__label" style={{marginBottom:'.2rem'}}>Gateway Intelligence Audit</div>
              <div style={{fontSize:'.78rem', color:'#4a5568', fontWeight:300}}>Multi-vector hardware probe</div>
            </div>
            <button className={`btn btn--ghost ${isAuditing?'btn--loading':''}`} onClick={runAudit} disabled={isAuditing}>
              {isAuditing?'Probing...':'Run Audit'}
            </button>
          </div>

          {audit ? (
            <div className="audit-grid">
              <div style={{background:'rgba(59,125,216,.03)', border:'1px solid rgba(255,255,255,.05)', borderRadius:'5px', padding:'.5rem'}}>
                <ResponsiveContainer width="100%" height={200}>
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="rgba(255,255,255,.06)"/>
                    <PolarAngleAxis dataKey="s" tick={{fill:'#4a5568', fontSize:9, fontFamily:'IBM Plex Mono,monospace'}}/>
                    <PolarRadiusAxis domain={[0,100]} tick={false} axisLine={false}/>
                    <Radar dataKey="A" stroke="#3b7dd8" fill="#3b7dd8" fillOpacity={0.1} strokeWidth={1.5}/>
                  </RadarChart>
                </ResponsiveContainer>
              </div>

              <div className="audit-panel">
                <div className="audit-panel__label">DNS Integrity</div>
                <div className="audit-status">
                  <span className={`dot ${auditDns?.status==='Safe'?'dot--live':'dot--danger'}`}/>
                  <span className="audit-val">{auditDns?.status??'—'}</span>
                </div>
                <div className="audit-msg">{auditDns?.message??'—'}</div>
                {auditDns?.details?.length>0 && (
                  <div className="dns-rows" style={{marginTop:'.6rem'}}>
                    {auditDns.details.map((d,i)=>(
                      <div key={i} className="dns-row">
                        <span className="dns-row__host">{d.host}</span>
                        <span className="dns-row__ip">{d.resolved??'N/A'}</span>
                        <span className={`badge badge--${d.status==='Safe'?'low':d.status==='Warning'?'medium':'critical'}`}>{d.status}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="audit-panel">
                <div className="audit-panel__label">Port Exposure</div>
                <div className="audit-status">
                  <span className={`badge badge--${auditPR?.level==='LOW'?'low':auditPR?.level==='MEDIUM'?'medium':auditPR?.level==='HIGH'?'high':'critical'}`}>{auditPR?.level??'—'}</span>
                </div>
                <div className="audit-msg" style={{marginTop:'.4rem'}}>{auditPR?.detail??'—'}</div>
                {critPorts.length>0 && (
                  <div className="port-pills">
                    {critPorts.map(p=><span key={p} className="port-pill">{p}</span>)}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="audit-empty">
              <div className="audit-empty__icon">◈</div>
              <div className="audit-empty__text">Run audit to inspect gateway integrity</div>
            </div>
          )}
        </div>

        {/* Encryption breakdown */}
        {encData.length > 0 && (
          <div className="chart-panel">
            <div className="chart-panel__label">Encryption Distribution</div>
            <div className="enc-list">
              {encData.map(([name, count]) => {
                const pct = Math.round((count/stats.total)*100)||0;
                const col = name.includes('WPA3')?'#2d7d6f':name.includes('WPA2')?'#3b7dd8':name.includes('WPA')?'#b45309':'#c0392b';
                return (
                  <div key={name} className="enc-row">
                    <span className="enc-row__label">{name}</span>
                    <div className="enc-row__bar"><div className="enc-row__fill" style={{width:`${pct}%`,background:col}}/></div>
                    <span className="enc-row__n">{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}