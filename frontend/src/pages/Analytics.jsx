import { useState, useEffect, useMemo } from 'react';
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';
import './Analytics.css';

const API = 'http://127.0.0.1:5000/api';

const Tip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background:'#161b27', border:'1px solid rgba(255,255,255,.1)', padding:'.4rem .65rem', borderRadius:'4px', fontFamily:'IBM Plex Mono,monospace', fontSize:'.68rem', color:'#7e8fa4' }}>
      {label && <div style={{marginBottom:'3px',color:'#4a5568'}}>{label}</div>}
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color }}>{p.name}: <strong style={{ color:'#c8d3e0' }}>{p.value}</strong></div>
      ))}
    </div>
  );
};

function MetricCard({ label, value, sub, color = '#3b7dd8' }) {
  return (
    <div className="metric-card">
      <div className="metric-card__label">{label}</div>
      <div className="metric-card__val" style={{ color }}>{value}</div>
      {sub && <div className="metric-card__sub">{sub}</div>}
    </div>
  );
}

export default function Analytics() {
  const [history,  setHistory]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [timeRange, setTimeRange] = useState(24); // hours

  useEffect(() => {
    const load = async () => {
      try {
        const r = await fetch(`${API}/history`);
        const j = await r.json();
        const arr = Array.isArray(j) ? j : Array.isArray(j?.data?.scans) ? j.data.scans : Array.isArray(j?.data) ? j.data : [];
        setHistory(arr);
      } catch { setError('Failed to load history data.'); }
      finally { setLoading(false); }
    };
    load();
  }, []);

  // Filter by time range
  const filtered = useMemo(() => {
    const cutoff = Date.now() / 1000 - timeRange * 3600;
    return history.filter(h => (h.timestamp || 0) >= cutoff);
  }, [history, timeRange]);

  // Trust score over time
  const trustTrend = useMemo(() =>
    filtered.slice(0, 30).reverse().map((s, i) => ({
      name:    `${i + 1}`,
      score:   s.trust_score ?? 0,
      threats: s.threats?.length ?? 0,
    })), [filtered]);

  // Encryption breakdown
  const encBreak = useMemo(() => {
    const m = {};
    filtered.forEach(s => { if (s.encryption) m[s.encryption] = (m[s.encryption] || 0) + 1; });
    return Object.entries(m).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  }, [filtered]);

  // Threat type breakdown
  const threatBreak = useMemo(() => {
    const m = {};
    filtered.forEach(s => {
      (s.threats || []).forEach(t => { m[t] = (m[t] || 0) + 1; });
    });
    return Object.entries(m).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 8);
  }, [filtered]);

  // Hourly scan activity
  const hourlyActivity = useMemo(() => {
    const hours = {};
    for (let i = 23; i >= 0; i--) {
      const h = new Date(); h.setHours(h.getHours() - i, 0, 0, 0);
      const key = h.getHours() + ':00';
      hours[key] = 0;
    }
    filtered.forEach(s => {
      if (!s.timestamp) return;
      const d = new Date((s.timestamp > 1e10 ? s.timestamp : s.timestamp * 1000));
      const key = d.getHours() + ':00';
      if (key in hours) hours[key]++;
    });
    return Object.entries(hours).map(([time, scans]) => ({ time, scans }));
  }, [filtered]);

  // Summary stats
  const stats = useMemo(() => {
    const total    = filtered.length;
    const threats  = filtered.filter(h => h.threats?.length > 0).length;
    const avgScore = total ? Math.round(filtered.reduce((s, h) => s + (h.trust_score || 0), 0) / total) : 0;
    const uniqueSSIDs = new Set(filtered.map(h => h.ssid)).size;
    return { total, threats, clean: total - threats, avgScore, uniqueSSIDs };
  }, [filtered]);

  const ENC_COLORS = ['#3b7dd8', '#2d7d6f', '#b45309', '#c0392b', '#7e5bef', '#4a5568'];

  if (loading) return <div className="load-screen"><div className="load-ring" /><div className="load-text">Loading analytics...</div></div>;

  return (
    <div className="page-root">
      <header className="pg-header">
        <div>
          <div className="pg-eyebrow">System / Analytics / Security Trends</div>
          <h1 className="pg-title">Security Analytics</h1>
          <div className="pg-meta">
            <span className="pg-tag">{stats.total} scans in range</span>
            <span className="pg-tag">{history.length} total records</span>
          </div>
        </div>
        <div className="pg-header__actions">
          {[6, 24, 72, 168].map(h => (
            <button
              key={h}
              className={`btn ${timeRange === h ? 'btn--primary' : 'btn--ghost'}`}
              onClick={() => setTimeRange(h)}
            >
              {h < 24 ? `${h}h` : h === 24 ? '24h' : h === 72 ? '3d' : '7d'}
            </button>
          ))}
        </div>
      </header>

      <div className="pg-body">
        {error && <div className="alert-bar alert-bar--error"><span>⚠</span><span>{error}</span></div>}

        {/* Metric cards */}
        <div className="metrics-row">
          <MetricCard label="Scans in Range"   value={stats.total}       color="#3b7dd8" />
          <div className="stat-divider" />
          <MetricCard label="With Threats"     value={stats.threats}     color={stats.threats > 0 ? '#c0392b' : '#7e8fa4'} sub={stats.total ? `${Math.round(stats.threats/stats.total*100)}% of scans` : '—'} />
          <div className="stat-divider" />
          <MetricCard label="Clean Scans"      value={stats.clean}       color="#2d7d6f" />
          <div className="stat-divider" />
          <MetricCard label="Avg Trust Score"  value={stats.avgScore}    color={stats.avgScore >= 80 ? '#2d7d6f' : stats.avgScore >= 50 ? '#b45309' : '#c0392b'} sub="/100" />
          <div className="stat-divider" />
          <MetricCard label="Unique Networks"  value={stats.uniqueSSIDs} color="#7e5bef" />
        </div>

        {/* Trust trend + hourly activity */}
        <div className="an-row an-row--2col">
          <div className="an-panel">
            <div className="an-panel__label">Trust Score Trend <span className="an-panel__sub">Last {Math.min(30, filtered.length)} scans</span></div>
            {trustTrend.length > 1 ? (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={trustTrend} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
                  <defs>
                    <linearGradient id="tg1" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#3b7dd8" stopOpacity={.15} />
                      <stop offset="95%" stopColor="#3b7dd8" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,.04)" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill:'#4a5568', fontSize:8 }} axisLine={false} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fill:'#4a5568', fontSize:8 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<Tip />} />
                  <Area type="monotone" dataKey="score" stroke="#3b7dd8" strokeWidth={1.5} fill="url(#tg1)" name="Trust Score" />
                  <Line type="monotone" dataKey="threats" stroke="#c0392b" strokeWidth={1} strokeDasharray="3 3" name="Threats" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            ) : <div className="an-empty">Not enough data — run more scans.</div>}
          </div>

          <div className="an-panel">
            <div className="an-panel__label">Hourly Scan Activity <span className="an-panel__sub">Last 24 hours</span></div>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={hourlyActivity} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
                <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,.04)" vertical={false} />
                <XAxis dataKey="time" tick={{ fill:'#4a5568', fontSize:7 }} axisLine={false} tickLine={false} interval={3} />
                <YAxis tick={{ fill:'#4a5568', fontSize:8 }} axisLine={false} tickLine={false} />
                <Tooltip content={<Tip />} />
                <Bar dataKey="scans" fill="#3b7dd8" opacity={0.7} radius={[2, 2, 0, 0]} name="Scans" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Encryption + Threats */}
        <div className="an-row an-row--2col">
          <div className="an-panel">
            <div className="an-panel__label">Encryption Distribution</div>
            {encBreak.length > 0 ? (
              <div style={{ display:'grid', gridTemplateColumns:'1fr 180px', gap:'1rem', alignItems:'center' }}>
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie data={encBreak} innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value">
                      {encBreak.map((_, i) => <Cell key={i} fill={ENC_COLORS[i % ENC_COLORS.length]} />)}
                    </Pie>
                    <Tooltip content={<Tip />} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="an-legend">
                  {encBreak.map((e, i) => (
                    <div key={e.name} className="an-legend__row">
                      <span className="an-legend__dot" style={{ background: ENC_COLORS[i % ENC_COLORS.length] }} />
                      <span className="an-legend__name">{e.name}</span>
                      <span className="an-legend__val">{e.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : <div className="an-empty">No data in range.</div>}
          </div>

          <div className="an-panel">
            <div className="an-panel__label">Top Threat Types</div>
            {threatBreak.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={threatBreak} layout="vertical" margin={{ top: 4, right: 4, left: 8, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,.04)" horizontal={false} />
                  <XAxis type="number" tick={{ fill:'#4a5568', fontSize:8 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill:'#7e8fa4', fontSize:9, fontFamily:'IBM Plex Mono,monospace' }} axisLine={false} tickLine={false} width={140} />
                  <Tooltip content={<Tip />} />
                  <Bar dataKey="value" fill="#c0392b" opacity={0.7} radius={[0, 2, 2, 0]} name="Count" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="an-empty" style={{ color:'#2d7d6f' }}>✓ No threats detected in range.</div>
            )}
          </div>
        </div>

        {/* Security posture summary */}
        <div className="posture-panel">
          <div className="an-panel__label" style={{ marginBottom:'1rem' }}>Security Posture Assessment</div>
          <div className="posture-grid">
            {[
              {
                metric: 'Threat Rate',
                value: stats.total ? `${Math.round(stats.threats / stats.total * 100)}%` : '—',
                status: stats.threats === 0 ? 'good' : stats.threats / stats.total < 0.1 ? 'warn' : 'bad',
                desc: 'Percentage of scans with at least one threat detected',
              },
              {
                metric: 'Average Trust',
                value: `${stats.avgScore}/100`,
                status: stats.avgScore >= 75 ? 'good' : stats.avgScore >= 50 ? 'warn' : 'bad',
                desc: 'Mean trust score across all scanned networks',
              },
              {
                metric: 'Network Diversity',
                value: stats.uniqueSSIDs,
                status: stats.uniqueSSIDs < 10 ? 'good' : stats.uniqueSSIDs < 25 ? 'warn' : 'bad',
                desc: 'Unique SSIDs seen — high diversity increases attack surface',
              },
              {
                metric: 'Clean Session Rate',
                value: stats.total ? `${Math.round(stats.clean / stats.total * 100)}%` : '—',
                status: stats.clean / stats.total > 0.9 ? 'good' : stats.clean / stats.total > 0.7 ? 'warn' : 'bad',
                desc: 'Proportion of scans where no threats were detected',
              },
            ].map(p => (
              <div key={p.metric} className={`posture-item posture-item--${p.status}`}>
                <div className="posture-item__metric">{p.metric}</div>
                <div className="posture-item__val">{p.value}</div>
                <div className="posture-item__desc">{p.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}