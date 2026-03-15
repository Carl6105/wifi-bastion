import { useState, useEffect, useRef, useCallback } from 'react';
import './SecurityAlerts.css';

const API = 'http://127.0.0.1:5000/api';

function fmt(ts) {
  if (!ts) return '—';
  const d = ts > 1e10 ? new Date(ts * 1000) : new Date(ts * 1000);
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function severityClass(s = '') {
  const u = s.toUpperCase();
  if (u === 'CRITICAL') return 'sev--critical';
  if (u === 'HIGH')     return 'sev--high';
  if (u === 'MEDIUM')   return 'sev--medium';
  return 'sev--low';
}

function AlertRow({ alert, idx }) {
  return (
    <div className={`alert-row ${severityClass(alert.severity)}`}>
      <div className="alert-row__left">
        <span className="alert-idx">{String(idx + 1).padStart(2, '0')}</span>
        <span className={`alert-dot ${severityClass(alert.severity)}`} />
      </div>
      <div className="alert-row__body">
        <div className="alert-row__type">{alert.type || 'ALERT'}</div>
        <div className="alert-row__msg">{alert.message}</div>
        {alert.mac  && <div className="alert-row__meta">MAC: {alert.mac}</div>}
        {alert.ips  && <div className="alert-row__meta">IPs: {alert.ips.join(', ')}</div>}
      </div>
      <div className="alert-row__right">
        <span className={`sev-badge ${severityClass(alert.severity)}`}>{alert.severity || 'INFO'}</span>
        {alert.timestamp && (
          <span className="alert-time">{fmt(alert.timestamp)}</span>
        )}
      </div>
    </div>
  );
}

function StatTile({ val, label, color }) {
  return (
    <div className="sa-stat">
      <div className="sa-stat__val" style={{ color }}>{val}</div>
      <div className="sa-stat__label">{label}</div>
    </div>
  );
}

export default function SecurityAlerts() {
  const [alerts,    setAlerts]    = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastCheck, setLastCheck] = useState(null);
  const [filter,    setFilter]    = useState('ALL');
  const ivRef = useRef(null);

  const load = useCallback(async () => {
    try {
      const r = await fetch(`${API}/security_alerts`);
      const j = await r.json();
      const arr = Array.isArray(j) ? j
                : Array.isArray(j?.data?.alerts) ? j.data.alerts
                : Array.isArray(j?.data) ? j.data : [];
      // Stamp each alert with fetch time if no timestamp
      const stamped = arr.map(a => ({ ...a, timestamp: a.timestamp || Date.now() / 1000 }));
      setAlerts(stamped);
      setLastCheck(new Date().toLocaleTimeString());
      setError(null);
    } catch (e) {
      setError('Failed to fetch alerts from backend.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    return () => clearInterval(ivRef.current);
  }, [load]);

  useEffect(() => {
    clearInterval(ivRef.current);
    if (autoRefresh) {
      ivRef.current = setInterval(load, 10000);
    }
  }, [autoRefresh, load]);

  const displayed = filter === 'ALL' ? alerts
    : alerts.filter(a => (a.severity || '').toUpperCase() === filter);

  const counts = {
    total:    alerts.length,
    critical: alerts.filter(a => a.severity === 'CRITICAL').length,
    high:     alerts.filter(a => a.severity === 'HIGH').length,
    medium:   alerts.filter(a => a.severity === 'MEDIUM').length,
  };

  if (loading) return (
    <div className="load-screen">
      <div className="load-ring" />
      <div className="load-text">Loading threat feed...</div>
    </div>
  );

  return (
    <div className="page-root">
      <header className="pg-header">
        <div>
          <div className="pg-eyebrow">System / Security / Live Threat Feed</div>
          <h1 className="pg-title">Security Alerts</h1>
          <div className="pg-meta">
            {lastCheck && <span className="pg-tag">Last check: {lastCheck}</span>}
            <span className={`pg-tag ${counts.critical > 0 ? 'pg-tag--alert' : 'pg-tag--ok'}`}>
              {counts.total} Active
            </span>
          </div>
        </div>
        <div className="pg-header__actions">
          <button
            className={`btn ${autoRefresh ? 'btn--primary' : 'btn--ghost'}`}
            onClick={() => setAutoRefresh(p => !p)}
          >
            <span className={`dot ${autoRefresh ? 'dot--live' : 'dot--off'}`} />
            {autoRefresh ? 'Auto-Refresh On' : 'Auto-Refresh Off'}
          </button>
          <button className="btn btn--ghost" onClick={load}>Refresh Now</button>
        </div>
      </header>

      <div className="pg-body">
        {error && (
          <div className="alert-bar alert-bar--error">
            <span>⚠</span><span>{error}</span>
            <button className="alert-bar__close" onClick={() => setError(null)}>✕</button>
          </div>
        )}

        {/* Stats */}
        <div className="sa-stats-row">
          <StatTile val={counts.total}    label="Total Active"     color={counts.total > 0 ? '#c0392b' : '#7e8fa4'} />
          <div className="stat-divider" />
          <StatTile val={counts.critical} label="Critical"         color={counts.critical > 0 ? '#c0392b' : '#7e8fa4'} />
          <div className="stat-divider" />
          <StatTile val={counts.high}     label="High"             color={counts.high > 0 ? '#c05621' : '#7e8fa4'} />
          <div className="stat-divider" />
          <StatTile val={counts.medium}   label="Medium"           color={counts.medium > 0 ? '#b45309' : '#7e8fa4'} />
          <div className="stat-divider" />
          <StatTile val={autoRefresh ? '10s' : 'Off'} label="Refresh Interval" color="#3b7dd8" />
        </div>

        {/* Filter */}
        <div className="controls-row">
          <div className="filter-group">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
              <button
                key={f}
                className={`filter-btn ${filter === f ? 'filter-btn--active' : ''}`}
                onClick={() => setFilter(f)}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* Alert explanation cards */}
        <div className="threat-explainers">
          <div className="explainer-card">
            <div className="explainer-card__title">ARP Spoofing</div>
            <div className="explainer-card__body">
              A device is claiming to be the gateway — all traffic may be flowing through
              an attacker's machine. Triggered when one MAC address maps to multiple IPs
              in the ARP table.
            </div>
            <div className="explainer-card__action">Mitigation: Use static ARP entries or 802.1X port security.</div>
          </div>
          <div className="explainer-card">
            <div className="explainer-card__title">Deauth Flood</div>
            <div className="explainer-card__body">
              An 802.11 deauthentication flood is forcing devices off the network.
              Common precursor to Evil Twin attacks — attacker disconnects you to force
              connection to their rogue AP.
            </div>
            <div className="explainer-card__action">Mitigation: Enable 802.11w (Management Frame Protection) on your router.</div>
          </div>
          <div className="explainer-card">
            <div className="explainer-card__title">DNS Hijack</div>
            <div className="explainer-card__body">
              DNS resolution is returning private or unexpected IPs for known-good
              public hostnames. Could indicate router compromise or a transparent
              DNS proxy intercepting queries.
            </div>
            <div className="explainer-card__action">Mitigation: Set DNS to 8.8.8.8 manually. Enable DNS-over-HTTPS if supported.</div>
          </div>
        </div>

        {/* Alert list */}
        {displayed.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state__icon">◉</div>
            <h3 className="empty-state__title">
              {filter === 'ALL' ? 'No active threats' : `No ${filter} alerts`}
            </h3>
            <p className="empty-state__sub">
              {filter === 'ALL'
                ? 'All monitored threat vectors are clear. Bastion is actively watching.'
                : `Filter to ALL to see all alerts.`}
            </p>
          </div>
        ) : (
          <div className="alerts-list">
            {displayed.map((a, i) => (
              <AlertRow key={i} alert={a} idx={i} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}