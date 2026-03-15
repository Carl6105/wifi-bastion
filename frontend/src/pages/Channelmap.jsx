import { useState, useEffect, useCallback } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, ResponsiveContainer } from 'recharts';
import './ChannelMap.css';

const API = 'http://127.0.0.1:5000/api';

function riskCol(score) {
  return score >= 80 ? '#2d7d6f' : score >= 50 ? '#b45309' : '#c0392b';
}

function Toast({ message, type, onDone }) {
  useEffect(() => { const t = setTimeout(onDone, 3000); return () => clearTimeout(t); }, []);
  return <div className={`toast toast--${type}`}><span>{type === 'success' ? '✓' : '✕'}</span> {message}</div>;
}

const TAG_COLORS = {
  Home:        '#3b7dd8',
  Office:      '#7e5bef',
  Trusted:     '#2d7d6f',
  Suspicious:  '#c0392b',
  '':          '#4a5568',
};

const TAGS = ['', 'Home', 'Office', 'Trusted', 'Suspicious'];

function NoteModal({ network, onSave, onClose }) {
  const [note, setNote] = useState(network.note || '');
  const [tag,  setTag]  = useState(network.tag  || '');

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal--warn" onClick={e => e.stopPropagation()}>
        <div className="modal__title">Edit Note — {network.ssid}</div>
        <div className="modal__body">
          <div style={{ marginBottom: '.75rem' }}>
            <div className="modal__field-label">Tag</div>
            <div className="tag-picker">
              {TAGS.map(t => (
                <button key={t}
                  className={`tag-btn ${tag === t ? 'tag-btn--active' : ''}`}
                  style={{ '--tc': TAG_COLORS[t] }}
                  onClick={() => setTag(t)}
                >
                  {t || 'None'}
                </button>
              ))}
            </div>
          </div>
          <div>
            <div className="modal__field-label">Note</div>
            <textarea
              className="note-textarea"
              value={note}
              onChange={e => setNote(e.target.value)}
              placeholder="Add a note about this network..."
              rows={3}
            />
          </div>
        </div>
        <div className="modal__actions">
          <button className="btn btn--ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn--primary" onClick={() => onSave(note, tag)}>Save Note</button>
        </div>
      </div>
    </div>
  );
}

export default function ChannelMap() {
  const [networks,  setNetworks]  = useState([]);
  const [notes,     setNotes]     = useState({});
  const [whitelist, setWhitelist] = useState(new Set());
  const [loading,   setLoading]   = useState(false);
  const [toast,     setToast]     = useState(null);
  const [editNet,   setEditNet]   = useState(null);
  const [lastScan,  setLastScan]  = useState(null);

  const showToast = (m, t = 'success') => setToast({ m, t });

  const loadNotes = useCallback(async () => {
    try {
      const [nRes, wRes] = await Promise.all([
        fetch(`${API}/notes`),
        fetch(`${API}/whitelist`),
      ]);
      const nJson = await nRes.json();
      const wJson = await wRes.json();
      setNotes(nJson?.data?.notes || nJson?.notes || {});
      const wArr = wJson?.data?.whitelist || wJson?.whitelist || [];
      setWhitelist(new Set(wArr.map(w => w.bssid?.toLowerCase())));
    } catch (e) { console.error(e); }
  }, []);

  const doScan = useCallback(async () => {
    setLoading(true);
    try {
      const res  = await fetch(`${API}/scan`, { method: 'POST' });
      const json = await res.json();
      const raw  = Array.isArray(json) ? json
                 : Array.isArray(json?.data?.networks) ? json.data.networks
                 : Array.isArray(json?.data) ? json.data : [];
      // Deduplicate
      const uniq = {};
      raw.forEach(n => {
        if (!uniq[n.bssid] || (n.signal ?? -100) > (uniq[n.bssid].signal ?? -100))
          uniq[n.bssid] = n;
      });
      setNetworks(Object.values(uniq).sort((a, b) => (a.channel || 0) - (b.channel || 0)));
      setLastScan(new Date().toLocaleTimeString());
      await loadNotes();
    } catch (e) { showToast('Scan failed.', 'error'); }
    finally { setLoading(false); }
  }, [loadNotes]);

  useEffect(() => { loadNotes(); }, [loadNotes]);

  // Build channel congestion data
  const channelData = (() => {
    const m = {};
    networks.forEach(n => {
      const ch = n.channel;
      if (!ch) return;
      if (!m[ch]) m[ch] = { channel: ch, count: 0, networks: [] };
      m[ch].count++;
      m[ch].networks.push(n);
    });
    return Object.values(m).sort((a, b) => a.channel - b.channel);
  })();

  const band24 = channelData.filter(c => c.channel <= 14);
  const band5  = channelData.filter(c => c.channel > 14);

  const congestionColor = (count) => count >= 4 ? '#c0392b' : count >= 2 ? '#b45309' : '#2d7d6f';

  const saveNote = async (note, tag) => {
    const net = editNet;
    setEditNet(null);
    try {
      const res = await fetch(`${API}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bssid: net.bssid, note, tag }),
      });
      if (res.ok) {
        showToast(`Note saved for ${net.ssid}.`, 'success');
        await loadNotes();
      } else showToast('Failed to save note.', 'error');
    } catch { showToast('Backend unreachable.', 'error'); }
  };

  const toggleWhitelist = async (net) => {
    const bssid = net.bssid?.toLowerCase();
    const isTrusted = whitelist.has(bssid);
    try {
      if (isTrusted) {
        await fetch(`${API}/whitelist/${net.bssid}`, { method: 'DELETE' });
        showToast(`${net.ssid} removed from trusted list.`, 'warn');
      } else {
        await fetch(`${API}/whitelist`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ bssid: net.bssid, ssid: net.ssid }),
        });
        showToast(`${net.ssid} marked as trusted.`, 'success');
      }
      await loadNotes();
    } catch { showToast('Request failed.', 'error'); }
  };

  const enriched = networks.map(n => ({
    ...n,
    note:      notes[n.bssid]?.note || '',
    tag:       notes[n.bssid]?.tag  || '',
    trusted:   whitelist.has(n.bssid?.toLowerCase()),
  }));

  const Tip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    const d = payload[0].payload;
    return (
      <div style={{ background:'#161b27', border:'1px solid rgba(255,255,255,.1)', padding:'.5rem .75rem', borderRadius:'4px', fontFamily:'IBM Plex Mono,monospace', fontSize:'.68rem' }}>
        <div style={{ color:'#c8d3e0', marginBottom:'3px' }}>Channel {d.channel}</div>
        <div style={{ color: congestionColor(d.count) }}>{d.count} network{d.count !== 1 ? 's' : ''}</div>
        {d.count >= 3 && <div style={{ color:'#c0392b', marginTop:'2px' }}>⚠ Congested</div>}
      </div>
    );
  };

  return (
    <div className="page-root">
      {toast && <Toast message={toast.m} type={toast.t} onDone={() => setToast(null)} />}
      {editNet && <NoteModal network={editNet} onSave={saveNote} onClose={() => setEditNet(null)} />}

      <header className="pg-header">
        <div>
          <div className="pg-eyebrow">System / Scanner / Channel Analysis</div>
          <h1 className="pg-title">Channel Map</h1>
          <div className="pg-meta">
            {lastScan && <span className="pg-tag">Last scan: {lastScan}</span>}
            <span className="pg-tag">{networks.length} networks</span>
            <span className="pg-tag">{Object.keys(notes).length} annotated</span>
            <span className="pg-tag">{whitelist.size} trusted</span>
          </div>
        </div>
        <button
          className={`btn btn--primary ${loading ? 'btn--loading' : ''}`}
          onClick={doScan}
          disabled={loading}
        >
          {loading ? 'Scanning...' : 'Scan & Refresh'}
        </button>
      </header>

      <div className="pg-body">

        {/* Channel congestion charts */}
        {channelData.length > 0 && (
          <div className="channel-charts">
            {band24.length > 0 && (
              <div className="an-panel">
                <div className="an-panel__label">
                  2.4 GHz Band
                  <span className="an-panel__sub" style={{ marginLeft: '.5rem' }}>
                    {band24.filter(c => c.count >= 3).length} congested channel(s)
                  </span>
                </div>
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart data={band24} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,.04)" vertical={false} />
                    <XAxis dataKey="channel" tick={{ fill: '#4a5568', fontSize: 9, fontFamily: 'IBM Plex Mono,monospace' }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#4a5568', fontSize: 9 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip content={<Tip />} />
                    <Bar dataKey="count" radius={[3, 3, 0, 0]} name="Networks">
                      {band24.map((c, i) => <Cell key={i} fill={congestionColor(c.count)} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
            {band5.length > 0 && (
              <div className="an-panel">
                <div className="an-panel__label">5 GHz Band</div>
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart data={band5} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,.04)" vertical={false} />
                    <XAxis dataKey="channel" tick={{ fill: '#4a5568', fontSize: 9, fontFamily: 'IBM Plex Mono,monospace' }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#4a5568', fontSize: 9 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip content={<Tip />} />
                    <Bar dataKey="count" radius={[3, 3, 0, 0]} name="Networks">
                      {band5.map((c, i) => <Cell key={i} fill={congestionColor(c.count)} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        )}

        {/* Network table with notes/whitelist */}
        {/* Dual-band info note */}
        {networks.length > 0 && (() => {
          const ssidCounts = {};
          networks.forEach(n => { ssidCounts[n.ssid] = (ssidCounts[n.ssid] || 0) + 1; });
          const dualBand = Object.values(ssidCounts).some(c => c > 1);
          return dualBand ? (
            <div className="dual-band-note">
              <span>ℹ</span>
              Networks appearing more than once have multiple radios (dual-band or mesh).
              Each BSSID is a separate radio — this is normal router behaviour.
            </div>
          ) : null;
        })()}

        {networks.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state__icon">◈</div>
            <h3 className="empty-state__title">No scan data</h3>
            <p className="empty-state__sub">Run a scan to see channel map and annotate networks.</p>
            <button className="btn btn--primary" onClick={doScan}>Run Scan</button>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr>
                <th>SSID</th>
                <th>BSSID</th>
                <th>Channel</th>
                <th>Band</th>
                <th>Signal</th>
                <th>Trust</th>
                <th>Tag</th>
                <th>Note</th>
                <th style={{ textAlign: 'center' }}>Trusted</th>
                <th style={{ textAlign: 'center' }}>Edit</th>
              </tr></thead>
              <tbody>
                {enriched.map((net, i) => {
                  // Band comes from backend netsh enrichment — authoritative on Windows
      const band = net.band && net.band !== 'Unknown'
        ? net.band
        : net.channel
          ? net.channel <= 14 ? '2.4 GHz' : net.channel <= 177 ? '5 GHz' : '6 GHz'
          : null;
                  const congested = (channelData.find(c => c.channel === net.channel)?.count || 0) >= 3;
                  return (
                    <tr key={net.bssid || i} className={net.threats?.length > 0 && !net.trusted ? 'row--threat' : ''}>
                      <td>
                        <div style={{ fontFamily: 'Syne,sans-serif', fontWeight: 600, fontSize: '.82rem', color: '#c8d3e0' }}>
                          {net.ssid}
                          {net.trusted && <span className="trusted-badge">✓ Trusted</span>}
                          {net.whitelisted && <span className="trusted-badge">✓ Whitelisted</span>}
                        </div>
                        <div className="td-dim" style={{ fontSize: '.58rem' }}>{net.vendor || '—'}</div>
                      </td>
                      <td className="td-mono" style={{ fontSize: '.65rem' }}>{net.bssid}</td>
                      <td>
                        <span className={`ch-badge ${congested ? 'ch-badge--busy' : net.channel == null ? 'ch-badge--unknown' : ''}`}>
                          {net.channel != null ? `CH ${net.channel}` : '—'}
                        </span>
                      </td>
                      <td className="td-dim" style={{ fontSize: '.68rem' }}>
                        {band
                          ? <span style={{ color: band === '5 GHz' ? '#7e5bef' : band === '6 GHz' ? '#3b7dd8' : '#7e8fa4' }}>{band}</span>
                          : <span style={{ color: '#4a5568' }}>—</span>
                        }
                      </td>
                      <td className="td-mono" style={{ fontSize: '.65rem' }}>{net.signal ?? '—'} dBm</td>
                      <td>
                        <div className="score-track">
                          <div className="score-bar">
                            <div className="score-fill" style={{ width: `${net.trust_score}%`, background: riskCol(net.trust_score) }} />
                          </div>
                          <span className="score-num" style={{ color: riskCol(net.trust_score) }}>{net.trust_score}</span>
                        </div>
                      </td>
                      <td>
                        {net.tag ? (
                          <span className="tag-chip" style={{ color: TAG_COLORS[net.tag], borderColor: TAG_COLORS[net.tag] + '55' }}>
                            {net.tag}
                          </span>
                        ) : <span className="td-dim">—</span>}
                      </td>
                      <td style={{ maxWidth: '180px' }}>
                        <span style={{ fontSize: '.75rem', color: '#7e8fa4', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {net.note || <span className="td-dim">—</span>}
                        </span>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <button
                          className={`btn ${net.trusted ? 'btn--ghost' : 'btn--ghost'}`}
                          style={{
                            fontSize: '.65rem', padding: '.25rem .6rem',
                            color: net.trusted ? '#2d7d6f' : '#4a5568',
                            borderColor: net.trusted ? 'rgba(45,125,111,.4)' : 'rgba(255,255,255,.08)',
                          }}
                          onClick={() => toggleWhitelist(net)}
                        >
                          {net.trusted ? '✓ Trusted' : 'Trust'}
                        </button>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <button
                          className="btn btn--ghost"
                          style={{ fontSize: '.65rem', padding: '.25rem .6rem' }}
                          onClick={() => setEditNet(net)}
                        >
                          ✎ Note
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}