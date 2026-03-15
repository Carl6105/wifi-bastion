import { useState, useEffect, useMemo } from 'react';
import './History.css';

const API = 'http://127.0.0.1:5000/api';

function riskCol(s) { return s>=80?'#2d7d6f':s>=50?'#b45309':'#c0392b'; }
function riskBadge(s) { return s>=80?'low':s>=50?'medium':s>=25?'high':'critical'; }

function fmt(ts) {
  if(!ts) return '—';
  const d = typeof ts==='string'?new Date(ts):ts>1e10?new Date(ts):new Date(ts*1000);
  return isNaN(d)?'—':d.toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
function fmtDay(ts) {
  if(!ts) return 'UNKNOWN';
  const d = typeof ts==='string'?new Date(ts):ts>1e10?new Date(ts):new Date(ts*1000);
  const t=new Date(); const y=new Date(t); y.setDate(t.getDate()-1);
  if(d.toDateString()===t.toDateString()) return 'TODAY';
  if(d.toDateString()===y.toDateString()) return 'YESTERDAY';
  return d.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}).toUpperCase();
}

function Toast({message,type,onDone}) {
  useEffect(()=>{ const t=setTimeout(onDone,3000); return ()=>clearTimeout(t); },[]);
  return <div className={`toast toast--${type}`}><span>{type==='success'?'✓':'✕'}</span>{message}</div>;
}

function PurgeModal({onConfirm,onCancel}) {
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal modal--danger" onClick={e=>e.stopPropagation()}>
        <div className="modal__title"><span className="modal__icon">⚠</span>Destructive Operation</div>
        <p className="modal__body">Permanently delete all scan history and security logs? This cannot be undone.</p>
        <p className="modal__warn">// PURGE_ARCHIVE — IRREVERSIBLE</p>
        <div className="modal__actions">
          <button className="btn btn--ghost"  onClick={onCancel}> Abort</button>
          <button className="btn btn--danger" onClick={onConfirm}>Confirm Purge</button>
        </div>
      </div>
    </div>
  );
}

function HistRow({entry,idx}) {
  const [open,setOpen] = useState(false);
  const hasT = Array.isArray(entry.threats)?entry.threats.length>0:!!entry.threats;
  const threats = Array.isArray(entry.threats)?entry.threats:entry.threats?[String(entry.threats)]:[];
  const score = entry.trust_score??0;

  return (
    <>
      <tr className={`data-table tbody tr ${hasT?'row--threat':''} ${open?'row--open':''}`}
          onClick={()=>setOpen(p=>!p)} style={{cursor:'pointer'}}>
        <td className="td-dim" style={{textAlign:'center'}}>{String(idx+1).padStart(3,'0')}</td>
        <td className="td-mono" style={{fontSize:'.65rem'}}>{fmt(entry.timestamp)}</td>
        <td>
          <div style={{fontFamily:'Syne,system-ui,sans-serif',fontSize:'.82rem',fontWeight:600,color:'#c8d3e0',marginBottom:'2px'}}>{entry.ssid||'Hidden Network'}</div>
          {entry.bssid&&<div className="td-dim" style={{fontSize:'.58rem'}}>{entry.bssid}</div>}
        </td>
        <td>{entry.encryption&&<span className="badge" style={{color:'#3b7dd8',borderColor:'rgba(59,125,216,.3)'}}>{entry.encryption}</span>}</td>
        <td>
          {hasT?(
            <span className="badge badge--critical">{threats.length} Threat{threats.length>1?'s':''}</span>
          ):(
            <span className="clean-row"><span className="dot dot--live"/>Clean</span>
          )}
        </td>
        <td>
          <div className="score-track">
            <div className="score-bar"><div className="score-fill" style={{width:`${score}%`,background:riskCol(score)}}/></div>
            <span className="score-num" style={{color:riskCol(score)}}>{score}</span>
          </div>
        </td>
        <td className="td-center td-dim" style={{fontSize:'.6rem'}}>{open?'▲':'▼'}</td>
      </tr>

      {open&&(
        <tr className="detail-row">
          <td colSpan={7}>
            <div className="detail-inner">
              {hasT&&(
                <div className="detail-section">
                  <div className="detail-section__label">Active Threats</div>
                  <div className="detail-chips">
                    {threats.map((t,i)=><span key={i} className="detail-chip">{t}</span>)}
                  </div>
                </div>
              )}
              <div className="detail-vectors">
                {[
                  {l:'DNS Secure',   v:entry.dns_secure},
                  {l:'Protocol',     v:entry.protocol_strength},
                  {l:'Packet Int.',  v:entry.packet_integrity},
                  {l:'Signal',       v:entry.signal_quality},
                ].filter(x=>x.v!==undefined).map(({l,v})=>(
                  <div key={l} className="vec-row">
                    <span className="vec-label">{l}</span>
                    <div className="vec-bar"><div className="vec-fill" style={{width:`${v}%`,background:riskCol(v)}}/></div>
                    <span className="vec-val">{v}</span>
                  </div>
                ))}
              </div>
              <div className="detail-meta">
                {entry.vendor&&<div className="dm-pair"><span className="dm-pair__k">Vendor</span><span className="dm-pair__v">{entry.vendor}</span></div>}
                {entry.signal!==undefined&&<div className="dm-pair"><span className="dm-pair__k">Signal</span><span className="dm-pair__v">{entry.signal} dBm</span></div>}
                {entry._id&&<div className="dm-pair"><span className="dm-pair__k">ID</span><span className="dm-pair__v" style={{fontSize:'.55rem',opacity:.6}}>{entry._id}</span></div>}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function History() {
  const [history,   setHistory]   = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState(null);
  const [showPurge, setShowPurge] = useState(false);
  const [toast,     setToast]     = useState(null);
  const [search,    setSearch]    = useState('');
  const [filter,    setFilter]    = useState('ALL');
  const [sortDir,   setSortDir]   = useState('DESC');

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const r = await fetch(`${API}/history`); const j = await r.json();
      const a = Array.isArray(j)?j:Array.isArray(j?.data?.scans)?j.data.scans:Array.isArray(j?.data)?j.data:[];
      setHistory(a);
    } catch { setError('Failed to load history.'); } finally { setLoading(false); }
  };

  const purge = async () => {
    setShowPurge(false);
    try {
      const r = await fetch(`${API}/history`,{method:'DELETE'});
      if(r.ok) { setHistory([]); setToast({m:'Archive purged.',t:'warn'}); }
      else setError('Purge failed.');
    } catch { setError('Backend unreachable.'); }
  };

  useEffect(()=>{ load(); },[]);

  const stats = useMemo(()=>{
    const threats = history.filter(h=>Array.isArray(h.threats)?h.threats.length>0:!!h.threats).length;
    const avg = history.length?Math.round(history.reduce((s,h)=>s+(h.trust_score||0),0)/history.length):0;
    return {total:history.length, threats, clean:history.length-threats, avg};
  },[history]);

  const displayed = useMemo(()=>{
    let out=[...history];
    if(filter==='THREATS') out=out.filter(h=>Array.isArray(h.threats)?h.threats.length>0:!!h.threats);
    if(filter==='CLEAN')   out=out.filter(h=>Array.isArray(h.threats)?h.threats.length===0:!h.threats);
    if(search.trim()){const q=search.toLowerCase(); out=out.filter(h=>(h.ssid||'').toLowerCase().includes(q)||(h.bssid||'').toLowerCase().includes(q)||(h.encryption||'').toLowerCase().includes(q)||(h.vendor||'').toLowerCase().includes(q));}
    out.sort((a,b)=>{const ta=a.timestamp||0,tb=b.timestamp||0; return sortDir==='DESC'?tb-ta:ta-tb;});
    return out;
  },[history,filter,search,sortDir]);

  const grouped = useMemo(()=>{
    const g=[]; let last=null;
    displayed.forEach((e,i)=>{
      const day=fmtDay(e.timestamp);
      if(day!==last){g.push({type:'day',label:day,key:`d-${day}`}); last=day;}
      g.push({type:'row',entry:e,idx:i,key:e._id||i});
    });
    return g;
  },[displayed]);

  if(loading) return <div className="load-screen"><div className="load-ring"/><div className="load-text">Accessing archive...</div></div>;

  return (
    <div className="page-root">
      {toast&&<Toast message={toast.m} type={toast.t} onDone={()=>setToast(null)}/>}
      {showPurge&&<PurgeModal onConfirm={purge} onCancel={()=>setShowPurge(false)}/>}

      <header className="pg-header">
        <div>
          <div className="pg-eyebrow">System / Data Retention / Logs</div>
          <h1 className="pg-title">Scan History Archive</h1>
          <div className="pg-meta">
            <span className="pg-tag">{stats.total} Records</span>
            <span className="pg-tag">{displayed.length} Shown</span>
          </div>
        </div>
        <div className="pg-header__actions">
          <button className="btn btn--ghost" onClick={load}>Refresh</button>
          {history.length>0&&<button className="btn btn--danger" onClick={()=>setShowPurge(true)}>Purge Archive</button>}
        </div>
      </header>

      <div className="pg-body">
        {error&&<div className="alert-bar alert-bar--error"><span>⚠</span><span>{error}</span><button className="alert-bar__close" onClick={()=>setError(null)}>✕</button></div>}

        <div className="stats-row">
          <div className="stat-cell"><span className="stat-cell__val">{stats.total}</span><span className="stat-cell__label">Total Records</span></div>
          <div className="stat-divider"/>
          <div className="stat-cell"><span className="stat-cell__val" style={{color:stats.threats>0?'#c0392b':'#7e8fa4'}}>{stats.threats}</span><span className="stat-cell__label">With Threats</span></div>
          <div className="stat-divider"/>
          <div className="stat-cell"><span className="stat-cell__val" style={{color:'#2d7d6f'}}>{stats.clean}</span><span className="stat-cell__label">Clean</span></div>
          <div className="stat-divider"/>
          <div className="stat-cell"><span className="stat-cell__val" style={{color:riskCol(stats.avg)}}>{stats.avg}</span><span className="stat-cell__label">Avg Trust</span></div>
        </div>

        <div className="controls-row">
          <div className="search-box" style={{flex:1,maxWidth:'320px'}}>
            <span className="search-box__icon">⌕</span>
            <input className="search-box__input" placeholder="Search SSID, BSSID, vendor..." value={search} onChange={e=>setSearch(e.target.value)}/>
            {search&&<button className="search-box__clear" onClick={()=>setSearch('')}>✕</button>}
          </div>
          <div className="filter-group">
            {['ALL','THREATS','CLEAN'].map(f=>(
              <button key={f} className={`filter-btn ${filter===f?'filter-btn--active':''}`} onClick={()=>setFilter(f)}>{f}</button>
            ))}
          </div>
          <button className="sort-btn" onClick={()=>setSortDir(d=>d==='DESC'?'ASC':'DESC')}>
            {sortDir==='DESC'?'↓ Newest':'↑ Oldest'}
          </button>
        </div>

        {history.length===0?(
          <div className="empty-state">
            <div className="empty-state__icon">▣</div>
            <h3 className="empty-state__title">No archive data</h3>
            <p className="empty-state__sub">Run a network scan to begin building security history.</p>
          </div>
        ):displayed.length===0?(
          <div className="empty-state" style={{minHeight:'160px',padding:'2rem'}}>
            <p className="empty-state__sub">No records match your query.</p>
          </div>
        ):(
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr>
                <th style={{width:'46px',textAlign:'center'}}>#</th>
                <th>Timestamp</th>
                <th>Network</th>
                <th>Encryption</th>
                <th>Status</th>
                <th>Trust</th>
                <th style={{width:'32px'}}/>
              </tr></thead>
              <tbody>
                {grouped.map(item=>item.type==='day'?(
                  <tr key={item.key} className="day-divider-row">
                    <td colSpan={7}>
                      <div className="day-divider">
                        <div className="day-divider__line"/>
                        <span className="day-divider__label">{item.label}</span>
                        <div className="day-divider__line"/>
                      </div>
                    </td>
                  </tr>
                ):(
                  <HistRow key={item.key} entry={item.entry} idx={item.idx}/>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}