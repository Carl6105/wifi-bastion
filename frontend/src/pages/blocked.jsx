import { useState, useEffect, useCallback } from 'react';
import './Blocked.css';

const API = 'http://127.0.0.1:5000/api';

function fmt(ts) {
  if(!ts) return '—';
  const d=typeof ts==='string'?new Date(ts):ts>1e10?new Date(ts):new Date(ts*1000);
  return isNaN(d)?'—':d.toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
}

function Toast({message,type,onDone}) {
  useEffect(()=>{ const t=setTimeout(onDone,3000); return ()=>clearTimeout(t); },[]);
  return <div className={`toast toast--${type}`}><span>{type==='success'?'✓':type==='warn'?'⚠':'✕'}</span>{message}</div>;
}

function ReleaseModal({network,onConfirm,onCancel}) {
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal modal--warn" onClick={e=>e.stopPropagation()}>
        <div className="modal__title"><span className="modal__icon">⚠</span>Policy Modification</div>
        <p className="modal__body">Release OS-level filter for:</p>
        <code className="modal__code">{network.ssid||network.bssid||'—'}</code>
        <p className="modal__warn">The system will allow connections to this BSSID again.</p>
        <div className="modal__actions">
          <button className="btn btn--ghost"  onClick={onCancel}>Abort</button>
          <button className="btn btn--amber"  onClick={onConfirm}>Release Filter</button>
        </div>
      </div>
    </div>
  );
}

export default function Blocked() {
  const [list,    setList]    = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [release, setRelease] = useState(null);
  const [toast,   setToast]   = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r=await fetch(`${API}/blocked`); if(!r.ok) throw new Error();
      const j=await r.json();
      const a=Array.isArray(j)?j:Array.isArray(j?.data?.blocked)?j.data.blocked:Array.isArray(j?.blocked)?j.blocked:Array.isArray(j?.data)?j.data:[];
      setList(a);
    } catch { setError('Failed to retrieve restriction policy.'); } finally { setLoading(false); }
  },[]);

  const unblock = async () => {
    const net=release; setRelease(null);
    try {
      const r=await fetch(`${API}/unblock_network`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({network_id:net._id||net.network_id,ssid:net.ssid})});
      const j=await r.json();
      if(r.ok){ setToast({m:`Filter released — ${net.ssid||net.bssid}`,t:'warn'}); load(); }
      else setToast({m:j?.message||'Unblock failed.',t:'error'});
    } catch { setToast({m:'Backend unreachable.',t:'error'}); }
  };

  useEffect(()=>{ load(); },[load]);

  if(loading) return <div className="load-screen"><div className="load-ring"/><div className="load-text">Querying restriction policy...</div></div>;

  return (
    <div className="page-root">
      {toast&&<Toast message={toast.m} type={toast.t} onDone={()=>setToast(null)}/>}
      {release&&<ReleaseModal network={release} onConfirm={unblock} onCancel={()=>setRelease(null)}/>}

      <header className="pg-header">
        <div>
          <div className="pg-eyebrow">System / Policy Engine / Blacklist</div>
          <h1 className="pg-title">Active Hardware Restrictions</h1>
          <div className="pg-meta">
            <span className={`pg-tag ${list.length>0?'pg-tag--alert':'pg-tag--ok'}`}>
              {list.length} Filter{list.length!==1?'s':''} Active
            </span>
          </div>
        </div>
        <button className="btn btn--ghost" onClick={load}>Refresh</button>
      </header>

      <div className="pg-body">
        {error&&<div className="alert-bar alert-bar--error"><span>⚠</span><span>{error}</span><button className="alert-bar__close" onClick={()=>setError(null)}>✕</button></div>}

        <div className="stats-row">
          <div className="stat-cell">
            <span className="stat-cell__val" style={{color:list.length>0?'#c0392b':'#7e8fa4'}}>{list.length}</span>
            <span className="stat-cell__label">Restricted BSSIDs</span>
          </div>
          <div className="stat-divider"/>
          <div className="stat-cell">
            <span className="stat-cell__val" style={{fontSize:'1rem',color:list.length>0?'#c0392b':'#2d7d6f'}}>{list.length>0?'ENFORCED':'CLEAR'}</span>
            <span className="stat-cell__label">Policy Status</span>
          </div>
          <div className="stat-divider"/>
          <div className="stat-cell">
            <span className="stat-cell__val" style={{fontSize:'1rem',color:'#b45309'}}>OS-LEVEL</span>
            <span className="stat-cell__label">Filter Depth</span>
          </div>
        </div>

        {list.length===0?(
          <div className="empty-state">
            <div className="empty-state__icon">◉</div>
            <h3 className="empty-state__title">No active restrictions</h3>
            <p className="empty-state__sub">Wireless environment is unrestricted. Block networks from the Scanner page.</p>
          </div>
        ):(
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr>
                <th style={{width:'46px',textAlign:'center'}}>#</th>
                <th>Network SSID</th>
                <th>BSSID</th>
                <th>Date Blocked</th>
                <th>Status</th>
                <th style={{textAlign:'right'}}>Action</th>
              </tr></thead>
              <tbody>
                {list.map((net,i)=>(
                  <tr key={net._id||net.bssid||i} className="row--threat">
                    <td className="td-dim" style={{textAlign:'center'}}>{String(i+1).padStart(3,'0')}</td>
                    <td>
                      <div style={{fontFamily:'Syne,system-ui,sans-serif',fontSize:'.82rem',fontWeight:600,color:'#c8d3e0'}}>{net.ssid||'Hidden Network'}</div>
                      {net.network_id&&<div className="td-dim" style={{fontSize:'.55rem'}}>ID: {net.network_id}</div>}
                    </td>
                    <td className="td-mono" style={{fontSize:'.65rem'}}>{net.bssid||'—'}</td>
                    <td className="td-mono" style={{fontSize:'.65rem'}}>{fmt(net.blocked_at||net.timestamp)}</td>
                    <td>
                      <div style={{display:'flex',alignItems:'center',gap:'.35rem'}}>
                        <span className="dot dot--danger"/>
                        <span className="td-mono" style={{fontSize:'.6rem',color:'#c0392b'}}>Restricted</span>
                      </div>
                    </td>
                    <td style={{textAlign:'right'}}>
                      <button className="btn btn--amber" onClick={()=>setRelease(net)}>Release</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}