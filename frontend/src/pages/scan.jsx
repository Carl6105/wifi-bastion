import React, { useState, useEffect, useCallback } from 'react';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Cell } from 'recharts';
import './scan.css';

const API = 'http://127.0.0.1:5000/api';

function riskCol(s) { return s>=80?'#2d7d6f':s>=50?'#b45309':'#c0392b'; }
function encCol(e='') {
  const u=e.toUpperCase();
  if(u.includes('WPA3'))return'#2d7d6f'; if(u.includes('WPA2'))return'#3b7dd8';
  if(u.includes('WPA'))return'#b45309'; return'#c0392b';
}

function Toast({message,type,onDone}){
  useEffect(()=>{const t=setTimeout(onDone,3000);return()=>clearTimeout(t);},[]);
  return <div className={`toast toast--${type}`}><span>{type==='success'?'✓':'✕'}</span>{message}</div>;
}

const Tip = ({active,payload})=>{
  if(!active||!payload?.length) return null;
  return <div style={{background:'#161b27',border:'1px solid rgba(255,255,255,.1)',padding:'.4rem .65rem',borderRadius:'4px',fontFamily:'IBM Plex Mono,monospace',fontSize:'.68rem',color:'#7e8fa4'}}>
    {payload.map((p,i)=><div key={i} style={{color:p.color}}>{p.name}: <strong style={{color:'#c8d3e0'}}>{p.value}</strong></div>)}
  </div>;
};

function ScanState(){
  const [step,setStep]=useState(0);
  const STEPS=['Binding 802.11 socket...','Sweeping 2.4 GHz band...','Sweeping 5 GHz band...','Parsing beacon frames...','Running threat analysis...','Computing trust vectors...'];
  useEffect(()=>{const t=setInterval(()=>setStep(s=>Math.min(s+1,STEPS.length)),650);return()=>clearInterval(t);},[]);
  return(
    <div className="scan-state">
      <div className="scan-ring-wrap">
        <div className="scan-ring"/><div className="scan-ring scan-ring--2"/><div className="scan-ring scan-ring--3"/>
        <div className="scan-sweep"/><div className="scan-core"/>
      </div>
      <div className="scan-log">
        {STEPS.slice(0,step).map((s,i)=>(
          <div key={i} className={`scan-log__line ${i===step-1?'scan-log__line--cur':''}`}>
            <span className="scan-log__tick">{i<step-1?'✓':'▶'}</span>{s}
          </div>
        ))}
        {step<=STEPS.length&&<span className="scan-log__cursor">█</span>}
      </div>
    </div>
  );
}

function ExpandedRow({net,history}){
  const hist=history[net.bssid]||[];
  return(
    <tr className="detail-row">
      <td colSpan={7}>
        <div className="exp-grid">
          {/* Metadata */}
          <div className="exp-panel">
            <div className="exp-panel__label">Metadata</div>
            {[
              {k:'BSSID',v:net.bssid},
              {k:'Vendor',v:net.vendor},
              {k:'Signal',v:net.signal!=null?`${net.signal} dBm`:'—'},
              {k:'Distance',v:net.distance!=null?`${net.distance} m`:'—'},
              {k:'Encryption',v:net.encryption},
            ].map(({k,v})=>(
              <div key={k} className="meta-kv">
                <span className="meta-kv__k">{k}</span>
                <span className="meta-kv__v" style={k==='Encryption'?{color:encCol(v)}:{}}>{v||'—'}</span>
              </div>
            ))}
            <div className="meta-kv">
              <span className="meta-kv__k">Trust</span>
              <span className="meta-kv__score" style={{color:riskCol(net.trust_score)}}>{net.trust_score}/100</span>
            </div>
          </div>

          {/* Signal history */}
          <div className="exp-panel">
            <div className="exp-panel__label">RF Signal History</div>
            {hist.length>1?(
              <ResponsiveContainer width="100%" height={130}>
                <AreaChart data={hist} margin={{top:4,right:4,left:-24,bottom:0}}>
                  <defs><linearGradient id="hg" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b7dd8" stopOpacity={.15}/><stop offset="95%" stopColor="#3b7dd8" stopOpacity={0}/></linearGradient></defs>
                  <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,.04)" vertical={false}/>
                  <XAxis dataKey="time" tick={{fill:'#4a5568',fontSize:7}} axisLine={false} tickLine={false}/>
                  <YAxis domain={[0,100]} tick={{fill:'#4a5568',fontSize:7}} axisLine={false} tickLine={false}/>
                  <Tooltip content={<Tip/>}/>
                  <Area type="monotone" dataKey="strength" stroke="#3b7dd8" strokeWidth={1.5} fill="url(#hg)" name="Signal"/>
                </AreaChart>
              </ResponsiveContainer>
            ):<div className="exp-panel__empty">Scan again to build history</div>}
          </div>

          {/* Security vectors */}
          <div className="exp-panel">
            <div className="exp-panel__label">Security Vectors</div>
            <ResponsiveContainer width="100%" height={130}>
              <BarChart data={[
                {n:'DNS',v:net.dns_secure??50},{n:'Proto',v:net.protocol_strength??50},
                {n:'Packet',v:net.packet_integrity??100},{n:'Signal',v:net.signal_quality??50},
              ]} margin={{top:4,right:4,left:-24,bottom:0}}>
                <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,.04)" vertical={false}/>
                <XAxis dataKey="n" tick={{fill:'#4a5568',fontSize:8}} axisLine={false} tickLine={false}/>
                <YAxis domain={[0,100]} tick={{fill:'#4a5568',fontSize:8}} axisLine={false} tickLine={false}/>
                <Tooltip content={<Tip/>}/>
                <Bar dataKey="v" name="Score" radius={[2,2,0,0]}>
                  {[net.dns_secure,net.protocol_strength,net.packet_integrity,net.signal_quality].map((v,i)=>(
                    <Cell key={i} fill={riskCol(v??50)}/>
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Radar */}
          <div className="exp-panel">
            <div className="exp-panel__label">Threat Radar</div>
            <ResponsiveContainer width="100%" height={130}>
              <RadarChart data={[
                {s:'DNS',A:net.dns_secure??50},{s:'Proto',A:net.protocol_strength??50},
                {s:'Packet',A:net.packet_integrity??100},{s:'Signal',A:net.signal_quality??50},{s:'Trust',A:net.trust_score??50},
              ]}>
                <PolarGrid stroke="rgba(255,255,255,.06)"/>
                <PolarAngleAxis dataKey="s" tick={{fill:'#4a5568',fontSize:8,fontFamily:'IBM Plex Mono,monospace'}}/>
                <PolarRadiusAxis domain={[0,100]} tick={false} axisLine={false}/>
                <Radar dataKey="A" stroke="#3b7dd8" fill="#3b7dd8" fillOpacity={.08} strokeWidth={1.5}/>
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {net.threats?.length>0&&(
          <div className="detail-section">
            <div className="detail-section__label">Active Threats</div>
            <div className="detail-chips">
              {net.threats.map((t,i)=><span key={i} className="detail-chip">{t}</span>)}
            </div>
          </div>
        )}
      </td>
    </tr>
  );
}

export default function Scan(){
  const [networks,setNetworks]=useState([]);
  const [scanning,setScanning]=useState(false);
  const [error,setError]=useState(null);
  const [auto,setAuto]=useState(false);
  const [lastScan,setLastScan]=useState(null);
  const [expanded,setExpanded]=useState(null);
  const [netHist,setNetHist]=useState({});
  const [scanN,setScanN]=useState(0);
  const [toast,setToast]=useState(null);

  const showToast=(m,t='success')=>{ setToast({m,t}); setTimeout(()=>setToast(null),3000); };

  const doScan=useCallback(async()=>{
    setScanning(true); setError(null);
    try{
      const r=await fetch(`${API}/scan`,{method:'POST'});
      if(!r.ok) throw new Error(`Server ${r.status}`);
      const j=await r.json();
      const raw=Array.isArray(j)?j:Array.isArray(j?.data?.networks)?j.data.networks:Array.isArray(j?.data)?j.data:[];
      const uniq={};
      raw.forEach(n=>{ const k=n.bssid; const s=n.signal??-100; if(!uniq[k]||s>(uniq[k].signal??-100)) uniq[k]=n; });
      const sorted=Object.values(uniq).sort((a,b)=>b.trust_score-a.trust_score);
      setNetworks(sorted); setLastScan(new Date().toLocaleTimeString()); setScanN(c=>c+1);
      setNetHist(prev=>{
        const u={...prev};
        sorted.forEach(n=>{
          const sig=typeof n.signal==='number'?n.signal:-100;
          u[n.bssid]=[...(u[n.bssid]||[]),{time:new Date().toLocaleTimeString().split(' ')[0],strength:Math.max(0,Math.min(100,sig+100))}].slice(-15);
        });
        return u;
      });
    }catch(e){setError(e.message);}finally{setScanning(false);}
  },[]);

  useEffect(()=>{ if(!auto) return; const id=setInterval(doScan,15000); return()=>clearInterval(id); },[auto,doScan]);

  const blockNet=async(net)=>{
    try{
      const r=await fetch(`${API}/block_network`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({network_id:net._id,bssid:net.bssid,ssid:net.ssid})});
      const j=await r.json();
      if(r.ok){ showToast(`${net.ssid||net.bssid} restricted at OS level.`,'success'); doScan(); }
      else showToast(j?.message||'Block failed.','error');
    }catch{ showToast('Block request failed.','error'); }
  };

  const dlReport=async()=>{
    try{
      const r=await fetch(`${API}/generate_report`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({networks})});
      if(!r.ok) throw new Error(`${r.status}`);
      const blob=await r.blob(); const url=URL.createObjectURL(blob);
      const a=Object.assign(document.createElement('a'),{href:url,download:`WiFi_Bastion_${new Date().toISOString().split('T')[0]}.pdf`});
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    }catch(e){setError(`Report error: ${e.message}`);}
  };

  return(
    <div className="page-root">
      {toast&&<Toast message={toast.m} type={toast.t} onDone={()=>setToast(null)}/>}

      <header className="pg-header">
        <div>
          <div className="pg-eyebrow">System / Scanner / RF Analysis</div>
          <h1 className="pg-title">Environment Scanner</h1>
          <div className="pg-meta">
            {lastScan&&<span className="pg-tag">Last scan: {lastScan}</span>}
            <span className="pg-tag">Scans: {scanN}</span>
            <span className="pg-tag">Networks: {networks.length}</span>
          </div>
        </div>
        <div className="pg-header__actions">
          <button className={`btn ${auto?'btn--primary':'btn--ghost'}`} onClick={()=>setAuto(p=>!p)}>
            <span className={`dot ${auto?'dot--live':'dot--off'}`}/>
            {auto?'Auto On':'Auto Off'}
          </button>
          {networks.length>0&&<button className="btn btn--ghost" onClick={dlReport}>Export PDF</button>}
          <button className={`btn btn--primary ${scanning?'btn--loading':''}`} onClick={doScan} disabled={scanning}>
            {scanning?'Scanning...':'Run Scan'}
          </button>
        </div>
      </header>

      <div className="pg-body">
        {error&&<div className="alert-bar alert-bar--error"><span>⚠</span><span>{error}</span><button className="alert-bar__close" onClick={()=>setError(null)}>✕</button></div>}

        {scanning&&networks.length===0?<ScanState/>:
        networks.length===0?(
          <div className="empty-state">
            <div className="empty-state__icon">◈</div>
            <h3 className="empty-state__title">Spectrum unmapped</h3>
            <p className="empty-state__sub">Run a scan to analyse nearby wireless networks.</p>
            <button className="btn btn--primary" onClick={doScan}>Run Scan</button>
          </div>
        ):(
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr>
                <th>Access Point</th>
                <th>Trust</th>
                <th>Encryption</th>
                <th>Threats</th>
                <th style={{textAlign:'center'}}>Signal</th>
                <th style={{textAlign:'center'}}>Audit</th>
                <th style={{textAlign:'center'}}>Action</th>
              </tr></thead>
              <tbody>
                {networks.map(net=>{
                  const isExp=expanded===net.bssid;
                  return(
                    <React.Fragment key={net.bssid}>
                      <tr className={`${net.threats?.length>0?'row--threat':''} ${isExp?'row--open':''} ${scanning?'':''}` } style={{opacity:scanning?.6:1}}>
                        <td>
                          <div style={{fontFamily:'Syne,system-ui,sans-serif',fontSize:'.85rem',fontWeight:600,color:'#c8d3e0',marginBottom:'2px'}}>
                            {net.ssid}
                            {net.band && net.band !== 'Unknown' && (
                              <span style={{
                                fontFamily:'IBM Plex Mono,monospace',
                                fontSize:'.55rem',
                                color: net.band === '5 GHz' ? '#7e5bef' : net.band === '6 GHz' ? '#3b7dd8' : '#4a5568',
                                border: '1px solid currentColor',
                                borderRadius:'3px',
                                padding:'1px 5px',
                                marginLeft:'.5rem',
                                opacity:.8,
                              }}>{net.band}</span>
                            )}
                            {net.channel && (
                              <span style={{fontFamily:'IBM Plex Mono,monospace',fontSize:'.55rem',color:'#4a5568',marginLeft:'.35rem'}}>
                                CH {net.channel}
                              </span>
                            )}
                          </div>
                          <div style={{display:'flex',gap:'.4rem',alignItems:'center'}}>
                            <span className="td-dim" style={{fontSize:'.58rem'}}>{net.bssid}</span>
                            <span className="td-mono" style={{fontSize:'.58rem',color:'#3b7dd8'}}>{net.vendor||''}</span>
                          </div>
                        </td>
                        <td style={{minWidth:'110px'}}>
                          <div className="score-track">
                            <div className="score-bar"><div className="score-fill" style={{width:`${net.trust_score}%`,background:riskCol(net.trust_score)}}/></div>
                            <span className="score-num" style={{color:riskCol(net.trust_score)}}>{net.trust_score}</span>
                          </div>
                        </td>
                        <td><span className="enc-tag" style={{color:encCol(net.encryption),borderColor:encCol(net.encryption)+'66'}}>{net.encryption}</span></td>
                        <td>
                          {net.threats?.length>0?(
                            <div className="threat-inline">
                              <span className="threat-count">{net.threats.length} threat{net.threats.length>1?'s':''}</span>
                              <span style={{fontSize:'.72rem',color:'#7e8fa4'}}>{net.threats[0]}</span>
                            </div>
                          ):(
                            <div className="clean-row"><span className="dot dot--live"/>Clean</div>
                          )}
                        </td>
                        <td style={{textAlign:'center'}}>
                          <div className="sig-bars">
                            {[1,2,3,4,5].map(i=>{
                              const sig=typeof net.signal==='number'?net.signal:-100;
                              const thresh=-100+i*15;
                              return <div key={i} className="sig-bar" style={{height:`${i*4+3}px`,background:sig>=thresh?riskCol(net.trust_score):'#1a2030',opacity:sig>=thresh?1:.25}}/>;
                            })}
                          </div>
                          <div className="sig-val">{net.signal??'—'}</div>
                        </td>
                        <td style={{textAlign:'center'}}>
                          <button className={`expand-btn ${isExp?'expand-btn--open':''}`} onClick={()=>setExpanded(isExp?null:net.bssid)}>
                            {isExp?'▲':'▼'}
                          </button>
                        </td>
                        <td style={{textAlign:'center'}}>
                          <button className="btn btn--danger" style={{fontSize:'.72rem',padding:'.3rem .65rem'}} onClick={()=>blockNet(net)}>Block</button>
                        </td>
                      </tr>
                      {isExp&&<ExpandedRow net={net} history={netHist}/>}
                    </React.Fragment>
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