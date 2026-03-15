import { useState, useCallback, useRef, useEffect } from 'react';
import './DeviceMap.css';

const API = 'http://127.0.0.1:5000/api';

const TYPES = {
  MOBILE: { icon:'▲', color:'#b45309', label:'Mobile',         code:'MOB', rank:1 },
  WORK:   { icon:'■', color:'#3b7dd8', label:'Workstation',     code:'WRK', rank:2 },
  INFRA:  { icon:'⬡', color:'#2d7d6f', label:'Infrastructure',  code:'INF', rank:3 },
  MEDIA:  { icon:'◈', color:'#c0392b', label:'Media Device',    code:'MED', rank:4 },
  PERIPH: { icon:'◆', color:'#7e5bef', label:'Peripheral',      code:'PRF', rank:5 },
  UNK:    { icon:'●', color:'#4a5568', label:'Unknown',         code:'UNK', rank:6 },
};

function classify(d){
  const os=(d.os||'').toLowerCase(), type=(d.device_type||'').toLowerCase();
  if(type.includes('phone')||os.includes('android')||os.includes('ios')) return TYPES.MOBILE;
  if(os.includes('windows')||os.includes('mac')||os.includes('linux')||type.includes('general')) return TYPES.WORK;
  if(type.includes('router')||type.includes('bridge')||type.includes('switch')||type.includes('wap')) return TYPES.INFRA;
  if(os.includes('tizen')||os.includes('webos')||type.includes('media')) return TYPES.MEDIA;
  if(type.includes('printer')||type.includes('storage')||type.includes('specialized')) return TYPES.PERIPH;
  return TYPES.UNK;
}

function Toast({message,type,onDone}){
  useEffect(()=>{const t=setTimeout(onDone,3000);return()=>clearTimeout(t);},[]);
  return <div className={`toast toast--${type}`}><span>{type==='success'?'✓':'✕'}</span>{message}</div>;
}

function DeauthModal({mac,onConfirm,onCancel}){
  return(
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal modal--danger" onClick={e=>e.stopPropagation()}>
        <div className="modal__title"><span className="modal__icon">⚠</span>Deauthentication Warning</div>
        <p className="modal__body">Transmit 802.11 deauth frames to target node:</p>
        <code className="modal__code">{mac}</code>
        <p className="modal__warn">⚠ Authorised use only. Illegal without permission.</p>
        <div className="modal__actions">
          <button className="btn btn--ghost"  onClick={onCancel}>Abort</button>
          <button className="btn btn--danger" onClick={onConfirm}>Transmit</button>
        </div>
      </div>
    </div>
  );
}

function TopoCanvas({groups,selectedIp,onSelect}){
  const svgRef=useRef(null); const nodeRefs=useRef({});
  const [lines,setLines]=useState([]);

  useEffect(()=>{
    const svg=svgRef.current; if(!svg) return;
    const sr=svg.getBoundingClientRect();
    const gw=nodeRefs.current['__gw__']; if(!gw) return;
    const gr=gw.getBoundingClientRect();
    const gx=gr.left-sr.left+gr.width/2, gy=gr.top-sr.top+gr.height/2;
    const nl=[];
    Object.entries(nodeRefs.current).forEach(([ip,el])=>{
      if(ip==='__gw__'||!el) return;
      const r=el.getBoundingClientRect();
      nl.push({ip,x1:gx,y1:gy,x2:r.left-sr.left+r.width/2,y2:r.top-sr.top+r.height/2});
    });
    setLines(nl);
  });

  return(
    <div className="topo-wrap">
      <svg ref={svgRef} className="topo-svg">
        {lines.map(({ip,x1,y1,x2,y2})=>{
          const sel=selectedIp===ip;
          return <line key={ip} x1={x1} y1={y1} x2={x2} y2={y2}
            stroke={sel?'rgba(59,125,216,.6)':'rgba(255,255,255,.06)'}
            strokeWidth={sel?1.5:.8}
            strokeDasharray={sel?'5 3':'2 5'}/>;
        })}
      </svg>
      <div className="topo-gw-row">
        <div className="topo-gw" ref={el=>{nodeRefs.current['__gw__']=el;}}>
          <div className="topo-gw__ring"/>
          <div className="topo-gw__icon">⬡</div>
          <div className="topo-gw__label">Gateway</div>
          <div className="topo-gw__sub">192.168.x.1</div>
        </div>
      </div>
      <div className="topo-lanes">
        {groups.map(g=>(
          <div key={g.type.code} className="topo-lane">
            <div className="topo-lane__hdr" style={{color:g.type.color,borderColor:g.type.color+'44'}}>
              {g.type.icon} {g.type.label}
              <span className="topo-lane__count td-mono" style={{fontSize:'.55rem',color:g.type.color}}>{g.devices.length}</span>
            </div>
            <div className="topo-lane__nodes">
              {g.devices.map(dev=>{
                const sel=selectedIp===dev.ip;
                return(
                  <div key={dev.ip} ref={el=>{nodeRefs.current[dev.ip]=el;}}
                    className={`topo-node ${sel?'topo-node--selected':''}`}
                    style={{'--nc':g.type.color,'borderLeftColor':g.type.color}}
                    onClick={()=>onSelect(sel?null:dev.ip)}>
                    <div className="topo-node__icon" style={{color:g.type.color}}>{g.type.icon}</div>
                    <div className="topo-node__ip">{dev.ip}</div>
                    <div className="topo-node__mac">{(dev.mac||'').substring(0,11)}…</div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function DetailPanel({device,targeted,onDeauth}){
  if(!device) return(
    <div className="detail-panel detail-panel--empty">
      <div className="detail-empty__icon">◈</div>
      <div className="detail-empty__text">Select a node to inspect</div>
    </div>
  );
  const spec=classify(device);
  return(
    <div className={`detail-panel ${targeted?'detail-panel--targeted':''}`} style={{borderTopColor:spec.color}}>
      {targeted&&<div className="dp-alert">DEAUTH ACTIVE</div>}
      <div className="dp-section">
        <div className="dp-section__label">Node Identity</div>
        <div className="dp-ident">
          <div className="dp-ident__icon" style={{color:spec.color}}>{spec.icon}</div>
          <div>
            <div className="dp-ident__ip">{device.ip}</div>
            <code className="dp-ident__mac">{device.mac}</code>
          </div>
          <span className="dp-ident__badge" style={{color:spec.color,borderColor:spec.color+'55'}}>{spec.code}</span>
        </div>
      </div>
      <div className="dp-section">
        <div className="dp-section__label">OS Fingerprint</div>
        <div className="dp-os">{device.os&&device.os!=='Unknown OS'?device.os:'Generic / Shielded'}</div>
        <div className="dp-kv-list">
          {[{k:'Vendor',v:device.vendor},{k:'Type',v:spec.label},{k:'Status',v:'Online'}].map(({k,v})=>(
            <div key={k} className="dp-kv">
              <span className="dp-kv__k">{k}</span>
              <span className="dp-kv__v" style={k==='Status'?{color:'#2d7d6f'}:{}}>{v||'—'}</span>
            </div>
          ))}
        </div>
      </div>
      {device.accuracy>0&&(
        <div className="dp-section">
          <div className="dp-section__label">OS Confidence</div>
          <div className="dp-conf-row">
            <div className="dp-conf-track"><div className="dp-conf-fill" style={{width:`${device.accuracy}%`,background:spec.color}}/></div>
            <span className="dp-conf-val" style={{color:spec.color}}>{device.accuracy}%</span>
          </div>
        </div>
      )}
      {device.open_ports?.length>0&&(
        <div className="dp-section">
          <div className="dp-section__label">Open Ports</div>
          <div className="dp-ports">
            {device.open_ports.slice(0,10).map(p=><span key={p} className="dp-port">{p}</span>)}
          </div>
        </div>
      )}
      <div className="dp-section">
        <button className="btn btn--danger dp-deauth-btn" onClick={()=>onDeauth(device.mac)} disabled={targeted}>
          {targeted?'Transmitting...':'Deauth Node'}
        </button>
      </div>
    </div>
  );
}

function MapState(){
  return(
    <div className="map-state">
      <div className="sonar-wrap">
        <div className="sonar-ring"/><div className="sonar-ring sonar-ring--2"/><div className="sonar-ring sonar-ring--3"/>
        <div className="sonar-sweep"/><div className="sonar-core"/>
      </div>
      <div className="scan-log">
        <div className="scan-log__line scan-log__line--cur">▶ Probing ARP table...</div>
        <div className="scan-log__line">▶ Running OS fingerprint scan...</div>
        <div className="scan-log__line">▶ Analysing TCP/IP stack...</div>
        <span className="scan-log__cursor">█</span>
      </div>
    </div>
  );
}

export default function DeviceMap(){
  const [devices,   setDevices]   = useState([]);
  const [isMapping, setIsMapping] = useState(false);
  const [error,     setError]     = useState(null);
  const [selIp,     setSelIp]     = useState(null);
  const [confMac,   setConfMac]   = useState(null);
  const [tgtMac,    setTgtMac]    = useState(null);
  const [scanTime,  setScanTime]  = useState(null);
  const [toast,     setToast]     = useState(null);

  const scan=useCallback(async()=>{
    setIsMapping(true); setError(null); setSelIp(null);
    try{
      const r=await fetch(`${API}/map_devices`);
      if(!r.ok) throw new Error('Run backend as Administrator — nmap needs elevated privileges.');
      const j=await r.json();
      const raw=Array.isArray(j)?j:Array.isArray(j?.data?.devices)?j.data.devices:Array.isArray(j?.data)?j.data:[];
      const sorted=[...raw].sort((a,b)=>{
        const pa=(a.ip||'').split('.').map(Number),pb=(b.ip||'').split('.').map(Number);
        for(let i=0;i<4;i++) if(pa[i]!==pb[i]) return pa[i]-pb[i];
        return 0;
      });
      setDevices(sorted); setScanTime(new Date().toLocaleTimeString());
    }catch(e){ setError(e.message); } finally{ setIsMapping(false); }
  },[]);

  const deauth=useCallback(async()=>{
    const mac=confMac; setConfMac(null); setTgtMac(mac);
    try{
      const r=await fetch(`${API}/disconnect_device`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac})});
      if(!r.ok){const j=await r.json(); throw new Error(j.message||'Failed');}
      setToast({m:`Deauth sent to ${mac}`,t:'warn'});
    }catch(e){ setError(e.message); } finally{ setTimeout(()=>setTgtMac(null),3000); }
  },[confMac]);

  const groups=Object.values(
    devices.reduce((acc,d)=>{
      const spec=classify(d);
      if(!acc[spec.code]) acc[spec.code]={type:spec,devices:[]};
      acc[spec.code].devices.push(d);
      return acc;
    },{}),
  ).sort((a,b)=>a.type.rank-b.type.rank);

  const selDev=devices.find(d=>d.ip===selIp)||null;

  return(
    <div className="page-root">
      {toast&&<Toast message={toast.m} type={toast.t} onDone={()=>setToast(null)}/>}
      {confMac&&<DeauthModal mac={confMac} onConfirm={deauth} onCancel={()=>setConfMac(null)}/>}

      <header className="pg-header">
        <div>
          <div className="pg-eyebrow">System / Topology / Node Discovery</div>
          <h1 className="pg-title">Network Topology Map</h1>
          <div className="pg-meta">
            <span className="pg-tag">Engine: nmap fingerprint</span>
            {scanTime&&<span className="pg-tag">Last scan: {scanTime}</span>}
            <span className="pg-tag">Nodes: {devices.length}</span>
          </div>
        </div>
        <button className={`btn btn--primary ${isMapping?'btn--loading':''}`} onClick={scan} disabled={isMapping}>
          {isMapping?'Scanning...':'Deep Discovery Scan'}
        </button>
      </header>

      <div className="pg-body">
        {error&&<div className="alert-bar alert-bar--error"><span>⚠</span><span>{error}</span><button className="alert-bar__close" onClick={()=>setError(null)}>✕</button></div>}

        {devices.length>0&&(
          <div className="type-bar">
            {groups.map(g=>(
              <div key={g.type.code} className="type-bar__item">
                <span className="type-bar__n" style={{color:g.type.color}}>{g.devices.length}</span>
                <span className="type-bar__l">{g.type.label}</span>
              </div>
            ))}
          </div>
        )}

        {isMapping?<MapState/>:
        devices.length===0?(
          <div className="empty-state">
            <div className="empty-state__icon">◈</div>
            <h3 className="empty-state__title">No discovery data</h3>
            <p className="empty-state__sub">Run a deep discovery scan to fingerprint active nodes and visualise network topology.</p>
            <button className="btn btn--primary" onClick={scan}>Run Discovery Scan</button>
          </div>
        ):(
          <div className="map-layout">
            <div className="map-canvas-col">
              <TopoCanvas groups={groups} selectedIp={selIp} onSelect={setSelIp}/>
            </div>
            <div className="map-detail-col">
              <DetailPanel device={selDev} targeted={selDev&&tgtMac===selDev.mac} onDeauth={setConfMac}/>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}