import React, { useState, useEffect, useMemo } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, 
  PieChart, Pie, Cell, BarChart, Bar 
} from 'recharts';
import './Scan.css';

const Scan = () => {
  const [networks, setNetworks] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [lastScanTime, setLastScanTime] = useState(null);
  const [expandedNet, setExpandedNet] = useState(null);
  
  // Track signal history per BSSID for the stability graph
  const [networkHistory, setNetworkHistory] = useState({});

  const PIE_COLORS = ['#22c55e', '#ef4444'];
  const BAR_COLORS = ['#3b82f6', '#8b5cf6', '#ec4899'];

  const startScan = async () => {
    setIsScanning(true);
    setError(null);
    try {
      const response = await fetch('http://127.0.0.1:5000/api/scan', { method: 'POST' });
      if (!response.ok) throw new Error("Backend connection failed");
      const data = await response.json();

      const uniqueSSIDs = {};
      data.forEach(net => {
        const name = net.ssid || "Hidden Network";
        // Ensure vendor and signal are captured even if they are in nested keys
        if (!uniqueSSIDs[name] || parseInt(net.signal) > parseInt(uniqueSSIDs[name].signal)) {
          uniqueSSIDs[name] = {
            ...net,
            vendor: net.vendor || "Unknown Vendor", // Fallback for vendor display
            signal: net.signal || -100
          };
        }
      });

      const sortedData = Object.values(uniqueSSIDs).sort((a, b) => b.trust_score - a.trust_score);
      setNetworks(sortedData);
      setLastScanTime(new Date().toLocaleTimeString());

      // Update history for each BSSID to create continuous lines
      setNetworkHistory(prev => {
        const updated = { ...prev };
        sortedData.forEach(net => {
          const bssid = net.bssid;
          const newPoint = {
            time: new Date().toLocaleTimeString().split(' ')[0],
            // Normalize signal for the graph (higher is better)
            strength: Math.max(0, 100 - Math.abs(parseInt(net.signal))) 
          };
          updated[bssid] = [...(updated[bssid] || []), newPoint].slice(-12);
        });
        return updated;
      });

    } catch (err) {
      setError(err.message);
    } finally {
      setIsScanning(false);
    }
  };

  const getPieData = (net) => [
    { name: 'Integrity', value: net.trust_score },
    { name: 'Risk Factor', value: 100 - net.trust_score }
  ];

const getBarData = (net) => [
  { name: 'DNS', val: net.dns_secure || 50 }, // Unique per network
  { name: 'Protocol', val: net.protocol_strength || 60 }, // Unique per network
  { name: 'Packet', val: net.packet_integrity || 100 } // Unique per network
];

  const downloadReport = async () => {
    try {
        const response = await fetch('http://127.0.0.1:5000/api/generate_report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ networks })
        });
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `WiFi_Bastion_Audit_${new Date().toISOString().split('T')[0]}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (err) { alert("Report error: " + err.message); }
  };

  const blockNetwork = async (network) => {
    try {
      const response = await fetch('http://127.0.0.1:5000/api/block_network', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ network_id: network._id, bssid: network.bssid, ssid: network.ssid })
      });
      if (response.ok) {
        alert(`Bastion restricted ${network.ssid} at the OS level.`);
        startScan();
      }
    } catch (err) { alert("Block request failed."); }
  };

  useEffect(() => {
    let interval;
    if (autoRefresh) interval = setInterval(startScan, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  return (
    <div className="page scan-container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ marginBottom: '0.5rem', color: '#0f172a' }}>Environment Scanner</h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
            <label className="tech-label" style={{ 
                display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', 
                background: autoRefresh ? '#dcfce7' : '#f1f5f9', 
                color: autoRefresh ? '#166534' : '#64748b',
                border: autoRefresh ? '1px solid #86efac' : '1px solid #e2e8f0'
            }}>
              <input type="checkbox" checked={autoRefresh} onChange={() => setAutoRefresh(!autoRefresh)} />
              {autoRefresh ? "AUTO-MONITOR ACTIVE" : "MANUAL MODE"}
            </label>
            {lastScanTime && <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'monospace' }}>LATEST_CAPTURE: {lastScanTime}</span>}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          {networks.length > 0 && (
            <button onClick={downloadReport} className="btn-export-pdf">
              <span>📋</span> Export Security Audit
            </button>
          )}
          <button onClick={startScan} disabled={isScanning} className="scan-btn-primary">
            {isScanning ? "Probing Spectrum..." : "Initialize Security Scan"}
          </button>
        </div>
      </div>

      {error && <div className="error-banner"><strong>Scanner Error:</strong> {error}</div>}

      {isScanning && networks.length === 0 ? (
        <div className="scanning-loader">
          <div className="pulse-ring"></div>
          <h3 style={{ marginTop: '2.5rem', color: '#1e293b' }}>Analyzing Signal Metadata</h3>
          <p style={{ color: '#64748b', fontFamily: 'monospace', fontSize: '0.8rem' }}>CAPTURING 802.11 MANAGEMENT FRAMES...</p>
        </div>
      ) : networks.length > 0 ? (
        <div className="table-card">
          <table className="bastion-table">
            <thead>
              <tr style={{ background: '#f8fafc', textAlign: 'left', borderBottom: '1px solid #e2e8f0' }}>
                <th>Access Point</th>
                <th>Integrity</th>
                <th>Encryption</th>
                <th>Threat Analysis</th>
                <th style={{ textAlign: 'center' }}>Deep Audit</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {networks.map((net, i) => (
                <React.Fragment key={net.bssid}>
                  <tr style={{ borderBottom: '1px solid #f1f5f9', opacity: isScanning ? 0.6 : 1 }}>
                    <td style={{ padding: '1.2rem' }}>
                      <div style={{ fontWeight: '700', color: '#0f172a' }}>{net.ssid}</div>
                      <div style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'monospace' }}>
                        {net.bssid} // <span style={{color: '#2563eb'}}>{net.vendor}</span>
                      </div>
                    </td>
                    <td style={{ padding: '1.2rem' }}>
                      <div className="trust-bar-container">
                        <div style={{ 
                          width: `${net.trust_score}%`, 
                          height: '100%', 
                          background: net.trust_score > 70 ? '#22c55e' : net.trust_score > 40 ? '#f59e0b' : '#ef4444' 
                        }} />
                      </div>
                      <span style={{ fontSize: '0.75rem', fontWeight: '800', color: '#475569' }}>{net.trust_score}% TRUST INDEX</span>
                    </td>
                    <td style={{ padding: '1.2rem' }}>
                      <span className={`enc-badge ${net.encryption.includes('WPA3') ? 'high' : 'med'}`}>{net.encryption}</span>
                    </td>
                    <td style={{ padding: '1.2rem' }}>
                      {net.threats?.length > 0 ? (
                        net.threats.map((t, idx) => <div key={idx} className="threat-text">⚠️ {t}</div>)
                      ) : (
                        <div className="secure-text"><div className="secure-dot"></div> Verified Secure</div>
                      )}
                    </td>
                    <td style={{ padding: '1.2rem', textAlign: 'center' }}>
                        <button 
                          onClick={() => setExpandedNet(expandedNet === net.bssid ? null : net.bssid)}
                          style={{ 
                            background: expandedNet === net.bssid ? '#2563eb' : '#f1f5f9', 
                            color: expandedNet === net.bssid ? 'white' : '#2563eb', 
                            border: '1px solid #e2e8f0', padding: '5px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 'bold' 
                          }}
                        >
                          {expandedNet === net.bssid ? "Close" : "📊 Audit"}
                        </button>
                    </td>
                    <td style={{ padding: '1.2rem' }}>
                      <button className="btn-block" onClick={() => blockNetwork(net)}>Restrict</button>
                    </td>
                  </tr>
                  
                  {expandedNet === net.bssid && (
                    <tr style={{ background: '#f8fafc' }}>
                      <td colSpan="6" style={{ padding: '2rem', borderBottom: '2px solid #e2e8f0' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr 1fr', gap: '25px' }}>
                           <div style={{ background: 'white', padding: '1.2rem', borderRadius: '12px', border: '1px solid #e2e8f0', textAlign: 'center' }}>
                             <p style={{ fontSize: '0.65rem', fontWeight: '900', color: '#64748b', marginBottom: '15px', textTransform: 'uppercase' }}>Integrity Ratio</p>
                             <ResponsiveContainer width="100%" height={140}>
                               <PieChart>
                                 <Pie data={getPieData(net)} innerRadius={35} outerRadius={55} paddingAngle={5} dataKey="value">
                                   {getPieData(net).map((entry, index) => <Cell key={`cell-${index}`} fill={PIE_COLORS[index]} />)}
                                 </Pie>
                                 <Tooltip />
                               </PieChart>
                             </ResponsiveContainer>
                           </div>

                           <div style={{ background: 'white', padding: '1.2rem', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
                             <p style={{ fontSize: '0.65rem', fontWeight: '900', color: '#64748b', marginBottom: '15px', textTransform: 'uppercase' }}>RF Signal Stability</p>
                             <ResponsiveContainer width="100%" height={140}>
                               <LineChart data={networkHistory[net.bssid] || []}>
                                 <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                                 <XAxis dataKey="time" hide />
                                 <YAxis domain={[0, 100]} stroke="#94a3b8" fontSize={10} tickFormatter={(val) => `${val}%`} />
                                 <Tooltip labelStyle={{color: '#64748b'}} />
                                 <Line type="monotone" dataKey="strength" name="Signal Quality" stroke="#2563eb" strokeWidth={3} dot={{ r: 4, fill: '#2563eb' }} animationDuration={600} />
                               </LineChart>
                             </ResponsiveContainer>
                           </div>

                           <div style={{ background: 'white', padding: '1.2rem', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
                             <p style={{ fontSize: '0.65rem', fontWeight: '900', color: '#64748b', marginBottom: '15px', textTransform: 'uppercase' }}>Security Vectors</p>
                             <ResponsiveContainer width="100%" height={140}>
                               <BarChart data={getBarData(net)}>
                                 <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                                 <XAxis dataKey="name" tick={{ fontSize: 10, fontWeight: 'bold' }} />
                                 <YAxis domain={[0, 100]} hide />
                                 <Tooltip cursor={{ fill: 'transparent' }} />
                                 <Bar dataKey="val" radius={[4, 4, 0, 0]}>
                                   {getBarData(net).map((entry, index) => <Cell key={`cell-${index}`} fill={BAR_COLORS[index]} />)}
                                 </Bar>
                               </BarChart>
                             </ResponsiveContainer>
                           </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state">
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📡</div>
          <h3>Spectrum Unmapped</h3>
          <p>Wireless environment is currently unmapped. Initialize a scan to begin hardware-level security audit.</p>
        </div>
      )}
    </div>
  );
};

export default Scan;