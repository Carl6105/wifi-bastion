import { useState, useEffect } from 'react';
import './DeviceMap.css';

const DeviceMap = () => {
  const [devices, setDevices] = useState([]);
  const [isMapping, setIsMapping] = useState(false);
  const [error, setError] = useState(null);
  const [disconnectingId, setDisconnectingId] = useState(null); // Tracks the blinking target

  const startMapping = async () => {
    setIsMapping(true);
    setError(null);
    try {
      const response = await fetch('http://127.0.0.1:5000/api/map_devices');
      if (!response.ok) throw new Error("Ensure Backend is running as Admin");
      
      const data = await response.json();
      setDevices(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsMapping(false);
    }
  };

  // Feature: Targeted De-authentication
  const handleDisconnect = async (mac) => {
    if (!window.confirm(`Initiate hardware-level disconnection for ${mac}?`)) return;
    
    setDisconnectingId(mac); // Initialize the red alert blink
    try {
      const response = await fetch('http://127.0.0.1:5000/api/disconnect_device', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac: mac })
      });
      
      const result = await response.json();
      if (response.ok) {
        console.log(`[BASTION] De-auth signal sent to ${mac}`);
      } else {
        throw new Error(result.message || "Failed to transmit.");
      }
    } catch (err) {
      alert("Eviction Failed: Ensure Wi-Fi card supports Monitor Mode.");
    } finally {
      // Keep blink active for 2 seconds to show "Attack Phase"
      setTimeout(() => setDisconnectingId(null), 2000);
    }
  };

  const getDeviceSpecs = (device) => {
    const os = (device.os || "").toLowerCase();
    const type = (device.device_type || "").toLowerCase();

    if (type.includes('phone') || os.includes('android') || os.includes('ios')) 
        return { icon: '📱', color: '#818cf8', label: 'Mobile' };
    
    if (type.includes('general purpose') || os.includes('windows') || os.includes('mac') || os.includes('linux')) 
        return { icon: '💻', color: '#3b82f6', label: 'Workstation' };

    if (os.includes('tizen') || os.includes('webos') || os.includes('tv') || type.includes('media')) 
        return { icon: '📺', color: '#f43f5e', label: 'Smart TV' };

    if (type.includes('router') || type.includes('bridge') || type.includes('switch') || type.includes('wap')) 
        return { icon: '🌐', color: '#10b981', label: 'Infrastructure' };

    return { icon: '🔌', color: '#94a3b8', label: 'IoT/Peripheral' };
  };

  return (
    <div className="page device-map-container">
      {/* Header Section */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '3rem' }}>
        <div>
          <span className="tech-label" style={{ background: '#dbeafe', color: '#1e40af' }}>FINGERPRINTING_ENGINE // v2.0</span>
          <h1 style={{ marginTop: '0.5rem', marginBottom: '0.5rem' }}>Network Topology Map</h1>
          <p style={{ color: '#64748b', fontSize: '0.9rem' }}>Discovered {devices.length} nodes with OS fingerprinting.</p>
        </div>
        <button 
          onClick={startMapping} 
          disabled={isMapping}
          className="discovery-btn"
          style={{ 
            padding: '1rem 2rem', 
            background: isMapping ? '#94a3b8' : '#2563eb',
            color: 'white', borderRadius: '12px', fontWeight: '700', cursor: 'pointer', border: 'none'
          }}
        >
          {isMapping ? "Fingerprinting..." : "Deep Discovery Scan"}
        </button>
      </div>

      {error && (
        <div className="error-signal-banner">
          <strong>ERROR_SIGNAL:</strong> {error}
        </div>
      )}

      {/* Discovery Animation State */}
      {isMapping ? (
        <div className="sonar-wrapper">
          <div className="sonar-circle">
            📡
            <div className="sonar-wave"></div>
            <div className="sonar-wave"></div>
            <div className="sonar-wave"></div>
          </div>
          <p className="sonar-text">
            ANALYZING TCP/IP STACK BEHAVIOR...
          </p>
        </div>
      ) : devices.length > 0 ? (
        <div className="device-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '20px' }}>
          {devices.map((device, i) => {
            const specs = getDeviceSpecs(device);
            const isTargeted = disconnectingId === device.mac;
            
            return (
              <div 
                key={i} 
                className={`device-card ${isTargeted ? 'target-blink' : ''}`} 
                style={{ borderTop: `4px solid ${isTargeted ? '#ef4444' : specs.color}` }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
                  <div style={{ display: 'flex', gap: '15px' }}>
                    <div style={{ 
                      width: '55px', height: '55px', background: `${specs.color}15`, 
                      borderRadius: '14px', display: 'flex', alignItems: 'center', 
                      justifyContent: 'center', fontSize: '1.8rem'
                    }}>
                      {specs.icon}
                    </div>
                    <div>
                      <div style={{ fontSize: '1.2rem', fontWeight: '800', color: '#1e293b' }}>{device.ip}</div>
                      <code style={{ fontSize: '0.7rem', color: '#94a3b8' }}>{device.mac}</code>
                    </div>
                  </div>
                  {/* Disconnect Kill-Switch */}
                  <button 
                    className="btn-kill-node" 
                    onClick={() => handleDisconnect(device.mac)}
                    title="Disconnect Node"
                  >
                    ☠️
                  </button>
                </div>

                <div className="os-info-box" style={{ background: '#f8fafc', padding: '1rem', borderRadius: '10px', border: '1px solid #f1f5f9' }}>
                    <div className="info-label" style={{ fontSize: '0.65rem', fontWeight: 'bold', color: '#94a3b8', textTransform: 'uppercase', marginBottom: '4px' }}>Detected OS</div>
                    <div style={{ fontSize: '0.9rem', fontWeight: '700', color: '#1e293b', marginBottom: '8px' }}>
                        {device.os !== 'Unknown' ? device.os : 'Generic / Shielded Device'}
                    </div>
                    
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.7rem', fontFamily: 'monospace', color: '#64748b' }}>{device.vendor}</span>
                        <span style={{ fontSize: '0.7rem', fontWeight: '900', color: specs.color }}>{specs.label}</span>
                    </div>
                </div>

                {device.accuracy > 0 && (
                  <div style={{ marginTop: '1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.65rem', fontWeight: 'bold', color: '#94a3b8' }}>
                        <span>CONFIDENCE_SCORE</span>
                        <span>{device.accuracy}%</span>
                    </div>
                    <div className="confidence-bg">
                        <div className="confidence-fill" style={{ width: `${device.accuracy}%`, background: specs.color }}></div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="empty-state-card">
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔍</div>
          <h3>No Discovery Data</h3>
          <p>Run a Deep Discovery Scan to fingerprint active devices and visualize network infrastructure.</p>
        </div>
      )}
    </div>
  );
};

export default DeviceMap;