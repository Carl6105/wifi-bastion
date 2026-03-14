import { useState, useEffect } from 'react';
import './Blocked.css';

const Blocked = () => {
  const [blockedList, setBlockedList] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchBlocked = async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/api/blocked');
      const data = await response.json();
      setBlockedList(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to fetch blocklist");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchBlocked(); }, []);

  const handleUnblock = async (network) => {
    if (!window.confirm(`Release OS filter for ${network.ssid}?`)) return;

    try {
      const response = await fetch('http://127.0.0.1:5000/api/unblock_network', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          network_id: network._id, 
          ssid: network.ssid 
        })
      });

      if (response.ok) {
        fetchBlocked();
      }
    } catch (err) {
      alert("Unblock request failed.");
    }
  };

  return (
    <div className="page blocked-container">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3rem' }}>
        <div>
          <span className="tech-label" style={{ background: '#fee2e2', color: '#991b1b' }}>POLICY // HARDWARE_RESTRICTIONS</span>
          <h1 style={{ marginTop: '0.5rem' }}>Restricted Networks</h1>
          <p style={{ color: '#64748b', fontSize: '0.9rem' }}>SSIDs currently blacklisted at the Operating System driver level.</p>
        </div>
        <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#94a3b8' }}>ACTIVE_FILTERS</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#1e293b' }}>{blockedList.length}</div>
        </div>
      </header>

      {blockedList.length > 0 ? (
        <div className="blocked-card">
          <table className="blocked-table">
            <thead>
              <tr>
                <th>Network SSID</th>
                <th>Physical Address (BSSID)</th>
                <th>Restriction Applied</th>
                <th>Policy Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {blockedList.map((net) => (
                <tr key={net._id}>
                  <td style={{ fontWeight: '700', color: '#0f172a' }}>{net.ssid}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#64748b' }}>{net.bssid}</td>
                  <td style={{ fontSize: '0.85rem', color: '#475569' }}>
                    {new Date(net.timestamp).toLocaleDateString()} at {new Date(net.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                  </td>
                  <td>
                    <span className="os-badge">OS-BLOCK</span>
                  </td>
                  <td>
                    <button className="btn-release" onClick={() => handleUnblock(net)}>
                      Release Filter
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        !loading && (
          <div style={{ textAlign: 'center', padding: '6rem 2rem', border: '2px dashed #e2e8f0', borderRadius: '16px', background: '#ffffff' }}>
            <div style={{ fontSize: '3rem', marginBottom: '1.5rem' }}>🔓</div>
            <h3 style={{ color: '#1e293b' }}>No Restrictions Active</h3>
            <p style={{ color: '#94a3b8', maxWidth: '400px', margin: '0 auto' }}>Your wireless environment is currently unrestricted. Dangerous SSIDs will appear here if blocked during a scan.</p>
          </div>
        )
      )}
    </div>
  );
};

export default Blocked;