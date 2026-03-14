import { useState, useEffect } from 'react';
import './History.css';

const History = () => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  // Standard fetch for loading logs
  const fetchHistory = async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/api/history');
      const data = await response.json();
      setHistory(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Fetch error:", err);
    } finally {
      setLoading(false);
    }
  };

  // Logic to clear all logs
  const clearHistory = async () => {
    if (!window.confirm("CRITICAL: This will permanently delete all security logs. Proceed?")) return;

    try {
      const response = await fetch('http://127.0.0.1:5000/api/history', {
        method: 'DELETE',
      });
      
      const data = await response.json();

      if (response.ok) {
        setHistory([]); // Reset UI
        alert(data.message || "Archive purged successfully.");
      } else {
        alert(data.error || "Purge failed.");
      }
    } catch (err) {
      alert("Failed to connect to security backend.");
    }
  };

  useEffect(() => { fetchHistory(); }, []);

  const formatDate = (ts) => {
    if (!ts) return "N/A";
    const date = ts > 10000000000 ? new Date(ts) : new Date(ts * 1000);
    return date.toLocaleString();
  };

  if (loading) return (
    <div className="page" style={{ textAlign: 'center', padding: '5rem' }}>
        <div className="spinner"></div>
        <h2 style={{ color: '#64748b', marginTop: '1rem' }}>Accessing Archive...</h2>
    </div>
  );

  const threatCount = history.filter(h => h.threats && h.threats.length > 0).length;

  return (
    <div className="page history-container">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '3rem' }}>
        <div>
          <span className="tech-label" style={{ background: '#f1f5f9', color: '#475569' }}>DATA_RETENTION // LOGS</span>
          <h1 style={{ marginTop: '0.5rem' }}>Scan History Audit</h1>
          <p style={{ color: '#64748b', fontSize: '0.9rem' }}>Comprehensive record of previous environment snapshots.</p>
        </div>
        
        <div style={{ display: 'flex', gap: '24px', alignItems: 'center' }}>
          {history.length > 0 && (
            <button className="btn-purge" onClick={clearHistory}>
              <span>🗑️</span> Purge Archive
            </button>
          )}
          <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#94a3b8' }}>THREAT_INCIDENTS</div>
              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: threatCount > 0 ? '#ef4444' : '#22c55e' }}>{threatCount}</div>
          </div>
        </div>
      </header>

      {history.length > 0 ? (
        <div className="history-card">
          <table className="history-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Network SSID</th>
                <th>Analysis & Threats</th>
                <th>Trust Index</th>
              </tr>
            </thead>
            <tbody>
              {history.map((entry, i) => {
                const hasThreats = Array.isArray(entry.threats) ? entry.threats.length > 0 : !!entry.threats;
                return (
                  <tr key={entry._id || i} className={hasThreats ? 'row-threat' : ''}>
                    <td className="timestamp-cell">{formatDate(entry.timestamp)}</td>
                    <td style={{ fontWeight: '700' }}>{entry.ssid || "Hidden Network"}</td>
                    <td>
                      {Array.isArray(entry.threats) ? (
                        entry.threats.length > 0 ? (
                          entry.threats.map((t, idx) => (
                            <span key={idx} className="badge error" style={{ marginRight: '5px' }}>⚠️ {t}</span>
                          ))
                        ) : <span className="badge success">Verified Safe</span>
                      ) : entry.threats ? (
                        <span className="badge error">{String(entry.threats)}</span>
                      ) : (
                        <span className="badge success">Verified Safe</span>
                      )}
                    </td>
                    <td>
                      <span className="trust-pill" style={{ 
                          background: (entry.trust_score || 0) > 70 ? '#dcfce7' : (entry.trust_score || 0) > 40 ? '#fef3c7' : '#fee2e2',
                          color: (entry.trust_score || 0) > 70 ? '#166534' : (entry.trust_score || 0) > 40 ? '#9a3412' : '#991b1b'
                      }}>
                        {entry.trust_score ?? '0'}/100
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ textAlign: 'center', padding: '6rem 2rem', border: '2px dashed #e2e8f0', borderRadius: '16px', background: '#ffffff' }}>
          <div style={{ fontSize: '3rem', marginBottom: '1.5rem' }}>📁</div>
          <h3 style={{ color: '#1e293b' }}>No Historical Data</h3>
          <p style={{ color: '#94a3b8', maxWidth: '400px', margin: '0 auto' }}>Run a network scan to begin compiling your security audit history.</p>
        </div>
      )}
    </div>
  );
};

export default History;