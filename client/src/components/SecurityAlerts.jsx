import { useEffect, useState } from 'react';

const SecurityAlerts = () => {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const checkAlerts = async () => {
      try {
        const response = await fetch('http://127.0.0.1:5000/api/security_alerts');
        const data = await response.json();
        setAlerts(data);
      } catch (err) {
        console.error("Alert check failed");
      }
    };

    // Poll every 5 seconds for real-time protection
    const interval = setInterval(checkAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  if (alerts.length === 0) return null;

  return (
    <div style={{ 
      background: '#fee2e2', 
      border: '2px solid #ef4444', 
      padding: '1rem', 
      margin: '1rem', 
      borderRadius: '8px',
      animation: 'pulse 2s infinite' 
    }}>
      <h3 style={{ color: '#991b1b', margin: 0 }}>⚠️ CRITICAL SECURITY ALERT</h3>
      {alerts.map((alert, i) => (
        <div key={i} style={{ color: '#b91c1c', fontWeight: 'bold', marginTop: '0.5rem' }}>
          {alert.type || "Threat Detected"}: {alert.mac ? `Attacker MAC: ${alert.mac}` : alert.message}
        </div>
      ))}
    </div>
  );
};

export default SecurityAlerts;