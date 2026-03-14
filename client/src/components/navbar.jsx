import { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import './Navbar.css';

const Navbar = () => {
  const [isOnline, setIsOnline] = useState(false);

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const response = await fetch('http://127.0.0.1:5000/api/history');
        setIsOnline(response.ok);
      } catch {
        setIsOnline(false);
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 5000); 
    return () => clearInterval(interval);
  }, []);

  return (
    <nav className="navbar">
      {/* Brand Section */}
      <NavLink to="/" className="nav-brand">
        <span className="brand-icon">🛡️</span>
        <span className="brand-name">Wi-Fi Bastion</span>
      </NavLink>

      {/* Nav Links - All White Text */}
      <div className="nav-links">
        <NavLink to="/dashboard" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          📊 Dashboard
        </NavLink>
        <NavLink to="/scan" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          📡 Scanner
        </NavLink>
        <NavLink to="/devices" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          🗺️ Topology
        </NavLink>
        <NavLink to="/history" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          📜 Archive
        </NavLink>
        <NavLink to="/blocked" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
          🚫 Restricted
        </NavLink>
      </div>

      {/* API Connection Indicator */}
      <div className="system-meta">
        <div className="api-status">
          <span className={`status-dot ${isOnline ? 'online' : 'offline'}`}></span>
          <span className="status-text">{isOnline ? 'API Connected' : 'API Offline'}</span>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;