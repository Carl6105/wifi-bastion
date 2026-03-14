import React from 'react';
import { Link } from 'react-router-dom';
import './Home.css';

const Home = () => {
  return (
    <div className="home-container">
      <div style={{ maxWidth: '1100px', padding: '6rem 2rem', zIndex: 1 }}>
        
        {/* Hero Section */}
        <header className="home-hero" style={{ marginBottom: '6rem', textAlign: 'center' }}>
          <h1 style={{ fontSize: '5rem', marginBottom: '1.5rem' }}>
            <span>🛡️</span> 
            <span className="home-title-text">Wi-Fi Bastion</span>
          </h1>
          <p style={{ fontSize: '1.25rem', color: '#475569', maxWidth: '800px', margin: '0 auto 3rem auto', lineHeight: '1.8' }}>
            A software-defined security perimeter that monitors airwaves for deauthentication floods, 
            detects rogue access points, and hardens your gateway via OS-level hardware filtering.
          </p>

          <Link to="/dashboard" style={{ textDecoration: 'none' }}>
            <button className="home-launch-btn" style={{ 
              padding: '1.1rem 3.5rem', 
              fontSize: '1.1rem', 
              backgroundColor: '#2563eb', 
              color: 'white', 
              border: 'none', 
              borderRadius: '8px', /* Sharper corners look more "Enterprise/Tech" */
              cursor: 'pointer',
              fontWeight: '600',
              letterSpacing: '0.5px',
              boxShadow: '0 10px 20px rgba(37, 99, 235, 0.2)'
            }}>
              INITIALIZE CONTROL CENTER
            </button>
          </Link>
        </header>

        {/* Feature Grid */}
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', 
          gap: '30px', 
          marginBottom: '6rem' 
        }}>
          <div className="feature-card" style={{ padding: '2.5rem', borderRadius: '12px' }}>
            <div style={{ color: '#2563eb', fontSize: '0.8rem', fontWeight: 'bold', marginBottom: '1rem', fontFamily: 'monospace' }}>[ 01 ]</div>
            <h3 style={{ marginBottom: '1rem' }}>Rogue Point Detection</h3>
            <p style={{ color: '#64748b', fontSize: '0.9rem', lineHeight: '1.6' }}>
                Advanced environment mapping tracks BSSID behavior to identify <strong>Evil Twin</strong> clones and signal strength anomalies.
            </p>
          </div>

          <div className="feature-card" style={{ padding: '2.5rem', borderRadius: '12px' }}>
            <div style={{ color: '#2563eb', fontSize: '0.8rem', fontWeight: 'bold', marginBottom: '1rem', fontFamily: 'monospace' }}>[ 02 ]</div>
            <h3 style={{ marginBottom: '1rem' }}>Gateway Integrity</h3>
            <p style={{ color: '#64748b', fontSize: '0.9rem', lineHeight: '1.6' }}>
                Automated DNS canary checks and port-exposure audits ensure your router isn't the weakest link in the chain.
            </p>
          </div>

          <div className="feature-card" style={{ padding: '2.5rem', borderRadius: '12px' }}>
            <div style={{ color: '#2563eb', fontSize: '0.8rem', fontWeight: 'bold', marginBottom: '1rem', fontFamily: 'monospace' }}>[ 03 ]</div>
            <h3 style={{ marginBottom: '1rem' }}>Active Blocking</h3>
            <p style={{ color: '#64748b', fontSize: '0.9rem', lineHeight: '1.6' }}>
                Direct integration with the Windows WLAN API to blacklist dangerous networks at the driver level.
            </p>
          </div>
        </div>

        {/* Technical Brief - Dark Mode FYP Impact */}
        <div className="tech-brief-box" style={{ 
          padding: '4rem', 
          borderRadius: '16px', 
          boxShadow: '0 30px 60px rgba(15, 23, 42, 0.2)'
        }}>
          <h2 style={{ fontSize: '2rem', marginBottom: '1.5rem' }}>Intrusion Analysis Engine</h2>
          <p style={{ color: '#94a3b8', fontSize: '1.1rem', lineHeight: '1.9', maxWidth: '850px' }}>
            Bastion operates on the principle of <strong>Zero-Trust Wireless</strong>. 
            By capturing and analyzing 802.11 frames, the system identifies the cryptographic 
            downgrades and deauthentication spikes that precede major network breaches. 
            It translates complex RF telemetry into actionable security intelligence.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Home;