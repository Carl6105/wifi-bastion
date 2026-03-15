import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import './home.css';

const FEATURES = [
  { n:'01', title:'Rogue AP Detection',    body:'BSSID behavioural analysis identifies Evil Twin clones and signal anomalies before traffic is intercepted.',         tags:['EVIL-TWIN','MAC-SPOOF','SIGNAL-DELTA'] },
  { n:'02', title:'Gateway Integrity',     body:'Multi-canary DNS checks and parallel port audits validate router configuration against known-good baselines.',       tags:['DNS-CANARY','PORT-SCAN','ARP-WATCH'] },
  { n:'03', title:'OS-Level Blocking',     body:'Direct integration with the Windows WLAN API blacklists dangerous networks at the driver level, not software.',      tags:['NETSH-WLAN','DRIVER-LEVEL','BLOCKLIST'] },
  { n:'04', title:'Packet Engine',         body:'802.11 frame capture detects deauthentication floods the moment they begin — before devices are disconnected.',      tags:['DEAUTH-FLOOD','SCAPY','MONITOR-MODE'] },
  { n:'05', title:'Trust Scoring',         body:'0–100 trust score weighs encryption strength, threat history, signal integrity, and DNS status simultaneously.',     tags:['WPA3','WPA2','RISK-MATRIX'] },
  { n:'06', title:'Audit Reports',         body:'One-click PDF security reports with executive summary, network analysis tables, and data-driven remediation steps.', tags:['PDF','REPORTLAB','COMPLIANCE'] },
];

export default function Home() {
  return (
    <div className="home-root">
      {/* Hero */}
      <section className="hero">
        <div className="hero__eyebrow">
          <div className="hero__eyebrow-line" />
          <span>Wireless Threat Intelligence Platform</span>
        </div>
        <h1 className="hero__title">
          <span>Wi-Fi</span>
          <span className="t-accent">Bastion</span>
        </h1>
        <p className="hero__sub">
          A software-defined security perimeter that monitors airwaves for deauthentication
          floods, detects rogue access points, and hardens your network via OS-level filtering.
        </p>
        <div className="hero__cta">
          <Link to="/dashboard" className="hero__btn hero__btn--primary">
            Open Dashboard →
          </Link>
          <Link to="/scan" className="hero__btn hero__btn--ghost">
            Run a Scan
          </Link>
        </div>
      </section>

      {/* Stats strip */}
      <div className="stats-strip">
        {[
          { val: '19+', label: 'Detection Modules' },
          { val: '802.11', label: 'Frame Analysis' },
          { val: '0–100', label: 'Trust Score Range' },
          { val: '6', label: 'Threat Vectors' },
          { val: 'Real-time', label: 'Alert Engine' },
        ].map(s => (
          <div key={s.label} className="stats-strip__item">
            <span className="stats-strip__val">{s.val}</span>
            <span className="stats-strip__label">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Features */}
      <section className="features">
        <h2 className="features__header">Capability Matrix</h2>
        <p className="features__sub">Every module runs continuously in the background.</p>
        <div className="features__grid">
          {FEATURES.map(f => (
            <div key={f.n} className="feat-card">
              <div className="feat-card__num">{f.n}</div>
              <h3 className="feat-card__title">{f.title}</h3>
              <p className="feat-card__body">{f.body}</p>
              <div className="feat-card__tags">
                {f.tags.map(t => <span key={t} className="feat-tag">{t}</span>)}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Brief */}
      <section className="brief">
        <div className="brief__inner">
          <div>
            <div className="brief__label">Zero-Trust Wireless</div>
            <h2 className="brief__title">Intrusion Analysis Engine</h2>
            <p className="brief__body">
              Bastion operates on the principle of <strong>zero-trust wireless</strong>.
              By capturing and analysing 802.11 management frames in real time, the system
              identifies cryptographic downgrades and deauthentication spikes that precede
              major network breaches — translating complex RF telemetry into actionable,
              prioritised security intelligence.
            </p>
          </div>
          <div className="brief__grid">
            {[
              { label: 'Detection Method', val: 'Passive + Active Hybrid' },
              { label: 'Response Time',   val: '< 15 seconds'             },
              { label: 'Persistence',     val: 'MongoDB Time-Series'      },
              { label: 'Protocol Coverage', val: 'WEP / WPA / WPA2 / WPA3' },
            ].map(c => (
              <div key={c.label} className="brief__cell">
                <div className="brief__cell-label">{c.label}</div>
                <div className="brief__cell-val">{c.val}</div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}