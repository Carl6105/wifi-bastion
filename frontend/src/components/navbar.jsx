import { useState, useEffect, useRef } from 'react';
import { NavLink } from 'react-router-dom';
import './navbar.css';

const API = 'http://127.0.0.1:5000/api';

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Overview'   },
  { to: '/scan',      label: 'Scanner'    },
  { to: '/alerts',    label: 'Alerts'     },
  { to: '/analytics', label: 'Analytics'  },
  { to: '/channels',  label: 'Channels'   },
  { to: '/devices',   label: 'Topology'   },
  { to: '/history',   label: 'Archive'    },
  { to: '/blocked',   label: 'Restricted' },
  { to: '/settings',  label: 'Settings'   },
];

function SignalIcon({ online }) {
  return (
    <span className="signal-icon" aria-hidden="true">
      {[1,2,3,4].map(i => (
        <span
          key={i}
          className={`signal-bar ${online ? 'signal-bar--lit' : ''}`}
          style={{ height: `${i * 3 + 2}px`, animationDelay: `${i*0.1}s` }}
        />
      ))}
    </span>
  );
}

export default function Navbar() {
  const [status,  setStatus]  = useState('checking');
  const [latency, setLatency] = useState(null);
  const [pings,   setPings]   = useState(0);
  const ivRef = useRef(null);

  const check = async () => {
    const t0 = performance.now();
    try {
      const res = await fetch(`${API}/health`, { signal: AbortSignal.timeout(3000) });
      const ms  = Math.round(performance.now() - t0);
      setStatus(res.ok ? 'online' : 'offline');
      setLatency(res.ok ? ms : null);
    } catch {
      setStatus('offline');
      setLatency(null);
    }
    setPings(p => p + 1);
  };

  useEffect(() => {
    check();
    ivRef.current = setInterval(check, 8000);
    return () => clearInterval(ivRef.current);
  }, []);

  const labels = { online: 'Connected', offline: 'Offline', checking: 'Connecting' };

  return (
    <nav className="navbar">
      <NavLink to="/" className="nav-brand">
        <div className="brand-mark">WB</div>
        <div className="brand-label">
          <span className="brand-label__name">Wi-Fi Bastion</span>
          <span className="brand-label__sub">Threat Intelligence</span>
        </div>
      </NavLink>

      <ul className="nav-links">
        {NAV_ITEMS.map(({ to, label }) => (
          <li key={to}>
            <NavLink to={to} className={({ isActive }) =>
              `nav-link ${isActive ? 'nav-link--active' : ''}`}>
              <span className="nav-link__label">{label}</span>
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="nav-status">
        <div className={`status-pill status-pill--${status}`}>
          <SignalIcon online={status === 'online'} />
          <span className="status-pill__label">{labels[status]}</span>
          {latency !== null && (
            <span className="status-pill__latency"></span>
          )}
        </div>
      </div>
    </nav>
  );
}