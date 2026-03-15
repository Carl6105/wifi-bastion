import { useState, useEffect } from 'react';
import './Settings.css';

const API = 'http://127.0.0.1:5000/api';

function Toast({ message, type, onDone }) {
  useEffect(() => { const t = setTimeout(onDone, 3000); return () => clearTimeout(t); }, []);
  return (
    <div className={`toast toast--${type}`}>
      <span>{type === 'success' ? '✓' : '✕'}</span> {message}
    </div>
  );
}

function ToggleRow({ label, sub, value, onChange }) {
  return (
    <div className="setting-row">
      <div className="setting-row__info">
        <div className="setting-row__label">{label}</div>
        {sub && <div className="setting-row__sub">{sub}</div>}
      </div>
      <button
        className={`toggle ${value ? 'toggle--on' : ''}`}
        onClick={() => onChange(!value)}
        aria-pressed={value}
      >
        <span className="toggle__knob" />
      </button>
    </div>
  );
}

function SliderRow({ label, sub, value, min, max, step = 1, unit, onChange }) {
  return (
    <div className="setting-row setting-row--slider">
      <div className="setting-row__info">
        <div className="setting-row__label">{label}</div>
        {sub && <div className="setting-row__sub">{sub}</div>}
      </div>
      <div className="slider-wrap">
        <input
          type="range" min={min} max={max} step={step}
          value={value}
          onChange={e => onChange(Number(e.target.value))}
          className="range-input"
        />
        <span className="range-val">{value}{unit}</span>
      </div>
    </div>
  );
}

function SectionCard({ title, children }) {
  return (
    <div className="settings-card">
      <div className="settings-card__title">{title}</div>
      {children}
    </div>
  );
}

export default function Settings() {
  const [settings, setSettings] = useState({
    scan_interval_seconds: 120,
    auto_block_evil_twin:  false,
    auto_block_threshold:  20,
    threat_check_interval: 15,
  });
  const [loading,  setLoading]  = useState(true);
  const [saving,   setSaving]   = useState(false);
  const [toast,    setToast]    = useState(null);
  const [channels, setChannels] = useState({});

  useEffect(() => {
    const load = async () => {
      try {
        const [sRes, hRes] = await Promise.all([
          fetch(`${API}/settings`),
          fetch(`${API}/health`),
        ]);
        const sJson = await sRes.json();
        const hJson = await hRes.json();
        const data  = sJson?.data || sJson;
        if (data && typeof data === 'object') setSettings(s => ({ ...s, ...data }));
        const ch = hJson?.data?.notification_channels || hJson?.notification_channels || {};
        setChannels(ch);
      } catch (e) { console.error(e); }
      finally { setLoading(false); }
    };
    load();
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const res = await fetch(`${API}/settings`, {
        method:  'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(settings),
      });
      const json = await res.json();
      if (res.ok) setToast({ m: 'Settings saved successfully.', t: 'success' });
      else setToast({ m: json?.message || 'Save failed.', t: 'error' });
    } catch { setToast({ m: 'Backend unreachable.', t: 'error' }); }
    finally { setSaving(false); }
  };

  const set = (key, val) => setSettings(s => ({ ...s, [key]: val }));

  if (loading) return (
    <div className="load-screen">
      <div className="load-ring" />
      <div className="load-text">Loading settings...</div>
    </div>
  );

  return (
    <div className="page-root">
      {toast && <Toast message={toast.m} type={toast.t} onDone={() => setToast(null)} />}

      <header className="pg-header">
        <div>
          <div className="pg-eyebrow">System / Configuration / Settings</div>
          <h1 className="pg-title">Application Settings</h1>
          <div className="pg-meta">
            <span className="pg-tag">Changes apply immediately</span>
          </div>
        </div>
        <button
          className={`btn btn--primary ${saving ? 'btn--loading' : ''}`}
          onClick={save}
          disabled={saving}
        >
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
      </header>

      <div className="pg-body">

        {/* Scanning */}
        <SectionCard title="Scanning">
          <SliderRow
            label="Auto-Scan Interval"
            sub="How often Bastion automatically scans in the background"
            value={settings.scan_interval_seconds}
            min={30} max={600} step={30} unit="s"
            onChange={v => set('scan_interval_seconds', v)}
          />
          <div className="setting-divider" />
          <SliderRow
            label="Threat Check Interval"
            sub="How often ARP, DNS, and deauth checks run"
            value={settings.threat_check_interval}
            min={5} max={60} step={5} unit="s"
            onChange={v => set('threat_check_interval', v)}
          />
        </SectionCard>

        {/* Auto-Response */}
        <SectionCard title="Automated Response">
          <ToggleRow
            label="Auto-Block Evil Twin"
            sub="Automatically restrict networks flagged as Evil Twins at OS level"
            value={settings.auto_block_evil_twin}
            onChange={v => set('auto_block_evil_twin', v)}
          />
          {settings.auto_block_evil_twin && (
            <>
              <div className="setting-divider" />
              <SliderRow
                label="Auto-Block Trust Threshold"
                sub="Block automatically if trust score is at or below this value"
                value={settings.auto_block_threshold}
                min={0} max={50} step={5} unit="/100"
                onChange={v => set('auto_block_threshold', v)}
              />
              <div className="setting-warn">
                ⚠ Auto-blocking is aggressive. Only enable if you understand the consequences.
                Legitimate networks with duplicate SSIDs (e.g. mesh systems) could be blocked.
              </div>
            </>
          )}
        </SectionCard>

        {/* Notification channels status */}
        <SectionCard title="Notification Channels">
          <p className="settings-note">
            Configure channels in your <code>.env</code> file. See the README for setup instructions.
          </p>
          <div className="channels-grid">
            {[
              { key: 'ntfy',    label: 'ntfy.sh',   doc: 'NTFY_TOPIC' },
              { key: 'discord', label: 'Discord',   doc: 'DISCORD_WEBHOOK_URL' },
              { key: 'slack',   label: 'Slack',     doc: 'SLACK_WEBHOOK_URL' },
              { key: 'email',   label: 'Gmail',     doc: 'ALERT_EMAIL + ALERT_EMAIL_PASSWORD' },
            ].map(ch => (
              <div key={ch.key} className={`channel-tile ${channels[ch.key] ? 'channel-tile--on' : ''}`}>
                <div className="channel-tile__dot" />
                <div className="channel-tile__label">{ch.label}</div>
                <div className="channel-tile__status">
                  {channels[ch.key] ? 'Configured' : 'Not configured'}
                </div>
                {!channels[ch.key] && (
                  <div className="channel-tile__env">{ch.doc}</div>
                )}
              </div>
            ))}
          </div>
        </SectionCard>

        {/* Current values reference */}
        <SectionCard title="Current Configuration">
          <div className="config-table">
            {Object.entries(settings).map(([k, v]) => (
              <div key={k} className="config-row">
                <span className="config-row__key">{k}</span>
                <span className="config-row__val">{String(v)}</span>
              </div>
            ))}
          </div>
        </SectionCard>

      </div>
    </div>
  );
}