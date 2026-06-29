// frontend/src/pages/Settings.jsx
/**
 * @file Settings.jsx
 * @description System Configuration page, rebuilt to match the proven
 * reference UI: Detection Settings, Alert Preferences, Threat Intelligence
 * (AbuseIPDB key), Geolocation Database status, and System Information.
 * Every field reads from and writes to real backend state:
 *   GET  /api/settings            -> current saved configuration
 *   POST /api/save-settings       -> persists configuration to Redis
 *   GET  /api/network-interfaces  -> real interfaces on the host (for the dropdown)
 *   GET  /api/system-info         -> real model/GeoIP/uptime/log-count status
 *   POST /api/reload-geoip        -> re-opens the GeoLite2 mmdb after you drop it in
 *   DELETE /api/history           -> "Export Logs" / clear, shared with History page
 */

import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { Shield, Bell, Database, Info, RefreshCw } from 'lucide-react';

const DEFAULT_SETTINGS = {
  sensitivity: 'medium',
  networkInterface: 'auto',
  flowTimeout: 120,
  sound: true,
  desktopNotifications: true,
  geolocationEnabled: true,
  threatIntelEnabled: true,
  autoBlock: false,
  abuseIPDBKey: '',
  abuseIPDBKeySet: false,
  criticalThreshold: 0.95,
  highThreshold: 0.85,
};

const ToggleSwitch = ({ checked, onChange }) => (
  <label className="toggle-switch">
    <input type="checkbox" checked={checked} onChange={onChange} />
    <span className="toggle-slider" />
  </label>
);

const formatUptime = (totalSeconds = 0) => {
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return `${h}h ${m}m ${s}s`;
};

const Settings = () => {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [interfaces, setInterfaces] = useState([]);
  const [systemInfo, setSystemInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [reloadingGeo, setReloadingGeo] = useState(false);
  const [saveState, setSaveState] = useState(null);

  const loadAll = useCallback(async () => {
    try {
      const [settingsRes, ifaceRes, infoRes] = await Promise.all([
        axios.get('/api/settings'),
        axios.get('/api/network-interfaces'),
        axios.get('/api/system-info'),
      ]);
      setSettings({ ...DEFAULT_SETTINGS, ...settingsRes.data });
      setInterfaces(ifaceRes.data || []);
      setSystemInfo(infoRes.data);
    } catch (err) {
      console.error('Failed to load settings/system info:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const update = (patch) => setSettings(prev => ({ ...prev, ...patch }));

  const save = async () => {
    setSaving(true);
    setSaveState(null);
    try {
      await axios.post('/api/save-settings', settings);
      setSaveState('success');
      await loadAll(); // refresh masked key state / system info
    } catch (e) {
      console.error('Failed to save settings:', e);
      setSaveState('error');
    } finally {
      setSaving(false);
      setTimeout(() => setSaveState(null), 4000);
    }
  };

  const reloadGeoDb = async () => {
    setReloadingGeo(true);
    try {
      const res = await axios.post('/api/reload-geoip');
      setSystemInfo(prev => ({ ...prev, geolocation_db: res.data }));
    } catch (e) {
      console.error('Failed to reload GeoIP database:', e);
    } finally {
      setReloadingGeo(false);
    }
  };

  const exportLogs = async () => {
    try {
      const res = await axios.get('/api/history');
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `ids-alerts-${Date.now()}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Export failed:', e);
    }
  };

  if (loading) return <div className="page-placeholder">Loading configuration…</div>;

  const modelStatus = systemInfo?.model;
  const geoStatus = systemInfo?.geolocation_db;

  return (
    <div className="page">
      <header className="page-header">
        <h1>
          <span className="eyebrow">AI-Based Intrusion Detection</span>
          System Configuration
        </h1>
      </header>

      <div className="settings-grid">
        {/* ---------------- Detection Settings ---------------- */}
        <div className="settings-card">
          <h3><Shield size={13} style={{ marginRight: 6, verticalAlign: '-2px' }} />Detection Settings</h3>

          <div className="setting-item">
            <div>
              <label>Detection Sensitivity</label>
              <span className="setting-hint">Adjust how aggressively the system detects threats</span>
            </div>
            <select value={settings.sensitivity} onChange={(e) => update({ sensitivity: e.target.value })}>
              <option value="low">Low (Fewer alerts)</option>
              <option value="medium">Medium (Balanced)</option>
              <option value="high">High (More alerts)</option>
            </select>
          </div>

          <div className="setting-item">
            <div>
              <label>Network Interface</label>
              <span className="setting-hint">Select which real network interface to monitor</span>
            </div>
            <select value={settings.networkInterface} onChange={(e) => update({ networkInterface: e.target.value })}>
              <option value="auto">Auto-detect</option>
              {interfaces.map((i) => (
                <option key={i.name} value={i.name}>
                  {i.name}{i.ipv4 ? ` — ${i.ipv4}` : ''}{!i.is_up ? ' (down)' : ''}
                </option>
              ))}
            </select>
          </div>

          <div className="setting-item">
            <div>
              <label>Flow Timeout (seconds)</label>
              <span className="setting-hint">Time before inactive flows are removed</span>
            </div>
            <input
              type="number"
              min="10" max="600"
              value={settings.flowTimeout}
              onChange={(e) => update({ flowTimeout: parseInt(e.target.value, 10) || 0 })}
              style={{ width: 90, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--panel-border)', color: 'var(--text)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}
            />
          </div>

          <div className="setting-item">
            <div>
              <label>Critical Threshold</label>
              <span className="setting-hint">Anomaly score above which an alert is CRITICAL</span>
            </div>
            <div>
              <input type="range" min="0.80" max="0.999" step="0.005"
                value={settings.criticalThreshold}
                onChange={(e) => update({ criticalThreshold: parseFloat(e.target.value) })} />
              <span className="range-value">{(settings.criticalThreshold * 100).toFixed(1)}%</span>
            </div>
          </div>

          <div className="setting-item">
            <div>
              <label>High Threshold</label>
              <span className="setting-hint">Anomaly score above which an alert is HIGH</span>
            </div>
            <div>
              <input type="range" min="0.50" max="0.95" step="0.005"
                value={settings.highThreshold}
                onChange={(e) => update({ highThreshold: parseFloat(e.target.value) })} />
              <span className="range-value">{(settings.highThreshold * 100).toFixed(1)}%</span>
            </div>
          </div>
        </div>

        {/* ---------------- Alert Preferences ---------------- */}
        <div className="settings-card">
          <h3><Bell size={13} style={{ marginRight: 6, verticalAlign: '-2px' }} />Alert Preferences</h3>

          <div className="setting-item">
            <div>
              <label>Sound Alerts</label>
              <span className="setting-hint">Play alert sounds for critical threats</span>
            </div>
            <ToggleSwitch checked={settings.sound} onChange={(e) => update({ sound: e.target.checked })} />
          </div>

          <div className="setting-item">
            <div>
              <label>Desktop Notifications</label>
              <span className="setting-hint">Show desktop alerts for threats</span>
            </div>
            <ToggleSwitch checked={settings.desktopNotifications} onChange={(e) => update({ desktopNotifications: e.target.checked })} />
          </div>

          <div className="setting-item">
            <div>
              <label>Geolocation</label>
              <span className="setting-hint">Show threat locations on the map</span>
            </div>
            <ToggleSwitch checked={settings.geolocationEnabled} onChange={(e) => update({ geolocationEnabled: e.target.checked })} />
          </div>

          <div className="setting-item">
            <div>
              <label>Threat Intelligence</label>
              <span className="setting-hint">Check threats against AbuseIPDB</span>
            </div>
            <ToggleSwitch checked={settings.threatIntelEnabled} onChange={(e) => update({ threatIntelEnabled: e.target.checked })} />
          </div>

          <div className="setting-item">
            <div>
              <label>Automatic IP Blocking</label>
              <span className="setting-hint">Auto-block source IPs on CRITICAL severity (real iptables/netsh rule)</span>
            </div>
            <ToggleSwitch checked={settings.autoBlock} onChange={(e) => update({ autoBlock: e.target.checked })} />
          </div>
        </div>

        {/* ---------------- Threat Intelligence (AbuseIPDB) ---------------- */}
        <div className="settings-card">
          <h3><Database size={13} style={{ marginRight: 6, verticalAlign: '-2px' }} />Threat Intelligence</h3>

          <div className="setting-item" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
            <div>
              <label>AbuseIPDB API Key</label>
              <span className="setting-hint">
                {settings.abuseIPDBKeySet ? 'A key is already saved — leave blank to keep it.' : (
                  <>Get a free key at{' '}
                    <a href="https://www.abuseipdb.com" target="_blank" rel="noreferrer" style={{ color: 'var(--data)' }}>
                      abuseipdb.com
                    </a> to enable threat intelligence.</>
                )}
              </span>
            </div>
            <input
              type="password"
              placeholder={settings.abuseIPDBKeySet ? '••••••••••••••••••••' : 'Paste your AbuseIPDB API key'}
              value={settings.abuseIPDBKey}
              onChange={(e) => update({ abuseIPDBKey: e.target.value })}
              className="search-input"
              style={{ width: '100%' }}
            />
          </div>
        </div>

        {/* ---------------- Geolocation Database ---------------- */}
        <div className="settings-card">
          <h3><Database size={13} style={{ marginRight: 6, verticalAlign: '-2px' }} />Geolocation Database</h3>

          {geoStatus?.available ? (
            <p className="page-subtext">{geoStatus.message}</p>
          ) : (
            <>
              <p className="page-subtext" style={{ color: 'var(--warn)', marginBottom: 10 }}>
                ⚠ {geoStatus?.message || 'Database not found'}
              </p>
              <div className="page-subtext" style={{ fontSize: 12, lineHeight: 1.7 }}>
                1. Create a free account at{' '}
                <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noreferrer" style={{ color: 'var(--data)' }}>
                  MaxMind
                </a><br />
                2. Download the GeoLite2-City database (MMDB format)<br />
                3. Place the file at <code>backend/config/GeoLite2-City.mmdb</code><br />
                4. Click "Reload Database" below
              </div>
            </>
          )}

          <div className="settings-actions" style={{ marginTop: 16 }}>
            <button className="btn-primary" onClick={reloadGeoDb} disabled={reloadingGeo}>
              <RefreshCw size={13} className={reloadingGeo ? 'spin' : ''} style={{ marginRight: 6, verticalAlign: '-2px' }} />
              {reloadingGeo ? 'Reloading…' : 'Reload Database'}
            </button>
          </div>
        </div>

        {/* ---------------- System Information ---------------- */}
        <div className="settings-card" style={{ gridColumn: '1 / -1' }}>
          <h3><Info size={13} style={{ marginRight: 6, verticalAlign: '-2px' }} />System Information</h3>
          <div className="settings-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            <div className="summary-card">
              <span className="label">Model Status</span>
              <span className={`value ${modelStatus?.status === 'ready' ? 'ok' : 'warn'}`} style={{ fontSize: modelStatus?.status === 'ready' ? 20 : 13 }}>
                {modelStatus?.status === 'ready'
                  ? (modelStatus.accuracy != null ? `${(modelStatus.accuracy * 100).toFixed(1)}%` : 'Calibrated')
                  : modelStatus?.status === 'uncalibrated'
                    ? 'Uncalibrated'
                    : 'Not trained'}
              </span>
            </div>
            <div className="summary-card">
              <span className="label">Geolocation DB</span>
              <span className={`value ${geoStatus?.available ? 'ok' : 'warn'}`} style={{ fontSize: 13 }}>
                {geoStatus?.available ? 'Available' : 'Not available'}
              </span>
            </div>
            <div className="summary-card">
              <span className="label">Log Entries</span>
              <span className="value">{systemInfo?.log_entries ?? 0}</span>
            </div>
            <div className="summary-card">
              <span className="label">System Uptime</span>
              <span className="value ok" style={{ fontSize: 16 }}>{formatUptime(systemInfo?.uptime_seconds)}</span>
            </div>
          </div>
          {modelStatus?.status !== 'ready' && (
            <p className="page-subtext" style={{ marginTop: 14, fontSize: 12 }}>{modelStatus?.message}</p>
          )}
        </div>
      </div>

      <div className="settings-actions">
        <button className="btn-primary" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save Configuration'}
        </button>
        <button className="action-btn" onClick={exportLogs}>Export Logs</button>
        {saveState === 'success' && <span className="save-confirmation">Configuration updated successfully.</span>}
        {saveState === 'error' && <span className="save-confirmation error">Failed to save. Check backend connectivity.</span>}
      </div>
    </div>
  );
};

export default Settings;
