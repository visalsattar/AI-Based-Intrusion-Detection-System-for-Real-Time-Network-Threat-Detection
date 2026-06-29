// frontend/src/pages/History.jsx
/**
 * @file History.jsx
 * @description Alert History page. Loads recent alerts from /api/history on
 * mount, then stays current by listening for the same 'new_alert' Socket.IO
 * event the Dashboard uses — so a new intrusion appears here immediately
 * without a page refresh. Supports free-text search (threat type / source
 * IP / location) and one-click severity filtering.
 */

import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import { Search, FileDown, Trash2 } from 'lucide-react';

const socket = io('/', { transports: ['polling', 'websocket'] });

const formatTimestamp = (timestamp) => {
  if (!timestamp) return '—';
  const ms = typeof timestamp === 'number' ? timestamp * 1000 : timestamp;
  const date = new Date(ms);
  return isNaN(date.getTime()) ? '—' : date.toLocaleString();
};

const getLocationLabel = (alert) => alert.location?.label || alert.location || 'Resolving…';

const SEVERITY_FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'];

const History = () => {
  const [alerts, setAlerts] = useState([]);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Initial load from the REST endpoint (backed by the Redis 'ids:alerts' stream)
  useEffect(() => {
    axios.get('/api/history')
      .then(res => {
        setAlerts(res.data);
        setLoading(false);
      })
      .catch(err => {
        console.error('Failed to fetch alert history:', err);
        setError('Could not load alert history. Is the backend running?');
        setLoading(false);
      });
  }, []);

  // Live updates: prepend any alert emitted while this page is open
  useEffect(() => {
    const handleNewAlert = (alert) => {
      setAlerts(prev => [alert, ...prev].slice(0, 300));
    };
    socket.on('new_alert', handleNewAlert);
    return () => socket.off('new_alert', handleNewAlert);
  }, []);

  const filtered = useMemo(() => {
    const term = search.toLowerCase();
    return alerts.filter(a => {
      const matchesSeverity = severityFilter === 'ALL' || a.severity === severityFilter;
      const matchesSearch = !term || [
        a.threat_type, a.src_ip, getLocationLabel(a), a.protocol,
      ].some(field => (field || '').toLowerCase().includes(term));
      return matchesSeverity && matchesSearch;
    });
  }, [alerts, search, severityFilter]);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ids-alert-history-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleClear = async () => {
    if (!window.confirm('Permanently clear all alert history from Redis? This cannot be undone.')) return;
    try {
      await axios.delete('/api/history');
      setAlerts([]);
    } catch (err) {
      console.error('Failed to clear history:', err);
      alert('Could not clear history — check backend connectivity.');
    }
  };

  if (loading) return <div className="page-placeholder">Loading alert history…</div>;
  if (error) return <div className="page-placeholder error-state">{error}</div>;

  return (
    <div className="page">
      <header className="page-header">
        <h1>
          <span className="eyebrow">AI-Based Intrusion Detection</span>
          Alert History
        </h1>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <p className="page-subtext" style={{ margin: 0 }}>{alerts.length} alerts recorded</p>
          <button className="action-btn" onClick={handleExport}><FileDown size={14} /> Export Logs</button>
          <button className="action-btn" onClick={handleClear} style={{ color: 'var(--alert)', borderColor: 'rgba(239,68,68,0.35)', background: 'rgba(239,68,68,0.08)' }}>
            <Trash2 size={14} /> Clear Logs
          </button>
        </div>
      </header>

      <div className="toolbar">
        <div style={{ position: 'relative' }}>
          <Search
            size={14}
            style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }}
          />
          <input
            type="text"
            placeholder="Search by threat type, IP, or location…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="search-input"
            style={{ paddingLeft: 32 }}
          />
        </div>

        <div className="filter-pills">
          {SEVERITY_FILTERS.map(level => (
            <button
              key={level}
              className={`filter-pill ${severityFilter === level ? `active ${level.toLowerCase()}` : ''}`}
              onClick={() => setSeverityFilter(level)}
            >
              {level}
            </button>
          ))}
        </div>
      </div>

      <div className="alerts-table">
        <h3>Logged Events</h3>
        {filtered.length === 0 ? (
          <div className="alerts-empty">No alerts match your current filters.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Threat Type</th>
                <th>Source IP</th>
                <th>Location</th>
                <th>Protocol</th>
                <th>Anomaly Score</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a, i) => (
                <tr key={a.timestamp ? `${a.timestamp}-${a.src_ip}-${i}` : i}>
                  <td>{formatTimestamp(a.timestamp)}</td>
                  <td>{a.threat_type || 'Unknown'}</td>
                  <td>{a.src_ip || a.flow_key || 'Unknown'}</td>
                  <td>{getLocationLabel(a)}</td>
                  <td>{a.protocol || '—'}</td>
                  <td>{typeof a.anomaly_score === 'number' ? `${(a.anomaly_score * 100).toFixed(1)}%` : '—'}</td>
                  <td>
                    <span className={`severity-badge ${(a.severity || '').toLowerCase()}`}>
                      {a.severity || 'UNKNOWN'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default History;
