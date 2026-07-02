// frontend/src/pages/ThreatIntel.jsx
/**
 * @file ThreatIntel.jsx
 * @description Threat Intelligence page. Backed entirely by GET /api/threat-intel,
 * which aggregates real detections from the Redis 'ids:alerts' stream and
 * enriches each unique attacker IP with a real AbuseIPDB lookup (cached in
 * Redis). If no AbuseIPDB key has been configured on the Settings page yet,
 * each row honestly shows "Not configured" instead of a fabricated score —
 * matching the same honesty pattern used for the Geolocation DB status card.
 */

import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { RefreshCw, Database } from 'lucide-react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

const SEVERITY_COLOR = { CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#38BDF8' };

const formatTimestamp = (ts) => {
  if (!ts) return '—';
  const ms = typeof ts === 'number' ? ts * 1000 : ts;
  const d = new Date(ms);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString();
};

const ScoreBadge = ({ record }) => {
  if (record.intel_status === 'not_configured') {
    return <span className="status-pill not-configured">Not configured</span>;
  }
  if (record.intel_status === 'rate_limited') {
    return <span className="status-pill not-configured">Rate limited</span>;
  }
  if (record.intel_status === 'error' || record.abuse_score == null) {
    return <span className="status-pill not-configured">Unavailable</span>;
  }
  const score = record.abuse_score;
  const cls = score >= 75 ? 'critical' : score >= 40 ? 'high' : 'medium';
  return <span className={`abuse-score ${cls}`}>{score}%</span>;
};

const ThreatIntel = () => {
  const [records, setRecords] = useState([]);
  const [count, setCount] = useState(0);
  const [geoDb, setGeoDb] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const fetchIntel = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) setRefreshing(true);
    try {
      const res = await axios.get('/api/threat-intel');
      setRecords(res.data.records || []);
      setCount(res.data.count || 0);
      setGeoDb(res.data.geolocation_db || null);
      setError(null);
    } catch (err) {
      console.error('Threat intel fetch failed:', err);
      setError('Unable to retrieve threat intelligence data.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchIntel();
    const interval = setInterval(() => fetchIntel(false), 20000);
    return () => clearInterval(interval);
  }, [fetchIntel]);

  if (loading) return <div className="page-placeholder">Loading threat intelligence…</div>;

  const mappable = records.filter(r => r.location?.lat != null && r.location?.lon != null);

  return (
    <div className="page">
      <header className="page-header">
        <h1>
          <span className="eyebrow">AI-Based Intrusion Detection</span>
          Threat Intelligence
        </h1>
        <button className="action-btn" onClick={() => fetchIntel(true)} disabled={refreshing}>
          <RefreshCw size={14} className={refreshing ? 'spin' : ''} /> {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      </header>

      {error && <div className="page-placeholder error-state">{error}</div>}

      <div className="summary-cards">
        <div className="summary-card">
          <span className="label">Threat Intel Records</span>
          <span className="value">{count}</span>
        </div>
        <div className="summary-card">
          <span className="label"><Database size={12} style={{ marginRight: 5, verticalAlign: '-1px' }} />Geolocation DB</span>
          <span className={`value ${geoDb?.available ? 'ok' : 'warn'}`}>
            {geoDb?.available ? geoDb.message : (geoDb?.message || 'Unknown')}
          </span>
        </div>
      </div>

      <div className="intel-map-card">
        <h3>Threat Origins</h3>
        <div className="intel-map-container" style={{ height: 280 }}>
          <MapContainer center={[20, 10]} zoom={1.5} minZoom={1.5} worldCopyJump
            style={{ height: '100%', width: '100%', background: '#0B0E14' }}>
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://carto.com/attributions">CARTO</a>'
            />
            {mappable.map((r) => (
              <CircleMarker
                key={r.ip}
                center={[r.location.lat, r.location.lon]}
                radius={6}
                pathOptions={{
                  color: SEVERITY_COLOR[r.severity] || '#38BDF8',
                  fillColor: SEVERITY_COLOR[r.severity] || '#38BDF8',
                  fillOpacity: 0.6, weight: 1.5,
                }}
              >
                <Popup>
                  <div className="intel-marker-popup">
                    <strong>{r.ip}</strong><br />
                    {r.location.label}<br />
                    {r.hits} hit{r.hits === 1 ? '' : 's'} · {r.severity}
                  </div>
                </Popup>
              </CircleMarker>
            ))}
          </MapContainer>
          {mappable.length === 0 && records.length > 0 && (
            <p className="page-subtext" style={{ marginTop: 8 }}>
              No mappable public IPs yet — current source IPs are private/internal
              addresses, which have no real-world geolocation.
            </p>
          )}
        </div>
      </div>

      <div className="alerts-table">
        <h3>Attacker IP Reputation</h3>
        {records.length === 0 ? (
          <div className="alerts-empty">
            No threat intelligence data available yet — records appear here once real
            packet capture starts detecting source IPs.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Source</th>
                <th>Abuse Score</th>
                <th>Reports</th>
                <th>ISP</th>
                <th>Last Reported</th>
              </tr>
            </thead>
            <tbody>
              {records.map((r) => (
                <tr key={r.ip}>
                  <td>{r.ip}</td>
                  <td>{r.source}</td>
                  <td><ScoreBadge record={r} /></td>
                  <td>{r.reports ?? '—'}</td>
                  <td>{r.isp || '—'}</td>
                  <td>{r.last_reported ? formatTimestamp(r.last_reported) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default ThreatIntel;
