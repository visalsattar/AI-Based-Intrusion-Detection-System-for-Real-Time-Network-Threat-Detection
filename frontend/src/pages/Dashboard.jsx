/**
 * @file Dashboard.jsx
 * @description Main user interface for the AI-Based Intrusion Detection System (IDS).
 * Every value on this page is real: alert history loads from /api/history
 * (the Redis 'ids:alerts' stream), live updates arrive over Socket.IO,
 * system load comes from /api/health (psutil), and network neighbors come
 * from /api/network-devices (the host's real ARP table). There is no mock
 * or placeholder data path.
 * @author Visal Sattar
 */

import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { io } from "socket.io-client";
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { Laptop, Search, FileDown, RefreshCw } from 'lucide-react';
import AlertTable from '../components/AlertTable';
import { AttackDonut, NetworkTrafficChart } from '../components/TrafficCharts';

// --- WE ADDED THIS: Use Vercel's URL variable, or fallback to localhost ---
const apiUrl = process.env.REACT_APP_API_URL || "http://localhost:5000";

// --- WE UPDATED THIS: Point Socket.IO to the apiUrl ---
const socket = io(apiUrl, {
  transports: ["polling", "websocket"],
  reconnectionAttempts: 5
});

const SEVERITY_COLOR = { CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#38BDF8' };

// The signature element: a literal signal trace. Animates only while genuinely connected.
const PulseLine = ({ connected }) => (
  <svg className="pulse-line" viewBox="0 0 36 16" fill="none" aria-hidden="true">
    <path
      d={connected ? "M0 8 H8 L11 2 L14 14 L17 8 H36" : "M0 8 H36"}
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

const downloadJSON = (data, filename) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
};

const Dashboard = () => {
  const [sysHealth, setSysHealth] = useState({ cpu: 0, ram: 0, disk: 0 });
  const [alerts, setAlerts] = useState([]);
  const [devices, setDevices] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [uptimeStart] = useState(Date.now());
  const [uptime, setUptime] = useState('0h 0m 0s');

  // --- Initial real history load (so the page isn't empty just because the
  // browser tab opened after alerts already happened) ---
  useEffect(() => {
    // WE UPDATED THIS AXIOS CALL
    axios.get(`${apiUrl}/api/history`)
      .then(res => setAlerts(res.data.slice(0, 100)))
      .catch(err => console.error('Failed to load alert history:', err));
  }, []);

  // --- Real system health poller (CPU/RAM/Disk via psutil) ---
  useEffect(() => {
    const fetchHealth = async () => {
      try {
        // WE UPDATED THIS AXIOS CALL
        const res = await axios.get(`${apiUrl}/api/health`);
        setSysHealth(res.data);
      } catch (error) {
        console.error("Failed to fetch system health metrics.", error);
      }
    };
    fetchHealth();
    const interval = setInterval(fetchHealth, 3000);
    return () => clearInterval(interval);
  }, []);

  // --- Real network devices (host ARP table) ---
  const fetchDevices = useCallback(async () => {
    setScanning(true);
    try {
      // WE UPDATED THIS AXIOS CALL
      const res = await axios.get(`${apiUrl}/api/network-devices`);
      setDevices(res.data);
    } catch (error) {
      console.error("Failed to fetch network devices.", error);
    } finally {
      setScanning(false);
    }
  }, []);

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 15000);
    return () => clearInterval(interval);
  }, [fetchDevices]);

  // --- Local uptime clock (this browser session, displayed like the reference UI) ---
  useEffect(() => {
    const tick = setInterval(() => {
      const secs = Math.floor((Date.now() - uptimeStart) / 1000);
      const h = Math.floor(secs / 3600);
      const m = Math.floor((secs % 3600) / 60);
      const s = secs % 60;
      setUptime(`${h}h ${m}m ${s}s`);
    }, 1000);
    return () => clearInterval(tick);
  }, [uptimeStart]);

  // --- WebSocket Connection & Alert Streaming ---
  useEffect(() => {
    const handleConnect = () => setIsConnected(true);
    const handleDisconnect = () => setIsConnected(false);

    const handleNewAlert = (alert) => {
      setAlerts(prev => [alert, ...prev.slice(0, 99)]);
      if (alert.severity === 'CRITICAL') {
        new Audio('/critical.mp3').play().catch(() => {});
      } else if (alert.severity === 'HIGH') {
        new Audio('/high.mp3').play().catch(() => {});
      }
    };

    socket.on('connect', handleConnect);
    socket.on('disconnect', handleDisconnect);
    socket.on('new_alert', handleNewAlert);
    if (socket.connected) setIsConnected(true);

    return () => {
      socket.off('connect', handleConnect);
      socket.off('disconnect', handleDisconnect);
      socket.off('new_alert', handleNewAlert);
    };
  }, []);

  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const mappable = alerts.filter(a => a.location?.lat != null && a.location?.lon != null);

  const handleExportLogs = () => downloadJSON(alerts, `ids-alerts-${Date.now()}.json`);

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>
          <span>
            <span className="eyebrow">AI-Based Intrusion Detection</span>
            Live Network Monitor
          </span>
        </h1>
        <div className={`status ${isConnected ? 'connected' : 'disconnected'}`}>
          <PulseLine connected={isConnected} />
          {isConnected ? 'Connected' : 'Disconnected'}
        </div>
      </header>

      {/* Metrics Grid */}
      <div className="metrics-grid">
        <div className="metric-card">
          <h3>Total Alerts</h3>
          <div className="value">{alerts.length}</div>
          <span className="trend">Session Uptime: {uptime}</span>
        </div>

        <div className="metric-card red">
          <h3>Critical</h3>
          <div className="value">{criticalCount}</div>
        </div>

        <div className={`metric-card ${sysHealth.cpu > 80 ? 'red' : ''}`}>
          <h3>CPU Load</h3>
          <div className="value">{sysHealth.cpu ?? 0}%</div>
          <span className="trend">System Health</span>
        </div>

        <div className={`metric-card ${sysHealth.ram > 80 ? 'orange' : ''}`}>
          <h3>RAM Usage</h3>
          <div className="value">{sysHealth.ram ?? 0}%</div>
          <span className="trend">System Health</span>
        </div>
      </div>

      {/* Threat Origins map + charts */}
      <div className="dashboard-grid-2col">
        <div className="intel-map-card">
          <h3>Threat Origins</h3>
          <div className="intel-map-container" style={{ height: 300 }}>
            <MapContainer center={[20, 10]} zoom={1.5} minZoom={1.5} worldCopyJump
              style={{ height: '100%', width: '100%', background: '#0B0E14' }}>
              <TileLayer
                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                attribution='&copy; <a href="https://carto.com/attributions">CARTO</a>'
              />
              {mappable.map((a, i) => (
                <CircleMarker
                  key={`${a.src_ip}-${a.timestamp}-${i}`}
                  center={[a.location.lat, a.location.lon]}
                  radius={6}
                  pathOptions={{
                    color: SEVERITY_COLOR[a.severity] || '#38BDF8',
                    fillColor: SEVERITY_COLOR[a.severity] || '#38BDF8',
                    fillOpacity: 0.6, weight: 1.5,
                  }}
                >
                  <Popup>
                    <div className="intel-marker-popup">
                      <strong>{a.src_ip}</strong><br />
                      {a.location.label}<br />
                      {a.threat_type} · {a.severity}
                    </div>
                  </Popup>
                </CircleMarker>
              ))}
            </MapContainer>
          </div>
        </div>
        <AttackDonut alerts={alerts} />
      </div>

      <NetworkTrafficChart alerts={alerts} />

      {/* Action buttons */}
      <div className="dashboard-actions">
        <button className="action-btn" onClick={fetchDevices} disabled={scanning}>
          <Search size={14} /> {scanning ? 'Scanning…' : 'Scan Network'}
        </button>
        <button className="action-btn" onClick={handleExportLogs}>
          <FileDown size={14} /> Export Logs
        </button>
        <button className="action-btn" onClick={fetchDevices}>
          <RefreshCw size={14} /> Refresh Devices
        </button>
      </div>

      {/* Network Devices — real ARP table entries */}
      <div className="device-card">
        <h3><Laptop size={14} style={{ marginRight: 6, verticalAlign: '-2px' }} /> Network Devices</h3>
        {devices.length === 0 ? (
          <p className="page-subtext">No devices detected in the local ARP table yet.</p>
        ) : (
          <div className="device-grid">
            {devices.map((d) => (
              <div className="device-item" key={d.ip}>
                <div>
                  <strong>{d.ip}</strong>
                  <span className="device-mac">{d.mac}</span>
                </div>
                <span className={`status-pill ${d.status === 'online' ? 'online' : 'stale'}`}>
                  {d.status}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      <AlertTable alerts={alerts} />
    </div>
  );
};

export const getTimeSeriesData = (alerts) => {
  const data = {};
  alerts.forEach(alert => {
    if (alert && alert.timestamp) {
      const dateStr = typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : alert.timestamp;
      const hour = new Date(dateStr).getHours();
      if (!isNaN(hour)) {
        data[hour] = (data[hour] || 0) + 1;
      }
    }
  });
  return Object.entries(data).map(([hour, count]) => ({ time: `${hour}:00`, alerts: count }));
};

export default Dashboard;
