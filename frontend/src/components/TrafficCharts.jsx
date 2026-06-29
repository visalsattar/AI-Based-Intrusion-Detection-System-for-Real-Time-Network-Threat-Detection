// frontend/src/components/TrafficCharts.jsx
/**
 * @file TrafficCharts.jsx
 * @description Attack Distribution donut + Threat Activity area chart.
 * Both are derived entirely from the real `alerts` array (sourced from the
 * Redis 'ids:alerts' stream via Socket.IO / REST) — there is no synthetic
 * fallback data. With zero alerts, both show an honest empty state instead
 * of a fabricated chart.
 */

import React, { useMemo } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';

const CATEGORY_COLORS = {
  Normal: '#38BDF8',
  DoS: '#EF4444',
  PortScan: '#F59E0B',
  BruteForce: '#A855F7',
  Other: '#64748B',
};

const categorize = (threatType = '') => {
  const t = threatType.toLowerCase();
  if (t.includes('benign') || t.includes('normal')) return 'Normal';
  if (t.includes('dos') || t.includes('ddos')) return 'DoS';
  if (t.includes('port scan') || t.includes('portscan') || t.includes('scan')) return 'PortScan';
  if (t.includes('brute')) return 'BruteForce';
  return 'Other';
};

const EmptyChartState = ({ label }) => (
  <div style={{
    height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
    color: 'var(--text-dim)', fontSize: 13, fontFamily: 'var(--font-mono)', textAlign: 'center',
  }}>
    {label}
  </div>
);

// ---------------- Attack Distribution Donut ----------------

export const AttackDonut = ({ alerts = [] }) => {
  const data = useMemo(() => {
    const counts = {};
    alerts.forEach(a => {
      const cat = categorize(a.threat_type);
      counts[cat] = (counts[cat] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [alerts]);

  return (
    <div className="chart-container">
      <h3>Attack Distribution</h3>
      {data.length === 0 ? (
        <EmptyChartState label={"No alerts yet —\nstart packet capture to populate this chart."} />
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={3}
              dataKey="value"
              stroke="none"
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={CATEGORY_COLORS[entry.name] || CATEGORY_COLORS.Other} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ backgroundColor: '#161B22', border: '1px solid #2A3340', borderRadius: 6, color: '#E8EAED' }} />
            <Legend verticalAlign="bottom" height={36} wrapperStyle={{ color: 'var(--text-dim)', fontSize: 12 }} />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
};

// ---------------- Threat Activity Over Time ----------------

export const NetworkTrafficChart = ({ alerts = [] }) => {
  const data = useMemo(() => {
    if (alerts.length === 0) return [];
    const buckets = {};
    alerts.forEach(a => {
      if (!a.timestamp) return;
      const ms = typeof a.timestamp === 'number' ? a.timestamp * 1000 : a.timestamp;
      const date = new Date(ms);
      if (isNaN(date.getTime())) return;
      // Bucket by minute so a burst of alerts reads as a real spike
      const key = `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
      buckets[key] = (buckets[key] || 0) + 1;
    });
    return Object.entries(buckets)
      .map(([time, count]) => ({ time, count }))
      .sort((a, b) => a.time.localeCompare(b.time))
      .slice(-30); // last 30 minute-buckets
  }, [alerts]);

  return (
    <div className="chart-container">
      <h3>Threat Activity (per minute)</h3>
      {data.length === 0 ? (
        <EmptyChartState label={"No alerts yet —\nthis chart populates as real detections arrive."} />
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EF4444" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1E2530" vertical={false} />
            <XAxis dataKey="time" stroke="#5B6573" tick={{ fill: '#5B6573', fontSize: 11 }} />
            <YAxis stroke="#5B6573" tick={{ fill: '#5B6573', fontSize: 11 }} allowDecimals={false} />
            <Tooltip contentStyle={{ backgroundColor: '#161B22', border: '1px solid #2A3340', borderRadius: 6, color: '#E8EAED' }} />
            <Area type="monotone" dataKey="count" name="Alerts" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#colorAlerts)" />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
};
