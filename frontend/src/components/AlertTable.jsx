import React from 'react';

const formatTimestamp = (timestamp) => {
  if (!timestamp) return '—';
  const ms = typeof timestamp === 'number' ? timestamp * 1000 : timestamp;
  const date = new Date(ms);
  return isNaN(date.getTime()) ? '—' : date.toLocaleTimeString();
};

// The real alert payload (see backend/src/ids_pipeline.py _process_prediction)
// sends src_ip directly. flow_key is also present but is just the source IP
// as a plain string with no delimiters -- it is not a composite key to split.
const getSourceIp = (alert) => alert.src_ip || alert.flow_key || 'Unknown';

const AlertTable = ({ alerts }) => {
  return (
    <div className="alerts-table">
      <h3>Latest Alerts</h3>
      {alerts.length === 0 ? (
        <div className="alerts-empty">No alerts yet. Listening for live network anomalies.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Anomaly Score</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert, index) => (
              <tr key={alert.timestamp ? `${alert.timestamp}-${index}` : index}>
                <td>{formatTimestamp(alert.timestamp)}</td>
                <td>{getSourceIp(alert)}</td>
                <td>{typeof alert.anomaly_score === 'number' ? `${(alert.anomaly_score * 100).toFixed(1)}%` : '—'}</td>
                <td>
                  <span className={`severity-badge ${(alert.severity || '').toLowerCase()}`}>
                    {alert.severity || 'UNKNOWN'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};
export default AlertTable;
