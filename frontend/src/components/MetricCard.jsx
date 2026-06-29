import React from 'react';

const MetricCard = ({ title, value, color = "default", trend }) => {
  return (
    <div className={`metric-card ${color}`}>
      <h3>{title}</h3>
      <div className="value">{value}</div>
      {trend && <span className="trend">{trend}</span>}
    </div>
  );
};
export default MetricCard;
