import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const Charts = ({ data }) => {
  return (
    <div className="chart-container">
      <h3>Live Anomaly Trends</h3>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" />
          <YAxis />
          <Tooltip />
          {/* This is the Line component that was missing from the import! */}
          <Line type="monotone" dataKey="alerts" stroke="#8884d8" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default Charts;