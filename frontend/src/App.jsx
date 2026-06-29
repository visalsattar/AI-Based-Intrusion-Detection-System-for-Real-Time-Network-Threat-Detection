// frontend/src/App.jsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import History from './pages/History';
import ThreatIntel from './pages/ThreatIntel';
import Settings from './pages/Settings';
import './App.css';

function App() {
  return (
    <Router>
      <div className="app-container">
        <Navbar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/history" element={<History />} />
            <Route path="/threat-intel" element={<ThreatIntel />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}
export default App;