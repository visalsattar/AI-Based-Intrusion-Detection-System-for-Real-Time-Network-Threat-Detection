import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, History, ShieldAlert, Settings } from 'lucide-react';

const Navbar = () => {
  return (
    <nav className="top-navbar">
      <div className="nav-brand">
        <ShieldAlert className="brand-icon" size={24} />
        <h2>AI-IDS Command Center</h2>
      </div>
      
      <div className="nav-links">
        <NavLink to="/" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
          <LayoutDashboard size={18} />
          <span>Dashboard</span>
        </NavLink>
        
        <NavLink to="/history" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
          <History size={18} />
          <span>Alert History</span>
        </NavLink>
        
        <NavLink to="/threat-intel" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
          <ShieldAlert size={18} />
          <span>Threat Intel</span>
        </NavLink>
        
        <NavLink to="/settings" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
          <Settings size={18} />
          <span>Settings</span>
        </NavLink>
      </div>
    </nav>
  );
};

export default Navbar;