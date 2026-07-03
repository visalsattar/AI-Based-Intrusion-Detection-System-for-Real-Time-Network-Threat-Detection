# Frontend — AI-Based IDS Dashboard

  Real-time React dashboard for the AI-Based Intrusion Detection System. Connects to the Flask backend via Socket.IO and displays live alerts, traffic charts, threat intelligence, and system settings.

  ---

  ## Setup

  ```bash
  npm install
  npm start
```
  Dashboard available at http://localhost:3000.

  By default connects to http://localhost:5000. Override with:
  REACT_APP_SOCKET_URL=http://your-backend-host:5000 npm start

  ---
  Pages
```
  ┌──────────────┬───────────────────────┬──────────────────────────────────────────────────────────────────┐
  │     Page     │         File          │                           Description                            │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ Dashboard    │ pages/Dashboard.jsx   │ Live alert feed, metric cards, traffic charts, socket connection │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ Threat Intel │ pages/ThreatIntel.jsx │ Threat intelligence view                                         │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ History      │ pages/History.jsx     │ Historical alert log                                             │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ Settings     │ pages/Settings.jsx    │ System configuration                                             │
  └──────────────┴───────────────────────┴──────────────────────────────────────────────────────────────────┘
```
  ---
  Structure

  src/
  ├── App.jsx                        # Router + page mounting
  ├── index.js                       # React entry point
  ├── components/
  │   ├── AlertTable.jsx             # Live alert log table
  │   ├── Charts.jsx                 # Alert volume over time (recharts)
  │   ├── MetricCard.jsx             # Stat card (total alerts, critical, high)
  │   ├── Navbar.jsx                 # Navigation bar
  │   └── TrafficCharts.jsx          # Attack traffic visualisation
  ├── pages/
  │   ├── Dashboard.jsx              # Main dashboard, socket connection
  │   ├── History.jsx                # Historical alerts
  │   ├── Settings.jsx               # Configuration panel
  │   └── ThreatIntel.jsx            # Threat intelligence
  └── styles/
      ├── global.css                 # Design tokens (colours, fonts)
      ├── Dashboard.css              # Dashboard layout
      ├── Navbar.css                 # Navigation styles
      └── Pages.css                  # Shared page styles

  ## Setup

  ```bash
  npm install
  npm start
  ```
  Dashboard available at http://localhost:3000.

  By default connects to http://localhost:5000. Override with:
  REACT_APP_SOCKET_URL=http://your-backend-host:5000 npm start

  ---
  Pages

  ┌──────────────┬───────────────────────┬──────────────────────────────────────────────────────────────────┐
  │     Page     │         File          │                           Description                            │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ Dashboard    │ pages/Dashboard.jsx   │ Live alert feed, metric cards, traffic charts, socket connection │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ Threat Intel │ pages/ThreatIntel.jsx │ Threat intelligence view                                         │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ History      │ pages/History.jsx     │ Historical alert log                                             │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ Settings     │ pages/Settings.jsx    │ System configuration                                             │
  └──────────────┴───────────────────────┴──────────────────────────────────────────────────────────────────┘

  ---
  Structure

  src/
  ├── App.jsx                        # Router + page mounting
  ├── index.js                       # React entry point
  ├── components/
  │   ├── AlertTable.jsx             # Live alert log table
  │   ├── Charts.jsx                 # Alert volume over time (recharts)
  │   ├── MetricCard.jsx             # Stat card (total alerts, critical, high)
  │   ├── Navbar.jsx                 # Navigation bar
  │   └── TrafficCharts.jsx          # Attack traffic visualisation
  ├── pages/
  │   ├── Dashboard.jsx              # Main dashboard, socket connection
  │   ├── History.jsx                # Historical alerts
  │   ├── Settings.jsx               # Configuration panel
  │   └── ThreatIntel.jsx            # Threat intelligence
  └── styles/
      ├── global.css                 # Design tokens (colours, fonts)
      ├── Dashboard.css              # Dashboard layout
      ├── Navbar.css                 # Navigation styles
      └── Pages.css                  # Shared page styles

  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ Dashboard    │ pages/Dashboard.jsx   │ Live alert feed, metric cards, traffic charts, socket connection │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ Threat Intel │ pages/ThreatIntel.jsx │ Threat intelligence view                                         │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ History      │ pages/History.jsx     │ Historical alert log                                             │
  ├──────────────┼───────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ Settings     │ pages/Settings.jsx    │ System configuration                                             │
  └──────────────┴───────────────────────┴──────────────────────────────────────────────────────────────────┘

  ---
  Structure

  src/
  ├── App.jsx                        # Router + page mounting
  ├── index.js                       # React entry point
  ├── components/
  │   ├── AlertTable.jsx             # Live alert log table
  │   ├── Charts.jsx                 # Alert volume over time (recharts)
  │   ├── MetricCard.jsx             # Stat card (total alerts, critical, high)
  │   ├── Navbar.jsx                 # Navigation bar
  │   └── TrafficCharts.jsx          # Attack traffic visualisation
  ├── pages/
  │   ├── Dashboard.jsx              # Main dashboard, socket connection
  │   ├── History.jsx                # Historical alerts
  │   ├── Settings.jsx               # Configuration panel
  │   └── ThreatIntel.jsx            # Threat intelligence
  └── styles/
      ├── global.css                 # Design tokens (colours, fonts)
      ├── Dashboard.css              # Dashboard layout
      ├── Navbar.css                 # Navigation styles
      └── Pages.css                  # Shared page styles

  ---
  How Alerts Arrive

  1. Backend detects a threat → publishes to Redis ids:alerts stream
  2. Flask Socket.IO bridge reads the stream → emits new_alert event
  3. Dashboard.jsx receives the event → updates alert table and charts in real time

  ---
  Known Limitations

  - public/alert.mp3 is a placeholder (0 bytes). Sound on CRITICAL alerts will not play until a real audio file is
  placed at that path. The failure is caught silently.
  - The "Session Alert Rate" metric is alerts-this-session / total-alerts-this-session, not a ground-truth detection
  rate. Real model metrics are in backend/models/real_metrics.json.
  - The /api/dashboard REST endpoint on the backend exists but is not currently wired into the UI. Only the WebSocket
  stream is used.

  ---
