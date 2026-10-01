# Frontend — AI-Based IDS Dashboard

React (Create React App) dashboard for the AI-Based IDS: live alerts, alert history, traffic charts, threat intelligence, and settings.

## Setup

```bash
npm install
npm start
```

The dev server runs at `http://localhost:3000` and proxies API and Socket.IO requests to the backend at `http://127.0.0.1:5000` (`"proxy"` in `package.json`). Start the backend first (`cd backend && python main.py`).

Production build:

```bash
npm run build
```

Under Docker, the backend serves the built app at `http://localhost:5000`.

Socket.IO connects with a relative URL (`io('/')`); there is no `REACT_APP_SOCKET_URL` setting.

## Authentication

When the backend has `IDS_API_TOKEN` set, REST calls and Socket.IO connections must carry that token. The dashboard sends it as a Bearer header on axios and as `auth.token` on the Dashboard socket.

## Pages

| Page         | File                      | Description |
|--------------|---------------------------|-------------|
| Dashboard    | `src/pages/Dashboard.jsx` | Live alerts, metrics, traffic charts, system health, network devices |
| Threat Intel | `src/pages/ThreatIntel.jsx` | Threat-intelligence data and map view |
| History      | `src/pages/History.jsx`   | Searchable, filterable alert history |
| Settings     | `src/pages/Settings.jsx`  | Detection thresholds, interface and system configuration |

## Structure

```
src/
├── App.jsx                 # Router and page mounting
├── App.css
├── index.js                # React entry; axios auth header
├── components/
│   ├── AlertTable.jsx      # Alert log table
│   ├── Charts.jsx          # Alert charts
│   ├── MetricCard.jsx      # Dashboard metric card
│   ├── Navbar.jsx          # Navigation
│   └── TrafficCharts.jsx   # Traffic visualisations
├── pages/
│   ├── Dashboard.jsx
│   ├── History.jsx
│   ├── Settings.jsx
│   └── ThreatIntel.jsx
└── styles/
    ├── global.css          # Global styles and design tokens
    ├── Dashboard.css
    ├── Navbar.css
    └── Pages.css
```

## Data flow

1. Initial data comes from REST endpoints: `/api/health`, `/api/history`, `/api/threat-intel`, `/api/settings`, `/api/save-settings`, `/api/system-info`, `/api/network-interfaces`, `/api/network-devices`, `/api/reload-geoip`.
2. The backend reads the Redis `ids:alerts` stream and emits live `new_alert` events over Flask-SocketIO.
3. `Dashboard.jsx` and `History.jsx` subscribe to those events and update without a page refresh.

## Tests

There are no frontend tests yet. `npm test` (react-scripts) will report that no tests were found.

## Known limitations

- The session alert rate on the dashboard is a UI metric for the current session, not a model detection rate. Model metrics are in `backend/README.md`.
- No automated frontend test coverage.
