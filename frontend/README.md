# Frontend - AI-Based IDS Dashboard

React dashboard for the AI-Based Intrusion Detection System. It displays alert history, live alerts, traffic charts, threat intelligence, and system settings.

## Setup

```bash
npm install
npm start
```

The development dashboard is available at `http://localhost:3000` and uses the Create React App proxy to reach the backend at `http://localhost:5000`.

For a production build:

```bash
npm run build
```

The frontend currently connects to Socket.IO with a relative URL (`io('/')`), so `REACT_APP_SOCKET_URL` is not a supported configuration variable.

## Pages

| Page | File | Description |
| :--- | :--- | :--- |
| Dashboard | `src/pages/Dashboard.jsx` | Live alerts, metrics, traffic charts, system health, and network devices |
| Threat Intel | `src/pages/ThreatIntel.jsx` | Threat intelligence data and map view |
| History | `src/pages/History.jsx` | Searchable and filterable alert history |
| Settings | `src/pages/Settings.jsx` | IDS and system configuration |

## Structure

```
src/
├── App.jsx                        # Router and page mounting
├── index.js                       # React entry point
├── components/
│   ├── AlertTable.jsx             # Alert log table
│   ├── Charts.jsx                 # Alert charts
│   ├── MetricCard.jsx             # Dashboard metric card
│   ├── Navbar.jsx                 # Main navigation
│   └── TrafficCharts.jsx          # Traffic visualisations
├── pages/
│   ├── Dashboard.jsx              # Main dashboard and live alerts
│   ├── History.jsx                # Historical alerts
│   ├── Settings.jsx               # Configuration panel
│   └── ThreatIntel.jsx            # Threat intelligence
└── styles/
    ├── global.css                 # Global styles and design tokens
    ├── Dashboard.css              # Dashboard layout
    ├── Navbar.css                 # Navigation styles
    └── Pages.css                  # Shared page styles
```

## Data Flow

1. The frontend loads initial data from backend REST endpoints such as `/api/history`, `/api/health`, and `/api/network-devices`.
2. The backend reads alerts from the Redis `ids:alerts` stream and emits live `new_alert` events through Flask-SocketIO.
3. `Dashboard.jsx` and `History.jsx` receive those events and update their views without a page refresh.

## Tests

```bash
npm test
```

## Known Limitations

* The UI uses REST endpoints for initial data and settings, and Socket.IO for live alert updates.
* The session alert rate is a session-level UI metric, not a ground-truth model detection rate. Model metrics are documented by the backend.
