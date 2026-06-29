# IDS Dashboard (React Frontend)

Real-time dashboard for the AI-Based Intrusion Detection System. Connects
to the Flask backend via WebSocket (`socket.io-client`) and renders live
alerts as they arrive.

## Setup

```bash
npm install
npm start
```

By default connects to `http://localhost:5000`. Override with:
```bash
REACT_APP_SOCKET_URL=http://your-backend-host:5000 npm start
```

## Known limitations

- **`public/alert.mp3` is an empty placeholder (0 bytes).** The dashboard
  attempts to play this file on a CRITICAL alert; the call fails silently
  (caught in `Dashboard.jsx`) until a real short audio file is placed at
  this path. No sound currently plays on critical alerts.
- **"Session Alert Rate"** on the dashboard is a real ratio (critical+high
  alerts / total alerts seen this browser session) — it is NOT the same
  as a true detection rate, which would require ground-truth labels the
  live dashboard does not have access to. See the backend's
  `docs/CHANGES.md` and Thesis Chapter 7 for the model's real, ground-truth
  evaluated metrics.
- This component only consumes the WebSocket `new_alert` stream. It does
  not call the backend's `/api/dashboard` REST endpoint, which exists
  for potential future use (e.g. fetching alert history on page load)
  but is not currently wired into the UI.

## Structure

```
src/
├── App.jsx                    # Mounts Dashboard
├── components/
│   ├── Dashboard.jsx           # Main container, socket connection, signal-pulse indicator
│   ├── MetricCard.jsx          # Small stat card
│   ├── Charts.jsx              # Alert-volume-over-time line chart (recharts)
│   └── AlertTable.jsx          # Live alert log
└── styles/
    ├── global.css               # Design tokens (colors, fonts)
    └── Dashboard.css            # Component styles
```
