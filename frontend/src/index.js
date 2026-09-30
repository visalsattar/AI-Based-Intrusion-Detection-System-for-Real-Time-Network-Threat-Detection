import React from 'react';
import ReactDOM from 'react-dom/client';
import axios from 'axios';
import App from './App';

// Optional shared-secret guard for IDS_API_TOKEN (see backend/routes.py's before_request
// guard). This is NOT real authentication: the token sits in localStorage and is visible to
// anyone with devtools access to this page. Its only job is to stop OTHER hosts on the network
// from issuing raw curl/script requests to a dashboard that's reachable beyond 127.0.0.1 -- the
// Origin-header check in routes.py is what stops a random web page's browser-side request. If
// you need to actually authenticate a human, put this behind a reverse proxy with real login.
//
// Usage: open the dashboard once as .../?token=<same value as IDS_API_TOKEN>; it's saved to
// localStorage and stripped from the URL, and every future request carries it automatically.
const params = new URLSearchParams(window.location.search);
const urlToken = params.get('token');
if (urlToken) {
  localStorage.setItem('idsApiToken', urlToken);
  params.delete('token');
  const rest = params.toString();
  window.history.replaceState({}, '', `${window.location.pathname}${rest ? `?${rest}` : ''}`);
}
const savedToken = localStorage.getItem('idsApiToken');
if (savedToken) {
  axios.defaults.headers.common['Authorization'] = `Bearer ${savedToken}`;
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
