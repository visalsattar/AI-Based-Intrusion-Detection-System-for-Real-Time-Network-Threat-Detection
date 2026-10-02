// frontend/src/components/AuthBanner.jsx
import React, { useEffect, useState } from 'react';

// Hook: true once any API call has returned 401 (see the axios interceptor in index.js).
export const useAuthRequired = () => {
  const [required, setRequired] = useState(() => Boolean(window.idsAuthRequired));
  useEffect(() => {
    const on = () => setRequired(true);
    window.addEventListener('ids-auth-required', on);
    return () => window.removeEventListener('ids-auth-required', on);
  }, []);
  return required;
};

// Shown on every page when the backend demands IDS_API_TOKEN and this browser lacks a valid one.
const AuthBanner = () => {
  const required = useAuthRequired();
  if (!required) return null;
  const hadToken = Boolean(localStorage.getItem('idsApiToken'));
  return (
    <div className="auth-banner" role="alert">
      <strong>{hadToken ? 'API token rejected.' : 'API token required.'}</strong>{' '}
      This dashboard is protected by <code>IDS_API_TOKEN</code>. Open it once as{' '}
      <code>{window.location.origin}/?token=&lt;your token&gt;</code>
      {' '}(the value in the project&apos;s <code>.env</code>). The browser remembers it after that.
    </div>
  );
};

export default AuthBanner;
