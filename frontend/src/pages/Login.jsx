import React, { useState } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { useAuth } from '../auth.jsx';

export default function Login() {
  const { user, login } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to={(loc.state && loc.state.from && loc.state.from.pathname) || '/'} replace />;

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      await login(username.trim(), password);
      nav((loc.state && loc.state.from && loc.state.from.pathname) || '/', { replace: true });
    } catch (err) {
      setError(err.message || 'Sign-in failed');
    } finally { setBusy(false); }
  };

  return (
    <div className="min-h-screen grid lg:grid-cols-2">
      {/* Left: identity / principle. The memorable element is the trust-boundary diagram. */}
      <div className="hidden lg:flex flex-col justify-between p-10 bg-base-900 border-r border-base-700/50">
        <div className="flex items-center gap-2.5">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none"><path d="M12 2.5 4.5 5.2v6.1c0 4.6 3.1 8.1 7.5 9.7 4.4-1.6 7.5-5.1 7.5-9.7V5.2L12 2.5Z" stroke="#3ea6c4" strokeWidth="1.4" fill="rgba(62,166,196,0.08)"/><circle cx="12" cy="11" r="2.1" fill="#3ea6c4"/><path d="M12 13.1V17" stroke="#3ea6c4" strokeWidth="1.4" strokeLinecap="round"/></svg>
          <div><div className="font-semibold">HLPA-DS</div><div className="text-xs text-ink-faint">Honeypot Luring Prevention & Attack Detection</div></div>
        </div>
        <div className="max-w-md">
          <h1 className="text-2xl font-semibold leading-snug">Attract suspicious activity to isolated decoys, detect it from the telemetry, and keep real systems outside the trust boundary.</h1>
          <TrustDiagram />
        </div>
        <p className="text-xs text-ink-faint max-w-md">Defensive, alert-first. Decoy content is synthetic. Any response action is lab-only and requires explicit approval. A source observation is a lead, never attribution.</p>
      </div>

      {/* Right: form */}
      <div className="flex items-center justify-center p-6">
        <form onSubmit={submit} className="w-full max-w-sm">
          <h2 className="text-lg font-semibold">Sign in to the console</h2>
          <p className="text-sm text-ink-dim mt-1">Access is role-based and every action is audit-logged.</p>
          <label className="block mt-6 text-sm">
            <span className="label">Username</span>
            <input className="field w-full mt-1" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
          </label>
          <label className="block mt-4 text-sm">
            <span className="label">Password</span>
            <input className="field w-full mt-1" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </label>
          {error && <div className="mt-4 text-sm text-bad bg-bad/10 border border-bad/30 rounded-md px-3 py-2">{error}</div>}
          <button className="btn-primary w-full justify-center mt-6" disabled={busy || !username || !password}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
          <p className="text-xs text-ink-faint mt-6 leading-relaxed">Default lab accounts are created from the API environment file (<span className="font-mono">admin</span>, <span className="font-mono">analyst</span>, <span className="font-mono">viewer</span>). Change these before any shared deployment.</p>
        </form>
      </div>
    </div>
  );
}

function TrustDiagram() {
  return (
    <svg viewBox="0 0 420 180" className="w-full mt-8" role="img" aria-label="Decoys sit inside an isolated trust boundary; production is outside it.">
      <defs><marker id="ar" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0l6 3-6 3z" fill="#64748b"/></marker></defs>
      <rect x="4" y="30" width="250" height="120" rx="8" fill="rgba(217,69,95,0.04)" stroke="#d9455f" strokeWidth="1" strokeDasharray="4 4"/>
      <text x="12" y="24" fill="#ec8296" fontSize="10" fontFamily="JetBrains Mono">isolated lab · default-deny egress</text>
      {['SSH', 'Canary', 'Web'].map((t, i) => (
        <g key={t}><rect x={20 + i * 76} y="54" width="64" height="34" rx="6" fill="#141b25" stroke="#263142"/><text x={52 + i * 76} y="75" fill="#9aa7ba" fontSize="11" textAnchor="middle">{t}</text></g>
      ))}
      <rect x="20" y="104" width="216" height="30" rx="6" fill="#0f141c" stroke="#263142"/><text x="128" y="123" fill="#3ea6c4" fontSize="11" textAnchor="middle">collector → detection → alerts</text>
      <line x1="254" y1="90" x2="320" y2="90" stroke="#64748b" strokeWidth="1.2" markerEnd="url(#ar)"/><text x="258" y="83" fill="#64748b" fontSize="9">logs only</text>
      <rect x="322" y="68" width="92" height="44" rx="6" fill="#0a0e14" stroke="#36445a"/><text x="368" y="88" fill="#9aa7ba" fontSize="10" textAnchor="middle">production</text><text x="368" y="102" fill="#64748b" fontSize="9" textAnchor="middle">no route in</text>
    </svg>
  );
}
