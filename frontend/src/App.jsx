import React from 'react';
import { Routes, Route, NavLink, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './auth.jsx';
import { Dot } from './ui.jsx';
import { usePoll } from './hooks.js';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Alerts from './pages/Alerts.jsx';
import AlertDetail from './pages/AlertDetail.jsx';
import Events from './pages/Events.jsx';
import Decoys from './pages/Decoys.jsx';
import Admin from './pages/Admin.jsx';

const NAV = [
  { to: '/', label: 'Overview', end: true },
  { to: '/alerts', label: 'Alerts' },
  { to: '/events', label: 'Events' },
  { to: '/decoys', label: 'Decoys' },
  { to: '/admin', label: 'Administration' },
];

function HealthPill() {
  const { data } = usePoll('/system/status', 7000);
  const c = data && data.collector ? data.collector.status : 'unknown';
  const ctrl = data && data.controller;
  return (
    <div className="flex items-center gap-4 text-xs text-ink-dim">
      <span className="flex items-center gap-1.5" title={`Collector ${c}`}><Dot state={c} /> collector</span>
      <span className="flex items-center gap-1.5" title={ctrl && ctrl.reachable ? 'Decoy controller reachable' : 'Decoy controller not reachable'}>
        <Dot state={ctrl && ctrl.reachable ? 'ok' : 'disabled'} /> controller
      </span>
    </div>
  );
}

function Shell({ children }) {
  const { user, logout } = useAuth();
  return (
    <div className="min-h-full flex flex-col">
      <header className="sticky top-0 z-20 bg-base-950/90 backdrop-blur border-b border-base-700/60">
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6 h-14 flex items-center gap-6">
          <div className="flex items-center gap-2.5 shrink-0">
            <ShieldMark />
            <div className="leading-tight">
              <div className="font-semibold text-sm tracking-tight">HLPA-DS</div>
              <div className="text-[10px] text-ink-faint -mt-0.5">Deception Console</div>
            </div>
          </div>
          <nav className="hidden md:flex items-center gap-1 flex-1">
            {NAV.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.end}
                className={({ isActive }) => `px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${isActive ? 'bg-base-800 text-ink' : 'text-ink-dim hover:text-ink hover:bg-base-900'}`}>
                {n.label}
              </NavLink>
            ))}
          </nav>
          <div className="flex items-center gap-4 ml-auto">
            <HealthPill />
            <div className="h-5 w-px bg-base-700" />
            <div className="text-right leading-tight">
              <div className="text-xs font-medium">{user.username}</div>
              <div className="text-[10px] text-ink-faint uppercase tracking-wide">{user.role}</div>
            </div>
            <button onClick={logout} className="btn-ghost !px-2.5 !py-1.5 text-xs">Sign out</button>
          </div>
        </div>
        <nav className="md:hidden flex items-center gap-1 px-4 pb-2 overflow-x-auto">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}
              className={({ isActive }) => `px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap ${isActive ? 'bg-base-800 text-ink' : 'text-ink-dim'}`}>
              {n.label}
            </NavLink>
          ))}
        </nav>
      </header>
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-4 sm:px-6 py-6">{children}</main>
      <footer className="border-t border-base-700/40 py-3 text-center text-[11px] text-ink-faint">
        HLPA-DS 1.0 · Academic project · Alert-first; source observations are not attribution · Synthetic lab data
      </footer>
    </div>
  );
}

function ShieldMark() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2.5 4.5 5.2v6.1c0 4.6 3.1 8.1 7.5 9.7 4.4-1.6 7.5-5.1 7.5-9.7V5.2L12 2.5Z" stroke="#3ea6c4" strokeWidth="1.4" fill="rgba(62,166,196,0.08)" />
      <circle cx="12" cy="11" r="2.1" fill="#3ea6c4" />
      <path d="M12 13.1V17" stroke="#3ea6c4" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

function RequireAuth({ children }) {
  const { user, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <div className="min-h-full grid place-items-center text-ink-faint">Loading…</div>;
  if (!user) return <Navigate to="/login" replace state={{ from: loc }} />;
  return <Shell>{children}</Shell>;
}

function Gate() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<RequireAuth><Dashboard /></RequireAuth>} />
      <Route path="/alerts" element={<RequireAuth><Alerts /></RequireAuth>} />
      <Route path="/alerts/:id" element={<RequireAuth><AlertDetail /></RequireAuth>} />
      <Route path="/events" element={<RequireAuth><Events /></RequireAuth>} />
      <Route path="/decoys" element={<RequireAuth><Decoys /></RequireAuth>} />
      <Route path="/admin" element={<RequireAuth><Admin /></RequireAuth>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return <AuthProvider><Gate /></AuthProvider>;
}
