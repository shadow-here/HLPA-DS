import React from 'react';

export function SeverityBadge({ severity }) {
  const s = (severity || 'low').toLowerCase();
  return <span className={`chip sev-bg-${s}`}>{s}</span>;
}

const STATUS_STYLE = {
  New: 'bg-accent/15 text-accent',
  Acknowledged: 'bg-base-700 text-ink',
  Investigating: 'bg-sev-medium/15 text-sev-medium',
  'Contained (lab only)': 'bg-sev-high/15 text-sev-high',
  Resolved: 'bg-ok/15 text-ok',
  'False Positive': 'bg-base-700 text-ink-dim',
};
export function StatusBadge({ status }) {
  return <span className={`chip ${STATUS_STYLE[status] || 'bg-base-700 text-ink'}`}>{status}</span>;
}

export function KindBadge({ kind }) {
  const map = { attacker: 'bg-base-700 text-ink-dim', isolation: 'bg-sev-critical/15 text-sev-critical', monitoring: 'bg-base-700 text-accent' };
  return <span className={`chip ${map[kind] || 'bg-base-700 text-ink-dim'}`}>{kind}</span>;
}

export function Dot({ state }) {
  const c = { ok: 'bg-ok', healthy: 'bg-ok', stale: 'bg-warn', degraded: 'bg-warn', pending: 'bg-warn',
    unhealthy: 'bg-bad', down: 'bg-bad', disabled: 'bg-ink-faint', disable_failed: 'bg-bad' }[state] || 'bg-ink-faint';
  const live = state === 'ok' || state === 'healthy';
  return <span className={`inline-block w-2 h-2 rounded-full ${c} ${live ? 'pulse-dot' : ''}`} />;
}

export function Panel({ title, action, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between px-4 sm:px-5 py-3 border-b border-base-700/50">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, tone }) {
  const toneClass = { bad: 'text-bad', warn: 'text-warn', ok: 'text-ok', accent: 'text-accent' }[tone] || 'text-ink';
  return (
    <div className="panel panel-pad">
      <div className="label">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${toneClass}`}>{value}</div>
    </div>
  );
}

export function Empty({ title, hint }) {
  return (
    <div className="text-center py-12 px-4">
      <div className="text-ink-dim font-medium">{title}</div>
      {hint && <div className="text-ink-faint text-sm mt-1">{hint}</div>}
    </div>
  );
}

export function Spinner({ label = 'Loading' }) {
  return <div className="text-ink-faint text-sm py-8 text-center">{label}…</div>;
}

export function ErrorNote({ error }) {
  if (!error) return null;
  return (
    <div className="panel panel-pad border-bad/40 bg-bad/5 text-sm">
      <span className="text-bad font-medium">Error:</span> <span className="text-ink-dim">{error.message || String(error)}</span>
      {error.details && <pre className="mt-2 text-xs text-ink-faint overflow-auto">{JSON.stringify(error.details, null, 2)}</pre>}
    </div>
  );
}

export function fmtTime(v, withSeconds = true) {
  if (!v) return '—';
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', ...(withSeconds ? { second: '2-digit' } : {}) });
}

export function fmtAgo(v) {
  if (!v) return '—';
  const diff = (Date.now() - new Date(v).getTime()) / 1000;
  if (diff < 0) return 'just now';
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function Mono({ children, className = '' }) {
  return <span className={`font-mono text-[13px] ${className}`}>{children}</span>;
}

// Everything the sensors capture is untrusted; React escapes by default, and we
// never use dangerouslySetInnerHTML. This renders raw values as plain text.
export function Raw({ value }) {
  if (value === null || value === undefined || value === '') return <span className="text-ink-faint">—</span>;
  return <span className="font-mono text-[13px] break-all">{String(value)}</span>;
}
