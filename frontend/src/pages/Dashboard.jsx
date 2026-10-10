import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePoll } from '../hooks.js';
import { api, qs } from '../api';
import { Panel, Stat, SeverityBadge, StatusBadge, Dot, Spinner, ErrorNote, Empty, fmtAgo, fmtTime, Mono } from '../ui.jsx';

const RANGES = [['1h', '1h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']];

export default function Dashboard() {
  const [range, setRange] = useState('24h');
  const { data, error, loading } = usePoll(`/dashboard${qs({ range })}`, 6000, [range]);
  const nav = useNavigate();

  if (error) return <ErrorNote error={error} />;
  if (loading && !data) return <Spinner label="Loading overview" />;
  const d = data || {};
  const sev = Object.fromEntries((d.open_by_severity || []).map((x) => [x.key, x.count]));
  const openHigh = (sev.high || 0) + (sev.critical || 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold">Overview</h1>
          <p className="text-sm text-ink-dim">Activity across all decoys for the selected window.</p>
        </div>
        <div className="flex items-center gap-1 bg-base-900 border border-base-700/60 rounded-lg p-1">
          {RANGES.map(([k, label]) => (
            <button key={k} onClick={() => setRange(k)} className={`px-3 py-1 rounded-md text-sm font-medium ${range === k ? 'bg-base-700 text-ink' : 'text-ink-dim hover:text-ink'}`}>{label}</button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Events (interactions)" value={fmtN(d.totals?.events)} />
        <Stat label="Open alerts" value={fmtN(d.totals?.open_alerts)} tone={d.totals?.open_alerts ? 'accent' : undefined} />
        <Stat label="High / critical open" value={fmtN(openHigh)} tone={openHigh ? 'bad' : 'ok'} />
        <Stat label="Ingest errors" value={fmtN(d.totals?.ingest_errors)} tone={d.totals?.ingest_errors ? 'warn' : 'ok'} />
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <Panel title="Activity over time" className="lg:col-span-2">
          <div className="panel-pad"><TimeChart series={d.series || []} bucketMs={d.bucket_ms} /></div>
        </Panel>
        <Panel title="Open alerts by severity">
          <div className="panel-pad space-y-3">
            {['critical', 'high', 'medium', 'low'].map((s) => (
              <div key={s} className="flex items-center justify-between">
                <SeverityBadge severity={s} />
                <span className="tabular-nums text-lg font-semibold">{sev[s] || 0}</span>
              </div>
            ))}
            {!d.open_by_severity?.length && <Empty title="No open alerts" hint="Nothing needs triage right now." />}
          </div>
        </Panel>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <Panel title="Decoy fleet" className="lg:col-span-1">
          <div className="divide-y divide-base-700/40">
            {(d.decoys || []).map((dc) => (
              <div key={dc._id} className="px-4 py-3 flex items-center justify-between">
                <div className="min-w-0">
                  <div className="text-sm font-medium truncate">{dc.name || dc._id}</div>
                  <div className="text-xs text-ink-faint">{dc.enabled ? `last event ${fmtAgo(dc.last_event_at)}` : 'disabled'}</div>
                </div>
                <div className="flex items-center gap-2 text-xs text-ink-dim">
                  {dc.isolation && !dc.isolation.all_blocked && <span className="chip sev-bg-critical" title="Egress self-test reached an external host">egress!</span>}
                  <Dot state={dc.enabled ? (dc.health?.status || 'pending') : 'disabled'} />
                  <span>{dc.enabled ? dc.health?.status || 'pending' : 'off'}</span>
                </div>
              </div>
            ))}
            {!d.decoys?.length && <Empty title="No decoys registered" />}
          </div>
        </Panel>

        <Panel title="Top observed sources" className="lg:col-span-1">
          <BarList items={(d.top_sources || []).map((x) => ({ label: x.key, value: x.count }))} onClick={(ip) => nav(`/events${qs({ src_ip: ip, range })}`)} empty="No source activity" />
        </Panel>

        <Panel title="Detection-rule hits" className="lg:col-span-1">
          <BarList items={(d.top_rules || []).map((x) => ({ label: x.key, value: x.count }))} onClick={(rid) => nav(`/alerts${qs({ rule_id: rid })}`)} empty="No alerts in range" />
        </Panel>
      </div>

      <Panel title="Unresolved alerts" action={<button className="link text-sm" onClick={() => nav('/alerts?status=open')}>View all →</button>}>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead><tr className="border-b border-base-700/50">
              <th className="th">Severity</th><th className="th">Title</th><th className="th">Rule</th><th className="th">Source</th><th className="th">Status</th><th className="th">Last seen</th>
            </tr></thead>
            <tbody>
              {(d.unresolved_alerts || []).slice(0, 10).map((a) => (
                <tr key={a._id} className="border-b border-base-800/60 row-hover" onClick={() => nav(`/alerts/${a._id}`)}>
                  <td className="td"><SeverityBadge severity={a.severity} /></td>
                  <td className="td max-w-xs truncate">{a.title}</td>
                  <td className="td"><Mono className="text-accent">{a.rule_id}</Mono></td>
                  <td className="td"><Mono>{a.src_ip || '—'}</Mono></td>
                  <td className="td"><StatusBadge status={a.status} /></td>
                  <td className="td text-ink-dim whitespace-nowrap">{fmtAgo(a.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!d.unresolved_alerts?.length && <Empty title="No unresolved alerts" hint="The queue is clear." />}
        </div>
      </Panel>
      {d.retention?.warning && <div className="text-xs text-warn">{d.retention.warning}</div>}
    </div>
  );
}

function fmtN(n) { return (n ?? 0).toLocaleString(); }

function TimeChart({ series, bucketMs }) {
  if (!series.length) return <Empty title="No activity in this window" />;
  const W = 760, H = 180, pad = { l: 36, r: 10, t: 10, b: 22 };
  const maxE = Math.max(1, ...series.map((s) => s.events));
  const innerW = W - pad.l - pad.r, innerH = H - pad.t - pad.b;
  const n = series.length;
  const bw = innerW / n;
  const x = (i) => pad.l + i * bw;
  const yE = (v) => pad.t + innerH - (v / maxE) * innerH;
  const alertPts = series.map((s, i) => [x(i) + bw / 2, s.alerts]).filter((p) => p[1] > 0);
  const maxA = Math.max(1, ...series.map((s) => s.alerts));
  const yA = (v) => pad.t + innerH - (v / maxA) * innerH;
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" preserveAspectRatio="none" style={{ minHeight: 180 }}>
        {[0, 0.5, 1].map((f) => (
          <g key={f}><line x1={pad.l} x2={W - pad.r} y1={pad.t + innerH * f} y2={pad.t + innerH * f} stroke="#1a2230" />
          <text x={pad.l - 6} y={pad.t + innerH * f + 3} fill="#64748b" fontSize="9" textAnchor="end">{Math.round(maxE * (1 - f))}</text></g>
        ))}
        {series.map((s, i) => (
          <rect key={i} x={x(i) + bw * 0.12} width={Math.max(1, bw * 0.76)} y={yE(s.events)} height={pad.t + innerH - yE(s.events)} fill="#2b7f99" opacity="0.85">
            <title>{`${fmtTime(s.t, false)} · ${s.events} events · ${s.alerts} alerts`}</title>
          </rect>
        ))}
        {alertPts.length > 1 && <polyline fill="none" stroke="#e2743a" strokeWidth="1.5" points={alertPts.map((p) => `${p[0]},${yA(p[1])}`).join(' ')} />}
        {alertPts.map((p, i) => <circle key={i} cx={p[0]} cy={yA(p[1])} r="2.5" fill="#e2743a" />)}
      </svg>
      <div className="flex gap-4 text-xs text-ink-faint mt-1">
        <span className="flex items-center gap-1.5"><span className="w-3 h-2 rounded-sm bg-accent-deep inline-block" /> events</span>
        <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-sev-high inline-block" /> alerts created</span>
      </div>
    </div>
  );
}

function BarList({ items, onClick, empty }) {
  if (!items.length) return <Empty title={empty} />;
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="panel-pad space-y-2">
      {items.slice(0, 8).map((it) => (
        <button key={it.label} onClick={() => onClick && onClick(it.label)} className="w-full group text-left">
          <div className="flex items-center justify-between text-sm mb-1">
            <Mono className="text-ink-dim group-hover:text-accent truncate">{it.label}</Mono>
            <span className="tabular-nums text-ink">{it.value}</span>
          </div>
          <div className="h-1.5 bg-base-800 rounded-full overflow-hidden"><div className="h-full bg-accent-deep group-hover:bg-accent" style={{ width: `${(it.value / max) * 100}%` }} /></div>
        </button>
      ))}
    </div>
  );
}
