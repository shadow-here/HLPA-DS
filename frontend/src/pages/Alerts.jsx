import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api, qs } from '../api';
import { useAuth } from '../auth.jsx';
import { Panel, SeverityBadge, StatusBadge, KindBadge, Spinner, ErrorNote, Empty, fmtAgo, Mono } from '../ui.jsx';

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];
const STATUSES = ['open', '', 'New', 'Acknowledged', 'Investigating', 'Contained (lab only)', 'Resolved', 'False Positive'];

export default function Alerts() {
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const { can } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const filters = {
    status: sp.get('status') ?? 'open',
    severity: sp.get('severity') ?? '',
    rule_id: sp.get('rule_id') ?? '',
    src_ip: sp.get('src_ip') ?? '',
    q: sp.get('q') ?? '',
    page: sp.get('page') ?? '1',
  };

  useEffect(() => {
    let active = true;
    setLoading(true);
    api.get(`/alerts${qs(filters)}&limit=50`).then((d) => { if (active) { setData(d); setError(null); } })
      .catch((e) => active && setError(e)).finally(() => active && setLoading(false));
    return () => { active = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sp]);

  const update = (patch) => {
    const next = { ...filters, ...patch, page: patch.page || '1' };
    setSp(Object.fromEntries(Object.entries(next).filter(([, v]) => v !== '')));
  };

  const exportUrl = `/exports/alerts${qs({ ...filters, page: undefined, format: 'csv', range: '30d' })}`;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div><h1 className="text-xl font-semibold">Alerts</h1><p className="text-sm text-ink-dim">Grouped, deduplicated detections. Click one to investigate its evidence.</p></div>
        {can('analyst') && <button className="btn-ghost" onClick={() => api.download(exportUrl)}>Export CSV</button>}
      </div>

      <Panel>
        <div className="panel-pad grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <Select label="Status" value={filters.status} onChange={(v) => update({ status: v })} options={STATUSES} render={(s) => (s === '' ? 'All' : s === 'open' ? 'Open (active)' : s)} />
          <Select label="Severity" value={filters.severity} onChange={(v) => update({ severity: v })} options={SEVERITIES} render={(s) => (s === '' ? 'All' : s)} />
          <label className="text-sm"><span className="label">Rule</span><input className="field w-full mt-1" placeholder="DET-01" value={filters.rule_id} onChange={(e) => update({ rule_id: e.target.value })} /></label>
          <label className="text-sm"><span className="label">Source IP</span><input className="field w-full mt-1" placeholder="203.0.113.10" value={filters.src_ip} onChange={(e) => update({ src_ip: e.target.value })} /></label>
          <label className="text-sm"><span className="label">Search</span><input className="field w-full mt-1" placeholder="title / id" value={filters.q} onChange={(e) => update({ q: e.target.value })} /></label>
        </div>
      </Panel>

      {error && <ErrorNote error={error} />}
      <Panel>
        {loading && !data ? <Spinner label="Loading alerts" /> : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-base-700/50">
                <th className="th">Severity</th><th className="th">Title</th><th className="th">Rule</th><th className="th">Kind</th><th className="th">Source</th><th className="th">Events</th><th className="th">Status</th><th className="th">Last seen</th>
              </tr></thead>
              <tbody>
                {(data?.items || []).map((a) => (
                  <tr key={a._id} className="border-b border-base-800/60 row-hover" onClick={() => nav(`/alerts/${a._id}`)}>
                    <td className="td"><SeverityBadge severity={a.severity} /></td>
                    <td className="td max-w-sm"><div className="truncate font-medium">{a.title}</div><Mono className="text-ink-faint text-[11px]">{a.alert_id}</Mono></td>
                    <td className="td"><Mono className="text-accent">{a.rule_id}</Mono></td>
                    <td className="td"><KindBadge kind={a.kind} /></td>
                    <td className="td"><Mono>{a.src_ip || '—'}</Mono></td>
                    <td className="td tabular-nums">{a.event_count}</td>
                    <td className="td"><StatusBadge status={a.status} /></td>
                    <td className="td text-ink-dim whitespace-nowrap">{fmtAgo(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data?.items?.length && <Empty title="No alerts match these filters" hint="Try widening the status to All." />}
          </div>
        )}
        {data && data.total > data.limit && (
          <Pager page={data.page} total={data.total} limit={data.limit} onPage={(p) => update({ page: String(p) })} />
        )}
      </Panel>
    </div>
  );
}

function Select({ label, value, onChange, options, render }) {
  return (
    <label className="text-sm"><span className="label">{label}</span>
      <select className="field w-full mt-1" value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => <option key={o} value={o}>{render ? render(o) : o}</option>)}
      </select>
    </label>
  );
}

export function Pager({ page, total, limit, onPage }) {
  const pages = Math.ceil(total / limit);
  page = Number(page);
  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-base-700/50 text-sm">
      <span className="text-ink-faint">{total.toLocaleString()} total · page {page} of {pages}</span>
      <div className="flex gap-2">
        <button className="btn-ghost !py-1.5" disabled={page <= 1} onClick={() => onPage(page - 1)}>Prev</button>
        <button className="btn-ghost !py-1.5" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  );
}
