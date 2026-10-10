import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api, qs } from '../api';
import { useAuth } from '../auth.jsx';
import { Panel, Spinner, ErrorNote, Empty, fmtTime, Mono, Raw } from '../ui.jsx';
import { Pager } from './Alerts.jsx';

const RANGES = [['1h', '1h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']];

export default function Events() {
  const [sp, setSp] = useSearchParams();
  const { can } = useAuth();
  const [data, setData] = useState(null);
  const [facets, setFacets] = useState({ categories: [], source_types: [], services: [] });
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);

  const filters = {
    range: sp.get('range') ?? '24h', src_ip: sp.get('src_ip') ?? '', decoy_id: sp.get('decoy_id') ?? '',
    source_type: sp.get('source_type') ?? '', event_category: sp.get('event_category') ?? '', service: sp.get('service') ?? '',
    tag: sp.get('tag') ?? '', alert_id: sp.get('alert_id') ?? '', q: sp.get('q') ?? '',
    hide_system: sp.get('hide_system') ?? 'true', page: sp.get('page') ?? '1',
  };

  useEffect(() => { api.get('/events/facets').then(setFacets).catch(() => {}); }, []);
  useEffect(() => {
    let active = true; setLoading(true);
    api.get(`/events${qs(filters)}&limit=50`).then((d) => active && (setData(d), setError(null)))
      .catch((e) => active && setError(e)).finally(() => active && setLoading(false));
    return () => { active = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sp]);

  const update = (patch) => setSp(Object.fromEntries(Object.entries({ ...filters, ...patch, page: patch.page || '1' }).filter(([, v]) => v !== '' && v != null)));
  const openEvent = (id) => api.get(`/events/${id}`).then(setSelected).catch(setError);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div><h1 className="text-xl font-semibold">Event explorer</h1><p className="text-sm text-ink-dim">Every normalized interaction. Times shown in your local zone (stored as UTC).</p></div>
        {can('analyst') && <button className="btn-ghost" onClick={() => api.download(`/exports/events${qs({ ...filters, page: undefined, format: 'csv' })}`)}>Export CSV</button>}
      </div>

      <Panel>
        <div className="panel-pad grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <Sel label="Range" value={filters.range} onChange={(v) => update({ range: v })} options={RANGES.map((r) => r[0])} />
          <Sel label="Source type" value={filters.source_type} onChange={(v) => update({ source_type: v })} options={['', ...facets.source_types]} any />
          <Sel label="Category" value={filters.event_category} onChange={(v) => update({ event_category: v })} options={['', ...facets.categories]} any />
          <Sel label="Service" value={filters.service} onChange={(v) => update({ service: v })} options={['', ...facets.services]} any />
          <label className="text-sm"><span className="label">Source IP</span><input className="field w-full mt-1" value={filters.src_ip} onChange={(e) => update({ src_ip: e.target.value })} placeholder="203.0.113.10" /></label>
          <label className="text-sm"><span className="label">Search</span><input className="field w-full mt-1" value={filters.q} onChange={(e) => update({ q: e.target.value })} placeholder="path / command / user" /></label>
          <label className="text-sm flex items-end gap-2 pb-1"><input type="checkbox" className="accent-accent w-4 h-4" checked={filters.hide_system === 'true'} onChange={(e) => update({ hide_system: e.target.checked ? 'true' : '' })} /><span>Hide heartbeat / system</span></label>
          {(filters.alert_id || filters.tag) && <div className="flex items-end"><button className="btn-ghost !py-1.5" onClick={() => update({ alert_id: '', tag: '' })}>Clear alert/tag filter</button></div>}
        </div>
      </Panel>

      {error && <ErrorNote error={error} />}
      <Panel>
        {loading && !data ? <Spinner label="Loading events" /> : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-base-700/50">
                <th className="th">Time</th><th className="th">Source type</th><th className="th">Category</th><th className="th">Src IP</th><th className="th">Decoy</th><th className="th">Detail</th><th className="th"></th>
              </tr></thead>
              <tbody>
                {(data?.items || []).map((e) => (
                  <tr key={e._id} className="border-b border-base-800/60 row-hover" onClick={() => openEvent(e._id)}>
                    <td className="td whitespace-nowrap text-ink-dim">{fmtTime(e.event_time)}</td>
                    <td className="td"><Mono className="text-ink-dim">{e.source_type}</Mono></td>
                    <td className="td"><Mono className="text-ink-dim">{e.event_category}</Mono></td>
                    <td className="td"><Mono>{e.src_ip || '—'}</Mono>{e.approved_source && <span className="chip bg-base-800 text-ok ml-1">test</span>}</td>
                    <td className="td text-ink-dim">{e.decoy_id || '—'}</td>
                    <td className="td max-w-md"><Raw value={e.command || e.http_path || e.message} /></td>
                    <td className="td text-ink-faint">{(e.tags || []).filter((t) => t.startsWith('cmd:') || t.startsWith('web:')).slice(0, 2).map((t) => <span key={t} className="chip bg-base-800 text-ink-dim mr-1">{t}</span>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data?.items?.length && <Empty title="No events match these filters" />}
          </div>
        )}
        {data && data.total > data.limit && <Pager page={data.page} total={data.total} limit={data.limit} onPage={(p) => update({ page: String(p) })} />}
      </Panel>

      {selected && <EventDrawer event={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function Sel({ label, value, onChange, options, any }) {
  return <label className="text-sm"><span className="label">{label}</span>
    <select className="field w-full mt-1" value={value} onChange={(e) => onChange(e.target.value)}>
      {options.map((o) => <option key={o} value={o}>{o === '' ? (any ? 'All' : o) : o}</option>)}
    </select></label>;
}

function EventDrawer({ event, onClose }) {
  const e = event;
  return (
    <div className="fixed inset-0 z-30 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative w-full max-w-lg bg-base-900 border-l border-base-700 h-full overflow-y-auto">
        <div className="sticky top-0 bg-base-900 border-b border-base-700/60 px-5 py-3 flex items-center justify-between">
          <h3 className="font-semibold text-sm">Event detail</h3>
          <button className="btn-ghost !py-1 !px-2 text-xs" onClick={onClose}>Close</button>
        </div>
        <div className="p-5 space-y-4 text-sm">
          <div className="grid grid-cols-2 gap-x-4 gap-y-2">
            {[['Event time', fmtTime(e.event_time)], ['Ingested', fmtTime(e.ingested_at)], ['Source type', e.source_type], ['Sensor', e.sensor_id],
              ['Decoy', e.decoy_id], ['Category', e.event_category], ['Service', e.service], ['Outcome', e.outcome],
              ['Src', `${e.src_ip || '—'}:${e.src_port || ''}`], ['Dst', `${e.dst_ip || '—'}:${e.dst_port || ''}`],
              ['Username', e.username], ['Credential', e.credential_fp ? `fp:${e.credential_fp}` : '—'], ['Session', e.session_id], ['Parser', e.parser_status]].map(([k, v]) => (
              <div key={k}><div className="label">{k}</div><div className="mt-0.5"><Raw value={v} /></div></div>
            ))}
          </div>
          {e.message && <div><div className="label">Message</div><div className="mt-0.5"><Raw value={e.message} /></div></div>}
          {e.command && <div><div className="label">Command (emulated shell)</div><pre className="mt-1 bg-base-950 border border-base-700/60 rounded p-2 text-[12px] whitespace-pre-wrap break-all">{e.command}</pre></div>}
          {(e.tags || []).length > 0 && <div><div className="label">Tags</div><div className="mt-1 flex flex-wrap gap-1">{e.tags.map((t) => <span key={t} className="chip bg-base-800 text-ink-dim">{t}</span>)}</div></div>}
          {(e.alert_ids || []).length > 0 && <div><div className="label">Alerts</div><div className="mt-1 flex flex-wrap gap-1">{e.alert_ids.map((a) => <a key={a} href={`/alerts/${a}`} className="chip bg-accent/15 text-accent">{a}</a>)}</div></div>}
          <div>
            <div className="label">Raw record {e.raw_visible ? '(sanitized)' : '(restricted to analysts)'}</div>
            {e.raw ? <pre className="mt-1 bg-base-950 border border-base-700/60 rounded p-2 text-[11px] overflow-auto max-h-64">{JSON.stringify(e.raw.record, null, 2)}</pre>
              : <div className="text-ink-faint mt-1">Raw record not shown for your role.</div>}
            <p className="text-[11px] text-ink-faint mt-1">Secret-like fields are stored only as keyed fingerprints — never as plaintext.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
