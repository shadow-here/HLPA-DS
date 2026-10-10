import React, { useState, useEffect } from 'react';
import { api, qs } from '../api';
import { useAuth } from '../auth.jsx';
import { usePoll } from '../hooks.js';
import { Panel, Spinner, ErrorNote, Empty, fmtTime, fmtAgo, Mono, Dot, SeverityBadge } from '../ui.jsx';

const TABS = [
  { id: 'rules', label: 'Detection rules' },
  { id: 'sources', label: 'Approved sources' },
  { id: 'indicators', label: 'Indicators' },
  { id: 'retention', label: 'Retention' },
  { id: 'users', label: 'Users', admin: true },
  { id: 'audit', label: 'Audit log', admin: true },
  { id: 'system', label: 'System status' },
];

export default function Admin() {
  const { can } = useAuth();
  const [tab, setTab] = useState('rules');
  const tabs = TABS.filter((t) => !t.admin || can('admin'));
  return (
    <div className="space-y-5">
      <div><h1 className="text-xl font-semibold">Administration</h1><p className="text-sm text-ink-dim">Tune detection, manage access, and inspect system health. Configuration changes are audit-logged.</p></div>
      <div className="flex gap-1 border-b border-base-700/60 overflow-x-auto">
        {tabs.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)} className={`px-3 py-2 text-sm font-medium whitespace-nowrap border-b-2 -mb-px ${tab === t.id ? 'border-accent text-ink' : 'border-transparent text-ink-dim hover:text-ink'}`}>{t.label}</button>
        ))}
      </div>
      {tab === 'rules' && <Rules canEdit={can('admin')} />}
      {tab === 'sources' && <ApprovedSources canEdit={can('admin')} />}
      {tab === 'indicators' && <Indicators canEdit={can('admin')} />}
      {tab === 'retention' && <Retention canEdit={can('admin')} />}
      {tab === 'users' && can('admin') && <Users />}
      {tab === 'audit' && can('admin') && <Audit />}
      {tab === 'system' && <SystemStatus />}
    </div>
  );
}

function useList(path) {
  const [data, setData] = useState(null); const [error, setError] = useState(null);
  const reload = () => api.get(path).then((d) => { setData(d); setError(null); }).catch(setError);
  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [path]);
  return { data, error, reload };
}

function Rules({ canEdit }) {
  const { data, error, reload } = useList('/rules');
  const [msg, setMsg] = useState('');
  if (error) return <ErrorNote error={error} />;
  if (!data) return <Spinner />;
  const patch = async (id, body) => { setMsg(''); try { await api.patch(`/rules/${id}`, body); reload(); } catch (e) { setMsg(e.message); } };
  return (
    <Panel title={`Detection catalogue (${data.rules.length})`}>
      {msg && <div className="px-4 pt-3 text-sm text-bad">{msg}</div>}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead><tr className="border-b border-base-700/50"><th className="th">ID</th><th className="th">Rule</th><th className="th">Type</th><th className="th">Severity</th><th className="th">Threshold</th><th className="th">Window</th><th className="th">Enabled</th></tr></thead>
          <tbody>
            {data.rules.map((r) => (
              <tr key={r._id} className="border-b border-base-800/60">
                <td className="td"><Mono className="text-accent">{r._id}</Mono><div className="text-[11px] text-ink-faint">v{r.version}</div></td>
                <td className="td max-w-xs"><div className="font-medium">{r.name}</div><div className="text-xs text-ink-faint">{r.description}</div></td>
                <td className="td"><Mono className="text-ink-dim">{r.type}</Mono> <span className="text-ink-faint text-xs">{r.kind}</span></td>
                <td className="td">{canEdit && r.type !== 'ioc' ? (
                  <select className="field !py-1 text-xs" value={r.severity} onChange={(e) => patch(r._id, { severity: e.target.value })}>{['low', 'medium', 'high', 'critical'].map((s) => <option key={s}>{s}</option>)}</select>
                ) : <SeverityBadge severity={r.severity} />}</td>
                <td className="td">{['threshold', 'distinct'].includes(r.type) ? (canEdit ? <NumEdit value={r.threshold} onSave={(v) => patch(r._id, { threshold: v })} /> : r.threshold) : '—'}</td>
                <td className="td">{['threshold', 'distinct'].includes(r.type) ? (canEdit ? <NumEdit value={r.window_seconds} onSave={(v) => patch(r._id, { window_seconds: v })} suffix="s" /> : `${r.window_seconds}s`) : '—'}</td>
                <td className="td">{canEdit ? <Toggle on={r.enabled} onChange={(v) => patch(r._id, { enabled: v })} /> : (r.enabled ? 'yes' : 'no')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function NumEdit({ value, onSave, suffix = '' }) {
  const [v, setV] = useState(value);
  useEffect(() => setV(value), [value]);
  return <span className="inline-flex items-center gap-1">
    <input className="field !py-1 !px-2 w-16 text-xs" type="number" value={v} onChange={(e) => setV(e.target.value)} />
    {Number(v) !== value && <button className="text-xs link" onClick={() => onSave(Number(v))}>save{suffix ? '' : ''}</button>}
  </span>;
}

function Toggle({ on, onChange }) {
  return <button onClick={() => onChange(!on)} className={`w-10 h-5 rounded-full transition-colors relative ${on ? 'bg-accent' : 'bg-base-700'}`}>
    <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${on ? 'left-5' : 'left-0.5'}`} /></button>;
}

function ApprovedSources({ canEdit }) {
  const { data, error, reload } = useList('/approved-sources');
  const [ip, setIp] = useState(''); const [reason, setReason] = useState(''); const [hours, setHours] = useState(24); const [msg, setMsg] = useState('');
  if (error) return <ErrorNote error={error} />;
  const add = async () => { setMsg(''); try { await api.post('/approved-sources', { ip, reason, expires_in_hours: Number(hours) }); setIp(''); setReason(''); reload(); } catch (e) { setMsg(e.message); } };
  return (
    <div className="space-y-4">
      <p className="text-sm text-ink-dim">Approved test sources are excluded from attacker rules so lab traffic does not create noise. Exclusions stay visible and expire automatically.</p>
      {canEdit && (
        <Panel title="Add approved source"><div className="panel-pad flex flex-wrap items-end gap-3">
          <label className="text-sm"><span className="label">IP</span><input className="field w-40 mt-1" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.200" /></label>
          <label className="text-sm flex-1 min-w-48"><span className="label">Reason (required)</span><input className="field w-full mt-1" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Lab test client" /></label>
          <label className="text-sm"><span className="label">Expires (h)</span><input className="field w-24 mt-1" type="number" value={hours} onChange={(e) => setHours(e.target.value)} /></label>
          <button className="btn-primary" disabled={!ip || !reason} onClick={add}>Add</button>
        </div>{msg && <div className="px-4 pb-3 text-sm text-bad">{msg}</div>}</Panel>
      )}
      <Panel title={`Approved sources (${data?.length || 0})`}>
        <Table rows={data} cols={['ip', 'reason', 'created_by', 'expires_at']} render={{ ip: (v) => <Mono>{v}</Mono>, expires_at: (v) => fmtTime(v) }}
          actions={canEdit ? (r) => <button className="link text-xs" onClick={() => api.del(`/approved-sources/${encodeURIComponent(r.ip)}`).then(reload)}>Remove</button> : null} empty="No approved sources" />
      </Panel>
    </div>
  );
}

function Indicators({ canEdit }) {
  const { data, error, reload } = useList('/indicators');
  const [value, setValue] = useState(''); const [type, setType] = useState('ip'); const [label, setLabel] = useState(''); const [msg, setMsg] = useState('');
  if (error) return <ErrorNote error={error} />;
  const add = async () => { setMsg(''); try { await api.post('/indicators', { value, type, label }); setValue(''); setLabel(''); reload(); } catch (e) { setMsg(e.message); } };
  return (
    <div className="space-y-4">
      <p className="text-sm text-ink-dim">Local indicator list for DET-07. A match is a lead for investigation, never attribution.</p>
      {canEdit && <Panel title="Add indicator"><div className="panel-pad flex flex-wrap items-end gap-3">
        <label className="text-sm"><span className="label">Type</span><select className="field mt-1" value={type} onChange={(e) => setType(e.target.value)}><option value="ip">ip</option><option value="sha256">sha256</option></select></label>
        <label className="text-sm flex-1 min-w-48"><span className="label">Value</span><input className="field w-full mt-1" value={value} onChange={(e) => setValue(e.target.value)} /></label>
        <label className="text-sm flex-1 min-w-32"><span className="label">Label</span><input className="field w-full mt-1" value={label} onChange={(e) => setLabel(e.target.value)} /></label>
        <button className="btn-primary" disabled={!value} onClick={add}>Add</button>
      </div>{msg && <div className="px-4 pb-3 text-sm text-bad">{msg}</div>}</Panel>}
      <Panel title={`Indicators (${data?.length || 0})`}>
        <Table rows={data} cols={['value', 'type', 'label', 'created_by']} render={{ value: (v) => <Mono>{v}</Mono> }}
          actions={canEdit ? (r) => <button className="link text-xs" onClick={() => api.del(`/indicators/${encodeURIComponent(r.value)}`).then(reload)}>Remove</button> : null} empty="No indicators" />
      </Panel>
    </div>
  );
}

function Retention({ canEdit }) {
  const { data, error, reload } = useList('/settings/retention');
  const [ev, setEv] = useState(''); const [al, setAl] = useState(''); const [msg, setMsg] = useState('');
  useEffect(() => { if (data) { setEv(data.events_days); setAl(data.alerts_days); } }, [data]);
  if (error) return <ErrorNote error={error} />;
  const save = async () => { setMsg(''); try { await api.put('/settings/retention', { events_days: Number(ev), alerts_days: Number(al) }); setMsg('Saved'); reload(); } catch (e) { setMsg(e.message); } };
  return (
    <Panel title="Data retention"><div className="panel-pad space-y-3 max-w-md text-sm">
      <p className="text-ink-dim">Normalized events and raw records are deleted after the event window; closed alerts and audit records after the alert window. The collector applies this hourly.</p>
      <label className="block"><span className="label">Events & raw records (days)</span><input className="field w-full mt-1" type="number" value={ev} onChange={(e) => setEv(e.target.value)} disabled={!canEdit} /></label>
      <label className="block"><span className="label">Alerts & audit (days)</span><input className="field w-full mt-1" type="number" value={al} onChange={(e) => setAl(e.target.value)} disabled={!canEdit} /></label>
      {canEdit && <button className="btn-primary" onClick={save}>Save retention policy</button>}
      {msg && <div className="text-sm text-ink-dim">{msg}</div>}
    </div></Panel>
  );
}

function Users() {
  const { data, error, reload } = useList('/users');
  const [form, setForm] = useState({ username: '', password: '', role: 'viewer' }); const [msg, setMsg] = useState('');
  if (error) return <ErrorNote error={error} />;
  const add = async () => { setMsg(''); try { await api.post('/users', form); setForm({ username: '', password: '', role: 'viewer' }); reload(); } catch (e) { setMsg(e.message); } };
  const patch = async (u, body) => { setMsg(''); try { await api.patch(`/users/${u}`, body); reload(); } catch (e) { setMsg(e.message); } };
  return (
    <div className="space-y-4">
      <Panel title="Add user"><div className="panel-pad flex flex-wrap items-end gap-3">
        <label className="text-sm"><span className="label">Username</span><input className="field w-40 mt-1" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
        <label className="text-sm"><span className="label">Password (≥10)</span><input className="field w-48 mt-1" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
        <label className="text-sm"><span className="label">Role</span><select className="field mt-1" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{['viewer', 'analyst', 'admin'].map((r) => <option key={r}>{r}</option>)}</select></label>
        <button className="btn-primary" disabled={!form.username || !form.password} onClick={add}>Create</button>
      </div>{msg && <div className="px-4 pb-3 text-sm text-bad">{msg}</div>}</Panel>
      <Panel title={`Users (${data?.length || 0})`}>
        <div className="overflow-x-auto"><table className="w-full">
          <thead><tr className="border-b border-base-700/50"><th className="th">Username</th><th className="th">Role</th><th className="th">Status</th><th className="th">Last login</th><th className="th"></th></tr></thead>
          <tbody>{(data || []).map((u) => (
            <tr key={u.username} className="border-b border-base-800/60">
              <td className="td font-medium">{u.username}</td>
              <td className="td"><select className="field !py-1 text-xs" value={u.role} onChange={(e) => patch(u.username, { role: e.target.value })}>{['viewer', 'analyst', 'admin'].map((r) => <option key={r}>{r}</option>)}</select></td>
              <td className="td">{u.disabled ? <span className="text-bad">disabled</span> : <span className="text-ok">active</span>}</td>
              <td className="td text-ink-dim">{u.last_login_at ? fmtAgo(u.last_login_at) : 'never'}</td>
              <td className="td"><button className="link text-xs" onClick={() => patch(u.username, { disabled: !u.disabled })}>{u.disabled ? 'Enable' : 'Disable'}</button></td>
            </tr>
          ))}</tbody>
        </table></div>
      </Panel>
    </div>
  );
}

function Audit() {
  const [sp, setSp] = useState({ action: '', outcome: '', page: 1 });
  const { data, error } = useList(`/audit${qs({ action: sp.action, outcome: sp.outcome, page: sp.page })}&limit=50`);
  if (error) return <ErrorNote error={error} />;
  return (
    <Panel title="Audit log" action={<div className="flex gap-2">
      <input className="field !py-1 text-xs w-32" placeholder="action" value={sp.action} onChange={(e) => setSp({ ...sp, action: e.target.value, page: 1 })} />
      <input className="field !py-1 text-xs w-28" placeholder="outcome" value={sp.outcome} onChange={(e) => setSp({ ...sp, outcome: e.target.value, page: 1 })} />
    </div>}>
      <div className="overflow-x-auto"><table className="w-full">
        <thead><tr className="border-b border-base-700/50"><th className="th">Time</th><th className="th">Actor</th><th className="th">Action</th><th className="th">Target</th><th className="th">Outcome</th><th className="th">Reason</th></tr></thead>
        <tbody>{(data?.items || []).map((a, i) => (
          <tr key={i} className="border-b border-base-800/60">
            <td className="td whitespace-nowrap text-ink-dim">{fmtTime(a.at)}</td>
            <td className="td">{a.actor} <span className="text-ink-faint text-xs">{a.role}</span></td>
            <td className="td"><Mono className="text-ink-dim">{a.action}</Mono></td>
            <td className="td"><Mono className="text-ink-faint">{a.target || '—'}</Mono></td>
            <td className="td"><span className={a.outcome === 'success' ? 'text-ok' : a.outcome === 'denied' || a.outcome === 'failure' ? 'text-bad' : 'text-ink-dim'}>{a.outcome}</span></td>
            <td className="td text-ink-dim max-w-xs truncate">{a.reason || '—'}</td>
          </tr>
        ))}</tbody>
      </table>{!data?.items?.length && <Empty title="No audit records" />}</div>
    </Panel>
  );
}

function SystemStatus() {
  const { data, error } = usePoll('/system/status', 5000);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <Spinner />;
  const c = data.collector || {};
  return (
    <div className="grid lg:grid-cols-2 gap-5">
      <Panel title="Collector / detection worker">
        <div className="panel-pad space-y-2 text-sm">
          <Row k="Status"><span className="inline-flex items-center gap-1.5"><Dot state={c.status} />{c.status}</span></Row>
          <Row k="Heartbeat">{c.heartbeat_at ? `${fmtAgo(c.heartbeat_at)} (${c.heartbeat_age_s}s)` : 'never'}</Row>
          <Row k="Last event">{c.last_event_at ? fmtAgo(c.last_event_at) : '—'}</Row>
          <Row k="Rules loaded">{c.rules_loaded ?? '—'}</Row>
          <Row k="Indicators">{c.indicators_loaded ?? '—'}</Row>
          {c.stats && <>
            <Row k="Events ingested">{c.stats.events_ingested?.toLocaleString()}</Row>
            <Row k="Parse errors">{c.stats.parse_errors}</Row>
            <Row k="Duplicates skipped">{c.stats.duplicates}</Row>
          </>}
        </div>
      </Panel>
      <Panel title="Sources & storage">
        <div className="panel-pad space-y-2 text-sm">
          {c.sources && Object.entries(c.sources).map(([name, s]) => (
            <Row key={name} k={name}><span className="inline-flex items-center gap-1.5"><Dot state={s.state === 'ok' ? 'ok' : 'warn'} />{s.state}</span></Row>
          ))}
          <div className="border-t border-base-700/50 my-2" />
          {data.storage?.collections && Object.entries(data.storage.collections).map(([col, n]) => <Row key={col} k={col}>{n.toLocaleString()}</Row>)}
          <Row k="Ingest errors (1h)"><span className={data.ingest_errors_last_hour ? 'text-warn' : 'text-ok'}>{data.ingest_errors_last_hour}</span></Row>
        </div>
      </Panel>
      <Panel title="Decoy controller" className="lg:col-span-2">
        <div className="panel-pad text-sm">
          {data.controller?.reachable ? (
            <div className="flex flex-wrap gap-2">{Object.entries(data.controller.containers || {}).map(([name, st]) => (
              <span key={name} className="chip bg-base-800 text-ink-dim"><Dot state={st.state === 'running' ? 'ok' : 'disabled'} /> {name}: {st.state}</span>
            ))}</div>
          ) : <div className="text-ink-faint">Not reachable — {data.controller?.error}. The platform runs alert-first; this only affects start/stop of decoy containers.</div>}
        </div>
      </Panel>
    </div>
  );
}

function Row({ k, children }) { return <div className="flex items-center justify-between"><span className="text-ink-faint">{k}</span><span className="text-ink">{children}</span></div>; }

function Table({ rows, cols, render = {}, actions, empty }) {
  if (!rows) return <Spinner />;
  if (!rows.length) return <Empty title={empty} />;
  return (
    <div className="overflow-x-auto"><table className="w-full">
      <thead><tr className="border-b border-base-700/50">{cols.map((c) => <th key={c} className="th">{c.replace(/_/g, ' ')}</th>)}{actions && <th className="th"></th>}</tr></thead>
      <tbody>{rows.map((r, i) => (
        <tr key={i} className="border-b border-base-800/60">
          {cols.map((c) => <td key={c} className="td">{render[c] ? render[c](r[c]) : (r[c] ?? '—')}</td>)}
          {actions && <td className="td text-right">{actions(r)}</td>}
        </tr>
      ))}</tbody>
    </table></div>
  );
}
