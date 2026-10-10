import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { api } from '../api';
import { useAuth } from '../auth.jsx';
import { Panel, SeverityBadge, StatusBadge, KindBadge, Spinner, ErrorNote, Empty, fmtTime, fmtAgo, Mono, Raw } from '../ui.jsx';

export default function AlertDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const { can } = useAuth();
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');
  const [target, setTarget] = useState('');
  const [actionErr, setActionErr] = useState('');

  const load = useCallback(() => {
    api.get(`/alerts/${id}`).then((a) => { setAlert(a); setError(null); }).catch(setError);
  }, [id]);
  useEffect(() => { load(); }, [load]);

  if (error) return <ErrorNote error={error} />;
  if (!alert) return <Spinner label="Loading alert" />;

  const apply = async () => {
    if (!target && !note.trim()) return;
    setBusy(true); setActionErr('');
    try {
      await api.patch(`/alerts/${id}`, { status: target || undefined, note: note.trim() || undefined });
      setNote(''); setTarget(''); load();
    } catch (e) { setActionErr(e.message + (e.details?.allowed ? ` (allowed: ${e.details.allowed.join(', ')})` : '')); }
    finally { setBusy(false); }
  };

  const ev = alert.matched_evidence || {};

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2 text-sm text-ink-faint">
        <Link to="/alerts" className="link">Alerts</Link><span>/</span><Mono>{alert.alert_id}</Mono>
      </div>

      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-start gap-3">
          <SeverityBadge severity={alert.severity} />
          <div>
            <h1 className="text-xl font-semibold leading-tight">{alert.title}</h1>
            <p className="text-sm text-ink-dim mt-1 max-w-2xl">{alert.summary}</p>
          </div>
        </div>
        <div className="flex items-center gap-2"><KindBadge kind={alert.kind} /><StatusBadge status={alert.status} /></div>
      </div>

      <div className="grid lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-5">
          <Panel title="Why this fired">
            <div className="panel-pad space-y-3 text-sm">
              <div className="flex flex-wrap gap-x-8 gap-y-2">
                <Field label="Rule">{alert.rule ? <><Mono className="text-accent">{alert.rule.id}</Mono> v{alert.rule_version} · {alert.rule.name}</> : <Mono>{alert.rule_id}</Mono>}</Field>
                <Field label="Detection latency">{alert.detection_latency_ms != null ? `${alert.detection_latency_ms} ms` : '—'}</Field>
                <Field label="Events">{alert.event_count}</Field>
              </div>
              <div className="bg-base-850 border border-base-700/60 rounded-md p-3">
                <div className="label mb-1">Matched condition</div>
                <div className="text-ink">{ev.condition || '—'}</div>
                {ev.sample_fields && Object.keys(ev.sample_fields).length > 0 && (
                  <div className="mt-3 space-y-1.5">
                    {Object.entries(ev.sample_fields).map(([k, vals]) => (
                      <div key={k} className="flex gap-2 text-[13px]">
                        <span className="text-ink-faint font-mono w-28 shrink-0">{k}</span>
                        <span className="flex flex-wrap gap-1">{vals.map((v, i) => <span key={i} className="chip bg-base-800 text-ink-dim">{String(v)}</span>)}</span>
                      </div>
                    ))}
                  </div>
                )}
                {ev.indicator_hits && <div className="mt-2 text-sev-high">Indicator match: {ev.indicator_hits.map((h) => `${h.field}=${h.value}`).join(', ')} — a lead, not attribution.</div>}
                {ev.matched_tags?.length > 0 && <div className="mt-2 text-ink-dim">Behaviour tags: {ev.matched_tags.join(', ')}</div>}
              </div>
            </div>
          </Panel>

          <Panel title={`Supporting events (${alert.events?.length || 0})`} action={<Link className="link text-sm" to={`/events?alert_id=${alert.alert_id}`}>Open in explorer →</Link>}>
            <div className="overflow-x-auto max-h-[420px]">
              <table className="w-full">
                <thead className="sticky top-0 bg-base-900"><tr className="border-b border-base-700/50">
                  <th className="th">Time (UTC-local)</th><th className="th">Category</th><th className="th">Source</th><th className="th">Detail</th>
                </tr></thead>
                <tbody>
                  {(alert.events || []).map((e) => (
                    <tr key={e._id} className="border-b border-base-800/60">
                      <td className="td whitespace-nowrap text-ink-dim">{fmtTime(e.event_time)}</td>
                      <td className="td"><Mono className="text-ink-dim">{e.event_category}</Mono></td>
                      <td className="td"><Mono>{e.src_ip || '—'}</Mono></td>
                      <td className="td max-w-md"><Raw value={e.command || e.http_path || e.message} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!alert.events?.length && <Empty title="No supporting events loaded" />}
            </div>
          </Panel>

          <Panel title="Timeline & audit">
            <div className="panel-pad">
              <ol className="relative border-l border-base-700 ml-2 space-y-4">
                {[...(alert.history || [])].reverse().map((h, i) => (
                  <li key={i} className="ml-4">
                    <span className="absolute -left-[5px] w-2.5 h-2.5 rounded-full bg-accent-deep mt-1.5" />
                    <div className="text-sm"><span className="font-medium">{h.action.replace(/_/g, ' ')}</span>
                      {h.from && <span className="text-ink-dim"> · {h.from} → {h.to}</span>}</div>
                    <div className="text-xs text-ink-faint">{h.actor} · {fmtTime(h.at)}</div>
                    {h.note && <div className="text-sm text-ink-dim mt-1 bg-base-850 rounded px-2 py-1">{h.note}</div>}
                  </li>
                ))}
              </ol>
            </div>
          </Panel>
        </div>

        <div className="space-y-5">
          <Panel title="Context">
            <div className="panel-pad space-y-2.5 text-sm">
              <Field label="Source (observed)"><Mono>{alert.src_ip || '—'}</Mono></Field>
              <Field label="Decoy">{alert.decoy ? `${alert.decoy.name}` : alert.decoy_id || '—'}</Field>
              <Field label="Service"><Mono>{alert.service || '—'}</Mono></Field>
              <Field label="First seen">{fmtTime(alert.first_seen)}</Field>
              <Field label="Last seen">{fmtTime(alert.last_seen)} <span className="text-ink-faint">({fmtAgo(alert.last_seen)})</span></Field>
            </div>
          </Panel>

          {can('analyst') ? (
            <Panel title="Investigate">
              <div className="panel-pad space-y-3">
                <label className="text-sm block">
                  <span className="label">Change status</span>
                  <select className="field w-full mt-1" value={target} onChange={(e) => setTarget(e.target.value)}>
                    <option value="">Keep “{alert.status}”</option>
                    {(alert.allowed_transitions || []).map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </label>
                {alert.note_required_for?.includes(target) && <p className="text-xs text-warn">A note is required for this status.</p>}
                <label className="text-sm block">
                  <span className="label">Analyst note</span>
                  <textarea className="field w-full mt-1 h-24 resize-none" value={note} onChange={(e) => setNote(e.target.value)} placeholder="What you found, why this status…" />
                </label>
                {actionErr && <div className="text-sm text-bad">{actionErr}</div>}
                <button className="btn-primary w-full justify-center" disabled={busy || (!target && !note.trim())} onClick={apply}>
                  {busy ? 'Saving…' : 'Apply'}
                </button>
                {alert.allowed_transitions?.length === 0 && <p className="text-xs text-ink-faint">This alert is in a terminal state; add a note or reopen to Investigating.</p>}
              </div>
            </Panel>
          ) : (
            <Panel title="Investigate"><div className="panel-pad text-sm text-ink-faint">Your role is read-only. Analysts and admins can change status and add notes.</div></Panel>
          )}

          {can('admin') && <ResponseGate id={id} srcIp={alert.src_ip} target={target} setTarget={setTarget} />}
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return <div><div className="label">{label}</div><div className="text-ink mt-0.5">{children}</div></div>;
}

// Lab-only response request (FR-15 / 7.4). The adapter is disabled by default,
// so this surfaces the safety gates and reports the refusal honestly.
function ResponseGate({ id, srcIp }) {
  const [msg, setMsg] = useState(null);
  const [open, setOpen] = useState(false);
  const request = async () => {
    setMsg(null);
    try {
      const r = await api.post(`/alerts/${id}/response-request`, { source: srcIp, scope: 'lab-firewall', duration_minutes: 30, reason: 'demo' });
      setMsg({ ok: true, text: `Applied: ${JSON.stringify(r)}` });
    } catch (e) {
      setMsg({ ok: false, text: e.message });
    }
  };
  return (
    <Panel title="Lab-only response">
      <div className="panel-pad text-sm space-y-3">
        <p className="text-ink-dim">Default behaviour is alert-only. A lab block targets only the disposable test firewall, is time-bounded, needs confirmation, and never touches production.</p>
        {!open ? <button className="btn-ghost w-full justify-center" onClick={() => setOpen(true)}>Request lab block…</button> : (
          <div className="space-y-2 bg-base-850 border border-base-700/60 rounded-md p-3">
            <div className="text-xs"><span className="label">Source</span> <Mono>{srcIp || '—'}</Mono> · <span className="label">Scope</span> lab-firewall · <span className="label">Expiry</span> 30 min</div>
            <button className="btn-danger w-full justify-center" onClick={request}>Confirm request</button>
          </div>
        )}
        {msg && <div className={`text-xs rounded px-2 py-1.5 ${msg.ok ? 'text-ok bg-ok/10' : 'text-warn bg-warn/10'}`}>{msg.text}</div>}
      </div>
    </Panel>
  );
}
