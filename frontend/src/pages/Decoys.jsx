import React, { useState } from 'react';
import { api } from '../api';
import { useAuth } from '../auth.jsx';
import { usePoll } from '../hooks.js';
import { Panel, Dot, Spinner, ErrorNote, Empty, fmtAgo, fmtTime, Mono } from '../ui.jsx';

export default function Decoys() {
  const { can } = useAuth();
  const { data, error, loading, reload } = usePoll('/decoys', 7000);
  const [checklistFor, setChecklistFor] = useState(null);
  const [banner, setBanner] = useState(null);

  if (error) return <ErrorNote error={error} />;
  if (loading && !data) return <Spinner label="Loading decoys" />;
  const decoys = data?.decoys || [];
  const checklist = data?.checklist || [];

  const act = async (id, body) => {
    setBanner(null);
    try { const r = await api.patch(`/decoys/${id}/status`, body); setBanner({ ok: true, text: r.message || 'Done' }); reload(); }
    catch (e) { setBanner({ ok: false, text: e.message + (e.details?.missing ? ` (missing: ${e.details.missing.join(', ')})` : '') }); }
  };

  const emergencyStop = async () => {
    if (!window.confirm('Stop ALL decoy containers now? This is the kill switch.')) return;
    setBanner(null);
    try { await api.post('/decoys/actions/emergency-stop', { reason: 'operator kill switch' }); setBanner({ ok: true, text: 'Emergency stop issued to all decoys.' }); reload(); }
    catch (e) { setBanner({ ok: false, text: e.message }); }
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div><h1 className="text-xl font-semibold">Decoy inventory</h1><p className="text-sm text-ink-dim">Lab network <Mono>{data?.lab_cidr}</Mono>. Decoys must pass the isolation checklist before they are enabled.</p></div>
        {can('admin') && <button className="btn-danger" onClick={emergencyStop}>Emergency stop all</button>}
      </div>

      {!data?.controller?.reachable && <div className="text-xs text-warn bg-warn/10 border border-warn/30 rounded-md px-3 py-2">Decoy controller not reachable — enable/disable will not start or stop containers. {data?.controller?.error}</div>}
      {banner && <div className={`text-sm rounded-md px-3 py-2 ${banner.ok ? 'text-ok bg-ok/10 border border-ok/30' : 'text-bad bg-bad/10 border border-bad/30'}`}>{banner.text}</div>}

      <div className="grid lg:grid-cols-2 gap-5">
        {decoys.map((d) => (
          <Panel key={d._id} title={d.name || d._id} action={<div className="flex items-center gap-2 text-xs"><Dot state={d.enabled ? (d.health?.status || 'pending') : 'disabled'} /><span className="text-ink-dim">{d.enabled ? d.health?.status || 'pending' : 'disabled'}</span></div>}>
            <div className="panel-pad space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                <F label="Type"><Mono>{d.type}</Mono></F>
                <F label="Address"><Mono>{d.address}</Mono></F>
                <F label="Ports"><Mono>{(d.ports || []).join(', ')}</Mono></F>
                <F label="Config version">v{d.config_version}</F>
                <F label="Zone">{d.network_zone?.split(' - ')[0] || '—'}</F>
                <F label="Last event">{d.enabled ? fmtAgo(d.last_event_at) : '—'}</F>
              </div>
              {d.purpose && <p className="text-ink-dim">{d.purpose}</p>}

              {d.health?.targets?.length > 0 && (
                <div className="bg-base-850 rounded-md p-2.5">
                  <div className="label mb-1">Health probes · {fmtAgo(d.health.checked_at)}</div>
                  <div className="flex flex-wrap gap-1.5">{d.health.targets.map((t) => <span key={t.port} className={`chip ${t.ok ? 'bg-ok/15 text-ok' : 'bg-bad/15 text-bad'}`}>:{t.port} {t.ok ? 'up' : 'down'}</span>)}</div>
                  {d.health.detail && <div className="text-xs text-ink-faint mt-1">{d.health.detail}</div>}
                </div>
              )}
              {d.isolation && (
                <div className={`rounded-md p-2.5 ${d.isolation.all_blocked ? 'bg-ok/10' : 'bg-bad/10'}`}>
                  <div className="label mb-1">Egress self-test · {fmtAgo(d.isolation.checked_at)}</div>
                  <div className={`text-xs ${d.isolation.all_blocked ? 'text-ok' : 'text-bad'}`}>{d.isolation.all_blocked ? 'All outbound blocked (isolated)' : 'An outbound connection succeeded — investigate!'}</div>
                </div>
              )}
              {d.container_state && <div className="text-xs text-ink-faint">container <Mono>{d.container}</Mono>: {d.container_state.state}{d.container_state.status ? ` (${d.container_state.status})` : ''}</div>}

              {can('admin') && (
                <div className="flex gap-2 pt-1">
                  {!d.enabled
                    ? <button className="btn-primary" onClick={() => setChecklistFor(checklistFor === d._id ? null : d._id)}>Enable…</button>
                    : <button className="btn-ghost" onClick={() => act(d._id, { action: 'disable', reason: 'operator disabled from console' })}>Disable</button>}
                  <button className="btn-ghost" onClick={() => act(d._id, { action: 'health_check' })}>Run health check</button>
                </div>
              )}

              {checklistFor === d._id && (
                <ChecklistForm checklist={checklist} onCancel={() => setChecklistFor(null)} onConfirm={(c) => { setChecklistFor(null); act(d._id, { action: 'enable', checklist: c, reason: 'isolation checklist confirmed' }); }} />
              )}
            </div>
          </Panel>
        ))}
        {!decoys.length && <Empty title="No decoys registered" />}
      </div>
    </div>
  );
}

function F({ label, children }) { return <div><div className="label">{label}</div><div className="mt-0.5">{children}</div></div>; }

function ChecklistForm({ checklist, onConfirm, onCancel }) {
  const [state, setState] = useState({});
  const allChecked = checklist.every((c) => state[c.key]);
  return (
    <div className="bg-base-950 border border-base-700 rounded-md p-3 space-y-2">
      <div className="text-sm font-medium text-warn">Isolation checklist — confirm each before enabling</div>
      {checklist.map((c) => (
        <label key={c.key} className="flex items-start gap-2 text-sm cursor-pointer">
          <input type="checkbox" className="accent-accent w-4 h-4 mt-0.5" checked={!!state[c.key]} onChange={(e) => setState((s) => ({ ...s, [c.key]: e.target.checked }))} />
          <span className="text-ink-dim">{c.label}</span>
        </label>
      ))}
      <div className="flex gap-2 pt-1">
        <button className="btn-primary" disabled={!allChecked} onClick={() => onConfirm(state)}>Confirm & enable</button>
        <button className="btn-ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}
