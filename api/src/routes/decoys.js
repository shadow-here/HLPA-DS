const express = require('express');
const config = require('../config');
const { getDb } = require('../db');
const { audit } = require('../audit');
const { requireRole } = require('../auth');
const controller = require('../controller-client');
const { HttpError, str, asyncH, inCidr } = require('../util');

const router = express.Router();
const DECOY_TYPES = ['cowrie', 'opencanary', 'http_decoy'];
const CHECKLIST = [
  ['authorized_interface', 'Listener is on the authorised lab interface / network only'],
  ['inbound_restricted', 'Allowed inbound sources are limited to the approved lab test clients'],
  ['egress_blocked', 'Outbound routes from the decoy are blocked (default-deny egress)'],
  ['no_real_secrets', 'Decoy content is synthetic - no real credentials, keys or data'],
  ['no_production_reach', 'The decoy has no route to production assets'],
];

function validPorts(ports) {
  return Array.isArray(ports) && ports.length > 0 && ports.length <= 64
    && ports.every((p) => Number.isInteger(p) && p >= 1 && p <= 65535);
}

async function withContainerState(decoys) {
  const st = await controller.status();
  const map = st.ok ? st.containers || {} : {};
  return {
    controller: st.ok ? { reachable: true } : { reachable: false, error: st.error },
    decoys: decoys.map((d) => ({ ...d, container_state: d.container ? (map[d.container] || (st.ok ? { state: 'not found' } : null)) : null })),
  };
}

router.get('/', asyncH(async (req, res) => {
  const decoys = await getDb().collection('decoys').find({}).sort({ _id: 1 }).toArray();
  const out = await withContainerState(decoys);
  res.json({ ...out, checklist: CHECKLIST.map(([key, label]) => ({ key, label })), lab_cidr: config.labCidr });
}));

router.get('/:id', asyncH(async (req, res) => {
  const d = await getDb().collection('decoys').findOne({ _id: str(req.params.id, 64) });
  if (!d) throw new HttpError(404, 'decoy not found');
  const out = await withContainerState([d]);
  res.json({ ...out.decoys[0], controller: out.controller });
}));

// Register decoy metadata (admin). New decoys always start disabled.
router.post('/', requireRole('admin'), asyncH(async (req, res) => {
  const b = req.body || {};
  const id = str(b.id, 48);
  if (!id || !/^[a-z0-9][a-z0-9-]{2,47}$/.test(id)) throw new HttpError(400, 'id must be 3-48 chars: lowercase letters, digits, dashes');
  if (!DECOY_TYPES.includes(b.type)) throw new HttpError(400, `type must be one of ${DECOY_TYPES.join(', ')}`);
  const address = str(b.address, 45);
  if (!address || !inCidr(address, config.labCidr)) throw new HttpError(400, `address must be inside the lab network ${config.labCidr}`);
  if (!validPorts(b.ports)) throw new HttpError(400, 'ports must be 1-64 integers between 1 and 65535');
  const healthPorts = b.health_ports && validPorts(b.health_ports) ? b.health_ports : b.ports.slice(0, 3);
  const doc = {
    _id: id,
    name: str(b.name, 100) || id,
    type: b.type,
    source_type: b.type,
    container: str(b.container, 64) || null,
    address,
    ports: b.ports,
    health_ports: healthPorts,
    network_zone: 'Zone B - decoy network (hlpa_lab_net, internal)',
    purpose: str(b.purpose, 300) || '',
    owner: str(b.owner, 100) || req.user.username,
    hostname_lure: str(b.hostname_lure, 100) || '',
    enabled: false,
    state: 'registered',
    is_decoy: true,
    config_version: 1,
    created_at: new Date(),
    created_by: req.user.username,
    health: { status: 'disabled', detail: 'not yet enabled' },
  };
  try {
    await getDb().collection('decoys').insertOne(doc);
  } catch (err) {
    if (err.code === 11000) throw new HttpError(409, 'a decoy with this id already exists');
    throw err;
  }
  await audit(req, 'decoy_register', { target: id, details: { type: doc.type, address, ports: doc.ports } });
  res.status(201).json(doc);
}));

// Edit metadata (admin). Bumps the configuration version.
router.patch('/:id', requireRole('admin'), asyncH(async (req, res) => {
  const id = str(req.params.id, 64);
  const d = await getDb().collection('decoys').findOne({ _id: id });
  if (!d) throw new HttpError(404, 'decoy not found');
  const b = req.body || {};
  const set = {};
  for (const f of ['name', 'purpose', 'owner', 'hostname_lure']) if (b[f] !== undefined) set[f] = str(b[f], 300) || '';
  if (b.ports !== undefined) { if (!validPorts(b.ports)) throw new HttpError(400, 'invalid ports'); set.ports = b.ports; }
  if (b.health_ports !== undefined) { if (!validPorts(b.health_ports)) throw new HttpError(400, 'invalid health_ports'); set.health_ports = b.health_ports; }
  if (!Object.keys(set).length) throw new HttpError(400, 'nothing to update');
  set.updated_at = new Date();
  set.updated_by = req.user.username;
  await getDb().collection('decoys').updateOne({ _id: id }, { $set: set, $inc: { config_version: 1 } });
  await audit(req, 'decoy_update', { target: id, details: { fields: Object.keys(set) } });
  res.json(await getDb().collection('decoys').findOne({ _id: id }));
}));

// Enable / disable / request health check (admin).
router.patch('/:id/status', requireRole('admin'), asyncH(async (req, res) => {
  const id = str(req.params.id, 64);
  const db = getDb();
  const d = await db.collection('decoys').findOne({ _id: id });
  if (!d) throw new HttpError(404, 'decoy not found');
  const action = str(req.body && req.body.action, 20);
  const reason = str(req.body && req.body.reason, 300) || null;

  if (action === 'health_check') {
    await db.collection('decoys').updateOne({ _id: id }, { $set: { health_check_requested_at: new Date() } });
    await audit(req, 'decoy_health_check', { target: id });
    return res.json({ ok: true, message: 'health check requested; the collector runs it within a few seconds' });
  }

  if (action === 'enable') {
    const checklist = (req.body && req.body.checklist) || {};
    const missing = CHECKLIST.filter(([k]) => checklist[k] !== true).map(([k]) => k);
    if (missing.length) {
      await audit(req, 'decoy_enable', { target: id, outcome: 'failure', reason: 'isolation checklist incomplete', details: { missing } });
      throw new HttpError(400, 'isolation checklist incomplete', { missing });
    }
    if (!inCidr(d.address, config.labCidr)) {
      await audit(req, 'decoy_enable', { target: id, outcome: 'failure', reason: 'address outside lab network' });
      throw new HttpError(400, `decoy address ${d.address} is outside the lab network ${config.labCidr}`);
    }
    let containerResult = { ok: true, skipped: true };
    if (d.container) containerResult = await controller.start(d.container);
    if (!containerResult.ok) {
      // FR-03: a failed action must not silently mark the decoy active.
      await audit(req, 'decoy_enable', { target: id, outcome: 'failure', reason: containerResult.error });
      throw new HttpError(502, `could not start decoy container: ${containerResult.error}`);
    }
    const now = new Date();
    await db.collection('decoys').updateOne({ _id: id }, {
      $set: {
        enabled: true, state: 'enabled', enabled_at: now, enabled_by: req.user.username,
        last_checklist: { ...Object.fromEntries(CHECKLIST.map(([k]) => [k, true])), confirmed_by: req.user.username, confirmed_at: now },
        health_check_requested_at: now,
        'health.status': 'pending', 'health.detail': 'waiting for first health check',
      },
    });
    await audit(req, 'decoy_enable', { target: id, reason, details: { checklist: 'all items confirmed', container: d.container || null } });
    return res.json({ ok: true, message: 'decoy enabled; health is pending until the collector verifies it' });
  }

  if (action === 'disable') {
    let containerResult = { ok: true, skipped: true };
    if (d.container) containerResult = await controller.stop(d.container);
    await db.collection('decoys').updateOne({ _id: id }, {
      $set: { enabled: false, state: containerResult.ok ? 'disabled' : 'disable_failed', disabled_at: new Date(), disabled_by: req.user.username },
    });
    await audit(req, 'decoy_disable', { target: id, outcome: containerResult.ok ? 'success' : 'failure', reason: reason || containerResult.error || null });
    if (!containerResult.ok) {
      throw new HttpError(502, `decoy marked disabled, but stopping the container FAILED (${containerResult.error}). Run scripts\\emergency-stop.ps1`);
    }
    return res.json({ ok: true, message: 'decoy disabled and container stopped' });
  }

  throw new HttpError(400, 'action must be enable, disable or health_check');
}));

// Emergency kill switch: stop every decoy container (admin).
router.post('/actions/emergency-stop', requireRole('admin'), asyncH(async (req, res) => {
  const db = getDb();
  const decoys = await db.collection('decoys').find({}).toArray();
  const results = [];
  for (const d of decoys) {
    const r = d.container ? await controller.stop(d.container) : { ok: true, skipped: true };
    results.push({ decoy: d._id, ok: r.ok, error: r.error || null });
    await db.collection('decoys').updateOne({ _id: d._id }, { $set: { enabled: false, state: r.ok ? 'disabled' : 'disable_failed', disabled_at: new Date(), disabled_by: req.user.username } });
  }
  const allOk = results.every((r) => r.ok);
  await audit(req, 'emergency_stop', { target: 'all decoys', outcome: allOk ? 'success' : 'failure', reason: str(req.body && req.body.reason, 300) || null, details: { results } });
  res.status(allOk ? 200 : 502).json({ ok: allOk, results });
}));

module.exports = router;
module.exports.CHECKLIST = CHECKLIST;
