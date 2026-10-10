const express = require('express');
const { getDb } = require('../db');
const { audit } = require('../audit');
const { requireRole } = require('../auth');
const {
  HttpError, str, intIn, timeRange, escapeRegex, asyncH,
  ALERT_STATES, OPEN_STATES, TRANSITIONS, NOTE_REQUIRED, SEVERITIES,
} = require('../util');

const router = express.Router();
const ALERT_RE = /^ALR-\d{8}-[0-9A-F]{6}$/;

function alertFilter(q) {
  const f = {};
  if (q.from || q.to || q.range) {
    const { from, to } = timeRange(q, '24h');
    f.last_seen = { $gte: from, $lte: to };
  }
  const status = str(q.status, 40);
  if (status === 'open') f.status = { $in: OPEN_STATES };
  else if (status) {
    if (!ALERT_STATES.includes(status)) throw new HttpError(400, 'invalid status');
    f.status = status;
  }
  const sev = str(q.severity, 10);
  if (sev) {
    if (!SEVERITIES.includes(sev)) throw new HttpError(400, 'invalid severity');
    f.severity = sev;
  }
  for (const field of ['rule_id', 'src_ip', 'decoy_id', 'kind']) {
    const v = str(q[field], 100);
    if (v) f[field] = v;
  }
  const text = str(q.q, 100);
  if (text) {
    const rx = { $regex: escapeRegex(text), $options: 'i' };
    f.$or = [{ title: rx }, { alert_id: rx }, { src_ip: rx }, { rule_name: rx }];
  }
  return f;
}

router.get('/', asyncH(async (req, res) => {
  const filter = alertFilter(req.query);
  const limit = intIn(req.query.limit, 50, 1, 200);
  const page = intIn(req.query.page, 1, 1, 100000);
  const col = getDb().collection('alerts');
  const [items, total] = await Promise.all([
    col.find(filter, { projection: { event_ids: 0, history: 0, analyst_notes: 0 } })
      .sort({ last_seen: -1 }).skip((page - 1) * limit).limit(limit).toArray(),
    col.countDocuments(filter),
  ]);
  res.json({ items, total, page, limit });
}));

router.get('/:id', asyncH(async (req, res) => {
  const id = str(req.params.id, 40);
  if (!id || !ALERT_RE.test(id)) throw new HttpError(400, 'invalid alert id');
  const db = getDb();
  const alert = await db.collection('alerts').findOne({ _id: id });
  if (!alert) throw new HttpError(404, 'alert not found');
  const [events, rule, decoy] = await Promise.all([
    db.collection('events').find({ _id: { $in: alert.event_ids || [] } }).sort({ event_time: 1 }).limit(500).toArray(),
    db.collection('rules').findOne({ _id: alert.rule_id }),
    alert.decoy_id ? db.collection('decoys').findOne({ _id: alert.decoy_id }, { projection: { name: 1, address: 1, type: 1 } }) : null,
  ]);
  res.json({
    ...alert,
    events,
    rule: rule ? { id: rule._id, name: rule.name, version: rule.version, type: rule.type, description: rule.description,
      threshold: rule.threshold, window_seconds: rule.window_seconds, severity: rule.severity, group_by: rule.group_by } : null,
    decoy,
    allowed_transitions: TRANSITIONS[alert.status] || [],
    note_required_for: NOTE_REQUIRED,
  });
}));

// State change and/or analyst note. Every change is validated and audited (FR-09, FR-14).
router.patch('/:id', requireRole('analyst'), asyncH(async (req, res) => {
  const id = str(req.params.id, 40);
  if (!id || !ALERT_RE.test(id)) throw new HttpError(400, 'invalid alert id');
  const db = getDb();
  const alert = await db.collection('alerts').findOne({ _id: id });
  if (!alert) throw new HttpError(404, 'alert not found');

  const status = str(req.body && req.body.status, 40);
  const note = req.body && typeof req.body.note === 'string' ? req.body.note.trim().slice(0, 2000) : '';
  if (!status && !note) throw new HttpError(400, 'provide a status and/or a note');

  const now = new Date();
  const set = { updated_at: now };
  const push = {};
  if (status && status !== alert.status) {
    const allowed = TRANSITIONS[alert.status] || [];
    if (!allowed.includes(status)) {
      await audit(req, 'alert_status_change', { target: id, outcome: 'failure', reason: `invalid transition ${alert.status} -> ${status}` });
      throw new HttpError(409, `cannot move an alert from "${alert.status}" to "${status}"`, { allowed });
    }
    if (NOTE_REQUIRED.includes(status) && !note) {
      throw new HttpError(400, `a note is required when setting status "${status}"`);
    }
    set.status = status;
    if (status === 'Acknowledged') { set.acknowledged_by = req.user.username; set.acknowledged_at = now; }
    if (status === 'Contained (lab only)') { set.contained_at = now; set.contained_by = req.user.username; }
    if (status === 'Resolved' || status === 'False Positive') { set.closed_at = now; set.closed_by = req.user.username; }
    push.history = { at: now, actor: req.user.username, action: 'status_change', from: alert.status, to: status, note: note || null };
  }
  if (note) {
    push.analyst_notes = { at: now, author: req.user.username, text: note };
    if (!push.history) push.history = { at: now, actor: req.user.username, action: 'note_added', note };
  }
  await db.collection('alerts').updateOne({ _id: id }, { $set: set, $push: push });
  await audit(req, set.status ? 'alert_status_change' : 'alert_note', {
    target: id,
    details: set.status ? { from: alert.status, to: set.status, note: Boolean(note) } : { note: true },
  });
  res.json(await db.collection('alerts').findOne({ _id: id }, { projection: { event_ids: 0 } }));
}));

// Lab-only response request (FR-15 / PRD 7.4). The response adapter is disabled by
// default and not configured in this MVP, so the request is refused and audited.
router.post('/:id/response-request', requireRole('admin'), asyncH(async (req, res) => {
  const id = str(req.params.id, 40);
  if (!id || !ALERT_RE.test(id)) throw new HttpError(400, 'invalid alert id');
  const alert = await getDb().collection('alerts').findOne({ _id: id }, { projection: { _id: 1, src_ip: 1 } });
  if (!alert) throw new HttpError(404, 'alert not found');
  await audit(req, 'response_request', {
    target: id,
    outcome: 'failure',
    reason: 'lab response adapter disabled (not configured)',
    details: { source: alert.src_ip, requested: req.body || {} },
  });
  res.status(409).json({
    error: 'lab response adapter is disabled (not configured). No network change was made.',
    state: 'not_applied',
  });
}));

module.exports = router;
module.exports.alertFilter = alertFilter;
