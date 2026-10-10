const express = require('express');
const { getDb } = require('../db');
const { ROLE_RANK } = require('../auth');
const { HttpError, str, intIn, timeRange, escapeRegex, asyncH } = require('../util');

const router = express.Router();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Build a validated Mongo filter from query params. Shared with exports/reports. */
function eventFilter(q) {
  const { from, to } = timeRange(q, '24h');
  const f = { event_time: { $gte: from, $lte: to } };
  for (const field of ['src_ip', 'decoy_id', 'source_type', 'event_category', 'service', 'session_id', 'sensor_id']) {
    const v = str(q[field], 100);
    if (v) f[field] = v;
  }
  const tag = str(q.tag, 60);
  if (tag) f.tags = tag;
  const alertId = str(q.alert_id, 40);
  if (alertId) f.alert_ids = alertId;
  if (q.approved === 'true') f.approved_source = true;
  if (q.approved === 'false') f.approved_source = { $ne: true };
  if (q.hide_system === 'true') f.event_category = f.event_category || { $nin: ['heartbeat', 'egress_attempt', 'sensor_status', 'session_meta'] };
  const text = str(q.q, 100);
  if (text) {
    const rx = { $regex: escapeRegex(text), $options: 'i' };
    f.$or = [{ message: rx }, { command: rx }, { http_path: rx }, { username: rx }, { src_ip: rx }];
  }
  return { filter: f, from, to };
}

router.get('/', asyncH(async (req, res) => {
  const { filter, from, to } = eventFilter(req.query);
  const limit = intIn(req.query.limit, 50, 1, 200);
  const page = intIn(req.query.page, 1, 1, 100000);
  const col = getDb().collection('events');
  const [items, total] = await Promise.all([
    col.find(filter).sort({ event_time: -1 }).skip((page - 1) * limit).limit(limit).toArray(),
    col.countDocuments(filter),
  ]);
  res.json({ items, total, page, limit, range: { from, to } });
}));

router.get('/facets', asyncH(async (req, res) => {
  const col = getDb().collection('events');
  const [categories, sources, services] = await Promise.all([
    col.distinct('event_category'), col.distinct('source_type'), col.distinct('service'),
  ]);
  res.json({ categories: categories.filter(Boolean).sort(), source_types: sources.filter(Boolean).sort(), services: services.filter(Boolean).sort() });
}));

router.get('/:id', asyncH(async (req, res) => {
  const id = str(req.params.id, 40);
  if (!id || !UUID_RE.test(id)) throw new HttpError(400, 'invalid event id');
  const db = getDb();
  const ev = await db.collection('events').findOne({ _id: id });
  if (!ev) throw new HttpError(404, 'event not found');
  // Sanitized raw record: analysts and admins only (PRD 6.3 restricted raw access).
  let raw = null;
  if (ROLE_RANK[req.user.role] >= ROLE_RANK.analyst && ev.raw_ref) {
    const r = await db.collection('raw_events').findOne({ _id: id });
    raw = r ? { source_file: r.source_file, offset: r.offset, record: r.raw } : null;
  }
  res.json({ ...ev, raw, raw_visible: ROLE_RANK[req.user.role] >= ROLE_RANK.analyst });
}));

module.exports = router;
module.exports.eventFilter = eventFilter;
