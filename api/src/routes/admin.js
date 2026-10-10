const express = require('express');
const bcrypt = require('bcryptjs');
const { getDb } = require('../db');
const { audit } = require('../audit');
const { requireRole } = require('../auth');
const { HttpError, str, intIn, isIp, asyncH, SEVERITIES } = require('../util');

const router = express.Router();
const ROLES = ['admin', 'analyst', 'viewer'];

// ------------------------------------------------------------------ rules
router.get('/rules', asyncH(async (req, res) => {
  const rules = await getDb().collection('rules').find({}).sort({ _id: 1 }).toArray();
  const taggers = await getDb().collection('settings').findOne({ _id: 'taggers' });
  res.json({ rules, taggers: taggers ? taggers.taggers : [] });
}));

router.patch('/rules/:id', requireRole('admin'), asyncH(async (req, res) => {
  const id = str(req.params.id, 20);
  const db = getDb();
  const rule = await db.collection('rules').findOne({ _id: id });
  if (!rule) throw new HttpError(404, 'rule not found');
  const b = req.body || {};
  const set = {};
  if (b.enabled !== undefined) { if (typeof b.enabled !== 'boolean') throw new HttpError(400, 'enabled must be boolean'); set.enabled = b.enabled; }
  if (b.severity !== undefined) { if (!SEVERITIES.includes(b.severity)) throw new HttpError(400, 'invalid severity'); set.severity = b.severity; }
  if (b.threshold !== undefined) {
    if (!['threshold', 'distinct'].includes(rule.type)) throw new HttpError(400, 'this rule type has no threshold');
    if (!Number.isInteger(b.threshold) || b.threshold < 1 || b.threshold > 100000) throw new HttpError(400, 'threshold must be 1-100000');
    set.threshold = b.threshold;
  }
  if (b.window_seconds !== undefined) {
    if (!['threshold', 'distinct'].includes(rule.type)) throw new HttpError(400, 'this rule type has no window');
    if (!Number.isInteger(b.window_seconds) || b.window_seconds < 1 || b.window_seconds > 86400) throw new HttpError(400, 'window_seconds must be 1-86400');
    set.window_seconds = b.window_seconds;
  }
  if (b.dedupe_seconds !== undefined) {
    if (!Number.isInteger(b.dedupe_seconds) || b.dedupe_seconds < 0 || b.dedupe_seconds > 604800) throw new HttpError(400, 'dedupe_seconds must be 0-604800');
    set.dedupe_seconds = b.dedupe_seconds;
  }
  if (!Object.keys(set).length) throw new HttpError(400, 'nothing to update');
  const before = Object.fromEntries(Object.keys(set).map((k) => [k, rule[k]]));
  set.updated_at = new Date();
  set.updated_by = req.user.username;
  await db.collection('rules').updateOne({ _id: id }, { $set: set, $inc: { version: 1 } });
  await audit(req, 'rule_update', { target: id, reason: str(b.reason, 300) || null, details: { before, after: Object.fromEntries(Object.keys(before).map((k) => [k, set[k]])) } });
  res.json(await db.collection('rules').findOne({ _id: id }));
}));

// ------------------------------------------------------------------ approved test sources (suppression)
router.get('/approved-sources', asyncH(async (req, res) => {
  res.json(await getDb().collection('approved_sources').find({}).sort({ created_at: -1 }).toArray());
}));

router.post('/approved-sources', requireRole('admin'), asyncH(async (req, res) => {
  const ip = str(req.body && req.body.ip, 45);
  const reason = str(req.body && req.body.reason, 300);
  if (!ip || !isIp(ip)) throw new HttpError(400, 'valid IP address required');
  if (!reason) throw new HttpError(400, 'a reason is required so the exclusion stays auditable');
  const hours = intIn(req.body.expires_in_hours, 24, 1, 24 * 90);
  const doc = { ip, reason, created_by: req.user.username, created_at: new Date(), expires_at: new Date(Date.now() + hours * 3600e3) };
  try { await getDb().collection('approved_sources').insertOne(doc); } catch (e) {
    if (e.code === 11000) throw new HttpError(409, 'this address is already approved'); throw e;
  }
  await audit(req, 'approved_source_add', { target: ip, reason, details: { expires_at: doc.expires_at } });
  res.status(201).json(doc);
}));

router.delete('/approved-sources/:ip', requireRole('admin'), asyncH(async (req, res) => {
  const ip = str(req.params.ip, 45);
  const r = await getDb().collection('approved_sources').deleteOne({ ip });
  if (!r.deletedCount) throw new HttpError(404, 'not found');
  await audit(req, 'approved_source_remove', { target: ip });
  res.json({ ok: true });
}));

// ------------------------------------------------------------------ indicators (DET-07)
router.get('/indicators', asyncH(async (req, res) => {
  res.json(await getDb().collection('indicators').find({}).sort({ created_at: -1 }).toArray());
}));

router.post('/indicators', requireRole('admin'), asyncH(async (req, res) => {
  const value = str(req.body && req.body.value, 128);
  const type = req.body && req.body.type === 'sha256' ? 'sha256' : 'ip';
  if (!value) throw new HttpError(400, 'value required');
  if (type === 'ip' && !isIp(value)) throw new HttpError(400, 'invalid IP address');
  if (type === 'sha256' && !/^[a-fA-F0-9]{64}$/.test(value)) throw new HttpError(400, 'invalid sha256');
  const doc = { value: value.toLowerCase(), type, label: str(req.body.label, 200) || '', created_by: req.user.username, created_at: new Date() };
  try { await getDb().collection('indicators').insertOne(doc); } catch (e) {
    if (e.code === 11000) throw new HttpError(409, 'indicator already exists'); throw e;
  }
  await audit(req, 'indicator_add', { target: doc.value, details: { type } });
  res.status(201).json(doc);
}));

router.delete('/indicators/:value', requireRole('admin'), asyncH(async (req, res) => {
  const value = str(req.params.value, 128);
  const r = await getDb().collection('indicators').deleteOne({ value: value && value.toLowerCase() });
  if (!r.deletedCount) throw new HttpError(404, 'not found');
  await audit(req, 'indicator_remove', { target: value });
  res.json({ ok: true });
}));

// ------------------------------------------------------------------ users (admin)
router.get('/users', requireRole('admin'), asyncH(async (req, res) => {
  res.json(await getDb().collection('users').find({}, { projection: { password_hash: 0 } }).sort({ username: 1 }).toArray());
}));

function checkPassword(p) {
  if (typeof p !== 'string' || p.length < 10 || p.length > 200) throw new HttpError(400, 'password must be 10-200 characters');
}

router.post('/users', requireRole('admin'), asyncH(async (req, res) => {
  const b = req.body || {};
  const username = str(b.username, 40);
  if (!username || !/^[a-zA-Z0-9._-]{3,40}$/.test(username)) throw new HttpError(400, 'username: 3-40 letters, digits, . _ -');
  if (!ROLES.includes(b.role)) throw new HttpError(400, `role must be one of ${ROLES.join(', ')}`);
  checkPassword(b.password);
  try {
    await getDb().collection('users').insertOne({ username, role: b.role, password_hash: await bcrypt.hash(b.password, 12), disabled: false, created_at: new Date(), created_by: req.user.username });
  } catch (e) { if (e.code === 11000) throw new HttpError(409, 'username exists'); throw e; }
  await audit(req, 'user_create', { target: username, details: { role: b.role } });
  res.status(201).json({ username, role: b.role });
}));

router.patch('/users/:username', requireRole('admin'), asyncH(async (req, res) => {
  const username = str(req.params.username, 40);
  const b = req.body || {};
  const db = getDb();
  const user = await db.collection('users').findOne({ username });
  if (!user) throw new HttpError(404, 'user not found');
  const set = {};
  if (b.role !== undefined) { if (!ROLES.includes(b.role)) throw new HttpError(400, 'invalid role'); set.role = b.role; }
  if (b.disabled !== undefined) set.disabled = Boolean(b.disabled);
  if (b.password !== undefined) { checkPassword(b.password); set.password_hash = await bcrypt.hash(b.password, 12); }
  if (!Object.keys(set).length) throw new HttpError(400, 'nothing to update');
  if (username === req.user.username && (set.disabled || (set.role && set.role !== 'admin'))) throw new HttpError(400, 'you cannot disable or demote your own account');
  if (user.role === 'admin' && (set.disabled || (set.role && set.role !== 'admin'))) {
    const admins = await db.collection('users').countDocuments({ role: 'admin', disabled: { $ne: true } });
    if (admins <= 1) throw new HttpError(400, 'at least one active admin must remain');
  }
  await db.collection('users').updateOne({ username }, { $set: { ...set, updated_at: new Date() } });
  await audit(req, 'user_update', { target: username, details: { fields: Object.keys(set).map((k) => (k === 'password_hash' ? 'password' : k)) } });
  res.json({ ok: true });
}));

// ------------------------------------------------------------------ settings, audit, ingest errors
router.get('/settings/retention', asyncH(async (req, res) => {
  res.json(await getDb().collection('settings').findOne({ _id: 'retention' }) || { events_days: 30, alerts_days: 90 });
}));

router.put('/settings/retention', requireRole('admin'), asyncH(async (req, res) => {
  const ev = intIn(req.body && req.body.events_days, NaN, 1, 365);
  const al = intIn(req.body && req.body.alerts_days, NaN, 1, 730);
  if (!Number.isFinite(ev) || !Number.isFinite(al)) throw new HttpError(400, 'events_days (1-365) and alerts_days (1-730) required');
  const before = await getDb().collection('settings').findOne({ _id: 'retention' });
  await getDb().collection('settings').updateOne({ _id: 'retention' }, { $set: { events_days: ev, alerts_days: al, updated_by: req.user.username, updated_at: new Date() } }, { upsert: true });
  await audit(req, 'retention_update', { target: 'retention', details: { before: before ? { events_days: before.events_days, alerts_days: before.alerts_days } : null, after: { events_days: ev, alerts_days: al } } });
  res.json({ events_days: ev, alerts_days: al });
}));

router.get('/audit', requireRole('admin'), asyncH(async (req, res) => {
  const f = {};
  for (const k of ['actor', 'action', 'outcome', 'target']) { const v = str(req.query[k], 100); if (v) f[k] = v; }
  const limit = intIn(req.query.limit, 100, 1, 500);
  const page = intIn(req.query.page, 1, 1, 100000);
  const col = getDb().collection('audit_log');
  const [items, total] = await Promise.all([col.find(f).sort({ at: -1 }).skip((page - 1) * limit).limit(limit).toArray(), col.countDocuments(f)]);
  res.json({ items, total, page, limit });
}));

router.get('/ingest-errors', requireRole('analyst'), asyncH(async (req, res) => {
  const limit = intIn(req.query.limit, 50, 1, 200);
  const col = getDb().collection('ingest_errors');
  const [items, total] = await Promise.all([col.find({}).sort({ at: -1 }).limit(limit).toArray(), col.countDocuments({})]);
  res.json({ items, total });
}));

module.exports = router;
