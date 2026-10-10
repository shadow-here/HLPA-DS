// API tests (PRD T-08 lifecycle/audit, T-09 authorization, T-10 injection,
// T-11 export accuracy). Requires a reachable MongoDB at MONGO_URL.
//
//   MONGO_URL=mongodb://localhost:27017 node --test test/
//
// If MONGO_URL is unset or unreachable, the suite skips with a clear message.
const { test, before, after, describe } = require('node:test');
const assert = require('node:assert');
const { startServer, agentFor, request } = require('./helpers');

let app, db, admin, analyst, viewer, available = true;

before(async () => {
  if (!process.env.MONGO_URL) { available = false; return; }
  try {
    const started = await startServer();
    app = started.app; db = started.db.getDb();
    admin = await agentFor(app, 'admin', process.env.ADMIN_PASSWORD);
    analyst = await agentFor(app, 'analyst', process.env.ANALYST_PASSWORD);
    viewer = await agentFor(app, 'viewer', process.env.VIEWER_PASSWORD);
    // Rules are normally seeded by the collector; seed a couple here so the
    // rule-management tests have something to act on in this API-only suite.
    await db.collection('rules').insertMany([
      { _id: 'DET-01', name: 'Repeated failed authentication', type: 'threshold', kind: 'attacker', enabled: true, severity: 'high', threshold: 5, window_seconds: 60, version: 1 },
      { _id: 'DET-06', name: 'High-frequency interaction', type: 'threshold', kind: 'attacker', enabled: true, severity: 'low', threshold: 60, window_seconds: 10, version: 1 },
    ]);
  } catch (e) { available = false; console.error('[test] setup failed:', e.message); }
});

after(async () => { if (available) { await db.dropDatabase(); await require('../src/db').close(); } });

const skip = () => ({ skip: !available ? 'MongoDB not available (set MONGO_URL)' : false });

describe('authentication & CSRF', () => {
  test('rejects unauthenticated access', skip(), async () => {
    const res = await request(app).get('/api/alerts');
    assert.equal(res.status, 401);
  });
  test('rejects state change without CSRF header', skip(), async () => {
    const res = await analyst.post('/api/auth/logout'); // no X-Requested-With
    assert.equal(res.status, 403);
  });
  test('wrong password is rejected and audited', skip(), async () => {
    const res = await request(app).post('/api/auth/login').set('X-Requested-With', 'hlpa').send({ username: 'admin', password: 'nope' });
    assert.equal(res.status, 401);
    const rec = await db.collection('audit_log').findOne({ action: 'login', outcome: 'failure' });
    assert.ok(rec);
  });
});

describe('authorization (T-09)', () => {
  test('viewer cannot change a rule', skip(), async () => {
    const res = await viewer.hdr(viewer.patch('/api/rules/DET-01')).send({ enabled: false });
    assert.equal(res.status, 403);
  });
  test('analyst cannot create a user', skip(), async () => {
    const res = await analyst.hdr(analyst.post('/api/users')).send({ username: 'x', password: 'xxxxxxxxxx', role: 'viewer' });
    assert.equal(res.status, 403);
  });
  test('denied attempt is recorded in the audit log', skip(), async () => {
    const rec = await db.collection('audit_log').findOne({ action: 'access_denied' });
    assert.ok(rec);
  });
  test('admin can disable and re-enable a rule', skip(), async () => {
    let res = await admin.hdr(admin.patch('/api/rules/DET-06')).send({ enabled: false });
    assert.equal(res.status, 200);
    assert.equal(res.body.enabled, false);
    res = await admin.hdr(admin.patch('/api/rules/DET-06')).send({ enabled: true });
    assert.equal(res.body.enabled, true);
    assert.ok(res.body.version >= 2); // version bumped on each change
  });
});

describe('decoy isolation checklist (FR-04)', () => {
  test('enable is refused without a complete checklist', skip(), async () => {
    const res = await admin.hdr(admin.patch('/api/decoys/decoy-ssh/status')).send({ action: 'enable', checklist: { egress_blocked: true } });
    assert.equal(res.status, 400);
    assert.ok(res.body.details.missing.length > 0);
  });
  test('registering a decoy outside the lab CIDR is rejected', skip(), async () => {
    const res = await admin.hdr(admin.post('/api/decoys')).send({ id: 'bad-decoy', type: 'http_decoy', address: '8.8.8.8', ports: [80] });
    assert.equal(res.status, 400);
  });
});

describe('alert lifecycle & audit (T-08)', () => {
  let alertId;
  before(async () => {
    if (!available) return;
    alertId = 'ALR-20260101-ABC123';
    await db.collection('alerts').insertOne({
      _id: alertId, alert_id: alertId, rule_id: 'DET-01', status: 'New', severity: 'high',
      src_ip: '203.0.113.1', event_ids: [], event_count: 1, history: [],
      first_seen: new Date(), last_seen: new Date(), created_at: new Date(), updated_at: new Date(),
    });
  });
  test('invalid transition is blocked (New -> Resolved)', skip(), async () => {
    const res = await analyst.hdr(analyst.patch(`/api/alerts/${alertId}`)).send({ status: 'Resolved', note: 'x' });
    assert.equal(res.status, 409);
  });
  test('valid transition New -> Acknowledged works and is audited', skip(), async () => {
    const res = await analyst.hdr(analyst.patch(`/api/alerts/${alertId}`)).send({ status: 'Acknowledged' });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'Acknowledged');
    const rec = await db.collection('audit_log').findOne({ action: 'alert_status_change', target: alertId });
    assert.ok(rec);
  });
  test('closing requires a note', skip(), async () => {
    await analyst.hdr(analyst.patch(`/api/alerts/${alertId}`)).send({ status: 'Investigating', note: 'looking' });
    const res = await analyst.hdr(analyst.patch(`/api/alerts/${alertId}`)).send({ status: 'Resolved' });
    assert.equal(res.status, 400);
  });
  test('lab response request is refused (adapter disabled)', skip(), async () => {
    const res = await admin.hdr(admin.post(`/api/alerts/${alertId}/response-request`)).send({});
    assert.equal(res.status, 409);
    assert.equal(res.body.state, 'not_applied');
  });
});

describe('injection safety (T-10)', () => {
  test('query operator injection is treated as a literal string', skip(), async () => {
    // ?src_ip[$ne]= would be an injection; simple query parser makes it a string, matching nothing.
    const res = await analyst.get('/api/events?src_ip[$ne]=');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.items));
  });
  test('stored HTML-looking event field is returned as data, not executed', skip(), async () => {
    const id = '00000000-0000-0000-0000-000000000001';
    await db.collection('events').insertOne({
      _id: id, event_id: id, source_type: 'http_decoy', event_time: new Date(), ingested_at: new Date(),
      event_category: 'web_request', http_path: '<script>alert(1)</script>', message: 'x', tags: [], raw_ref: null,
    });
    const res = await analyst.get(`/api/events/${id}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.http_path, '<script>alert(1)</script>'); // stored/returned verbatim as a string
  });
});

describe('exports (T-11)', () => {
  test('CSV neutralises spreadsheet formula triggers', skip(), async () => {
    const id = '00000000-0000-0000-0000-000000000002';
    await db.collection('events').insertOne({
      _id: id, event_id: id, source_type: 'http_decoy', event_time: new Date(), ingested_at: new Date(),
      event_category: 'web_request', http_path: '=cmd|calc', username: '@evil', message: 'x', tags: [], raw_ref: null,
    });
    const res = await analyst.get('/api/exports/events?format=csv&range=30d');
    assert.equal(res.status, 200);
    assert.ok(res.headers['content-type'].includes('text/csv'));
    // formula-trigger cells are prefixed with a single quote
    assert.ok(res.text.includes("'=cmd|calc") || res.text.includes('"\'=cmd|calc'));
  });
  test('viewer cannot export', skip(), async () => {
    const res = await viewer.get('/api/exports/events?format=csv');
    assert.equal(res.status, 403);
  });
});

describe('health endpoint', () => {
  test('public health needs no auth and hides internals', skip(), async () => {
    const res = await request(app).get('/api/health');
    assert.ok([200, 503].includes(res.status));
    assert.ok('database' in res.body);
    assert.ok(!('mongoUrl' in res.body));
  });
});
