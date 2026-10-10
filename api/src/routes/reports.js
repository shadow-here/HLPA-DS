const express = require('express');
const { getDb } = require('../db');
const { audit } = require('../audit');
const { requireRole } = require('../auth');
const config = require('../config');
const { eventFilter } = require('./events');
const { alertFilter } = require('./alerts');
const { HttpError, str, timeRange, csvCell, percentile, asyncH, OPEN_STATES, escapeRegex } = require('../util');

const router = express.Router();
const SYSTEM_CATS = ['heartbeat', 'egress_attempt', 'sensor_status', 'health', 'session_meta'];

const EVENT_FIELDS = {
  event_id: 'Unique id assigned at ingestion (idempotency key)',
  event_time: 'UTC time reported by the sensor',
  ingested_at: 'UTC time the collector stored the event',
  source_type: 'cowrie | opencanary | http_decoy | collector',
  sensor_id: 'Sensor that produced the record',
  decoy_id: 'Registered decoy',
  src_ip: 'Observed source address (not attribution)',
  src_port: 'Observed source port',
  dst_ip: 'Decoy destination address',
  dst_port: 'Decoy destination port',
  service: 'Service / protocol name',
  event_category: 'connection, auth_failure, session_command, web_request, ...',
  outcome: 'Sensor-reported outcome',
  session_id: 'Sensor session reference',
  username: 'Username submitted to the decoy (synthetic accounts)',
  credential_fp: 'Keyed non-reversible fingerprint of a submitted secret (never the secret)',
  command: 'Command typed into the emulated shell',
  http_method: 'HTTP method', http_path: 'Requested path', http_status: 'Decoy response status',
  tags: 'Classification labels', alert_ids: 'Alerts this event supports',
  approved_source: 'True when the source is an approved test client',
  parser_status: 'parsed | partial',
  message: 'Human-readable summary',
};
const ALERT_FIELDS = {
  alert_id: 'Alert id', rule_id: 'Triggering rule', rule_version: 'Rule version', rule_name: 'Rule name',
  title: 'Evidence-based title', severity: 'low | medium | high | critical', status: 'Workflow state',
  kind: 'attacker | isolation | monitoring', src_ip: 'Observed source', decoy_id: 'Decoy', service: 'Service',
  first_seen: 'Earliest supporting event (UTC)', last_seen: 'Latest supporting event (UTC)',
  event_count: 'Number of supporting events', detection_latency_ms: 'Ingestion-to-alert latency',
  created_at: 'Alert created (UTC)', updated_at: 'Alert last updated (UTC)',
};

async function groupCount(col, match, field, limit = 10) {
  const rows = await getDb().collection(col).aggregate([
    { $match: match },
    { $group: { _id: `$${field}`, count: { $sum: 1 } } },
    { $sort: { count: -1 } },
    { $limit: limit },
  ]).toArray();
  return rows.map((r) => ({ key: r._id === null || r._id === undefined ? 'unknown' : r._id, count: r.count }));
}

function bucketMs(from, to) {
  const span = to - from;
  const nice = [60e3, 5 * 60e3, 15 * 60e3, 30 * 60e3, 3600e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3, 86400e3];
  return nice.find((b) => span / b <= 60) || 86400e3;
}

async function summary(from, to) {
  const db = getDb();
  const evMatch = { event_time: { $gte: from, $lte: to }, event_category: { $nin: SYSTEM_CATS } };
  const alMatch = { last_seen: { $gte: from, $lte: to } };
  const createdMatch = { created_at: { $gte: from, $lte: to } };

  const [totalEvents, totalAlerts, bySeverity, byStatus, byRule, byCategory, byDecoy, bySource, topSources, openAlerts, ingestErrors, latencies, retention, approvedEvents] = await Promise.all([
    db.collection('events').countDocuments(evMatch),
    db.collection('alerts').countDocuments(alMatch),
    groupCount('alerts', alMatch, 'severity'),
    groupCount('alerts', alMatch, 'status'),
    groupCount('alerts', alMatch, 'rule_id', 20),
    groupCount('events', evMatch, 'event_category', 20),
    groupCount('events', evMatch, 'decoy_id', 20),
    groupCount('events', evMatch, 'source_type', 10),
    groupCount('events', { ...evMatch, src_ip: { $ne: null } }, 'src_ip', 10),
    db.collection('alerts').find({ ...alMatch, status: { $in: OPEN_STATES } }, { projection: { event_ids: 0, history: 0, analyst_notes: 0, matched_evidence: 0 } })
      .sort({ last_seen: -1 }).limit(50).toArray(),
    db.collection('ingest_errors').countDocuments({ at: { $gte: from, $lte: to } }),
    db.collection('alerts').find(createdMatch, { projection: { detection_latency_ms: 1 } }).limit(20000).toArray(),
    db.collection('settings').findOne({ _id: 'retention' }),
    db.collection('events').countDocuments({ ...evMatch, approved_source: true }),
  ]);
  const lat = latencies.map((a) => a.detection_latency_ms).filter((v) => typeof v === 'number');
  const retentionDays = (retention && retention.events_days) || 30;
  const retentionStart = new Date(Date.now() - retentionDays * 86400e3);
  return {
    range: { from, to },
    totals: { events: totalEvents, alerts: totalAlerts, open_alerts: openAlerts.length, ingest_errors: ingestErrors, approved_source_events: approvedEvents },
    alerts_by_severity: bySeverity,
    alerts_by_status: byStatus,
    top_rules: byRule,
    events_by_category: byCategory,
    events_by_decoy: byDecoy,
    events_by_source_type: bySource,
    top_sources: topSources,
    unresolved_alerts: openAlerts,
    detection_latency_ms: { samples: lat.length, p50: percentile(lat, 50), p95: percentile(lat, 95), max: lat.length ? Math.max(...lat) : null },
    retention: {
      events_days: retentionDays,
      warning: from < retentionStart ? `Range starts before the ${retentionDays}-day event retention window; events older than ${retentionStart.toISOString()} may have been deleted, so totals can be incomplete.` : null,
    },
    notes: 'Source addresses are observations, not attribution. System/health events are excluded from interaction totals.',
  };
}

// Dashboard overview (all roles)
router.get('/dashboard', asyncH(async (req, res) => {
  const { from, to } = timeRange(req.query, '24h');
  const db = getDb();
  const base = await summary(from, to);
  const step = bucketMs(from, to);
  const [evTimes, alTimes, decoys, openBySeverity] = await Promise.all([
    db.collection('events').find({ event_time: { $gte: from, $lte: to }, event_category: { $nin: SYSTEM_CATS } }, { projection: { event_time: 1, _id: 0 } }).limit(200000).toArray(),
    db.collection('alerts').find({ created_at: { $gte: from, $lte: to } }, { projection: { created_at: 1, _id: 0 } }).limit(50000).toArray(),
    db.collection('decoys').find({}, { projection: { name: 1, enabled: 1, health: 1, last_event_at: 1, address: 1, type: 1, isolation: 1 } }).toArray(),
    groupCount('alerts', { status: { $in: OPEN_STATES } }, 'severity'),
  ]);
  const start = Math.floor(from.getTime() / step) * step;
  const n = Math.min(500, Math.ceil((to.getTime() - start) / step) + 1);
  const series = Array.from({ length: n }, (_, i) => ({ t: new Date(start + i * step), events: 0, alerts: 0 }));
  for (const e of evTimes) { const i = Math.floor((new Date(e.event_time).getTime() - start) / step); if (series[i]) series[i].events++; }
  for (const a of alTimes) { const i = Math.floor((new Date(a.created_at).getTime() - start) / step); if (series[i]) series[i].alerts++; }
  res.json({ ...base, bucket_ms: step, series, decoys, open_by_severity: openBySeverity });
}));

// Time-bounded summary report (all roles may view; FR-13)
router.get('/reports/summary', asyncH(async (req, res) => {
  const { from, to } = timeRange(req.query, '24h');
  const data = await summary(from, to);
  await audit(req, 'report_view', { target: 'summary', details: { from, to } });
  res.json({ ...data, generated_at: new Date(), generated_by: req.user.username, generator: 'HLPA-DS 1.0.0' });
}));

// Ingestion completeness check for the controlled 100-event test (T-03 / O-02)
router.get('/reports/ingestion-test', requireRole('analyst'), asyncH(async (req, res) => {
  const runId = str(req.query.run_id, 40);
  if (!runId || !/^[A-Za-z0-9-]{4,40}$/.test(runId)) throw new HttpError(400, 'run_id required (letters, digits, dashes)');
  const expected = Math.max(1, parseInt(req.query.expected || '100', 10) || 100);
  const db = getDb();
  const filter = { event_category: 'web_request', http_path: { $regex: escapeRegex(`run=${runId}`) } };
  const events = await db.collection('events').find(filter, { projection: { http_path: 1, event_time: 1, ingested_at: 1 } }).toArray();
  const seq = new Set();
  for (const e of events) { const m = /[?&]n=(\d+)/.exec(e.http_path || ''); if (m) seq.add(parseInt(m[1], 10)); }
  const missing = [];
  for (let i = 1; i <= expected; i++) if (!seq.has(i)) missing.push(i);
  const lags = events.map((e) => new Date(e.ingested_at) - new Date(e.event_time)).filter((v) => v >= 0);
  const times = events.map((e) => new Date(e.event_time).getTime());
  const errors = times.length ? await db.collection('ingest_errors').countDocuments({ at: { $gte: new Date(Math.min(...times)), $lte: new Date(Math.max(...times) + 60e3) } }) : 0;
  res.json({
    run_id: runId, expected, stored_unique: seq.size, stored_records: events.length,
    completeness_pct: Math.round((seq.size / expected) * 1000) / 10,
    target_pct: 95, pass: seq.size / expected >= 0.95,
    missing_sequence_numbers: missing.slice(0, 100),
    ingest_lag_ms: { p50: percentile(lags, 50), p95: percentile(lags, 95) },
    parse_errors_in_window: errors,
  });
}));

// ---- exports (analyst+, audited, formula-safe CSV)
function sendExport(res, kind, format, meta, fields, rows) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  if (format === 'json') {
    res.setHeader('Content-Disposition', `attachment; filename="hlpa-${kind}-${stamp}.json"`);
    return res.json({ meta, field_definitions: fields, count: rows.length, records: rows });
  }
  const cols = Object.keys(fields);
  const lines = [
    `# HLPA-DS ${kind} export`,
    `# generated_at=${meta.generated_at.toISOString()} generated_by=${meta.generated_by}`,
    `# range_from=${meta.range.from.toISOString()} range_to=${meta.range.to.toISOString()} rows=${rows.length}${meta.truncated ? ' (TRUNCATED at export limit)' : ''}`,
    `# filters=${JSON.stringify(meta.filters)}`,
    cols.join(','),
    ...rows.map((r) => cols.map((c) => csvCell(c === 'event_id' || c === 'alert_id' ? (r[c] || r._id) : r[c])).join(',')),
  ];
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="hlpa-${kind}-${stamp}.csv"`);
  return res.send(lines.join('\r\n'));
}

function exportFilters(q) {
  const out = {};
  for (const [k, v] of Object.entries(q)) if (k !== 'format' && typeof v === 'string') out[k] = v.slice(0, 100);
  return out;
}

router.get('/exports/events', requireRole('analyst'), asyncH(async (req, res) => {
  const format = req.query.format === 'json' ? 'json' : 'csv';
  const { filter, from, to } = eventFilter(req.query);
  const projection = Object.fromEntries(Object.keys(EVENT_FIELDS).map((k) => [k, 1]));
  const rows = await getDb().collection('events').find(filter, { projection }).sort({ event_time: 1 }).limit(config.exportMaxRows + 1).toArray();
  const truncated = rows.length > config.exportMaxRows;
  if (truncated) rows.pop();
  const meta = { generated_at: new Date(), generated_by: req.user.username, range: { from, to }, filters: exportFilters(req.query), truncated };
  await audit(req, 'export', { target: 'events', details: { format, rows: rows.length, from, to, filters: meta.filters } });
  sendExport(res, 'events', format, meta, EVENT_FIELDS, rows);
}));

router.get('/exports/alerts', requireRole('analyst'), asyncH(async (req, res) => {
  const format = req.query.format === 'json' ? 'json' : 'csv';
  const { from, to } = timeRange(req.query, '24h');
  const filter = { ...alertFilter(req.query), last_seen: { $gte: from, $lte: to } };
  const projection = Object.fromEntries(Object.keys(ALERT_FIELDS).map((k) => [k, 1]));
  const rows = await getDb().collection('alerts').find(filter, { projection }).sort({ first_seen: 1 }).limit(config.exportMaxRows + 1).toArray();
  const truncated = rows.length > config.exportMaxRows;
  if (truncated) rows.pop();
  const meta = { generated_at: new Date(), generated_by: req.user.username, range: { from, to }, filters: exportFilters(req.query), truncated };
  await audit(req, 'export', { target: 'alerts', details: { format, rows: rows.length, from, to, filters: meta.filters } });
  sendExport(res, 'alerts', format, meta, ALERT_FIELDS, rows);
}));

router.get('/exports/report', requireRole('analyst'), asyncH(async (req, res) => {
  const { from, to } = timeRange(req.query, '24h');
  const data = await summary(from, to);
  await audit(req, 'export', { target: 'summary_report', details: { from, to } });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  res.setHeader('Content-Disposition', `attachment; filename="hlpa-summary-report-${stamp}.json"`);
  res.json({ ...data, generated_at: new Date(), generated_by: req.user.username, generator: 'HLPA-DS 1.0.0' });
}));

module.exports = router;
