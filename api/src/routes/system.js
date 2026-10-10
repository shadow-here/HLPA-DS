const express = require('express');
const config = require('../config');
const { getDb, ping } = require('../db');
const controller = require('../controller-client');
const { asyncH } = require('../util');

// Public, non-sensitive health (no credentials, no internal config).
const publicRouter = express.Router();
publicRouter.get('/health', asyncH(async (req, res) => {
  const dbOk = await ping();
  let collector = 'unknown';
  if (dbOk) {
    const st = await getDb().collection('system_status').findOne({ _id: 'collector' }, { projection: { heartbeat_at: 1 } });
    collector = st && (Date.now() - new Date(st.heartbeat_at).getTime()) / 1000 < config.collectorStaleSeconds ? 'ok' : 'stale';
  }
  res.status(dbOk ? 200 : 503).json({ status: dbOk ? 'ok' : 'degraded', api: 'ok', database: dbOk ? 'ok' : 'down', collector });
}));

// Authenticated detailed status (FR-16)
const router = express.Router();
router.get('/status', asyncH(async (req, res) => {
  const db = getDb();
  const [collector, decoys, counts, stats, ctrl, recentErrors] = await Promise.all([
    db.collection('system_status').findOne({ _id: 'collector' }),
    db.collection('decoys').find({}, { projection: { name: 1, enabled: 1, health: 1, last_event_at: 1, isolation: 1, container: 1 } }).toArray(),
    Promise.all(['events', 'alerts', 'raw_events', 'ingest_errors', 'audit_log'].map(async (c) => [c, await db.collection(c).estimatedDocumentCount()])),
    db.command({ dbStats: 1 }).catch(() => null),
    controller.status(),
    db.collection('ingest_errors').countDocuments({ at: { $gte: new Date(Date.now() - 3600e3) } }),
  ]);
  const hbAge = collector ? (Date.now() - new Date(collector.heartbeat_at).getTime()) / 1000 : null;
  res.json({
    api: { status: 'ok', uptime_s: Math.round(process.uptime()), node: process.version },
    collector: collector ? {
      status: hbAge < config.collectorStaleSeconds ? 'ok' : 'stale',
      heartbeat_at: collector.heartbeat_at, heartbeat_age_s: Math.round(hbAge),
      last_event_at: collector.last_event_at, stats: collector.stats, sources: collector.sources,
      rules_loaded: collector.rules_loaded, indicators_loaded: collector.indicators_loaded,
      approved_sources: collector.approved_sources,
    } : { status: 'never seen' },
    storage: {
      status: 'ok',
      collections: Object.fromEntries(counts),
      data_size_bytes: stats ? stats.dataSize : null,
      storage_size_bytes: stats ? stats.storageSize : null,
    },
    ingest_errors_last_hour: recentErrors,
    controller: ctrl.ok ? { reachable: true, containers: ctrl.containers } : { reachable: false, error: ctrl.error },
    decoys,
    server_time: new Date(),
  });
}));

module.exports = { publicRouter, router };
