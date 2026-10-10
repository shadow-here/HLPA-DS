const { getDb } = require('./db');

/**
 * Append an audit record (PRD FR-14 / NFR-10): actor, action, target, time, outcome, reason.
 * Never store secrets in `details`.
 */
async function audit(req, action, { target = null, outcome = 'success', reason = null, details = null } = {}) {
  try {
    await getDb().collection('audit_log').insertOne({
      at: new Date(),
      actor: req && req.user ? req.user.username : (details && details.username) || 'anonymous',
      role: req && req.user ? req.user.role : null,
      action,
      target,
      outcome,
      reason,
      details,
      ip: req ? req.ip : null,
    });
  } catch (err) {
    console.error('[audit] failed to write audit record', err.message);
  }
}

module.exports = { audit };
