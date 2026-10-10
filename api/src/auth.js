const jwt = require('jsonwebtoken');
const config = require('./config');
const { getDb } = require('./db');
const { audit } = require('./audit');

const COOKIE = 'hlpa_session';
const ROLE_RANK = { viewer: 1, analyst: 2, admin: 3 };

function issueToken(user) {
  return jwt.sign({ sub: user.username, role: user.role }, config.jwtSecret, {
    expiresIn: `${config.sessionHours}h`,
  });
}

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.cookieSecure,
    maxAge: config.sessionHours * 3600 * 1000,
    path: '/',
  };
}

/** Authenticate every protected request on the server (not only in the UI). */
async function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies[COOKIE];
  if (!token) return res.status(401).json({ error: 'authentication required' });
  try {
    const payload = jwt.verify(token, config.jwtSecret);
    // Re-read the account so disabling a user or changing a role applies immediately.
    const user = await getDb().collection('users').findOne(
      { username: payload.sub },
      { projection: { password_hash: 0 } },
    );
    if (!user || user.disabled) return res.status(401).json({ error: 'session no longer valid' });
    req.user = { username: user.username, role: user.role };
    return next();
  } catch {
    return res.status(401).json({ error: 'session expired or invalid' });
  }
}

/** Role gate. Denials are audited (failed access attempts, PRD 7.2). */
function requireRole(minRole) {
  return async (req, res, next) => {
    if (req.user && ROLE_RANK[req.user.role] >= ROLE_RANK[minRole]) return next();
    await audit(req, 'access_denied', {
      target: `${req.method} ${req.originalUrl.split('?')[0]}`,
      outcome: 'denied',
      reason: `requires role ${minRole}`,
    });
    return res.status(403).json({ error: `forbidden: requires ${minRole} role` });
  };
}

/** Simple CSRF defence for cookie auth: state-changing requests must carry a custom header. */
function requireCsrfHeader(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.get('X-Requested-With') !== 'hlpa') {
    return res.status(403).json({ error: 'missing X-Requested-With header' });
  }
  return next();
}

module.exports = { COOKIE, ROLE_RANK, issueToken, cookieOptions, requireAuth, requireRole, requireCsrfHeader };
