const crypto = require('crypto');

function int(name, def) {
  const v = parseInt(process.env[name] || '', 10);
  return Number.isFinite(v) ? v : def;
}

let jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || jwtSecret.length < 16) {
  jwtSecret = crypto.randomBytes(32).toString('hex');
  if (process.env.NODE_ENV !== 'test') {
    console.warn('[config] JWT_SECRET missing/short - generated a random one (sessions reset on restart). Set it in .env');
  }
}

module.exports = {
  port: int('PORT', 4000),
  mongoUrl: process.env.MONGO_URL || 'mongodb://localhost:27017',
  mongoDb: process.env.MONGO_DB || 'hlpa',
  jwtSecret,
  sessionHours: int('SESSION_HOURS', 8),
  cookieSecure: (process.env.COOKIE_SECURE || 'false') === 'true',
  decoysFile: process.env.DECOYS_FILE || require('path').join(__dirname, '..', '..', 'config', 'decoys.json'),
  labCidr: process.env.LAB_CIDR || '10.66.0.0/24',
  controllerUrl: process.env.CONTROLLER_URL || '',
  controllerToken: process.env.CONTROLLER_TOKEN || '',
  collectorStaleSeconds: int('COLLECTOR_STALE_SECONDS', 20),
  exportMaxRows: int('EXPORT_MAX_ROWS', 50000),
  seedUsers: [
    { username: process.env.ADMIN_USERNAME || 'admin', password: process.env.ADMIN_PASSWORD, role: 'admin' },
    { username: process.env.ANALYST_USERNAME || 'analyst', password: process.env.ANALYST_PASSWORD, role: 'analyst' },
    { username: process.env.VIEWER_USERNAME || 'viewer', password: process.env.VIEWER_PASSWORD, role: 'viewer' },
  ],
};
