// Small, dependency-free validation and formatting helpers.

class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const ALERT_STATES = ['New', 'Acknowledged', 'Investigating', 'Contained (lab only)', 'Resolved', 'False Positive'];
const OPEN_STATES = ['New', 'Acknowledged', 'Investigating', 'Contained (lab only)'];

// PRD 4.5 state machine
const TRANSITIONS = {
  New: ['Acknowledged', 'False Positive'],
  Acknowledged: ['Investigating', 'False Positive', 'Resolved'],
  Investigating: ['Contained (lab only)', 'Resolved', 'False Positive'],
  'Contained (lab only)': ['Investigating', 'Resolved'],
  Resolved: ['Investigating'],
  'False Positive': ['Investigating'],
};
const NOTE_REQUIRED = ['Contained (lab only)', 'Resolved', 'False Positive'];

/** Coerce a query value to a bounded plain string (blocks {$ne:..} style injection). */
function str(v, max = 200) {
  if (v === undefined || v === null) return undefined;
  if (Array.isArray(v)) v = v[0];
  if (typeof v !== 'string' && typeof v !== 'number') return undefined;
  const s = String(v).trim();
  if (!s) return undefined;
  return s.slice(0, max);
}

function intIn(v, def, min, max) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}

function date(v) {
  const s = str(v, 40);
  if (!s) return undefined;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) throw new HttpError(400, `invalid date: ${s}`);
  return d;
}

/** Resolve a time range from ?from&to or ?range=15m|1h|24h|7d|30d. Default 24h. */
function timeRange(q, defaultRange = '24h') {
  let to = date(q.to) || new Date();
  let from = date(q.from);
  if (!from) {
    const r = str(q.range, 8) || defaultRange;
    const m = /^(\d+)([mhd])$/.exec(r);
    if (!m) throw new HttpError(400, 'range must look like 15m, 1h, 24h or 7d');
    const mult = { m: 60e3, h: 3600e3, d: 86400e3 }[m[2]];
    from = new Date(to.getTime() - parseInt(m[1], 10) * mult);
  }
  if (from > to) throw new HttpError(400, '"from" must be before "to"');
  return { from, to };
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isIp(s) {
  if (typeof s !== 'string') return false;
  const v4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  return v4.test(s) || (/^[0-9a-fA-F:]+$/.test(s) && s.includes(':') && s.length <= 45);
}

function ipToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
}

function inCidr(ip, cidr) {
  if (!isIp(ip) || ip.includes(':')) return false;
  const [base, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

/** CSV cell: quote, and neutralise spreadsheet formula triggers (PRD 6.3). */
function csvCell(v) {
  if (v === null || v === undefined) return '';
  let s = v instanceof Date ? v.toISOString() : Array.isArray(v) ? v.join(';') : typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  if (/[",\n\r]/.test(s)) s = `"${s.replace(/"/g, '""')}"`;
  return s;
}

function percentile(values, p) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

module.exports = {
  HttpError, SEVERITIES, ALERT_STATES, OPEN_STATES, TRANSITIONS, NOTE_REQUIRED,
  str, intIn, date, timeRange, escapeRegex, isIp, inCidr, csvCell, percentile, asyncH,
};
