// Client for the decoy-controller sidecar (the only component with Docker access).
// It can only start/stop/inspect the allow-listed decoy containers.
const config = require('./config');

async function call(method, path) {
  if (!config.controllerUrl) {
    return { ok: false, error: 'decoy controller not configured' };
  }
  try {
    const res = await fetch(`${config.controllerUrl}${path}`, {
      method,
      headers: { 'X-Controller-Token': config.controllerToken },
      signal: AbortSignal.timeout(15000),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, error: body.error || `controller HTTP ${res.status}`, body };
    return { ok: true, ...body };
  } catch (err) {
    return { ok: false, error: `controller unreachable: ${err.message}` };
  }
}

module.exports = {
  status: () => call('GET', '/status'),
  start: (name) => call('POST', `/containers/${encodeURIComponent(name)}/start`),
  stop: (name) => call('POST', `/containers/${encodeURIComponent(name)}/stop`),
};
