// Spin up the API against an in-memory-ish mongo using mongodb-memory-server if
// available; otherwise skip (CI note printed). We use a lightweight approach:
// connect to a throwaway database on a MONGO_URL the test environment provides.
const assert = require('node:assert');

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-key-0123456789';
process.env.ADMIN_PASSWORD = 'AdminPass#2026';
process.env.ANALYST_PASSWORD = 'AnalystPass#2026';
process.env.VIEWER_PASSWORD = 'ViewerPass#2026';
process.env.LAB_CIDR = '10.66.0.0/24';
process.env.MONGO_DB = `hlpa_test_${Date.now()}`;

const request = require('supertest');

async function startServer() {
  const db = require('../src/db');
  await db.connect();
  const { seed } = require('../src/seed');
  await seed();
  const { createApp } = require('../src/app');
  return { app: createApp(), db };
}

// Log in and return an agent carrying the session cookie.
async function agentFor(app, username, password) {
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').set('X-Requested-With', 'hlpa').send({ username, password });
  assert.equal(res.status, 200, `login failed for ${username}: ${JSON.stringify(res.body)}`);
  // supertest agent keeps cookies; attach a helper that sets the CSRF header.
  agent.hdr = (req) => req.set('X-Requested-With', 'hlpa');
  return agent;
}

module.exports = { startServer, agentFor, request };
