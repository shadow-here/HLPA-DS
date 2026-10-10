const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { getDb } = require('../db');
const { audit } = require('../audit');
const { COOKIE, issueToken, cookieOptions, requireAuth } = require('../auth');
const { str, asyncH } = require('../util');

const router = express.Router();

// Rate limit sign-in attempts (PRD 6.4 / 7.2).
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: parseInt(process.env.LOGIN_RATE_LIMIT || '10', 10),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'too many sign-in attempts, try again later' },
});

// A constant hash so unknown usernames take the same time as wrong passwords.
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

router.post('/login', loginLimiter, asyncH(async (req, res) => {
  const username = str(req.body && req.body.username, 64);
  const password = req.body && typeof req.body.password === 'string' ? req.body.password.slice(0, 200) : '';
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

  const user = await getDb().collection('users').findOne({ username });
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok || user.disabled) {
    await audit(req, 'login', { outcome: 'failure', reason: 'invalid credentials or disabled account', details: { username } });
    return res.status(401).json({ error: 'invalid username or password' });
  }
  await getDb().collection('users').updateOne({ _id: user._id }, { $set: { last_login_at: new Date() } });
  req.user = { username: user.username, role: user.role };
  await audit(req, 'login', { outcome: 'success' });
  res.cookie(COOKIE, issueToken(user), cookieOptions());
  return res.json({ username: user.username, role: user.role });
}));

router.post('/logout', requireAuth, asyncH(async (req, res) => {
  await audit(req, 'logout');
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
}));

router.get('/me', requireAuth, (req, res) => res.json(req.user));

module.exports = router;
