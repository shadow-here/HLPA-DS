const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { requireAuth, requireCsrfHeader } = require('./auth');
const { HttpError } = require('./util');

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 'loopback, linklocal, uniquelocal');
  // 'simple' parser: query values are plain strings, never nested objects ({$ne: ..} injection).
  app.set('query parser', 'simple');
  app.use(helmet());
  app.use(express.json({ limit: '64kb' }));
  app.use(cookieParser());
  app.use((req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  const { publicRouter, router: systemRouter } = require('./routes/system');
  app.use('/api', publicRouter); // GET /api/health
  app.use('/api', requireCsrfHeader);
  app.use('/api/auth', require('./routes/auth'));

  // Everything below requires a valid session.
  app.use('/api', requireAuth);
  app.use('/api/system', systemRouter);
  app.use('/api/decoys', require('./routes/decoys'));
  app.use('/api/events', require('./routes/events'));
  app.use('/api/alerts', require('./routes/alerts'));
  app.use('/api', require('./routes/reports'));
  app.use('/api', require('./routes/admin'));

  app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));

  // Safe error messages: no stack traces or internals to the client.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message, details: err.details });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid JSON body' });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'request body too large' });
    console.error('[api] unhandled error', err);
    return res.status(500).json({ error: 'internal server error' });
  });
  return app;
}

module.exports = { createApp };
