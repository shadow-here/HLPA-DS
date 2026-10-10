const config = require('./config');
const db = require('./db');
const { seed } = require('./seed');
const { createApp } = require('./app');

async function main() {
  await db.connect();
  await seed();
  const app = createApp();
  const server = app.listen(config.port, () => console.log(`[api] HLPA-DS API listening on :${config.port}`));
  const shutdown = () => { server.close(() => db.close().then(() => process.exit(0))); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  console.error('[api] fatal', err);
  process.exit(1);
});
