const fs = require('fs');
const bcrypt = require('bcryptjs');
const config = require('./config');
const { getDb } = require('./db');

async function ensureIndexes() {
  const db = getDb();
  await db.collection('users').createIndex({ username: 1 }, { unique: true });
  await db.collection('audit_log').createIndex({ at: -1 });
  await db.collection('approved_sources').createIndex({ ip: 1 }, { unique: true });
  await db.collection('indicators').createIndex({ value: 1 }, { unique: true });
}

async function seed() {
  const db = getDb();
  await ensureIndexes();

  // Users: created once from environment variables. Passwords are bcrypt-hashed.
  for (const u of config.seedUsers) {
    if (!u.password) continue;
    const exists = await db.collection('users').findOne({ username: u.username });
    if (!exists) {
      await db.collection('users').insertOne({
        username: u.username,
        role: u.role,
        password_hash: await bcrypt.hash(u.password, 12),
        disabled: false,
        created_at: new Date(),
        created_by: 'seed',
      });
      console.log(`[seed] created ${u.role} user '${u.username}'`);
    }
  }
  if ((await db.collection('users').countDocuments({ role: 'admin' })) === 0) {
    console.warn('[seed] no admin user exists - set ADMIN_PASSWORD in .env and restart the api');
  }

  // Decoy registry: seeded from config/decoys.json, starts DISABLED until the
  // isolation checklist is completed in the dashboard (FR-04).
  if (fs.existsSync(config.decoysFile)) {
    const decoys = JSON.parse(fs.readFileSync(config.decoysFile, 'utf8'));
    for (const d of decoys) {
      const exists = await db.collection('decoys').findOne({ _id: d._id });
      if (!exists) {
        await db.collection('decoys').insertOne({
          ...d,
          enabled: false,
          state: 'registered',
          config_version: 1,
          is_decoy: true,
          created_at: new Date(),
          created_by: 'seed',
          health: { status: 'disabled', detail: 'not yet enabled' },
        });
        console.log(`[seed] registered decoy ${d._id}`);
      }
    }
  }

  await db.collection('settings').updateOne(
    { _id: 'retention' },
    { $setOnInsert: { events_days: 30, alerts_days: 90 } },
    { upsert: true },
  );
}

module.exports = { seed, ensureIndexes };
