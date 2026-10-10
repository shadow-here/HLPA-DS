const { MongoClient } = require('mongodb');
const config = require('./config');

let client;
let db;

async function connect(url = config.mongoUrl, name = config.mongoDb) {
  for (let attempt = 1; attempt <= 60; attempt++) {
    try {
      client = new MongoClient(url, { serverSelectionTimeoutMS: 3000 });
      await client.connect();
      await client.db(name).command({ ping: 1 });
      db = client.db(name);
      return db;
    } catch (err) {
      console.warn(`[db] waiting for database (${attempt}/60): ${err.message}`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error('database unreachable');
}

function getDb() {
  if (!db) throw new Error('database not connected');
  return db;
}

async function ping() {
  try {
    await getDb().command({ ping: 1 });
    return true;
  } catch {
    return false;
  }
}

async function close() {
  if (client) await client.close();
  client = undefined;
  db = undefined;
}

module.exports = { connect, getDb, ping, close };
