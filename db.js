const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = path.join(__dirname, 'akihara.db');
const db = new Database(dbPath);

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance INTEGER DEFAULT 1000,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    last_daily TEXT,
    last_weekly TEXT,
    last_monthly TEXT
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT,
    amount INTEGER,
    details TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Create admin if not exists
const admin = db.prepare('SELECT id FROM users WHERE email = ?').get('zerr59');
if (!admin) {
  const hash = bcrypt.hashSync('12345678', 10);
  db.prepare(`
    INSERT INTO users (email, password, balance, is_admin)
    VALUES (?, ?, 100000, 1)
  `).run('zerr59', hash);
  console.log('✅ Admin créé : zerr59 / 12345678');
}

module.exports = db;
