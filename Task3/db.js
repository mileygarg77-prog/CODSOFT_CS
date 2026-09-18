const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  )`);
});

db.run(`CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT,
  owner_id INTEGER,
  iv TEXT,
  authTag TEXT
)`);

module.exports = db;