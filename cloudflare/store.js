// SQLite rows hold complete documents (up to 8 MiB); the HTTP surface caps writes at 5 MiB.
export class Store {
  constructor(storage) {
    this.storage = storage;
    this.sql = storage.sql;
    this.sql.exec('CREATE TABLE IF NOT EXISTS documents (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
  }

  get(key, defaultValue = null) {
    const row = this.sql.exec('SELECT value FROM documents WHERE key = ?', key).toArray()[0];
    return row ? JSON.parse(row.value) : defaultValue;
  }

  put(key, value) {
    this.sql.exec('INSERT INTO documents (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, JSON.stringify(value));
  }

  delete(key) { this.sql.exec('DELETE FROM documents WHERE key = ?', key); }

  list(prefix) {
    return this.sql.exec('SELECT key, value FROM documents WHERE substr(key, 1, ?) = ? ORDER BY key', prefix.length, prefix).toArray()
      .map(row => ({ key: row.key, value: JSON.parse(row.value) }));
  }

  transaction(fn) { return this.storage.transactionSync(fn); }
}
