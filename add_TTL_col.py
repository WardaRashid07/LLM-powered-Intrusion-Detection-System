import sqlite3
conn = sqlite3.connect("ids_alerts.db")
conn.execute("ALTER TABLE alerts ADD COLUMN ttl INTEGER DEFAULT 0")
conn.commit()
conn.close()