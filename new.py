import sqlite3

# Connect to your database
DB_PATH = r"D:\User\warda\Downloads\IDS_Project\ids_alerts.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Delete all alerts
cursor.execute("DELETE FROM alerts")
conn.commit()

# Verify it's empty
count = cursor.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
print(f"✅ Database cleared! Now has {count} alerts.")

conn.close()