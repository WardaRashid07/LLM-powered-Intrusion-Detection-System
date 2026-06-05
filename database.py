import sqlite3

DB_PATH = "ids_alerts.db"


def init_db():
    """Initialize database connection"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return conn


def get_alerts(conn, limit=500):
    """Get recent alerts from database"""
    cursor = conn.execute("""
        SELECT 
            timestamp, 
            signature, 
            src_ip, 
            dst_ip, 
            llm_classification, 
            attack_type, 
            explanation, 
            risk_score, 
            false_positive_likelihood,
            priority,
            protocol,
            src_port,
            dst_port
        FROM alerts 
        ORDER BY created_at DESC 
        LIMIT ?
    """, (limit,))

    columns = [description[0] for description in cursor.description]
    rows = cursor.fetchall()

    alerts = []
    for row in rows:
        alert = dict(zip(columns, row))
        alerts.append(alert)

    return alerts