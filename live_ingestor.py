import paramiko
import requests
import sqlite3
import json
import time
import re
import hashlib
from datetime import datetime

# ── CONFIG ── change these to match your setup
PFSENSE_IP = "192.168.100.1"
PFSENSE_USER = "admin"
PFSENSE_PASS = "Password123!"
ALERTS_PATH = "/var/log/suricata/suricata_em135727/alerts.log"
COLAB_URL = "https://stony-aim-purist.ngrok-free.dev/classify"  # update each session
DB_PATH = r"D:\User\warda\Downloads\IDS_Project\ids_alerts.db"
POLL_EVERY = 10  # seconds


# ── DATABASE ──
def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, signature TEXT,
        src_ip TEXT, dst_ip TEXT,
        src_port INTEGER, dst_port INTEGER,
        protocol TEXT, priority INTEGER,
        classification_suricata TEXT,
        llm_classification TEXT,
        attack_type TEXT, explanation TEXT,
        risk_score INTEGER,
        false_positive_likelihood INTEGER,
        ttl INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    # ── NEW: Create attacker_profiles table ──
    conn.execute('''CREATE TABLE IF NOT EXISTS attacker_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT UNIQUE,
        methodology TEXT,
        objective TEXT,
        skill_level TEXT,
        recommended_response TEXT,
        attack_count INTEGER,
        time_span TEXT,
        ports_targeted TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    return conn

eve_ttl_cache = {}
# ── PARSER ──
def parse_line(line):
    line = line.strip()
    if not line:
        return None
    pattern = r"""
        ^(?P<timestamp>\S+)\s+
        \[\*\*\]\s+
        \[[^\]]+\]\s+
        (?P<signature>.+?)\s+
        \[\*\*\]\s+
        \[Classification:\s*(?P<classification>[^\]]+)\]\s+
        \[Priority:\s*(?P<priority>\d+)\]\s+
        \{(?P<protocol>[^\}]+)\}\s+
        (?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+
        (?P<dst_ip>[\d.]+):(?P<dst_port>\d+)
    """
    m = re.match(pattern, line, re.VERBOSE)
    if not m:
        return None
    src_ip = m.group('src_ip')

    # Get TTL from cache (from eve.json)
    ttl = eve_ttl_cache.get(src_ip, 0)
    return {
        'timestamp': m.group('timestamp'),
        'signature': m.group('signature'),
        'classification_suricata': m.group('classification'),
        'priority': int(m.group('priority')),
        'protocol': m.group('protocol'),
        'src_ip': m.group('src_ip'),
        'src_port': int(m.group('src_port')),
        'dst_ip': m.group('dst_ip'),
        'dst_port': int(m.group('dst_port')),
    }


# ── FETCH FROM PFSENSE ──
def fetch_alerts_from_pfsense():
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(PFSENSE_IP, username=PFSENSE_USER,
                    password=PFSENSE_PASS, timeout=10)
        _, stdout, _ = ssh.exec_command(f"cat {ALERTS_PATH}")
        alert_lines = stdout.read().decode('utf-8', errors='ignore').splitlines()

        EVE_PATH = "/var/log/suricata/suricata_em135727/eve.json"
        _, stdout, _ = ssh.exec_command(f"tail -100 {EVE_PATH}")
        eve_lines = stdout.read().decode('utf-8', errors='ignore').splitlines()
        ssh.close()

        global eve_ttl_cache
        for line in eve_lines:
            try:
                data = json.loads(line)
                if 'alert' in data and 'ttl' in data:
                    src_ip = data.get('src_ip', '')
                    ttl = data.get('ttl', 0)
                    if src_ip:
                        eve_ttl_cache[src_ip] = ttl
            except:
                pass
        return alert_lines
    except Exception as e:
        print(f"[SSH ERROR] {e}")
        return []


# ── SEND TO COLAB API ──
def classify_via_api(alert):
    try:
        response = requests.post(
            COLAB_URL,
            json=alert,
            timeout=30
        )
        return response.json()
    except Exception as e:
        print(f"[API ERROR] {e}")
        return {
            'classification': 'error',
            'attack_type': 'unknown',
            'explanation': 'API unreachable',
            'risk_score': 5,
            'false_positive_likelihood': 50
        }


# ── SAVE TO DB ──
def save(conn, alert, result):
    conn.execute('''INSERT INTO alerts
        (timestamp, signature, src_ip, dst_ip, src_port, dst_port,
         protocol, priority, classification_suricata,
         llm_classification, attack_type, explanation,
         risk_score, false_positive_likelihood, ttl)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        alert['timestamp'], alert['signature'],
        alert['src_ip'], alert['dst_ip'],
        alert['src_port'], alert['dst_port'],
        alert['protocol'], alert['priority'],
        alert['classification_suricata'],
        result.get('classification', 'error'),
        result.get('attack_type', 'unknown'),
        result.get('explanation', ''),
        result.get('risk_score', 5),
        result.get('false_positive_likelihood', 50),
        alert.get('ttl', 0)
    ))
    conn.commit()


# ============================================
# ── NEW: ATTACKER PROFILING FUNCTIONS ──
# ============================================

def build_attacker_profile(conn, src_ip):
    """Build attacker profile from all alerts from same source IP"""

    # Query all alerts from this attacker
    cursor = conn.execute('''
        SELECT signature, attack_type, dst_port, timestamp, risk_score, created_at
        FROM alerts 
        WHERE src_ip = ? AND llm_classification = 'hack'
        ORDER BY created_at ASC
    ''', (src_ip,))

    alerts = cursor.fetchall()

    # Need at least 2 alerts for a meaningful profile
    if len(alerts) < 2:
        return None

    # Extract data for profile
    attack_sequence = []
    ports = set()
    timestamps = []
    risks = []

    for alert in alerts:
        signature, attack_type, dst_port, timestamp, risk, created_at = alert
        attack_sequence.append(attack_type or "unknown")
        if dst_port and dst_port > 0:
            ports.add(str(dst_port))
        timestamps.append(created_at or timestamp)
        risks.append(risk or 0)

    # Build prompt for LLM
    profile_prompt = f"""You are a security analyst. Analyze this attacker's behavior pattern and return ONLY JSON.

Attacker IP: {src_ip}
Total attacks: {len(alerts)}
Attack sequence: {' → '.join(attack_sequence)}
Ports targeted: {list(ports)}
Time span: {str(timestamps[0])[:16] if timestamps[0] else 'unknown'} to {str(timestamps[-1])[:16] if timestamps[-1] else 'unknown'}
Max risk score: {max(risks)}

Respond with:
{{"methodology": "reconnaissance/exploitation/disruption/mixed", "objective": "what attacker wants", "skill_level": "script_kiddie/intermediate/advanced", "recommended_response": "action to take", "summary": "one sentence summary"}}"""

    # Send to Colab API for analysis
    try:
        # Create a fake alert structure for the API
        profile_alert = {
            "signature": profile_prompt
            , "src_ip": src_ip}
        result = classify_via_api(profile_alert)
        return result
    except Exception as e:
        print(f"  [Profile Error] {e}")
        return {
            "methodology": "unknown",
            "objective": "unknown",
            "skill_level": "unknown",
            "recommended_response": f"Block IP {src_ip} and investigate",
            "summary": f"Attacker {src_ip} launched {len(alerts)} attacks"
        }


def check_and_profile_attackers(conn):
    """Check for attackers with 2+ alerts and create profiles"""

    # Get all attacker IPs with 2+ hack alerts
    cursor = conn.execute('''
        SELECT src_ip, COUNT(*) as cnt
        FROM alerts 
        WHERE llm_classification = 'hack'
        GROUP BY src_ip
        HAVING cnt >= 2
    ''')

    for row in cursor:
        src_ip, count = row

        # Check if already profiled
        existing = conn.execute(
            'SELECT 1 FROM attacker_profiles WHERE src_ip = ?', (src_ip,)
        ).fetchone()

        if not existing:
            print(f"\n  🔍 Building profile for attacker {src_ip} ({count} attacks)")
            profile = build_attacker_profile(conn, src_ip)

            if profile:
                # Get ports as string
                ports_cursor = conn.execute('''
                    SELECT DISTINCT dst_port FROM alerts 
                    WHERE src_ip = ? AND dst_port > 0
                ''', (src_ip,))
                ports = [str(p[0]) for p in ports_cursor.fetchall() if p[0]]

                # Get time span
                time_cursor = conn.execute('''
                    SELECT MIN(created_at), MAX(created_at) FROM alerts 
                    WHERE src_ip = ?
                ''', (src_ip,))
                start, end = time_cursor.fetchone()

                conn.execute('''
                    INSERT OR REPLACE INTO attacker_profiles 
                    (src_ip, methodology, objective, skill_level, recommended_response, 
                     attack_count, time_span, ports_targeted)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    src_ip,
                    profile.get('methodology', 'unknown'),
                    profile.get('objective', 'unknown'),
                    profile.get('skill_level', 'unknown'),
                    profile.get('recommended_response', f'Block {src_ip}'),
                    count,
                    f"{start} to {end}" if start else "unknown",
                    ', '.join(ports) if ports else 'none'
                ))
                conn.commit()
                print(f"  ✅ Profile saved for {src_ip}")
                print(f"     📊 Summary: {profile.get('summary', 'Unknown')[:100]}")


# ── MAIN LOOP ──
def main():
    conn = init_db()
    seen = set()
    print(f"[LLM-IDS] Live ingestor started — polling pfSense every {POLL_EVERY}s")
    print(f"[LLM-IDS] API: {COLAB_URL}")
    print("[LLM-IDS] Dashboard: streamlit run dashboard.py\n")

    while True:
        lines = fetch_alerts_from_pfsense()
        new_count = 0

        for line in lines:
            h = hashlib.md5(line.encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)

            alert = parse_line(line)
            if not alert:
                continue

            result = classify_via_api(alert)
            save(conn, alert, result)
            new_count += 1

            icon = "🔴" if result.get('risk_score', 0) >= 7 else "🟡"
            print(f"{icon} {alert['signature'][:50]}")
            print(f"   → {result.get('classification', '?').upper()} | "
                  f"Risk {result.get('risk_score', '?')}/10 | "
                  f"{result.get('explanation', '')[:80]}")

        # ── NEW: Check for attacker profiles after new alerts ──
        if new_count > 0:
            check_and_profile_attackers(conn)

        if new_count == 0:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Waiting for alerts...",
                  end='\r')

        time.sleep(POLL_EVERY)


if __name__ == '__main__':
    main()