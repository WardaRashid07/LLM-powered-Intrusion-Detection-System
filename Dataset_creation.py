"""
IDS Dataset Builder v2
Sources : alerts.log (OPT1) + alerts1.log (LAN)
          eve.json   (LAN)  + opt1_eve.json (OPT1)  [both optional paths]
Output  : dataset.csv  +  dataset.db (table: alerts)
"""

import re, json, sqlite3, pandas as pd
from pathlib import Path
from datetime import datetime, timezone

# ── PATHS ────────────────────────────────────────────────────────────────────
ALERTS_OPT1  = Path("/mnt/user-data/uploads/alerts.log")
ALERTS_LAN   = Path("/mnt/user-data/uploads/alerts1.log")
EVE_LAN      = Path("/mnt/user-data/uploads/eve.json")
EVE_OPT1     = Path("/mnt/user-data/uploads/opt1_eve.json")   # upload when ready

OUT_CSV = Path("/mnt/user-data/outputs/dataset.csv")
OUT_DB  = Path("/mnt/user-data/outputs/dataset.db")
OUT_CSV.parent.mkdir(parents=True, exist_ok=True)

# ── STEP 1: PARSE alerts.log files ───────────────────────────────────────────
ALERT_RE = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)"
    r"\s+\[\*\*\]\s+\[\d+:(?P<sig_id>\d+):\d+\]\s+(?P<signature>.+?)\s+\[\*\*\]"
    r".*?\[Classification:\s*(?P<alert_category>[^\]]+)\]"
    r".*?\[Priority:\s*(?P<priority>\d+)\]"
    r"\s+\{(?P<protocol>\w+)\}"
    r"\s+(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
)

def parse_alerts(path, iface_label):
    rows = []
    with open(path) as f:
        for line in f:
            m = ALERT_RE.search(line)
            if m:
                r = m.groupdict()
                r["priority"]  = int(r["priority"])
                r["src_port"]  = int(r["src_port"])
                r["dst_port"]  = int(r["dst_port"])
                r["interface"] = iface_label
                rows.append(r)
    print(f"[{path.name}]  {len(rows)} rows  (interface: {iface_label})")
    return pd.DataFrame(rows)

# ── STEP 2: PARSE eve.json files ─────────────────────────────────────────────
def parse_eve(path, iface_label):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            if ev.get("event_type") != "alert":
                continue

            flow = ev.get("flow", {})
            http = ev.get("http", {})

            # flow duration
            flow_duration = None
            ts_str  = ev.get("timestamp", "")
            fs_str  = flow.get("start", "")
            if ts_str and fs_str:
                try:
                    def parse_ts(s):
                        s = s[:26].replace("+0000","").replace("Z","")
                        return datetime.fromisoformat(s)
                    flow_duration = round(abs((parse_ts(ts_str) - parse_ts(fs_str)).total_seconds()), 4)
                except Exception:
                    pass

            rows.append({
                "flow_id"        : str(ev.get("flow_id", "")),
                "src_ip"         : ev.get("src_ip"),
                "src_port"       : ev.get("src_port"),
                "dst_ip"         : ev.get("dest_ip"),
                "dst_port"       : ev.get("dest_port"),
                "protocol"       : ev.get("proto"),
                "app_proto"      : ev.get("app_proto"),
                "direction"      : ev.get("direction"),
                "flow_bytes_toserver"   : flow.get("bytes_toserver"),
                "flow_bytes_toclient"   : flow.get("bytes_toclient"),
                "flow_bytes"     : (flow.get("bytes_toserver") or 0) + (flow.get("bytes_toclient") or 0),
                "pkts_toserver"  : flow.get("pkts_toserver"),
                "pkts_toclient"  : flow.get("pkts_toclient"),
                "flow_duration"  : flow_duration,
                "http_user_agent": http.get("http_user_agent") if http else None,
                "payload_printable": ev.get("payload_printable"),
                "_iface"         : iface_label,
            })

    print(f"[{path.name}]  {len(rows)} alert events  (interface: {iface_label})")
    return pd.DataFrame(rows)

# ── STEP 3: MERGE alerts + eve ────────────────────────────────────────────────
def make_fuzzy_key(df):
    return (df["src_ip"].astype(str)  + "|" +
            df["dst_ip"].astype(str)  + "|" +
            df["dst_port"].astype(str)+ "|" +
            df["protocol"].astype(str))

def merge_all(df_alerts, df_eve):
    # fuzzy join: src_ip + dst_ip + dst_port + protocol
    df_eve["_fkey"] = make_fuzzy_key(df_eve)
    eve_lookup = (df_eve.groupby("_fkey")
                        .first()
                        .reset_index()
                        [["_fkey","app_proto","direction",
                          "flow_bytes","flow_bytes_toserver","flow_bytes_toclient",
                          "pkts_toserver","pkts_toclient",
                          "flow_duration","http_user_agent","payload_printable"]])

    df_alerts["_fkey"] = make_fuzzy_key(df_alerts)
    df = df_alerts.merge(eve_lookup, on="_fkey", how="left")
    df.drop(columns="_fkey", inplace=True)
    return df

# ── STEP 4: LABELING ──────────────────────────────────────────────────────────

ATTACK_TYPE_MAP = [
    (r"nmap|port.?scan|fin.?stealth|xmas|null.?scan|udp.?scan|syn.?scan|ack.?scan|window.?scan|os.?detect", "port_scan"),
    (r"hydra|brute.?force|ftp.?brute|ssh.?brute|login.?attempt|password.?spray",                           "brute_force"),
    (r"slowloris|http.?dos|dos|flood|syn.?flood",                                                           "dos"),
    (r"nikto|web.?scan|web.?application.?scan|sql.?inject|xss|directory.?trav",                            "web_scan"),
    (r"smb|netbios|rdp|exploit|shellcode|overflow|ms17",                                                    "exploit"),
    (r"trojan|malware|botnet|c2|c&c|beacon|rat\b",                                                         "malware_c2"),
    (r"icmp|ping.?sweep|arp",                                                                               "info_leak"),
    (r"et.?info|et.?policy|dns",                                                                            "info_leak"),
]

KILL_CHAIN = {
    "port_scan"  : "Reconnaissance",
    "web_scan"   : "Reconnaissance",
    "info_leak"  : "Reconnaissance",
    "brute_force": "Exploitation",
    "exploit"    : "Exploitation",
    "dos"        : "Actions on Objectives",
    "malware_c2" : "Command & Control",
    "other"      : "Unknown",
}

def assign_attack_type(sig):
    s = str(sig).lower()
    for pattern, label in ATTACK_TYPE_MAP:
        if re.search(pattern, s):
            return label
    return "other"

def compute_fp_likelihood(row):
    score = 0
    sig  = str(row.get("signature", ""))
    prio = row.get("priority", 0)

    if sig.upper().startswith("SURICATA"):          score += 40
    if prio == 3:                                    score += 30
    if re.search(r"ET\s*(INFO|POLICY)", sig, re.I): score += 20
    if not row.get("flow_bytes"):                   score += 10

    return min(score, 100)

def label(df):
    df = df.copy()
    df["attack_type"]     = df["signature"].apply(assign_attack_type)
    df["kill_chain_stage"]= df["attack_type"].map(KILL_CHAIN).fillna("Unknown")
    df["fp_likelihood"]   = df.apply(compute_fp_likelihood, axis=1)
    df["ground_truth"]    = df["fp_likelihood"].apply(
                                lambda s: "false_positive" if s >= 60 else "true_positive")
    return df

# ── STEP 5: FINALISE ──────────────────────────────────────────────────────────
FINAL_COLS = [
    "timestamp","signature","sig_id","interface",
    "src_ip","dst_ip","src_port","dst_port",
    "protocol","priority","alert_category",
    "app_proto","direction",
    "flow_bytes","flow_bytes_toserver","flow_bytes_toclient",
    "pkts_toserver","pkts_toclient","flow_duration",
    "http_user_agent","payload_printable",
    "ground_truth","fp_likelihood",
    "attack_type","kill_chain_stage",
]

def finalise(df):
    for col in FINAL_COLS:
        if col not in df.columns:
            df[col] = None
    df = df[FINAL_COLS]
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df

# ── STEP 6: DEDUP ─────────────────────────────────────────────────────────────
def dedup(df):
    before = len(df)
    df = df.drop_duplicates(
        subset=["timestamp","signature","src_ip","dst_ip","dst_port"]
    )
    print(f"[dedup]  {before} → {len(df)} rows")
    return df

# ── STEP 7: SAVE ──────────────────────────────────────────────────────────────
def save(df):
    df.to_csv(OUT_CSV, index=False)
    print(f"[output] CSV → {OUT_CSV}  ({len(df)} rows)")

    conn = sqlite3.connect(OUT_DB)
    df.to_sql("alerts", conn, if_exists="replace", index=False)
    for col in ["src_ip","ground_truth","attack_type","fp_likelihood","interface"]:
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{col} ON alerts({col})")
    conn.commit()
    conn.close()
    print(f"[output] DB  → {OUT_DB}  (table: alerts)")

# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  IDS Dataset Builder v2")
    print("=" * 55)

    # --- parse alerts ---
    df_opt1 = parse_alerts(ALERTS_OPT1, "OPT1")
    df_lan  = parse_alerts(ALERTS_LAN,  "LAN")
    df_alerts = pd.concat([df_opt1, df_lan], ignore_index=True)

    # --- parse eve ---
    eve_frames = []
    if EVE_LAN.exists():
        eve_frames.append(parse_eve(EVE_LAN, "LAN"))
    if EVE_OPT1.exists():
        eve_frames.append(parse_eve(EVE_OPT1, "OPT1"))

    if eve_frames:
        df_eve = pd.concat(eve_frames, ignore_index=True)
        df = merge_all(df_alerts, df_eve)
    else:
        print("[eve] no eve files found — skipping enrichment")
        df = df_alerts.copy()

    # --- label, dedup, finalise ---
    df = label(df)
    df = dedup(df)
    df = finalise(df)

    # --- stats ---
    print("\n── Label distribution ──")
    print(df["ground_truth"].value_counts().to_string())
    print("\n── Attack types ──")
    print(df["attack_type"].value_counts().to_string())
    print("\n── Kill chain stages ──")
    print(df["kill_chain_stage"].value_counts().to_string())
    print("\n── Interface split ──")
    print(df["interface"].value_counts().to_string())
    print("\n── fp_likelihood distribution ──")
    bins = [0,10,20,30,40,50,60,70,80,90,100]
    print(pd.cut(df["fp_likelihood"], bins=bins, include_lowest=True)
            .value_counts().sort_index().to_string())
    print(f"\n── eve enrichment coverage ──")
    print(f"flow_bytes    filled: {df['flow_bytes'].notna().sum()} / {len(df)}")
    print(f"flow_duration filled: {df['flow_duration'].notna().sum()} / {len(df)}")
    print(f"app_proto     filled: {df['app_proto'].notna().sum()} / {len(df)}")

    save(df)
    print("\nDone ✓")

if __name__ == "__main__":
    main()