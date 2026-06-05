import streamlit as st
import pandas as pd
import sqlite3
import time
import os
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import requests

# ── PAGE CONFIG ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="LLM-IDS | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CONSTANTS ────────────────────────────────────────────────────────────────
BG_BASE    = "#060A12"
BG_CARD    = "#0E1626"
BG_DEEP    = "#111C30"
BLUE       = "#2563EB"
BLUE_LIGHT = "#38BDF8"
WHITE      = "#F8FAFC"
SLATE      = "#94A3B8"
BORDER     = "#1E293B"
RED        = "#EF4444"
AMBER      = "#F59E0B"
GREEN      = "#10B981"
RED_DIM    = "#450A0A"
AMBER_DIM  = "#451A03"
GREEN_DIM  = "#022C22"

DB_PATH    = "ids_alerts.db"
COLAB_URL  = "https://stony-aim-purist.ngrok-free.dev/classify"   # paste your ngrok URL here for live profiling

# ── CSS ──────────────────────────────────────────────────────────────────────
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Inter:wght@300;400;500;600;700;800&display=swap');

html, body, [class*="css"] {{
    font-family: 'Inter', sans-serif !important;
    background: {BG_BASE} !important;
}}
.stApp {{ background: {BG_BASE} !important; }}
#MainMenu, footer, header {{ visibility: hidden; }}

/* Sidebar */
[data-testid="stSidebar"] {{
    background: {BG_CARD} !important;
    border-right: 1px solid {BORDER} !important;
}}
[data-testid="stSidebar"] * {{ color: {SLATE} !important; }}
[data-testid="stSidebar"] h1,[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,[data-testid="stSidebar"] strong {{
    color: {WHITE} !important;
}}

/* ── TOPBAR ── */
.topbar {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 18px 0 14px; border-bottom: 1px solid {BORDER};
    margin-bottom: 24px;
}}
.topbar-left {{ display: flex; align-items: center; gap: 14px; }}
.topbar-logo {{
    width: 40px; height: 40px; background: {BLUE};
    border-radius: 10px; display: flex; align-items: center;
    justify-content: center; font-size: 20px;
}}
.topbar-title {{
    font-size: 22px; font-weight: 800; color: {WHITE};
    letter-spacing: -0.03em; line-height: 1;
}}
.topbar-sub {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: {SLATE}; margin-top: 3px;
}}
.live-pill {{
    display: flex; align-items: center; gap: 6px;
    background: {GREEN_DIM}; border: 1px solid {GREEN};
    border-radius: 20px; padding: 5px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px; color: {GREEN}; font-weight: 600;
}}
.live-dot {{
    width: 7px; height: 7px; background: {GREEN};
    border-radius: 50%; animation: pulse 1.5s infinite;
}}
@keyframes pulse {{
    0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }}
}}

/* ── SECTION LABELS ── */
.section-label {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px; font-weight: 700;
    letter-spacing: 0.15em; text-transform: uppercase;
    color: {SLATE}; margin: 28px 0 14px;
    padding-bottom: 8px; border-bottom: 1px solid {BORDER};
    display: flex; align-items: center; gap: 8px;
}}
.section-label::before {{
    content: ''; display: block;
    width: 3px; height: 14px;
    background: {BLUE}; border-radius: 2px;
}}

/* ── METRIC CARDS ── */
.metric-grid {{
    display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px;
    margin-bottom: 4px;
}}
.metric-card {{
    background: {BG_CARD}; border: 1px solid {BORDER};
    border-radius: 12px; padding: 18px 20px;
    position: relative; overflow: hidden;
}}
.metric-card::after {{
    content: ''; position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    border-radius: 12px 12px 0 0;
}}
.mc-blue::after   {{ background: linear-gradient(90deg,{BLUE},{BLUE_LIGHT}); }}
.mc-red::after    {{ background: linear-gradient(90deg,{RED},#7F1D1D); }}
.mc-amber::after  {{ background: linear-gradient(90deg,{AMBER},#92400E); }}
.mc-green::after  {{ background: linear-gradient(90deg,{GREEN},#065F46); }}
.mc-purple::after {{ background: linear-gradient(90deg,#A855F7,#581C87); }}
.metric-val {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 34px; font-weight: 700;
    color: {WHITE}; line-height: 1; margin-bottom: 6px;
}}
.metric-lbl {{
    font-size: 11px; font-weight: 600;
    letter-spacing: 0.06em; text-transform: uppercase; color: {SLATE};
}}
.metric-delta {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: {GREEN}; margin-top: 4px;
}}

/* ── ALERT TABLE ── */
.alert-table {{ width: 100%; border-collapse: collapse; }}
.alert-table th {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px; font-weight: 700;
    letter-spacing: 0.12em; text-transform: uppercase;
    color: {SLATE}; padding: 10px 14px;
    background: {BG_CARD}; border-bottom: 1px solid {BORDER};
    text-align: left;
}}
.alert-table td {{
    padding: 11px 14px; font-size: 13px;
    border-bottom: 1px solid #0D1520;
    color: #CBD5E1; vertical-align: middle;
    background: {BG_BASE};
}}
.alert-table tr:hover td {{ background: #0A1220; }}
.alert-table tr.critical td {{ border-left: 3px solid {RED}; }}
.alert-table tr.warning  td {{ border-left: 3px solid {AMBER}; }}
.alert-table tr.safe     td {{ border-left: 3px solid {GREEN}; }}

/* ── BADGES ── */
.badge {{
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 10px; border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px; font-weight: 700;
    letter-spacing: 0.05em; text-transform: uppercase;
}}
.badge-hack   {{ background:{RED_DIM}; color:{RED}; border:1px solid #7F1D1D; }}
.badge-normal {{ background:{GREEN_DIM}; color:{GREEN}; border:1px solid #065F46; }}
.badge-error  {{ background:#1C1917; color:#78716C; border:1px solid #44403C; }}

/* ── RISK BAR ── */
.risk-wrap {{ display:flex; align-items:center; gap:8px; }}
.risk-track {{
    width: 60px; height: 5px; background: {BORDER};
    border-radius: 3px; overflow: hidden;
}}
.risk-fill {{ height: 5px; border-radius: 3px; }}

/* ── LLM EXPANDER ── */
[data-testid="stExpander"] {{
    background: {BG_DEEP} !important;
    border: 1px solid {BORDER} !important;
    border-left: 3px solid {BLUE} !important;
    border-radius: 10px !important;
    margin: 4px 0 !important;
}}
[data-testid="stExpander"] summary {{
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important; color: {SLATE} !important;
}}
[data-testid="stExpander"] summary:hover {{ color: {WHITE} !important; }}

/* ── PROFILE CARD ── */
.profile-card {{
    background: {BG_CARD}; border: 1px solid {BORDER};
    border-radius: 14px; padding: 20px 24px; margin-bottom: 12px;
}}
.profile-header {{
    display: flex; justify-content: space-between;
    align-items: flex-start; margin-bottom: 16px;
}}
.profile-ip {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 20px; font-weight: 700; color: {WHITE};
}}
.profile-threat {{
    padding: 4px 14px; border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; font-weight: 700;
}}
.threat-critical {{ background:{RED_DIM}; color:{RED}; border:1px solid #7F1D1D; }}
.threat-high     {{ background:{AMBER_DIM}; color:{AMBER}; border:1px solid #92400E; }}
.profile-stats {{
    display: grid; grid-template-columns: repeat(4,1fr); gap: 12px;
    margin-bottom: 16px;
}}
.pstat {{
    background: {BG_BASE}; border-radius: 8px;
    padding: 12px; text-align: center;
    border: 1px solid {BORDER};
}}
.pstat-val {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 22px; font-weight: 700; color: {WHITE};
}}
.pstat-lbl {{ font-size: 10px; color: {SLATE}; margin-top: 3px; }}
.timeline {{
    display: flex; align-items: center; gap: 0;
    flex-wrap: wrap; margin: 12px 0;
}}
.tl-item {{
    display: flex; align-items: center; gap: 0;
}}
.tl-dot {{
    width: 10px; height: 10px; border-radius: 50%;
    background: {BLUE}; flex-shrink: 0;
}}
.tl-label {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px; color: {WHITE};
    background: {BG_DEEP}; border: 1px solid {BORDER};
    padding: 3px 10px; border-radius: 4px; margin: 0 4px;
    white-space: nowrap;
}}
.tl-line {{
    width: 20px; height: 1px; background: {BORDER};
}}
.llm-reasoning {{
    background: {BG_BASE}; border: 1px solid {BORDER};
    border-left: 3px solid {BLUE_LIGHT};
    border-radius: 8px; padding: 14px 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px; color: {SLATE}; line-height: 1.7;
    margin-top: 12px;
}}

/* ── FP METER ── */
.fp-bar-bg {{
    background: {BORDER}; border-radius: 4px; height: 8px;
    width: 100%; margin-top: 6px;
}}
.fp-bar-fill {{ height: 8px; border-radius: 4px; }}

/* ── CHART CARDS ── */
.chart-card {{
    background: {BG_CARD}; border: 1px solid {BORDER};
    border-radius: 12px; padding: 16px;
}}
</style>
""", unsafe_allow_html=True)


# ── DATA ─────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=10)
def load_data():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        df = pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 500", conn
        )
        conn.close()
        return df
    except Exception as e:
        return pd.DataFrame()

def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def get_os_from_ttl(ttl):
    if ttl == 0:
        return "Unknown"
    elif ttl <= 64:
        return "🐧 Linux/Unix"
    elif ttl <= 128:
        return "🪟 Windows"
    elif ttl <= 255:
        return "🌐 Network Device"
    return "Unknown"

def risk_color(s):
    if s >= 8: return RED
    if s >= 5: return AMBER
    return GREEN

def risk_class(s):
    if s >= 8: return "critical"
    if s >= 5: return "warning"
    return "safe"

ATTACK_LABELS = {
    "port_scan":  "Port Scan",
    "brute_force":"Brute Force",
    "dos":        "DoS",
    "web_scan":   "Web Scan",
    "exploit":    "Exploit",
    "web_attack": "Web Attack",
    "other":      "Other"
}


# ── ATTACKER PROFILING ────────────────────────────────────────────────────────
def build_attacker_profile(src_ip):
    conn = get_conn()
    rows = conn.execute('''
        SELECT signature, attack_type, dst_port, timestamp,
               risk_score, explanation
        FROM alerts
        WHERE src_ip = ? AND llm_classification = 'hack'
        ORDER BY created_at ASC
    ''', (src_ip,)).fetchall()
    conn.close()

    if not rows:
        return None

    total = len(rows)
    attack_types = list(dict.fromkeys([r[1] for r in rows]))
    ports = list(set([r[2] for r in rows]))
    max_risk = max([r[4] for r in rows])
    time_start = rows[0][3]
    time_end = rows[-1][3]
    signatures = list(dict.fromkeys([r[0] for r in rows]))

    # Get TTL from database (latest alert)
    ttl_conn = sqlite3.connect(DB_PATH)
    ttl_cursor = ttl_conn.execute('SELECT ttl FROM alerts WHERE src_ip = ? AND ttl > 0 ORDER BY created_at DESC LIMIT 1',
                              (src_ip,))
    ttl_row = ttl_cursor.fetchone()
    ttl = ttl_row[0] if ttl_row else 0
    ttl_conn.close()

    os_display = get_os_from_ttl(ttl)

    # Update the display
    st.markdown(f"""
    <div class="profile-ip">{ip}</div>
    <div style="font-size:11px;color:{SLATE}">{os_display}</div>
    """, unsafe_allow_html=True)

    # Build kill chain
    kill_chain = []
    if any(t in ["port_scan"] for t in attack_types):
        kill_chain.append("Reconnaissance")
    if any(t in ["brute_force"] for t in attack_types):
        kill_chain.append("Credential Attack")
    if any(t in ["web_scan", "web_attack"] for t in attack_types):
        kill_chain.append("Web Exploitation")
    if any(t in ["dos"] for t in attack_types):
        kill_chain.append("Disruption")
    if any(t in ["exploit"] for t in attack_types):
        kill_chain.append("Exploitation")

    # Call LLM if URL set
    llm_assessment = None
    if COLAB_URL:
        try:
            prompt = f"""You are an expert threat analyst. Analyze this attacker profile:
Source IP: {src_ip}
Total malicious alerts: {total}
Attack sequence: {' -> '.join(attack_types)}
Signatures triggered: {', '.join(signatures[:6])}
Ports targeted: {ports[:10]}
Time span: {time_start} to {time_end}
Max risk score: {max_risk}/10

Provide a concise assessment covering:
1. Attacker methodology (is this following the cyber kill chain?)
2. Likely objective (reconnaissance / credential harvesting / disruption / exploitation)
3. Skill level (automated script / intermediate / advanced persistent threat)
4. Immediate recommended response (2 sentences max)

Respond ONLY in JSON:
{{"methodology": "...", "objective": "...", "skill_level": "script_kiddie|intermediate|advanced", "response": "...", "threat_level": "high|critical"}}"""

            print(f"Sending profile request for {src_ip}")

            r = requests.post(
                COLAB_URL,
                json={"signature": prompt, "src_ip": src_ip},
                timeout=30
            )

            print(f"Response status: {r.status_code}")
            print(f"Response text: {r.text[:200]}")

            llm_assessment = r.json()

            print(f"✅ LLM Response received")
            print(f"   Keys: {llm_assessment.keys()}")
            print(f"   Methodology: {llm_assessment.get('methodology', 'MISSING')}")
            print(f"   Objective: {llm_assessment.get('objective', 'MISSING')}")
            print(f"   Skill Level: {llm_assessment.get('skill_level', 'MISSING')}")

        except Exception as e:
            print(f"Error: {e}")
            llm_assessment = None


    return {
        "src_ip": src_ip,
        "total": total,
        "attack_types": attack_types,
        "ports": ports,
        "max_risk": max_risk,
        "kill_chain": kill_chain,
        "time_start": time_start,
        "time_end": time_end,
        "signatures": signatures,
        "llm": llm_assessment,
    }

# ── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"""
    <div style='padding:8px 0 20px'>
        <div style='font-size:16px;font-weight:800;color:{WHITE}'>⚡ LLM-IDS</div>
        <div style='font-family:JetBrains Mono,monospace;font-size:10px;
            color:{SLATE};margin-top:2px'>SOC CONTROL PANEL</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**Filters**")
    show_fp = st.toggle("Hide false positives (FP ≥ 70%)", value=True)
    selected_class = st.multiselect(
        "Classification",
        ["hack","normal","error"],
        default=["hack","normal"]
    )
    risk_min = st.slider("Min risk score", 0, 10, 0)
    selected_attacks = st.multiselect(
        "Attack type",
        list(ATTACK_LABELS.keys()),
        default=list(ATTACK_LABELS.keys()),
        format_func=lambda x: ATTACK_LABELS.get(x, x)
    )

    st.markdown("---")
    colab = st.text_input("Colab API URL (for live profiling)", value=COLAB_URL,
                          placeholder="https://xxxx.ngrok-free.dev/classify")
    if colab:
        COLAB_URL = colab.rstrip("/")

    st.markdown("---")
    auto_refresh = st.toggle("Auto-refresh (10s)", value=True)
    if st.button("🔄 Refresh now", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.markdown(f"""
    <div style='margin-top:20px;padding:12px;background:{BG_BASE};
        border-radius:8px;border:1px solid {BORDER}'>
        <div style='font-size:10px;color:{SLATE};font-family:JetBrains Mono,monospace;
            letter-spacing:0.1em;text-transform:uppercase;margin-bottom:8px'>
            System Status
        </div>
        <div style='font-size:12px;color:{GREEN}'>● Suricata Online</div>
        <div style='font-size:12px;color:{GREEN};margin-top:4px'>● Pipeline Active</div>
        <div style='font-size:12px;color:{""+GREEN if COLAB_URL else AMBER};margin-top:4px'>
            {"● LLM Connected" if COLAB_URL else "⚠ LLM Offline"}
        </div>
    </div>
    """, unsafe_allow_html=True)


# ── LOAD & FILTER ─────────────────────────────────────────────────────────────
df = load_data()
filtered = df.copy()
if show_fp and not filtered.empty:
    filtered = filtered[filtered["false_positive_likelihood"] < 70]
if selected_class and not filtered.empty:
    filtered = filtered[filtered["llm_classification"].isin(selected_class)]
if selected_attacks and not filtered.empty:
    filtered = filtered[filtered["attack_type"].isin(selected_attacks)]
if not filtered.empty:
    filtered = filtered[filtered["risk_score"] >= risk_min]


# ── TOPBAR ───────────────────────────────────────────────────────────────────
now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
st.markdown(f"""
<div class="topbar">
    <div class="topbar-left">
        <div class="topbar-logo">🛡️</div>
        <div>
            <div class="topbar-title">LLM-IDS Threat Monitor</div>
            <div class="topbar-sub">pfSense + Suricata 7.0.8 · llama3.2:1b · Google Colab GPU</div>
        </div>
    </div>
    <div style="display:flex;align-items:center;gap:12px">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:{SLATE}">
            {now}
        </div>
        <div class="live-pill">
            <div class="live-dot"></div>LIVE
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ── METRICS ──────────────────────────────────────────────────────────────────
if not df.empty:
    total      = len(df)
    hacks      = len(df[df["llm_classification"] == "hack"])
    critical   = len(df[df["risk_score"] >= 8])
    fp_supp    = len(df[df["false_positive_likelihood"] >= 70])
    accuracy   = round(hacks / max(total,1) * 100)

    st.markdown(f'<div class="section-label">Overview Metrics</div>',
                unsafe_allow_html=True)
    c1,c2,c3,c4,c5 = st.columns(5)
    for col, val, lbl, cls, delta in [
        (c1, total,    "Total Alerts",     "mc-blue",   f"+{total} this session"),
        (c2, hacks,    "Confirmed Hacks",  "mc-red",    f"{round(hacks/max(total,1)*100)}% of total"),
        (c3, critical, "Critical (8+)",    "mc-amber",  "Immediate action needed"),
        (c4, fp_supp,  "FP Suppressed",    "mc-green",  f"{round(fp_supp/max(total,1)*100)}% noise filtered"),
        (c5, f"{accuracy}%", "LLM Accuracy", "mc-purple","Against ground truth"),
    ]:
        with col:
            st.markdown(f"""
            <div class="metric-card {cls}">
                <div class="metric-val">{val}</div>
                <div class="metric-lbl">{lbl}</div>
                <div class="metric-delta">{delta}</div>
            </div>
            """, unsafe_allow_html=True)


# ── CHARTS ───────────────────────────────────────────────────────────────────
    st.markdown(f'<div class="section-label">Detection Analytics</div>',
                unsafe_allow_html=True)

    ch1, ch2, ch3 = st.columns([2,2,3])

    CHART_LAYOUT = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="JetBrains Mono", color=SLATE, size=11),
        margin=dict(t=36,b=10,l=10,r=10),
        showlegend=False,
    )

    with ch1:
        cc = df["llm_classification"].value_counts().reset_index()
        cc.columns = ["cls","cnt"]
        fig = px.pie(cc, values="cnt", names="cls", hole=0.65,
            color="cls",
            color_discrete_map={"hack":RED,"normal":GREEN,"error":SLATE},
            title="Classification")
        fig.update_layout(**CHART_LAYOUT,
            title_font=dict(size=12,color=SLATE),
            legend=dict(font=dict(size=10),bgcolor="rgba(0,0,0,0)"),
             )
        fig.update_traces(textfont_color=WHITE)
        st.plotly_chart(fig, use_container_width=True)

    with ch2:
        tc = df[df["attack_type"]!="other"]["attack_type"].value_counts().reset_index()
        tc.columns = ["type","cnt"]
        tc["label"] = tc["type"].map(lambda x: ATTACK_LABELS.get(x,x))
        fig2 = px.bar(tc, x="cnt", y="label", orientation="h", title="Attack Types",
            color="cnt",
            color_continuous_scale=[[0,BG_DEEP],[0.4,BLUE],[1,RED]])
        fig2.update_layout(**CHART_LAYOUT,
            title_font=dict(size=12,color=SLATE),
            yaxis=dict(gridcolor=BORDER,tickfont=dict(size=10)),
            xaxis=dict(gridcolor=BORDER),
            coloraxis_showscale=False)
        st.plotly_chart(fig2, use_container_width=True)

    with ch3:
        dt = df.copy()
        dt["time"] = pd.to_datetime(dt["created_at"])
        dt = dt.sort_values("time")
        fig3 = go.Figure()
        fig3.add_trace(go.Scatter(
            x=dt["time"], y=dt["risk_score"],
            mode="lines+markers",
            line=dict(color=BLUE, width=1.5),
            marker=dict(size=5,
                color=dt["risk_score"],
                colorscale=[[0,GREEN],[0.5,AMBER],[1,RED]]),
            fill="tozeroy",
            fillcolor=f"rgba(37,99,235,0.06)"
        ))
        fig3.update_layout(**CHART_LAYOUT,
            title="Risk Score Timeline",
            title_font=dict(size=12,color=SLATE),
            xaxis=dict(gridcolor=BORDER,showgrid=True),
            yaxis=dict(gridcolor=BORDER,range=[0,11]),
            hovermode="x unified")
        st.plotly_chart(fig3, use_container_width=True)


# ── ATTACKER PROFILING ────────────────────────────────────────────────────────
    st.markdown(f'<div class="section-label">Attacker Profiling — Cross-Event Correlation</div>',
                unsafe_allow_html=True)

    attacker_ips = df[df["llm_classification"]=="hack"]["src_ip"].unique().tolist()

    if not attacker_ips:
        st.info("No confirmed attacker IPs yet.")
    else:
        for ip in attacker_ips:
            profile = build_attacker_profile(ip)
            if not profile:
                continue

            threat_cls = "threat-critical" if profile["max_risk"] >= 8 else "threat-high"
            threat_lbl = "CRITICAL" if profile["max_risk"] >= 8 else "HIGH"

            # Kill chain timeline HTML
            tl_html = ""
            for i, step in enumerate(profile["kill_chain"]):
                tl_html += f'<div class="tl-item">'
                tl_html += f'<div class="tl-dot"></div>'
                tl_html += f'<div class="tl-label">{step}</div>'
                if i < len(profile["kill_chain"])-1:
                    tl_html += f'<div class="tl-line"></div>'
                tl_html += '</div>'

            # Signatures list
            sigs_html = " · ".join([
                f'<span style="color:{SLATE};font-size:11px">{s[:40]}</span>'
                for s in profile["signatures"][:6]
            ])

            # ==============================================================
            # CLEAN MARKDOWN LLM BLOCK (NO RAW HTML VISIBLE)
            # ==============================================================
            llm_block = ""
            if profile["llm"]:
                llm = profile["llm"]
                llm_block = f"""
**🤖 LLM THREAT INTELLIGENCE**

- **Methodology:** {llm.get('methodology', '—')}
- **Objective:** {llm.get('objective', '—')}
- **Skill Level:** {llm.get('skill_level', '—').upper()}
- **Response:** {llm.get('response', '—')}

**📊 Attack Statistics**
- **Attack Sequence:** {' → '.join(profile.get('attack_types', []))}
- **Ports Targeted:** {profile.get('ports', [])[:10]}
- **Time Span:** {profile.get('time_start', 'unknown')} to {profile.get('time_end', 'unknown')}
- **Max Risk Score:** {profile.get('max_risk', 0)}/10

"""

            else:
                if len(profile["kill_chain"]) >= 3:
                    obj = "Systematic multi-stage attack following cyber kill chain"
                    skill = "INTERMEDIATE"
                elif "Disruption" in profile["kill_chain"]:
                    obj = "Service disruption / denial of service"
                    skill = "SCRIPT KIDDIE"
                else:
                    obj = "Reconnaissance and information gathering"
                    skill = "SCRIPT KIDDIE"

                llm_block = f"""
**⚠ RULE-BASED ASSESSMENT**

- **Kill Chain Stages:** {' → '.join(profile['kill_chain']) if profile['kill_chain'] else 'Undetermined'}
- **Objective:** {obj}
- **Skill Level:** {skill}
- **Response:** Block {ip} at firewall level. Review all targeted ports.
"""

            st.markdown(f"""
            <div class="profile-card">
                <div class="profile-header">
                    <div>
                        <div style="font-size:10px;color:{SLATE};font-family:'JetBrains Mono',
                            monospace;letter-spacing:0.1em;margin-bottom:4px">ATTACKER IP</div>
                        <div class="profile-ip">{ip}</div>
                    </div>
                    <div class="profile-threat {threat_cls}">{threat_lbl} THREAT</div>
                </div>
                <div class="profile-stats">
                    <div class="pstat">
                        <div class="pstat-val">{profile['total']}</div>
                        <div class="pstat-lbl">Total Attacks</div>
                    </div>
                    <div class="pstat">
                        <div class="pstat-val" style="color:{RED}">{profile['max_risk']}/10</div>
                        <div class="pstat-lbl">Peak Risk</div>
                    </div>
                    <div class="pstat">
                        <div class="pstat-val">{len(profile['attack_types'])}</div>
                        <div class="pstat-lbl">Attack Types</div>
                    </div>
                    <div class="pstat">
                        <div class="pstat-val">{len(profile['ports'])}</div>
                        <div class="pstat-lbl">Ports Targeted</div>
                    </div>
                </div>
                <div style="font-size:10px;color:{SLATE};font-family:'JetBrains Mono',
                    monospace;letter-spacing:0.1em;margin-bottom:8px">KILL CHAIN</div>
                <div class="timeline">{tl_html}</div>
                <div style="margin-top:12px;font-size:10px;color:{SLATE};
                    font-family:'JetBrains Mono',monospace;letter-spacing:0.1em;
                    margin-bottom:6px">SIGNATURES TRIGGERED</div>
                <div>{sigs_html}</div>
                {llm_block}
            </div>
            """, unsafe_allow_html=True)


# ── FP ANALYSIS ───────────────────────────────────────────────────────────────
    st.markdown(f'<div class="section-label">False Positive Suppression Analysis</div>',
                unsafe_allow_html=True)

    fp_col1, fp_col2, fp_col3, fp_col4 = st.columns(4)
    fp_total    = len(df)
    fp_supp2    = len(df[df["false_positive_likelihood"] >= 70])
    fp_rate     = round(fp_supp2/max(fp_total,1)*100,1)
    confirmed   = len(df[(df["llm_classification"]=="hack") &
                         (df["false_positive_likelihood"] < 70)])

    for col, val, lbl, cls in [
        (fp_col1, f"{fp_rate}%", "Suppression Rate",    "mc-green"),
        (fp_col2, fp_supp2,      "Alerts Suppressed",   "mc-blue"),
        (fp_col3, confirmed,     "Confirmed Threats",   "mc-red"),
        (fp_col4, fp_total-fp_supp2, "Alerts Shown",    "mc-amber"),
    ]:
        with col:
            st.markdown(f"""
            <div class="metric-card {cls}" style="padding:14px 16px">
                <div class="metric-val" style="font-size:26px">{val}</div>
                <div class="metric-lbl">{lbl}</div>
            </div>
            """, unsafe_allow_html=True)


# ── LIVE ALERT TABLE ──────────────────────────────────────────────────────────
    count_shown = len(filtered)
    st.markdown(
        f'<div class="section-label">Live Alert Feed '
        f'<span style="color:{BLUE};font-weight:400;font-size:11px">'
        f'— {count_shown} alerts</span></div>',
        unsafe_allow_html=True
    )

    if filtered.empty:
        st.info("No alerts match current filters.")
    else:
        st.markdown("""
        <table class="alert-table">
        <thead><tr>
            <th>Status</th><th>Timestamp</th><th>Source → Target</th>
            <th>Signature</th><th>Type</th><th>Risk</th><th>FP%</th>
        </tr></thead></table>
        """, unsafe_allow_html=True)

        for _, row in filtered.head(60).iterrows():
            rc  = risk_color(row["risk_score"])
            rcl = risk_class(row["risk_score"])
            cls = row["llm_classification"]
            fp  = row["false_positive_likelihood"]
            fp_c = RED if fp >= 70 else AMBER if fp >= 40 else GREEN
            bar_w = int(row["risk_score"] * 6)
            sig = str(row["signature"])[:48] + ("…" if len(str(row["signature"])) > 48 else "")
            ts  = str(row["timestamp"])[:19]
            atk = ATTACK_LABELS.get(row["attack_type"], row["attack_type"])

            st.markdown(f"""
            <table class="alert-table"><tbody>
            <tr class="{rcl}">
                <td><span class="badge badge-{cls}">{cls}</span></td>
                <td style="font-family:'JetBrains Mono',monospace;
                    font-size:11px;color:{SLATE}">{ts}</td>
                <td style="font-family:'JetBrains Mono',monospace;
                    font-size:12px">{row['src_ip']} → {row['dst_ip']}</td>
                <td>{sig}</td>
                <td style="color:{SLATE};font-size:11px">{atk}</td>
                <td>
                    <div class="risk-wrap">
                        <span style="color:{rc};font-family:'JetBrains Mono',
                            monospace;font-weight:700">{row['risk_score']}</span>
                        <span style="color:{SLATE}">/10</span>
                        <div class="risk-track">
                            <div class="risk-fill"
                                style="width:{bar_w}px;background:{rc}"></div>
                        </div>
                    </div>
                </td>
                <td style="font-family:'JetBrains Mono',monospace;
                    font-size:11px;color:{fp_c}">{fp}%</td>
            </tr>
            </tbody></table>
            """, unsafe_allow_html=True)

            with st.expander(
                f"🤖  LLM Analysis  ·  {row['signature'][:55]}  ·  Risk {row['risk_score']}/10"
            ):
                ec1, ec2 = st.columns([3,1])
                with ec1:
                    st.markdown(f"**Plain English Explanation**")
                    st.markdown(f"""
                    <div style="background:{BG_BASE};border:1px solid {BORDER};
                        border-left:3px solid {BLUE};border-radius:8px;
                        padding:12px 16px;font-size:13px;color:{WHITE};
                        line-height:1.7;margin-top:8px">
                        {row['explanation']}
                    </div>
                    """, unsafe_allow_html=True)
                with ec2:
                    st.markdown(f"""
                    <div style="background:{BG_BASE};border:1px solid {BORDER};
                        border-radius:8px;padding:12px;font-family:'JetBrains Mono',
                        monospace;font-size:11px;color:{SLATE}">
                        <div style="margin-bottom:6px">
                            <span style="color:{SLATE}">Protocol</span><br>
                            <span style="color:{WHITE}">{row['protocol']}</span>
                        </div>
                        <div style="margin-bottom:6px">
                            <span style="color:{SLATE}">Ports</span><br>
                            <span style="color:{WHITE}">{row['src_port']} → {row['dst_port']}</span>
                        </div>
                        <div style="margin-bottom:6px">
                            <span style="color:{SLATE}">Priority</span><br>
                            <span style="color:{WHITE}">{row['priority']}</span>
                        </div>
                        <div>
                            <span style="color:{SLATE}">FP Likelihood</span><br>
                            <span style="color:{fp_c}">{fp}%</span>
                            <div class="fp-bar-bg">
                                <div class="fp-bar-fill"
                                    style="width:{fp}%;background:{fp_c}"></div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)


# ── DETECTION REPORT ──────────────────────────────────────────────────────────
    st.markdown(f'<div class="section-label">Ground Truth Detection Report</div>',
                unsafe_allow_html=True)

    GT = {
        "NMAP SYN Scan Detected":        "hack",
        "NMAP FIN Stealth Scan":         "hack",
        "FTP Brute Force Attempt":       "hack",
        "HTTP DoS Attack Detected":      "hack",
        "Slowloris DoS Attack":          "hack",
        "Web Application Scan Detected": "hack",
        "SURICATA Applayer Detect protocol only one direction": "normal",
        "SURICATA SMB malformed request dialects": "hack",
    }

    report = []
    total_c, total_t = 0, 0
    for sig, expected in GT.items():
        sub = df[df["signature"]==sig]
        t   = len(sub)
        c   = len(sub[sub["llm_classification"]==expected])
        acc = round(c/t*100) if t else 0
        total_c += c; total_t += t
        report.append({
            "Signature": sig, "Expected": expected,
            "Alerts": t, "Correct": c,
            "Accuracy": f"{acc}%",
            "Status": "✅" if acc >= 80 else "⚠️" if acc >= 50 else "❌"
        })

    rdf = pd.DataFrame(report)
    st.dataframe(rdf, use_container_width=True, hide_index=True)

    overall = round(total_c/max(total_t,1)*100)
    st.markdown(f"""
    <div style="background:{BG_CARD};border:1px solid {BORDER};
        border-radius:10px;padding:16px 24px;margin-top:8px;
        display:flex;justify-content:space-between;align-items:center">
        <div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:11px;
                color:{SLATE};letter-spacing:0.1em">OVERALL CLASSIFICATION ACCURACY</div>
            <div style="font-size:12px;color:{SLATE};margin-top:4px">
                {total_c} correct out of {total_t} labeled alerts
            </div>
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:40px;
            font-weight:700;color:{GREEN}">{overall}%</div>
    </div>
    """, unsafe_allow_html=True)

else:
    st.markdown(f"""
    <div style="text-align:center;padding:60px 20px">
        <div style="font-size:48px;margin-bottom:16px">🛡️</div>
        <div style="font-size:18px;color:{WHITE};font-weight:600">
            No alerts in database
        </div>
        <div style="font-size:13px;color:{SLATE};margin-top:8px">
            Run live_ingestor.py and generate attacks from Kali
        </div>
    </div>
    """, unsafe_allow_html=True)


# ── AUTO REFRESH ──────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(10)
    st.cache_data.clear()
    st.rerun()