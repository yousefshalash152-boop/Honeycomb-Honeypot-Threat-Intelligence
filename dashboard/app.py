"""Honeycomb SOC Dashboard (Stage 4) - Member 2 (Data Pipeline & Storage)

Professional Cybersecurity SOC Dashboard:
1. Overview (Attack Metrics & KPIs)
2. Attacker IP Details (Safe Plain-Text Command Inspection)
3. Campaigns & Correlation (C1-C3 Multi-source Attack Tracking)
"""
import os
import sqlite3
import pandas as pd
import streamlit as st

# Configure Page
st.set_page_config(
    page_title="Honeycomb SOC Dashboard",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Paths
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(APP_DIR, ".."))
DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "honeycomb.db")
SAMPLE_LOG_PATH = os.path.join(PROJECT_ROOT, "tests", "sample.jsonl")

# Helper: Database Connection
def get_db_connection(db_path=DEFAULT_DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

# Helper: Check if DB exists and has events
def is_db_ready(db_path=DEFAULT_DB_PATH):
    if not os.path.exists(db_path):
        return False
    try:
        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        table_exists = cur.fetchone() is not None
        if not table_exists:
            conn.close()
            return False
        cur.execute("SELECT count(*) FROM events")
        cnt = cur.fetchone()[0]
        conn.close()
        return cnt > 0
    except Exception:
        return False

# Helper: Seed DB with sample and scenario data
def seed_sample_data(db_path=DEFAULT_DB_PATH):
    import glob
    from honeycomb.src.storage.loader import load_file
    from honeycomb.src.campaigns_db import build_campaigns
    
    res = load_file(db_path, SAMPLE_LOG_PATH)
    scenarios = glob.glob(os.path.join(PROJECT_ROOT, "tests", "fixtures", "scenarios", "*.jsonl"))
    for s in scenarios:
        load_file(db_path, s)
        
    conn = get_db_connection(db_path)
    build_campaigns(conn)
    conn.close()
    return res

# ==============================================================================
# SIDEBAR
# ==============================================================================
with st.sidebar:
    st.markdown("## 🍯 **Honeycomb SOC**")
    st.caption("Threat Intelligence & Honeypot Monitoring")
    st.markdown("---")

    page = st.radio(
        "Navigation",
        [
            "📊 Overview",
            "🎯 Attacker IP Details",
            "🌐 Campaigns & Correlation",
        ],
        index=0,
    )

    st.markdown("---")
    st.markdown("### ⚙️ Database Status")
    db_ready = is_db_ready()

    if db_ready:
        st.success("🟢 Connected & Healthy")
        conn = get_db_connection()
        total_ev = conn.execute("SELECT count(*) FROM events").fetchone()[0]
        total_ips = conn.execute("SELECT count(DISTINCT src_ip) FROM events").fetchone()[0]
        conn.close()
        st.metric("Total Events", f"{total_ev:,}")
        st.metric("Unique Attacker IPs", f"{total_ips:,}")
    else:
        st.warning("🟡 Database Not Initialized")
        if st.button("📥 Load Sample & Scenario Data"):
            with st.spinner("Ingesting logs and extracting correlations..."):
                res = seed_sample_data()
                st.success(f"Loaded {res['inserted']} events successfully!")
                st.rerun()

    st.markdown("---")
    st.caption("**Role:** Member 2 (Data Pipeline & SIEM)\n\n**Engineer:** Ibrahim Saeed\n\n**Branch:** `feature/dashboard-streamlit`")

# Ensure DB has data before rendering pages
if not is_db_ready():
    st.info("👋 Welcome to Honeycomb SOC Dashboard!\n\nPlease click **'Load Sample & Scenario Data'** in the sidebar to populate the database.")
    st.stop()

# ==============================================================================
# PAGE 1: OVERVIEW
# ==============================================================================
if page == "📊 Overview":
    st.title("📊 Honeypot Attack Overview & KPIs")
    st.markdown("Real-time telemetry and metrics captured from Cowrie Honeypot traps.")

    conn = get_db_connection()

    # KPI Metrics Row
    total_events = conn.execute("SELECT count(*) FROM events").fetchone()[0]
    unique_ips = conn.execute("SELECT count(DISTINCT src_ip) FROM events").fetchone()[0]
    total_sessions = conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
    failed_logins = conn.execute("SELECT count(*) FROM events WHERE event_type = 'cowrie.login.failed'").fetchone()[0]
    success_logins = conn.execute("SELECT count(*) FROM events WHERE event_type = 'cowrie.login.success'").fetchone()[0]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🎯 Total Ingested Events", f"{total_events:,}")
    with col2:
        st.metric("🌐 Unique Attacker IPs", f"{unique_ips:,}")
    with col3:
        st.metric("🚪 Attacker Sessions", f"{total_sessions:,}")
    with col4:
        st.metric("🔑 Auth Attempts", f"{failed_logins} Failed / {success_logins} Success")

    st.markdown("---")

    # Charts Row
    c_left, c_right = st.columns([1, 1])

    with c_left:
        st.subheader("🔥 Top 10 Attacking IP Addresses")
        df_top_ips = pd.read_sql_query("""
            SELECT src_ip as "IP Address", count(*) as "Event Count"
            FROM events
            GROUP BY src_ip
            ORDER BY "Event Count" DESC
            LIMIT 10
        """, conn)
        st.bar_chart(df_top_ips.set_index("IP Address"))

    with c_right:
        st.subheader("📈 Event Types Distribution")
        df_types = pd.read_sql_query("""
            SELECT event_type as "Event Type", count(*) as "Occurrences"
            FROM events
            GROUP BY event_type
            ORDER BY "Occurrences" DESC
        """, conn)
        st.dataframe(df_types, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("🕵️ Targeted Credentials (Brute Force Analysis)")
    col_u, col_p = st.columns(2)
    with col_u:
        st.markdown("**Top Targeted Usernames:**")
        df_users = pd.read_sql_query("""
            SELECT username as "Username", count(*) as "Attempts"
            FROM events
            WHERE username IS NOT NULL AND username != ''
            GROUP BY username
            ORDER BY "Attempts" DESC
            LIMIT 5
        """, conn)
        st.table(df_users)
    with col_p:
        st.markdown("**Top Targeted Passwords:**")
        df_pw = pd.read_sql_query("""
            SELECT password as "Password", count(*) as "Attempts"
            FROM events
            WHERE password IS NOT NULL AND password != ''
            GROUP BY password
            ORDER BY "Attempts" DESC
            LIMIT 5
        """, conn)
        st.table(df_pw)

    conn.close()

# ==============================================================================
# PAGE 2: ATTACKER IP DETAILS
# ==============================================================================
elif page == "🎯 Attacker IP Details":
    st.title("🎯 Attacker IP Deep Dive & Forensics")
    st.markdown("Detailed forensic investigation of individual attacker IPs and executed payloads.")

    conn = get_db_connection()
    ips_list = [r[0] for r in conn.execute("SELECT DISTINCT src_ip FROM events ORDER BY src_ip").fetchall()]

    selected_ip = st.selectbox("🔍 Select Attacker IP to Investigate:", ips_list)

    if selected_ip:
        # IP Summary
        ip_stats = conn.execute("""
            SELECT 
                MIN(ts_utc) as first_seen,
                MAX(ts_utc) as last_seen,
                COUNT(*) as total_events,
                COUNT(DISTINCT session_id) as total_sessions
            FROM events
            WHERE src_ip = ?
        """, (selected_ip,)).fetchone()

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("First Seen (UTC)", ip_stats["first_seen"][:19].replace("T", " ") if ip_stats["first_seen"] else "N/A")
        c2.metric("Last Seen (UTC)", ip_stats["last_seen"][:19].replace("T", " ") if ip_stats["last_seen"] else "N/A")
        c3.metric("Total Events", ip_stats["total_events"])
        c4.metric("Active Sessions", ip_stats["total_sessions"])

        st.markdown("---")

        # Commands Executed (Plain text requirement from plan)
        st.subheader("💻 Executed Shell Commands")
        st.caption("🛡️ Security Policy: Attacker input is rendered strictly as plain text to eliminate XSS risks.")

        commands = conn.execute("""
            SELECT ts_utc, session_id, command
            FROM events
            WHERE src_ip = ? AND command IS NOT NULL AND command != ''
            ORDER BY ts_utc ASC
        """, (selected_ip,)).fetchall()

        if commands:
            for row in commands:
                ts = row["ts_utc"][:19].replace("T", " ")
                sid = row["session_id"] or "Unknown"
                st.markdown(f"**⏰ `{ts}` | Session: `{sid}`**")
                # Plain text display as required by project specification
                st.code(row["command"], language="bash")
        else:
            st.info("No shell commands were executed by this IP (reconnaissance or credential brute force only).")

        st.markdown("---")

        # Credentials tried by this IP
        st.subheader("🔑 Credentials Tried by This Attacker")
        df_creds = pd.read_sql_query("""
            SELECT ts_utc as "Timestamp (UTC)", username as "Username", password as "Password", event_type as "Result"
            FROM events
            WHERE src_ip = ? AND (username IS NOT NULL OR password IS NOT NULL)
            ORDER BY ts_utc ASC
        """, conn, params=(selected_ip,))
        st.dataframe(df_creds, use_container_width=True, hide_index=True)

    conn.close()

# ==============================================================================
# PAGE 3: CAMPAIGNS & CORRELATION
# ==============================================================================
elif page == "🌐 Campaigns & Correlation":
    st.title("🌐 Multi-Source Attack Campaigns & Correlation")
    st.markdown("Correlation engine linking sessions from different IPs based on shared artifacts (C1: File Hash, C2: Download URL, C3: Command Sequence).")

    conn = get_db_connection()

    # Check if campaigns table exists and has rows
    try:
        campaigns_count = conn.execute("SELECT count(*) FROM campaigns").fetchone()[0]
    except Exception:
        campaigns_count = 0

    if campaigns_count == 0:
        st.warning("No campaigns correlated yet in the database.")
        if st.button("⚡ Run Correlation Engine"):
            from honeycomb.src.campaigns_db import build_campaigns
            found = build_campaigns(conn)
            st.success(f"Detected and indexed {found} coordinated campaigns!")
            st.rerun()
    else:
        campaigns = conn.execute("SELECT * FROM campaigns").fetchall()
        st.success(f"Identified **{len(campaigns)}** active multi-session attack campaign(s).")

        for camp in campaigns:
            cid = camp["campaign_id"]
            rule = camp["rule"]
            conf = camp["confidence"]
            evidence = camp["evidence"]
            reason = camp["reason"]

            with st.expander(f"🚩 Campaign ID: `{cid}` — Rule: **{rule}** | Confidence: **{conf.upper()}**", expanded=True):
                st.markdown(f"**Reason / Description:** {reason}")
                st.markdown(f"**Digital Evidence Artifact:** `{evidence}`")

                # Show IPs and sessions involved
                df_sessions = pd.read_sql_query("""
                    SELECT session_id as "Session ID", src_ip as "Attacker IP"
                    FROM campaign_sessions
                    WHERE campaign_id = ?
                """, conn, params=(cid,))
                st.markdown("**Correlated Sessions and Originating IPs:**")
                st.dataframe(df_sessions, use_container_width=True, hide_index=True)

    conn.close()
