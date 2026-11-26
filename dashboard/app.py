"""Honeycomb SOC Dashboard (Stage 4) - Member 2 (Data Pipeline & Storage)

Official Specification (Plan Page 9):
- Built with Streamlit
- 3 Pages:
  1. Overview (نظرة عامة)
  2. IP Details (تفاصيل الـ IP) - strictly plain text for attacker commands
  3. Campaigns (الحملات)
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

# Helper: Seed DB with sample data if empty
def seed_sample_data(db_path=DEFAULT_DB_PATH):
    from honeycomb.src.storage.loader import load_file
    from honeycomb.src.campaigns_db import build_campaigns
    
    res = load_file(db_path, SAMPLE_LOG_PATH)
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
        "اختر الصفحة / Navigation",
        [
            "📊 نظرة عامة (Overview)",
            "🎯 تفاصيل الـ IP (IP Details)",
            "🌐 الحملات (Campaigns)",
        ],
        index=0,
    )

    st.markdown("---")
    st.markdown("### ⚙️ حالة قاعدة البيانات (DB Status)")
    db_ready = is_db_ready()

    if db_ready:
        st.success("🟢 قاعدة البيانات متصلة وجاهزة")
        conn = get_db_connection()
        total_ev = conn.execute("SELECT count(*) FROM events").fetchone()[0]
        total_ips = conn.execute("SELECT count(DISTINCT src_ip) FROM events").fetchone()[0]
        conn.close()
        st.metric("إجمالي الأحداث (Events)", f"{total_ev:,}")
        st.metric("عناوين المهاجمين (IPs)", f"{total_ips:,}")
    else:
        st.warning("🟡 قاعدة البيانات غير محملة")
        if st.button("📥 تحميل بيانات تجريبية (Load Sample)"):
            with st.spinner("جاري تحميل البيانات..."):
                res = seed_sample_data()
                st.success(f"تم تحميل {res['inserted']} حدث بنجاح!")
                st.rerun()

    st.markdown("---")
    st.caption("👤 **Member 2:** Ibrahim Saeed (عضو 2)\n\n📦 **Branch:** feature/dashboard-streamlit")

# Ensure DB has data before rendering pages
if not is_db_ready():
    st.info("👋 مرحباً بك في لوحة تحكم Honeycomb SOC!\n\nيرجى الضغط على زر **'تحميل بيانات تجريبية (Load Sample)'** من القائمة الجانبية لتشغيل البيانات فوراً.")
    st.stop()

# ==============================================================================
# PAGE 1: OVERVIEW (نظرة عامة)
# ==============================================================================
if page == "📊 نظرة عامة (Overview)":
    st.title("📊 لوحة المراقبة العامة (Attack Overview & KPIs)")
    st.markdown("نظرة شاملة على نشاط الفخ (Cowrie Honeypot) وعمليات الاختراق المسجلة.")

    conn = get_db_connection()

    # KPI Metrics Row
    total_events = conn.execute("SELECT count(*) FROM events").fetchone()[0]
    unique_ips = conn.execute("SELECT count(DISTINCT src_ip) FROM events").fetchone()[0]
    total_sessions = conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
    failed_logins = conn.execute("SELECT count(*) FROM events WHERE event_type = 'cowrie.login.failed'").fetchone()[0]
    success_logins = conn.execute("SELECT count(*) FROM events WHERE event_type = 'cowrie.login.success'").fetchone()[0]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🎯 إجمالي الأحداث (Events)", f"{total_events:,}")
    with col2:
        st.metric("🌐 مهاجمين فريدين (Attacker IPs)", f"{unique_ips:,}")
    with col3:
        st.metric("🚪 الجلسات (Sessions)", f"{total_sessions:,}")
    with col4:
        st.metric("🔑 محاولات الدخول", f"{failed_logins} فاشلة / {success_logins} ناجحة")

    st.markdown("---")

    # Charts Row
    c_left, c_right = st.columns([1, 1])

    with c_left:
        st.subheader("🔥 أكثر 10 عناوين IP مهاجمة (Top Attacking IPs)")
        df_top_ips = pd.read_sql_query("""
            SELECT src_ip as "IP Address", count(*) as "Attack Count"
            FROM events
            GROUP BY src_ip
            ORDER BY "Attack Count" DESC
            LIMIT 10
        """, conn)
        st.bar_chart(df_top_ips.set_index("IP Address"))

    with c_right:
        st.subheader("📈 أنواع الأحداث المسجلة (Event Types Distribution)")
        df_types = pd.read_sql_query("""
            SELECT event_type as "Event Type", count(*) as "Count"
            FROM events
            GROUP BY event_type
            ORDER BY "Count" DESC
        """, conn)
        st.dataframe(df_types, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("🕵️ أكثر أسماء المستخدمين والباسوردات المستهدفة (Credentials Targeted)")
    col_u, col_p = st.columns(2)
    with col_u:
        st.markdown("**Usernames الأكثر تخميناً:**")
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
        st.markdown("**Passwords الأكثر استخداماً:**")
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
# PAGE 2: IP DETAILS (تفاصيل الـ IP)
# ==============================================================================
elif page == "🎯 تفاصيل الـ IP (IP Details)":
    st.title("🎯 تفاصيل وتحليل المهاجم (Attacker IP Deep Dive)")
    st.markdown("فحص دقيق لكافة تحركات وأوامر المهاجم مع ضمان أمان العرض كنص عادي.")

    conn = get_db_connection()
    ips_list = [r[0] for r in conn.execute("SELECT DISTINCT src_ip FROM events ORDER BY src_ip").fetchall()]

    selected_ip = st.selectbox("🔍 اختر عنوان الـ IP المطلوب فحصه:", ips_list)

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
        c1.metric("أول ظهور (First Seen)", ip_stats["first_seen"][:19].replace("T", " ") if ip_stats["first_seen"] else "N/A")
        c2.metric("آخر ظهور (Last Seen)", ip_stats["last_seen"][:19].replace("T", " ") if ip_stats["last_seen"] else "N/A")
        c3.metric("عدد الهجمات", ip_stats["total_events"])
        c4.metric("الجلسات المفتوحة", ip_stats["total_sessions"])

        st.markdown("---")

        # Commands Executed (Plain text requirement from plan)
        st.subheader("💻 الأوامر التي كتبها المهاجم (Executed Commands)")
        st.caption("⚠️ يتم عرض الأوامر كنص عادي (Plain Text Safe View) لمنع أي هجمات XSS.")

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
            st.info("لم يقم هذا المهاجم بتنفيذ أي أوامر shell داخل السيرفر (محاولات تسجيل دخول فقط).")

        st.markdown("---")

        # Credentials tried by this IP
        st.subheader("🔑 بيانات الدخول التي جربها هذا الـ IP")
        df_creds = pd.read_sql_query("""
            SELECT ts_utc as "Timestamp", username as "Username", password as "Password", event_type as "Result"
            FROM events
            WHERE src_ip = ? AND (username IS NOT NULL OR password IS NOT NULL)
            ORDER BY ts_utc ASC
        """, conn, params=(selected_ip,))
        st.dataframe(df_creds, use_container_width=True, hide_index=True)

    conn.close()

# ==============================================================================
# PAGE 3: CAMPAIGNS (الحملات)
# ==============================================================================
elif page == "🌐 الحملات (Campaigns)":
    st.title("🌐 كشف الحملات المشبوهة والربط (Campaigns & Correlation)")
    st.markdown("ربط الهجمات القادمة من عناوين مختلفة بناءً على القواعد المشتركة (C1: نفس الملف، C2: نفس الرابط، C3: نفس تسلسل الأوامر).")

    conn = get_db_connection()

    # Check if campaigns table exists and has rows
    try:
        campaigns_count = conn.execute("SELECT count(*) FROM campaigns").fetchone()[0]
    except Exception:
        campaigns_count = 0

    if campaigns_count == 0:
        st.warning("لم يتم إنشاء حملات بعد في قاعدة البيانات.")
        if st.button("⚡ تشغيل محرك الربط وكشف الحملات (Run Correlation Engine)"):
            from honeycomb.src.campaigns_db import build_campaigns
            found = build_campaigns(conn)
            st.success(f"تم اكتشاف وتوثيق {found} حملة مشبوهة!")
            st.rerun()
    else:
        campaigns = conn.execute("SELECT * FROM campaigns").fetchall()
        st.success(f"تم اكتشاف **{len(campaigns)}** حملة هجوم منسقة.")

        for camp in campaigns:
            cid = camp["campaign_id"]
            rule = camp["rule"]
            conf = camp["confidence"]
            evidence = camp["evidence"]
            reason = camp["reason"]

            with st.expander(f"🚩 الحملة: `{cid}` — قاعدة: **{rule}** | درجة الثقة: **{conf.upper()}**", expanded=True):
                st.markdown(f"**السبب والوصف:** {reason}")
                st.markdown(f"**الدليل الرقمي (Evidence):** `{evidence}`")

                # Show IPs and sessions involved
                df_sessions = pd.read_sql_query("""
                    SELECT session_id as "Session ID", src_ip as "Attacker IP"
                    FROM campaign_sessions
                    WHERE campaign_id = ?
                """, conn, params=(cid,))
                st.markdown("**الجلسات وعناوين الـ IP المرتبطة بهذه الحملة:**")
                st.dataframe(df_sessions, use_container_width=True, hide_index=True)

    conn.close()
