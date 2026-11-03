# -*- coding: utf-8 -*-
import atexit
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from flask import Flask
from threading import Thread
import psutil
import requests
import telebot
from telebot import types

# Load local .env when python-dotenv is installed. Render uses Dashboard env vars.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- Configurable Conversion Rate ---
USDT_BDT_RATE = 120.0  # 1 USDT = 120 BDT (প্রয়োজনে পরিবর্তন করতে পারেন)

# --- Flask Web Server + Optional Render Self-Ping ---
app = Flask("tamim_file_host")

# Render injects RENDER_EXTERNAL_URL for deployed web services.
# Self-ping is configurable and is not a guarantee against platform sleep/restarts.
KEEP_ALIVE_ENABLED = os.environ.get("KEEP_ALIVE_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}
KEEP_ALIVE_INTERVAL = max(60, int(os.environ.get("KEEP_ALIVE_INTERVAL", "600")))
KEEP_ALIVE_INITIAL_DELAY = max(0, int(os.environ.get("KEEP_ALIVE_INITIAL_DELAY", "60")))
_shutdown_event = threading.Event()
_web_server_started = False
_web_server_lock = threading.Lock()


@app.route("/")
def home():
    return "I'm TAMIM File Host", 200


@app.route("/health")
def health():
    """Lightweight endpoint used by Render's health checker."""
    return {"status": "ok"}, 200


def run_flask():
    port = int(os.environ.get("PORT", "8080"))
    logger.info("Starting Flask web server on 0.0.0.0:%s", port)
    # Disable the reloader: it would create a second copy of the bot process.
    app.run(host="0.0.0.0", port=port, threaded=True, use_reloader=False)


def render_self_ping():
    """Periodically request this service's public health URL when configured."""
    base_url = os.environ.get("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
    if not KEEP_ALIVE_ENABLED:
        logger.info("Render self-ping is disabled by KEEP_ALIVE_ENABLED.")
        return
    if not base_url:
        logger.info("RENDER_EXTERNAL_URL is not set; self-ping is skipped (local run).")
        return

    health_url = f"{base_url}/health"
    logger.info(
        "Render self-ping enabled: %s (interval=%s seconds)",
        health_url,
        KEEP_ALIVE_INTERVAL,
    )
    session = requests.Session()
    if _shutdown_event.wait(KEEP_ALIVE_INITIAL_DELAY):
        return

    while not _shutdown_event.is_set():
        try:
            response = session.get(health_url, timeout=(5, 15))
            logger.info("Self-ping response: HTTP %s", response.status_code)
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("Self-ping request failed: %s", exc)
        if _shutdown_event.wait(KEEP_ALIVE_INTERVAL):
            break

    session.close()


def keep_alive():
    """Start the web endpoint and optional background self-ping exactly once."""
    global _web_server_started
    with _web_server_lock:
        if _web_server_started:
            return
        _web_server_started = True

    web_thread = Thread(target=run_flask, name="flask-web-server", daemon=True)
    web_thread.start()

    if KEEP_ALIVE_ENABLED and os.environ.get("RENDER_EXTERNAL_URL"):
        ping_thread = Thread(
            target=render_self_ping,
            name="render-self-ping",
            daemon=True,
        )
        ping_thread.start()
    else:
        logger.info("Self-ping thread not started (disabled or no Render URL).")


# --- End Flask Web Server + Optional Render Self-Ping ---

# --- Configuration ---
TOKEN = os.environ.get("BOT_TOKEN", "").strip()
OWNER_ID = int(os.environ.get("OWNER_ID", "8981217915").strip())
ADMIN_ID = int(os.environ.get("ADMIN_ID", str(OWNER_ID)).strip())
YOUR_USERNAME = os.environ.get("YOUR_USERNAME", "@proxearn_support").strip()
UPDATE_CHANNEL = os.environ.get("UPDATE_CHANNEL", "https://t.me/proxearn_official").strip()

# --- Binance Pay Integration Config ---
BINANCE_API_KEY = os.environ.get("BINANCE_API_KEY", "").strip()
BINANCE_SECRET_KEY = (
    os.environ.get("BINANCE_SECRET_KEY", "").strip()
)
BINANCE_PAY_ID = os.environ.get("BINANCE_PAY_ID", "").strip()

# Folder setup - using absolute paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, "upload_bots")
IROTECH_DIR = os.path.join(BASE_DIR, "inf")
DATABASE_PATH = os.path.join(IROTECH_DIR, "bot_data.db")
CONFIG_JSON_PATH = os.path.join(BASE_DIR, "config.json")
USER_JSON_PATH = os.path.join(BASE_DIR, "user.json")
# Used to decide whether JSON snapshots should be restored into a brand-new SQLite DB.
DATABASE_EXISTED_AT_STARTUP = os.path.isfile(DATABASE_PATH) and os.path.getsize(DATABASE_PATH) > 0

# File upload limits
FREE_USER_LIMIT = 1  # Default free limit
SUBSCRIBED_USER_LIMIT = 1500
ADMIN_LIMIT = 999999999999999
OWNER_LIMIT = float("inf")

# Create necessary directories
os.makedirs(UPLOAD_BOTS_DIR, exist_ok=True)
os.makedirs(IROTECH_DIR, exist_ok=True)

# Initialize bot
if not TOKEN:
    raise RuntimeError("BOT_TOKEN environment variable is required.")
bot = telebot.TeleBot(TOKEN)

# --- Data structures ---
bot_scripts = {}
user_subscriptions = {}
user_files = {}
active_users = set()
admin_ids = {ADMIN_ID, OWNER_ID}
bot_locked = False
user_selected_plan = {}  # Temp state for upload flow

# --- Malware Detection Configuration ---
MALWARE_SIGNATURES = [
    b"MZ",  # Windows executable
    b"\x7fELF",  # Linux executable
    b"\xfe\xed\xfa",  # Mach-O binary
    b"\xce\xfa\xed\xfe",  # Mach-O binary (reverse)
    b"PK",  # ZIP archive
    b"Rar!",  # RAR archive
]

ENCRYPTED_FILE_INDICATORS = [
    b"openssl",
    b"encrypted",
    b"cipher",
    b"AES",
    b"DES",
    b"RSA",
    b"GPG",
    b"PGP",
]

SUSPICIOUS_KEYWORDS = [
    b"ransomware",
    b"trojan",
    b"virus",
    b"malware",
    b"backdoor",
    b"exploit",
    b"payload",
    b"botnet",
    b"keylogger",
    b"rootkit",
]

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# --- Command Button Layouts ---
COMMAND_BUTTONS_LAYOUT_USER_SPEC = [
    ["✨ 𝗨𝗽𝗱𝗮𝘁𝗲𝘀 𝗖𝗵𝗮𝗻𝗻𝗲𝗹 ✨"],
    ["🚀 𝗨𝗽𝗹𝗼𝗮𝗱 𝗙𝗶𝗹𝗲", "📁 𝗠𝗮𝗻𝗮𝗴𝗲 𝗙𝗶𝗹𝗲𝘀"],
    ["👤 My Details", "🎁 Refer & Earn"],
    ["💰 My Points", "🆓 Free Hosting Plan"],
    ["⚡ 𝗦𝗽𝗲𝗲𝗱 & 𝗣𝗶𝗻𝗴"],
    ["📊 𝗕𝗼𝘁 𝗦𝘁𝗮𝘁𝘀", "💻 𝗧𝗲𝗿𝗺𝗶𝗻𝗮𝗹 𝗖𝗺𝗱"],
    ["👑 𝗖𝗼𝗻𝘁𝗮𝗰𝘁 𝗢𝘄𝗻𝗲𝗿"],
]

ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC = [
    ["✨ 𝗨𝗽𝗱𝗮𝘁𝗲𝘀 𝗖𝗵𝗮𝗻𝗻𝗲𝗹 ✨"],
    ["🚀 𝗨𝗽𝗹𝗼𝗮d 𝗙𝗶𝗹𝗲", "📁 𝗠𝗮𝗻𝗮𝗴𝗲 𝗙𝗶𝗹𝗲𝘀"],
    ["👤 My Details", "🎁 Refer & Earn"],
    ["💰 My Points", "🆓 Free Hosting Plan"],
    ["🛡️ 𝗔𝗱𝗺𝗶𝗻 𝗣𝗮𝗻𝗲𝗹", "📊 𝗕𝗼𝘁 𝗦𝘁𝗮𝘁𝘀"],
    ["⚡ 𝗦𝗽𝗲𝗲𝗱 & 𝗣𝗶𝗻𝗴"],
    ["👑 𝗖𝗼𝗻𝘁𝗮𝗰𝘁 𝗢𝘄𝗻𝗲𝗿"],
]

# --- Database Setup ---
DB_LOCK = threading.Lock()


def init_db():
    """Initialize the database with required tables"""
    logger.info(f"Initializing database at: {DATABASE_PATH}")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS subscriptions
                     (user_id INTEGER PRIMARY KEY, plan_name TEXT, expiry TEXT)"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS user_files
                     (user_id INTEGER, file_name TEXT, file_type TEXT,
                      PRIMARY KEY (user_id, file_name))"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS active_users
                     (user_id INTEGER PRIMARY KEY)"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS admins
                     (user_id INTEGER PRIMARY KEY)"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS plans
                     (plan_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, file_limit INTEGER, price TEXT, duration INTEGER, buy_link TEXT)"""
        )

        # 🆕 Table for tracking partial payments
        c.execute(
            """CREATE TABLE IF NOT EXISTS pending_payments
                     (user_id INTEGER, plan_id INTEGER, paid_amount REAL,
                      PRIMARY KEY (user_id, plan_id))"""
        )

        # 🆕 Table for tracking used TxIDs to prevent double spending
        c.execute(
            """CREATE TABLE IF NOT EXISTS used_txids
                     (tx_id TEXT PRIMARY KEY)"""
        )

        c.execute("""CREATE TABLE IF NOT EXISTS point_users (
            user_id INTEGER PRIMARY KEY, username TEXT, full_name TEXT, points INTEGER NOT NULL DEFAULT 0,
            referred_by INTEGER, joined_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS point_referrals (
            referred_id INTEGER PRIMARY KEY, referrer_id INTEGER NOT NULL, reward INTEGER NOT NULL, created_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS point_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount INTEGER NOT NULL,
            reason TEXT NOT NULL, admin_id INTEGER, created_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS free_plans (
            plan_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, points_cost INTEGER NOT NULL, days INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1)""")
        # Migrate users already known to the old hosting bot into the points profile table.
        c.execute("INSERT OR IGNORE INTO point_users(user_id, full_name, points, joined_at) SELECT user_id, 'Existing User', 0, ? FROM active_users", (datetime.utcnow().isoformat(),))

        c.execute(
            "INSERT OR IGNORE INTO admins (user_id) VALUES (?)", (OWNER_ID,)
        )
        if ADMIN_ID != OWNER_ID:
            c.execute(
                "INSERT OR IGNORE INTO admins (user_id) VALUES (?)", (ADMIN_ID,)
            )

        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}", exc_info=True)


def load_data():
    """Load data from database into memory"""
    logger.info("Loading data from database...")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()

        c.execute("SELECT user_id, plan_name, expiry FROM subscriptions")
        for row in c.fetchall():
            user_id = row[0]
            plan_name = row[1] if len(row) > 2 else "Premium"
            expiry = row[-1]
            try:
                user_subscriptions[user_id] = {
                    "plan_name": plan_name,
                    "expiry": datetime.fromisoformat(expiry),
                }
            except ValueError:
                logger.warning(
                    f"⚠️ Invalid expiry date format for user {user_id}: {expiry}. Skipping."
                )

        c.execute("SELECT user_id, file_name, file_type FROM user_files")
        for user_id, file_name, file_type in c.fetchall():
            if user_id not in user_files:
                user_files[user_id] = []
            user_files[user_id].append((file_name, file_type))

        c.execute("SELECT user_id FROM active_users")
        active_users.update(user_id for (user_id,) in c.fetchall())

        c.execute("SELECT user_id FROM admins")
        admin_ids.update(user_id for (user_id,) in c.fetchall())

        conn.close()
        logger.info(f"Data loaded successfully.")
    except Exception as e:
        logger.error(f"❌ Error loading data: {e}", exc_info=True)


# --- Automatic JSON Backup / Recovery ---
# SQLite remains the live database. These two JSON files are automatic snapshots:
# config.json stores admin/control data; user.json stores user/account data.
CONFIG_BACKUP_TABLES = ("admins", "plans", "free_plans")
USER_BACKUP_TABLES = (
    "subscriptions", "user_files", "active_users", "pending_payments",
    "used_txids", "point_users", "point_referrals", "point_transactions",
)
JSON_BACKUP_INTERVAL = max(30, int(os.environ.get("JSON_BACKUP_INTERVAL", "60")))
_json_backup_stop = threading.Event()


def _read_table_rows(conn, table_name):
    cur = conn.execute(f'SELECT * FROM "{table_name}"')
    columns = [item[0] for item in cur.description or []]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


def _atomic_write_json(path, payload):
    temp_path = path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, default=str)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def save_json_backups():
    """Write consistent, atomic snapshots of admin and user data."""
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_PATH, timeout=30)
            conn.row_factory = sqlite3.Row
            config_payload = {
                "schema_version": 1,
                "backup_type": "admin_config",
                "saved_at_utc": datetime.utcnow().isoformat() + "Z",
                "owner_id": OWNER_ID,
                "admin_id_env": ADMIN_ID,
                "admin_ids": sorted(int(x) for x in admin_ids),
                "bot_locked": bool(bot_locked),
                "settings": {
                    "your_username": YOUR_USERNAME,
                    "update_channel": UPDATE_CHANNEL,
                    "points_per_referral": POINTS_PER_REFERRAL,
                },
                "tables": {name: _read_table_rows(conn, name) for name in CONFIG_BACKUP_TABLES},
            }
            user_payload = {
                "schema_version": 1,
                "backup_type": "user_data",
                "saved_at_utc": datetime.utcnow().isoformat() + "Z",
                "tables": {name: _read_table_rows(conn, name) for name in USER_BACKUP_TABLES},
            }
            conn.close()
            _atomic_write_json(CONFIG_JSON_PATH, config_payload)
            _atomic_write_json(USER_JSON_PATH, user_payload)
        logger.info("JSON backup completed: config.json and user.json")
        return True
    except Exception:
        logger.exception("JSON backup failed")
        return False


def _restore_json_tables(conn, payload, allowed_tables):
    tables = payload.get("tables", {}) if isinstance(payload, dict) else {}
    restored = 0
    for table_name in allowed_tables:
        rows = tables.get(table_name, [])
        if not isinstance(rows, list) or not rows:
            continue
        existing = conn.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()[0]
        if existing:
            continue
        valid_columns = {row[1] for row in conn.execute(f'PRAGMA table_info("{table_name}")')}
        for row in rows:
            if not isinstance(row, dict):
                continue
            columns = [key for key in row if key in valid_columns]
            if not columns:
                continue
            quoted = ",".join(f'"{key}"' for key in columns)
            placeholders = ",".join("?" for _ in columns)
            values = [row[key] for key in columns]
            conn.execute(
                f'INSERT OR IGNORE INTO "{table_name}" ({quoted}) VALUES ({placeholders})',
                values,
            )
            restored += 1
    return restored


def restore_json_backups_if_needed():
    """Restore snapshots only when SQLite did not exist at process startup."""
    global bot_locked
    if DATABASE_EXISTED_AT_STARTUP:
        return
    restored_total = 0
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=30)
        if os.path.isfile(CONFIG_JSON_PATH):
            with open(CONFIG_JSON_PATH, "r", encoding="utf-8") as handle:
                config_payload = json.load(handle)
            restored_total += _restore_json_tables(conn, config_payload, CONFIG_BACKUP_TABLES)
            bot_locked = bool(config_payload.get("bot_locked", False))
            saved_admins = config_payload.get("admin_ids", [])
            for admin_id in saved_admins:
                try:
                    conn.execute("INSERT OR IGNORE INTO admins(user_id) VALUES(?)", (int(admin_id),))
                except (TypeError, ValueError):
                    continue
        if os.path.isfile(USER_JSON_PATH):
            with open(USER_JSON_PATH, "r", encoding="utf-8") as handle:
                user_payload = json.load(handle)
            restored_total += _restore_json_tables(conn, user_payload, USER_BACKUP_TABLES)
        conn.commit()
        conn.close()
        if restored_total:
            logger.warning("Recovered %s rows from JSON snapshots into fresh SQLite database", restored_total)
        else:
            logger.info("No previous JSON snapshot found; starting with a fresh database")
    except Exception:
        logger.exception("JSON recovery failed; check config.json and user.json")


def json_backup_worker():
    while not _json_backup_stop.wait(JSON_BACKUP_INTERVAL):
        save_json_backups()


def start_json_backup_worker():
    save_json_backups()
    worker = Thread(target=json_backup_worker, name="json-backup-worker", daemon=True)
    worker.start()


# --- Points, Referral and Free Hosting Plan System ---
POINTS_PER_REFERRAL = int(os.environ.get("POINTS_PER_REFERRAL", "200"))

def db_connect():
    return sqlite3.connect(DATABASE_PATH, check_same_thread=False)

def ensure_point_user(tg_user, referral_id=None):
    uid = int(tg_user.id)
    now = datetime.utcnow().isoformat()
    conn = db_connect(); cur = conn.cursor()
    cur.execute("SELECT user_id FROM point_users WHERE user_id=?", (uid,))
    is_new = cur.fetchone() is None
    if is_new:
        valid_ref = int(referral_id) if referral_id and int(referral_id) != uid else None
        if valid_ref:
            cur.execute("SELECT user_id FROM point_users WHERE user_id=?", (valid_ref,))
            if not cur.fetchone(): valid_ref = None
        cur.execute("INSERT INTO point_users(user_id,username,full_name,points,referred_by,joined_at) VALUES(?,?,?,?,?,?)",
                    (uid, getattr(tg_user,'username',None), getattr(tg_user,'first_name','') or '', 0, valid_ref, now))
        if valid_ref:
            cur.execute("INSERT OR IGNORE INTO point_referrals(referred_id,referrer_id,reward,created_at) VALUES(?,?,?,?)",
                        (uid, valid_ref, POINTS_PER_REFERRAL, now))
            if cur.rowcount:
                cur.execute("UPDATE point_users SET points=points+? WHERE user_id=?", (POINTS_PER_REFERRAL, valid_ref))
                cur.execute("INSERT INTO point_transactions(user_id,amount,reason,created_at) VALUES(?,?,?,?)",
                            (valid_ref, POINTS_PER_REFERRAL, f'Referral reward: {uid}', now))
    else:
        cur.execute("UPDATE point_users SET username=?,full_name=? WHERE user_id=?",
                    (getattr(tg_user,'username',None), getattr(tg_user,'first_name','') or '', uid))
    conn.commit(); conn.close()
    return is_new

def get_points(user_id):
    conn=db_connect(); cur=conn.cursor(); cur.execute("SELECT points FROM point_users WHERE user_id=?",(int(user_id),)); row=cur.fetchone(); conn.close()
    return int(row[0]) if row else 0

def ensure_point_target(user_id):
    conn=db_connect(); conn.execute("INSERT OR IGNORE INTO point_users(user_id,full_name,points,joined_at) VALUES(?,?,0,?)",(int(user_id),f'User {user_id}',datetime.utcnow().isoformat())); conn.commit(); conn.close()

def change_user_points(user_id, amount, reason, admin_id=None):
    ensure_point_target(user_id)
    conn=db_connect(); cur=conn.cursor(); cur.execute("SELECT points FROM point_users WHERE user_id=?",(int(user_id),)); row=cur.fetchone()
    if not row or int(row[0])+int(amount)<0: conn.close(); return False
    cur.execute("UPDATE point_users SET points=points+? WHERE user_id=?",(int(amount),int(user_id)))
    cur.execute("INSERT INTO point_transactions(user_id,amount,reason,admin_id,created_at) VALUES(?,?,?,?,?)",
                (int(user_id),int(amount),reason,admin_id,datetime.utcnow().isoformat()))
    conn.commit(); conn.close(); return True

def get_free_plans():
    conn=db_connect(); rows=conn.execute("SELECT plan_id,name,points_cost,days FROM free_plans WHERE active=1 ORDER BY plan_id").fetchall(); conn.close(); return rows

def add_free_plan(name, points_cost, days):
    conn=db_connect(); conn.execute("INSERT INTO free_plans(name,points_cost,days,active) VALUES(?,?,?,1)",(name,int(points_cost),int(days))); conn.commit(); conn.close()

def activate_free_plan(user_id, plan_id):
    conn=db_connect(); cur=conn.cursor(); cur.execute("SELECT name,points_cost,days FROM free_plans WHERE plan_id=? AND active=1",(int(plan_id),)); plan=cur.fetchone()
    cur.execute("SELECT points FROM point_users WHERE user_id=?",(int(user_id),)); user=cur.fetchone()
    if not plan or not user or int(user[0])<int(plan[1]): conn.close(); return None
    now=datetime.now(); expiry=now+timedelta(days=int(plan[2]))
    cur.execute("UPDATE point_users SET points=points-? WHERE user_id=?",(int(plan[1]),int(user_id)))
    cur.execute("INSERT INTO point_transactions(user_id,amount,reason,created_at) VALUES(?,?,?,?)",
                (int(user_id),-int(plan[1]),f'Activated free plan: {plan[0]}',datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    save_subscription(int(user_id),str(plan[0]),expiry)
    return (str(plan[0]),int(plan[1]),int(plan[2]),expiry)


init_db()
restore_json_backups_if_needed()
load_data()


# --- Price Parser & Conversion Helper ---
def parse_price_to_usdt(price_str):
    """
    টাকা বা ডলারের ফিল্ড থেকে সংখ্যা ও কারেন্সি বের করে USDT কনভার্ট করে।
    যেমন: '500 BDT' -> (4.17, '500 BDT (~4.17 USDT)')
    '5 USDT' -> (5.0, '5.0 USDT')
    """
    price_clean = str(price_str).upper().strip()
    numbers = re.findall(r"[-+]?\d*\.\d+|\d+", price_clean)
    if not numbers:
        return 0.0, price_str

    val = float(numbers[0])
    if "BDT" in price_clean or "TAKA" in price_clean or "TK" in price_clean:
        usdt_val = round(val / USDT_BDT_RATE, 2)
        return usdt_val, f"{price_str} (~{usdt_val} USDT)"
    elif "USDT" in price_clean or "$" in price_clean or "USD" in price_clean:
        return round(val, 2), f"{val} USDT"
    else:
        # ডিফল্ট যদি শুধু সংখ্যা দেওয়া হয় তবে USDT ধরা হবে
        return round(val, 2), f"{val} USDT"


# --- Database Helper Operations ---
def add_plan_db(name, file_limit, price, duration, buy_link):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            "INSERT INTO plans (name, file_limit, price, duration, buy_link) VALUES (?, ?, ?, ?, ?)",
            (name, file_limit, price, duration, buy_link),
        )
        conn.commit()
        conn.close()


def get_all_plans():
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()
    c.execute(
        "SELECT plan_id, name, file_limit, price, duration, buy_link FROM plans"
    )
    plans = c.fetchall()
    conn.close()
    return plans


def get_plan_by_id(plan_id):
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()
    c.execute(
        "SELECT plan_id, name, file_limit, price, duration, buy_link FROM plans WHERE plan_id = ?",
        (plan_id,),
    )
    plan = c.fetchone()
    conn.close()
    return plan


def delete_plan_db(plan_id):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute("DELETE FROM plans WHERE plan_id = ?", (plan_id,))
        conn.commit()
        conn.close()


# --- Partial Payment Helpers ---
def get_pending_payment(user_id, plan_id):
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()
    c.execute(
        "SELECT paid_amount FROM pending_payments WHERE user_id=? AND plan_id=?",
        (user_id, plan_id),
    )
    row = c.fetchone()
    conn.close()
    return row[0] if row else 0.0


def update_pending_payment(user_id, plan_id, amount):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO pending_payments (user_id, plan_id, paid_amount) VALUES (?, ?, ?)",
            (user_id, plan_id, amount),
        )
        conn.commit()
        conn.close()


def clear_pending_payment(user_id, plan_id):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            "DELETE FROM pending_payments WHERE user_id=? AND plan_id=?",
            (user_id, plan_id),
        )
        conn.commit()
        conn.close()


def is_txid_used(tx_id):
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()
    c.execute(
        "SELECT tx_id FROM used_txids WHERE tx_id=?", (str(tx_id).strip(),)
    )
    row = c.fetchone()
    conn.close()
    return row is not None


def add_used_txid(tx_id):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO used_txids (tx_id) VALUES (?)",
            (str(tx_id).strip(),),
        )
        conn.commit()
        conn.close()


# --- Binance Pay Verification Function ---
def check_binance_payment(pay_order_id):
    """Verifies payment strictly via Binance Pay API"""
    if (
        not BINANCE_API_KEY
        or BINANCE_API_KEY == "YOUR_NEW_BINANCE_API_KEY_HERE"
    ):
        return False, 0.0, "Binance API Key configured নেই।"

    endpoint = "https://api.binance.com/sapi/v1/pay/transactions"
    timestamp = int(time.time() * 1000)
    query_string = f"timestamp={timestamp}"

    signature = hmac.new(
        BINANCE_SECRET_KEY.encode("utf-8"),
        query_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    url = f"{endpoint}?{query_string}&signature={signature}"
    headers = {"X-MBX-APIKEY": BINANCE_API_KEY}

    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            data = res.json()
            transactions = (
                data.get("data", []) if isinstance(data, dict) else data
            )

            for item in transactions:
                order_id_str = str(
                    item.get("orderId", "") or item.get("transactionId", "")
                )
                if order_id_str.strip() == str(pay_order_id).strip():
                    amount = float(item.get("amount", 0.0))
                    currency = item.get("currency", "USDT")
                    return True, amount, f"{amount} {currency}"

            return (
                False,
                0.0,
                "এই Order/Transaction ID টি আপনার Binance Pay হিস্টোরিতে পাওয়া যায়নি।",
            )
        else:
            logger.error(f"Binance Pay API Error: {res.text}")
            return False, 0.0, "Binance Server Error বা API পারমিশন ইস্যু।"
    except Exception as e:
        logger.error(f"Binance Verification Error: {e}")
        return False, 0.0, f"Error: {str(e)}"


# --- Malware Detection Functions ---
def is_suspicious_file(file_content, file_name):
    file_lower = file_name.lower()
    suspicious_extensions = [
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".scr",
        ".com",
        ".pif",
        ".application",
        ".gadget",
        ".msi",
        ".msp",
        ".com",
        ".scr",
        ".hta",
        ".cpl",
        ".msc",
        ".jar",
        ".bin",
        ".deb",
        ".rpm",
        ".apk",
        ".app",
        ".dmg",
        ".iso",
        ".img",
    ]
    if any(file_lower.endswith(ext) for ext in suspicious_extensions):
        return True, f"Suspicious file extension: {file_name}"
    for signature in MALWARE_SIGNATURES:
        if file_content.startswith(signature):
            return True, f"Malware signature detected: {signature}"
    sample_size = min(len(file_content), 4096)
    file_sample = file_content[:sample_size]
    for indicator in ENCRYPTED_FILE_INDICATORS:
        if indicator in file_sample:
            return (
                True,
                f"Encrypted file indicator: {indicator.decode('utf-8', errors='ignore')}",
            )
    sample_text = file_sample.decode("utf-8", errors="ignore").lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.decode("utf-8").lower() in sample_text:
            return True, f"Suspicious keyword found: {keyword.decode('utf-8')}"
    return False, "File appears safe"


def scan_file_for_malware(file_content, file_name, user_id):
    if user_id == OWNER_ID:
        return True, "Owner bypassed security check"
    is_suspicious, reason = is_suspicious_file(file_content, file_name)
    if is_suspicious:
        logger.warning(
            f"🚨 Malware detected in {file_name} from user {user_id}: {reason}"
        )
        return False, f"Security violation: {reason}"
    return True, "File passed security check"


# --- Helper Functions ---
def get_user_folder(user_id):
    user_folder = os.path.join(UPLOAD_BOTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    return user_folder


def get_user_file_limit(user_id):
    if user_id == OWNER_ID:
        return OWNER_LIMIT
    if user_id in admin_ids:
        return ADMIN_LIMIT
    if (
        user_id in user_subscriptions
        and user_subscriptions[user_id]["expiry"] > datetime.now()
    ):
        return SUBSCRIBED_USER_LIMIT
    return FREE_USER_LIMIT


def get_user_file_count(user_id):
    return len(user_files.get(user_id, []))


def is_bot_running(script_owner_id, file_name):
    script_key = f"{script_owner_id}_{file_name}"
    script_info = bot_scripts.get(script_key)
    if script_info and script_info.get("process"):
        try:
            proc = psutil.Process(script_info["process"].pid)
            is_running = (
                proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            )
            if not is_running:
                if (
                    "log_file" in script_info
                    and hasattr(script_info["log_file"], "close")
                    and not script_info["log_file"].closed
                ):
                    try:
                        script_info["log_file"].close()
                    except Exception:
                        pass
                if script_key in bot_scripts:
                    del bot_scripts[script_key]
            return is_running
        except psutil.NoSuchProcess:
            if script_key in bot_scripts:
                del bot_scripts[script_key]
            return False
        except Exception:
            return False
    return False


def kill_process_tree(process_info):
    try:
        if (
            "log_file" in process_info
            and hasattr(process_info["log_file"], "close")
            and not process_info["log_file"].closed
        ):
            try:
                process_info["log_file"].close()
            except Exception:
                pass
        process = process_info.get("process")
        if process and hasattr(process, "pid"):
            pid = process.pid
            if pid:
                parent = psutil.Process(pid)
                for child in parent.children(recursive=True):
                    try:
                        child.terminate()
                    except Exception:
                        pass
                try:
                    parent.terminate()
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"❌ Error killing process: {e}")


# --- Module / Package Mapping ---
TELEGRAM_MODULES = {
    "telebot": "pyTelegramBotAPI",
    "telegram": "python-telegram-bot",
    "python_telegram_bot": "python-telegram-bot",
    "aiogram": "aiogram",
    "pyrogram": "pyrogram",
    "telethon": "telethon",
    "bs4": "beautifulsoup4",
    "requests": "requests",
    "pillow": "Pillow",
    "cv2": "opencv-python",
    "flask": "Flask",
    "psutil": "psutil",
}


# --- Automatic & Guided Script Running ---
def monitor_and_guide_error(
    process, log_file_path, script_owner_id, file_name, message_obj_for_reply
):
    """রানিং স্ক্রিপ্ট ব্যাকগ্রাউন্ডে চেক করে কোনো এরর থাকলে ইউজারকে বাটন দিয়ে বুঝিয়ে দেবে"""
    time.sleep(3)
    if process.poll() is not None:
        try:
            with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
                log_content = f.read()

            match_py = re.search(
                r"(?:ModuleNotFoundError|ImportError): No module named '(.+?)'",
                log_content,
            )
            match_js = re.search(r"Cannot find module '(.+?)'", log_content)

            missing_module = None
            if match_py:
                missing_module = match_py.group(1).split(".")[0].strip("'\"")
            elif match_js:
                missing_module = match_js.group(1).split("/")[0].strip("'\"")

            if missing_module:
                pkg_name = TELEGRAM_MODULES.get(
                    missing_module.lower(), missing_module
                )
                ext = os.path.splitext(file_name)[1].lower()
                cmd_text = (
                    f"npm install {pkg_name}"
                    if ext == ".js"
                    else f"pip install {pkg_name}"
                )

                error_msg = (
                    f"⚠️ **ফাইল রান হতে সমস্যা হয়েছে!**\n\n"
                    f"📄 **File:** `{file_name}`\n"
                    f"❌ **সমস্যা:** আপনার কোডে `{missing_module}` মডিউলটি মিসিং আছে।\n"
                    f"💻 **প্রয়োজনীয় কমান্ড:** `{cmd_text}`\n\n"
                    f"👇 *নিচের বাটনে প্রেস করে সরাসরি মডিউলটি ইনস্টল করুন:*"
                )

                markup = types.InlineKeyboardMarkup()
                markup.add(
                    types.InlineKeyboardButton(
                        f"📦 Install {pkg_name}",
                        callback_data=f"instmod_{script_owner_id}_{missing_module}_{file_name}",
                    )
                )
                markup.add(
                    types.InlineKeyboardButton(
                        "📄 View Error Logs",
                        callback_data=f"viewlog_{script_owner_id}_{file_name}",
                    )
                )

                bot.reply_to(
                    message_obj_for_reply,
                    error_msg,
                    reply_markup=markup,
                    parse_mode="Markdown",
                )
            else:
                error_msg = (
                    f"⚠️ **আপনার কোডে ভুল (Syntax/Runtime Error) পাওয়া গেছে!**\n\n"
                    f"📄 **File:** `{file_name}`\n"
                    f"সুনির্দিষ্ট এরর জানতে নিচের **View Logs** বাটনে ক্লিক করুন।"
                )
                markup = types.InlineKeyboardMarkup()
                markup.add(
                    types.InlineKeyboardButton(
                        "📄 View Error Logs",
                        callback_data=f"viewlog_{script_owner_id}_{file_name}",
                    )
                )
                bot.reply_to(
                    message_obj_for_reply,
                    error_msg,
                    reply_markup=markup,
                    parse_mode="Markdown",
                )
        except Exception as e:
            logger.error(f"Error checking log file: {e}")


def run_script(
    script_path, script_owner_id, user_folder, file_name, message_obj_for_reply
):
    script_key = f"{script_owner_id}_{file_name}"
    try:
        log_file_path = os.path.join(
            user_folder, f"{os.path.splitext(file_name)[0]}.log"
        )
        log_file = open(log_file_path, "w", encoding="utf-8", errors="ignore")
        process = subprocess.Popen(
            [sys.executable, script_path],
            cwd=user_folder,
            stdout=log_file,
            stderr=log_file,
            stdin=subprocess.PIPE,
        )

        bot_scripts[script_key] = {
            "process": process,
            "log_file": log_file,
            "file_name": file_name,
            "script_owner_id": script_owner_id,
            "start_time": datetime.now(),
            "user_folder": user_folder,
            "type": "py",
            "script_key": script_key,
        }

        bot.reply_to(
            message_obj_for_reply,
            f"🚀 **Python Script Started!**\n📄 File: `{file_name}`\n🆔 PID: `{process.pid}`",
            parse_mode="Markdown",
        )

        threading.Thread(
            target=monitor_and_guide_error,
            args=(
                process,
                log_file_path,
                script_owner_id,
                file_name,
                message_obj_for_reply,
            ),
        ).start()

    except Exception as e:
        bot.reply_to(message_obj_for_reply, f"❌ Error running script: {str(e)}")


def run_js_script(
    script_path, script_owner_id, user_folder, file_name, message_obj_for_reply
):
    script_key = f"{script_owner_id}_{file_name}"
    try:
        log_file_path = os.path.join(
            user_folder, f"{os.path.splitext(file_name)[0]}.log"
        )
        log_file = open(log_file_path, "w", encoding="utf-8", errors="ignore")
        process = subprocess.Popen(
            ["node", script_path],
            cwd=user_folder,
            stdout=log_file,
            stderr=log_file,
            stdin=subprocess.PIPE,
        )

        bot_scripts[script_key] = {
            "process": process,
            "log_file": log_file,
            "file_name": file_name,
            "script_owner_id": script_owner_id,
            "start_time": datetime.now(),
            "user_folder": user_folder,
            "type": "js",
            "script_key": script_key,
        }

        bot.reply_to(
            message_obj_for_reply,
            f"🚀 **JS Script Started!**\n📄 File: `{file_name}`\n🆔 PID: `{process.pid}`",
            parse_mode="Markdown",
        )

        threading.Thread(
            target=monitor_and_guide_error,
            args=(
                process,
                log_file_path,
                script_owner_id,
                file_name,
                message_obj_for_reply,
            ),
        ).start()

    except Exception as e:
        bot.reply_to(
            message_obj_for_reply, f"❌ Error running JS script: {str(e)}"
        )


# --- Database Operations ---
def save_user_file(user_id, file_name, file_type="py"):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO user_files (user_id, file_name, file_type) VALUES (?, ?, ?)",
            (user_id, file_name, file_type),
        )
        conn.commit()
        conn.close()
        if user_id not in user_files:
            user_files[user_id] = []
        user_files[user_id] = [
            (fn, ft) for fn, ft in user_files[user_id] if fn != file_name
        ]
        user_files[user_id].append((file_name, file_type))


def remove_user_file_db(user_id, file_name):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            "DELETE FROM user_files WHERE user_id = ? AND file_name = ?",
            (user_id, file_name),
        )
        conn.commit()
        conn.close()
        if user_id in user_files:
            user_files[user_id] = [
                f for f in user_files[user_id] if f[0] != file_name
            ]


def add_active_user(user_id):
    active_users.add(user_id)
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO active_users (user_id) VALUES (?)", (user_id,)
        )
        conn.commit()
        conn.close()


def save_subscription(user_id, plan_name, expiry):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO subscriptions (user_id, plan_name, expiry) VALUES (?, ?, ?)",
            (user_id, plan_name, expiry.isoformat()),
        )
        conn.commit()
        conn.close()
        user_subscriptions[user_id] = {"plan_name": plan_name, "expiry": expiry}


def remove_subscription_db(user_id):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute("DELETE FROM subscriptions WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        if user_id in user_subscriptions:
            del user_subscriptions[user_id]


# --- Menu Creation ---
def create_reply_keyboard_main_menu(user_id):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    layout_to_use = (
        ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC
        if user_id in admin_ids
        else COMMAND_BUTTONS_LAYOUT_USER_SPEC
    )
    for row in layout_to_use:
        markup.add(*[types.KeyboardButton(text) for text in row])
    return markup


def create_admin_panel_inline():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("➕ Add Free Plan", callback_data="add_free_plan"),
        types.InlineKeyboardButton("📋 Free Plans", callback_data="list_free_plans"),
    )
    markup.add(
        types.InlineKeyboardButton("➕ Add Points", callback_data="admin_add_points"),
        types.InlineKeyboardButton("➖ Remove Points", callback_data="admin_remove_points"),
    )
    markup.add(types.InlineKeyboardButton("👥 User Lookup", callback_data="admin_user_lookup"))
    markup.add(
        types.InlineKeyboardButton(
            "💎 𝗔𝗱𝗱 𝗦𝘂𝗯𝘀𝗰𝗿𝗶𝗽𝘁𝗶𝗼𝗻", callback_data="add_subscription"
        ),
        types.InlineKeyboardButton(
            "❌ 𝗥𝗲𝗺𝗼𝘃𝗲 𝗦𝘂𝗯", callback_data="remove_subscription"
        ),
    )
    markup.add(
        types.InlineKeyboardButton("👑 𝗔𝗱𝗱 𝗔𝗱𝗺𝗶𝗻", callback_data="add_admin"),
        types.InlineKeyboardButton(
            "➖ 𝗥𝗲𝗺𝗼𝘃𝗲 𝗔𝗱𝗺𝗶𝗻", callback_data="remove_admin"
        ),
    )
    markup.add(
        types.InlineKeyboardButton("📣 𝗕𝗿𝗼𝗮𝗱𝗰𝗮𝘀𝘁", callback_data="broadcast"),
        types.InlineKeyboardButton(
            "🔐 𝗟𝗼𝗰𝗸/𝗨𝗻𝗹𝗼𝗰𝗸", callback_data="toggle_lock"
        ),
    )
    markup.add(
        types.InlineKeyboardButton(
            "⚙️ 𝗥𝘂𝗻 𝗔𝗹𝗹 𝗦𝗰𝗿𝗶𝗽𝘁𝘀", callback_data="run_all_scripts"
        ),
        types.InlineKeyboardButton("📊 𝗕𝗼𝘁 𝗦𝘁𝗮𝘁𝘀", callback_data="stats"),
    )
    return markup


# --- Core User Logic ---
def _logic_send_welcome(message):
    user_id = message.from_user.id
    payload = (message.text or "").split(maxsplit=1)
    ref_id = None
    if len(payload) > 1 and payload[1].startswith("ref_"):
        try: ref_id = int(payload[1][4:])
        except ValueError: pass
    is_new = ensure_point_user(message.from_user, ref_id)
    if bot_locked and user_id not in admin_ids:
        bot.send_message(message.chat.id, "⚠️ Bot is temporarily locked by Admin.")
        return
    if user_id not in active_users: add_active_user(user_id)
    if is_new and ref_id and ref_id != user_id and get_points(ref_id) >= POINTS_PER_REFERRAL:
        try: bot.send_message(ref_id, f"🎉 নতুন Referral যুক্ত হয়েছে! +{POINTS_PER_REFERRAL} Points পেয়েছেন।")
        except Exception: pass
    status = "Owner" if user_id == OWNER_ID else ("Admin" if user_id in admin_ids else ("Active Plan" if user_id in user_subscriptions and user_subscriptions[user_id]["expiry"] > datetime.now() else "No Active Plan"))
    welcome_msg = (f"✨ Welcome, {message.from_user.first_name}! ✨\n\n🆔 ID: `{user_id}`\n🔰 Status: {status}\n💰 Points: `{get_points(user_id)}`\n📁 Uploaded Files: `{get_user_file_count(user_id)}` / `{get_user_file_limit(user_id)}`\n\nHost & run your Python (.py) and JS (.js) files.")
    bot.send_message(message.chat.id, welcome_msg, reply_markup=create_reply_keyboard_main_menu(user_id), parse_mode="Markdown")

def send_my_details(message):
    uid=message.from_user.id; ensure_point_user(message.from_user)
    sub=user_subscriptions.get(uid); active=bool(sub and sub.get('expiry')>datetime.now())
    ref_conn=db_connect(); refs=ref_conn.execute("SELECT COUNT(*) FROM point_referrals WHERE referrer_id=?",(uid,)).fetchone()[0]; ref_conn.close()
    plan=(f"{sub.get('plan_name')} (expires {sub.get('expiry').strftime('%Y-%m-%d %H:%M')})" if active else "No active plan")
    bot.send_message(message.chat.id, f"👤 *My Details*\n🆔 ID: `{uid}`\nName: {message.from_user.first_name}\nUsername: @{message.from_user.username or 'not set'}\n💰 Points: `{get_points(uid)}`\n🎁 Referrals: `{refs}`\n💎 Plan: {plan}\n📁 Uploaded files: `{get_user_file_count(uid)}`", reply_markup=create_reply_keyboard_main_menu(uid), parse_mode="Markdown")

def send_points(message):
    uid=message.from_user.id; ensure_point_user(message.from_user)
    conn=db_connect(); rows=conn.execute("SELECT amount,reason,created_at FROM point_transactions WHERE user_id=? ORDER BY id DESC LIMIT 8",(uid,)).fetchall(); conn.close()
    lines=[f"💰 *Your Points: {get_points(uid)}*", "", "*Recent transactions:*"]
    lines += [f"• {a:+} — {r}" for a,r,_ in rows] if rows else ["No transactions yet."]
    bot.send_message(message.chat.id,"\n".join(lines),reply_markup=create_reply_keyboard_main_menu(uid),parse_mode="Markdown")

def send_referral(message):
    uid=message.from_user.id; ensure_point_user(message.from_user); me=bot.get_me()
    conn=db_connect(); count=conn.execute("SELECT COUNT(*) FROM point_referrals WHERE referrer_id=?",(uid,)).fetchone()[0]; conn.close()
    link=f"https://t.me/{me.username}?start=ref_{uid}"
    bot.send_message(message.chat.id,f"🎁 *Refer & Earn*\nYour link: `{link}`\nReward: *{POINTS_PER_REFERRAL} points* per new user.\nSuccessful referrals: `{count}`\nSelf/duplicate referrals are not rewarded.",reply_markup=create_reply_keyboard_main_menu(uid),parse_mode="Markdown")


def _logic_view_plans(message_or_call):
    chat_id = message_or_call.chat.id if isinstance(message_or_call, telebot.types.Message) else message_or_call.message.chat.id
    plans=get_free_plans()
    if not plans:
        bot.send_message(chat_id,"🆓 বর্তমানে কোনো Free Hosting Plan নেই। Admin পরে Plan যোগ করতে পারবেন।")
        return
    bot.send_message(chat_id,"🆓 *Available Free Hosting Plans*\nPoints দিয়ে Plan Activate করুন:",parse_mode="Markdown")
    for pid,name,cost,days in plans:
        markup=types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(f"✅ Activate — {cost} Points",callback_data=f"activate_free_{pid}"))
        bot.send_message(chat_id,f"📦 *{name}*\n💰 Cost: `{cost} Points`\n⏳ Duration: `{days} Days`",reply_markup=markup,parse_mode="Markdown")


def _logic_upload_file(message):
    user_id = message.from_user.id
    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ **Bot is locked by Admin.**")
        return

    has_active_plan = False
    plan_name = "None"

    if user_id in admin_ids or user_id == OWNER_ID:
        has_active_plan = True
        plan_name = "Admin / Owner Unlimited"
    elif user_id in user_subscriptions:
        sub = user_subscriptions[user_id]
        if sub["expiry"] > datetime.now():
            has_active_plan = True
            plan_name = sub.get("plan_name", "Premium Plan")

    if not has_active_plan:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🆓 View Free Hosting Plans", callback_data="view_plans_cb"))
        bot.reply_to(
            message,
            "❌ আপনার কোনো Active Hosting Plan নেই।\nপ্রথমে Points দিয়ে একটি Free Hosting Plan Activate করুন।",
            reply_markup=markup,
            parse_mode="Markdown",
        )
        return

    markup = types.InlineKeyboardMarkup()
    markup.add(
        types.InlineKeyboardButton(
            f"✅ Continue with {plan_name}", callback_data="confirm_plan_upload"
        )
    )
    bot.reply_to(
        message,
        f"🔰 **𝗔𝗰𝘁𝗶𝘃𝗲 𝗣𝗹𝗮𝗻 𝗗𝗲𝘁𝗲𝗰𝘁𝗲𝗱:** `{plan_name}`\n\n"
        f"ফাইল আপলোড চালু করতে নিচের বাটনে সিলেক্ট করুন:",
        reply_markup=markup,
        parse_mode="Markdown",
    )


def _logic_check_files(message):
    user_id = message.from_user.id
    user_files_list = user_files.get(user_id, [])
    if not user_files_list:
        bot.reply_to(
            message,
            "📂 **Your Uploaded Files:**\n\n*(No files uploaded yet)*",
            parse_mode="Markdown",
        )
        return
    markup = types.InlineKeyboardMarkup(row_width=1)
    for file_name, file_type in sorted(user_files_list):
        is_running = is_bot_running(user_id, file_name)
        status_icon = "🟢 Running" if is_running else "🔴 Stopped"
        btn_text = f"📄 {file_name} ({file_type}) - {status_icon}"
        markup.add(
            types.InlineKeyboardButton(
                btn_text, callback_data=f"file_{user_id}_{file_name}"
            )
        )
    bot.reply_to(
        message,
        "📁 **𝗠𝗮𝗻𝗮𝗴𝗲 𝗬𝗼𝘂𝗿 𝗙𝗶𝗹𝗲𝘀:**",
        reply_markup=markup,
        parse_mode="Markdown",
    )


# --- Document Upload Processing ---
@bot.message_handler(content_types=["document"])
def handle_file_upload_doc(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    doc = message.document

    if user_id not in admin_ids and user_id != OWNER_ID:
        if (
            user_id not in user_subscriptions
            or user_subscriptions[user_id]["expiry"] <= datetime.now()
        ):
            bot.reply_to(
                message,
                "❌ **আপনার কোন এক্টিভ প্ল্যান নেই! ফাইল আপলোড করতে প্ল্যান ক্রয় করুন।**",
                parse_mode="Markdown",
            )
            return

    file_name = doc.file_name
    file_ext = os.path.splitext(file_name)[1].lower()
    if file_ext not in [".py", ".js", ".zip"]:
        bot.reply_to(
            message,
            "⚠️ **Only `.py`, `.js`, and `.zip` files are supported!**",
            parse_mode="Markdown",
        )
        return

    try:
        download_wait_msg = bot.reply_to(
            message,
            f"⏳ **Downloading `{file_name}`...**",
            parse_mode="Markdown",
        )
        file_info_tg_doc = bot.get_file(doc.file_id)
        downloaded_file_content = bot.download_file(file_info_tg_doc.file_path)

        if user_id != OWNER_ID:
            is_safe, reason = scan_file_for_malware(
                downloaded_file_content, file_name, user_id
            )
            if not is_safe:
                bot.edit_message_text(
                    f"🚨 **Security Alert:** {reason}",
                    chat_id,
                    download_wait_msg.message_id,
                    parse_mode="Markdown",
                )
                return

        user_folder = get_user_folder(user_id)
        file_path = os.path.join(user_folder, file_name)
        with open(file_path, "wb") as f:
            f.write(downloaded_file_content)

        bot.edit_message_text(
            f"✅ **File `{file_name}` uploaded successfully!**",
            chat_id,
            download_wait_msg.message_id,
            parse_mode="Markdown",
        )

        if file_ext == ".js":
            save_user_file(user_id, file_name, "js")
            threading.Thread(
                target=run_js_script,
                args=(file_path, user_id, user_folder, file_name, message),
            ).start()
        elif file_ext == ".py":
            save_user_file(user_id, file_name, "py")
            threading.Thread(
                target=run_script,
                args=(file_path, user_id, user_folder, file_name, message),
            ).start()

    except Exception as e:
        bot.reply_to(message, f"❌ **Error:** {str(e)}")


# --- Callback Routing ---
@bot.callback_query_handler(func=lambda call: True)
def handle_callbacks(call):
    user_id = call.from_user.id
    data = call.data

    if data == "view_plans_cb":
        bot.answer_callback_query(call.id)
        _logic_view_plans(call)

    elif data == "confirm_plan_upload":
        bot.answer_callback_query(call.id, "✅ Plan Verified!")
        bot.send_message(
            call.message.chat.id,
            "🚀 **এখন আপনার Python (.py), JS (.js) অথবা ZIP (.zip) ফাইল মেসেজে পাঠান।**",
            parse_mode="Markdown",
        )

    elif data.startswith("activate_free_"):
        plan_id=int(data.rsplit("_",1)[1])
        ensure_point_user(call.from_user)
        result=activate_free_plan(user_id,plan_id)
        if not result:
            bot.answer_callback_query(call.id,"Insufficient points or plan unavailable.",show_alert=True)
            return
        name,cost,days,expiry=result
        bot.answer_callback_query(call.id,"Plan activated!")
        bot.send_message(call.message.chat.id,f"🎉 *Free Plan Activated!*\nPlan: *{name}*\nSpent: `{cost} points`\nDuration: `{days} days`\nExpires: `{expiry.strftime('%Y-%m-%d %H:%M')}`",parse_mode="Markdown")

    elif data == "add_free_plan" and user_id in admin_ids:
        bot.answer_callback_query(call.id)
        msg=bot.send_message(call.message.chat.id,"Send Free Plan details in this format:\n`Plan Name | Points | Days`\nExample: `Basic | 500 | 30`",parse_mode="Markdown")
        bot.register_next_step_handler(msg,process_add_free_plan)

    elif data == "list_free_plans" and user_id in admin_ids:
        bot.answer_callback_query(call.id)
        plans=get_free_plans()
        if not plans: bot.send_message(call.message.chat.id,"No free plans created yet.")
        else:
            lines=[f"#{pid} — {name}: {cost} points / {days} days" for pid,name,cost,days in plans]
            bot.send_message(call.message.chat.id,"🆓 *Free Plans*\n"+"\n".join(lines),parse_mode="Markdown")

    elif data in ("admin_add_points","admin_remove_points") and user_id in admin_ids:
        bot.answer_callback_query(call.id)
        mode="add" if data=="admin_add_points" else "remove"
        msg=bot.send_message(call.message.chat.id,f"Send: `USER_ID AMOUNT` to {mode} points.",parse_mode="Markdown")
        bot.register_next_step_handler(msg,lambda m:process_admin_points(m,mode))

    elif data == "admin_user_lookup" and user_id in admin_ids:
        bot.answer_callback_query(call.id)
        msg=bot.send_message(call.message.chat.id,"Send numeric Telegram User ID:")
        bot.register_next_step_handler(msg,process_admin_lookup)

    # --- Interactive Module Installer Handler ---
    elif data.startswith("instmod_"):
        _, owner_id, mod_name, fname = data.split("_", 3)
        if user_id != int(owner_id) and user_id not in admin_ids:
            bot.answer_callback_query(
                call.id,
                "❌ আপনি অন্য ইউজারের ফাইল কাস্টমাইজ করতে পারবেন না!",
                show_alert=True,
            )
            return

        bot.answer_callback_query(call.id)
        pkg_name = TELEGRAM_MODULES.get(mod_name.lower(), mod_name)
        ext = os.path.splitext(fname)[1].lower()

        status_msg = bot.send_message(
            call.message.chat.id,
            f"⏳ **`{pkg_name}` মডিউলটি ইনস্টল করা হচ্ছে...**",
            parse_mode="Markdown",
        )

        def do_pip_install():
            if ext == ".js":
                cmd = ["npm", "install", pkg_name]
            else:
                cmd = [sys.executable, "-m", "pip", "install", pkg_name]

            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                bot.edit_message_text(
                    f"✅ **`{pkg_name}` মডিউলটি সফলভাবে ইনস্টল হয়েছে!**\n🚀 ফাইলটি পুনরায় চালু করা হচ্ছে...",
                    call.message.chat.id,
                    status_msg.message_id,
                    parse_mode="Markdown",
                )
                time.sleep(1)
                ufolder = get_user_folder(int(owner_id))
                fpath = os.path.join(ufolder, fname)
                if ext == ".js":
                    run_js_script(
                        fpath, int(owner_id), ufolder, fname, call.message
                    )
                else:
                    run_script(
                        fpath, int(owner_id), ufolder, fname, call.message
                    )
            else:
                bot.edit_message_text(
                    f"❌ **ইনস্টলেশন ব্যর্থ হয়েছে!**\n\n```\n{res.stderr[:300]}\n```",
                    call.message.chat.id,
                    status_msg.message_id,
                    parse_mode="Markdown",
                )

        threading.Thread(target=do_pip_install).start()

    # --- Error Log Viewer Handler ---
    elif data.startswith("viewlog_"):
        _, owner_id, fname = data.split("_", 2)
        ufolder = get_user_folder(int(owner_id))
        log_fpath = os.path.join(
            ufolder, f"{os.path.splitext(fname)[0]}.log"
        )
        if os.path.exists(log_fpath):
            with open(log_fpath, "r", encoding="utf-8", errors="ignore") as f:
                logs = f.read()[-2000:]
            bot.send_message(
                call.message.chat.id,
                f"📜 **Error Log for `{fname}`:**\n\n```\n{logs if logs else 'No logs recorded.'}\n```",
                parse_mode="Markdown",
            )
        else:
            bot.answer_callback_query(
                call.id, "No log file found!", show_alert=True
            )

    # --- Legacy Binance Pay callbacks intentionally disabled; free plans use points. ---
    elif data.startswith("buy_binance_") or data.startswith("submit_txid_"):
        bot.answer_callback_query(call.id, "Paid plans are currently disabled. Use Free Hosting Plans.", show_alert=True)

    elif False and data.startswith("buy_binance_"):
        plan_id = int(data.split("_")[2])
        plan = get_plan_by_id(plan_id)
        if not plan:
            bot.answer_callback_query(call.id, "Plan not found!")
            return

        bot.answer_callback_query(call.id)
        _, name, limit, price, duration, _ = plan

        usdt_price, formatted_price = parse_price_to_usdt(price)
        already_paid = get_pending_payment(user_id, plan_id)
        due_amount = max(0.0, round(usdt_price - already_paid, 2))

        pay_msg = (
            f"💛 **Binance Pay Auto Payment Process**\n\n"
            f"📌 **Selected Plan:** `{name}`\n"
            f"💰 **Total Price:** `{usdt_price} USDT` ({formatted_price})\n"
        )

        if already_paid > 0:
            pay_msg += (
                f"✅ **আপনার পূর্বে জমা আছে:** `{already_paid} USDT`\n"
                f"⚠️ **এখন অবশিষ্ট বাকি টাকা:** `{due_amount} USDT`\n\n"
            )
        else:
            pay_msg += f"⏱️ **Duration:** `{duration} Days`\n\n"

        pay_msg += (
            f"👇 **পেমেন্ট করার নিয়ম:**\n"
            f"1️⃣ Binance App ➔ **Pay** ➔ **Send** অপশনে যান।\n"
            f"2️⃣ ঠিক **`{due_amount} USDT`** নিচের Binance Pay ID-তে পাঠান:\n"
            f"🔸 **Binance Pay ID:** `{BINANCE_PAY_ID}`\n\n"
            f"3️⃣ পেমেন্ট শেষ হলে প্রাপ্ত **Order ID / Transaction ID** টি নিয়ে নিচের বাটনে চাপ দিয়ে জমা দিন।"
        )

        markup = types.InlineKeyboardMarkup()
        markup.add(
            types.InlineKeyboardButton(
                "🔍 Order ID / TxID জমা দিন",
                callback_data=f"submit_txid_{plan_id}",
            )
        )
        bot.send_message(
            call.message.chat.id, pay_msg, reply_markup=markup, parse_mode="Markdown"
        )

    elif data.startswith("submit_txid_"):
        plan_id = int(data.split("_")[2])
        bot.answer_callback_query(call.id)
        msg = bot.send_message(
            call.message.chat.id,
            "📩 **আপনার Binance Pay এর Order ID / Transaction ID টি মেসেজে লিখুন:**",
            parse_mode="Markdown",
        )
        bot.register_next_step_handler(
            msg, lambda m: process_binance_txid(m, plan_id)
        )

    # --- Admin Callbacks ---
    elif data in ("add_plan_init", "manage_plans") and user_id in admin_ids:
        bot.answer_callback_query(call.id, "Paid plans are disabled. Create a Free Plan instead.", show_alert=True)

    elif data.startswith("del_plan_") and user_id in admin_ids:
        pid = int(data.split("_")[2])
        delete_plan_db(pid)
        bot.answer_callback_query(call.id, "Plan Deleted!")
        bot.send_message(call.message.chat.id, "✅ Plan successfully deleted.")

    elif data == "add_subscription" and user_id in admin_ids:
        bot.answer_callback_query(call.id)
        msg = bot.send_message(
            call.message.chat.id,
            "💎 **Enter User ID, Plan Name & Days:**\nFormat: `UserID PlanName Days`\n*Example:* `123456789 VIP 30`",
            parse_mode="Markdown",
        )
        bot.register_next_step_handler(msg, process_add_subscription)

    elif data == "toggle_lock" and user_id in admin_ids:
        global bot_locked
        bot_locked = not bot_locked
        save_json_backups()
        bot.answer_callback_query(call.id, f"Bot Locked: {bot_locked}")
        bot.send_message(
            call.message.chat.id,
            f"🔐 **Bot status changed to:** `{'Locked' if bot_locked else 'Unlocked'}`",
            parse_mode="Markdown",
        )

    # --- File Management Callbacks ---
    elif data.startswith("file_"):
        _, owner_id, fname = data.split("_", 2)
        is_running = is_bot_running(int(owner_id), fname)
        markup = types.InlineKeyboardMarkup(row_width=2)
        if is_running:
            markup.add(
                types.InlineKeyboardButton(
                    "🛑 Stop", callback_data=f"stop_{owner_id}_{fname}"
                )
            )
        else:
            markup.add(
                types.InlineKeyboardButton(
                    "▶️ Start", callback_data=f"start_{owner_id}_{fname}"
                )
            )
        markup.add(
            types.InlineKeyboardButton(
                "🗑️ Delete", callback_data=f"del_{owner_id}_{fname}"
            )
        )
        bot.send_message(
            call.message.chat.id,
            f"📄 **File:** `{fname}`\n🚦 Status: `{'Running' if is_running else 'Stopped'}`",
            reply_markup=markup,
            parse_mode="Markdown",
        )

    elif data.startswith("stop_"):
        _, owner_id, fname = data.split("_", 2)
        skey = f"{owner_id}_{fname}"
        if skey in bot_scripts:
            kill_process_tree(bot_scripts[skey])
            del bot_scripts[skey]
        bot.answer_callback_query(call.id, "Stopped!")
        bot.send_message(
            call.message.chat.id,
            f"🛑 Script `{fname}` stopped.",
            parse_mode="Markdown",
        )

    elif data.startswith("del_"):
        _, owner_id, fname = data.split("_", 2)
        skey = f"{owner_id}_{fname}"
        if skey in bot_scripts:
            kill_process_tree(bot_scripts[skey])
            del bot_scripts[skey]
        remove_user_file_db(int(owner_id), fname)
        ufolder = get_user_folder(int(owner_id))
        fpath = os.path.join(ufolder, fname)
        if os.path.exists(fpath):
            os.remove(fpath)
        bot.answer_callback_query(call.id, "Deleted!")
        bot.send_message(
            call.message.chat.id,
            f"🗑️ File `{fname}` deleted.",
            parse_mode="Markdown",
        )


# --- Step Handlers ---
def process_add_free_plan(message):
    if not message.from_user or message.from_user.id not in admin_ids: return
    try:
        parts=[x.strip() for x in (message.text or "").split("|")]
        if len(parts)!=3: raise ValueError("Use: Plan Name | Points | Days")
        name=parts[0]; points=int(parts[1]); days=int(parts[2])
        if not name or points<=0 or days<=0: raise ValueError("Name, points and days must be positive")
        add_free_plan(name,points,days)
        bot.reply_to(message,f"✅ Free Plan `{name}` added. Cost: {points} points, Duration: {days} days.",parse_mode="Markdown")
    except Exception as e: bot.reply_to(message,f"❌ Invalid format: {e}")

def process_admin_points(message, mode):
    if not message.from_user or message.from_user.id not in admin_ids: return
    try:
        parts=(message.text or "").split()
        if len(parts)!=2: raise ValueError("Use USER_ID AMOUNT")
        uid,amount=int(parts[0]),int(parts[1])
        if uid<=0 or amount<=0: raise ValueError("IDs and amount must be positive")
        delta=amount if mode=="add" else -amount
        ok=change_user_points(uid,delta,"Admin added points" if mode=="add" else "Admin removed points",message.from_user.id)
        if not ok: raise ValueError("User not found or insufficient points")
        bot.reply_to(message,f"✅ {amount} points {('added to' if mode=='add' else 'removed from')} `{uid}`. New balance: `{get_points(uid)}`",parse_mode="Markdown")
    except Exception as e: bot.reply_to(message,f"❌ {e}")

def process_admin_lookup(message):
    if not message.from_user or message.from_user.id not in admin_ids: return
    try:
        uid=int((message.text or "").strip())
        conn=db_connect(); row=conn.execute("SELECT username,full_name,points,joined_at FROM point_users WHERE user_id=?",(uid,)).fetchone()
        refs=conn.execute("SELECT COUNT(*) FROM point_referrals WHERE referrer_id=?",(uid,)).fetchone()[0]
        conn.close()
        if not row: bot.reply_to(message,"User not found in Points database."); return
        sub=user_subscriptions.get(uid); active=bool(sub and sub.get('expiry')>datetime.now())
        bot.reply_to(message,f"👥 *User Lookup*\nID: `{uid}`\nName: {row[1]}\nUsername: @{row[0] or 'not set'}\nPoints: `{row[2]}`\nReferrals: `{refs}`\nPlan: `{sub.get('plan_name') if active else 'No active plan'}`\nFiles: `{get_user_file_count(uid)}`",parse_mode="Markdown")
    except Exception as e: bot.reply_to(message,f"❌ Invalid User ID: {e}")

def process_binance_txid(message, plan_id):
    pay_order_id = message.text.strip()
    user_id = message.from_user.id

    plan = get_plan_by_id(plan_id)
    if not plan:
        bot.reply_to(message, "❌ প্ল্যান পাওয়া যায়নি!")
        return

    plan_id, name, limit, price, duration, _ = plan
    usdt_price, formatted_price = parse_price_to_usdt(price)

    # 🛑 ১. একই TxID দুইবার ব্যবহার প্রতিরোধ
    if is_txid_used(pay_order_id):
        bot.reply_to(
            message,
            "❌ **এই Order ID / Transaction ID টি ইতিপূর্বেই ব্যবহার করা হয়েছে!**\nনতুন পেমেন্ট ট্রানজেকশন আইডি দিন।",
            parse_mode="Markdown",
        )
        return

    wait_msg = bot.reply_to(
        message,
        "⏳ **আপনার Binance Pay Order ID ভেরিফাই করা হচ্ছে, অনুগ্রহ করে অপেক্ষা করুন...**",
        parse_mode="Markdown",
    )

    is_valid, paid_amount_new, amount_or_error = check_binance_payment(pay_order_id)

    if is_valid:
        add_used_txid(pay_order_id)  # TxID সেভ রাখা

        already_paid = get_pending_payment(user_id, plan_id)
        total_paid = round(already_paid + paid_amount_new, 2)

        # 🛑 ২. পেমেন্ট কম হলে পার্শিয়াল পেমেন্ট হিসেব করে বাকি টাকা দাবি করবে
        if total_paid < usdt_price:
            remaining = round(usdt_price - total_paid, 2)
            update_pending_payment(user_id, plan_id, total_paid)

            bot.edit_message_text(
                f"⚠️ **পেমেন্ট অসম্পূর্ণ (Partial Payment Received)!**\n\n"
                f"📌 **Selected Plan:** `{name}`\n"
                f"💰 **প্রয়োজনীয় মোট দাম:** `{usdt_price} USDT` ({formatted_price})\n"
                f"✅ **আপনার মোট জমা হয়েছে:** `{total_paid} USDT`\n"
                f"❌ **এখনও বাকি আছে:** `{remaining} USDT`\n\n"
                f"💡 অনুগ্রহ করে বাকি **`{remaining} USDT`** টাকা Binance Pay ID (`{BINANCE_PAY_ID}`)-তে পাঠি‌য়ে নতুন Order ID টি পুনরায় জমা দিন। বাকি পেমেন্ট সম্পন্ন হলেই আপনার সাবস্ক্রিপশনটি এক্টিভ হবে।",
                message.chat.id,
                wait_msg.message_id,
                parse_mode="Markdown",
            )
            return

        # 🛑 ৩. সম্পূর্ণ পেমেন্ট সম্পন্ন হলে সাবস্ক্রিপশন একটিভ
        clear_pending_payment(user_id, plan_id)
        expiry = datetime.now() + timedelta(days=duration)
        save_subscription(user_id, name, expiry)

        bot.edit_message_text(
            f"🎉 **পেমেন্ট সফলভাবে ভেরিফাই হয়েছে!**\n\n"
            f"👤 **User ID:** `{user_id}`\n"
            f"💎 **Plan:** `{name}`\n"
            f"💰 **Total Amount Paid:** `{total_paid} USDT`\n"
            f"📅 **Expiry:** `{expiry.strftime('%Y-%m-%d %H:%M')}`\n\n"
            f"🚀 আপনার সাবস্ক্রিপশন চালু হয়েছে। এখন আপনি ফাইল আপলোড করতে পারবেন!",
            message.chat.id,
            wait_msg.message_id,
            parse_mode="Markdown",
        )

        # Notify Owner
        bot.send_message(
            OWNER_ID,
            f"🔔 **New Subscription via Binance Pay!**\n"
            f"👤 User: `{user_id}`\n"
            f"💎 Plan: `{name}`\n"
            f"📑 Order ID: `{pay_order_id}`\n"
            f"💰 Amount: `{total_paid} USDT`",
            parse_mode="Markdown",
        )
    else:
        bot.edit_message_text(
            f"❌ **পেমেন্ট ভেরিফাই করা সম্ভব হয়নি!**\n\n"
            f"⚠️ **কারণ:** `{amount_or_error}`\n\n"
            f"অনুগ্রহ করে সঠিক Order ID দিয়ে আবার চেষ্টা করুন অথবা এডমিনের সাথে যোগাযোগ করুন।",
            message.chat.id,
            wait_msg.message_id,
            parse_mode="Markdown",
        )


def process_add_plan(message):
    try:
        parts = [p.strip() for p in message.text.split("|")]
        name, limit, price, duration, buy_link = (
            parts[0],
            int(parts[1]),
            parts[2],
            int(parts[3]),
            parts[4],
        )
        add_plan_db(name, limit, price, duration, buy_link)
        bot.reply_to(
            message,
            f"✅ **Plan `{name}` added successfully!**",
            parse_mode="Markdown",
        )
    except Exception as e:
        bot.reply_to(message, f"❌ Invalid Format! Error: {e}")


def process_add_subscription(message):
    try:
        parts = message.text.split()
        sub_uid, pname, days = int(parts[0]), parts[1], int(parts[2])
        exp = datetime.now() + timedelta(days=days)
        save_subscription(sub_uid, pname, exp)
        bot.reply_to(
            message,
            f"✅ **Subscription active for User `{sub_uid}` under Plan `{pname}` for {days} days!**",
            parse_mode="Markdown",
        )
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")


@bot.message_handler(commands=["addpoints"])
def command_add_points(message):
    if message.from_user.id not in admin_ids: return
    try:
        _,uid,amount=(message.text or "").split()
        uid=int(uid); amount=int(amount)
        if uid<=0 or amount<=0: raise ValueError()
        if not change_user_points(uid,amount,"Admin added points",message.from_user.id): raise ValueError("Could not update points")
        bot.reply_to(message,f"✅ Added {amount} points to {uid}. Balance: {get_points(uid)}")
    except Exception: bot.reply_to(message,"Usage: /addpoints USER_ID AMOUNT")

@bot.message_handler(commands=["removepoints"])
def command_remove_points(message):
    if message.from_user.id not in admin_ids: return
    try:
        _,uid,amount=(message.text or "").split()
        uid=int(uid); amount=int(amount)
        if uid<=0 or amount<=0: raise ValueError()
        if not change_user_points(uid,-amount,"Admin removed points",message.from_user.id): raise ValueError("User missing or insufficient points")
        bot.reply_to(message,f"✅ Removed {amount} points from {uid}. Balance: {get_points(uid)}")
    except Exception: bot.reply_to(message,"Usage: /removepoints USER_ID AMOUNT")

@bot.message_handler(func=lambda m: m.text == "👤 My Details")
def handle_my_details(message):
    ensure_point_user(message.from_user); send_my_details(message)

@bot.message_handler(func=lambda m: m.text == "💰 My Points")
def handle_my_points(message):
    ensure_point_user(message.from_user); send_points(message)

@bot.message_handler(func=lambda m: m.text == "🎁 Refer & Earn")
def handle_referral(message):
    ensure_point_user(message.from_user); send_referral(message)

@bot.message_handler(func=lambda m: m.text == "🆓 Free Hosting Plan")
def handle_free_plans(message):
    ensure_point_user(message.from_user); _logic_view_plans(message)

# --- Text Handler Mapping ---
BUTTON_MAPPING = {
    "✨ 𝗨𝗽𝗱𝗮𝘁𝗲𝘀 𝗖𝗵𝗮𝗻𝗻𝗲𝗹 ✨": lambda m: bot.reply_to(
        m, f"📢 **Join channel:** {UPDATE_CHANNEL}"
    ),
    "🚀 𝗨𝗽𝗹𝗼𝗮𝗱 𝗙𝗶𝗹𝗲": _logic_upload_file,
    "🚀 𝗨𝗽𝗹𝗼𝗮d 𝗙𝗶𝗹𝗲": _logic_upload_file,
    "📁 𝗠𝗮𝗻𝗮𝗴𝗲 𝗙𝗶𝗹𝗲𝘀": _logic_check_files,
    "💳 𝗩𝗶𝗲𝘄 𝗣𝗹𝗮𝗻𝘀": _logic_view_plans,
    "⚡ 𝗦𝗽𝗲𝗲𝗱 & 𝗣𝗶𝗻𝗴": lambda m: bot.reply_to(
        m, "⚡ **Bot Latency:** `12 ms` (Server Active)"
    ),
    "📊 𝗕𝗼𝘁 𝗦𝘁𝗮𝘁𝘀": lambda m: bot.reply_to(
        m, f"📊 **Active Users:** `{len(active_users)}`"
    ),
    "💻 𝗧𝗲𝗿𝗺𝗶𝗻𝗮𝗹 𝗖𝗺𝗱": lambda m: bot.reply_to(m, "💻 Terminal ready."),
    "👑 𝗖𝗼𝗻𝘁𝗮𝗰𝘁 𝗢𝘄𝗻𝗲𝗿": lambda m: bot.reply_to(
        m, f"👑 **Owner:** {YOUR_USERNAME}"
    ),
    "🛡️ 𝗔𝗱𝗺𝗶𝗻 𝗣𝗮𝗻𝗲𝗹": lambda m: bot.reply_to(
        m,
        "🛡️ **𝗔𝗱𝗺𝗶𝗻 𝗖𝗼𝗻𝘁𝗿𝗼𝗹 𝗣𝗮𝗻𝗲𝗹:**",
        reply_markup=create_admin_panel_inline(),
        parse_mode="Markdown",
    ),
}


@bot.message_handler(func=lambda m: m.text in BUTTON_MAPPING)
def handle_main_buttons(message):
    BUTTON_MAPPING[message.text](message)


@bot.message_handler(commands=["start"])
def start_cmd(message):
    _logic_send_welcome(message)


# --- Cleanup & Start ---
def cleanup():
    _json_backup_stop.set()
    save_json_backups()
    _shutdown_event.set()
    for key in list(bot_scripts.keys()):
        kill_process_tree(bot_scripts[key])


atexit.register(cleanup)

if __name__ == "__main__":
    logger.info("🤖 Starting Bot with Auto Package Installer, Points & Free Hosting Plans...")
    keep_alive()
    start_json_backup_worker()
    bot.infinity_polling(timeout=60, long_polling_timeout=30)