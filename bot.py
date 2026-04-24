import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes
)
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson import ObjectId
import re
from functools import wraps
import html
import uuid
import os
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "attack_bot")
API_URL = os.getenv("API_URL")
API_KEY = os.getenv("API_KEY")
ADMIN_IDS = [int(id.strip()) for id in os.getenv("ADMIN_IDS", "1793697840").split(",")]

# Store active attack timers
active_timers = {}

# Blocked ports (must match backend)
BLOCKED_PORTS = {8700, 20000, 443, 17500, 9031, 20002, 20001}

# Allowed port range
MIN_PORT = 1
MAX_PORT = 65535

def make_aware(dt):
    if dt is None:
        return None
    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_current_time():
    return datetime.now(timezone.utc)

def escape_markdown(text: str) -> str:
    if not text:
        return ""
    special_chars = r'_*[]()~`>#+-=|{}.!'
    return ''.join(f'\\{char}' if char in special_chars else char for char in str(text))

# MongoDB Connection
class Database:
    def __init__(self):
        self.client = MongoClient(MONGODB_URI)
        self.db = self.client[DATABASE_NAME]
        self.users = self.db.users
        self.attacks = self.db.attacks
        
        try:
            result = self.users.delete_many({"user_id": None})
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} documents with null user_id")
            result = self.users.delete_many({"user_id": {"$exists": False}})
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} documents without user_id")
        except Exception as e:
            logger.error(f"Error cleaning users collection: {e}")
        
        try:
            self.users.drop_indexes()
            logger.info("Dropped all existing indexes from users collection")
        except Exception as e:
            logger.info(f"No existing indexes to drop: {e}")
        
        try:
            self.attacks.drop_indexes()
            logger.info("Dropped all existing indexes from attacks collection")
        except Exception as e:
            logger.info(f"No existing indexes to drop: {e}")
        
        try:
            self.attacks.create_index([("timestamp", DESCENDING)])
            self.attacks.create_index([("user_id", ASCENDING)])
            self.attacks.create_index([("status", ASCENDING)])
            logger.info("Created indexes for attacks collection")
        except Exception as e:
            logger.error(f"Error creating attacks indexes: {e}")
        
        try:
            self.users.create_index([("user_id", ASCENDING)], unique=True, sparse=True)
            logger.info("Created unique index on user_id for users collection")
        except Exception as e:
            logger.error(f"Error creating users index: {e}")
        
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
        existing_user = self.get_user(user_id)
        if existing_user:
            return existing_user
            
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
            logger.info(f"Created new user: {user_id}")
        except pymongo.errors.DuplicateKeyError:
            user_data = self.get_user(user_id)
            logger.info(f"User {user_id} already exists")
        except Exception as e:
            logger.error(f"Error creating user: {e}")
        return user_data
    
    def approve_user(self, user_id: int, days: int) -> bool:
        expires_at = get_current_time() + timedelta(days=days)
        result = self.users.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "approved": True,
                    "approved_at": get_current_time(),
                    "expires_at": expires_at
                }
            }
        )
        return result.modified_count > 0
    
    def disapprove_user(self, user_id: int) -> bool:
        result = self.users.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "approved": False,
                    "expires_at": None
                }
            }
        )
        return result.modified_count > 0
    
    def log_attack(self, user_id: int, ip: str, port: int, duration: int, status: str, response: str = None, attack_id: str = None):
        attack_data = {
            "_id": str(uuid.uuid4()),
            "user_id": user_id,
            "ip": ip,
            "port": port,
            "duration": duration,
            "status": status,
            "response": response[:500] if response else None,
            "timestamp": get_current_time(),
            "attack_id": attack_id
        }
        try:
            self.attacks.insert_one(attack_data)
            self.users.update_one(
                {"user_id": user_id},
                {"$inc": {"total_attacks": 1}}
            )
            logger.info(f"Logged attack for user {user_id}: {status}")
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
    
    def update_attack_status(self, attack_id: str, status: str):
        try:
            self.attacks.update_one(
                {"attack_id": attack_id},
                {"$set": {"status": status, "completed_at": get_current_time()}}
            )
        except Exception as e:
            logger.error(f"Failed to update attack status: {e}")
    
    def get_all_users(self) -> List[Dict]:
        users = list(self.users.find({"user_id": {"$ne": None, "$exists": True}}))
        for user in users:
            if user.get("created_at"):
                user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"):
                user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"):
                user["expires_at"] = make_aware(user["expires_at"])
            if "total_attacks" not in user:
                user["total_attacks"] = 0
        return users
    
    def get_approved_users(self) -> List[Dict]:
        users = list(self.users.find({"approved": True, "is_banned": False, "user_id": {"$ne": None}}))
        for user in users:
            if user.get("created_at"):
                user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"):
                user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"):
                user["expires_at"] = make_aware(user["expires_at"])
        return users
    
    def get_user_attack_stats(self, user_id: int) -> Dict:
        total_attacks = self.attacks.count_documents({"user_id": user_id})
        successful_attacks = self.attacks.count_documents({"user_id": user_id, "status": "success"})
        failed_attacks = self.attacks.count_documents({"user_id": user_id, "status": "failed"})
        
        recent_attacks = list(self.attacks.find(
            {"user_id": user_id}
        ).sort("timestamp", -1).limit(10))
        
        for attack in recent_attacks:
            if attack.get("timestamp"):
                attack["timestamp"] = make_aware(attack["timestamp"])
        
        return {
            "total": total_attacks,
            "successful": successful_attacks,
            "failed": failed_attacks,
            "recent": recent_attacks
        }

# Initialize database
print("🔄 Initializing database connection...")
db = Database()
print("✅ Database initialized successfully!")

def is_port_blocked(port: int) -> bool:
    return port in BLOCKED_PORTS

def get_blocked_ports_list() -> str:
    return ", ".join(str(port) for port in sorted(BLOCKED_PORTS))

def admin_required(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in ADMIN_IDS:
            await update.message.reply_text("❌ You are not authorized to use this command.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper

async def is_user_approved(user_id: int) -> bool:
    user = db.get_user(user_id)
    if not user:
        return False
    if not user.get("approved", False):
        return False
    expires_at = user.get("expires_at")
    if expires_at:
        expires_at = make_aware(expires_at)
        if expires_at < get_current_time():
            return False
    return True

# API Functions
def check_api_health() -> Dict:
    try:
        response = requests.get(
            f"{API_URL}/api/v1/health",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"status": "error", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {"status": "error", "error": str(e)}

def check_running_attacks() -> Dict:
    try:
        response = requests.get(
            f"{API_URL}/api/v1/active",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"Running attacks error: {e}")
        return {"success": False, "error": str(e)}

def get_user_stats() -> Dict:
    try:
        response = requests.get(
            f"{API_URL}/api/v1/stats",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        return {"success": False, "error": str(e)}

def launch_attack(ip: str, port: int, duration: int) -> Dict:
    try:
        response = requests.post(
            f"{API_URL}/api/v1/attack",
            json={"ip": ip, "port": port, "duration": duration},
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=15
        )
        return response.json()
    except Exception as e:
        logger.error(f"Attack launch error: {e}")
        return {"error": str(e), "success": False}

# ============ LIVE COUNTDOWN TIMER FUNCTION ============
async def attack_countdown(chat_id: int, message_id: int, attack_id: str, duration: int, target: str, port: int, context: ContextTypes.DEFAULT_TYPE):
    """Send live countdown timer for attack"""
    try:
        remaining = duration
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("🛑 Stop Attack", callback_data=f"stop_{attack_id}")]
        ])
        
        while remaining > 0:
            # Format time in mm:ss
            minutes = remaining // 60
            seconds = remaining % 60
            time_str = f"{minutes:02d}:{seconds:02d}"
            
            # Calculate percentage
            percentage = ((duration - remaining) / duration) * 100
            
            # Create progress bar
            bar_length = 20
            filled = int(bar_length * percentage / 100)
            bar = "█" * filled + "░" * (bar_length - filled)
            
            message_text = (
                f"⚔️ **ATTACK IN PROGRESS** ⚔️\n\n"
                f"🎯 **Target:** `{target}:{port}`\n"
                f"⏱️ **Time Remaining:** `{time_str}`\n"
                f"📊 **Progress:** `{percentage:.1f}%`\n"
                f"`{bar}`\n\n"
                f"🆔 **Attack ID:** `{attack_id[:8]}...`\n\n"
                f"⏳ Attack will stop automatically when timer reaches 00:00"
            )
            
            try:
                await context.bot.edit_message_text(
                    message_text,
                    chat_id=chat_id,
                    message_id=message_id,
                    parse_mode='Markdown',
                    reply_markup=keyboard
                )
            except Exception as e:
                logger.error(f"Error updating countdown: {e}")
            
            await asyncio.sleep(1)
            remaining -= 1
        
        # Attack completed
        completion_text = (
            f"✅ **ATTACK COMPLETED** ✅\n\n"
            f"🎯 **Target:** `{target}:{port}`\n"
            f"⏱️ **Duration:** {duration} seconds\n"
            f"📊 **Status:** Successfully completed\n\n"
            f"🆔 **Attack ID:** `{attack_id[:8]}...`\n\n"
            f"💡 You can start a new attack using `/attack` command"
        )
        
        await context.bot.edit_message_text(
            completion_text,
            chat_id=chat_id,
            message_id=message_id,
            parse_mode='Markdown'
        )
        
        # Remove from active timers
        if attack_id in active_timers:
            del active_timers[attack_id]
            
        # Update database
        db.update_attack_status(attack_id, "completed")
        
    except Exception as e:
        logger.error(f"Countdown error: {e}")
        await context.bot.send_message(
            chat_id,
            f"✅ Attack on {target}:{port} has completed after {duration} seconds!"
        )

# ============ STOP ATTACK FUNCTION ============
async def stop_attack(chat_id: int, attack_id: str, context: ContextTypes.DEFAULT_TYPE):
    """Stop an ongoing attack"""
    try:
        # Call API to stop attack
        response = requests.post(
            f"{API_URL}/api/v1/stop",
            json={"attack_id": attack_id},
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            # Cancel timer
            if attack_id in active_timers:
                # Timer will be cancelled by removing from dict
                # The task will continue but won't update
                pass
            
            await context.bot.send_message(
                chat_id,
                f"🛑 **ATTACK STOPPED** 🛑\n\n"
                f"🆔 Attack ID: `{attack_id[:8]}...`\n"
                f"✅ Attack has been terminated successfully.\n\n"
                f"💡 You can start a new attack using `/attack` command",
                parse_mode='Markdown'
            )
            
            # Update database
            db.update_attack_status(attack_id, "stopped")
            
            # Remove from active timers
            if attack_id in active_timers:
                del active_timers[attack_id]
                
        else:
            await context.bot.send_message(
                chat_id,
                f"❌ Failed to stop attack. Please try again."
            )
    except Exception as e:
        logger.error(f"Stop attack error: {e}")
        await context.bot.send_message(
            chat_id,
            f"❌ Error stopping attack: {str(e)[:100]}"
        )

# ============ CALLBACK HANDLER FOR STOP BUTTON ============
async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks"""
    query = update.callback_query
    await query.answer()
    
    data = query.data
    user_id = update.effective_user.id
    
    if data.startswith("stop_"):
        attack_id = data.replace("stop_", "")
        
        # Confirm stop
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("✅ Yes, Stop Attack", callback_data=f"confirm_stop_{attack_id}"),
                InlineKeyboardButton("❌ No, Continue", callback_data="cancel_stop")
            ]
        ])
        
        await query.edit_message_text(
            f"⚠️ **Are you sure you want to stop this attack?**\n\n"
            f"🆔 Attack ID: `{attack_id[:8]}...`\n\n"
            f"Stopping the attack will immediately terminate it.",
            parse_mode='Markdown',
            reply_markup=keyboard
        )
    
    elif data.startswith("confirm_stop_"):
        attack_id = data.replace("confirm_stop_", "")
        await stop_attack(update.effective_chat.id, attack_id, context)
    
    elif data == "cancel_stop":
        # Restore original message or just close
        await query.edit_message_text("✅ Attack continuation confirmed. No action taken.")

# Bot Command Handlers
@admin_required
async def approve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) < 2:
            await update.message.reply_text(
                "❌ Usage: /approve <user_id> <days>\n\n"
                "Example: /approve 123456789 30"
            )
            return
        
        user_id = int(context.args[0])
        days = int(context.args[1])
        
        if days <= 0:
            await update.message.reply_text("❌ Days must be a positive number.")
            return
        
        user = db.get_user(user_id)
        if not user:
            db.create_user(user_id)
        
        if db.approve_user(user_id, days):
            expires_at = get_current_time() + timedelta(days=days)
            await update.message.reply_text(
                f"✅ User {user_id} has been approved for {days} days!\n"
                f"📅 Expires on: {expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC"
            )
            
            try:
                await context.bot.send_message(
                    user_id,
                    f"✅ Congratulations! Your account has been approved for {days} days.\n"
                    f"📅 Expires on: {expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
                    f"Use /help to see available commands."
                )
            except Exception as e:
                logger.error(f"Failed to notify user: {e}")
        else:
            await update.message.reply_text("❌ Failed to approve user.")
            
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID or days. Please use numbers only.")
    except Exception as e:
        logger.error(f"Approve error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def disapprove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) < 1:
            await update.message.reply_text("❌ Usage: /disapprove <user_id>")
            return
        
        user_id = int(context.args[0])
        
        if db.disapprove_user(user_id):
            await update.message.reply_text(f"✅ User {user_id} has been disapproved.")
            
            try:
                await context.bot.send_message(
                    user_id,
                    "❌ Your access has been revoked. Please contact admin for more information."
                )
            except Exception as e:
                logger.error(f"Failed to notify user: {e}")
        else:
            await update.message.reply_text("❌ Failed to disapprove user. User may not exist.")
            
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID.")
    except Exception as e:
        logger.error(f"Disapprove error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    status_msg = await update.message.reply_text("🔄 Checking API health status...")
    health = check_api_health()
    
    if health.get("status") == "ok":
        message = (
            f"✅ API Status: Healthy\n\n"
            f"🕐 Timestamp: {health.get('timestamp', 'N/A')}\n"
            f"📦 Version: {health.get('version', 'N/A')}\n\n"
            f"🌐 API URL: {API_URL}"
        )
    else:
        message = (
            f"❌ API Status: Unhealthy\n\n"
            f"Error: {health.get('error', 'Unknown error')}\n\n"
            f"🌐 API URL: {API_URL}"
        )
    
    await status_msg.edit_text(message)

@admin_required
async def running_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    status_msg = await update.message.reply_text("🔄 Fetching active attacks...")
    attacks = check_running_attacks()
    
    if attacks.get("success"):
        active_attacks = attacks.get("activeAttacks", [])
        if active_attacks:
            message = f"🎯 Active Attacks ({len(active_attacks)})\n\n"
            for attack in active_attacks:
                message += (
                    f"🔹 Target: {attack['target']}:{attack['port']}\n"
                    f"   ⏱️ Expires in: {attack['expiresIn']}s\n"
                    f"   🆔 ID: {attack['attackId'][:8]}...\n\n"
                )
        else:
            message = "✅ No active attacks running."
        
        message += f"\n📊 Limits:\n"
        message += f"   • Current: {attacks.get('count', 0)} / {attacks.get('maxConcurrent', 0)}\n"
        message += f"   • Remaining slots: {attacks.get('remainingSlots', 0)}"
    else:
        message = f"❌ Failed to fetch active attacks\n\nError: {attacks.get('error', 'Unknown error')}"
    
    await status_msg.edit_text(message)

@admin_required
async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        users = db.get_all_users()
        
        if not users:
            await update.message.reply_text("📭 No users found.")
            return
        
        approved_count = sum(1 for u in users if u.get("approved", False))
        total_attacks = sum(u.get("total_attacks", 0) for u in users)
        
        message = f"👥 User Statistics\n\n"
        message += f"📊 Total Users: {len(users)}\n"
        message += f"✅ Approved Users: {approved_count}\n"
        message += f"❌ Disapproved Users: {len(users) - approved_count}\n"
        message += f"🎯 Total Attacks: {total_attacks}\n\n"
        
        message += "📋 User List:\n"
        for idx, user in enumerate(users[:10], 1):
            user_id = user.get('user_id', 'Unknown')
            status = "✅" if user.get("approved", False) else "❌"
            
            if user.get("approved", False) and user.get("expires_at"):
                try:
                    expires_at = make_aware(user["expires_at"])
                    if expires_at > get_current_time():
                        days_left = (expires_at - get_current_time()).days
                        status += f" ({days_left}d)"
                    else:
                        status += " (Expired)"
                except Exception:
                    status += " (Date error)"
            
            attacks_count = user.get("total_attacks", 0)
            message += f"{idx}. {user_id} {status} - {attacks_count} attacks\n"
        
        if len(users) > 10:
            message += f"\n*And {len(users) - 10} more users...*"
        
        if len(message) > 4000:
            message = message[:4000] + "\n\n... (truncated)"
        
        await update.message.reply_text(message)
        
    except Exception as e:
        logger.error(f"Users command error: {e}")
        await update.message.reply_text(f"❌ Error displaying users: {str(e)}")

@admin_required
async def blocked_ports_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    blocked_ports_str = get_blocked_ports_list()
    message = (
        f"🚫 Blocked Ports\n\n"
        f"The following ports are blocked and cannot be used for attacks:\n\n"
        f"{blocked_ports_str}\n\n"
        f"📊 Total blocked: {len(BLOCKED_PORTS)} ports\n\n"
        f"✅ Allowed ports: All ports from {MIN_PORT} to {MAX_PORT} except the blocked ones."
    )
    await update.message.reply_text(message)

@admin_required
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        users = db.get_all_users()
        approved_users = [u for u in users if u.get("approved", False)]
        total_attacks = sum(u.get("total_attacks", 0) for u in users)
        
        yesterday = get_current_time() - timedelta(days=1)
        recent_attacks = db.attacks.count_documents({"timestamp": {"$gte": yesterday}})
        
        successful_attacks = db.attacks.count_documents({"status": "success"})
        failed_attacks = db.attacks.count_documents({"status": "failed"})
        
        api_stats = get_user_stats()
        
        message = (
            f"📊 Bot Statistics\n\n"
            f"👥 Users:\n"
            f"• Total: {len(users)}\n"
            f"• Approved: {len(approved_users)}\n"
            f"• Pending: {len(users) - len(approved_users)}\n\n"
            f"🎯 Attacks:\n"
            f"• Total: {total_attacks}\n"
            f"• Last 24h: {recent_attacks}\n"
            f"• Successful: {successful_attacks}\n"
            f"• Failed: {failed_attacks}\n\n"
            f"🚫 Blocked Ports: {len(BLOCKED_PORTS)}\n"
            f"🕐 Bot Uptime: Running"
        )
        
        if api_stats.get("success"):
            message += f"\n\n📡 API Stats:\n"
            message += f"• Status: {api_stats.get('status', 'N/A')}\n"
            message += f"• Days Remaining: {api_stats.get('daysRemaining', 'N/A')}"
        
        await update.message.reply_text(message)
        
    except Exception as e:
        logger.error(f"Stats command error: {e}")
        await update.message.reply_text(f"❌ Error displaying stats: {str(e)}")

# User commands
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = update.effective_user.id
        username = update.effective_user.username
        
        user = db.get_user(user_id)
        if not user:
            db.create_user(user_id, username)
        
        if await is_user_approved(user_id):
            user_data = db.get_user(user_id)
            expires_at = user_data.get("expires_at")
            days_left = 0
            if expires_at:
                expires_at = make_aware(expires_at)
                days_left = (expires_at - get_current_time()).days
                if days_left < 0:
                    days_left = 0
            
            message = (
                f"✅ **Welcome back, {username or user_id}!**\n\n"
                f"Your account is active and ready to use.\n"
                f"📅 **Expires in:** {days_left} days\n\n"
                f"**Available Commands:**\n"
                f"🔹 `/attack ip port duration` - Launch an attack with live timer\n"
                f"🔹 `/myattacks` - Check your active attacks\n"
                f"🔹 `/myinfo` - View your account info\n"
                f"🔹 `/mystats` - View your attack statistics\n"
                f"🔹 `/blockedports` - Show blocked ports\n"
                f"🔹 `/help` - Show all commands\n\n"
                f"⚠️ **Live Timer Feature:** Attacks show real-time countdown!"
            )
        else:
            message = (
                f"❌ **Access Denied, {username or user_id}!**\n\n"
                f"Your account is not approved yet.\n"
                f"Please contact the administrator to get access.\n\n"
                f"Once approved, you'll be able to use the bot's features."
            )
        
        await update.message.reply_text(message, parse_mode='Markdown')
        
    except Exception as e:
        logger.error(f"Start command error: {e}")
        await update.message.reply_text("❌ An error occurred. Please try again later.")

# ============ UPDATED ATTACK COMMAND WITH LIVE TIMER ============
async def attack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not await is_user_approved(user_id):
        await update.message.reply_text(
            "❌ **Access Denied!**\n\n"
            "Your account is not approved or has expired.\n"
            "Please contact the administrator.",
            parse_mode='Markdown'
        )
        return
    
    if len(context.args) != 3:
        blocked_ports_str = get_blocked_ports_list()
        await update.message.reply_text(
            f"❌ **Usage:** `/attack ip port duration`\n\n"
            f"**Example:** `/attack 192.168.1.1 80 60`\n\n"
            f"**Parameters:**\n"
            f"• **ip** - Target IP address\n"
            f"• **port** - Port number (1-65535)\n"
            f"• **duration** - Attack duration in seconds (1-300)\n\n"
            f"🚫 **Blocked Ports:** {blocked_ports_str}\n\n"
            f"💡 **Live Timer:** Attack will show real-time countdown!",
            parse_mode='Markdown'
        )
        return
    
    ip = context.args[0]
    port_str = context.args[1]
    duration_str = context.args[2]
    
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        await update.message.reply_text("❌ Invalid IP address format.")
        return
    
    try:
        port = int(port_str)
        if port < MIN_PORT or port > MAX_PORT:
            await update.message.reply_text(f"❌ Invalid port. Must be between {MIN_PORT} and {MAX_PORT}.")
            return
        if is_port_blocked(port):
            blocked_ports_str = get_blocked_ports_list()
            await update.message.reply_text(
                f"❌ Port {port} is blocked!\n\n"
                f"🚫 Blocked ports: {blocked_ports_str}\n"
                f"Please use a different port."
            )
            return
    except ValueError:
        await update.message.reply_text("❌ Invalid port. Please use a number between 1 and 65535.")
        return
    
    try:
        duration = int(duration_str)
        if duration < 1 or duration > 300:
            await update.message.reply_text("❌ Invalid duration. Must be between 1 and 300 seconds (5 minutes).")
            return
    except ValueError:
        await update.message.reply_text("❌ Invalid duration. Please use a number.")
        return
    
    # Send initial message
    status_msg = await update.message.reply_text(
        f"🎯 **Launching Attack...**\n\n"
        f"**Target:** `{ip}:{port}`\n"
        f"**Duration:** {duration} seconds\n\n"
        f"🔄 Please wait...",
        parse_mode='Markdown'
    )
    
    # Launch attack via API
    response = launch_attack(ip, port, duration)
    
    if response.get("success"):
        attack_data = response.get("attack", {})
        attack_id = attack_data.get('id', str(uuid.uuid4())[:8])
        limits = response.get("limits", {})
        account = response.get("account", {})
        
        # Log attack
        db.log_attack(user_id, ip, port, duration, "success", str(response), attack_id)
        
        # Start countdown timer
        asyncio.create_task(
            attack_countdown(
                update.effective_chat.id,
                status_msg.message_id,
                attack_id,
                duration,
                ip,
                port,
                context
            )
        )
        
    else:
        error_msg = response.get("error", "Unknown error")
        details = response.get("message", "")
        
        message = (
            f"❌ **Attack Failed!**\n\n"
            f"**Error:** {error_msg}\n"
            f"**Details:** {details}\n\n"
            f"**Possible reasons:**\n"
            f"• Invalid parameters\n"
            f"• Port is blocked\n"
            f"• Rate limit exceeded\n"
            f"• Service temporarily unavailable"
        )
        
        db.log_attack(user_id, ip, port, duration, "failed", str(response))
        await status_msg.edit_text(message, parse_mode='Markdown')

async def myattacks_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ You are not approved to use this bot.")
        return
    
    attacks = check_running_attacks()
    
    if attacks.get("success"):
        active_attacks = attacks.get("activeAttacks", [])
        if active_attacks:
            message = f"🎯 Your Active Attacks ({len(active_attacks)})\n\n"
            for attack in active_attacks:
                message += (
                    f"🔹 Target: {attack['target']}:{attack['port']}\n"
                    f"   ⏱️ Expires in: {attack['expiresIn']}s\n\n"
                )
        else:
            message = "✅ You have no active attacks running."
        
        message += f"\n📊 Usage: {attacks.get('count', 0)} / {attacks.get('maxConcurrent', 0)} concurrent attacks"
    else:
        message = f"❌ Failed to fetch attacks: {attacks.get('error', 'Unknown error')}"
    
    await update.message.reply_text(message)

async def myinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = update.effective_user.id
        user = db.get_user(user_id)
        
        if not user:
            await update.message.reply_text("❌ User not found. Please use /start first.")
            return
        
        if user.get("approved"):
            expires_at = user.get("expires_at")
            if expires_at:
                expires_at = make_aware(expires_at)
                days_left = (expires_at - get_current_time()).days
                hours_left = int((expires_at - get_current_time()).seconds / 3600)
                if days_left >= 0:
                    expires_str = f"{days_left} days, {hours_left} hours"
                else:
                    expires_str = "Expired"
            else:
                expires_str = "Never"
            
            approved_at_str = user.get('approved_at').strftime('%Y-%m-%d') if user.get('approved_at') else 'N/A'
            created_at_str = user.get('created_at').strftime('%Y-%m-%d') if user.get('created_at') else 'N/A'
            
            message = (
                f"📋 **Your Account Information**\n\n"
                f"🆔 **User ID:** `{user['user_id']}`\n"
                f"👤 **Username:** @{user.get('username', 'N/A')}\n"
                f"✅ **Status:** Approved\n"
                f"📅 **Approved On:** {approved_at_str}\n"
                f"⏰ **Expires In:** {expires_str}\n"
                f"📊 **Total Attacks:** {user.get('total_attacks', 0)}\n"
                f"📅 **Member Since:** {created_at_str}"
            )
        else:
            created_at_str = user.get('created_at').strftime('%Y-%m-%d') if user.get('created_at') else 'N/A'
            
            message = (
                f"❌ **Account Not Approved**\n\n"
                f"🆔 **User ID:** `{user['user_id']}`\n"
                f"👤 **Username:** @{user.get('username', 'N/A')}\n"
                f"📅 **Member Since:** {created_at_str}\n\n"
                f"Please contact the administrator to get access."
            )
        
        await update.message.reply_text(message, parse_mode='Markdown')
        
    except Exception as e:
        logger.error(f"Myinfo command error: {e}")
        await update.message.reply_text("❌ Error retrieving user information.")

async def mystats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ You are not approved to use this bot.")
        return
    
    stats = db.get_user_attack_stats(user_id)
    
    success_rate = (stats['successful']/stats['total']*100 if stats['total'] > 0 else 0)
    
    message = (
        f"📊 **Your Attack Statistics**\n\n"
        f"🎯 **Total Attacks:** {stats['total']}\n"
        f"✅ **Successful:** {stats['successful']}\n"
        f"❌ **Failed:** {stats['failed']}\n"
        f"📈 **Success Rate:** {success_rate:.1f}%\n\n"
    )
    
    if stats['recent']:
        message += "🕐 **Recent Attacks:**\n"
        for attack in stats['recent'][:5]:
            status_icon = "✅" if attack['status'] == "success" else "❌"
            if attack.get('timestamp'):
                timestamp = make_aware(attack['timestamp'])
                time_ago = (get_current_time() - timestamp).seconds // 60
                message += (
                    f"{status_icon} `{attack['ip']}:{attack['port']}` - "
                    f"{attack['duration']}s - {time_ago}m ago\n"
                )
    
    await update.message.reply_text(message, parse_mode='Markdown')

async def blocked_ports_user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    blocked_ports_str = get_blocked_ports_list()
    message = (
        f"🚫 **Blocked Ports**\n\n"
        f"The following ports are blocked and cannot be used for attacks:\n\n"
        f"`{blocked_ports_str}`\n\n"
        f"📊 **Total blocked:** {len(BLOCKED_PORTS)} ports\n\n"
        f"✅ **Allowed ports:** All ports from {MIN_PORT} to {MAX_PORT} except the blocked ones.\n\n"
        f"💡 **Tip:** Use common ports like 80, 8080, 25565, etc."
    )
    await update.message.reply_text(message, parse_mode='Markdown')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    is_admin = user_id in ADMIN_IDS
    is_approved = await is_user_approved(user_id)
    
    message = "🤖 **Bot Commands**\n\n"
    
    message += "📱 **User Commands:**\n"
    message += "🔹 `/start` - Start the bot\n"
    message += "🔹 `/help` - Show this help menu\n"
    
    if is_approved:
        message += "🔹 `/attack ip port duration` - Launch an attack with live timer\n"
        message += "🔹 `/myattacks` - Check your active attacks\n"
        message += "🔹 `/myinfo` - View your account info\n"
        message += "🔹 `/mystats` - View your attack statistics\n"
        message += "🔹 `/blockedports` - Show blocked ports\n"
    
    if is_admin:
        message += "\n👑 **Admin Commands:**\n"
        message += "🔹 `/approve userid days` - Approve a user\n"
        message += "🔹 `/disapprove userid` - Disapprove a user\n"
        message += "🔹 `/users` - List all users\n"
        message += "🔹 `/status` - Check API health\n"
        message += "🔹 `/running` - Check running attacks\n"
        message += "🔹 `/stats` - View bot statistics\n"
        message += "🔹 `/blockedports` - Show blocked ports (admin)\n"
    
    message += "\n⚠️ **Live Timer Feature:**\n"
    message += "• Real-time countdown display\n"
    message += "• Progress bar\n"
    message += "• Stop button to cancel attack\n"
    message += "• Auto-completion notification\n\n"
    message += "⚠️ **Disclaimer:** Misuse of this bot will result in immediate ban."
    
    await update.message.reply_text(message, parse_mode='Markdown')

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Update {update} caused error {context.error}")
    if update and update.effective_message:
        await update.effective_message.reply_text(
            "❌ An error occurred. Please try again later or contact administrator."
        )

def main():
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Admin commands
    application.add_handler(CommandHandler("approve", approve_command))
    application.add_handler(CommandHandler("disapprove", disapprove_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("running", running_command))
    application.add_handler(CommandHandler("users", users_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("blockedports", blocked_ports_command))
    
    # User commands
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("attack", attack_command))
    application.add_handler(CommandHandler("myattacks", myattacks_command))
    application.add_handler(CommandHandler("myinfo", myinfo_command))
    application.add_handler(CommandHandler("mystats", mystats_command))
    application.add_handler(CommandHandler("blockedports", blocked_ports_user_command))
    
    # Callback handler for buttons
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Error handler
    application.add_error_handler(error_handler)
    
    print("🤖 Bot is starting...")
    print(f"📊 MongoDB: Connected and indexes optimized")
    print(f"👑 Admin IDs: {ADMIN_IDS}")
    print(f"🌐 API URL: {API_URL}")
    print(f"🔑 API Key: {API_KEY[:10]}...")
    print(f"🚫 Blocked Ports: {get_blocked_ports_list()}")
    print(f"⏱️ Live Timer Feature: ENABLED")
    print("✅ Bot is running!")
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()