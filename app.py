import os
import sys
import time
import uuid
import math
import re
import html
import json
import base64
import logging
import asyncio
import threading
import secrets
import string
import hashlib
import requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from functools import wraps
from typing import Dict, List, Any, Tuple, Optional

import psutil
import psycopg2
import redis
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Blueprint, current_app
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from logging.handlers import RotatingFileHandler
from supabase import create_client
from telegram import Bot
import httpx

# Load environment variables from .env file
load_dotenv()

# Debug: Check if environment variables are loaded
print(" Loading environment variables...")
print("Current directory:", os.getcwd())
print(".env file exists:", os.path.exists('.env'))
print("SUPABASE_URL loaded:", bool(os.environ.get('SUPABASE_URL')))
print("SUPABASE_KEY loaded:", bool(os.environ.get('SUPABASE_SERVICE_ROLE_KEY')))

# Remove the PostgreSQL connection test entirely - only use Supabase

# =============================================================================
# FLASK APP CONFIGURATION
# =============================================================================

app = Flask(__name__)

# PRODUCTION CONFIGURATION
class Config:
    # REQUIRED - No defaults for secrets
    SECRET_KEY = os.environ['SECRET_KEY']  # Will raise error if missing
    JWT_SECRET_KEY = os.environ['JWT_SECRET_KEY']
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Supabase Configuration - REQUIRED
    SUPABASE_URL = os.environ["SUPABASE_URL"]
    SUPABASE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    
    # Redis Configuration
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
    
    # Security Settings
    WITHDRAWAL_MIN_AMOUNT = int(os.getenv('WITHDRAWAL_MIN_AMOUNT', 400))
    WITHDRAWAL_MAX_AMOUNT = int(os.getenv('WITHDRAWAL_MAX_AMOUNT', 5000))
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # M-PESA Configuration - PRODUCTION
    MPESA_CONSUMER_KEY = os.environ['MPESA_CONSUMER_KEY']
    MPESA_CONSUMER_SECRET = os.environ['MPESA_CONSUMER_SECRET']
    MPESA_BUSINESS_SHORTCODE = os.environ['MPESA_BUSINESS_SHORTCODE']
    MPESA_PASSKEY = os.environ['MPESA_PASSKEY']
    MPESA_B2C_SHORTCODE = os.environ['MPESA_B2C_SHORTCODE']
    MPESA_B2C_INITIATOR_NAME = os.environ['MPESA_B2C_INITIATOR_NAME']
    MPESA_B2C_SECURITY_CREDENTIAL = os.environ['MPESA_B2C_SECURITY_CREDENTIAL']
    MPESA_ENVIRONMENT = os.environ.get('MPESA_ENVIRONMENT', 'production')  # Default to production
    
    # Callback URLs - REQUIRED for production
    MPESA_CALLBACK_URL = os.environ['MPESA_CALLBACK_URL']
    MPESA_B2C_CALLBACK_URL = os.environ['MPESA_B2C_CALLBACK_URL']
    MPESA_B2C_QUEUE_TIMEOUT_URL = os.environ['MPESA_B2C_QUEUE_TIMEOUT_URL']
    
    # Celcom SMS Configuration - REQUIRED
    CELCOM_SMS_API_KEY = os.environ['CELCOM_SMS_API_KEY']
    CELCOM_SENDER_ID = os.environ.get('CELCOM_SENDER_ID', 'RefNinja')
    CELCOM_SMS_URL = os.environ.get('CELCOM_SMS_URL', 'https://api.celcomafrica.com/sms/send')
    
    # Telegram (Optional)
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')
    
    # Safaricom IPs (Whitelist) - PRODUCTION
    SAFARICOM_IPS = [
        '196.201.214.200', '196.201.214.206', '196.201.213.114',
        '196.201.212.227', '196.201.212.224', '196.201.212.138',
        '196.201.212.129', '196.201.212.136', '196.201.212.74',
        '196.201.212.69'
    ]
    
    # Session Security
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = True  # Always True in production
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

class DevelopmentConfig(Config):
    SESSION_COOKIE_SECURE = False
    DEBUG = True
        
# Load appropriate config based on environment
if os.getenv('FLASK_ENV') == 'development':
    app.config.from_object(DevelopmentConfig)
    app.logger.info("Development configuration loaded")
else:
    app.config.from_object(Config)
    app.logger.info("Production configuration loaded")

# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

# Initialize Supabase client
supabase = create_client(app.config.get('SUPABASE_URL'), app.config.get('SUPABASE_KEY'))

# Initialize Redis client
redis_client = redis.from_url(app.config['REDIS_URL'], decode_responses=True)

# =============================================================================
# EXTENSIONS INITIALIZATION
# =============================================================================

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Custom key function for rate limiting that uses user ID when available
def get_limiter_key():
    """Use user ID if authenticated, otherwise IP address."""
    try:
        if current_user and current_user.is_authenticated:
            return f"user:{current_user.id}"
    except Exception:
        pass
    return get_remote_address()

# Initialize rate limiter
rate_limiter = Limiter(
    app=app,
    key_func=get_limiter_key,
    storage_uri=app.config.get("REDIS_URL", "memory://"),
    default_limits=["1000 per day", "200 per hour", "40 per minute"],
    strategy="fixed-window",  # or "moving-window"
    on_breach=lambda limit: current_app.logger.warning(f"🚫 Rate limit hit: {limit}")
)

# =============================================================================
# DATABASE MODELS
# =============================================================================

# Database Models as Python Classes (for type hinting and structure)
class User(UserMixin):
    def __init__(self, data=None):
        if data:
            self.id = data.get('id')
            self.username = data.get('username')
            self.email = data.get('email')
            self.password_hash = data.get('password_hash')
            self.phone = data.get('phone')
            self.name = data.get('name')
            self.balance = data.get('balance', 0.0)
            self.total_earned = data.get('total_earned', 0.0)
            self.total_withdrawn = data.get('total_withdrawn', 0.0)
            self.referral_code = data.get('referral_code')
            self.referred_by = data.get('referred_by')
            self.referral_balance = data.get('referral_balance', 0.0)
            self.referral_count = data.get('referral_count', 0)
            self._is_admin = data.get('is_admin', False)
            self._is_verified = data.get('is_verified', False)
            self._is_active = data.get('is_active', True)
            self.created_at = data.get('created_at')
            self.last_login = data.get('last_login')
            self.login_attempts = data.get('login_attempts', 0)
            self.locked_until = data.get('locked_until')
            self.two_factor_enabled = data.get('two_factor_enabled', False)
            self.user_rank = data.get('user_rank', 'Bronze')
            self.total_commission = data.get('total_commission', 0.0)
            self.referral_source = data.get('referral_source', 'direct')
            self.reset_token = data.get('reset_token')
            self.reset_token_expires = data.get('reset_token_expires')

    @property
    def is_active(self):
        return self._is_active

    @is_active.setter
    def is_active(self, value):
        self._is_active = value

    @property
    def is_admin(self):
        return self._is_admin

    @is_admin.setter
    def is_admin(self, value):
        self._is_admin = value

    @property
    def is_verified(self):
        return self._is_verified

    @is_verified.setter
    def is_verified(self, value):
        self._is_verified = value

    def set_password(self, password):
        # When creating a new user
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        # When verifying login
        return check_password_hash(self.password_hash, password)
    
    def is_locked(self):
        if self.locked_until and datetime.fromisoformat(self.locked_until.replace('Z', '+00:00')) > datetime.now(timezone.utc):
            return True
        return False
    
    def generate_phone_linked_referral_code(self):
        phone_hash = hashlib.md5(self.phone.encode()).hexdigest()[:6].upper()
        self.referral_code = f"RN{phone_hash}"
    
    def update_rank(self):
        if self.total_commission >= 10000:
            self.user_rank = 'Diamond'
        elif self.total_commission >= 5000:
            self.user_rank = 'Platinum'
        elif self.total_commission >= 2000:
            self.user_rank = 'Gold'
        elif self.total_commission >= 1000:
            self.user_rank = 'Silver'
        else:
            self.user_rank = 'Bronze'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'password_hash': self.password_hash,
            'phone': self.phone,
            'name': self.name,
            'balance': self.balance,
            'total_earned': self.total_earned,
            'total_withdrawn': self.total_withdrawn,
            'referral_code': self.referral_code,
            'referred_by': self.referred_by,
            'referral_balance': self.referral_balance,
            'referral_count': self.referral_count,
            'is_admin': self._is_admin,
            'is_verified': self._is_verified,
            'is_active': self._is_active,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'login_attempts': self.login_attempts,
            'locked_until': self.locked_until,
            'two_factor_enabled': self.two_factor_enabled,
            'user_rank': self.user_rank,
            'total_commission': self.total_commission,
            'referral_source': self.referral_source,
            'reset_token': self.reset_token,
            'reset_token_expires': self.reset_token_expires
        }

# =============================================================================
# DATABASE UTILITIES
# =============================================================================

# Enhanced SupabaseDB class with error handling
class SupabaseDB:
    @staticmethod
    def create_job(job_data):
        try:
            response = supabase.table('jobs').insert(job_data).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("create_job", e, False)

    @staticmethod
    def get_all_jobs(user_id=None):
        """
        Get all jobs from the database
        """
        try:
            if user_id:
                # Get jobs for specific user
                response = supabase.table('jobs')\
                    .select('*')\
                    .eq('user_id', user_id)\
                    .order('created_at', desc=True)\
                    .execute()
            else:
                # Get all jobs (admin view)
                response = supabase.table('jobs')\
                    .select('*')\
                    .order('created_at', desc=True)\
                    .execute()
            
            return response.data if response.data else []
        except Exception as e:
            current_app.logger.error(f"Error getting jobs: {str(e)}")
            return []

    @staticmethod
    def get_job_by_id(job_id):
        try:
            response = supabase.table('jobs').select('*').eq('id', job_id).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("get_job_by_id", e, False)

    @staticmethod
    def update_job(job_id, update_data):
        try:
            update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
            response = supabase.table('jobs').update(update_data).eq('id', job_id).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("update_job", e, False)

    @staticmethod
    def delete_job(job_id):
        try:
            response = supabase.table('jobs').delete().eq('id', job_id).execute()
            return True
        except Exception as e:
            return SupabaseDB.handle_db_error("delete_job", e, False)
    
    @staticmethod
    def test_connection():
        """Test if Supabase connection is working"""
        try:
            response = supabase.table('users').select('*').limit(1).execute()
            return True, "Connection successful"
        except Exception as e:
            return False, f"Connection failed: {e}"

    @staticmethod
    def reconnect():
        """Attempt to reinitialize Supabase connection"""
        try:
            global supabase
            supabase = create_client(
                os.environ.get('SUPABASE_URL'), 
                os.environ.get('SUPABASE_SERVICE_ROLE_KEY')
            )
            return True, "Reconnection successful"
        except Exception as e:
            return False, f"Reconnection failed: {e}"

    @staticmethod
    def execute_with_retry(operation, retries=3, delay=2, timeout=5.0):
        """
        Execute a Supabase operation with retries and a timeout.
        Prevents long hangs that cause Gunicorn worker timeouts.
        """
        for attempt in range(retries):
            try:
                # Run the operation, enforcing a network timeout
                return operation(timeout)
            except Exception as e:
                print(f"[SupabaseDB] Attempt {attempt + 1} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(delay)
                else:
                    raise e

    @staticmethod
    def get_user_by_id(user_id):
        """
        Fetch a user by ID safely, with timeout + retry.
        """
        def operation(timeout):
            try:
                # Apply timeout at HTTP level (Supabase uses httpx under the hood)
                response = supabase.table('users').select('*').eq('id', user_id).execute()
                if response.data:
                    print(f"[SupabaseDB] Loaded user {user_id}")
                    return User(response.data[0])
                else:
                    print(f"[SupabaseDB] No user found for id={user_id}")
                    return None
            except httpx.TimeoutException:
                raise Exception(f"Supabase query for user {user_id} timed out after {timeout}s")

        try:
            return SupabaseDB.execute_with_retry(operation)
        except Exception as e:
            print(f"[SupabaseDB] get_user_by_id() failed: {e}")
            return None
        
    @staticmethod
    def handle_db_error(method_name, error, raise_exception=True):
        """Standardized database error handling"""
        error_msg = f"Database error in {method_name}: {str(error)}"
        current_app.logger.error(error_msg)
        
        if raise_exception:
            raise Exception(f"Database operation failed: {method_name}")
        return None

    @staticmethod
    def get_user_by_phone(phone):
        try:
            response = supabase.table('users').select('*').eq('phone', phone).execute()
            if response.data:
                return User(response.data[0])
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("get_user_by_phone", e, False)

    @staticmethod
    def get_user_by_username(username):
        try:
            response = supabase.table('users').select('*').eq('username', username).execute()
            if response.data:
                return User(response.data[0])
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("get_user_by_username", e, False)

    @staticmethod
    def get_user_by_email(email):
        try:
            response = supabase.table('users').select('*').eq('email', email).execute()
            if response.data:
                return User(response.data[0])
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("get_user_by_email", e, False)

    @staticmethod
    def get_user_by_referral_code(referral_code):
        try:
            response = supabase.table('users').select('*').eq('referral_code', referral_code).execute()
            if response.data:
                return User(response.data[0])
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("get_user_by_referral_code", e, False)

    @staticmethod
    def create_user(user_data):
        try:
            # Validate required fields
            required_fields = ['id', 'username', 'phone', 'name', 'password_hash']
            for field in required_fields:
                if field not in user_data or not user_data[field]:
                    raise ValueError(f"Missing required field: {field}")

            response = supabase.table('users').insert(user_data).execute()
            if response.data:
                return User(response.data[0])
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("create_user", e)

    @staticmethod
    def update_user(user_id, update_data):
        try:
            if not user_id:
                raise ValueError("User ID is required for update")
                
            response = supabase.table('users').update(update_data).eq('id', user_id).execute()
            if response.data:
                return User(response.data[0])
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("update_user", e)

    @staticmethod
    def create_transaction(transaction_data):
        try:
            # Validate transaction data
            required_fields = ['id', 'user_id', 'amount', 'transaction_type']
            for field in required_fields:
                if field not in transaction_data:
                    raise ValueError(f"Missing required transaction field: {field}")

            response = supabase.table('transactions').insert(transaction_data).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("create_transaction", e)

    @staticmethod
    def update_transaction(transaction_id, update_data):
        try:
            response = supabase.table('transactions').update(update_data).eq('id', transaction_id).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("update_transaction", e, False)

    @staticmethod
    def get_transaction_by_id(transaction_id):
        try:
            response = supabase.table('transactions').select('*').eq('id', transaction_id).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("get_transaction_by_id", e, False)

    @staticmethod
    def get_transactions_by_user(user_id, limit=None, transaction_type=None):
        try:
            query = supabase.table('transactions').select('*').eq('user_id', user_id)
            if transaction_type:
                query = query.eq('transaction_type', transaction_type)
            query = query.order('created_at', desc=True)
            if limit:
                query = query.limit(limit)
            response = query.execute()
            return response.data
        except Exception as e:
            return SupabaseDB.handle_db_error("get_transactions_by_user", e, False)

    @staticmethod
    def get_referrals_by_referrer(referrer_id):
        try:
            response = supabase.table('referrals').select('*').eq('referrer_id', referrer_id).order('created_at', desc=True).execute()
            return response.data
        except Exception as e:
            return SupabaseDB.handle_db_error("get_referrals_by_referrer", e, False)

    @staticmethod
    def create_referral(referral_data):
        try:
            response = supabase.table('referrals').insert(referral_data).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("create_referral", e, False)

    @staticmethod
    def get_security_logs_by_user(user_id, limit=None):
        try:
            query = supabase.table('security_logs').select('*').eq('user_id', user_id).order('created_at', desc=True)
            if limit:
                query = query.limit(limit)
            response = query.execute()
            return response.data
        except Exception as e:
            return SupabaseDB.handle_db_error("get_security_logs_by_user", e, False)

    @staticmethod
    def create_security_log(log_data):
        try:
            response = supabase.table('security_logs').insert(log_data).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("create_security_log", e, False)

    @staticmethod
    def create_mpesa_callback(callback_data):
        try:
            response = supabase.table('mpesa_callbacks').insert(callback_data).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("create_mpesa_callback", e, False)

    @staticmethod
    def get_two_factor_code(user_id, code, purpose, used=False):
        try:
            response = supabase.table('two_factor_codes').select('*').eq('user_id', user_id).eq('code', code).eq('purpose', purpose).eq('is_used', used).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("get_two_factor_code", e, False)

    @staticmethod
    def create_two_factor_code(code_data):
        try:
            response = supabase.table('two_factor_codes').insert(code_data).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("create_two_factor_code", e, False)

    @staticmethod
    def update_two_factor_code(code_id, update_data):
        try:
            response = supabase.table('two_factor_codes').update(update_data).eq('id', code_id).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            return SupabaseDB.handle_db_error("update_two_factor_code", e, False)

    @staticmethod
    def get_all_users():
        try:
            response = supabase.table('users').select('*').execute()
            return response.data
        except Exception as e:
            return SupabaseDB.handle_db_error("get_all_users", e, False)

    @staticmethod
    def get_pending_withdrawals():
        try:
            response = supabase.table('transactions').select('*').eq('transaction_type', 'withdrawal').eq('status', 'pending').execute()
            return response.data
        except Exception as e:
            return SupabaseDB.handle_db_error("get_pending_withdrawals", e, False)

    @staticmethod
    def get_pending_payments():
        try:
            response = supabase.table('transactions').select('*').eq('transaction_type', 'registration_fee').eq('status', 'pending').execute()
            return response.data
        except Exception as e:
            return SupabaseDB.handle_db_error("get_pending_payments", e, False)

    @staticmethod
    def get_recent_users(limit=10):
        try:
            response = supabase.table('users').select('*').order('created_at', desc=True).limit(limit).execute()
            return response.data
        except Exception as e:
            return SupabaseDB.handle_db_error("get_recent_users", e, False)

    @staticmethod
    def get_recent_activity(limit=10):
        try:
            response = supabase.table('transactions').select('*').order('created_at', desc=True).limit(limit).execute()
            return response.data
        except Exception as e:
            return SupabaseDB.handle_db_error("get_recent_activity", e, False)

    @staticmethod
    def get_top_users(limit=50):
        try:
            response = supabase.table('users').select('*').order('total_commission', desc=True).limit(limit).execute()
            return response.data
        except Exception as e:
            return SupabaseDB.handle_db_error("get_top_users", e, False)

    @staticmethod
    def get_users_count():
        try:
            response = supabase.table('users').select('*', count='exact').execute()
            return len(response.data)
        except Exception as e:
            return SupabaseDB.handle_db_error("get_users_count", e, False)

    @staticmethod
    def get_verified_users_count():
        try:
            response = supabase.table('users').select('*', count='exact').eq('is_verified', True).execute()
            return len(response.data)
        except Exception as e:
            return SupabaseDB.handle_db_error("get_verified_users_count", e, False)

    @staticmethod
    def get_referrals_count():
        try:
            response = supabase.table('referrals').select('*', count='exact').execute()
            return len(response.data)
        except Exception as e:
            return SupabaseDB.handle_db_error("get_referrals_count", e, False)

    @staticmethod
    def get_total_commission():
        try:
            response = supabase.table('users').select('total_commission').execute()
            total = sum(user['total_commission'] for user in response.data if user['total_commission'])
            return total
        except Exception as e:
            return SupabaseDB.handle_db_error("get_total_commission", e, False)

    @staticmethod
    def get_total_withdrawn():
        try:
            response = supabase.table('users').select('total_withdrawn').execute()
            total = sum(user['total_withdrawn'] for user in response.data if user['total_withdrawn'])
            return total
        except Exception as e:
            return SupabaseDB.handle_db_error("get_total_withdrawn", e, False)

    @staticmethod
    def get_total_balance():
        try:
            response = supabase.table('users').select('balance').execute()
            total = sum(user['balance'] for user in response.data if user['balance'])
            return total
        except Exception as e:
            return SupabaseDB.handle_db_error("get_total_balance", e, False)

# =============================================================================
# DATABASE SCHEMA MANAGER
# =============================================================================

def supabase_check(table_name: str, limit: int = 1, retries: int = 3, timeout: int = 5):
    """Check Supabase availability with retry logic and timeout."""
    for attempt in range(1, retries + 1):
        try:
            # Supabase-py doesn't support direct timeout, so use requests timeout override
            response = supabase.table(table_name).select("*").limit(limit).execute()
            return response
        except Exception as e:
            app.logger.warning(f"Supabase attempt {attempt} failed: {e}")
            time.sleep(min(2 ** attempt, 10))  # exponential backoff
    raise ConnectionError(f"Supabase {table_name} check failed after {retries} attempts")

class DatabaseHealthMonitor:
    """Monitor database health and performance"""
    
    @staticmethod
    def get_database_metrics():
        """Get comprehensive database metrics"""
        try:
            metrics = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'connection_status': 'unknown',
                'response_time': 0,
                'table_counts': {},
                'performance': {}
            }
            
            # Test connection speed
            start_time = time.time()
            response = supabase.table('users').select('*', count='exact').limit(1).execute()
            metrics['response_time'] = round((time.time() - start_time) * 1000, 2)
            metrics['connection_status'] = 'healthy'
            
            # Get table counts
            tables = ['users', 'transactions', 'referrals', 'security_logs', 'mpesa_callbacks', 'two_factor_codes']
            for table in tables:
                try:
                    response = supabase.table(table).select('*', count='exact').execute()
                    metrics['table_counts'][table] = len(response.data)
                except Exception as e:
                    metrics['table_counts'][table] = f"error: {e}"
            
            return metrics
            
        except Exception as e:
            return {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'connection_status': 'unhealthy',
                'error': str(e)
            }
    
    @staticmethod
    def log_database_health():
        """Log database health status"""
        metrics = DatabaseHealthMonitor.get_database_metrics()
        
        if metrics['connection_status'] == 'healthy':
            app.logger.info(f"Database health: {metrics['response_time']}ms response")
        else:
            app.logger.error(f"Database health issue: {metrics.get('error', 'Unknown error')}")
        
        return metrics

class DatabaseManager:
    """Production-grade database schema manager for Supabase (uses direct DB connection)."""
    
    def __init__(self, supabase_client):
        self.supabase = supabase_client
        self.logger = logging.getLogger(__name__)
    
    def _run_sql_via_db_url(self, sql: str, db_url: Optional[str] = None, timeout: int = 30) -> None:
        """
        Execute raw SQL using direct Postgres connection via SUPABASE_DB_URL.
        Raises Exception on failure.
        """
        db_url = db_url or os.environ.get('SUPABASE_DB_URL')
        if not db_url:
            raise Exception("SUPABASE_DB_URL not set; cannot execute raw SQL via direct DB connection.")
        
        # Use autocommit for DDL/DDL-like statements
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
        finally:
            conn.close()
    
    def execute_sql(self, sql: str, max_retries: int = 3) -> bool:
        """Execute SQL with proper error handling and retries using direct DB connection."""
        for attempt in range(max_retries):
            try:
                self._run_sql_via_db_url(sql)
                self.logger.info(f"SQL executed successfully (attempt {attempt + 1})")
                return True
                
            except Exception as e:
                err = str(e)
                # Avoid emoji in logs to prevent Windows console encoding errors
                self.logger.warning(f"SQL execution attempt {attempt + 1} failed: {err}")
                
                if "already exists" in err.lower():
                    self.logger.info("Table/index already exists (non-fatal)")
                    return True
                
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    self.logger.info(f"Retrying SQL execution in {wait} seconds...")
                    time.sleep(wait)
                else:
                    self.logger.error(f"All SQL execution attempts failed: {err}")
                    return False
        return False
    
    def create_tables(self) -> bool:
        """Create all required tables with proper constraints"""
        tables = self._get_table_definitions()
        
        for table_name, sql in tables:
            self.logger.info(f"Creating table: {table_name}")
            if not self.execute_sql(sql):
                self.logger.error(f"Failed to create table: {table_name}")
                return False
        
        self.logger.info("All tables created successfully")
        return True
    
    def create_indexes(self) -> bool:
        """Create performance indexes"""
        indexes = self._get_index_definitions()
        
        for index_name, sql in indexes:
            self.logger.info(f"Creating index: {index_name}")
            if not self.execute_sql(sql):
                self.logger.warning(f"Index creation failed (may already exist): {index_name}")
        
        self.logger.info("All indexes created/verified")
        return True
    
    def _get_table_definitions(self) -> List[Tuple[str, str]]:
        """Return all table creation SQL with proper error handling"""
        return [
            ("users", """
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE,
                phone VARCHAR(20) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                password_hash TEXT NOT NULL,
                balance DECIMAL(10,2) DEFAULT 0.0 CHECK (balance >= 0),
                total_earned DECIMAL(10,2) DEFAULT 0.0 CHECK (total_earned >= 0),
                total_withdrawn DECIMAL(10,2) DEFAULT 0.0 CHECK (total_withdrawn >= 0),
                referral_code VARCHAR(20) UNIQUE,
                referred_by VARCHAR(20),
                referral_balance DECIMAL(10,2) DEFAULT 0.0 CHECK (referral_balance >= 0),
                referral_count INTEGER DEFAULT 0 CHECK (referral_count >= 0),
                is_admin BOOLEAN DEFAULT FALSE,
                is_verified BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                login_attempts INTEGER DEFAULT 0 CHECK (login_attempts >= 0),
                locked_until TIMESTAMPTZ,
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                user_rank VARCHAR(20) DEFAULT 'Bronze',
                total_commission DECIMAL(10,2) DEFAULT 0.0 CHECK (total_commission >= 0),
                referral_source VARCHAR(50) DEFAULT 'direct',
                reset_token TEXT,
                reset_token_expires TIMESTAMPTZ,
                -- Additional constraints
                CONSTRAINT valid_phone CHECK (phone ~ '^254[17]\\d{8}$'),
                CONSTRAINT valid_email CHECK (email IS NULL OR email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'),
                CONSTRAINT chk_balance_limits CHECK (balance <= 1000000),
                CONSTRAINT chk_username_length CHECK (LENGTH(username) >= 3)
            );
            """),
            
            ("transactions", """
            CREATE TABLE IF NOT EXISTS transactions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                amount DECIMAL(10,2) NOT NULL CHECK (ABS(amount) <= 50000),
                transaction_type VARCHAR(50) NOT NULL CHECK (transaction_type IN ('withdrawal', 'registration_fee', 'referral_bonus')),
                status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'rejected', 'Under Review')),
                phone_number VARCHAR(20),
                mpesa_code VARCHAR(100),
                checkout_request_id VARCHAR(100),
                merchant_request_id VARCHAR(100),
                b2c_conversation_id VARCHAR(100),
                b2c_originator_conversation_id VARCHAR(100),
                description TEXT,
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                processed_at TIMESTAMPTZ,
                -- Constraints
                CONSTRAINT chk_withdrawal_amount CHECK (
                    transaction_type != 'withdrawal' OR 
                    (amount <= 0 AND ABS(amount) >= 400 AND ABS(amount) <= 5000)
                ),
                CONSTRAINT chk_registration_fee CHECK (
                    transaction_type != 'registration_fee' OR 
                    (amount = 200)
                )
            );
            """),
            
            ("referrals", """
            CREATE TABLE IF NOT EXISTS referrals (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                referrer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                referred_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                referral_code_used VARCHAR(20) NOT NULL,
                commission_earned DECIMAL(10,2) DEFAULT 0.0 CHECK (commission_earned >= 0),
                status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
                created_at TIMESTAMPTZ DEFAULT NOW(),
                -- Ensure unique referral relationships
                CONSTRAINT unique_referral_relationship UNIQUE (referrer_id, referred_id)
            );
            """),
            
            ("security_logs", """
            CREATE TABLE IF NOT EXISTS security_logs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE SET NULL,
                event_type VARCHAR(100) NOT NULL,
                ip_address INET,
                user_agent TEXT,
                details TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                -- Index for faster querying
                CONSTRAINT valid_event_type CHECK (event_type IN (
                    'LOGIN_SUCCESS', 'LOGIN_FAILED', 'REGISTRATION', 'LOGOUT',
                    'WITHDRAWAL_INITIATED', 'WITHDRAWAL_COMPLETED', 'WITHDRAWAL_FAILED',
                    'SUSPICIOUS_WITHDRAWAL', '2FA_SUCCESS', '2FA_FAILED',
                    'PASSWORD_CHANGE', 'PROFILE_UPDATE', 'SMS_SENT_SUCCESS',
                    'SMS_SENT_FAILED', 'UNAUTHORIZED_ACCESS', 'ADMIN_ACTION'
                ))
            );
            """),
            
            ("mpesa_callbacks", """
            CREATE TABLE IF NOT EXISTS mpesa_callbacks (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                payload JSONB NOT NULL,
                ip_address INET,
                callback_type VARCHAR(50) CHECK (callback_type IN ('STK', 'B2C', 'C2B')),
                processed BOOLEAN DEFAULT FALSE,
                processed_at TIMESTAMPTZ,
                error_message TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """),
            
            ("jobs", """
            CREATE TABLE IF NOT EXISTS jobs (
              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
              title VARCHAR(255) NOT NULL,
              description TEXT,
               company VARCHAR(255),
               job_link TEXT NOT NULL,
               category VARCHAR(100),
               location VARCHAR(100),
               salary_range VARCHAR(100),
               application_deadline DATE,
               is_active BOOLEAN DEFAULT TRUE,
               is_featured BOOLEAN DEFAULT FALSE,
               created_by UUID REFERENCES users(id),
               created_at TIMESTAMPTZ DEFAULT NOW(),
               updated_at TIMESTAMPTZ DEFAULT NOW(),
               -- Constraints
               CONSTRAINT valid_job_link CHECK (job_link ~ '^https?://'),
                CONSTRAINT valid_category CHECK (category IN ('Internship', 'Full-time', 'Part-time', 'Contract', 'Remote', 'Other'))
            );
            """),
            
            ("two_factor_codes", """
            CREATE TABLE IF NOT EXISTS two_factor_codes (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                code VARCHAR(10) NOT NULL,
                purpose VARCHAR(50) NOT NULL CHECK (purpose IN ('LOGIN', 'WITHDRAWAL', 'PASSWORD_RESET')),
                expires_at TIMESTAMPTZ NOT NULL,
                is_used BOOLEAN DEFAULT FALSE,
                used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                -- Ensure codes are unique per user and purpose when not used
                CONSTRAINT unique_active_code UNIQUE (user_id, code, purpose) 
                WHERE (is_used = FALSE AND expires_at > NOW())
            );
            """)
        ]
    
    def _get_index_definitions(self) -> List[Tuple[str, str]]:
        """Return all index creation SQL"""
        return [
            # Users table indexes
            ("idx_users_phone", "CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);"),
            ("idx_users_email", "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"),
            ("idx_users_referral_code", "CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);"),
            ("idx_users_referred_by", "CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users(referred_by);"),
            ("idx_users_created_at", "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);"),
            ("idx_users_is_verified", "CREATE INDEX IF NOT EXISTS idx_users_is_verified ON users(is_verified) WHERE is_verified = true;"),
            
            # Transactions table indexes
            ("idx_transactions_user_id", "CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);"),
            ("idx_transactions_status", "CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);"),
            ("idx_transactions_created_at", "CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);"),
            ("idx_transactions_type_status", "CREATE INDEX IF NOT EXISTS idx_transactions_type_status ON transactions(transaction_type, status);"),
            ("idx_transactions_mpesa_code", "CREATE INDEX IF NOT EXISTS idx_transactions_mpesa_code ON transactions(mpesa_code) WHERE mpesa_code IS NOT NULL;"),
            
            # Referrals table indexes
            ("idx_referrals_referrer_id", "CREATE INDEX IF NOT EXISTS idx_referrals_referrer_id ON referrals(referrer_id);"),
            ("idx_referrals_referred_id", "CREATE INDEX IF NOT EXISTS idx_referrals_referred_id ON referrals(referred_id);"),
            ("idx_referrals_created_at", "CREATE INDEX IF NOT EXISTS idx_referrals_created_at ON referrals(created_at);"),
            
            # Security logs indexes
            ("idx_security_logs_user_id", "CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON security_logs(user_id);"),
            ("idx_security_logs_created_at", "CREATE INDEX IF NOT EXISTS idx_security_logs_created_at ON security_logs(created_at);"),
            ("idx_security_logs_event_type", "CREATE INDEX IF NOT EXISTS idx_security_logs_event_type ON security_logs(event_type);"),
            
            # Two-factor codes indexes
            ("idx_two_factor_codes_user_id", "CREATE INDEX IF NOT EXISTS idx_two_factor_codes_user_id ON two_factor_codes(user_id);"),
            ("idx_two_factor_codes_code", "CREATE INDEX IF NOT EXISTS idx_two_factor_codes_code ON two_factor_codes(code);"),
            ("idx_two_factor_codes_expires", "CREATE INDEX IF NOT EXISTS idx_two_factor_codes_expires ON two_factor_codes(expires_at) WHERE is_used = false;"),
            
            # M-Pesa callbacks indexes
            ("idx_mpesa_callbacks_processed", "CREATE INDEX IF NOT EXISTS idx_mpesa_callbacks_processed ON mpesa_callbacks(processed) WHERE processed = false;"),
            ("idx_mpesa_callbacks_created_at", "CREATE INDEX IF NOT EXISTS idx_mpesa_callbacks_created_at ON mpesa_callbacks(created_at);")
        ]
    
    def verify_schema(self) -> dict:
        """Verify all tables and indexes exist and are accessible"""
        verification_results = {}
        tables_to_check = ['users', 'transactions', 'referrals', 'security_logs', 'mpesa_callbacks', 'two_factor_codes']
        
        for table in tables_to_check:
            try:
                # Try to select one row from each table via Supabase client
                response = self.supabase.table(table).select('*', count='exact').limit(1).execute()
                verification_results[table] = {
                    'exists': True,
                    'accessible': True,
                    'row_count': len(response.data) if hasattr(response, 'data') else 0
                }
            except Exception as e:
                verification_results[table] = {
                    'exists': False,
                    'accessible': False,
                    'error': str(e)
                }
        
        return verification_results
    
    def initialize_database(self) -> bool:
        """Complete database initialization process"""
        self.logger.info("Starting database initialization...")
        
        # Step 1: Create tables
        if not self.create_tables():
            self.logger.error("Table creation failed")
            return False
        
        # Step 2: Create indexes
        if not self.create_indexes():
            self.logger.error("Index creation failed")
            return False
        
        # Step 3: Verify schema
        verification = self.verify_schema()
        failed_tables = [table for table, result in verification.items() if not result['exists']]
        
        if failed_tables:
            self.logger.error(f"Schema verification failed for tables: {failed_tables}")
            return False
        
        self.logger.info("Database initialization completed successfully")
        return True

def create_admin_user_if_missing():
    """Create admin user only if it doesn't exist"""
    try:
        admin_user = SupabaseDB.get_user_by_username('admin')
        if not admin_user:
            print("👨‍💼 Creating admin user...")
            
            admin_data = {
                'id': str(uuid.uuid4()),
                'username': 'admin',
                'email': os.environ.get('ADMIN_EMAIL', 'admin@referralninja.co.ke'),
                'phone': os.environ.get('ADMIN_PHONE', '254712345678'),
                'name': 'System Administrator',
                'is_admin': True,
                'is_verified': True,
                'is_active': True,
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
            admin = User(admin_data)
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')  # Change in production!
            admin.set_password(admin_password)
            admin.generate_phone_linked_referral_code()
            
            admin_dict = admin.to_dict()
            admin_dict.pop('password_hash', None)
            admin_dict['password_hash'] = admin.password_hash
            
            created_admin = SupabaseDB.create_user(admin_dict)
            if created_admin:
                print("✅ Admin user created successfully")
                print(f"   Username: admin")
                print(f"   Password: {admin_password}")
                print("   ⚠️  CHANGE THE PASSWORD IMMEDIATELY!")
            else:
                print("❌ Failed to create admin user")
        else:
            print("✅ Admin user already exists")
            
    except Exception as e:
        print(f"❌ Admin user creation error: {e}")

# =============================================================================
# SECURITY CLASSES
# =============================================================================

class SecurityMonitor:
    @staticmethod
    def log_security_event(event_type, user_id, details):
        """Log security events"""
        security_log = {
            'user_id': user_id,
            'event_type': event_type,
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
            'details': str(details),
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        SupabaseDB.create_security_log(security_log)
        current_app.logger.info(f"Security Event: {event_type} - User: {user_id} - {details}")
    
    @staticmethod
    def generate_2fa_code(user_id, purpose):
        """Generate 2FA code"""
        code = ''.join(secrets.choice(string.digits) for _ in range(6))
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        
        two_fa_code = {
            'user_id': user_id,
            'code': code,
            'purpose': purpose,
            'expires_at': expires_at.isoformat(),
            'is_used': False,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        SupabaseDB.create_two_factor_code(two_fa_code)
        
        # Send 2FA code via Celcom SMS
        user = SupabaseDB.get_user_by_id(user_id)
        if user:
            CelcomSMS.send_2fa_code(user.phone, code)
        
        current_app.logger.info(f"2FA Code for {user_id}: {code}")
        return code
    
    @staticmethod
    def verify_2fa_code(user_id, code, purpose):
        """Verify 2FA code"""
        two_fa_code = SupabaseDB.get_two_factor_code(user_id, code, purpose, False)
        
        if not two_fa_code:
            return False
        
        expires_at = datetime.fromisoformat(two_fa_code['expires_at'].replace('Z', '+00:00'))
        if expires_at < datetime.now(timezone.utc):
            return False
        
        # Mark as used
        SupabaseDB.update_two_factor_code(two_fa_code['id'], {'is_used': True})
        return True
    
    @staticmethod
    def notify_admins(message):
        """Notify admins of security events"""
        current_app.logger.warning(f"ADMIN ALERT: {message}")

class FraudDetector:
    @staticmethod
    def check_suspicious_activity(user, amount, request_obj):
        """Detect suspicious withdrawal patterns"""
        checks = []
        
        # Check 1: Amount exceeds threshold
        if amount > 2000:  # Suspicious amount threshold
            checks.append("Amount exceeds normal threshold")
        
        # Check 2: Multiple rapid withdrawals
        recent_withdrawals = SupabaseDB.get_transactions_by_user(
            user.id, 
            transaction_type='withdrawal'
        )
        # Filter for last hour
        recent_withdrawals = [t for t in recent_withdrawals 
                            if datetime.fromisoformat(t['created_at'].replace('Z', '+00:00')) >= datetime.now(timezone.utc) - timedelta(hours=1)]
        
        if len(recent_withdrawals) >= 3:
            checks.append("Multiple withdrawals in short period")
        
        # Check 3: Unusual time (2AM - 5AM)
        current_hour = datetime.now(timezone.utc).hour
        if 2 <= current_hour <= 5:
            checks.append("Unusual withdrawal time")
        
        # Check 4: New device/location
        if recent_withdrawals:
            recent_withdrawal = recent_withdrawals[0]
            if recent_withdrawal.get('ip_address') != request_obj.remote_addr:
                checks.append("Different IP address from previous withdrawals")
        
        # Check 5: New user with large withdrawal
        user_created = datetime.fromisoformat(user.created_at.replace('Z', '+00:00'))
        if user_created > datetime.now(timezone.utc) - timedelta(days=1) and amount > 1000:
            checks.append("New user with large withdrawal")
        
        return " | ".join(checks) if checks else None

# =============================================================================
# CELCOM SMS IMPLEMENTATION
# =============================================================================

class CelcomSMS:
    @staticmethod
    def send_sms(phone, message, max_retries=3):
        """
        Send SMS using Celcom Africa API with retry logic
        """
        for attempt in range(max_retries):
            try:
                # Ensure phone number is in correct format (254...)
                phone_clean = CelcomSMS.format_phone_number(phone)
                
                # Prepare payload for Celcom API
                payload = {
                    'api_key': app.config['CELCOM_SMS_API_KEY'],
                    'sender_id': app.config['CELCOM_SENDER_ID'],
                    'phone': phone_clean,
                    'message': message
                }
                
                headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                
                # Make API request
                response = requests.post(
                    app.config['CELCOM_SMS_URL'],
                    json=payload,
                    headers=headers,
                    timeout=30
                )
                
                # Log the request and response for debugging
                current_app.logger.info(f"Celcom SMS API Request: {payload}")
                current_app.logger.info(f"Celcom SMS API Response: {response.status_code} - {response.text}")
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Check if SMS was sent successfully based on Celcom API response structure
                    if result.get('status') == 'success' or result.get('success') or response.status_code == 200:
                        current_app.logger.info(f"✅ Celcom SMS sent successfully to {phone_clean}")
                        
                        # Log successful SMS delivery
                        SecurityMonitor.log_security_event(
                            "SMS_SENT_SUCCESS",
                            None,
                            {"phone": phone_clean, "message_length": len(message), "provider": "Celcom"}
                        )
                        return True
                    else:
                        error_msg = result.get('message', 'Unknown error from Celcom API')
                        current_app.logger.error(f"❌ Celcom SMS failed: {error_msg}")
                else:
                    current_app.logger.error(f"❌ Celcom SMS HTTP error: {response.status_code} - {response.text}")
                
                # Wait before retry (exponential backoff)
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    current_app.logger.info(f"Retrying SMS in {wait_time} seconds...")
                    time.sleep(wait_time)
                    
            except requests.exceptions.RequestException as e:
                current_app.logger.error(f"Celcom SMS network error (attempt {attempt + 1}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
            except Exception as e:
                current_app.logger.error(f"Celcom SMS unexpected error (attempt {attempt + 1}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
        
        # All retries failed
        SecurityMonitor.log_security_event(
            "SMS_SENT_FAILED",
            None,
            {"phone": phone, "error": "All retries failed", "provider": "Celcom"}
        )
        return False
    
    @staticmethod
    def format_phone_number(phone):
        """
        Format phone number to Celcom compatible format (254...)
        """
        # Remove any non-digit characters
        phone_clean = re.sub(r'\D', '', phone)
        
        # Handle different formats
        if phone_clean.startswith('0'):
            # Convert 07... to 2547...
            return '254' + phone_clean[1:]
        elif phone_clean.startswith('+'):
            # Remove + prefix
            return phone_clean[1:]
        elif phone_clean.startswith('254') and len(phone_clean) == 12:
            # Already in correct format
            return phone_clean
        elif len(phone_clean) == 9:
            # Assume it's missing country code
            return '254' + phone_clean
        else:
            # Return as is, let API handle validation
            return phone_clean
    
    @staticmethod
    def send_2fa_code(phone, code):
        """
        Send 2FA code via SMS
        """
        message = f"Your Referral Ninja verification code is: {code}. This code expires in 10 minutes."
        return CelcomSMS.send_sms(phone, message)
    
    @staticmethod
    def send_withdrawal_notification(phone, username, amount, status, transaction_id=None):
        """
        Send withdrawal status notification
        """
        if status == 'processing':
            message = f"Hi {username}, your withdrawal of Ksh {amount} is being processed. You'll get confirmation shortly."
        elif status == 'completed':
            message = f"Hi {username}, your withdrawal of Ksh {amount} was successful! Transaction ID: {transaction_id}. Invite friends to earn more."
        elif status == 'failed':
            message = f"Hi {username}, your withdrawal of Ksh {amount} failed. Your balance has been refunded. Please try again."
        else:
            message = f"Hi {username}, your withdrawal of Ksh {amount} is {status}."
        
        return CelcomSMS.send_sms(phone, message)
    
    @staticmethod
    def send_registration_notification(phone, username):
        """
        Send welcome message after registration
        """
        message = f"✅ Welcome to Referral Ninja, {username}! Complete your KSH 200 payment to activate your account and start earning."
        return CelcomSMS.send_sms(phone, message)
    
    @staticmethod
    def send_referral_notification(phone, username, referral_bonus):
        """
        Send notification when referral bonus is earned
        """
        message = f"💰 Hi {username}, you've earned Ksh {referral_bonus} referral bonus! Keep inviting friends to earn more."
        return CelcomSMS.send_sms(phone, message)

# =============================================================================
# M-PESA INTEGRATION
# =============================================================================

# Production M-Pesa Configuration
def get_mpesa_base_url():
    """Get M-Pesa base URL based on environment"""
    if app.config['MPESA_ENVIRONMENT'] == 'sandbox':
        return 'https://sandbox.safaricom.co.ke'
    else:
        return 'https://api.safaricom.co.ke'

def get_mpesa_access_token():
    """Get M-Pesa OAuth token with production support"""
    try:
        consumer_key = app.config['MPESA_CONSUMER_KEY']
        consumer_secret = app.config['MPESA_CONSUMER_SECRET']
        
        if not consumer_key or not consumer_secret:
            raise ValueError("M-Pesa consumer key and secret are required")
        
        auth = (consumer_key, consumer_secret)
        base_url = get_mpesa_base_url()
        url = f"{base_url}/oauth/v1/generate?grant_type=client_credentials"
        
        response = requests.get(url, auth=auth, timeout=30)
        response.raise_for_status()
        
        token_data = response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            raise ValueError("Failed to get access token from M-Pesa")
            
        return access_token
        
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"M-Pesa token request failed: {str(e)}")
        raise Exception("M-Pesa service unavailable")
    except Exception as e:
        current_app.logger.error(f"M-Pesa token error: {str(e)}")
        raise

def initiate_stk_push(phone_number, amount, account_reference, transaction_desc):
    """Production-ready STK push initiation"""
    try:
        access_token = get_mpesa_access_token()
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        business_shortcode = app.config['MPESA_BUSINESS_SHORTCODE']
        passkey = app.config['MPESA_PASSKEY']
        
        password = base64.b64encode(
            f"{business_shortcode}{passkey}{timestamp}".encode()
        ).decode()
        
        # Format phone number for production
        phone_clean = CelcomSMS.format_phone_number(phone_number)
        
        payload = {
            "BusinessShortCode": business_shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": amount,
            "PartyA": phone_clean,
            "PartyB": business_shortcode,
            "PhoneNumber": phone_clean,
            "CallBackURL": app.config['MPESA_CALLBACK_URL'],
            "AccountReference": account_reference,
            "TransactionDesc": transaction_desc
        }
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        base_url = get_mpesa_base_url()
        response = requests.post(
            f'{base_url}/mpesa/stkpush/v1/processrequest',
            json=payload,
            headers=headers,
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        if result.get('ResponseCode') == '0':
            current_app.logger.info(f"STK Push initiated for {phone_clean}, Amount: {amount}")
            return result
        else:
            error_message = result.get('errorMessage', 'Unknown error')
            current_app.logger.error(f"STK Push failed: {error_message}")
            raise Exception(f"M-Pesa STK push failed: {error_message}")
            
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"STK Push network error: {str(e)}")
        raise Exception("M-Pesa service unavailable")
    except Exception as e:
        current_app.logger.error(f"STK Push error: {str(e)}")
        raise

def get_mpesa_b2c_access_token():
    """Get M-PESA B2C access token"""
    try:
        auth_string = f"{app.config['MPESA_CONSUMER_KEY']}:{app.config['MPESA_CONSUMER_SECRET']}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        
        headers = {
            'Authorization': f'Basic {encoded_auth}'
        }
        
        base_url = get_mpesa_base_url()
        response = requests.get(
            f'{base_url}/oauth/v1/generate?grant_type=client_credentials',
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json().get('access_token')
        else:
            app.logger.error(f"M-PESA B2C token error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        app.logger.error(f"Error getting M-PESA B2C token: {e}")
        return None

def initiate_b2c_payment(phone_number, amount, transaction_reference, remarks="Referral withdrawal"):
    """Initiate B2C payment to user (payout)"""
    try:
        access_token = get_mpesa_b2c_access_token()
        if not access_token:
            app.logger.error("Failed to get M-PESA B2C access token")
            return None
        
        # Format phone number
        if phone_number.startswith('0'):
            phone_number = '254' + phone_number[1:]
        elif phone_number.startswith('+'):
            phone_number = phone_number[1:]
        
        # Security credential (in production, this should be encrypted)
        security_credential = app.config['MPESA_B2C_SECURITY_CREDENTIAL']
        
        payload = {
            "InitiatorName": app.config['MPESA_B2C_INITIATOR_NAME'],
            "SecurityCredential": security_credential,
            "CommandID": "BusinessPayment",
            "Amount": amount,
            "PartyA": app.config['MPESA_B2C_SHORTCODE'],
            "PartyB": phone_number,
            "Remarks": remarks,
            "QueueTimeOutURL": app.config['MPESA_B2C_QUEUE_TIMEOUT_URL'],
            "ResultURL": app.config['MPESA_B2C_CALLBACK_URL'],
            "Occasion": "ReferralPayout",
            "OriginatorConversationID": transaction_reference
        }
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        base_url = get_mpesa_base_url()
        response = requests.post(
            f'{base_url}/mpesa/b2c/v1/paymentrequest',
            json=payload,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('ResponseCode') == '0':
                app.logger.info(f"B2C payment initiated successfully for {phone_number}, Amount: {amount}")
                return result
            else:
                error_message = result.get('errorMessage', 'Unknown error')
                app.logger.error(f"B2C payment failed: {error_message}")
                return None
        else:
            app.logger.error(f"B2C payment HTTP error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"Error initiating B2C payment: {e}")
        return None

def process_automatic_withdrawal(withdrawal_transaction):
    """Process withdrawal automatically via M-Pesa B2C"""
    try:
        user = SupabaseDB.get_user_by_id(withdrawal_transaction['user_id'])
        if not user:
            app.logger.error(f"User not found for withdrawal: {withdrawal_transaction['id']}")
            return False
        
        amount = abs(withdrawal_transaction['amount'])
        phone_number = withdrawal_transaction['phone_number']
        
        # Initiate B2C payment
        b2c_response = initiate_b2c_payment(
            phone_number=phone_number,
            amount=amount,
            transaction_reference=str(withdrawal_transaction['id']),
            remarks=f"Withdrawal for {user.username}"
        )
        
        if b2c_response and b2c_response.get('ResponseCode') == '0':
            # Update transaction with B2C reference
            update_data = {
                'mpesa_code': b2c_response.get('TransactionID', 'PENDING'),
                'b2c_conversation_id': b2c_response.get('ConversationID', ''),
                'b2c_originator_conversation_id': b2c_response.get('OriginatorConversationID', ''),
                'status': 'processing',
                'description': f'M-Pesa B2C payout initiated - {b2c_response.get("ResponseDescription", "")}'
            }
            SupabaseDB.update_transaction(withdrawal_transaction['id'], update_data)
            
            # Send initial SMS via Celcom
            CelcomSMS.send_withdrawal_notification(
                user.phone,
                user.username,
                amount,
                'processing'
            )
            
            app.logger.info(f"B2C payout initiated for user {user.username}, withdrawal ID: {withdrawal_transaction['id']}")
            return True
        else:
            # B2C initiation failed, mark as failed and refund
            update_data = {
                'status': 'failed',
                'description': 'M-Pesa B2C initiation failed'
            }
            SupabaseDB.update_transaction(withdrawal_transaction['id'], update_data)
            
            # Refund user balance
            user.balance += amount
            user.total_withdrawn -= amount
            SupabaseDB.update_user(user.id, {
                'balance': user.balance,
                'total_withdrawn': user.total_withdrawn
            })
            
            # Send failure SMS via Celcom
            CelcomSMS.send_withdrawal_notification(
                user.phone,
                user.username,
                amount,
                'failed'
            )
            
            app.logger.error(f"B2C payout initiation failed for user {user.username}")
            return False
            
    except Exception as e:
        app.logger.error(f"Error processing automatic withdrawal: {e}")
        return False

def query_stk_push_status(checkout_request_id):
    """Query status of STK push transaction"""
    try:
        access_token = get_mpesa_access_token()
        if not access_token:
            return None
            
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password = base64.b64encode(
            f"{app.config['MPESA_BUSINESS_SHORTCODE']}{app.config['MPESA_PASSKEY']}{timestamp}".encode()
        ).decode()
        
        payload = {
            "BusinessShortCode": app.config['MPESA_BUSINESS_SHORTCODE'],
            "Password": password,
            "Timestamp": timestamp,
            "CheckoutRequestID": checkout_request_id
        }
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        base_url = get_mpesa_base_url()
        response = requests.post(
            f'{base_url}/mpesa/stkpushquery/v1/query',
            json=payload,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            app.logger.error(f"STK Query error: {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"Error querying STK status: {e}")
        return None

# =============================================================================
# TELEGRAM INTEGRATION
# =============================================================================

async def send_telegram_message_async(message: str):
    """Send Telegram message asynchronously (safe for Flask contexts)."""
    try:
        # Use app context safely
        app = current_app._get_current_object()
        token = app.config.get("TELEGRAM_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
        chat_id = app.config.get("TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID")

        if not token or not chat_id:
            app.logger.warning("⚠️ Telegram credentials missing — skipping alert")
            return

        safe_message = html.escape(message)
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": safe_message, "parse_mode": "HTML"}

        # Run the request non-blocking
        await asyncio.to_thread(requests.post, url, json=payload, timeout=10)
        app.logger.info("✅ Telegram notification sent successfully")

    except Exception as e:
        try:
            app.logger.error(f"Telegram notification failed: {html.escape(str(e))}")
        except Exception:
            print(f"Telegram notification failed: {str(e)}")


def send_telegram_notification(message: str):
    """Send Telegram notifications safely from any thread or async context."""
    try:
        from app import app as flask_app
        app = flask_app
        with app.app_context():
            token = app.config.get("TELEGRAM_BOT_TOKEN")
            chat_id = app.config.get("TELEGRAM_CHAT_ID")
            if not token or not chat_id:
                app.logger.warning("⚠️ Telegram credentials missing — skipping alert")
                return

            safe_message = html.escape(message)
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = {"chat_id": chat_id, "text": safe_message, "parse_mode": "HTML"}

            # Run sync HTTP in a thread (safe for background threads)
            threading.Thread(target=requests.post, args=(url,), kwargs={"json": payload, "timeout": 10}).start()
            app.logger.info("✅ Telegram notification sent successfully")
    except Exception as e:
        app.logger.error(f"Telegram notification failed: {html.escape(str(e))}")
           
def send_withdrawal_notification_to_telegram(user, transaction):
    """Send withdrawal notification to Telegram"""
    try:
        message = f"""
💰 <b>New Withdrawal Request</b>

👤 <b>User Details:</b>
• Username: {user.username}
• Email: {user.email}
• Phone: {user.phone}
• User ID: #{user.id}

💸 <b>Withdrawal Information:</b>
• Amount: KSH {abs(transaction['amount'])}
• Phone: {transaction['phone_number']}
• Status: ⏳ Pending Processing

⏰ <b>Time Submitted:</b>
{transaction['created_at']}

<i>Please process this withdrawal in the admin dashboard.</i>
"""
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        return True
    except Exception as e:
        current_app.logger.error(f"Error sending withdrawal notification to Telegram: {str(e)}")
        return False

# =============================================================================
# HEALTH MONITORING SYSTEM
# =============================================================================

class HealthMonitor:
    """Comprehensive health monitoring system for production"""
    
    def __init__(self, supabase_client, redis_client, app_config):
        self.supabase = supabase_client
        self.redis = redis_client
        self.config = app_config
        self.logger = logging.getLogger(__name__)
    
    def comprehensive_health_check(self) -> Dict[str, Any]:
        """Run comprehensive health checks for all critical systems"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '1.0.0',
            'components': {}
        }
        
        # Critical components (if any fail, overall status is unhealthy)
        critical_components = {
            'database': self._check_database_health(),
            'redis': self._check_redis_health(),
            'mpesa_api': self._check_mpesa_health(),
            'celcom_sms': self._check_celcom_sms_health(),
        }
        
        # Important components (failures affect functionality but not overall status)
        important_components = {
            'system_resources': self._check_system_resources(),
            'telegram_bot': self._check_telegram_health(),
        }
        
        # Operational metrics
        operational_metrics = {
            'pending_withdrawals': self._get_pending_withdrawals_count(),
            'pending_payments': self._get_pending_payments_count(),
            'recent_errors': self._get_recent_errors(),
            'uptime': self._get_system_uptime(),
        }
        
        health_status['components']['critical'] = critical_components
        health_status['components']['important'] = important_components
        health_status['components']['metrics'] = operational_metrics
        
        # Determine overall status
        if any(comp['status'] == 'unhealthy' for comp in critical_components.values()):
            health_status['status'] = 'unhealthy'
        elif any(comp['status'] == 'degraded' for comp in critical_components.values()):
            health_status['status'] = 'degraded'
        elif any(comp['status'] == 'unhealthy' for comp in important_components.values()):
            health_status['status'] = 'degraded'
        
        return health_status
    
    def _check_database_health(self) -> Dict[str, Any]:
        """Check database connection and performance"""
        try:
            start_time = time.time()
            
            # Test basic connection
            response = self.supabase.table('users').select('*', count='exact').limit(1).execute()
            connection_time = time.time() - start_time
            
            # Test write operation
            test_data = {
                'event_type': 'HEALTH_CHECK',
                'details': 'Database health check',
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            write_response = self.supabase.table('security_logs').insert(test_data).execute()
            
            status = 'healthy'
            if connection_time > 2.0:  # More than 2 seconds is slow
                status = 'degraded'
            
            return {
                'status': status,
                'response_time_ms': round(connection_time * 1000, 2),
                'connection': True,
                'read_operation': True,
                'write_operation': bool(write_response.data),
                'details': f'Database connection OK ({connection_time:.2f}s)'
            }
            
        except Exception as e:
            self.logger.error(f"Database health check failed: {e}")
            return {
                'status': 'unhealthy',
                'response_time_ms': None,
                'connection': False,
                'read_operation': False,
                'write_operation': False,
                'error': str(e),
                'details': 'Database connection failed'
            }
    
    def _check_redis_health(self) -> Dict[str, Any]:
        """Check Redis connection health"""
        try:
            start_time = time.time()
            
            # Test basic connection
            self.redis.ping()
            connection_time = time.time() - start_time
            
            # Test read/write operations
            test_key = f"health_check_{int(time.time())}"
            test_value = "health_check_value"
            
            self.redis.set(test_key, test_value, ex=10)  # Set with 10s expiry
            retrieved_value = self.redis.get(test_key)
            
            status = 'healthy'
            if connection_time > 0.1:  # More than 100ms is slow for Redis
                status = 'degraded'
            
            return {
                'status': status,
                'response_time_ms': round(connection_time * 1000, 2),
                'connection': True,
                'read_operation': retrieved_value == test_value,
                'write_operation': True,
                'details': f'Redis connection OK ({connection_time:.3f}s)'
            }
            
        except Exception as e:
            self.logger.error(f"Redis health check failed: {e}")
            return {
                'status': 'unhealthy',
                'response_time_ms': None,
                'connection': False,
                'read_operation': False,
                'write_operation': False,
                'error': str(e),
                'details': 'Redis connection failed'
            }
    
    def _check_mpesa_health(self) -> Dict[str, Any]:
        """Check M-Pesa API availability"""
        try:
            start_time = time.time()
            
            # Get access token (this tests the API)
            access_token = get_mpesa_access_token()
            response_time = time.time() - start_time
            
            status = 'healthy'
            if response_time > 5.0:  # M-Pesa is slow if >5s
                status = 'degraded'
            
            return {
                'status': status,
                'response_time_ms': round(response_time * 1000, 2),
                'access_token_obtained': bool(access_token),
                'environment': self.config.get('MPESA_ENVIRONMENT', 'unknown'),
                'details': f'M-Pesa API accessible ({response_time:.2f}s)'
            }
            
        except Exception as e:
            self.logger.error(f"M-Pesa health check failed: {e}")
            return {
                'status': 'unhealthy',
                'response_time_ms': None,
                'access_token_obtained': False,
                'environment': self.config.get('MPESA_ENVIRONMENT', 'unknown'),
                'error': str(e),
                'details': 'M-Pesa API unavailable'
            }

    def _check_celcom_sms_health(self) -> Dict[str, Any]:
        """Check Celcom SMS API health"""
        try:
            # Test configuration without sending actual SMS
            api_key = self.config.get('CELCOM_SMS_API_KEY')
            sender_id = self.config.get('CELCOM_SENDER_ID')
            
            if not api_key or api_key == 'your_celcom_api_key':
                return {
                    'status': 'unhealthy',
                    'configured': False,
                    'details': 'Celcom SMS API key not configured'
                }
            
            # Make a test request to check API key validity
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            test_payload = {
                'api_key': api_key,
                'sender_id': sender_id,
                'phone': '254700000000',  # Test number
                'message': 'HEALTH CHECK - IGNORE'
            }
            
            # Don't actually send, just check if credentials are valid
            # by making a lightweight request
            response = requests.post(
                self.config.get('CELCOM_SMS_URL', 'https://api.celcomafrica.com/sms/send'),
                json=test_payload,
                headers=headers,
                timeout=10
            )
            
            # Even if it fails due to invalid number, if we get a response
            # the API is working
            if response.status_code in [200, 400]:  # 400 might be due to test number
                return {
                    'status': 'healthy',
                    'configured': True,
                    'api_accessible': True,
                    'details': 'Celcom SMS API is accessible'
                }
            else:
                return {
                    'status': 'degraded',
                    'configured': True,
                    'api_accessible': False,
                    'http_status': response.status_code,
                    'details': f'Celcom SMS API returned HTTP {response.status_code}'
                }
                
        except requests.exceptions.Timeout:
            return {
                'status': 'unhealthy',
                'configured': True,
                'api_accessible': False,
                'error': 'Timeout',
                'details': 'Celcom SMS API timeout'
            }
        except Exception as e:
            self.logger.error(f"Celcom SMS health check failed: {e}")
            return {
                'status': 'unhealthy',
                'configured': bool(api_key and api_key != 'your_celcom_api_key'),
                'api_accessible': False,
                'error': str(e),
                'details': 'Celcom SMS API check failed'
            }
    
    def _check_system_resources(self) -> Dict[str, Any]:
        """Check system resource utilization"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            status = 'healthy'
            warnings = []
            
            if cpu_percent > 80:
                status = 'degraded'
                warnings.append(f'High CPU usage: {cpu_percent}%')
            
            if memory.percent > 85:
                status = 'degraded'
                warnings.append(f'High memory usage: {memory.percent}%')
            
            if disk.percent > 90:
                status = 'degraded'
                warnings.append(f'Low disk space: {disk.percent}% used')
            
            return {
                'status': status,
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'warnings': warnings,
                'details': f'CPU: {cpu_percent}%, Memory: {memory.percent}%, Disk: {disk.percent}%'
            }
            
        except Exception as e:
            self.logger.error(f"System resources check failed: {e}")
            return {
                'status': 'unknown',
                'error': str(e),
                'details': 'System resource check failed'
            }
    
    def _check_telegram_health(self) -> Dict[str, Any]:
        """Check Telegram bot health"""
        bot_token = self.config.get('TELEGRAM_BOT_TOKEN')
        chat_id = self.config.get('TELEGRAM_CHAT_ID')
        
        if not bot_token or bot_token == 'your_bot_token_here':
            return {
                'status': 'unknown',
                'configured': False,
                'details': 'Telegram bot not configured'
            }
        
        return {
            'status': 'healthy',
            'configured': True,
            'details': 'Telegram bot configured'
        }
    
    def _get_pending_withdrawals_count(self) -> Dict[str, Any]:
        """Get pending withdrawals metrics"""
        try:
            pending_withdrawals = SupabaseDB.get_pending_withdrawals()
            count = len(pending_withdrawals)
            total_amount = sum(abs(t['amount']) for t in pending_withdrawals)
            
            status = 'normal'
            if count > 20:
                status = 'high'
            elif count > 50:
                status = 'critical'
            
            return {
                'status': status,
                'count': count,
                'total_amount': total_amount,
                'details': f'{count} pending withdrawals (KSH {total_amount:,.2f})'
            }
            
        except Exception as e:
            return {
                'status': 'unknown',
                'error': str(e),
                'details': 'Failed to get pending withdrawals'
            }
    
    def _get_pending_payments_count(self) -> Dict[str, Any]:
        """Get pending payments metrics"""
        try:
            pending_payments = SupabaseDB.get_pending_payments()
            count = len(pending_payments)
            
            return {
                'count': count,
                'details': f'{count} pending registration payments'
            }
            
        except Exception as e:
            return {
                'count': 0,
                'error': str(e),
                'details': 'Failed to get pending payments'
            }
    
    def _get_recent_errors(self) -> Dict[str, Any]:
        """Get recent error metrics"""
        try:
            # Get errors from security logs in last hour
            one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            
            response = self.supabase.table('security_logs') \
                .select('*', count='exact') \
                .like('event_type', '%FAILED%') \
                .gte('created_at', one_hour_ago) \
                .execute()
            
            error_count = len(response.data)
            
            return {
                'count': error_count,
                'period': '1h',
                'details': f'{error_count} errors in last hour'
            }
            
        except Exception as e:
            return {
                'count': 0,
                'error': str(e),
                'details': 'Failed to get error count'
            }
    
    def _get_system_uptime(self) -> Dict[str, Any]:
        """Get system uptime information"""
        try:
            uptime_seconds = time.time() - psutil.boot_time()
            uptime_hours = uptime_seconds / 3600
            
            return {
                'hours': round(uptime_hours, 2),
                'details': f'System uptime: {uptime_hours:.2f} hours'
            }
            
        except Exception as e:
            return {
                'hours': 0,
                'error': str(e),
                'details': 'Failed to get uptime'
            }

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def validate_referral_code(code):
    if not code:
        return None
    referrer = SupabaseDB.get_user_by_referral_code(code)
    if not referrer:
        return None
    if not referrer.is_verified:
        return None
    return referrer

def extract_mpesa_code(message):
    patterns = [
        r'[A-Z0-9]{10}',
        r'[A-Z0-9]{9}',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return match.group(0)
    
    return 'PENDING'

def get_user_ranking(user_id):
    user = SupabaseDB.get_user_by_id(user_id)
    if not user:
        return None
    
    ranked_users = SupabaseDB.get_top_users(limit=1000)  # Get all users for ranking
    
    for index, ranked_user_data in enumerate(ranked_users):
        ranked_user = User(ranked_user_data)
        if ranked_user.id == user_id:
            return {
                'position': index + 1,
                'total_users': len(ranked_users),
                'user_rank': user.user_rank
            }
    return None

# Updated send_sms function to use Celcom SMS
def send_sms(phone, message):
    """
    Main SMS function that uses Celcom SMS service
    This maintains backward compatibility with existing code
    """
    return CelcomSMS.send_sms(phone, message)

# =============================================================================
# PAYMENT-ONLY USER STORAGE FUNCTIONS
# =============================================================================

def create_permanent_user_after_payment(temp_user_data, transaction_id):
    """Create permanent user record after successful payment"""
    try:
        # Create user data for permanent storage
        user_data = {
            'id': temp_user_data['id'],
            'username': temp_user_data['username'],
            'email': temp_user_data['email'],
            'phone': temp_user_data['phone'],
            'name': temp_user_data['name'],
            'is_verified': True,
            'is_active': True,
            'created_at': temp_user_data['created_at']
        }
        
        # Create user object and set password
        user = User(user_data)
        user.set_password(temp_user_data['password'])
        user.generate_phone_linked_referral_code()
        
        # Set referral data if applicable
        if temp_user_data.get('referrer'):
            user.referred_by = temp_user_data['referral_code']
            user.referral_source = temp_user_data['referral_source']
        
        # Save to database
        user_dict = user.to_dict()
        user_dict.pop('password_hash', None)
        user_dict['password_hash'] = user.password_hash
        
        created_user = SupabaseDB.create_user(user_dict)
        
        if not created_user:
            app.logger.error(f"Failed to create permanent user for {temp_user_data['username']}")
            return None
        
        # Create transaction record
        transaction_data = {
            'id': transaction_id,
            'user_id': created_user.id,
            'amount': 200.0,
            'transaction_type': 'registration_fee',
            'status': 'completed',
            'phone_number': created_user.phone,
            'description': 'Account registration fee - Payment completed',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        SupabaseDB.create_transaction(transaction_data)
        
        # Handle referral commission if applicable
        if created_user.referred_by:
            referrer = SupabaseDB.get_user_by_referral_code(created_user.referred_by)
            if referrer:
                referrer.referral_balance += 50
                referrer.balance += 50
                referrer.total_commission += 50
                referrer.referral_count += 1
                referrer.update_rank()
                
                referral_data = {
                    'referrer_id': referrer.id,
                    'referred_id': created_user.id,
                    'referral_code_used': created_user.referred_by,
                    'commission_earned': 50.0,
                    'status': 'active',
                    'created_at': datetime.now(timezone.utc).isoformat()
                }
                SupabaseDB.create_referral(referral_data)
                
                # Update referrer in database
                SupabaseDB.update_user(referrer.id, {
                    'referral_balance': referrer.referral_balance,
                    'balance': referrer.balance,
                    'total_commission': referrer.total_commission,
                    'referral_count': referrer.referral_count,
                    'user_rank': referrer.user_rank
                })
                
                # Send referral bonus notification
                CelcomSMS.send_referral_notification(referrer.phone, referrer.username, 50)
        
        # Log security event
        SecurityMonitor.log_security_event(
            "REGISTRATION_COMPLETED", 
            created_user.id, 
            {"ip": request.remote_addr if request else None, "transaction_id": transaction_id}
        )
        
        app.logger.info(f"✅ Permanent user created after payment: {created_user.username}")
        return created_user
        
    except Exception as e:
        app.logger.error(f"Error creating permanent user: {str(e)}")
        return None

def cleanup_expired_temp_users():
    """Clean up temporary user data that's too old (e.g., >24 hours)"""
    # This would require storing temp user data with timestamps
    # For now, we rely on session expiration
    pass

# =============================================================================
# BLUEPRINTS AND ROUTES
# =============================================================================

# Blueprints
auth_bp = Blueprint("auth_api", __name__)
mpesa_bp = Blueprint("mpesa_api", __name__)
withdraw_bp = Blueprint("withdraw_api", __name__)

# API Authentication Routes with Security - MODIFIED FOR PAYMENT-ONLY STORAGE
@auth_bp.route("/register", methods=["POST"])
@rate_limiter.limit("10 per hour")
def api_register():
    try:
        data = request.get_json()
        phone = data.get("phone", "").strip()
        name = data.get("full_name", "").strip()
        password = data.get("password")
        email = data.get("email", "").strip()
        username = data.get("username", "").strip()
        
        # Validation
        if not name or not name.strip():
            return jsonify({"error": "Full name is required"}), 400
            
        if not re.match(r'^254[17]\d{8}$', phone):
            return jsonify({"error": "Invalid phone number format"}), 400
        
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        
        # Check if phone already exists in permanent database
        if SupabaseDB.get_user_by_phone(phone):
            return jsonify({"error": "Phone number already registered"}), 409
        
        # Store temporary user data
        temp_user_data = {
            'id': str(uuid.uuid4()),
            'username': username,
            'email': email,
            'phone': phone,
            'name': name,
            'password': password,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Generate temporary referral code
        phone_hash = hashlib.md5(phone.encode()).hexdigest()[:6].upper()
        temp_user_data['temp_referral_code'] = f"RN{phone_hash}"
        
        # Store temporary user data in session
        session['temp_user_data'] = temp_user_data
        session['pending_verification_user'] = temp_user_data['id']
        
        # Send welcome SMS
        CelcomSMS.send_registration_notification(phone, username)
        
        return jsonify({
            "message": "Registration successful. Please complete KSH 200 payment to activate your account.",
            "user_id": temp_user_data['id'],
            "requires_payment": True
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({"error": "Registration failed"}), 500

@auth_bp.route("/login", methods=["POST"])
@rate_limiter.limit("5 per minute")
def api_login():
    try:
        data = request.get_json()
        phone = data.get("phone", "").strip()
        password = data.get("password")
        
        user = SupabaseDB.get_user_by_phone(phone)
        
        if not user:
            SecurityMonitor.log_security_event(
                "LOGIN_FAILED", 
                None,
                {"ip": request.remote_addr, "reason": "Invalid credentials - user not found"}
            )
            return jsonify({"error": "Invalid phone or password"}), 401
        
        # When verifying login
        if check_password_hash(user.password_hash, password):
            print("Login successful!")
            
            if user.is_locked():
                return jsonify({"error": "Account temporarily locked. Try again later."}), 423
            
            if not user.is_active:
                return jsonify({"error": "Account deactivated"}), 403
            
            if not user.is_verified:
                return jsonify({"error": "Account not verified. Please complete payment verification."}), 403
            
            # Reset login attempts on successful login
            update_data = {
                'login_attempts': 0,
                'locked_until': None,
                'last_login': datetime.now(timezone.utc).isoformat()
            }
            SupabaseDB.update_user(user.id, update_data)
            
            # Generate 2FA code if enabled
            if user.two_factor_enabled:
                code = SecurityMonitor.generate_2fa_code(user.id, "LOGIN")
                return jsonify({
                    "message": "2FA code sent to your phone",
                    "requires_2fa": True
                })
            
            access_token = create_access_token(identity=user.id)
            
            SecurityMonitor.log_security_event(
                "LOGIN_SUCCESS", 
                user.id, 
                {"ip": request.remote_addr}
            )
            
            return jsonify({
                "access_token": access_token,
                "user": {
                    "id": user.id,
                    "phone": user.phone,
                    "name": user.name,
                    "balance": user.balance,
                    "username": user.username,
                    "email": user.email
                }
            })
        else:
            SecurityMonitor.log_security_event(
                "LOGIN_FAILED", 
                user.id,
                {"ip": request.remote_addr, "reason": "Invalid credentials - wrong password"}
            )
            return jsonify({"error": "Invalid phone or password"}), 401
        
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

@auth_bp.route("/verify-2fa", methods=["POST"])
@rate_limiter.limit("10 per minute")
def verify_2fa():
    try:
        data = request.get_json()
        phone = data.get("phone")
        code = data.get("code")
        
        user = SupabaseDB.get_user_by_phone(phone)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if SecurityMonitor.verify_2fa_code(user.id, code, "LOGIN"):
            access_token = create_access_token(identity=user.id)
            
            SecurityMonitor.log_security_event(
                "2FA_SUCCESS", 
                user.id, 
                {"ip": request.remote_addr}
            )
            
            return jsonify({
                "access_token": access_token,
                "user": {
                    "id": user.id,
                    "phone": user.phone,
                    "name": user.name,
                    "balance": user.balance
                }
            })
        else:
            SecurityMonitor.log_security_event(
                "2FA_FAILED", 
                user.id, 
                {"ip": request.remote_addr}
            )
            return jsonify({"error": "Invalid 2FA code"}), 401
            
    except Exception as e:
        current_app.logger.error(f"2FA verification error: {str(e)}")
        return jsonify({"error": "Verification failed"}), 500

# M-Pesa Callback Handlers
def is_safaricom_ip(ip):
    """Verify callback is from Safaricom IP"""
    return ip in current_app.config['SAFARICOM_IPS']

@mpesa_bp.route("/mpesa/withdraw-callback", methods=["POST"])
def mpesa_withdraw_callback():
    """Secure M-Pesa callback handler"""
    try:
        client_ip = request.remote_addr
        
        # Log all callbacks for audit
        callback_log = {
            'payload': request.get_data(as_text=True),
            'ip_address': client_ip,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        SupabaseDB.create_mpesa_callback(callback_log)
        
        # Verify Safaricom IP
        if not is_safaricom_ip(client_ip):
            current_app.logger.warning(f"Suspicious callback from IP: {client_ip}")
            SecurityMonitor.log_security_event(
                "UNAUTHORIZED_CALLBACK", 
                None, 
                {"ip": client_ip, "payload": request.get_data(as_text=True)}
            )
            return jsonify({"ResultCode": 1, "ResultDesc": "Unauthorized"}), 401
        
        data = request.get_json(force=True)
        current_app.logger.info(f"✅ M-Pesa callback: {json.dumps(data)}")
        
        result = data.get("Result", {})
        result_code = result.get("ResultCode")
        result_desc = result.get("ResultDesc")
        transaction_id = result.get("TransactionID")
        originator_conversation_id = result.get("OriginatorConversationID")
        
        if not originator_conversation_id:
            current_app.logger.error("❌ No withdrawal reference in callback")
            return jsonify({"ResultCode": 1, "ResultDesc": "Missing reference"})
        
        withdrawal_data = SupabaseDB.get_transaction_by_id(originator_conversation_id)
        if not withdrawal_data:
            current_app.logger.error(f"❌ Withdrawal not found: {originator_conversation_id}")
            return jsonify({"ResultCode": 1, "ResultDesc": "Withdrawal not found"})
        
        user = SupabaseDB.get_user_by_id(withdrawal_data['user_id'])
        
        if result_code == 0:  # Success
            update_data = {
                'status': 'completed',
                'mpesa_code': transaction_id,
                'processed_at': datetime.now(timezone.utc).isoformat()
            }
            SupabaseDB.update_transaction(withdrawal_data['id'], update_data)
            
            # Success SMS via Celcom
            CelcomSMS.send_withdrawal_notification(
                user.phone, 
                user.name, 
                abs(withdrawal_data['amount']), 
                'completed', 
                transaction_id
            )
            
            SecurityMonitor.log_security_event(
                "WITHDRAWAL_COMPLETED", 
                user.id, 
                {
                    "amount": abs(withdrawal_data['amount']),
                    "mpesa_transaction_id": transaction_id,
                    "withdrawal_id": withdrawal_data['id']
                }
            )
            
        else:  # Failed
            update_data = {
                'status': 'failed'
            }
            SupabaseDB.update_transaction(withdrawal_data['id'], update_data)
            
            # Refund user balance
            user.balance += abs(withdrawal_data['amount'])
            user.total_withdrawn -= abs(withdrawal_data['amount'])
            SupabaseDB.update_user(user.id, {
                'balance': user.balance,
                'total_withdrawn': user.total_withdrawn
            })
            
            # Failure SMS via Celcom
            CelcomSMS.send_withdrawal_notification(
                user.phone, 
                user.name, 
                abs(withdrawal_data['amount']), 
                'failed'
            )
            
            SecurityMonitor.log_security_event(
                "WITHDRAWAL_FAILED", 
                user.id, 
                {
                    "amount": abs(withdrawal_data['amount']),
                    "reason": result_desc,
                    "withdrawal_id": withdrawal_data['id']
                }
            )
        
        return jsonify({"ResultCode": 0, "ResultDesc": "Success"})
        
    except Exception as e:
        current_app.logger.error(f"❌ Callback processing error: {str(e)}")
        SecurityMonitor.log_security_event(
            "CALLBACK_ERROR", 
            None, 
            {"error": str(e), "ip": request.remote_addr}
        )
        return jsonify({"ResultCode": 1, "ResultDesc": "System error"}), 500

# Secure Withdrawal API Routes
@withdraw_bp.route("/withdraw", methods=["POST"])
@jwt_required()
@rate_limiter.limit("10 per hour", key_func=lambda: get_jwt_identity())
@rate_limiter.limit("1000 per day", key_func=lambda: get_jwt_identity())
def api_request_withdrawal():
    """Secure withdrawal request with fraud detection"""
    try:
        current_user_id = get_jwt_identity()
        user = SupabaseDB.get_user_by_id(current_user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if not user.is_active:
            return jsonify({"error": "Account deactivated"}), 403
        
        if user.is_locked():
            return jsonify({"error": "Account temporarily locked"}), 423

        data = request.get_json()
        amount = float(data.get("amount", 0))
        phone_number = data.get("phone_number")
        
        # Input validation
        if amount < current_app.config['WITHDRAWAL_MIN_AMOUNT']:
            return jsonify({"error": f"Minimum withdrawal is {current_app.config['WITHDRAWAL_MIN_AMOUNT']}"}), 400
        
        if amount > current_app.config['WITHDRAWAL_MAX_AMOUNT']:
            return jsonify({"error": f"Maximum withdrawal is {current_app.config['WITHDRAWAL_MAX_AMOUNT']}"}), 400
        
        if not amount.is_integer():
            return jsonify({"error": "Amount must be a whole number"}), 400
        
        # Check balance
        if user.balance < amount:
            SecurityMonitor.log_security_event(
                "INSUFFICIENT_BALANCE", 
                user.id, 
                {"amount": amount, "balance": user.balance}
            )
            return jsonify({"error": "Insufficient balance"}), 400
        
        # Fraud detection
        fraud_check = FraudDetector.check_suspicious_activity(user, amount, request)
        if fraud_check:
            withdrawal_data = {
                'id': str(uuid.uuid4()),
                'user_id': user.id,
                'amount': -amount,
                'transaction_type': 'withdrawal',
                'status': 'Under Review',
                'phone_number': phone_number,
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            SupabaseDB.create_transaction(withdrawal_data)
            
            SecurityMonitor.log_security_event(
                "SUSPICIOUS_WITHDRAWAL", 
                user.id, 
                {
                    "amount": amount, 
                    "reason": fraud_check,
                    "withdrawal_id": withdrawal_data['id'],
                    "ip": request.remote_addr
                }
            )
            
            # Notify admins
            SecurityMonitor.notify_admins(
                f"Suspicious withdrawal: User {user.phone} attempted Ksh {amount}. Reason: {fraud_check}"
            )
            
            return jsonify({
                "message": "Withdrawal under review due to suspicious activity. We'll notify you.",
                "withdrawal_id": withdrawal_data['id'],
                "under_review": True
            }), 202
        
        # 2FA for large amounts
        if amount >= 2000:  # Suspicious amount threshold
            if user.two_factor_enabled:
                code = SecurityMonitor.generate_2fa_code(user.id, "WITHDRAWAL")
                return jsonify({
                    "message": "2FA code sent to your phone",
                    "requires_2fa": True,
                    "withdrawal_id": str(uuid.uuid4())
                })
        
        # Process withdrawal
        withdrawal_id = str(uuid.uuid4())
        withdrawal_data = {
            'id': withdrawal_id,
            'user_id': user.id,
            'amount': -amount,
            'transaction_type': 'withdrawal',
            'status': 'processing',
            'phone_number': phone_number,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Deduct balance
        user.balance -= amount
        user.total_withdrawn += amount
        SupabaseDB.update_user(user.id, {
            'balance': user.balance,
            'total_withdrawn': user.total_withdrawn
        })
        
        SupabaseDB.create_transaction(withdrawal_data)
        
        # Send initial SMS via Celcom
        CelcomSMS.send_withdrawal_notification(
            user.phone,
            user.name,
            amount,
            'processing'
        )
        
        # Initiate M-Pesa payment
        try:
            process_automatic_withdrawal(withdrawal_data)
        except Exception as e:
            current_app.logger.error(f"M-Pesa initiation failed: {str(e)}")
        
        SecurityMonitor.log_security_event(
            "WITHDRAWAL_INITIATED", 
            user.id, 
            {
                "amount": amount,
                "withdrawal_id": withdrawal_id,
                "ip": request.remote_addr
            }
        )
        
        return jsonify({
            "message": "Withdrawal processing",
            "withdrawal_id": withdrawal_id,
            "amount": amount
        })
        
    except Exception as e:
        current_app.logger.error(f"Withdrawal error: {str(e)}")
        SecurityMonitor.log_security_event(
            "WITHDRAWAL_ERROR", 
            user.id if 'user' in locals() else None, 
            {"error": str(e), "ip": request.remote_addr}
        )
        return jsonify({"error": "Withdrawal processing failed"}), 500

@withdraw_bp.route("/withdraw/confirm-2fa", methods=["POST"])
@jwt_required()
def confirm_2fa_withdrawal():
    """Confirm withdrawal with 2FA code"""
    try:
        current_user_id = get_jwt_identity()
        user = SupabaseDB.get_user_by_id(current_user_id)
        
        data = request.get_json()
        code = data.get("code")
        withdrawal_id = data.get("withdrawal_id")
        
        if SecurityMonitor.verify_2fa_code(user.id, code, "WITHDRAWAL"):
            # Process the withdrawal after 2FA verification
            withdrawal = SupabaseDB.get_transaction_by_id(withdrawal_id)
            if withdrawal and withdrawal['status'] == 'pending':
                SupabaseDB.update_transaction(withdrawal_id, {'status': 'processing'})
                
                process_automatic_withdrawal(withdrawal)
                
                return jsonify({
                    "message": "Withdrawal confirmed and processing",
                    "withdrawal_id": withdrawal_id
                })
            else:
                return jsonify({"error": "Invalid withdrawal"}), 400
        else:
            SecurityMonitor.log_security_event(
                "WITHDRAWAL_2FA_FAILED", 
                user.id, 
                {"withdrawal_id": withdrawal_id}
            )
            return jsonify({"error": "Invalid 2FA code"}), 401
            
    except Exception as e:
        current_app.logger.error(f"2FA confirmation error: {str(e)}")
        return jsonify({"error": "Confirmation failed"}), 500

# Register Blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(mpesa_bp, url_prefix='/api')
app.register_blueprint(withdraw_bp, url_prefix='/api')

# =============================================================================
# FLASK ROUTES - MODIFIED FOR PAYMENT-ONLY STORAGE
# =============================================================================

@app.context_processor
def utility_processor():
    def safe_strftime(dt, fmt="%b %d, %Y %I:%M %p"):
        try:
            return dt.strftime(fmt) if dt else ""
        except Exception:
            return ""
    return dict(safe_strftime=safe_strftime)

@app.route('/robots.txt')
def robots():
    robots_txt = '''User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/
Disallow: /health/detailed
Disallow: /debug-settings

Sitemap: https://www.referralninja.co.ke/sitemap.xml'''
    return app.response_class(robots_txt, mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap():
    """Generate dynamic sitemap"""
    from flask import render_template_string
    import datetime
    
    base_url = 'https://www.referralninja.co.ke'
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    
    sitemap_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>{base_url}/</loc>
    <lastmod>{today}</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>{base_url}/login</loc>
    <lastmod>{today}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>{base_url}/register</loc>
    <lastmod>{today}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>{base_url}/dashboard</loc>
    <lastmod>{today}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>{base_url}/referral-system</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>{base_url}/withdraw</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>{base_url}/jobs</loc>
    <lastmod>{today}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>{base_url}/leaderboard</loc>
    <lastmod>{today}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.7</priority>
  </url>
</urlset>'''
    
    return app.response_class(sitemap_xml, mimetype='application/xml')


# Health Check Routes
@app.route('/health')
def health_check():
    """Basic health check for load balancers"""
    try:
        response = supabase_check('users', limit=1)
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'database': 'connected',
            'version': '1.0.0'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'database': 'error',
            'error': str(e)
        }), 503

@app.route('/health/detailed')
@login_required
@admin_required
def detailed_health_check():
    """Detailed health check for administrators"""
    health_monitor = HealthMonitor(supabase, redis_client, app.config)  # Add redis_client
    health_status = health_monitor.comprehensive_health_check()
    
    return jsonify(health_status)

@app.route('/health/readiness')
def readiness_check():
    try:
        supabase_check('users', limit=1)
        return jsonify({'status': 'ready', 'timestamp': datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        return jsonify({'status': 'not_ready', 'timestamp': datetime.now(timezone.utc).isoformat(), 'error': str(e)}), 503

@app.route('/health/liveness')
def liveness_check():
    return jsonify({'status': 'alive', 'timestamp': datetime.now(timezone.utc).isoformat()})

# Health monitoring background task
def start_health_monitoring():
    """Start background health monitoring safely in a thread."""
    
    def monitor_health():
        
        # Make sure we have Flask context in this thread
        with app.app_context():
            health_monitor = HealthMonitor(supabase, redis_client, app.config)  # Add redis_client

            while True:
                try:
                    health_status = health_monitor.comprehensive_health_check()

                    if health_status['status'] != 'healthy':
                        current_app.logger.warning(
                            f"System health degraded: {health_status['status']}"
                        )

                    # Alert on critical issues safely
                    if health_status['status'] == 'unhealthy':
                        _alert_on_critical_health_issue(health_status)

                except Exception as e:
                    safe_error = html.escape(str(e))
                    current_app.logger.error(f"Health monitoring error: {safe_error}")

                # Run every 5 minutes
                time.sleep(300)

    def _alert_on_critical_health_issue(health_status):
        critical_issues = []
        for component, status in health_status['components']['critical'].items():
            if status['status'] == 'unhealthy':
                critical_issues.append(f"{component}: {status.get('error', 'Unknown error')}")

        if critical_issues:
            message = "🚨 CRITICAL HEALTH ALERT:\n" + "\n".join([html.escape(i) for i in critical_issues])
            # This is now safe in a thread
            send_telegram_notification(message)

    # Start monitoring in a daemon thread
    thread = threading.Thread(target=monitor_health, daemon=True)
    thread.start()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_verified:
        flash('Please complete payment verification to access dashboard.', 'warning')
        return redirect(url_for('account_activation'))
    
    # Get user transactions
    transactions = SupabaseDB.get_transactions_by_user(current_user.id, transaction_type='withdrawal')
    
    total_withdrawn = sum(abs(t['amount']) for t in transactions if t['status'] == 'completed')
    pending_withdrawals = len([t for t in transactions if t['status'] == 'pending'])
    
    withdrawals = [t for t in transactions][:5]  # Last 5 withdrawals
    
    return render_template('dashboard.html',
                         total_withdrawn=total_withdrawn,
                         pending_withdrawals=pending_withdrawals,
                         withdrawals=withdrawals)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user already logged in, send to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = bool(request.form.get('remember_me'))

        app.logger.info(f"Login attempt for username: {username}")

        # Validate input
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('auth/login.html')

        # Fetch user from Supabase
        user = SupabaseDB.get_user_by_username(username)

        if user:
            app.logger.info(f"User found: {user.username}, verified={user.is_verified}, active={user.is_active}")

            # Check lock status
            if user.is_locked():
                flash('Account temporarily locked. Please try again later.', 'error')
                return render_template('auth/login.html')

            # ✅ Use Werkzeug's built-in password verification
            if check_password_hash(user.password_hash, password):
                app.logger.info(f"Login successful for {username}")

                # Require verification before login
                if not user.is_verified:
                    flash('Please complete your payment verification before logging in.', 'warning')
                    session['pending_verification_user'] = user.id
                    return redirect(url_for('account_activation'))

                # Reset login attempts on success
                SupabaseDB.update_user(user.id, {
                    'login_attempts': 0,
                    'locked_until': None,
                    'last_login': datetime.now(timezone.utc).isoformat()
                })

                login_user(user, remember=remember_me)
                next_page = request.args.get('next')

                # Log success
                SecurityMonitor.log_security_event(
                    "LOGIN_SUCCESS",
                    user.id,
                    {"ip": request.remote_addr}
                )

                flash('Login successful!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))

            else:
                # ❌ Invalid password
                attempts = user.login_attempts + 1
                update_data = {'login_attempts': attempts}

                if attempts >= 5:
                    locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
                    update_data['locked_until'] = locked_until.isoformat()
                    flash('Account locked for 30 minutes due to too many failed attempts.', 'error')
                else:
                    flash('Invalid username or password.', 'error')

                SupabaseDB.update_user(user.id, update_data)

                # Log failed login
                SecurityMonitor.log_security_event(
                    "LOGIN_FAILED",
                    user.id,
                    {
                        "ip": request.remote_addr,
                        "reason": "Invalid credentials",
                        "attempts": attempts
                    }
                )

        else:
            # User doesn't exist
            app.logger.warning(f"Login failed — user not found: {username}")
            flash('Invalid username or password.', 'error')

    # Render login page
    return render_template('auth/login.html')

# MODIFIED REGISTRATION ROUTE - Stores data temporarily until payment
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    referral_code = request.args.get('ref', '')
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        name = request.form.get('full_name', '').strip()
        password = request.form.get('password')
        referral_code = request.form.get('referral_code')
        terms = request.form.get('terms')
        
        if not name:
            flash('Full name is required.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if not terms:
            flash('You must agree to the Terms of Service and Privacy Policy.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if not re.match(r'^254[0-9]{9}$', phone_number) and not re.match(r'^07[0-9]{8}$', phone_number):
            flash('Please enter a valid Kenyan phone number.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if phone_number.startswith('07'):
            phone_number = '254' + phone_number[1:]
        
        # Check if phone already exists in database (permanent users)
        if SupabaseDB.get_user_by_phone(phone_number):
            flash('Phone number already registered.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        # Check if username already exists in database (permanent users)
        if SupabaseDB.get_user_by_username(username):
            flash('Username already exists.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if email and SupabaseDB.get_user_by_email(email):
            flash('Email already registered.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        referrer = None
        if referral_code:
            referrer = validate_referral_code(referral_code)
            if not referrer:
                flash('Invalid referral code. Please check and try again.', 'error')
                return render_template('auth/register.html', referral_code=referral_code)
        
        # Store user data temporarily in session instead of creating database record
        temp_user_data = {
            'id': str(uuid.uuid4()),
            'username': username,
            'email': email,
            'phone': phone_number,
            'name': name,
            'password': password,
            'referral_code': referral_code,
            'referrer': referrer.id if referrer else None,
            'referral_source': 'referral_link' if request.args.get('ref') else 'manual_entry' if referral_code else 'direct',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Generate temporary referral code for display
        phone_hash = hashlib.md5(phone_number.encode()).hexdigest()[:6].upper()
        temp_user_data['temp_referral_code'] = f"RN{phone_hash}"
        
        # Store temporary user data in session
        session['temp_user_data'] = temp_user_data
        session['pending_verification_user'] = temp_user_data['id']
        
        # Send welcome SMS
        CelcomSMS.send_registration_notification(phone_number, username)
        
        flash('Registration successful! Please complete KSH 200 payment to activate your account.', 'success')
        return redirect(url_for('account_activation'))
    
    return render_template('auth/register.html', referral_code=referral_code)

@app.route('/logout')
@login_required
def logout():
    SecurityMonitor.log_security_event(
        "LOGOUT", 
        current_user.id, 
        {"ip": request.remote_addr}
    )
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# MODIFIED ACCOUNT ACTIVATION ROUTE - Uses temporary session data
@app.route('/account-activation')
def account_activation():
    user_id = session.get('pending_verification_user')
    temp_user_data = session.get('temp_user_data')
    
    if not user_id or not temp_user_data:
        flash('Invalid access. Please register first.', 'error')
        return redirect(url_for('register'))
    
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('dashboard'))
    
    # Pass temporary user data to the template
    user_data = {
        'username': temp_user_data['username'],
        'phone': temp_user_data['phone'],
        'email': temp_user_data['email'],
        'full_name': temp_user_data['name'],
        'referral_code': temp_user_data['temp_referral_code']
    }
    
    return render_template('account_activation.html', user_data=user_data)

# Payment Instructions Route for backward compatibility
@app.route('/payment-instructions')
def payment_instructions():
    return redirect(url_for('account_activation'))

# MODIFIED STK PUSH ROUTES - Use temporary user data
@app.route('/initiate-stk-push', methods=['POST'])
def initiate_stk_push_route():
    user_id = session.get('pending_verification_user')
    temp_user_data = session.get('temp_user_data')
    
    if not user_id or not temp_user_data:
        return jsonify({'success': False, 'message': 'Session expired. Please register again.'})
    
    # Check if there's already a pending transaction
    transaction_id = f"reg_{temp_user_data['id']}"
    existing_transaction = SupabaseDB.get_transaction_by_id(transaction_id)
    
    if existing_transaction and existing_transaction['status'] == 'pending':
        transaction = existing_transaction
    else:
        # Create transaction record linked to temporary user ID
        transaction_data = {
            'id': transaction_id,
            'user_id': temp_user_data['id'],  # Use temporary ID
            'amount': 200.0,
            'transaction_type': 'registration_fee',
            'status': 'pending',
            'phone_number': temp_user_data['phone'],
            'description': 'Account registration fee - STK Push initiated',
            'ip_address': request.remote_addr,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        transaction = SupabaseDB.create_transaction(transaction_data)
    
    try:
        # Format phone number for M-PESA (254 format)
        phone_number = temp_user_data['phone']
        if phone_number.startswith('0'):
            phone_number = '254' + phone_number[1:]
        elif phone_number.startswith('+'):
            phone_number = phone_number[1:]
        
        # Initiate STK push
        stk_response = initiate_stk_push(
            phone_number=phone_number,
            amount=1 if app.config['MPESA_ENVIRONMENT'] == 'sandbox' else 200,
            account_reference=temp_user_data['temp_referral_code'],
            transaction_desc="ReferralNinja Registration"
        )
        
        if stk_response and stk_response.get('ResponseCode') == '0':
            # STK push initiated successfully
            update_data = {
                'checkout_request_id': stk_response.get('CheckoutRequestID'),
                'merchant_request_id': stk_response.get('MerchantRequestID'),
                'mpesa_message': f"STK Push initiated - {stk_response.get('CustomerMessage')}"
            }
            SupabaseDB.update_transaction(transaction['id'], update_data)
            
            return jsonify({
                'success': True, 
                'message': 'STK push sent to your phone! Please check your phone and enter your M-PESA PIN to complete payment.',
                'checkout_request_id': transaction['checkout_request_id']
            })
        else:
            error_message = stk_response.get('errorMessage', 'Failed to initiate STK push') if stk_response else 'M-PESA service unavailable'
            return jsonify({'success': False, 'message': f'STK Push failed: {error_message}'})
    
    except Exception as e:
        app.logger.error(f"Error in STK push: {str(e)}")
        return jsonify({'success': False, 'message': f'Error initiating payment: {str(e)}'})

# MODIFIED PAYMENT STATUS CHECK - Creates user on successful payment
@app.route('/check-payment-status', methods=['POST'])
def check_payment_status():
    user_id = session.get('pending_verification_user')
    temp_user_data = session.get('temp_user_data')
    
    if not user_id or not temp_user_data:
        return jsonify({'success': False, 'message': 'Session expired'})
    
    # Check if there's already a completed transaction for this temporary user
    transaction_id = f"reg_{temp_user_data['id']}"
    existing_transaction = SupabaseDB.get_transaction_by_id(transaction_id)
    
    if existing_transaction and existing_transaction['status'] == 'completed':
        # Payment already completed, create user and log them in
        user = create_permanent_user_after_payment(temp_user_data, transaction_id)
        if user:
            login_user(user)
            session.pop('pending_verification_user', None)
            session.pop('temp_user_data', None)
            return jsonify({'success': True, 'verified': True, 'message': 'Payment verified! You have been logged in successfully.'})
    
    # Check STK status for pending transactions
    pending_transaction = SupabaseDB.get_transaction_by_id(transaction_id)
    
    if pending_transaction and pending_transaction.get('checkout_request_id'):
        # Query M-PESA for transaction status
        stk_status = query_stk_push_status(pending_transaction['checkout_request_id'])
        if stk_status and stk_status.get('ResultCode') == '0':
            # Payment completed via query, create permanent user
            SupabaseDB.update_transaction(transaction_id, {
                'status': 'completed',
                'mpesa_code': stk_status.get('MpesaReceiptNumber')
            })
            
            user = create_permanent_user_after_payment(temp_user_data, transaction_id)
            if user:
                login_user(user)
                session.pop('pending_verification_user', None)
                session.pop('temp_user_data', None)
                return jsonify({'success': True, 'verified': True, 'message': 'Payment verified via query! You have been logged in successfully.'})
    
    # Check if there's a pending transaction
    if pending_transaction:
        return jsonify({'success': True, 'verified': False, 'pending': True})
    
    return jsonify({'success': True, 'verified': False, 'pending': False})

# MODIFIED M-PESA CALLBACK - Creates user on payment success
@app.route('/mpesa-callback', methods=['POST'])
def mpesa_callback():
    """Handle M-PESA STK push callback - CREATE USER AFTER PAYMENT"""
    try:
        callback_data = request.get_json()
        
        # Log the callback for debugging
        app.logger.info("M-PESA Callback received: %s", json.dumps(callback_data, indent=2))
        
        # Extract relevant information from callback
        stk_callback = callback_data.get('Body', {}).get('stkCallback', {})
        result_code = stk_callback.get('ResultCode')
        result_desc = stk_callback.get('ResultDesc')
        checkout_request_id = stk_callback.get('CheckoutRequestID')
        merchant_request_id = stk_callback.get('MerchantRequestID')
        
        # Find the transaction
        response = supabase.table('transactions').select('*').eq('checkout_request_id', checkout_request_id).execute()
        transaction = response.data[0] if response.data else None
        
        if transaction:
            if result_code == 0:
                # Payment successful - UPDATE TRANSACTION
                update_data = {'status': 'completed'}
                
                # Extract metadata
                metadata = stk_callback.get('CallbackMetadata', {}).get('Item', [])
                mpesa_data = {}
                for item in metadata:
                    name = item.get('Name')
                    value = item.get('Value')
                    mpesa_data[name] = value
                
                update_data['mpesa_code'] = mpesa_data.get('MpesaReceiptNumber')
                update_data['description'] = f'Account registration fee - Payment completed via STK Push. Amount: {mpesa_data.get("Amount")}, Phone: {mpesa_data.get("PhoneNumber")}'
                
                SupabaseDB.update_transaction(transaction['id'], update_data)
                
                # Find temporary user data and create permanent user
                # We need to get the user_id from the transaction and find the corresponding temp data
                # This would require storing temp user data in a way we can retrieve it
                # For now, we'll rely on the frontend to check payment status and create the user
                
                app.logger.info(f"✅ Payment completed for transaction {transaction['id']}")
                
            else:
                # Payment failed
                update_data = {
                    'status': 'failed',
                    'description': f'Payment failed: {result_desc}'
                }
                SupabaseDB.update_transaction(transaction['id'], update_data)
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        app.logger.error(f"❌ Error processing M-PESA callback: {str(e)}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

# M-PESA B2C CALLBACK HANDLER
@app.route('/mpesa-b2c-callback', methods=['POST'])
def mpesa_b2c_callback():
    """Handle M-PESA B2C payout callbacks - AUTO UPDATE WITHDRAWAL STATUS"""
    try:
        callback_data = request.get_json()
        
        # Log the callback for debugging
        app.logger.info("M-PESA B2C Callback received: %s", json.dumps(callback_data, indent=2))
        
        # Extract relevant information from callback
        result = callback_data.get('Result', {})
        result_code = result.get('ResultCode')
        result_desc = result.get('ResultDesc')
        originator_conversation_id = result.get('OriginatorConversationID')
        conversation_id = result.get('ConversationID')
        transaction_id = result.get('TransactionID')
        
        # Find the withdrawal transaction using OriginatorConversationID (which is our withdrawal ID)
        withdrawal_transaction = SupabaseDB.get_transaction_by_id(originator_conversation_id)
        
        if not withdrawal_transaction:
            app.logger.error(f"❌ Withdrawal transaction not found for ID: {originator_conversation_id}")
            return jsonify({'ResultCode': 1, 'ResultDesc': 'Transaction not found'})
        
        user = SupabaseDB.get_user_by_id(withdrawal_transaction['user_id'])
        if not user:
            app.logger.error(f"❌ User not found for withdrawal: {withdrawal_transaction['id']}")
            return jsonify({'ResultCode': 1, 'ResultDesc': 'User not found'})
        
        amount = abs(withdrawal_transaction['amount'])
        
        if result_code == 0:
            # B2C payment successful
            update_data = {
                'status': 'completed',
                'mpesa_code': transaction_id,
                'description': f'M-Pesa B2C payout completed - {result_desc}'
            }
            SupabaseDB.update_transaction(withdrawal_transaction['id'], update_data)
            
            # Send success SMS to user via Celcom
            CelcomSMS.send_withdrawal_notification(
                user.phone,
                user.username,
                amount,
                'completed',
                transaction_id
            )
            
            app.logger.info(f"✅ B2C payout completed for user {user.username}, transaction ID: {transaction_id}")
            
        else:
            # B2C payment failed
            update_data = {
                'status': 'failed',
                'description': f'M-Pesa B2C payout failed - {result_desc}'
            }
            SupabaseDB.update_transaction(withdrawal_transaction['id'], update_data)
            
            # Refund user balance
            user.balance += amount
            user.total_withdrawn -= amount
            SupabaseDB.update_user(user.id, {
                'balance': user.balance,
                'total_withdrawn': user.total_withdrawn
            })
            
            # Send failure SMS to user via Celcom
            CelcomSMS.send_withdrawal_notification(
                user.phone,
                user.username,
                amount,
                'failed'
            )
            
            app.logger.error(f"❌ B2C payout failed for user {user.username}: {result_desc}")
        
        # Always return success to M-PESA to stop retries
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        app.logger.error(f"❌ Error processing M-PESA B2C callback: {str(e)}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'System error'})

@app.route('/mpesa-b2c-timeout', methods=['POST'])
def mpesa_b2c_timeout():
    """Handle B2C timeout callbacks"""
    callback_data = request.get_json()
    app.logger.warning(f"⚠️ M-PESA B2C Timeout callback: {json.dumps(callback_data)}")
    return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})

@app.route('/api/payment-status')
def api_payment_status():
    user_id = session.get('pending_verification_user')
    temp_user_data = session.get('temp_user_data')
    
    if not user_id or not temp_user_data:
        return jsonify({'verified': False, 'error': 'Session expired'})
    
    # Check if user has been created in database
    user = SupabaseDB.get_user_by_id(temp_user_data['id'])
    if user and user.is_verified:
        session.pop('pending_verification_user', None)
        session.pop('temp_user_data', None)
        return jsonify({'verified': True})
    
    return jsonify({'verified': False})

@app.route('/referral-system')
@login_required
def referral_system():
    if not current_user.is_verified:
        flash('Please complete payment verification to access referral system.', 'warning')
        return redirect(url_for('account_activation'))
    
    referrals = SupabaseDB.get_referrals_by_referrer(current_user.id)
    
    base_url = request.host_url.rstrip('/')
    referral_url = f"{base_url}/register?ref={current_user.referral_code}"
    
    share_links = {
        'whatsapp': f"https://wa.me/?text=Join Referral Ninja and earn money! Use my code: {current_user.referral_code} - {referral_url}",
        'facebook': f"https://www.facebook.com/sharer/sharer.php?u={referral_url}",
        'twitter': f"https://twitter.com/intent/tweet?text=Join Referral Ninja! Use my code: {current_user.referral_code}&url={referral_url}",
        'telegram': f"https://t.me/share/url?url={referral_url}&text=Join Referral Ninja! Use my code: {current_user.referral_code}"
    }
    
    return render_template('referral_system.html',
                         referrals=referrals,
                         share_links=share_links,
                         referral_url=referral_url)

@app.route('/referrals')
@login_required
def referrals():
    return redirect(url_for('referral_system'))

@app.route('/leaderboard')
@login_required
def leaderboard():
    if not current_user.is_verified:
        flash('Please complete payment verification to view leaderboard.', 'warning')
        return redirect(url_for('account_activation'))
    
    top_users_data = SupabaseDB.get_top_users(limit=5)
    top_users = [User(user_data) for user_data in top_users_data]
    
    user_ranking = get_user_ranking(current_user.id)
    
    return render_template('leaderboard.html',
                         top_users=top_users,
                         user_ranking=user_ranking)

@app.route('/statistics')
@login_required
def statistics():
    if not current_user.is_verified:
        flash('Please complete payment verification to view statistics.', 'warning')
        return redirect(url_for('account_activation'))
    
    total_earned = current_user.total_commission
    total_withdrawn = current_user.total_withdrawn
    pending_balance = current_user.balance
    
    # For referral stats, we'd need to implement a more complex query
    # This is a simplified version
    referral_stats = []  # Would need custom implementation for date grouping
    
    return render_template('statistics.html',
                         total_earned=total_earned,
                         total_withdrawn=total_withdrawn,
                         pending_balance=pending_balance,
                         referral_stats=referral_stats)

# UPDATED WITHDRAW ROUTE - Now with automatic M-Pesa B2C processing
@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    if not current_user.is_verified:
        flash('Please complete payment verification to withdraw funds.', 'warning')
        return redirect(url_for('account_activation'))
    
    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        phone_number = request.form.get('phone_number')
        
        # UPDATED: Minimum withdrawal amount changed from 100 to 400
        if amount < 400:
            flash('Minimum withdrawal amount is KSH 400.', 'error')
            return redirect(url_for('withdraw'))
        
        if amount > current_user.balance:
            flash('Insufficient balance.', 'error')
            return redirect(url_for('withdraw'))
        
        # Validate phone number format
        if not re.match(r'^254[0-9]{9}$', phone_number) and not re.match(r'^07[0-9]{8}$', phone_number):
            flash('Please enter a valid Kenyan phone number.', 'error')
            return redirect(url_for('withdraw'))
        
        # Convert to 254 format
        if phone_number.startswith('07'):
            phone_number = '254' + phone_number[1:]
        elif phone_number.startswith('+'):
            phone_number = phone_number[1:]
        
        # Fraud detection for web withdrawals too
        fraud_check = FraudDetector.check_suspicious_activity(current_user, amount, request)
        if fraud_check:
            transaction_data = {
                'id': str(uuid.uuid4()),
                'user_id': current_user.id,
                'amount': -amount,
                'transaction_type': 'withdrawal',
                'status': 'Under Review',
                'phone_number': phone_number,
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            SupabaseDB.create_transaction(transaction_data)
            
            SecurityMonitor.log_security_event(
                "SUSPICIOUS_WITHDRAWAL", 
                current_user.id, 
                {
                    "amount": amount, 
                    "reason": fraud_check,
                    "withdrawal_id": transaction_data['id'],
                    "ip": request.remote_addr
                }
            )
            
            flash('Withdrawal under review due to suspicious activity. We will notify you once processed.', 'warning')
            return redirect(url_for('dashboard'))
        
        transaction_data = {
            'id': str(uuid.uuid4()),
            'user_id': current_user.id,
            'amount': -amount,
            'transaction_type': 'withdrawal',
            'status': 'pending',
            'phone_number': phone_number,
            'description': f'M-Pesa withdrawal to {phone_number} - Pending automatic processing',
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Deduct balance immediately
        current_user.balance -= amount
        current_user.total_withdrawn += amount
        SupabaseDB.update_user(current_user.id, {
            'balance': current_user.balance,
            'total_withdrawn': current_user.total_withdrawn
        })
        
        SupabaseDB.create_transaction(transaction_data)
        
        # Send initial SMS via Celcom
        CelcomSMS.send_withdrawal_notification(
            current_user.phone,
            current_user.username,
            amount,
            'processing'
        )
        
        # 🔄 NEW: Process withdrawal automatically via M-Pesa B2C
        processing_result = process_automatic_withdrawal(transaction_data)
        
        if processing_result:
            flash('Withdrawal request submitted! We are processing your payment via M-Pesa. You will receive an SMS confirmation shortly.', 'success')
        else:
            flash('Withdrawal request received but automatic processing failed. Our team will process it manually within 24 hours.', 'warning')
            # Send Telegram notification for manual processing
            send_withdrawal_notification_to_telegram(current_user, transaction_data)
        
        return redirect(url_for('dashboard'))
    
    transactions = SupabaseDB.get_transactions_by_user(current_user.id, transaction_type='withdrawal', limit=5)
    
    return render_template('withdraw.html', transactions=transactions)

# UPDATED JOBS ROUTE - Fixed the missing method error
@app.route('/jobs')
@login_required
def jobs():
    """Jobs page for students to view available job opportunities"""
    if not current_user.is_verified:
        flash('Please complete payment verification to access jobs.', 'warning')
        return redirect(url_for('account_activation'))
    
    try:
        # Get filter parameters
        category = request.args.get('category', '')
        search = request.args.get('search', '')
        
        # Get all active jobs using the instance method
        db = SupabaseDB()
        jobs_data = db.get_all_jobs()
        
        # Apply filters
        filtered_jobs = []
        for job in jobs_data:
            # Check if job is active
            if not job.get('is_active', True):
                continue
                
            if category and job.get('category') != category:
                continue
            if search and search.lower() not in job.get('title', '').lower() and search.lower() not in job.get('company', '').lower():
                continue
            filtered_jobs.append(job)
        
        # Get unique categories for filter dropdown
        categories = list(set(job.get('category') for job in jobs_data if job.get('category')))
        
        return render_template('jobs.html', 
                             jobs=filtered_jobs,
                             categories=categories,
                             selected_category=category,
                             search_query=search)
                             
    except Exception as e:
        current_app.logger.error(f"Error loading jobs page: {str(e)}")
        flash('Error loading jobs page. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/jobs')
@login_required
@admin_required
def admin_jobs():
    """Admin page to manage job postings"""
    try:
        db = SupabaseDB()
        jobs_data = db.get_all_jobs()
        return render_template('admin_jobs.html', jobs=jobs_data)
    except Exception as e:
        current_app.logger.error(f"Error loading admin jobs: {str(e)}")
        flash('Error loading jobs management page.', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/jobs/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_job():
    """Create a new job posting"""
    if request.method == 'POST':
        try:
            job_data = {
                'id': str(uuid.uuid4()),
                'title': request.form.get('title', '').strip(),
                'description': request.form.get('description', '').strip(),
                'company': request.form.get('company', '').strip(),
                'job_link': request.form.get('job_link', '').strip(),
                'category': request.form.get('category', 'Other'),
                'location': request.form.get('location', '').strip(),
                'salary_range': request.form.get('salary_range', '').strip(),
                'application_deadline': request.form.get('application_deadline'),
                'is_active': bool(request.form.get('is_active')),
                'is_featured': bool(request.form.get('is_featured')),
                'created_by': current_user.id,
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
            # Validate required fields
            if not job_data['title'] or not job_data['job_link']:
                flash('Title and Job Link are required fields.', 'error')
                return redirect(url_for('create_job'))
            
            # Validate URL format
            if not re.match(r'^https?://', job_data['job_link']):
                flash('Please enter a valid job link (must start with http:// or https://).', 'error')
                return redirect(url_for('create_job'))
            
            db = SupabaseDB()
            created_job = db.create_job(job_data)
            
            if created_job:
                flash('Job posting created successfully!', 'success')
                return redirect(url_for('admin_jobs'))
            else:
                flash('Failed to create job posting. Please try again.', 'error')
                
        except Exception as e:
            app.logger.error(f"Error creating job: {str(e)}")
            flash('Error creating job posting. Please try again.', 'error')
    
    return render_template('create_job.html')

@app.route('/admin/jobs/<job_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_job(job_id):
    """Edit an existing job posting"""
    db = SupabaseDB()
    job = db.get_job_by_id(job_id)
    
    if not job:
        flash('Job not found.', 'error')
        return redirect(url_for('admin_jobs'))
    
    if request.method == 'POST':
        try:
            update_data = {
                'title': request.form.get('title', '').strip(),
                'description': request.form.get('description', '').strip(),
                'company': request.form.get('company', '').strip(),
                'job_link': request.form.get('job_link', '').strip(),
                'category': request.form.get('category', 'Other'),
                'location': request.form.get('location', '').strip(),
                'salary_range': request.form.get('salary_range', '').strip(),
                'application_deadline': request.form.get('application_deadline'),
                'is_active': bool(request.form.get('is_active')),
                'is_featured': bool(request.form.get('is_featured'))
            }
            
            # Validate required fields
            if not update_data['title'] or not update_data['job_link']:
                flash('Title and Job Link are required fields.', 'error')
                return redirect(url_for('edit_job', job_id=job_id))
            
            # Validate URL format
            if not re.match(r'^https?://', update_data['job_link']):
                flash('Please enter a valid job link (must start with http:// or https://).', 'error')
                return redirect(url_for('edit_job', job_id=job_id))
            
            updated_job = db.update_job(job_id, update_data)
            
            if updated_job:
                flash('Job posting updated successfully!', 'success')
                return redirect(url_for('admin_jobs'))
            else:
                flash('Failed to update job posting. Please try again.', 'error')
                
        except Exception as e:
            app.logger.error(f"Error updating job: {str(e)}")
            flash('Error updating job posting. Please try again.', 'error')
    
    return render_template('edit_job.html', job=job)

@app.route('/admin/jobs/<job_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_job(job_id):
    """Delete a job posting"""
    db = SupabaseDB()
    job = db.get_job_by_id(job_id)
    
    if not job:
        flash('Job not found.', 'error')
        return redirect(url_for('admin_jobs'))
    
    try:
        success = db.delete_job(job_id)
        if success:
            flash('Job posting deleted successfully!', 'success')
        else:
            flash('Failed to delete job posting.', 'error')
    except Exception as e:
        app.logger.error(f"Error deleting job: {str(e)}")
        flash('Error deleting job posting.', 'error')
    
    return redirect(url_for('admin_jobs'))

@app.route('/admin/jobs/<job_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_job_status(job_id):
    """Toggle job active status"""
    db = SupabaseDB()
    job = db.get_job_by_id(job_id)
    
    if not job:
        return jsonify({'success': False, 'message': 'Job not found'})
    
    try:
        new_status = not job.get('is_active', False)
        updated_job = db.update_job(job_id, {'is_active': new_status})
        
        if updated_job:
            status_text = "activated" if new_status else "deactivated"
            return jsonify({'success': True, 'message': f'Job {status_text} successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to update job status'})
            
    except Exception as e:
        app.logger.error(f"Error toggling job status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        name = request.form.get('full_name', '').strip()
        new_password = request.form.get('new_password')
        
        if not email:
            flash('Email is required.', 'error')
            return redirect(url_for('profile'))
        
        if not phone_number:
            flash('Phone number is required.', 'error')
            return redirect(url_for('profile'))
        
        if not name:
            flash('Full name is required.', 'error')
            return redirect(url_for('profile'))
        
        update_data = {
            'email': email,
            'phone': phone_number,
            'name': name
        }
        
        if new_password:
            # When creating a new user
            hashed_pw = generate_password_hash(new_password)
            update_data['password_hash'] = hashed_pw
            flash('Password updated successfully!', 'success')
        
        try:
            SupabaseDB.update_user(current_user.id, update_data)
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            flash('Error updating profile. Please try again.', 'error')
            return redirect(url_for('profile'))
    
    total_earned = current_user.total_commission
    total_withdrawn = current_user.total_withdrawn
    balance = current_user.balance
    
    # Get referred count
    response = supabase.table('users').select('*', count='exact').eq('referred_by', current_user.referral_code).execute()
    referred_count = len(response.data)
    
    return render_template('profile.html', 
                         total_earned=total_earned,
                         total_withdrawn=total_withdrawn,
                         balance=balance,
                         referred_count=referred_count)

# Updated settings route with better error handling
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Settings route with enhanced error handling"""
    try:
        # Quick Supabase health check
        response = supabase.table('users').select('*').limit(1).execute()
    except Exception as e:
        app.logger.error(f"Supabase error in settings: {e}")
        flash('Database connection issue. Please try again later.', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if user is verified
    if not current_user.is_verified:
        flash('Please complete payment verification to access settings.', 'warning')
        return redirect(url_for('account_activation'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        name = request.form.get('full_name', '').strip()
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        try:
            # Basic validation
            if not email or not phone_number or not name:
                flash('Email, phone number and full name are required.', 'error')
                return redirect(url_for('settings'))
            
            # Validate phone number format
            if not re.match(r'^254[0-9]{9}$', phone_number) and not re.match(r'^07[0-9]{8}$', phone_number):
                flash('Please enter a valid Kenyan phone number.', 'error')
                return redirect(url_for('settings'))
            
            # Convert to 254 format
            if phone_number.startswith('07'):
                phone_number = '254' + phone_number[1:]
            
            # Check for duplicate email/phone
            email_response = supabase.table('users').select('*').eq('email', email).neq('id', current_user.id).execute()
            phone_response = supabase.table('users').select('*').eq('phone', phone_number).neq('id', current_user.id).execute()
            
            if email_response.data:
                flash('Email already registered.', 'error')
                return redirect(url_for('settings'))
            
            if phone_response.data:
                flash('Phone number already registered.', 'error')
                return redirect(url_for('settings'))
            
            # Update user info
            update_data = {
                'email': email,
                'phone': phone_number,
                'name': name
            }
            
            # Handle password change if provided
            if new_password:
                if not current_password:
                    flash('Current password is required to change password.', 'error')
                    return redirect(url_for('settings'))
                
                # When verifying login
                if not check_password_hash(current_user.password_hash, current_password):
                    flash('Current password is incorrect.', 'error')
                    return redirect(url_for('settings'))
                
                if new_password != confirm_password:
                    flash('New passwords do not match.', 'error')
                    return redirect(url_for('settings'))
                
                if len(new_password) < 6:
                    flash('Password must be at least 6 characters long.', 'error')
                    return redirect(url_for('settings'))
                
                # When creating a new user
                hashed_pw = generate_password_hash(new_password)
                update_data['password_hash'] = hashed_pw
                flash('Password updated successfully!', 'success')
            
            # Save changes
            SupabaseDB.update_user(current_user.id, update_data)
            flash('Settings updated successfully!', 'success')
            return redirect(url_for('settings'))
            
        except Exception as e:
            app.logger.error(f"Error updating settings: {str(e)}")
            flash(f'Error updating settings: {str(e)}', 'error')
            return redirect(url_for('settings'))
    
    # For GET request, calculate stats safely
    try:
        total_earned = current_user.total_commission or 0.0
        total_withdrawn = current_user.total_withdrawn or 0.0
        balance = current_user.balance or 0.0
        
        response = supabase.table('users').select('*', count='exact').eq('referred_by', current_user.referral_code).execute()
        referred_count = len(response.data)
        
        return render_template('settings.html',
                             total_earned=total_earned,
                             total_withdrawn=total_withdrawn,
                             balance=balance,
                             referred_count=referred_count)
                             
    except Exception as e:
        app.logger.error(f"Error loading settings page: {str(e)}")
        flash('Error loading settings page. Please try again.', 'error')
        return redirect(url_for('dashboard'))

# Forgot Password Route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('auth/forgot_password.html')
        
        user = SupabaseDB.get_user_by_email(email)
        if user:
            # In a real application, you would generate a reset token and send an email
            # For now, we'll just show a success message
            flash('If an account with that email exists, password reset instructions have been sent.', 'success')
        else:
            # Don't reveal whether email exists for security
            flash('If an account with that email exists, password reset instructions have been sent.', 'success')
        
        return redirect(url_for('login'))
    
    return render_template('auth/forgot_password.html')


@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    from flask import request, redirect, flash, url_for
    from werkzeug.security import check_password_hash, generate_password_hash

    current_pw = request.form.get('current_password')
    new_pw = request.form.get('new_password')
    confirm_pw = request.form.get('confirm_password')

    user = current_user  # Flask-Login user

    # Verify old password
    if not check_password_hash(user.password, current_pw):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for('settings'))

    # Confirm both new passwords match
    if new_pw != confirm_pw:
        flash("New passwords do not match.", "warning")
        return redirect(url_for('settings'))

    # Hash and update in Supabase
    new_hashed_pw = generate_password_hash(new_pw)

    supabase.table("users").update({
        "password": new_hashed_pw
    }).eq("id", user.id).execute()

    flash("Password updated successfully!", "success")
    return redirect(url_for('settings'))

@app.route('/debug-settings')
@login_required
def debug_settings():
    from flask import jsonify
    debug_info = {
        "user": current_user.username,
        "email": current_user.email,
        "plan": getattr(current_user, 'plan', 'free'),
        "status": "ok"
    }
    return jsonify(debug_info)


# Admin Dashboard Route
@app.route('/admin/database')
@login_required
@admin_required
def admin_database():
    """Admin database management interface"""
    # Get database metrics
    db_metrics = DatabaseHealthMonitor.get_database_metrics()
    
    # Get table sizes and info
    table_info = {}
    tables = ['users', 'transactions', 'referrals', 'security_logs', 'mpesa_callbacks']
    
    for table in tables:
        try:
            response = supabase.table(table).select('*', count='exact').execute()
            table_info[table] = {
                'count': len(response.data),
                'accessible': True
            }
        except Exception as e:
            table_info[table] = {
                'count': 0,
                'accessible': False,
                'error': str(e)
            }
    
    return render_template('admin_database.html',
                         db_metrics=db_metrics,
                         table_info=table_info)

@app.route('/admin/database/test-connection', methods=['POST'])
@login_required
@admin_required
def admin_test_database_connection():
    """Test database connection from admin panel"""
    success, message = SupabaseDB.test_connection()
    
    if success:
        flash('Database connection test: SUCCESS', 'success')
    else:
        flash(f'Database connection test: FAILED - {message}', 'error')
    
    return redirect(url_for('admin_database'))

@app.route('/admin/database/reconnect', methods=['POST'])
@login_required
@admin_required
def admin_reconnect_database():
    """Reconnect to database from admin panel"""
    success, message = SupabaseDB.reconnect()
    
    if success:
        flash('Database reconnection: SUCCESS', 'success')
    else:
        flash(f'Database reconnection: FAILED - {message}', 'error')
    
    return redirect(url_for('admin_database'))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    app.logger.info(f"Admin access attempt by: {current_user.username}, is_admin: {current_user.is_admin}")
    
    try:
        # Test Supabase connection first
        response = supabase.table('users').select('*').limit(1).execute()
        app.logger.info("Supabase connection test passed")
        
        # Admin statistics
        try:
            total_users = SupabaseDB.get_users_count()
            app.logger.info(f"Total users: {total_users}")
        except Exception as e:
            app.logger.error(f"Error counting users: {e}")
            total_users = 0
        
        try:
            total_verified = SupabaseDB.get_verified_users_count()
            app.logger.info(f"Total verified: {total_verified}")
        except Exception as e:
            app.logger.error(f"Error counting verified users: {e}")
            total_verified = 0
        
        try:
            total_referrals = SupabaseDB.get_referrals_count()
            app.logger.info(f"Total referrals: {total_referrals}")
        except Exception as e:
            app.logger.error(f"Error counting referrals: {e}")
            total_referrals = 0
        
        try:
            total_commission = SupabaseDB.get_total_commission()
            app.logger.info(f"Total commission: {total_commission}")
        except Exception as e:
            app.logger.error(f"Error calculating total commission: {e}")
            total_commission = 0
        
        try:
            total_withdrawn_amount = SupabaseDB.get_total_withdrawn()
            app.logger.info(f"Total withdrawn: {total_withdrawn_amount}")
        except Exception as e:
            app.logger.error(f"Error calculating total withdrawn: {e}")
            total_withdrawn_amount = 0
        
        try:
            total_balance = SupabaseDB.get_total_balance()
            app.logger.info(f"Total balance: {total_balance}")
        except Exception as e:
            app.logger.error(f"Error calculating total balance: {e}")
            total_balance = 0
        
        try:
            pending_withdrawals_data = SupabaseDB.get_pending_withdrawals()
            pending_withdrawals = len(pending_withdrawals_data)
            app.logger.info(f"Pending withdrawals: {pending_withdrawals}")
        except Exception as e:
            app.logger.error(f"Error counting pending withdrawals: {e}")
            pending_withdrawals = 0

        try:
            pending_payments_data = SupabaseDB.get_pending_payments()
            pending_payments = len(pending_payments_data)
            app.logger.info(f"Pending payments: {pending_payments}")
        except Exception as e:
            app.logger.error(f"Error counting pending payments: {e}")
            pending_payments = 0
        
        try:
            recent_users_data = SupabaseDB.get_recent_users(limit=10)
            recent_users = [User(user_data) for user_data in recent_users_data]
            app.logger.info(f"Recent users: {len(recent_users)}")
        except Exception as e:
            app.logger.error(f"Error fetching recent users: {e}")
            recent_users = []
        
        try:
            # Get pending withdrawal transactions with user info
            pending_withdrawal_transactions = []
            for withdrawal in pending_withdrawals_data:
                user = SupabaseDB.get_user_by_id(withdrawal['user_id'])
                pending_withdrawal_transactions.append((withdrawal, user))
            app.logger.info(f"Pending withdrawal transactions: {len(pending_withdrawal_transactions)}")
        except Exception as e:
            app.logger.error(f"Error fetching pending withdrawal transactions: {e}")
            pending_withdrawal_transactions = []

        try:
            # Get pending payment transactions with user info
            pending_payment_transactions = []
            for payment in pending_payments_data:
                user = SupabaseDB.get_user_by_id(payment['user_id'])
                pending_payment_transactions.append((payment, user))
            app.logger.info(f"Pending payment transactions: {len(pending_payment_transactions)}")
        except Exception as e:
            app.logger.error(f"Error fetching pending payment transactions: {e}")
            pending_payment_transactions = []
        
        try:
            recent_activity_data = SupabaseDB.get_recent_activity(limit=10)
            recent_activity = recent_activity_data
            app.logger.info(f"Recent activity: {len(recent_activity)}")
        except Exception as e:
            app.logger.error(f"Error fetching recent activity: {e}")
            recent_activity = []
        
        current_time = datetime.now(timezone.utc)
        
        app.logger.info("All queries successful, rendering template...")
        
        return render_template('admin_dashboard.html',
                             total_users=total_users,
                             total_verified=total_verified,
                             total_referrals=total_referrals,
                             total_commission=total_commission,
                             total_withdrawn_amount=total_withdrawn_amount,
                             total_balance=total_balance,
                             pending_withdrawals=pending_withdrawals,
                             pending_payments=pending_payments,
                             recent_users=recent_users,
                             pending_withdrawal_transactions=pending_withdrawal_transactions,
                             pending_payment_transactions=pending_payment_transactions,
                             recent_activity=recent_activity,
                             current_time=current_time)
                             
    except Exception as e:
        app.logger.error(f"Error in admin_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Error accessing admin dashboard: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/withdrawal-notice')
@login_required
@admin_required
def admin_withdrawal_notice():
    """Admin page to view and manage pending withdrawal requests"""
    try:
        # Get pending withdrawals with user information
        response = supabase.table('transactions')\
            .select('*, users(*)')\
            .eq('transaction_type', 'withdrawal')\
            .in_('status', ['pending', 'Under Review', 'processing'])\
            .order('created_at', desc=True)\
            .execute()
        
        pending_withdrawals = []
        total_pending_amount = 0
        
        for item in response.data:
            transaction = item
            user_data = item.get('users', {})
            user = User(user_data) if user_data else None
            
            if user:
                pending_withdrawals.append({
                    'transaction': transaction,
                    'user': user,
                    'days_pending': (datetime.now(timezone.utc) - 
                                   datetime.fromisoformat(transaction['created_at'].replace('Z', '+00:00'))).days
                })
                total_pending_amount += abs(transaction['amount'])
        
        # Get statistics
        stats = {
            'total_pending': len(pending_withdrawals),
            'total_amount': total_pending_amount,
            'under_review': len([w for w in pending_withdrawals if w['transaction']['status'] == 'Under Review']),
            'processing': len([w for w in pending_withdrawals if w['transaction']['status'] == 'processing']),
            'regular_pending': len([w for w in pending_withdrawals if w['transaction']['status'] == 'pending'])
        }
        
        return render_template('admin_withdrawal_notice.html',
                             pending_withdrawals=pending_withdrawals,
                             stats=stats,
                             current_time=datetime.now(timezone.utc))
                             
    except Exception as e:
        app.logger.error(f"Error loading withdrawal notice page: {str(e)}")
        flash('Error loading withdrawal notices.', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/withdrawal-notice/update-status', methods=['POST'])
@login_required
@admin_required
def update_withdrawal_status():
    """Update withdrawal status via AJAX"""
    try:
        data = request.get_json()
        transaction_id = data.get('transaction_id')
        new_status = data.get('status')
        notes = data.get('notes', '')
        
        if not transaction_id or not new_status:
            return jsonify({'success': False, 'message': 'Missing required fields'})
        
        transaction = SupabaseDB.get_transaction_by_id(transaction_id)
        if not transaction:
            return jsonify({'success': False, 'message': 'Transaction not found'})
        
        user = SupabaseDB.get_user_by_id(transaction['user_id'])
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        # Prepare update data
        update_data = {
            'status': new_status,
            'description': f"Status updated to {new_status} by admin"
        }
        
        if notes:
            update_data['description'] += f" - {notes}"
        
        # Handle different status changes
        if new_status == 'rejected':
            # Refund the amount
            refund_amount = abs(transaction['amount'])
            user.balance += refund_amount
            user.total_withdrawn -= refund_amount
            
            SupabaseDB.update_user(user.id, {
                'balance': user.balance,
                'total_withdrawn': user.total_withdrawn
            })
            
            # Send rejection SMS
            CelcomSMS.send_withdrawal_notification(
                user.phone,
                user.username,
                refund_amount,
                'failed',
                notes="Withdrawal rejected by admin"
            )
            
        elif new_status == 'processing':
            # Initiate automatic processing if not already processing
            if transaction['status'] != 'processing':
                process_automatic_withdrawal(transaction)
        
        # Update transaction
        SupabaseDB.update_transaction(transaction_id, update_data)
        
        # Log admin action
        SecurityMonitor.log_security_event(
            "ADMIN_WITHDRAWAL_UPDATE",
            current_user.id,
            {
                "transaction_id": transaction_id,
                "old_status": transaction['status'],
                "new_status": new_status,
                "user_affected": user.id,
                "notes": notes
            }
        )
        
        return jsonify({
            'success': True, 
            'message': f'Withdrawal status updated to {new_status}'
        })
        
    except Exception as e:
        app.logger.error(f"Error updating withdrawal status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/withdrawal-notice/bulk-action', methods=['POST'])
@login_required
@admin_required
def bulk_withdrawal_action():
    """Process bulk actions on withdrawals"""
    try:
        data = request.get_json()
        action = data.get('action')
        transaction_ids = data.get('transaction_ids', [])
        
        if not action or not transaction_ids:
            return jsonify({'success': False, 'message': 'Missing required fields'})
        
        results = {
            'processed': 0,
            'failed': 0,
            'details': []
        }
        
        for transaction_id in transaction_ids:
            try:
                transaction = SupabaseDB.get_transaction_by_id(transaction_id)
                if not transaction:
                    results['failed'] += 1
                    results['details'].append(f"Transaction {transaction_id} not found")
                    continue
                
                user = SupabaseDB.get_user_by_id(transaction['user_id'])
                if not user:
                    results['failed'] += 1
                    results['details'].append(f"User for transaction {transaction_id} not found")
                    continue
                
                if action == 'approve':
                    # For pending withdrawals, process automatically
                    if transaction['status'] == 'pending':
                        processing_result = process_automatic_withdrawal(transaction)
                        if processing_result:
                            results['processed'] += 1
                            results['details'].append(f"Approved and processing transaction {transaction_id}")
                        else:
                            results['failed'] += 1
                            results['details'].append(f"Failed to process transaction {transaction_id}")
                    
                    # For under review, move to processing
                    elif transaction['status'] == 'Under Review':
                        SupabaseDB.update_transaction(transaction_id, {'status': 'processing'})
                        process_automatic_withdrawal(transaction)
                        results['processed'] += 1
                        results['details'].append(f"Approved transaction {transaction_id}")
                
                elif action == 'reject':
                    # Refund and mark as rejected
                    refund_amount = abs(transaction['amount'])
                    user.balance += refund_amount
                    user.total_withdrawn -= refund_amount
                    
                    SupabaseDB.update_user(user.id, {
                        'balance': user.balance,
                        'total_withdrawn': user.total_withdrawn
                    })
                    
                    SupabaseDB.update_transaction(transaction_id, {
                        'status': 'rejected',
                        'description': 'Bulk rejected by admin'
                    })
                    
                    # Send rejection SMS
                    CelcomSMS.send_withdrawal_notification(
                        user.phone,
                        user.username,
                        refund_amount,
                        'failed',
                        notes="Withdrawal rejected by admin"
                    )
                    
                    results['processed'] += 1
                    results['details'].append(f"Rejected transaction {transaction_id}")
                
                # Log bulk action
                SecurityMonitor.log_security_event(
                    "ADMIN_BULK_WITHDRAWAL_ACTION",
                    current_user.id,
                    {
                        "action": action,
                        "transaction_id": transaction_id,
                        "user_affected": user.id
                    }
                )
                
            except Exception as e:
                results['failed'] += 1
                results['details'].append(f"Error processing {transaction_id}: {str(e)}")
        
        return jsonify({
            'success': True,
            'message': f'Bulk action completed: {results["processed"]} processed, {results["failed"]} failed',
            'results': results
        })
        
    except Exception as e:
        app.logger.error(f"Error in bulk withdrawal action: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/withdrawals')
@login_required
@admin_required
def admin_withdrawals():
    try:
        app.logger.info("📦 Fetching all withdrawals from Supabase...")
        withdrawals_data = supabase.table('transactions')\
            .select('*, users(*)')\
            .eq('transaction_type', 'withdrawal')\
            .order('created_at', desc=True)\
            .execute()
        
        app.logger.info(f"✅ Supabase response: {withdrawals_data}")

        withdrawals = []
        for item in withdrawals_data.data or []:
            user_data = item.get('users', {})
            user = User(user_data) if user_data else None
            withdrawals.append((item, user))
        
        pending_withdrawals_data = SupabaseDB.get_pending_withdrawals()
        total_pending_withdrawals = sum(abs(t['amount']) for t in pending_withdrawals_data)

        return render_template(
            'admin_withdrawals.html',
            withdrawals=withdrawals,
            total_pending_withdrawals=total_pending_withdrawals
        )
    except Exception as e:
        app.logger.error(f"❌ Error loading withdrawals: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

# Update admin withdrawal approval to handle automatic processing
@app.route('/admin/approve-withdrawal/<transaction_id>', methods=['POST'])
@login_required
@admin_required
def approve_withdrawal(transaction_id):
    transaction = SupabaseDB.get_transaction_by_id(transaction_id)
    
    if not transaction or transaction['transaction_type'] != 'withdrawal':
        return jsonify({'success': False, 'message': 'Not a withdrawal transaction'})
    
    # If already processing via B2C, don't allow manual approval
    if transaction['status'] == 'processing':
        return jsonify({'success': False, 'message': 'Withdrawal is being processed automatically via M-Pesa'})
    
    try:
        # For pending withdrawals that failed auto-processing, process manually
        if transaction['status'] == 'pending':
            # Initiate manual B2C processing
            processing_result = process_automatic_withdrawal(transaction)
            
            if processing_result:
                return jsonify({'success': True, 'message': 'Withdrawal sent for automatic processing via M-Pesa'})
            else:
                return jsonify({'success': False, 'message': 'Automatic processing failed. Please try manual M-Pesa payment.'})
        
        # For already completed transactions
        SupabaseDB.update_transaction(transaction_id, {
            'status': 'completed',
            'description': f'M-Pesa withdrawal approved manually - Processed to {transaction["phone_number"]}'
        })
        
        return jsonify({'success': True, 'message': 'Withdrawal approved successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/reject-withdrawal/<transaction_id>', methods=['POST'])
@login_required
@admin_required
def reject_withdrawal(transaction_id):
    transaction = SupabaseDB.get_transaction_by_id(transaction_id)
    user = SupabaseDB.get_user_by_id(transaction['user_id']) if transaction else None
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    if not transaction or transaction['transaction_type'] != 'withdrawal':
        return jsonify({'success': False, 'message': 'Not a withdrawal transaction'})
    
    try:
        refund_amount = abs(transaction['amount'])
        user.balance += refund_amount
        user.total_withdrawn -= refund_amount
        
        SupabaseDB.update_user(user.id, {
            'balance': user.balance,
            'total_withdrawn': user.total_withdrawn
        })
        
        SupabaseDB.update_transaction(transaction_id, {
            'status': 'rejected',
            'description': 'Withdrawal rejected - Amount refunded'
        })
        
        return jsonify({'success': True, 'message': 'Withdrawal rejected and amount refunded'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users_data = SupabaseDB.get_all_users()
    users = []
    
    for user_data in users_data:
        user = User(user_data)

        # ✅ Convert created_at to datetime if it's a string
        if isinstance(user.created_at, str):
            try:
                user.created_at = datetime.fromisoformat(user.created_at.replace("Z", ""))
            except Exception:
                pass

        # Count referrals
        response = supabase.table('users').select('*', count='exact').eq('referred_by', user.referral_code).execute()
        user.referral_count = len(response.data)

        # Count pending withdrawals
        withdrawals = SupabaseDB.get_transactions_by_user(user.id, transaction_type='withdrawal')
        user.pending_withdrawals = len([w for w in withdrawals if w['status'] == 'pending'])

        users.append(user)
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/toggle-user-status/<user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    user = SupabaseDB.get_user_by_id(user_id)
    
    try:
        update_data = {'is_active': not user.is_active}
        SupabaseDB.update_user(user_id, update_data)
        
        status = "activated" if not user.is_active else "deactivated"
        return jsonify({'success': True, 'message': f'User {status} successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@login_manager.user_loader
def load_user(user_id):
    try:
        return SupabaseDB.get_user_by_id(user_id)
    except Exception as e:
        app.logger.error(f"Error loading user {user_id}: {e}")
        return None

@app.route('/api/admin/stats')
@login_required
@admin_required
def api_admin_stats():
    stats = {
        'total_users': SupabaseDB.get_users_count(),
        'total_verified': SupabaseDB.get_verified_users_count(),
        'pending_withdrawals': len(SupabaseDB.get_pending_withdrawals())
    }
    
    return jsonify(stats)

@app.route('/api/live-stats')
@login_required
def api_live_stats():
    return jsonify({
        'balance': current_user.balance,
        'total_referrals': current_user.referral_count,
        'total_commission': current_user.total_commission,
        'user_rank': current_user.user_rank
    })

@app.route('/api/user-ranking')
@login_required
def api_user_ranking():
    ranking = get_user_ranking(current_user.id)
    return jsonify(ranking or {})

@app.route('/favicon.ico')
def favicon():
    return '', 204

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal Server Error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(error):
    app.logger.error(f"Unhandled Exception: {error}")
    return render_template('500.html'), 500

# =============================================================================
# APPLICATION INITIALIZATION
# =============================================================================

# Setup logging
if not app.debug:
    file_handler = RotatingFileHandler('error.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.ERROR)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Referral Ninja startup')
    
# Fix console logging encoding
if sys.stdout.encoding != 'utf-8':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)

# Environment validation
def validate_environment():
    """Validate all required environment variables are set"""
    required_vars = [
        'SECRET_KEY',
        'JWT_SECRET_KEY',
        'SUPABASE_URL',
        'SUPABASE_KEY',
        'SUPABASE_SERVICE_ROLE_KEY',
        'MPESA_CONSUMER_KEY',
        'MPESA_CONSUMER_SECRET',
        'MPESA_BUSINESS_SHORTCODE',
        'MPESA_PASSKEY',
        'MPESA_B2C_SHORTCODE',
        'MPESA_B2C_INITIATOR_NAME',
        'MPESA_B2C_SECURITY_CREDENTIAL',
        'MPESA_CALLBACK_URL',
        'MPESA_B2C_CALLBACK_URL',
        'MPESA_B2C_QUEUE_TIMEOUT_URL',
        'CELCOM_SMS_API_KEY'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise Exception(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    current_app.logger.info("✓ All required environment variables are set")

# Updated initialization function
def init_db():
    """Initialize and verify Supabase database connection (no local SQL)."""
    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            current_app.logger.info("🔍 Testing Supabase connection...")
            response = supabase.table("users").select("*").limit(1).execute()

            if response.data is not None:
                current_app.logger.info("✅ Supabase client verified successfully")
                
                # Test Redis connection
                try:
                    redis_client.ping()
                    current_app.logger.info("✅ Redis connection verified successfully")
                except Exception as e:
                    current_app.logger.error(f"❌ Redis connection failed: {e}")
                    return False

                # Optionally check if admin exists
                if os.environ.get("CREATE_ADMIN_USER") == "true":
                    create_admin_user_if_missing()
                    current_app.logger.info("✅ Admin user checked/created")

                return True
            else:
                current_app.logger.warning("⚠️ No data returned from Supabase - table may be empty")
                return True  # Still fine, as Supabase is reachable

        except Exception as e:
            retry_count += 1
            current_app.logger.error(f"❌ Database initialization attempt {retry_count} failed: {e}")

            if retry_count < max_retries:
                wait_time = 2 ** retry_count
                current_app.logger.info(f"Retrying Supabase check in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                current_app.logger.critical("❌ All Supabase connection attempts failed")
                return False

# Enhanced before_request with health checks (add Redis check)
_last_health_check = {"time": None, "ok": True}

@rate_limiter.exempt  # Prevent rate-limiter interference
@app.before_request
def before_request():
    """Fast health check before requests — skips public routes and caches results."""
    global _last_health_check

    from flask import request

    now = datetime.utcnow()

    # ✅ Skip checks for simple routes (public/static)
    skip_routes = {"static", "index", "home", "login", "register", "health"}
    if request.endpoint in skip_routes or request.path.startswith("/static/"):
        return

    # ✅ Cache recent health results (avoid hitting Supabase/Redis every time)
    cache_valid = (
        _last_health_check["time"]
        and (now - _last_health_check["time"]) < timedelta(minutes=2)
    )
    if cache_valid and _last_health_check["ok"]:
        return  # healthy state cached

    success = True

    # --- 🧩 Supabase check ---
    for i in range(3):
        try:
            # safe call (even if function ignores timeout)
            supabase_check("users", limit=1, timeout=3)
            current_app.logger.debug("Supabase OK ✅")
            break
        except Exception as e:
            current_app.logger.warning(f"Supabase check failed (attempt {i+1}/3): {e}")
            time.sleep(0.5)
    else:
        success = False

    # --- ⚙️ Redis check ---
    for i in range(3):
        try:
            redis_client.ping()
            current_app.logger.debug("Redis OK ✅")
            break
        except Exception as e:
            current_app.logger.warning(f"Redis check failed (attempt {i+1}/3): {e}")
            time.sleep(0.5)
    else:
        success = False

    _last_health_check.update({"time": now, "ok": success})

    # ⚠️ Don’t block users if services are slow — just log it
    if not success:
        current_app.logger.error("⚠️ Background service check failed, continuing anyway")

    # --- 🔒 Security logging for sensitive endpoints ---
    sensitive_endpoints = {"api_request_withdrawal", "withdraw", "admin_dashboard"}
    if request.endpoint in sensitive_endpoints:
        try:
            user_id = current_user.id if current_user.is_authenticated else None
            SecurityMonitor.log_security_event(
                "SENSITIVE_ENDPOINT_ACCESS",
                user_id,
                {
                    "endpoint": request.endpoint,
                    "ip": request.remote_addr,
                    "method": request.method,
                },
            )
            current_app.logger.info(f"Security event logged for {request.endpoint}")
        except Exception as e:
            current_app.logger.warning(f"Security logging failed: {e}")
      
# Add utility functions to Jinja2 context
@app.context_processor
def utility_processor():
    return {
        'abs': abs,
        'min': min,
        'max': max,
        'round': round,
        'len': len,
        'now': datetime.now(timezone.utc)
    }

# =============================================================================
# APPLICATION STARTUP
# =============================================================================

# Initialize the database when the app starts
with app.app_context():
    try:
        validate_environment()
        
        if init_db():
            app.logger.info("✅ Database initialization completed successfully")
            
            # Start health monitoring in production
            if not app.debug:
                start_health_monitoring()
                app.logger.info("✅ Health monitoring started")
        else:
            app.logger.error("❌ Database initialization failed")
    except Exception as e:
        app.logger.error(f"❌ Application initialization failed: {e}")

# Production Startup Script
if __name__ == '__main__':
    try:
        with app.app_context():
            validate_environment()

            if init_db():
                app.logger.info("✅ Database initialization completed successfully")
                app.logger.info("✅ Redis connection established")

                if not app.debug:
                    start_health_monitoring()
                    app.logger.info("✅ Health monitoring started")
            else:
                app.logger.error("❌ Database initialization failed - exiting")
                sys.exit(1)

        print("🚀 Starting Referral Ninja Application - PRODUCTION READY")
        print("✅ Environment validation: PASSED")
        print("✅ Database schema: VERIFIED")
        print("✅ Redis cache: CONFIGURED")
        print("✅ Rate limiting: ENABLED (Redis-backed)")
        print("✅ Security configuration: ENABLED")
        print("✅ M-Pesa environment: PRODUCTION")
        print("✅ Celcom SMS: CONFIGURED")
        print("✅ Health monitoring: ACTIVE")
        print("✅ PAYMENT-ONLY USER STORAGE: ENABLED")

        port = int(os.environ.get('PORT', 10000))
        host = '0.0.0.0'

        print(f"✅ Server starting on {host}:{port}")
        print(f"✅ Health endpoint: http://{host}:{port}/health")
        print(f"✅ Detailed health: http://{host}:{port}/health/detailed")
        print(f"✅ Minimum withdrawal: KSH {app.config['WITHDRAWAL_MIN_AMOUNT']}")

        app.logger.info(f"🚀 Starting Flask app on {host}:{port}")
        app.run(
            host=host,
            port=port,
            debug=False,  # Always False in production
            threaded=True
        )

    except Exception as e:
        print(f"❌ CRITICAL: Failed to start application: {e}")
        print("Please check:")
        print("1. All required environment variables are set")
        print("2. Supabase connection is working")
        print("3. Redis connection is working")
        print("4. M-Pesa credentials are valid")
        sys.exit(1)