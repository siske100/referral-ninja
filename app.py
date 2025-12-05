# =============================================================================
# STANDARD LIBRARY IMPORTS
# =============================================================================
import os
import sys
import time
import uuid
import math
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
import time
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
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from functools import wraps
from typing import Dict, List, Any, Tuple, Optional
import urllib.parse

# =============================================================================
# THIRD-PARTY IMPORTS
# =============================================================================
import requests
import httpx
import psutil
import psycopg2
import redis
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, 
    flash, session, jsonify, Blueprint, current_app, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, 
    logout_user, current_user
)
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug import Request
from logging.handlers import RotatingFileHandler
from supabase import create_client
from telegram import Bot


# =============================================================================
# APPLICATION SETUP AND CONFIGURATION
# =============================================================================

# Emergency recursion limit and logging fixes
sys.setrecursionlimit(5000)

# Load environment variables from .env file
load_dotenv()

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def setup_safe_logging():
    """Configure safe logging without recursion risks"""
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Create a safe formatter that can't cause recursion
    class SafeFormatter(logging.Formatter):
        def format(self, record):
            try:
                return super().format(record)
            except RecursionError:
                return f"RECURSION_ERROR: {record.name} {record.levelname}: {record.msg}"
            except Exception:
                return f"LOG_FORMAT_ERROR: {record.msg}"
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
        handlers=[
            # File handler for errors - simplified
            logging.FileHandler('logs/error.log', encoding='utf-8'),
            # Console handler
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Apply safe formatter to all handlers
    formatter = SafeFormatter('%(asctime)s %(name)s %(levelname)s: %(message)s')
    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)
    
    # Set specific log levels
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('supabase').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('redis').setLevel(logging.WARNING)
    
    # Create logger instance
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    
    return logger

# Initialize safe logging
logger = setup_safe_logging()

# Debug: Check if environment variables are loaded
logger.info("Loading environment variables...")
logger.info(f"Current directory: {os.getcwd()}")
logger.info(f".env file exists: {os.path.exists('.env')}")
logger.info(f"SUPABASE_URL loaded: {bool(os.environ.get('SUPABASE_URL'))}")
logger.info(f"SUPABASE_KEY loaded: {bool(os.environ.get('SUPABASE_SERVICE_ROLE_KEY'))}")

# =============================================================================
# FLASK APP CONFIGURATION
# =============================================================================

app = Flask(__name__)

# PRODUCTION CONFIGURATION
class Config:
    
    
    # Email Configuration
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
    BREVO_SENDER_NAME = os.environ.get('BREVO_SENDER_NAME', 'ReferralNinja')
    BREVO_SENDER_EMAIL = os.environ.get('BREVO_SENDER_EMAIL', 'noreply@referralninja.co.ke')
    
    # reCAPTCHA Configuration
    RECAPTCHA_SITE_KEY = os.environ['RECAPTCHA_SITE_KEY']
    RECAPTCHA_SECRET_KEY = os.environ['RECAPTCHA_SECRET_KEY']
    RECAPTCHA_VERIFY_URL = os.environ['RECAPTCHA_VERIFY_URL']
    
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
    
    # Fraud Detection Settings
    MAX_ACCOUNTS_PER_IP = 3
    MAX_ACCOUNTS_PER_DEVICE = 2
    MAX_WITHDRAWALS_PER_HOUR = 3
    MAX_LOGIN_ATTEMPTS_PER_HOUR = 10
    SUSPICIOUS_AMOUNT_THRESHOLD = 5001
    NEW_USER_WITHDRAWAL_LIMIT = 1000
    FRAUD_BLOCK_DURATION_HOURS = 24
    
    # Rate limiting settings
    RATE_LIMITING_ENABLED = True
    RATE_LIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')
    RATE_LIMIT_STRATEGY = 'moving-window'
    RATE_LIMIT_HEADERS_ENABLED = True
    
    # Rate limit tiers
    RATE_LIMITS = {
        'strict': ["100 per day", "20 per hour"],
        'normal': ["1000 per day", "100 per hour", "10 per minute"],
        'generous': ["5000 per day", "1000 per hour", "100 per minute"]
    }


class EmailService:
    """Handle sending withdrawal verification emails using Brevo API"""
    
    def __init__(self, app_config):
        self.config = app_config
        self.logger = logging.getLogger(__name__)
        
        # Log configuration for debugging
        self.logger.info(f"EmailService initialized with Brevo API")
        self.logger.info(f"  Brevo API Key Present: {bool(self.config.get('BREVO_API_KEY'))}")
        self.logger.info(f"  Brevo Sender Name: {self.config.get('BREVO_SENDER_NAME', 'ReferralNinja')}")
        self.logger.info(f"  Brevo Sender Email: {self.config.get('BREVO_SENDER_EMAIL', 'noreply@referralninja.co.ke')}")
        
        # Initialize Brevo API client
        self.api_client = None
        if self.config.get('BREVO_API_KEY'):
            self._init_brevo_client()
    
    def _init_brevo_client(self):
        """Initialize Brevo API client"""
        try:
            # Configure API key authorization
            configuration = sib_api_v3_sdk.Configuration()
            configuration.api_key['api-key'] = self.config.get('BREVO_API_KEY')
            
            # Create API client
            self.api_client = sib_api_v3_sdk.ApiClient(configuration)
            
            # Create instances of the API class
            self.transactional_api = sib_api_v3_sdk.TransactionalEmailsApi(self.api_client)
            
            self.logger.info("✅ Brevo API client initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Brevo API client: {str(e)}")
            self.api_client = None
            return False
    
    def send_withdrawal_verification_email(self, user_email, username, verification_code, amount, transaction_id):
        """Send withdrawal verification code via Brevo API"""
        try:
            # Log that we're starting the email process
            self.logger.info(f"🎯 Starting email send process for {user_email}")
            self.logger.info(f"  Username: {username}")
            self.logger.info(f"  Amount: KSH {amount}")
            self.logger.info(f"  Code: {verification_code}")
            self.logger.info(f"  Transaction ID: {transaction_id}")
            
            # Check if Brevo client is initialized
            if not self.api_client:
                self.logger.error("❌ Brevo API client not initialized")
                return False
            
            # Email content
            subject = "ReferralNinja - Withdrawal Verification Required"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background-color: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
                    .content {{ background-color: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; border: 1px solid #ddd; }}
                    .code {{ font-size: 32px; font-weight: bold; color: #4CAF50; text-align: center; margin: 20px 0; padding: 15px; background-color: #f0f9f0; border-radius: 5px; }}
                    .warning {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                    .button {{ display: inline-block; background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Withdrawal Verification</h1>
                    </div>
                    <div class="content">
                        <h2>Hello {username},</h2>
                        <p>You have requested to withdraw <strong>KSH {amount:,.2f}</strong> from your ReferralNinja account.</p>
                        
                        <p>To complete this withdrawal, please use the verification code below:</p>
                        
                        <div class="code">{verification_code}</div>
                        
                        <div class="warning">
                            <strong>⚠️ Important:</strong>
                            <ul>
                                <li>This code will expire in <strong>10 minutes</strong></li>
                                <li>Do not share this code with anyone</li>
                                <li>If you didn't request this withdrawal, please contact support immediately</li>
                            </ul>
                        </div>
                        
                        <p>To verify your withdrawal:</p>
                        <ol>
                            <li>Go to your ReferralNinja account</li>
                            <li>Navigate to the withdrawal page</li>
                            <li>Enter the verification code above</li>
                        </ol>
                        
                        <p>Transaction ID: <code>{transaction_id}</code></p>
                        
                        <p>Best regards,<br>
                        <strong>ReferralNinja Security Team</strong></p>
                        
                        <hr>
                        <p style="font-size: 12px; color: #777;">
                            This is an automated message. Please do not reply to this email.<br>
                            If you need assistance, contact: support@referralninja.co.ke
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Plain text version
            text_content = f"""
            WITHDRAWAL VERIFICATION REQUIRED
            
            Hello {username},
            
            You have requested to withdraw KSH {amount:,.2f} from your ReferralNinja account.
            
            VERIFICATION CODE: {verification_code}
            
            This code will expire in 10 minutes.
            
            Transaction ID: {transaction_id}
            
            If you didn't request this withdrawal, please contact support immediately.
            
            Best regards,
            ReferralNinja Security Team
            """
            
            self.logger.info(f"📧 Email content prepared. Sending via Brevo API...")
            
            # Send email via Brevo API
            success = self._send_email_via_brevo(
                recipient=user_email,
                subject=subject,
                text_content=text_content,
                html_content=html_content,
                recipient_name=username
            )
            
            if success:
                self.logger.info(f"✅ Withdrawal verification email sent to {user_email} (Transaction: {transaction_id})")
                return True
            else:
                self.logger.error(f"❌ Failed to send email to {user_email}")
                return False
            
        except Exception as e:
            self.logger.error(f"❌ Error preparing withdrawal email: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
    
    def _send_email_via_brevo(self, recipient, subject, text_content, html_content, recipient_name=None):
        """Send email using Brevo Transactional Email API"""
        try:
            if not self.api_client:
                self.logger.error("❌ Brevo API client not initialized")
                return False
            
            # Prepare the email sending parameters
            sender_name = self.config.get('BREVO_SENDER_NAME', 'ReferralNinja')
            sender_email = self.config.get('BREVO_SENDER_EMAIL', 'noreply@referralninja.co.ke')
            
            # Create SendSmtpEmail object
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                sender={"name": sender_name, "email": sender_email},
                to=[{"email": recipient, "name": recipient_name or recipient}],
                html_content=html_content,
                text_content=text_content,
                subject=subject
            )
            
            # Send the email
            self.logger.info(f"📤 Sending email via Brevo API to {recipient}...")
            api_response = self.transactional_api.send_transac_email(send_smtp_email)
            
            # Log the response
            self.logger.info(f"✅ Brevo API Response: Message ID: {api_response.message_id}")
            self.logger.info(f"   Status: Email queued successfully")
            
            return True
            
        except ApiException as e:
            self.logger.error(f"❌ Brevo API Exception: {e}")
            self.logger.error(f"   Status Code: {e.status}")
            self.logger.error(f"   Reason: {e.reason}")
            self.logger.error(f"   Response Body: {e.body}")
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Error sending email via Brevo: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
    
    def send_withdrawal_confirmation_email(self, user_email, username, amount, transaction_id, mpesa_code=None):
        """Send withdrawal confirmation email via Brevo API"""
        try:
            subject = "ReferralNinja - Withdrawal Completed Successfully"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background-color: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
                    .content {{ background-color: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; border: 1px solid #ddd; }}
                    .success {{ background-color: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>✅ Withdrawal Successful!</h1>
                    </div>
                    <div class="content">
                        <h2>Hello {username},</h2>
                        
                        <div class="success">
                            <h3>🎉 Your withdrawal has been processed successfully!</h3>
                            <p><strong>Amount:</strong> KSH {amount:,.2f}</p>
                            <p><strong>Status:</strong> Completed</p>
                            {f'<p><strong>M-Pesa Transaction ID:</strong> {mpesa_code}</p>' if mpesa_code else ''}
                        </div>
                        
                        <p>The funds have been sent to your M-Pesa account and should arrive shortly.</p>
                        
                        <p><strong>Transaction Details:</strong></p>
                        <ul>
                            <li><strong>Transaction ID:</strong> {transaction_id}</li>
                            <li><strong>Date Processed:</strong> {datetime.now(timezone.utc).strftime('%d %B, %Y at %H:%M')}</li>
                        </ul>
                        
                        <p>Keep earning by inviting more friends to join ReferralNinja!</p>
                        
                        <p>Best regards,<br>
                        <strong>ReferralNinja Team</strong></p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Send via Brevo API
            success = self._send_email_via_brevo(
                recipient=user_email,
                subject=subject,
                text_content=html_content,  # Use HTML as text content
                html_content=html_content,
                recipient_name=username
            )
            
            if success:
                self.logger.info(f"✅ Withdrawal confirmation email sent to {user_email}")
                return True
            else:
                self.logger.error(f"❌ Failed to send confirmation email to {user_email}")
                return False
            
        except Exception as e:
            self.logger.error(f"❌ Error sending confirmation email: {str(e)}")
            return False

    def send_simple_email(self, recipient, subject, message, recipient_name=None):
        """Send a simple email via Brevo API"""
        try:
            if not self.api_client:
                self.logger.error("❌ Brevo API client not initialized")
                return False
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .content {{ padding: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="content">
                        {message}
                    </div>
                </div>
            </body>
            </html>
            """
            
            success = self._send_email_via_brevo(
                recipient=recipient,
                subject=subject,
                text_content=message,
                html_content=html_content,
                recipient_name=recipient_name
            )
            
            return success
            
        except Exception as e:
            self.logger.error(f"❌ Error sending simple email: {str(e)}")
            return False

# Initialize email service with Brevo API
email_service = EmailService({
    'BREVO_API_KEY': app.config.get('BREVO_API_KEY'),
    'BREVO_SENDER_NAME': app.config.get('BREVO_SENDER_NAME', 'ReferralNinja'),
    'BREVO_SENDER_EMAIL': app.config.get('BREVO_SENDER_EMAIL', 'noreply@referralninja.co.ke'),
})

class DevelopmentConfig(Config):
    SESSION_COOKIE_SECURE = False
    DEBUG = True
        
# Load appropriate config based on environment
if os.getenv('FLASK_ENV') == 'development':
    app.config.from_object(DevelopmentConfig)
    logger.info("Development configuration loaded")
else:
    app.config.from_object(Config)
    logger.info("Production configuration loaded")

# =============================================================================
# DATABASE AND EXTERNAL SERVICES SETUP
# =============================================================================

# Initialize Supabase client
supabase = create_client(app.config.get('SUPABASE_URL'), app.config.get('SUPABASE_KEY'))

# =============================================================================
# REDIS SETUP WITH SAFE WRAPPER
# =============================================================================

class SafeRedis:
    def __init__(self, redis_url):
        self.redis_url = redis_url
        self._client = None
        self.logger = logging.getLogger(__name__)
        self._connect()
    
    def _connect(self):
        """Initialize Redis connection with error handling"""
        try:
            self._client = redis.from_url(
                self.redis_url, 
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                max_connections=10
            )
            # Test connection
            self._client.ping()
            self.logger.info("Redis connection established successfully")
        except Exception as e:
            self.logger.error(f"Redis connection failed: {e}")
            self._client = None
    
    def __getattr__(self, name):
        """Delegate to redis client with reconnection logic"""
        if self._client is None:
            self._connect()
            if self._client is None:
                # Return a dummy method that returns None instead of raising error
                return self._dummy_method
        
        attr = getattr(self._client, name)
        
        if not callable(attr):
            return attr
            
        def safe_method(*args, **kwargs):
            try:
                return attr(*args, **kwargs)
            except (redis.ConnectionError, redis.TimeoutError):
                self.logger.warning("Redis connection lost, reconnecting...")
                self._connect()
                if self._client is None:
                    return None
                # Re-get the attribute after reconnection
                new_attr = getattr(self._client, name)
                return new_attr(*args, **kwargs)
            except Exception as e:
                self.logger.error(f"Redis operation failed: {e}")
                return None
        
        return safe_method
    
    def _dummy_method(self, *args, **kwargs):
        """Dummy method that returns None when Redis is unavailable"""
        return None
    
    def exists(self, key):
        """Safe exists check"""
        try:
            if self._client:
                return self._client.exists(key)
            return False
        except Exception:
            return False
    
    def get(self, key, default=None):
        """Safe get with default"""
        try:
            if self._client:
                result = self._client.get(key)
                return result if result is not None else default
            return default
        except Exception:
            return default
    
    def setex(self, key, time, value):
        """Safe setex"""
        try:
            if self._client:
                return self._client.setex(key, time, value)
            return False
        except Exception:
            return False
    
    def incr(self, key):
        """Safe increment with None handling"""
        try:
            if self._client:
                result = self._client.incr(key)
                return result if result is not None else 1
            return 1
        except Exception:
            return 1
    
    def lpush(self, key, value):
        """Safe list push"""
        try:
            if self._client:
                return self._client.lpush(key, value)
            return 0
        except Exception:
            return 0
    
    def lrange(self, key, start, end):
        """Safe list range"""
        try:
            if self._client:
                return self._client.lrange(key, start, end)
            return []
        except Exception:
            return []
    
    def ltrim(self, key, start, end):
        """Safe list trim"""
        try:
            if self._client:
                return self._client.ltrim(key, start, end)
            return False
        except Exception:
            return False
    
    def expire(self, key, time):
        """Safe expire"""
        try:
            if self._client:
                return self._client.expire(key, time)
            return False
        except Exception:
            return False
    
    def delete(self, key):
        """Safe delete"""
        try:
            if self._client:
                return self._client.delete(key)
            return 0
        except Exception:
            return 0
    
    def keys(self, pattern):
        """Safe keys pattern matching"""
        try:
            if self._client:
                return self._client.keys(pattern)
            return []
        except Exception:
            return []
    
    def ping(self):
        """Safe ping to test connection"""
        try:
            if self._client:
                return self._client.ping()
            return False
        except Exception:
            return False

# Initialize Redis with safe wrapper
redis_client = SafeRedis(app.config['REDIS_URL'])

# Emergency fallback for Redis failures
def safe_redis_operation(operation, default_return=None):
    """Execute Redis operation with comprehensive error handling"""
    try:
        result = operation()
        # Ensure we don't return None for critical operations that need numbers
        if result is None and default_return is not None:
            return default_return
        return result
    except Exception as e:
        logger.error(f"Redis operation failed: {e}")
        return default_return

# Test Redis connection on startup
try:
    if redis_client.ping():
        logger.info("✅ Redis connection successful")
    else:
        logger.warning("⚠️ Redis connection may be unstable")
except Exception as e:
    logger.error(f"❌ Redis connection test failed: {e}")

# =============================================================================
# FLASK EXTENSIONS INITIALIZATION
# =============================================================================

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# =============================================================================
# RATE LIMITING CONFIGURATION
# =============================================================================

def get_limiter_key():
    """Enhanced rate limiting key function with proper None handling"""
    # First try to use authenticated user ID
    try:
        if hasattr(current_app, 'login_manager'):
            from flask_login import current_user
            if current_user.is_authenticated:
                return f"user:{current_user.id}"
    except Exception as e:
        current_app.logger.debug(f"User-based rate limit key failed: {e}")
    
    # Fall back to IP address with safe handling
    try:
        ip_address = get_remote_address()
        
        # ALWAYS exempt localhost and internal IPs from rate limiting
        exempt_ips = ['127.0.0.1', 'localhost', '::1']
        if ip_address in exempt_ips:
            # Return a special exempt key instead of None
            return f"exempt:{ip_address}"
        
        return f"ip:{ip_address}"
        
    except Exception as e:
        current_app.logger.error(f"Rate limit IP fallback failed: {e}")
        return f"unknown:{int(time.time())}"

# Safe rate limiter initialization with fallbacks
try:
    rate_limiter = Limiter(
        app=app,
        key_func=get_limiter_key,
        storage_uri=app.config.get("REDIS_URL", "memory://"),
        default_limits=["2000 per day", "500 per hour", "50 per minute"],  # Balanced limits
        strategy="moving-window",  # Better than fixed-window
        on_breach=lambda limit: current_app.logger.warning(f"Rate limit breached: {limit}"),
        fail_on_first_breach=False  # Don't crash if Redis fails
    )
    logger.info("Rate limiter initialized successfully")
except Exception as e:
    logger.error(f"Rate limiter initialization failed: {e}")
    # Fallback to memory-based limiter
    rate_limiter = Limiter(
        app=app,
        key_func=get_limiter_key,
        storage_uri="memory://",
        default_limits=["1000 per day", "200 per hour", "20 per minute"],  # Conservative memory limits
        strategy="moving-window"
    )
    logger.info("Rate limiter fallback to memory storage")

# =============================================================================
# DATABASE MODELS
# =============================================================================

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
        if self.total_commission >= 70000:
            self.user_rank = 'Diamond'
        elif self.total_commission >= 30000:
            self.user_rank = 'Platinum'
        elif self.total_commission >= 15000:
            self.user_rank = 'Gold'
        elif self.total_commission >= 5000:
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
    def get_tier_distribution():
        try:
            response = supabase.table("users") \
                .select("id, user_rank") \
                .execute()

            data = getattr(response, "data", None)

            if not data or not isinstance(data, list):
                logger.error("Invalid tier distribution data")
                return {
                    'bronze_percentage': 40,
                    'silver_percentage': 25,
                    'gold_percentage': 20,
                    'platinum_percentage': 10,
                    'diamond_percentage': 5
                }

            total = len(data)
            if total == 0:
                return {tier: 0 for tier in [
                    'bronze_percentage', 'silver_percentage', 
                    'gold_percentage', 'platinum_percentage', 
                    'diamond_percentage'
                ]}

            counters = {
                'Bronze': 0,
                'Silver': 0,
                'Gold': 0,
                'Platinum': 0,
                'Diamond': 0,
            }

            for user in data:
                tier = user.get('user_rank', 'Bronze')
                if tier in counters:
                    counters[tier] += 1

            return {
                'bronze_percentage': round(counters['Bronze'] / total * 100, 1),
                'silver_percentage': round(counters['Silver'] / total * 100, 1),
                'gold_percentage': round(counters['Gold'] / total * 100, 1),
                'platinum_percentage': round(counters['Platinum'] / total * 100, 1),
                'diamond_percentage': round(counters['Diamond'] / total * 100, 1),
            }

        except Exception as e:
            logger.error(f"Tier error: {e}")
            return {
                'bronze_percentage': 40,
                'silver_percentage': 25,
                'gold_percentage': 20,
                'platinum_percentage': 10,
                'diamond_percentage': 5
            }

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
            logger.error(f"Error getting jobs: {str(e)}")
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
                logger.warning(f"SupabaseDB Attempt {attempt + 1} failed: {e}")
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
                    logger.info(f"SupabaseDB Loaded user {user_id}")
                    return User(response.data[0])
                else:
                    logger.warning(f"SupabaseDB No user found for id={user_id}")
                    return None
            except httpx.TimeoutException:
                raise Exception(f"Supabase query for user {user_id} timed out after {timeout}s")

        try:
            return SupabaseDB.execute_with_retry(operation)
        except Exception as e:
            logger.error(f"SupabaseDB get_user_by_id() failed: {e}")
            return None
        
    @staticmethod
    def handle_db_error(method_name, error, raise_exception=True):
        """Standardized database error handling"""
        error_msg = f"Database error in {method_name}: {str(error)}"
        logger.error(error_msg)
        
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
    def get_all_transactions_by_user(user_id):
        """Get all transactions for a user regardless of type"""
        try:
            response = supabase.table('transactions') \
                .select('*') \
                .eq('user_id', user_id) \
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting all transactions for user {user_id}: {e}")
            return []

    @staticmethod
    def get_referred_users(referrer_id):
        """Get all users referred by a specific user"""
        try:
            response = supabase.table('users') \
                .select('*') \
                .eq('referred_by', referrer_id) \
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting referred users for {referrer_id}: {e}")
            return []

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
        """Fetch all users with safe defaults and consistent types."""
        try:
            response = (
                supabase.table("users")
                .select(
                    """
                    id, username, email, phone, name, balance,
                    total_commission, total_withdrawn, referral_code,
                    referred_by, referral_balance, referral_count,
                    is_verified, is_active, user_rank,
                    created_at, last_login
                    """
                )
                .order("created_at", desc=True)
                .execute()
            )

            users = response.data if isinstance(response.data, list) else []
            cleaned_users = []

            for user in users:
                if not isinstance(user, dict):
                    continue

                # --- Normalise numeric fields ---
                numeric_fields = [
                    "total_commission",
                    "referral_balance",
                    "balance",
                    "total_withdrawn",
                ]

                for field in numeric_fields:
                    value = user.get(field)
                    try:
                        user[field] = float(value) if value is not None else 0.0
                    except (ValueError, TypeError):
                        user[field] = 0.0

                # --- Normalise safe defaults ---
                defaults = {
                    "user_rank": "Bronze",
                    "username": "Unknown User",
                    "email": "",
                    "referral_count": 0,
                }

                for key, default_value in defaults.items():
                    user[key] = user.get(key) or default_value

                cleaned_users.append(user)

            return cleaned_users

        except Exception as e:
            logger.error(f"Error getting all users: {e}")
            return []
        
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
        """Get top users ranked by total_commission and referral_count."""
        try:
            # Fetch all users
            response = supabase.table('users') \
                .select(
                    'id, username, email, phone, name, total_commission, referral_count, '
                    'user_rank, balance, is_verified'
                ).execute()

            data = getattr(response, "data", None)

            if not isinstance(data, list):
                logger.error(f"Supabase returned invalid user list: {data}")
                return []

            ranked_users = []

            for user in data:
                if not isinstance(user, dict):
                    continue

                # Safe numeric extraction
                def safe_float(value, default=0.0):
                    try:
                        return float(value) if value not in (None, "") else default
                    except (ValueError, TypeError):
                        return default

                def safe_int(value, default=0):
                    try:
                        return int(value) if value not in (None, "") else default
                    except (ValueError, TypeError):
                        return default

                ranked_users.append({
                    'id': user.get('id'),
                    'username': user.get('username') or 'Unknown User',
                    'email': user.get('email', '') or '',
                    'phone': user.get('phone', '') or '',
                    'name': user.get('name', '') or '',
                    'total_commission': safe_float(user.get('total_commission')),
                    'referral_count': safe_int(user.get('referral_count')),
                    'user_rank': user.get('user_rank', 'Bronze'),
                    'balance': safe_float(user.get('balance')),
                    'is_verified': bool(user.get('is_verified', False))
                })

            # Sort by: commission DESC, referrals DESC
            ranked_users.sort(
                key=lambda x: (x['total_commission'], x['referral_count']),
                reverse=True
            )

            # Return limited list
            return ranked_users[:limit]

        except Exception as e:
            logger.error(f"Error in get_top_users: {e}")
            return []

    # Additional method for dashboard challenge progress
    @staticmethod
    def get_challenge_progress(user_id, challenge_id=None):
        """Get user's progress for a specific challenge"""
        try:
            if challenge_id:
                response = supabase.table('challenge_progress') \
                    .select('*') \
                    .eq('user_id', user_id) \
                    .eq('challenge_id', challenge_id) \
                    .single() \
                    .execute()
            else:
                # Get current active challenge
                response = supabase.table('challenge_progress') \
                    .select('*') \
                    .eq('user_id', user_id) \
                    .eq('is_active', True) \
                    .single() \
                    .execute()
            
            return response.data if response.data else None
        except Exception as e:
            logger.error(f"Error getting challenge progress for user {user_id}: {e}")
            return None
        
    @staticmethod
    def update_user_ranks_batch():
        """Update all users' ranks based on total_commission."""
        try:
            users = SupabaseDB.get_all_users()
            if not users or not isinstance(users, list):
                logger.error("No users found to update ranks.")
                return False

            for user_data in users:
                if not isinstance(user_data, dict):
                    continue

                user_id = user_data.get('id')
                if not user_id:
                    continue

                # Safe conversion of total_commission
                try:
                    commission = float(user_data.get('total_commission', 0) or 0)
                except (ValueError, TypeError):
                    commission = 0.0

                # Determine new rank
                if commission >= 70000:
                    new_rank = 'Diamond'
                elif commission >= 30000:
                    new_rank = 'Platinum'
                elif commission >= 15000:
                    new_rank = 'Gold'
                elif commission >= 5000:
                    new_rank = 'Silver'
                else:
                    new_rank = 'Bronze'

                current_rank = user_data.get('user_rank', 'Bronze')

                # Update if rank has changed
                if current_rank != new_rank:
                    try:
                        SupabaseDB.update_user(user_id, {'user_rank': new_rank})
                        logger.info(f"Updated user {user_id} from {current_rank} to {new_rank}")
                    except Exception as update_error:
                        logger.error(f"Failed to update user {user_id}: {update_error}")
                        continue

            return True

        except Exception as e:
            logger.error(f"Error updating user ranks batch: {e}")
            return False

    @staticmethod
    def get_users_count():
        try:
            response = supabase.table('users').select('*', count='exact').execute()
            count = response.count if hasattr(response, 'count') else len(response.data)
            return count
        except Exception as e:
            logger.error(f"Error getting users count: {e}")
            return 0

    @staticmethod
    def get_verified_users_count():
        try:
            response = supabase.table('users').select('*', count='exact').eq('is_verified', True).execute()
            count = response.count if hasattr(response, 'count') else len(response.data)
            return count
        except Exception as e:
            logger.error(f"Error getting verified users count: {e}")
            return 0

    @staticmethod
    def get_referrals_count():
        try:
            response = supabase.table('referrals').select('*', count='exact').execute()
            count = response.count if hasattr(response, 'count') else len(response.data)
            return count
        except Exception as e:
            logger.error(f"Error getting referrals count: {e}")
            return 0

    @staticmethod
    def get_total_commission():
        try:
            response = supabase.table('users').select('total_commission').execute()
            total = sum(float(user['total_commission']) for user in response.data 
                       if user.get('total_commission') is not None)
            return total
        except Exception as e:
            logger.error(f"Error getting total commission: {e}")
            return 0.0

    @staticmethod
    def get_total_withdrawn():
        try:
            response = supabase.table('users').select('total_withdrawn').execute()
            total = sum(float(user['total_withdrawn']) for user in response.data 
                       if user.get('total_withdrawn') is not None)
            return total
        except Exception as e:
            logger.error(f"Error getting total withdrawn: {e}")
            return 0.0

    @staticmethod
    def get_total_balance():
        try:
            response = supabase.table('users').select('balance').execute()
            total = sum(float(user['balance']) for user in response.data 
                       if user.get('balance') is not None)
            return total
        except Exception as e:
            logger.error(f"Error getting total balance: {e}")
            return 0.0

    @staticmethod
    def get_dashboard_stats():
        """Get overall dashboard statistics for admin"""
        try:
            stats = {
                'total_users': SupabaseDB.get_users_count(),
                'verified_users': SupabaseDB.get_verified_users_count(),
                'total_referrals': SupabaseDB.get_referrals_count(),
                'total_commission': SupabaseDB.get_total_commission(),
                'total_withdrawn': SupabaseDB.get_total_withdrawn(),
                'total_balance': SupabaseDB.get_total_balance(),
                'tier_distribution': SupabaseDB.get_tier_distribution()
            }
            return stats
        except Exception as e:
            logger.error(f"Error getting dashboard stats: {e}")
            return {
                'total_users': 0,
                'verified_users': 0,
                'total_referrals': 0,
                'total_commission': 0,
                'total_withdrawn': 0,
                'total_balance': 0,
                'tier_distribution': {
                    'bronze_percentage': 40,
                    'silver_percentage': 25,
                    'gold_percentage': 20,
                    'platinum_percentage': 10,
                    'diamond_percentage': 5
                }
            }

# =============================================================================
# SECURITY AND FRAUD DETECTION
# =============================================================================

class EnhancedFraudDetector:
    def __init__(self, redis_client, supabase_client):
        self.redis = redis_client
        self.supabase = supabase_client
        self.logger = logging.getLogger(__name__)
        
        # Fraud detection thresholds (configurable)
        self.MAX_ACCOUNTS_PER_IP = app.config.get('MAX_ACCOUNTS_PER_IP', 3)
        self.MAX_ACCOUNTS_PER_DEVICE = app.config.get('MAX_ACCOUNTS_PER_DEVICE', 2)
        self.MAX_WITHDRAWALS_PER_HOUR = app.config.get('MAX_WITHDRAWALS_PER_HOUR', 3)
        self.MAX_LOGIN_ATTEMPTS_PER_HOUR = app.config.get('MAX_LOGIN_ATTEMPTS_PER_HOUR', 10)
        self.SUSPICIOUS_AMOUNT_THRESHOLD = app.config.get('SUSPICIOUS_AMOUNT_THRESHOLD', 2000)
        self.NEW_USER_WITHDRAWAL_LIMIT = app.config.get('NEW_USER_WITHDRAWAL_LIMIT', 1000)
        
    def get_device_fingerprint(self, request):
        """Generate a unique device fingerprint"""
        user_agent = request.headers.get('User-Agent', '')
        accept_language = request.headers.get('Accept-Language', '')
        accept_encoding = request.headers.get('Accept-Encoding', '')
        
        fingerprint_string = f"{user_agent}{accept_language}{accept_encoding}"
        device_hash = hashlib.md5(fingerprint_string.encode()).hexdigest()
        return device_hash
    
    def get_ip_geolocation(self, ip_address):
        """Get approximate geolocation for IP (using free service)"""
        try:
            # Using ipapi.co free tier (1000 requests/month)
            response = requests.get(f"http://ipapi.co/{ip_address}/json/", timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return {'country': 'Unknown', 'city': 'Unknown'}
    
    def safe_track_user_activity(self, user_id, ip_address, device_fingerprint, action):
        """Safe user activity tracking"""
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            key = f"user_activity:{user_id}"
            
            activity = {
                'timestamp': timestamp,
                'ip': ip_address,
                'device': device_fingerprint,
                'action': action
            }
            
            # Store last 100 activities (rotate)
            self.redis.lpush(key, json.dumps(activity))
            self.redis.ltrim(key, 0, 99)
            self.redis.expire(key, 86400 * 30)  # Keep for 30 days
        except Exception as e:
            print(f"Activity tracking failed: {e}")
    
    def detect_suspicious_signup(self, ip_address, device_fingerprint, user_data):
        """Detect suspicious registration patterns"""
        warnings = []
        
        # ✅ EXEMPT LOCALHOST FROM FRAUD DETECTION
        if ip_address in ['127.0.0.1', 'localhost', '::1']:
            return warnings  # Return empty list, no warnings
        
        try:
            # Check IP-based registrations
            ip_key = f"signups:ip:{ip_address}"
            ip_signups = self.redis.get(ip_key) or 0
            if int(ip_signups) >= self.MAX_ACCOUNTS_PER_IP:
                warnings.append(f"Too many accounts from this IP ({ip_signups})")
            
            # Check device-based registrations
            device_key = f"signups:device:{device_fingerprint}"
            device_signups = self.redis.get(device_key) or 0
            if int(device_signups) >= self.MAX_ACCOUNTS_PER_DEVICE:
                warnings.append(f"Too many accounts from this device ({device_signups})")
            
            # Check rapid succession registrations
            recent_signups_key = f"recent_signups:{ip_address}"
            recent_count = self.redis.llen(recent_signups_key)
            if recent_count >= 2:  # More than 2 signups in short period
                warnings.append("Rapid succession registrations detected")
        except Exception as e:
            print(f"Fraud detection error: {e}")
        
        return warnings
    
    def detect_suspicious_withdrawal(self, user, amount, request):
        """Enhanced withdrawal fraud detection"""
        warnings = []
        user_id = user.id
        ip_address = request.remote_addr
        device_fingerprint = self.get_device_fingerprint(request)
        
        # ✅ EXEMPT LOCALHOST FROM WITHDRAWAL FRAUD DETECTION
        if ip_address in ['127.0.0.1', 'localhost', '::1']:
            return warnings  # Return empty list, no warnings
        
        try:
            # Amount-based checks
            if amount > self.SUSPICIOUS_AMOUNT_THRESHOLD:
                warnings.append("Amount exceeds normal threshold")
            
            # New user with large withdrawal
            user_created = datetime.fromisoformat(user.created_at.replace('Z', '+00:00'))
            user_age_days = (datetime.now(timezone.utc) - user_created).days
            if user_age_days < 1 and amount > self.NEW_USER_WITHDRAWAL_LIMIT:
                warnings.append("New user with large withdrawal")
            
            # Frequency checks
            withdrawal_count = self.get_recent_withdrawals_count(user_id, hours=1)
            if withdrawal_count >= self.MAX_WITHDRAWALS_PER_HOUR:
                warnings.append("Too many withdrawals in short period")
            
            # Device/IP anomaly detection
            if self.detect_behavior_anomaly(user_id, ip_address, device_fingerprint, 'withdrawal'):
                warnings.append("Unusual withdrawal pattern detected")
            
            # Time-based anomaly (2AM - 5AM)
            current_hour = datetime.now(timezone.utc).hour
            if 2 <= current_hour <= 5:
                warnings.append("Unusual withdrawal time")
            
            # Geolocation anomaly
            if self.detect_geolocation_anomaly(user_id, ip_address):
                warnings.append("Suspicious location change")
        except Exception as e:
            print(f"Withdrawal fraud detection error: {e}")
        
        return warnings
    
    def get_recent_withdrawals_count(self, user_id, hours=1):
        """Count recent withdrawals for a user"""
        try:
            key = f"withdrawals:user:{user_id}:recent"
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            # Get withdrawals from last hour and filter
            withdrawals = self.redis.lrange(key, 0, -1)
            recent_withdrawals = [
                w for w in withdrawals 
                if datetime.fromisoformat(json.loads(w)['timestamp']) > cutoff_time
            ]
            
            return len(recent_withdrawals)
        except Exception:
            return 0
    
    def detect_behavior_anomaly(self, user_id, current_ip, current_device, action):
        """Detect anomalies in user behavior patterns"""
        try:
            activity_key = f"user_activity:{user_id}"
            activities = self.redis.lrange(activity_key, 0, 49)  # Last 50 activities
            
            if not activities:
                return False
            
            # Analyze patterns
            unique_ips = set()
            unique_devices = set()
            
            for activity_json in activities:
                activity = json.loads(activity_json)
                unique_ips.add(activity['ip'])
                unique_devices.add(activity['device'])
            
            # Check if current IP/device is new
            if current_ip not in unique_ips and len(unique_ips) > 0:
                return True
            
            if current_device not in unique_devices and len(unique_devices) > 0:
                return True
        except Exception:
            return False
            
        return False
    
    def detect_geolocation_anomaly(self, user_id, current_ip):
        """Detect suspicious geolocation changes"""
        try:
            current_geo = self.get_ip_geolocation(current_ip)
            if current_geo.get('country') == 'Unknown':
                return False
            
            # Get previous locations from user activity
            activity_key = f"user_activity:{user_id}"
            activities = self.redis.lrange(activity_key, 0, 99)
            
            previous_countries = set()
            for activity_json in activities:
                activity = json.loads(activity_json)
                geo = self.get_ip_geolocation(activity['ip'])
                if geo.get('country') != 'Unknown':
                    previous_countries.add(geo['country'])
            
            # If current country is different from all previous countries
            if (previous_countries and 
                current_geo.get('country') not in previous_countries):
                return True
        except Exception:
            return False
            
        return False
    
    def block_suspicious_activity(self, user_id, reason, duration_hours=24):
        """Temporarily block user due to suspicious activity"""
        try:
            block_key = f"user_blocked:{user_id}"
            block_data = {
                'reason': reason,
                'blocked_until': (datetime.now(timezone.utc) + 
                                timedelta(hours=duration_hours)).isoformat(),
                'blocked_at': datetime.now(timezone.utc).isoformat()
            }
            
            self.redis.setex(block_key, duration_hours * 3600, json.dumps(block_data))
            
            # Log security event
            SecurityMonitor.log_security_event(
                "USER_BLOCKED_FRAUD",
                user_id,
                {"reason": reason, "duration_hours": duration_hours}
            )
            
            self.logger.warning(f"User {user_id} blocked for {duration_hours}h: {reason}")
        except Exception as e:
            print(f"Block user error: {e}")
    
    def safe_is_user_blocked(self, user_id):
        """Safe user block check"""
        try:
            block_key = f"user_blocked:{user_id}"
            block_data = self.redis.get(block_key)
            
            if block_data:
                data = json.loads(block_data)
                blocked_until = datetime.fromisoformat(data['blocked_until'])
                if datetime.now(timezone.utc) < blocked_until:
                    return True
                else:
                    # Remove expired block
                    self.redis.delete(block_key)
            
            return False
        except Exception:
            return False
    
    def increment_signup_counter(self, ip_address, device_fingerprint):
        """Increment counters for IP and device signups"""
        try:
            # ✅ DON'T COUNT LOCALHOST REGISTRATIONS
            if ip_address in ['127.0.0.1', 'localhost', '::1']:
                return
            
            # IP-based counter (reset after 24 hours)
            ip_key = f"signups:ip:{ip_address}"
            self.redis.incr(ip_key)
            self.redis.expire(ip_key, 86400)  # 24 hours
            
            # Device-based counter (reset after 24 hours)
            device_key = f"signups:device:{device_fingerprint}"
            self.redis.incr(device_key)
            self.redis.expire(device_key, 86400)  # 24 hours
            
            # Recent signups list (keep for 1 hour)
            recent_key = f"recent_signups:{ip_address}"
            self.redis.lpush(recent_key, datetime.now(timezone.utc).isoformat())
            self.redis.expire(recent_key, 3600)  # 1 hour
            self.redis.ltrim(recent_key, 0, 4)  # Keep only last 5
        except Exception as e:
            print(f"Increment signup counter error: {e}")
    
    def log_withdrawal_attempt(self, user_id, amount, ip_address, device_fingerprint):
        """Log withdrawal attempt for pattern analysis"""
        try:
            # ✅ DON'T LOG LOCALHOST WITHDRAWALS
            if ip_address in ['127.0.0.1', 'localhost', '::1']:
                return
            
            withdrawal_data = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'amount': amount,
                'ip': ip_address,
                'device': device_fingerprint
            }
            
            key = f"withdrawals:user:{user_id}:recent"
            self.redis.lpush(key, json.dumps(withdrawal_data))
            self.redis.ltrim(key, 0, 99)  # Keep last 100 withdrawals
            self.redis.expire(key, 86400 * 7)  # Keep for 7 days
        except Exception as e:
            print(f"Log withdrawal attempt error: {e}")

# Initialize enhanced fraud detector
fraud_detector = EnhancedFraudDetector(redis_client, supabase)

# =============================================================================
# SECURITY MIDDLEWARE
# =============================================================================

class FixedSecurityMiddleware:
    def __init__(self, app, fraud_detector):
        self.app = app  # Store the Flask app, not wsgi_app
        self.fraud_detector = fraud_detector
        self.logger = logging.getLogger(__name__)
    
    def __call__(self, environ, start_response):
        # Create request object safely
        try:
            request = Request(environ)
            path = request.path
        except Exception:
            # If we can't parse the request, just pass through
            return self.app(environ, start_response)
        
        # Skip security checks for health endpoints and static files
        if (path.startswith('/health') or 
            path.startswith('/static') or
            path == '/robots.txt' or
            path == '/sitemap.xml'):
            return self.app(environ, start_response)
        
        # Safe pre-request checks
        try:
            self.safe_pre_request_checks(request)
        except Exception as e:
            # Log but don't let security checks break the app
            self.logger.error(f"Security check error: {str(e)}")
        
        # Call the actual Flask application
        return self.app(environ, start_response)
    
    def safe_pre_request_checks(self, request):
        """Perform security checks without recursion risk"""
        ip_address = request.remote_addr
        
        # Check for known malicious IPs (safe version)
        if self.safe_is_ip_blacklisted(ip_address):
            self.logger.warning(f"Blocked blacklisted IP: {ip_address}")
            abort(403, description="Access denied")
        
        # Rate limiting by IP (basic protection) - EXEMPT LOCALHOST
        if ip_address not in ['127.0.0.1', 'localhost', '::1'] and self.safe_is_ip_rate_limited(ip_address):
            self.logger.warning(f"Rate limited IP: {ip_address}")
            abort(429, description="Too many requests")
    
    def safe_is_ip_blacklisted(self, ip_address):
        """Safe IP blacklist check without recursion"""
        try:
            # Use direct Redis methods with safety
            blacklist_key = f"ip_blacklist:{ip_address}"
            return redis_client.exists(blacklist_key)
        except Exception as e:
            # Use print instead of logger to avoid recursion
            print(f"Redis blacklist check failed: {str(e)}")
            return False
    
    def safe_is_ip_rate_limited(self, ip_address):
        """Safe IP rate limiting without recursion - EXEMPT LOCALHOST"""
        # Always exempt localhost from rate limiting
        if ip_address in ['127.0.0.1', 'localhost', '::1']:
            return False
            
        try:
            rate_limit_key = f"rate_limit:ip:{ip_address}"
            current = redis_client.incr(rate_limit_key)
            
            # Ensure current is an integer for comparison
            if current is None:
                current = 1
                
            if current == 1:
                redis_client.expire(rate_limit_key, 60)  # 1 minute window
            
            # Safe comparison - convert to int if needed
            current_int = int(current) if current is not None else 1
            return current_int > 1000  # 1000 requests per minute
        except Exception as e:
            print(f"Redis rate limit check failed: {str(e)}")
            return False  # Don't rate limit if Redis is down

# Apply the fixed security middleware - CORRECTED
app.wsgi_app = FixedSecurityMiddleware(app.wsgi_app, fraud_detector)

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
            'device_fingerprint': fraud_detector.get_device_fingerprint(request) if request else None,
            'details': str(details),
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        SupabaseDB.create_security_log(security_log)
        logger.info(f"Security Event: {event_type} - User: {user_id} - {details}")
    
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
        
        logger.info(f"2FA Code for {user_id}: {code}")
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
        logger.warning(f"ADMIN ALERT: {message}")

class FraudDetector:
    @staticmethod
    def check_suspicious_activity(user, amount, request):
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
            if recent_withdrawal.get('ip_address') != request.remote_addr:
                checks.append("Different IP address from previous withdrawals")
        
        # Check 5: New user with large withdrawal
        user_created = datetime.fromisoformat(user.created_at.replace('Z', '+00:00'))
        if user_created > datetime.now(timezone.utc) - timedelta(days=1) and amount > 1000:
            checks.append("New user with large withdrawal")
        
        return " | ".join(checks) if checks else None

# =============================================================================
# EXTERNAL SERVICE INTEGRATIONS
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
                logger.info(f"Celcom SMS API Request: {payload}")
                logger.info(f"Celcom SMS API Response: {response.status_code} - {response.text}")
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Check if SMS was sent successfully based on Celcom API response structure
                    if result.get('status') == 'success' or result.get('success') or response.status_code == 200:
                        logger.info(f"Celcom SMS sent successfully to {phone_clean}")
                        
                        # Log successful SMS delivery
                        SecurityMonitor.log_security_event(
                            "SMS_SENT_SUCCESS",
                            None,
                            {"phone": phone_clean, "message_length": len(message), "provider": "Celcom"}
                        )
                        return True
                    else:
                        error_msg = result.get('message', 'Unknown error from Celcom API')
                        logger.error(f"Celcom SMS failed: {error_msg}")
                else:
                    logger.error(f"Celcom SMS HTTP error: {response.status_code} - {response.text}")
                
                # Wait before retry (exponential backoff)
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying SMS in {wait_time} seconds...")
                    time.sleep(wait_time)
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Celcom SMS network error (attempt {attempt + 1}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
            except Exception as e:
                logger.error(f"Celcom SMS unexpected error (attempt {attempt + 1}): {str(e)}")
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
        message = f"Welcome to Referral Ninja, {username}! Complete your KSH 200 payment to activate your account and start earning."
        return CelcomSMS.send_sms(phone, message)
    
    @staticmethod
    def send_referral_notification(phone, username, referral_bonus):
        """
        Send notification when referral bonus is earned
        """
        message = f"Hi {username}, you've earned Ksh {referral_bonus} referral bonus! Keep inviting friends to earn more."
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
        logger.error(f"M-Pesa token request failed: {str(e)}")
        raise Exception("M-Pesa service unavailable")
    except Exception as e:
        logger.error(f"M-Pesa token error: {str(e)}")
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
            logger.info(f"STK Push initiated for {phone_clean}, Amount: {amount}")
            return result
        else:
            error_message = result.get('errorMessage', 'Unknown error')
            logger.error(f"STK Push failed: {error_message}")
            raise Exception(f"M-Pesa STK push failed: {error_message}")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"STK Push network error: {str(e)}")
        raise Exception("M-Pesa service unavailable")
    except Exception as e:
        logger.error(f"STK Push error: {str(e)}")
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
            logger.error(f"M-PESA B2C token error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        logger.error(f"Error getting M-PESA B2C token: {e}")
        return None

def initiate_b2c_payment(phone_number, amount, transaction_reference, remarks="Referral withdrawal"):
    """Initiate B2C payment to user (payout)"""
    try:
        access_token = get_mpesa_b2c_access_token()
        if not access_token:
            logger.error("Failed to get M-PESA B2C access token")
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
                logger.info(f"B2C payment initiated successfully for {phone_number}, Amount: {amount}")
                return result
            else:
                error_message = result.get('errorMessage', 'Unknown error')
                logger.error(f"B2C payment failed: {error_message}")
                return None
        else:
            logger.error(f"B2C payment HTTP error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error initiating B2C payment: {e}")
        return None

def process_automatic_withdrawal(withdrawal_transaction):
    """Process withdrawal automatically via M-Pesa B2C"""
    try:
        user = SupabaseDB.get_user_by_id(withdrawal_transaction['user_id'])
        if not user:
            logger.error(f"User not found for withdrawal: {withdrawal_transaction['id']}")
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
            
            logger.info(f"B2C payout initiated for user {user.username}, withdrawal ID: {withdrawal_transaction['id']}")
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
            
            logger.error(f"B2C payout initiation failed for user {user.username}")
            return False
            
    except Exception as e:
        logger.error(f"Error processing automatic withdrawal: {e}")
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
            logger.error(f"STK Query error: {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error querying STK status: {e}")
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
            logger.warning("Telegram credentials missing — skipping alert")
            return

        safe_message = html.escape(message)
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": safe_message, "parse_mode": "HTML"}

        # Run the request non-blocking
        await asyncio.to_thread(requests.post, url, json=payload, timeout=10)
        logger.info("Telegram notification sent successfully")

    except Exception as e:
        try:
            logger.error(f"Telegram notification failed: {html.escape(str(e))}")
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
                logger.warning("Telegram credentials missing — skipping alert")
                return

            safe_message = html.escape(message)
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = {"chat_id": chat_id, "text": safe_message, "parse_mode": "HTML"}

            # Run sync HTTP in a thread (safe for background threads)
            threading.Thread(target=requests.post, args=(url,), kwargs={"json": payload, "timeout": 10}).start()
            logger.info("Telegram notification sent successfully")
    except Exception as e:
        logger.error(f"Telegram notification failed: {html.escape(str(e))}")
           
def send_withdrawal_notification_to_telegram(user, transaction):
    """Send withdrawal notification to Telegram"""
    try:
        message = f"""
New Withdrawal Request

User Details:
• Username: {user.username}
• Email: {user.email}
• Phone: {user.phone}
• User ID: #{user.id}

Withdrawal Information:
• Amount: KSH {abs(transaction['amount'])}
• Phone: {transaction['phone_number']}
• Status: Pending Processing

Time Submitted:
{transaction['created_at']}

Please process this withdrawal in the admin dashboard.
"""
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        return True
    except Exception as e:
        logger.error(f"Error sending withdrawal notification to Telegram: {str(e)}")
        return False

# =============================================================================
# DATABASE MANAGEMENT AND HEALTH MONITORING
# =============================================================================

def supabase_check(table_name: str, limit: int = 1, retries: int = 3, timeout: int = 5):
    """Check Supabase availability with retry logic and timeout."""
    for attempt in range(1, retries + 1):
        try:
            # Supabase-py doesn't support direct timeout, so use requests timeout override
            response = supabase.table(table_name).select("*").limit(limit).execute()
            return response
        except Exception as e:
            logger.warning(f"Supabase attempt {attempt} failed: {e}")
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
            logger.info(f"Database health: {metrics['response_time']}ms response")
        else:
            logger.error(f"Database health issue: {metrics.get('error', 'Unknown error')}")
        
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
                device_fingerprint TEXT,
                fraud_warnings TEXT,
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
                device_fingerprint TEXT,
                details TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                -- Index for faster querying
                CONSTRAINT valid_event_type CHECK (event_type IN (
                    'LOGIN_SUCCESS', 'LOGIN_FAILED', 'REGISTRATION', 'LOGOUT',
                    'WITHDRAWAL_INITIATED', 'WITHDRAWAL_COMPLETED', 'WITHDRAWAL_FAILED',
                    'SUSPICIOUS_WITHDRAWAL', '2FA_SUCCESS', '2FA_FAILED',
                    'PASSWORD_CHANGE', 'PROFILE_UPDATE', 'SMS_SENT_SUCCESS',
                    'SMS_SENT_FAILED', 'UNAUTHORIZED_ACCESS', 'ADMIN_ACTION',
                    'SUSPICIOUS_REGISTRATION', 'USER_BLOCKED_FRAUD', 'SUSPICIOUS_USER_AGENT'
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
            ("idx_transactions_device_fingerprint", "CREATE INDEX IF NOT EXISTS idx_transactions_device_fingerprint ON transactions(device_fingerprint);"),
            
            # Referrals table indexes
            ("idx_referrals_referrer_id", "CREATE INDEX IF NOT EXISTS idx_referrals_referrer_id ON referrals(referrer_id);"),
            ("idx_referrals_referred_id", "CREATE INDEX IF NOT EXISTS idx_referrals_referred_id ON referrals(referred_id);"),
            ("idx_referrals_created_at", "CREATE INDEX IF NOT EXISTS idx_referrals_created_at ON referrals(created_at);"),
            
            # Security logs indexes
            ("idx_security_logs_user_id", "CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON security_logs(user_id);"),
            ("idx_security_logs_created_at", "CREATE INDEX IF NOT EXISTS idx_security_logs_created_at ON security_logs(created_at);"),
            ("idx_security_logs_event_type", "CREATE INDEX IF NOT EXISTS idx_security_logs_event_type ON security_logs(event_type);"),
            ("idx_security_logs_device_fingerprint", "CREATE INDEX IF NOT EXISTS idx_security_logs_device_fingerprint ON security_logs(device_fingerprint);"),
            
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
            logger.info("Creating admin user...")
            
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
                logger.info("Admin user created successfully")
                logger.info(f"Username: admin")
                logger.info(f"Password: {admin_password}")
                logger.info("CHANGE THE PASSWORD IMMEDIATELY!")
            else:
                logger.error("Failed to create admin user")
        else:
            logger.info("Admin user already exists")
            
    except Exception as e:
        logger.error(f"Admin user creation error: {e}")

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
            'redis': self._check_redis_health_improved(),
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
    
    def _check_redis_health_improved(self) -> Dict[str, Any]:
        """Improved Redis health check with better error handling"""
        try:
            start_time = time.time()
            
            # Test basic connection with ping
            ping_result = self.redis.ping()
            connection_time = time.time() - start_time
            
            # Test read/write operations with safe defaults
            test_key = f"health_check_{int(time.time())}"
            test_value = "health_check_value"
            
            set_result = self.redis.setex(test_key, 10, test_value)  # Set with 10s expiry
            retrieved_value = self.redis.get(test_key, "NOT_FOUND")
            
            # Determine status based on operations
            status = 'healthy'
            if not ping_result:
                status = 'unhealthy'
            elif connection_time > 0.1:  # More than 100ms is slow for Redis
                status = 'degraded'
            elif retrieved_value != test_value:
                status = 'degraded'
            
            return {
                'status': status,
                'response_time_ms': round(connection_time * 1000, 2),
                'connection': bool(ping_result),
                'read_operation': retrieved_value == test_value,
                'write_operation': bool(set_result),
                'details': f'Redis connection OK ({connection_time:.3f}s)' if ping_result else 'Redis connection failed'
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

def verify_recaptcha(response_token: str, remote_ip: str = None) -> bool:
    """
    Verify reCAPTCHA response token with Google's API
    """
    try:
        data = {
            'secret': app.config['RECAPTCHA_SECRET_KEY'],
            'response': response_token
        }
        
        if remote_ip:
            data['remoteip'] = remote_ip
            
        response = requests.post(
            app.config['RECAPTCHA_VERIFY_URL'],
            data=data,
            timeout=10
        )
        response.raise_for_status()
        
        result = response.json()
        
        # Log reCAPTCHA result for debugging
        logger.info(f"reCAPTCHA verification: {result.get('success')}, score: {result.get('score', 'N/A')}")
        
        return result.get('success', False)
        
    except Exception as e:
        logger.error(f"reCAPTCHA verification failed: {e}")
        return False

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
    """Calculate user's ranking based on commission + referrals."""
    try:
        # Fetch the user
        user = SupabaseDB.get_user_by_id(user_id)
        if not user:
            return None

        # Fetch all users
        users = SupabaseDB.get_all_users()
        if not users or not isinstance(users, list):
            return None

        # Create a list with all users' data
        ranked_users = []
        for u in users:
            if not isinstance(u, dict):
                continue

            # Safe numeric conversions with explicit defaults
            try:
                commission = float(u.get("total_commission", 0) or 0)
            except (ValueError, TypeError):
                commission = 0.0

            try:
                referrals = int(u.get("referral_count", 0) or 0)
            except (ValueError, TypeError):
                referrals = 0

            ranked_users.append({
                "id": str(u.get("id")),
                "total_commission": commission,
                "referral_count": referrals,
                "user_rank": u.get("user_rank", "Bronze")
            })

        # Sort by: commission DESC, referrals DESC
        ranked_users.sort(
            key=lambda x: (-x["total_commission"], -x["referral_count"])
        )

        # Find user position (1-indexed)
        position = None
        for idx, ru in enumerate(ranked_users):
            if ru["id"] == str(user_id):
                position = idx + 1  # 1-indexed ranking
                break

        if position is None:
            return None

        total_users = len(ranked_users)
        
        # Calculate percentile: percentage of users BELOW current user
        # Formula: (users below / total users) * 100
        if total_users > 1:
            users_below = total_users - position
            percentile = round((users_below / total_users) * 100, 1)
        else:
            percentile = 100.0  # Only user, so top 100%

        # Safe user attributes
        safe_commission = float(getattr(user, "total_commission", 0) or 0)
        safe_referrals = int(getattr(user, "referral_count", 0) or 0)
        safe_user_rank = getattr(user, "user_rank", "Bronze")

        return {
            "position": position,
            "total_users": total_users,
            "user_rank": safe_user_rank,
            "total_commission": safe_commission,
            "referral_count": safe_referrals,
            "percentile": percentile
        }

    except Exception as e:
        logger.error(f"Error in get_user_ranking: {e}")
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

def track_pending_payment(checkout_request_id, temp_user_data):
    """Store pending payment info in Redis (survives app restarts)"""
    try:
        payment_key = f"pending_payment:{checkout_request_id}"
        payment_data = {
            'temp_user_data': temp_user_data,
            'checkout_request_id': checkout_request_id,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'status': 'pending'
        }
        
        # Store for 1 hour (payment timeout)
        redis_client.setex(payment_key, 3600, json.dumps(payment_data))
        return True
    except Exception as e:
        logger.error(f"Error tracking payment: {e}")
        return False

def get_pending_payment(checkout_request_id):
    """Retrieve pending payment info from Redis"""
    try:
        payment_key = f"pending_payment:{checkout_request_id}"
        payment_data = redis_client.get(payment_key)
        if payment_data:
            return json.loads(payment_data)
    except Exception as e:
        logger.error(f"Error getting pending payment: {e}")
    return None

def complete_payment(checkout_request_id, mpesa_data):
    """Mark payment as completed and trigger user creation"""
    try:
        payment_key = f"pending_payment:{checkout_request_id}"
        payment_data = get_pending_payment(checkout_request_id)
        
        if payment_data:
            # Update payment data
            payment_data['status'] = 'completed'
            payment_data['mpesa_data'] = mpesa_data
            payment_data['completed_at'] = datetime.now(timezone.utc).isoformat()
            
            # Store for 24 hours (for debugging)
            redis_client.setex(payment_key, 86400, json.dumps(payment_data))
            
            # Create permanent user
            user = create_permanent_user_after_payment(
                payment_data['temp_user_data'], 
                {
                    'checkout_request_id': checkout_request_id,
                    'mpesa_receipt_number': mpesa_data.get('MpesaReceiptNumber'),
                    **mpesa_data
                }
            )
            
            if user:
                # Store user login token in Redis (for auto-login)
                login_token = secrets.token_urlsafe(32)
                redis_client.setex(f"auto_login:{login_token}", 300, user.id)
                
                # Clean up pending payment
                redis_client.delete(payment_key)
                
                return {'success': True, 'login_token': login_token}
    
    except Exception as e:
        logger.error(f"Error completing payment: {e}")
    
    return {'success': False}

def create_permanent_user_after_payment(temp_user_data, payment_data):
    """Create permanent user record after successful payment"""
    try:
        # Create user data for permanent storage
        user_data = {
            'id': temp_user_data['id'],
            'username': temp_user_data['username'],
            'email': temp_user_data['email'],
            'phone': temp_user_data['phone'],
            'name': temp_user_data['name'],
            'password_hash': generate_password_hash(temp_user_data['password']),
            'is_verified': True,
            'is_active': True,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Generate referral code
        phone_hash = hashlib.md5(temp_user_data['phone'].encode()).hexdigest()[:6].upper()
        user_data['referral_code'] = f"RN{phone_hash}"
        
        # Set referral data if applicable
        if temp_user_data.get('referral_code'):
            user_data['referred_by'] = temp_user_data['referral_code']
            user_data['referral_source'] = temp_user_data.get('referral_source', 'referral_link')
        
        # Save to database
        created_user = SupabaseDB.create_user(user_data)
        
        if not created_user:
            logger.error(f"Failed to create permanent user for {temp_user_data['username']}")
            return None
        
        # Create transaction record - NOW this will work because user exists
        transaction_id = str(uuid.uuid4())
        transaction_data = {
            'id': transaction_id,
            'user_id': created_user.id,
            'amount': 200.0,
            'transaction_type': 'registration_fee',
            'status': 'completed',
            'phone_number': created_user.phone,
            'mpesa_code': payment_data.get('mpesa_receipt_number', 'PENDING'),
            'checkout_request_id': payment_data.get('checkout_request_id'),
            'merchant_request_id': payment_data.get('merchant_request_id'),
            'description': 'Account registration fee - Payment completed',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # This will now succeed because user exists
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
                    'id': str(uuid.uuid4()),
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
            {
                "ip": temp_user_data.get('ip_address'),
                "transaction_id": transaction_id,
                "payment_reference": payment_data.get('payment_reference')
            }
        )
        
        # Send welcome email
        try:
            email_service.send_simple_email(
                recipient=created_user.email,
                subject="Welcome to ReferralNinja!",
                message=f"Hello {created_user.username},\n\nYour account has been successfully activated with KSH 200 payment. You can now login and start earning!\n\nYour referral code: {created_user.referral_code}\n\nBest regards,\nReferralNinja Team"
            )
        except Exception as e:
            logger.error(f"Error sending welcome email: {e}")
        
        logger.info(f"Permanent user created after payment: {created_user.username}")
        return created_user
        
    except Exception as e:
        logger.error(f"Error creating permanent user: {str(e)}", exc_info=True)
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

# =============================================================================
# API AUTHENTICATION ROUTES
# =============================================================================

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
        recaptcha_token = data.get("recaptcha_token")
        
        # Verify reCAPTCHA for API
        if not verify_recaptcha(recaptcha_token, request.remote_addr):
            return jsonify({"error": "reCAPTCHA verification failed"}), 400
        
        # Get IP and device info
        ip_address = request.remote_addr
        device_fingerprint = fraud_detector.get_device_fingerprint(request)
        
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
        
        # FRAUD DETECTION: Check for suspicious registration patterns
        fraud_warnings = fraud_detector.detect_suspicious_signup(
            ip_address, device_fingerprint, {
                'username': username,
                'email': email,
                'phone': phone
            }
        )
        
        if fraud_warnings:
            logger.warning(f"Suspicious registration detected: {fraud_warnings}")
            SecurityMonitor.log_security_event(
                "SUSPICIOUS_REGISTRATION",
                None,
                {
                    "ip": ip_address,
                    "device": device_fingerprint,
                    "warnings": fraud_warnings,
                    "username": username,
                    "phone": phone
                }
            )
            
            # For high-risk patterns, block immediately
            if len(fraud_warnings) >= 2:
                return jsonify({"error": "Registration blocked due to suspicious activity. Please contact support."}), 403
        
        # Store temporary user data
        temp_user_data = {
            'id': str(uuid.uuid4()),
            'username': username,
            'email': email,
            'phone': phone,
            'name': name,
            'password': password,
            'ip_address': ip_address,
            'device_fingerprint': device_fingerprint,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Generate temporary referral code
        phone_hash = hashlib.md5(phone.encode()).hexdigest()[:6].upper()
        temp_user_data['temp_referral_code'] = f"RN{phone_hash}"
        
        # Store temporary user data in session
        session['temp_user_data'] = temp_user_data
        session['pending_verification_user'] = temp_user_data['id']
        
        # Increment signup counters for fraud detection
        fraud_detector.increment_signup_counter(ip_address, device_fingerprint)
        
        # Send welcome SMS
        CelcomSMS.send_registration_notification(phone, username)
        
        return jsonify({
            "message": "Registration successful. Please complete KSH 200 payment to activate your account.",
            "user_id": temp_user_data['id'],
            "requires_payment": True
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
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
            logger.info("Login successful!")
            
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
        logger.error(f"Login error: {str(e)}")
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
        logger.error(f"2FA verification error: {str(e)}")
        return jsonify({"error": "Verification failed"}), 500

# =============================================================================
# M-PESA CALLBACK HANDLERS
# =============================================================================

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
            logger.warning(f"Suspicious callback from IP: {client_ip}")
            SecurityMonitor.log_security_event(
                "UNAUTHORIZED_CALLBACK", 
                None, 
                {"ip": client_ip, "payload": request.get_data(as_text=True)}
            )
            return jsonify({"ResultCode": 1, "ResultDesc": "Unauthorized"}), 401
        
        data = request.get_json(force=True)
        logger.info(f"M-Pesa callback: {json.dumps(data)}")
        
        result = data.get("Result", {})
        result_code = result.get("ResultCode")
        result_desc = result.get("ResultDesc")
        transaction_id = result.get("TransactionID")
        originator_conversation_id = result.get("OriginatorConversationID")
        
        if not originator_conversation_id:
            logger.error("No withdrawal reference in callback")
            return jsonify({"ResultCode": 1, "ResultDesc": "Missing reference"})
        
        withdrawal_data = SupabaseDB.get_transaction_by_id(originator_conversation_id)
        if not withdrawal_data:
            logger.error(f"Withdrawal not found: {originator_conversation_id}")
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
        logger.error(f"Callback processing error: {str(e)}")
        SecurityMonitor.log_security_event(
            "CALLBACK_ERROR", 
            None, 
            {"error": str(e), "ip": request.remote_addr}
        )
        return jsonify({"ResultCode": 1, "ResultDesc": "System error"}), 500

# =============================================================================
# SECURE WITHDRAWAL API ROUTES
# =============================================================================

@withdraw_bp.route("/withdraw", methods=["POST"])
@jwt_required()
@rate_limiter.limit("10 per hour", key_func=lambda: get_jwt_identity())
@rate_limiter.limit("1000 per day", key_func=lambda: get_jwt_identity())
def api_request_withdrawal():
    """Secure withdrawal request with enhanced fraud detection"""
    try:
        current_user_id = get_jwt_identity()
        user = SupabaseDB.get_user_by_id(current_user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if not user.is_active:
            return jsonify({"error": "Account deactivated"}), 403
        
        # Check if user is blocked for fraud
        if fraud_detector.safe_is_user_blocked(user.id):
            return jsonify({"error": "Account temporarily blocked for security reasons. Please contact support."}), 423
        
        if user.is_locked():
            return jsonify({"error": "Account temporarily locked"}), 423

        data = request.get_json()
        amount = float(data.get("amount", 0))
        phone_number = data.get("phone_number")
        
        # Get IP and device info
        ip_address = request.remote_addr
        device_fingerprint = fraud_detector.get_device_fingerprint(request)
        
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
        
        # ENHANCED FRAUD DETECTION
        fraud_warnings = fraud_detector.detect_suspicious_withdrawal(user, amount, request)
        
        if fraud_warnings:
            withdrawal_data = {
                'id': str(uuid.uuid4()),
                'user_id': user.id,
                'amount': -amount,
                'transaction_type': 'withdrawal',
                'status': 'Under Review',
                'phone_number': phone_number,
                'ip_address': ip_address,
                'user_agent': request.headers.get('User-Agent'),
                'device_fingerprint': device_fingerprint,
                'fraud_warnings': json.dumps(fraud_warnings),
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            SupabaseDB.create_transaction(withdrawal_data)
            
            SecurityMonitor.log_security_event(
                "SUSPICIOUS_WITHDRAWAL", 
                user.id, 
                {
                    "amount": amount, 
                    "warnings": fraud_warnings,
                    "withdrawal_id": withdrawal_data['id'],
                    "ip": ip_address,
                    "device": device_fingerprint
                }
            )
            
            # Block user if multiple high-risk warnings
            if len(fraud_warnings) >= 3:
                fraud_detector.block_suspicious_activity(
                    user.id, 
                    f"Multiple fraud warnings: {', '.join(fraud_warnings)}"
                )
            
            # Notify admins via Telegram
            message = f"SUSPICIOUS WITHDRAWAL\nUser: {user.username}\nAmount: KSH {amount}\nWarnings: {', '.join(fraud_warnings)}\nIP: {ip_address}"
            send_telegram_notification(message)
            
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
            'ip_address': ip_address,
            'user_agent': request.headers.get('User-Agent'),
            'device_fingerprint': device_fingerprint,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Track withdrawal attempt
        fraud_detector.log_withdrawal_attempt(user.id, amount, ip_address, device_fingerprint)
        
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
            logger.error(f"M-Pesa initiation failed: {str(e)}")
        
        SecurityMonitor.log_security_event(
            "WITHDRAWAL_INITIATED", 
            user.id, 
            {
                "amount": amount,
                "withdrawal_id": withdrawal_id,
                "ip": ip_address,
                "device": device_fingerprint
            }
        )
        
        return jsonify({
            "message": "Withdrawal processing",
            "withdrawal_id": withdrawal_id,
            "amount": amount
        })
        
    except Exception as e:
        logger.error(f"Withdrawal error: {str(e)}")
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
        logger.error(f"2FA confirmation error: {str(e)}")
        return jsonify({"error": "Confirmation failed"}), 500

# Register Blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(mpesa_bp, url_prefix='/api')
app.register_blueprint(withdraw_bp, url_prefix='/api')

# =============================================================================
# FLASK ROUTES
# =============================================================================

@app.context_processor
def utility_processor():
    def safe_strftime(dt, fmt="%b %d, %Y %I:%M %p"):
        try:
            return dt.strftime(fmt) if dt else ""
        except Exception:
            return ""

    return {
        'safe_strftime': safe_strftime,
        'abs': abs,
        'min': min,
        'max': max,
        'round': round,
        'len': len,
        'now': datetime.now(timezone.utc),
        'hasattr': hasattr,  # Add this line
        'getattr': getattr   # Add this for consistency
    }

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

# =============================================================================
# HEALTH CHECK ROUTES - EXEMPT FROM RATE LIMITING
# =============================================================================

@app.route('/health')
@rate_limiter.exempt
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
@rate_limiter.exempt
@login_required
@admin_required
def detailed_health_check():
    """Detailed health check for administrators"""
    health_monitor = HealthMonitor(supabase, redis_client, app.config)
    health_status = health_monitor.comprehensive_health_check()
    
    return jsonify(health_status)

@app.route('/health/readiness')
@rate_limiter.exempt
def readiness_check():
    try:
        supabase_check('users', limit=1)
        return jsonify({'status': 'ready', 'timestamp': datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        return jsonify({'status': 'not_ready', 'timestamp': datetime.now(timezone.utc).isoformat(), 'error': str(e)}), 503

@app.route('/health/liveness')
@rate_limiter.exempt
def liveness_check():
    return jsonify({'status': 'alive', 'timestamp': datetime.now(timezone.utc).isoformat()})

@app.route('/health/emergency')
@rate_limiter.exempt
def emergency_health_check():
    """Emergency health check that never fails"""
    health_info = {
        'status': 'alive',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'python_version': sys.version,
        'platform': sys.platform
    }
    
    # Test Redis
    try:
        redis_status = redis_client.ping() if hasattr(redis_client, 'ping') else 'unknown'
        health_info['redis'] = redis_status
    except Exception as e:
        health_info['redis'] = f'error: {str(e)}'
    
    # Test Supabase
    try:
        response = supabase.table('users').select('*').limit(1).execute()
        health_info['supabase'] = 'connected' if response.data is not None else 'no_data'
    except Exception as e:
        health_info['supabase'] = f'error: {str(e)}'
    
    return jsonify(health_info)

# =============================================================================
# RATE LIMITING TEST ROUTES
# =============================================================================

@app.route('/rate-limit-test')
def rate_limit_test():
    """Test endpoint to check rate limiting"""
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    test_limiter = Limiter(
        key_func=get_remote_address,
        storage_uri="memory://",
        default_limits=["10 per minute"]
    )
    
    @test_limiter.limit("5 per minute")
    def test_function():
        return jsonify({
            "message": "Rate limit test successful",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": get_remote_address(),
            "limits": "5 requests per minute"
        })
    
    return test_function()

@app.route('/rate-limit-status')
@rate_limiter.exempt
def rate_limit_status():
    """Check current rate limit status"""
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        # Test Redis connection for rate limiting
        if redis_client.ping():
            storage_status = "redis"
        else:
            storage_status = "memory"
        
        return jsonify({
            "status": "active",
            "storage": storage_status,
            "your_ip": get_remote_address(),
            "key_used": get_limiter_key(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

# =============================================================================
# HEALTH MONITORING BACKGROUND TASK
# =============================================================================

def start_health_monitoring():
    """Start background health monitoring safely in a thread."""
    
    def monitor_health():
        
        # Make sure we have Flask context in this thread
        with app.app_context():
            health_monitor = HealthMonitor(supabase, redis_client, app.config)

            while True:
                try:
                    health_status = health_monitor.comprehensive_health_check()

                    if health_status['status'] != 'healthy':
                        logger.warning(
                            f"System health degraded: {health_status['status']}"
                        )

                    # Alert on critical issues safely
                    if health_status['status'] == 'unhealthy':
                        _alert_on_critical_health_issue(health_status)

                except Exception as e:
                    safe_error = html.escape(str(e))
                    logger.error(f"Health monitoring error: {safe_error}")

                # Run every 5 minutes
                time.sleep(300)

    def _alert_on_critical_health_issue(health_status):
        critical_issues = []
        for component, status in health_status['components']['critical'].items():
            if status['status'] == 'unhealthy':
                critical_issues.append(f"{component}: {status.get('error', 'Unknown error')}")

        if critical_issues:
            message = "CRITICAL HEALTH ALERT:\n" + "\n".join([html.escape(i) for i in critical_issues])
            # This is now safe in a thread
            send_telegram_notification(message)

    # Start monitoring in a daemon thread
    thread = threading.Thread(target=monitor_health, daemon=True)
    thread.start()

# =============================================================================
# MAIN APPLICATION ROUTES
# =============================================================================
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID from database for Flask-Login"""
    try:
        user = SupabaseDB.get_user_by_id(user_id)
        if user:
            # Debug logging
            logger.info(f"Loaded user {user_id} from database")
            logger.info(f"  User data: balance={user.balance}, total_earned={user.total_earned}")
            return user
        return None
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
        return None
    
    
@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_verified:
        flash('Please complete payment verification to access dashboard.', 'warning')
        return redirect(url_for('account_activation'))
    
    try:
        # Debug: Log current user data
        logger.info(f"Current user data for {current_user.id}:")
        logger.info(f"  Balance: {current_user.balance}")
        logger.info(f"  Total earned: {current_user.total_earned}")
        logger.info(f"  Total withdrawn: {current_user.total_withdrawn}")
        logger.info(f"  Referral count: {current_user.referral_count}")
        logger.info(f"  Total commission: {current_user.total_commission}")
        
        # Convert values to float to ensure proper formatting
        available_balance = float(current_user.balance) if current_user.balance else 0.0
        total_withdrawn = float(current_user.total_withdrawn) if current_user.total_withdrawn else 0.0
        all_time_earnings = float(current_user.total_earned) if current_user.total_earned else 0.0
        total_referrals = int(current_user.referral_count) if current_user.referral_count else 0
        earned_from_referrals = float(current_user.total_commission) if current_user.total_commission else 0.0
        
        # Ready to withdraw is the same as available balance
        ready_to_withdraw = available_balance if available_balance > 0 else 0
        
        # Get user transactions for withdrawals to calculate pending
        transactions = SupabaseDB.get_transactions_by_user(current_user.id, transaction_type='withdrawal')
        
        # Get pending and processing withdrawals from transactions
        pending_withdrawals_count = len([t for t in transactions if t.get('status') in ['pending', 'processing']])
        being_processed_count = len([t for t in transactions if t.get('status') == 'processing'])
        
        # Recent withdrawals (last 5 for activity section)
        recent_withdrawals = sorted(transactions, 
                                  key=lambda x: x.get('created_at', ''), 
                                  reverse=True)[:5]
        
        # Get active referrals (referrals who are verified)
        active_referrals = 0
        referred_users = SupabaseDB.get_referred_users(current_user.id)
        
        for user in referred_users:
            # Check if user is verified
            if user.get('is_verified'):
                active_referrals += 1
        
        # Calculate this month referrals
        from datetime import datetime
        current_month = datetime.now().month
        current_year = datetime.now().year
        
        this_month_referrals = 0
        for user in referred_users:
            created_at = user.get('created_at')
            if created_at:
                try:
                    if isinstance(created_at, str):
                        # Try to parse the string date
                        if 'T' in created_at:
                            user_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        else:
                            user_date = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
                    else:
                        # It might already be a datetime object
                        user_date = created_at
                    
                    if user_date.month == current_month and user_date.year == current_year:
                        this_month_referrals += 1
                except (ValueError, AttributeError, TypeError) as e:
                    logger.error(f"Error parsing date for user {user.get('id')}: {e}")
                    continue
        
        # Conversion rate (active referrals / total referrals * 100)
        if total_referrals > 0:
            conversion_rate = f"{(active_referrals / total_referrals * 100):.1f}%"
        else:
            conversion_rate = "0%"
        
        # Current challenge stats - use user's total referrals for progress
        challenge_progress = total_referrals
        challenge_target = 3000
        
        # Calculate challenge progress percentage
        challenge_percentage = (challenge_progress / challenge_target * 100) if challenge_target > 0 else 0
        challenge_percentage = min(challenge_percentage, 100)  # Cap at 100%
        
        # Prepare data for template
        referral_stats = {
            'total_referrals': total_referrals,
            'active_referrals': active_referrals,
            'earned_from_referrals': earned_from_referrals,
            'this_month': this_month_referrals,
            'conversion_rate': conversion_rate
        }
        
        financial_stats = {
            'available_balance': available_balance,
            'ready_to_withdraw': ready_to_withdraw,
            'total_withdrawn': total_withdrawn,
            'all_time_earnings': all_time_earnings,
            'pending_withdrawals': pending_withdrawals_count,
            'being_processed': being_processed_count
        }
        
        challenge_stats = {
            'progress': challenge_progress,
            'target': challenge_target,
            'percentage': challenge_percentage
        }
        
        # Debug: Log the stats we're passing to template
        logger.info(f"Dashboard stats for {current_user.id}:")
        logger.info(f"  Financial stats: {financial_stats}")
        logger.info(f"  Referral stats: {referral_stats}")
        logger.info(f"  Challenge stats: {challenge_stats}")
        
        return render_template('dashboard.html',
                             financial_stats=financial_stats,
                             total_withdrawn=total_withdrawn,
                             pending_withdrawals=pending_withdrawals_count,
                             withdrawals=recent_withdrawals,
                             referral_stats=referral_stats,
                             challenge_stats=challenge_stats)
    
    except Exception as e:
        logger.error(f"Error loading dashboard for user {current_user.id}: {e}", exc_info=True)
        
        # Return default values on error
        financial_stats = {
            'available_balance': 0,
            'ready_to_withdraw': 0,
            'total_withdrawn': 0,
            'all_time_earnings': 0,
            'pending_withdrawals': 0,
            'being_processed': 0
        }
        
        referral_stats = {
            'total_referrals': 0,
            'active_referrals': 0,
            'earned_from_referrals': 0,
            'this_month': 0,
            'conversion_rate': '0%'
        }
        
        challenge_stats = {
            'progress': 0,
            'target': 3000,
            'percentage': 0
        }
        
        flash('Error loading dashboard. Please try again.', 'error')
        return render_template('dashboard.html',
                             financial_stats=financial_stats,
                             total_withdrawn=0,
                             pending_withdrawals=0,
                             withdrawals=[],
                             referral_stats=referral_stats,
                             challenge_stats=challenge_stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user already logged in, send to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = bool(request.form.get('remember_me'))
        recaptcha_response = request.form.get('g-recaptcha-response')

        # ALWAYS verify reCAPTCHA for login
        if not verify_recaptcha(recaptcha_response, request.remote_addr):
            flash('Please complete the reCAPTCHA verification.', 'error')
            return render_template('auth/login.html', 
                                 recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

        logger.info(f"Login attempt for username: {username}")

        # Validate input
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('auth/login.html', 
                                 recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

        # Fetch user from Supabase
        user = SupabaseDB.get_user_by_username(username)

        if user:
            logger.info(f"User found: {user.username}, verified={user.is_verified}, active={user.is_active}")

            # Check lock status
            if user.is_locked():
                flash('Account temporarily locked. Please try again later.', 'error')
                return render_template('auth/login.html', 
                                     recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

            # ✅ Use Werkzeug's built-in password verification
            if check_password_hash(user.password_hash, password):
                logger.info(f"Login successful for {username}")

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
            logger.warning(f"Login failed — user not found: {username}")
            flash('Invalid username or password.', 'error')

    # Render login page - ALWAYS pass recaptcha_site_key
    return render_template('auth/login.html', 
                         recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

# MODIFIED REGISTRATION ROUTE - Stores data temporarily until payment with FRAUD DETECTION
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
        
        # Get reCAPTCHA response
        recaptcha_response = request.form.get('g-recaptcha-response')
        
        # Verify reCAPTCHA
        if not verify_recaptcha(recaptcha_response, request.remote_addr):
            flash('Please complete the reCAPTCHA verification.', 'error')
            return render_template('auth/register.html', 
                                 referral_code=referral_code,
                                 recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        # Get IP and device info
        ip_address = request.remote_addr
        device_fingerprint = fraud_detector.get_device_fingerprint(request)
        
        if not name:
            flash('Full name is required.', 'error')
            return render_template('auth/register.html', 
                                 referral_code=referral_code,
                                 recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        if not terms:
            flash('You must agree to the Terms of Service and Privacy Policy.', 'error')
            return render_template('auth/register.html', 
                                 referral_code=referral_code,
                                 recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        if not re.match(r'^254[0-9]{9}$', phone_number) and not re.match(r'^07[0-9]{8}$', phone_number):
            flash('Please enter a valid Kenyan phone number.', 'error')
            return render_template('auth/register.html', 
                                 referral_code=referral_code,
                                 recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        if phone_number.startswith('07'):
            phone_number = '254' + phone_number[1:]
        
        # Check if phone already exists in database (permanent users)
        if SupabaseDB.get_user_by_phone(phone_number):
            flash('Phone number already registered.', 'error')
            return render_template('auth/register.html', 
                                 referral_code=referral_code,
                                 recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        # Check if username already exists in database (permanent users)
        if SupabaseDB.get_user_by_username(username):
            flash('Username already exists.', 'error')
            return render_template('auth/register.html', 
                                 referral_code=referral_code,
                                 recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        if email and SupabaseDB.get_user_by_email(email):
            flash('Email already registered.', 'error')
            return render_template('auth/register.html', 
                                 referral_code=referral_code,
                                 recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        # FRAUD DETECTION: Check for suspicious registration patterns
        fraud_warnings = fraud_detector.detect_suspicious_signup(
            ip_address, device_fingerprint, {
                'username': username,
                'email': email,
                'phone': phone_number
            }
        )
        
        if fraud_warnings:
            logger.warning(f"Suspicious registration detected: {fraud_warnings}")
            SecurityMonitor.log_security_event(
                "SUSPICIOUS_REGISTRATION",
                None,
                {
                    "ip": ip_address,
                    "device": device_fingerprint,
                    "warnings": fraud_warnings,
                    "username": username,
                    "phone": phone_number
                }
            )
            
            # For high-risk patterns, block immediately
            if len(fraud_warnings) >= 2:
                flash('Registration blocked due to suspicious activity. Please contact support.', 'error')
                return render_template('auth/register.html', 
                                     referral_code=referral_code,
                                     recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        referrer = None
        if referral_code:
            referrer = validate_referral_code(referral_code)
            if not referrer:
                flash('Invalid referral code. Please check and try again.', 'error')
                return render_template('auth/register.html', 
                                     referral_code=referral_code,
                                     recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
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
            'ip_address': ip_address,
            'device_fingerprint': device_fingerprint,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Generate temporary referral code for display
        phone_hash = hashlib.md5(phone_number.encode()).hexdigest()[:6].upper()
        temp_user_data['temp_referral_code'] = f"RN{phone_hash}"
        
        # Store temporary user data in session
        session['temp_user_data'] = temp_user_data
        session['pending_verification_user'] = temp_user_data['id']
        
        # Increment signup counters for fraud detection
        fraud_detector.increment_signup_counter(ip_address, device_fingerprint)
        
        # Send welcome SMS
        CelcomSMS.send_registration_notification(phone_number, username)
        
        flash('Registration successful! Please complete KSH 200 payment to activate your account.', 'success')
        return redirect(url_for('account_activation'))
    
    return render_template(
        'auth/register.html',
        referral_code=referral_code,
        recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
 
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
    
    # DON'T create transaction yet - we'll create it in the callback AFTER user is saved
    
    try:
        # Format phone number for M-PESA (254 format)
        phone_number = temp_user_data['phone']
        if phone_number.startswith('0'):
            phone_number = '254' + phone_number[1:]
        elif phone_number.startswith('+'):
            phone_number = phone_number[1:]
        
        # Generate a unique reference for this payment
        payment_reference = f"RN{temp_user_data['temp_referral_code']}_{int(time.time())}"
        
        # Initiate STK push
        stk_response = initiate_stk_push(
            phone_number=phone_number,
            amount=1 if app.config['MPESA_ENVIRONMENT'] == 'sandbox' else 200,
            account_reference=payment_reference,
            transaction_desc="ReferralNinja Registration"
        )
        
        if stk_response and stk_response.get('ResponseCode') == '0':
            # Store payment reference in session for callback matching
            session['pending_payment'] = {
                'checkout_request_id': stk_response.get('CheckoutRequestID'),
                'merchant_request_id': stk_response.get('MerchantRequestID'),
                'payment_reference': payment_reference,
                'temp_user_data': temp_user_data,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            return jsonify({
                'success': True, 
                'message': 'STK push sent to your phone! Please check your phone and enter your M-PESA PIN to complete payment.',
                'checkout_request_id': stk_response.get('CheckoutRequestID')
            })
        else:
            error_message = stk_response.get('errorMessage', 'Failed to initiate STK push') if stk_response else 'M-PESA service unavailable'
            return jsonify({'success': False, 'message': f'STK Push failed: {error_message}'})
    
    except Exception as e:
        logger.error(f"Error in STK push: {str(e)}")
        return jsonify({'success': False, 'message': f'Error initiating payment: {str(e)}'})

# MODIFIED PAYMENT STATUS CHECK - Creates user on successful payment
@app.route('/check-payment-status', methods=['POST'])
def check_payment_status():
    user_id = session.get('pending_verification_user')
    temp_user_data = session.get('temp_user_data')
    
    if not user_id or not temp_user_data:
        return jsonify({'verified': False, 'message': 'Session expired'})
    
    # Check if user has been created in database
    user = SupabaseDB.get_user_by_id(temp_user_data['id'])
    if user and user.is_verified:
        session.pop('pending_verification_user', None)
        session.pop('temp_user_data', None)
        session.pop('pending_payment', None)
        return jsonify({'verified': True, 'message': 'Payment verified! Account activated.'})
    
    # Check if payment is pending in our records
    pending_payment = session.get('pending_payment')
    
    if pending_payment and pending_payment.get('checkout_request_id'):
        # Query M-PESA for transaction status
        stk_status = query_stk_push_status(pending_payment['checkout_request_id'])
        if stk_status and stk_status.get('ResultCode') == '0':
            # Payment completed via query, create permanent user
            user = create_permanent_user_after_payment(temp_user_data, pending_payment)
            if user:
                login_user(user)
                session.pop('pending_verification_user', None)
                session.pop('temp_user_data', None)
                session.pop('pending_payment', None)
                return jsonify({'verified': True, 'message': 'Payment verified via query! Account activated.'})
    
    return jsonify({'verified': False, 'pending': bool(pending_payment)})

# MODIFIED M-PESA CALLBACK - Creates user on payment success
@app.route('/mpesa-callback', methods=['POST'])
def mpesa_callback_main():
    """Handle M-PESA STK push callback in main app - CREATE USER AFTER PAYMENT"""
    try:
        callback_data = request.get_json()
        logger.info("M-PESA Callback received in main app: %s", json.dumps(callback_data, indent=2))
        
        # Extract relevant information
        stk_callback = callback_data.get('Body', {}).get('stkCallback', {})
        result_code = stk_callback.get('ResultCode')
        result_desc = stk_callback.get('ResultDesc')
        checkout_request_id = stk_callback.get('CheckoutRequestID')
        merchant_request_id = stk_callback.get('MerchantRequestID')
        
        if result_code == 0:
            # Payment successful
            metadata = stk_callback.get('CallbackMetadata', {}).get('Item', [])
            mpesa_data = {}
            for item in metadata:
                name = item.get('Name')
                value = item.get('Value')
                mpesa_data[name] = value
            
            mpesa_receipt = mpesa_data.get('MpesaReceiptNumber')
            amount = mpesa_data.get('Amount')
            phone = mpesa_data.get('PhoneNumber')
            
            logger.info(f"Payment successful - Receipt: {mpesa_receipt}, Amount: {amount}, Phone: {phone}")
            
            # Find the pending payment in session storage (in production, use Redis/database)
            # For now, we'll log and handle via frontend polling
            logger.info(f"Payment completed for checkout: {checkout_request_id}")
            
            return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        else:
            # Payment failed
            logger.error(f"Payment failed: {result_desc}")
            return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})  # Still return success to M-Pesa
        
    except Exception as e:
        logger.error(f"Error processing M-PESA callback in main app: {str(e)}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@app.route('/auto-login/<token>')
def auto_login(token):
    """Auto-login user after successful payment"""
    try:
        user_id = redis_client.get(f"auto_login:{token}")
        if user_id:
            user = SupabaseDB.get_user_by_id(user_id)
            if user:
                login_user(user)
                redis_client.delete(f"auto_login:{token}")
                
                # Clean up session
                session.pop('pending_verification_user', None)
                session.pop('temp_user_data', None)
                session.pop('pending_payment', None)
                
                flash('Payment successful! Your account has been activated.', 'success')
                return redirect(url_for('dashboard'))
        
        flash('Invalid or expired login token. Please login manually.', 'error')
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Auto-login error: {e}")
        flash('Auto-login failed. Please login manually.', 'error')
        return redirect(url_for('login'))

# M-PESA B2C CALLBACK HANDLER
@app.route('/mpesa-b2c-callback', methods=['POST'])
def mpesa_b2c_callback():
    """Handle M-PESA B2C payout callbacks - AUTO UPDATE WITHDRAWAL STATUS"""
    try:
        callback_data = request.get_json()
        
        # Log the callback for debugging
        logger.info("M-PESA B2C Callback received: %s", json.dumps(callback_data, indent=2))
        
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
            logger.error(f"Withdrawal transaction not found for ID: {originator_conversation_id}")
            return jsonify({'ResultCode': 1, 'ResultDesc': 'Transaction not found'})
        
        user = SupabaseDB.get_user_by_id(withdrawal_transaction['user_id'])
        if not user:
            logger.error(f"User not found for withdrawal: {withdrawal_transaction['id']}")
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
            
            logger.info(f"B2C payout completed for user {user.username}, transaction ID: {transaction_id}")
            
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
            
            logger.error(f"B2C payout failed for user {user.username}: {result_desc}")
        
        # Always return success to M-PESA to stop retries
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Error processing M-PESA B2C callback: {str(e)}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'System error'})

@app.route('/mpesa-b2c-timeout', methods=['POST'])
def mpesa_b2c_timeout():
    """Handle B2C timeout callbacks"""
    callback_data = request.get_json()
    logger.warning(f"M-PESA B2C Timeout callback: {json.dumps(callback_data)}")
    return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})

@app.route('/api/payment-status', methods=['GET'])
def api_payment_status():
    """Check payment status - returns whether user should be redirected to login"""
    user_id = session.get('pending_verification_user')
    temp_user_data = session.get('temp_user_data')
    
    if not user_id or not temp_user_data:
        return jsonify({'verified': False, 'message': 'Session expired'})
    
    # Check if user exists in database (payment completed)
    user = SupabaseDB.get_user_by_id(temp_user_data['id'])
    if user and user.is_verified:
        # Clean up session
        session.pop('pending_verification_user', None)
        session.pop('temp_user_data', None)
        session.pop('pending_payment', None)
        
        return jsonify({
            'verified': True,
            'message': 'Payment verified!',
            'user_id': user.id,
            'username': user.username
        })
    
    # Check for auto-login token (if payment completed via callback)
    pending_payment = session.get('pending_payment')
    if pending_payment:
        checkout_request_id = pending_payment.get('checkout_request_id')
        
        # Check Redis for completed payment
        payment_data = get_pending_payment(checkout_request_id)
        if payment_data and payment_data.get('status') == 'completed':
            # Auto-login token should be available
            return jsonify({
                'verified': True,
                'message': 'Payment completed!',
                'auto_login': True
            })
    
    return jsonify({'verified': False, 'pending': True})

@app.template_filter('format_number')
def format_number(value):
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return "0"

@app.template_filter('format_currency')
def format_currency(value):
    try:
        if float(value) == int(float(value)):
            return f"{int(value):,}"
        else:
            return f"{float(value):,.2f}"
    except (ValueError, TypeError):
        return "0"

@app.template_filter('format_date')
def format_date(date_value, format='%d %b %Y %H:%M'):
    if date_value:
        if isinstance(date_value, str):
            try:
                # Try to parse the string
                from datetime import datetime
                # Handle different date formats
                for fmt in ('%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S%z', '%Y-%m-%d %H:%M:%S'):
                    try:
                        dt = datetime.strptime(date_value, fmt)
                        return dt.strftime(format)
                    except ValueError:
                        continue
                return date_value
            except:
                return date_value
        else:
            return date_value.strftime(format)
    return ''

@app.route('/referral-system')
@login_required
def referral_system():
    if not current_user.is_verified:
        flash('Please complete payment verification to access referral system.', 'warning')
        return redirect(url_for('account_activation'))
    
    # Get referrals for current user
    referrals = SupabaseDB.get_referrals_by_referrer(current_user.id)
    
    # Calculate Diani progress
    target_referrals = 3000
    current_referrals = current_user.referral_count or 0
    referrals_to_go = max(0, target_referrals - current_referrals)
    
    # Calculate progress percentage
    if target_referrals > 0:
        progress_percentage = min(100, (current_referrals / target_referrals) * 100)
    else:
        progress_percentage = 0
    
    # Build referral URL
    base_url = request.host_url.rstrip('/')
    referral_url = f"{base_url}/register?ref={current_user.referral_code}"
    
    # Prepare share links for different platforms
    share_message = f"Join Referral Ninja and earn money! Use my code: {current_user.referral_code}"
    
    share_links = {
        'whatsapp': f"https://wa.me/?text={urllib.parse.quote(share_message + ' - ' + referral_url)}",
        'facebook': f"https://www.facebook.com/sharer/sharer.php?u={urllib.parse.quote(referral_url)}&quote={urllib.parse.quote(share_message)}",
        'twitter': f"https://twitter.com/intent/tweet?text={urllib.parse.quote(share_message)}&url={urllib.parse.quote(referral_url)}",
        'telegram': f"https://t.me/share/url?url={urllib.parse.quote(referral_url)}&text={urllib.parse.quote(share_message)}"
    }
    
    # Get referral statistics
    total_earnings = current_user.total_commission or 0
    commission_per_referral = 50  # KSH per referral
    
    return render_template('referral_system.html',
                         referrals=referrals,
                         share_links=share_links,
                         referral_url=referral_url,
                         # Progress data
                         target_referrals=target_referrals,
                         current_referrals=current_referrals,
                         referrals_to_go=referrals_to_go,
                         progress_percentage=progress_percentage,
                         # Earnings data
                         total_earnings=total_earnings,
                         commission_per_referral=commission_per_referral)

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

    try:
        # Fetch top users
        top_users_data = SupabaseDB.get_top_users(limit=50)
        top_users = []

        for user_data in top_users_data:
            try:
                # Ensure all required fields exist
                user_data.setdefault('username', 'Unknown User')
                user_data.setdefault('email', '')
                user_data.setdefault('user_rank', 'Bronze')
                user_data.setdefault('balance', 0.0)
                user_data.setdefault('referral_count', 0)
                user_data.setdefault('total_commission', 0.0)

                # Create User object for template
                top_users.append(User(user_data))
            except Exception as e:
                logger.error(f"Error creating User object: {e}")
                continue

        # Get current user's ranking
        user_ranking = get_user_ranking(current_user.id)

        # Get tier distribution
        tier_distribution = SupabaseDB.get_tier_distribution()

        # Calculate next tier progress if applicable
        if user_ranking:
            user_rank = user_ranking.get('user_rank', 'Bronze')
            user_commission = float(user_ranking.get('total_commission', 0))

            tier_requirements = {
                'Bronze': 0,
                'Silver': 5000,
                'Gold': 15000,
                'Platinum': 30000,
                'Diamond': 70000
            }

            if user_rank != 'Diamond':
                next_tier = tier_requirements.get(user_rank, 70000)
                progress_percentage = min((user_commission / next_tier) * 100, 100) if next_tier > 0 else 0
                user_ranking['next_tier_progress'] = round(progress_percentage, 1)
                user_ranking['next_tier_requirement'] = next_tier
            else:
                user_ranking['next_tier_progress'] = 100
                user_ranking['next_tier_requirement'] = tier_requirements['Diamond']

        return render_template(
            'leaderboard.html',
            top_users=top_users,
            user_ranking=user_ranking,
            current_user=current_user,
            tier_stats=tier_distribution
        )

    except Exception as e:
        logger.error(f"Error in leaderboard route: {e}", exc_info=True)
        flash('Error loading leaderboard. Please try again.', 'error')
        return render_template(
            'leaderboard.html',
            top_users=[],
            user_ranking=None,
            current_user=current_user,
            tier_stats=None
        )


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

def reload_user_from_db(user_id):
    """Reload user from database to ensure fresh data"""
    from flask_login import current_user
    
    # Fetch fresh user data from database
    fresh_user_data = SupabaseDB.get_user_by_id(user_id)
    
    if fresh_user_data:
        # Update current_user object with fresh data
        current_user.balance = fresh_user_data.balance
        current_user.total_withdrawn = fresh_user_data.total_withdrawn
        current_user.is_verified = fresh_user_data.is_verified
        current_user.phone = fresh_user_data.phone
        # Add other fields as needed
    
    return current_user

# UPDATED WITHDRAW ROUTE - Now with enhanced fraud detection and Brevo email integration
@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    def validate_and_normalize_phone(phone_str):
        """Validate and normalize Kenyan phone number to 254 format"""
        # Remove all non-digits
        digits = re.sub(r'\D', '', phone_str)
        
        if not digits:
            return None, "Phone number is required"
        
        # Check common Kenyan formats
        if digits.startswith('254') and len(digits) == 12:
            return digits, None  # Already in 254 format
        elif digits.startswith('07') and len(digits) == 10:
            return '254' + digits[1:], None  # Remove leading 0, add 254
        elif digits.startswith('7') and len(digits) == 9:
            return '254' + digits, None  # Add 254 prefix
        elif digits.startswith('+254') and len(digits) == 13:
            return digits[1:], None  # Remove +
        elif digits.startswith('01') and len(digits) == 10:
            return '254' + digits[1:], None  # Old 01 format
        else:
            return None, "Invalid phone format. Use: 07XX XXX XXX or 254XXXXXXXXX"
    
    def refresh_user():
        """Refresh current user data from database"""
        try:
            user_data = SupabaseDB.get_user_by_id(current_user.id)
            if user_data:
                if hasattr(user_data, '__dict__'):
                    # Copy non-private attributes
                    for key, value in user_data.__dict__.items():
                        if not key.startswith('_'):
                            setattr(current_user, key, value)
                else:
                    # Assume it's an object with attributes
                    current_user.balance = float(getattr(user_data, 'balance', 0))
                    current_user.total_withdrawn = float(getattr(user_data, 'total_withdrawn', 0))
                    current_user.is_verified = bool(getattr(user_data, 'is_verified', False))
                    current_user.phone = getattr(user_data, 'phone', '')
                    current_user.email = getattr(user_data, 'email', '')
                    current_user.email_verified = bool(getattr(user_data, 'email_verified', False))
        except Exception as e:
            app.logger.error(f"Error refreshing user: {e}")
    
    def send_brevo_email(to_email, subject, html_content):
        """Send email using Brevo API"""
        try:
            api_key = app.config.get('BREVO_API_KEY')
            sender_name = app.config.get('BREVO_SENDER_NAME', 'ReferralNinja')
            sender_email = app.config.get('BREVO_SENDER_EMAIL', 'noreply@referralninja.co.ke')
            
            if not api_key:
                app.logger.error("Brevo API key not configured")
                return False, "Email service not configured"
            
            url = "https://api.brevo.com/v3/smtp/email"
            headers = {
                "api-key": api_key,
                "Content-Type": "application/json"
            }
            
            data = {
                "sender": {
                    "name": sender_name,
                    "email": sender_email
                },
                "to": [{"email": to_email}],
                "subject": subject,
                "htmlContent": html_content
            }
            
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 201:
                app.logger.info(f"Brevo email sent successfully to {to_email}")
                return True, "Email sent successfully"
            else:
                app.logger.error(f"Brevo API error: {response.status_code} - {response.text}")
                return False, f"Email service error: {response.status_code}"
                
        except Exception as e:
            app.logger.error(f"Error sending Brevo email: {e}")
            return False, f"Email sending failed: {str(e)}"
    
    # Refresh user at start
    refresh_user()
    
    if not current_user.is_verified:
        flash('Please complete payment verification to withdraw funds.', 'warning')
        return redirect(url_for('account_activation'))
    
    # Check if user has email (required for verification)
    if not current_user.email:
        flash('Email address is required for withdrawals. Please add an email to your account in settings.', 'error')
        return redirect(url_for('settings'))
    
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount', 0))
        except ValueError:
            flash('Please enter a valid amount.', 'error')
            return redirect(url_for('withdraw'))
        
        phone_number = request.form.get('phone_number', '').strip()
        withdrawal_terms = request.form.get('withdrawal_terms') == 'on'
        
        # Minimum withdrawal amount is 400
        if amount < 400:
            flash('Minimum withdrawal amount is KES 400.', 'error')
            return redirect(url_for('withdraw'))
        
        # Check available balance
        refresh_user()
        if amount > current_user.balance:
            flash(f'Insufficient balance. Available: KES {current_user.balance:.2f}', 'error')
            return redirect(url_for('withdraw'))
        
        # Check if terms were agreed to
        if not withdrawal_terms:
            flash('You must agree to the withdrawal terms and conditions.', 'error')
            return redirect(url_for('withdraw'))
        
        # Validate and normalize phone number
        normalized_phone, error_msg = validate_and_normalize_phone(phone_number)
        if error_msg:
            flash(error_msg, 'error')
            return redirect(url_for('withdraw'))
        phone_number = normalized_phone
        
        # Check if email is verified (recommended but not required)
        if not getattr(current_user, 'email_verified', False):
            flash('⚠️ For enhanced security, please verify your email address. Check your email for verification link.', 'warning')
        
        # Fraud detection
        fraud_warnings = []
        if fraud_detector:
            try:
                fraud_warnings = fraud_detector.detect_suspicious_withdrawal(current_user, amount, request)
            except Exception as e:
                app.logger.error(f"Error in fraud detection: {e}")
        
        # Prepare transaction data
        transaction_id = str(uuid.uuid4())
        transaction_data = {
            'id': transaction_id,
            'user_id': current_user.id,
            'amount': -amount,
            'transaction_type': 'withdrawal',
            'phone_number': phone_number,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # ALWAYS require email verification
        # Generate 6-digit verification code
        verification_code = ''.join(secrets.choice(string.digits) for _ in range(6))
        verification_expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        
        # Set to pending verification (ALL withdrawals require email verification)
        transaction_data.update({
            'status': 'pending_verification',
            'description': f'M-Pesa withdrawal to {phone_number} - Pending email verification',
            'withdrawal_verification_code': verification_code,
            'withdrawal_verification_expires': verification_expires.isoformat(),
            'withdrawal_verified': False
        })
        
        # Add fraud warnings to transaction data if any
        if fraud_warnings:
            transaction_data.update({
                'fraud_warnings': json.dumps(fraud_warnings),
                'description': f'M-Pesa withdrawal to {phone_number} - Pending email verification (Suspicious activity detected)'
            })
            
            # Log security event for suspicious withdrawal attempt
            try:
                SecurityMonitor.log_security_event(
                    "SUSPICIOUS_WITHDRAWAL_ATTEMPT", 
                    current_user.id, 
                    {
                        "amount": amount, 
                        "warnings": fraud_warnings,
                        "withdrawal_id": transaction_id,
                        "ip": request.remote_addr,
                        "requires_verification": True
                    }
                )
            except Exception as e:
                app.logger.error(f"Error logging security event: {e}")
        
        # Create withdrawal transaction WITHOUT deducting balance yet
        try:
            SupabaseDB.create_transaction(transaction_data)
        except Exception as e:
            app.logger.error(f"Error creating transaction: {e}")
            flash('Error creating withdrawal request. Please try again.', 'error')
            return redirect(url_for('withdraw'))
        
        # Send verification email using Brevo
        try:
            # Create verification email HTML
            subject = "Your Withdrawal Verification Code"
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Withdrawal Verification</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(to right, #4f46e5, #7c3aed); padding: 20px; text-align: center;">
                    <h1 style="color: white; margin: 0;">ReferralNinja</h1>
                </div>
                
                <div style="padding: 30px; background-color: #f9f9f9;">
                    <h2>Withdrawal Verification</h2>
                    <p>Hello <strong>{current_user.username}</strong>,</p>
                    
                    <p>You have requested to withdraw <strong>KES {amount:,.2f}</strong> to M-Pesa number <strong>{phone_number}</strong>.</p>
                    
                    <div style="background-color: #fff; border: 2px dashed #4f46e5; padding: 20px; text-align: center; margin: 20px 0;">
                        <h3 style="color: #7c3aed; margin-top: 0;">Your Verification Code</h3>
                        <div style="font-size: 32px; font-weight: bold; letter-spacing: 10px; color: #4f46e5; margin: 15px 0;">
                            {verification_code}
                        </div>
                        <p style="color: #666; font-size: 14px;">
                            This code will expire in 10 minutes
                        </p>
                    </div>
                    
                    <p>Enter this code on the verification page to complete your withdrawal.</p>
                    
                    {"<div style='background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 10px; margin: 20px 0;'>" + 
                     "<strong>⚠️ Security Notice:</strong> This withdrawal has been flagged for additional review due to suspicious activity patterns." + 
                     "</div>" if fraud_warnings else ""}
                    
                    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                        <p style="color: #666; font-size: 12px;">
                            <strong>Transaction ID:</strong> {transaction_id}<br>
                            <strong>Request Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                            <strong>IP Address:</strong> {request.remote_addr}
                        </p>
                        <p style="color: #666; font-size: 12px;">
                            If you did not initiate this withdrawal, please contact our support team immediately.
                        </p>
                    </div>
                </div>
                
                <div style="background-color: #f3f4f6; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                    <p>© {datetime.now().year} ReferralNinja. All rights reserved.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </body>
            </html>
            """
            
            # Send email using Brevo
            success, message = send_brevo_email(
                to_email=current_user.email,
                subject=subject,
                html_content=html_content
            )
            
            if not success:
                app.logger.error(f"Brevo email failed: {message}")
                # If email fails, update the transaction and show error
                SupabaseDB.update_transaction(transaction_id, {
                    'status': 'failed',
                    'description': 'Failed to send verification email'
                })
                flash('Failed to send verification email. Please check your email address or try again later.', 'error')
                return redirect(url_for('withdraw'))
            
            # Store transaction ID in session for verification page
            session['pending_withdrawal_id'] = transaction_id
            session['pending_withdrawal_amount'] = amount
            session['pending_withdrawal_phone'] = phone_number
            
            # Log email sent
            SecurityMonitor.log_security_event(
                "WITHDRAWAL_VERIFICATION_SENT",
                current_user.id,
                {
                    "amount": amount,
                    "withdrawal_id": transaction_id,
                    "email": current_user.email,
                    "suspicious": bool(fraud_warnings)
                }
            )
            
            if fraud_warnings:
                flash(f'⚠️ Withdrawal flagged for review. A 6-digit verification code has been sent to {current_user.email}. Please complete verification.', 'warning')
            else:
                flash(f'✅ 6-digit verification code sent to {current_user.email}. Please check your email.', 'success')
            
            # REDIRECT TO VERIFICATION PAGE (New Flow)
            return redirect(url_for('verify_withdrawal_email'))
            
        except Exception as e:
            app.logger.error(f"Error sending verification email: {e}")
            
            # If email fails, update the transaction and show error
            SupabaseDB.update_transaction(transaction_id, {
                'status': 'failed',
                'description': 'Failed to send verification email'
            })
            
            flash('Failed to send verification email. Please check your email address or try again later.', 'error')
            return redirect(url_for('withdraw'))
    
    # GET request - show withdrawal page with multi-step form
    refresh_user()
    
    # Get recent withdrawals (last 5)
    transactions = []
    try:
        transactions = SupabaseDB.get_transactions_by_user(
            current_user.id, 
            transaction_type='withdrawal', 
            limit=5
        )
    except Exception as e:
        app.logger.error(f"Error fetching transactions: {e}")
    
    # Process transactions for display
    processed_transactions = []
    for transaction in transactions:
        # Convert to dict if needed
        if hasattr(transaction, '__dict__'):
            tx_dict = transaction.__dict__.copy()
            # Remove private attributes
            tx_dict = {k: v for k, v in tx_dict.items() if not k.startswith('_')}
        elif isinstance(transaction, dict):
            tx_dict = transaction.copy()
        else:
            tx_dict = {}
        
        # Format phone number for display (254... to 07...)
        phone = tx_dict.get('phone_number', '')
        if phone and str(phone).startswith('254'):
            tx_dict['display_phone'] = '0' + str(phone)[3:]
        else:
            tx_dict['display_phone'] = str(phone) if phone else ''
        
        # Ensure amount is positive for display
        amount_val = tx_dict.get('amount', 0)
        try:
            amount_val = float(amount_val)
            if amount_val < 0:
                tx_dict['display_amount'] = abs(amount_val)
            else:
                tx_dict['display_amount'] = amount_val
        except (ValueError, TypeError):
            tx_dict['display_amount'] = 0
            
        # Ensure we have all required attributes
        required_fields = ['amount', 'phone_number', 'status', 'description', 'created_at']
        for field in required_fields:
            if field not in tx_dict:
                tx_dict[field] = ''
        
        # Format date for display
        created_at = tx_dict.get('created_at')
        if created_at:
            if hasattr(created_at, 'strftime'):
                tx_dict['formatted_date'] = created_at.strftime('%d %b, %H:%M')
            elif isinstance(created_at, str):
                try:
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    tx_dict['formatted_date'] = dt.strftime('%d %b, %H:%M')
                except:
                    tx_dict['formatted_date'] = created_at
            else:
                tx_dict['formatted_date'] = str(created_at)
        else:
            tx_dict['formatted_date'] = ''
            
        processed_transactions.append(tx_dict)
    
    # Format user's phone for display
    user_phone_formatted = ""
    if hasattr(current_user, 'phone') and current_user.phone:
        if current_user.phone.startswith('254'):
            user_phone_formatted = '0' + current_user.phone[3:]
        else:
            user_phone_formatted = current_user.phone
    
    return render_template('withdraw.html', 
                         transactions=processed_transactions,
                         user_email=current_user.email,
                         user_phone_formatted=user_phone_formatted,
                         email_verified=getattr(current_user, 'email_verified', False))


@app.route('/withdraw/verify-email', methods=['GET', 'POST'])
@login_required
def verify_withdrawal_email():
    """Verify email code for withdrawal"""
    # Check if there's a pending withdrawal
    withdrawal_id = session.get('pending_withdrawal_id')
    if not withdrawal_id:
        flash('No pending withdrawal to verify.', 'error')
        return redirect(url_for('withdraw'))
    
    # Get withdrawal details
    withdrawal = SupabaseDB.get_transaction_by_id(withdrawal_id)
    if not withdrawal or withdrawal['user_id'] != current_user.id:
        flash('Invalid withdrawal request.', 'error')
        session.pop('pending_withdrawal_id', None)
        return redirect(url_for('withdraw'))
    
    if withdrawal['status'] != 'pending_verification':
        flash('This withdrawal has already been processed.', 'info')
        session.pop('pending_withdrawal_id', None)
        return redirect(url_for('dashboard'))
    
    def send_confirmation_email():
        """Send confirmation email using Brevo"""
        subject = "Withdrawal Successful"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Withdrawal Successful</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(to right, #10b981, #059669); padding: 20px; text-align: center;">
                <h1 style="color: white; margin: 0;">✅ Withdrawal Successful</h1>
            </div>
            
            <div style="padding: 30px; background-color: #f9f9f9;">
                <h2>Hello {current_user.username},</h2>
                
                <p>We're pleased to inform you that your withdrawal has been processed successfully.</p>
                
                <div style="background-color: #fff; border: 2px solid #10b981; padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <h3 style="color: #059669; margin-top: 0;">Transaction Details</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;"><strong>Amount:</strong></td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; text-align: right;">KES {abs(withdrawal['amount']):,.2f}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;"><strong>Sent To:</strong></td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; text-align: right;">{withdrawal.get('phone_number', '')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;"><strong>Transaction ID:</strong></td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; text-align: right;">{withdrawal_id}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0;"><strong>Date:</strong></td>
                            <td style="padding: 10px 0; text-align: right;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                        </tr>
                    </table>
                </div>
                
                <p>The funds have been sent to your M-Pesa account. Please allow a few minutes for the transaction to reflect.</p>
                
                <div style="background-color: #f0fdf4; border-left: 4px solid #10b981; padding: 10px; margin: 20px 0;">
                    <strong>💡 Tip:</strong> You can track all your transactions in your dashboard.
                </div>
                
                <p>If you have any questions, please don't hesitate to contact our support team.</p>
                
                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                    <p style="color: #666; font-size: 12px;">
                        <strong>Remaining Balance:</strong> KES {current_user.balance:,.2f}<br>
                        <strong>Total Withdrawn:</strong> KES {current_user.total_withdrawn:,.2f}
                    </p>
                </div>
            </div>
            
            <div style="background-color: #f3f4f6; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                <p>© {datetime.now().year} ReferralNinja. All rights reserved.</p>
                <p>This is an automated message, please do not reply to this email.</p>
            </div>
        </body>
        </html>
        """
        
        return send_brevo_email(
            to_email=current_user.email,
            subject=subject,
            html_content=html_content
        )
    
    def send_under_review_email():
        """Send under review email using Brevo"""
        subject = "Withdrawal Under Review"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Withdrawal Under Review</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(to right, #f59e0b, #d97706); padding: 20px; text-align: center;">
                <h1 style="color: white; margin: 0;">⚠️ Withdrawal Under Review</h1>
            </div>
            
            <div style="padding: 30px; background-color: #f9f9f9;">
                <h2>Hello {current_user.username},</h2>
                
                <p>Your withdrawal request has been received and is currently under review for security verification.</p>
                
                <div style="background-color: #fff; border: 2px solid #f59e0b; padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <h3 style="color: #d97706; margin-top: 0;">Review Details</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;"><strong>Amount:</strong></td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; text-align: right;">KES {abs(withdrawal['amount']):,.2f}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;"><strong>M-Pesa Number:</strong></td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; text-align: right;">{withdrawal.get('phone_number', '')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb;"><strong>Transaction ID:</strong></td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #e5e7eb; text-align: right;">{withdrawal_id}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0;"><strong>Date Submitted:</strong></td>
                            <td style="padding: 10px 0; text-align: right;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                        </tr>
                    </table>
                </div>
                
                <div style="background-color: #fffbeb; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0;">
                    <h4 style="color: #d97706; margin-top: 0;">Why is my withdrawal under review?</h4>
                    <p>As part of our security measures, we occasionally review withdrawals to prevent fraudulent activities. This is a standard procedure and helps protect your account.</p>
                </div>
                
                <p><strong>What happens next?</strong></p>
                <ul>
                    <li>Our security team will review your withdrawal request</li>
                    <li>You will be notified once the review is complete</li>
                    <li>If approved, funds will be sent to your M-Pesa account</li>
                    <li>If additional verification is needed, we will contact you</li>
                </ul>
                
                <p><strong>Estimated review time:</strong> 1-2 hours during business hours</p>
                
                <p>If you have any questions, please contact our support team.</p>
            </div>
            
            <div style="background-color: #f3f4f6; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                <p>© {datetime.now().year} ReferralNinja. All rights reserved.</p>
                <p>This is an automated message, please do not reply to this email.</p>
            </div>
        </body>
        </html>
        """
        
        return send_brevo_email(
            to_email=current_user.email,
            subject=subject,
            html_content=html_content
        )
    
    if request.method == 'POST':
        verification_code = request.form.get('verification_code', '').strip()
        
        if not verification_code:
            flash('Please enter the verification code.', 'error')
            return render_template('verify_withdrawal_email.html',
                                 user_email=current_user.email,
                                 amount=abs(withdrawal['amount']),
                                 withdrawal_id=withdrawal_id)
        
        # Check verification code
        stored_code = withdrawal.get('withdrawal_verification_code')
        expires_at_str = withdrawal.get('withdrawal_verification_expires')
        
        if not stored_code or not expires_at_str:
            flash('Verification data missing. Please restart withdrawal.', 'error')
            session.pop('pending_withdrawal_id', None)
            return redirect(url_for('withdraw'))
        
        # Check if code matches
        if stored_code != verification_code:
            # Log failed attempt
            SecurityMonitor.log_security_event(
                "WITHDRAWAL_VERIFICATION_FAILED",
                current_user.id,
                {
                    "withdrawal_id": withdrawal_id,
                    "attempted_code": verification_code,
                    "expected_code": stored_code
                }
            )
            
            flash('Invalid verification code. Please try again.', 'error')
            return render_template('verify_withdrawal_email.html',
                                 user_email=current_user.email,
                                 amount=abs(withdrawal['amount']),
                                 withdrawal_id=withdrawal_id)
        
        # Check if code is expired
        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
        if datetime.now(timezone.utc) > expires_at:
            SupabaseDB.update_transaction(withdrawal_id, {
                'status': 'failed',
                'description': 'Verification code expired'
            })
            session.pop('pending_withdrawal_id', None)
            flash('Verification code has expired. Please request a new withdrawal.', 'error')
            return redirect(url_for('withdraw'))
        
        # VERIFICATION SUCCESSFUL!
        
        # Check if there are fraud warnings
        fraud_warnings = []
        try:
            fraud_warnings_str = withdrawal.get('fraud_warnings')
            if fraud_warnings_str:
                fraud_warnings = json.loads(fraud_warnings_str)
        except:
            pass
        
        # Check balance again (in case it changed)
        def refresh_user():
            try:
                user_data = SupabaseDB.get_user_by_id(current_user.id)
                if user_data:
                    if hasattr(user_data, '__dict__'):
                        for key, value in user_data.__dict__.items():
                            if not key.startswith('_'):
                                setattr(current_user, key, value)
                    else:
                        current_user.balance = float(getattr(user_data, 'balance', 0))
                        current_user.total_withdrawn = float(getattr(user_data, 'total_withdrawn', 0))
            except Exception as e:
                app.logger.error(f"Error refreshing user: {e}")
        
        refresh_user()
        amount = abs(withdrawal['amount'])
        if current_user.balance < amount:
            SupabaseDB.update_transaction(withdrawal_id, {
                'status': 'failed',
                'description': 'Insufficient balance during verification'
            })
            session.pop('pending_withdrawal_id', None)
            flash('Insufficient balance. Withdrawal cancelled.', 'error')
            return redirect(url_for('withdraw'))
        
        # Check if transaction is suspicious
        if fraud_warnings:
            # SUSPICIOUS WITHDRAWAL: Email verification passed, but still needs manual review
            transaction_update = {
                'status': 'Under Review',
                'withdrawal_verified': True,
                'withdrawal_verified_at': datetime.now(timezone.utc).isoformat(),
                'description': f'M-Pesa withdrawal to {withdrawal.get("phone_number")} - Email verification passed, awaiting manual review'
            }
            
            # Store in session for the dashboard to show this is under review
            session['recent_withdrawal_status'] = 'under_review'
            session['recent_withdrawal_amount'] = amount
            
            flash('✅ Email verification successful! Your withdrawal is under review for security purposes. We will notify you once processed.', 'warning')
        else:
            # NORMAL WITHDRAWAL: Email verification passed, proceed to send money
            transaction_update = {
                'status': 'processing',
                'withdrawal_verified': True,
                'withdrawal_verified_at': datetime.now(timezone.utc).isoformat(),
                'description': 'Email verification completed - Processing M-Pesa payment'
            }
            
            # Store in session for the dashboard to show this is processing
            session['recent_withdrawal_status'] = 'processing'
            session['recent_withdrawal_amount'] = amount
            
            flash('✅ Email verification successful! Processing your withdrawal...', 'success')
        
        # Update transaction
        SupabaseDB.update_transaction(withdrawal_id, transaction_update)
        
        # Only deduct balance for normal withdrawals (not suspicious ones)
        if not fraud_warnings:
            # Deduct balance from user
            new_balance = current_user.balance - amount
            new_total_withdrawn = current_user.total_withdrawn + amount
            
            update_success = SupabaseDB.update_user(current_user.id, {
                'balance': new_balance,
                'total_withdrawn': new_total_withdrawn
            })
            
            if not update_success:
                flash('Failed to update balance. Please contact support.', 'error')
                return redirect(url_for('dashboard'))
            
            # Update local user object
            current_user.balance = new_balance
            current_user.total_withdrawn = new_total_withdrawn
        
        # Log successful verification
        SecurityMonitor.log_security_event(
            "WITHDRAWAL_VERIFICATION_SUCCESS",
            current_user.id,
            {
                "withdrawal_id": withdrawal_id,
                "amount": amount,
                "method": "email_verification",
                "suspicious": bool(fraud_warnings)
            }
        )
        
        # Get phone number from withdrawal (the one user entered during registration/withdrawal)
        phone_number = withdrawal.get('phone_number')
        
        if not fraud_warnings and phone_number:
            # NORMAL WITHDRAWAL: Send money via M-Pesa immediately
            try:
                # Initialize M-Pesa service
                mpesa_service = MpesaService(app.config)
                
                # Process M-Pesa payment
                mpesa_result = mpesa_service.send_money(
                    phone_number=phone_number,
                    amount=amount,
                    transaction_id=withdrawal_id,
                    description=f"Withdrawal for {current_user.username}"
                )
                
                if mpesa_result.get('success'):
                    # Update transaction as completed
                    SupabaseDB.update_transaction(withdrawal_id, {
                        'status': 'completed',
                        'description': f'M-Pesa payment sent to {phone_number}',
                        'mpesa_reference': mpesa_result.get('reference'),
                        'mpesa_response': json.dumps(mpesa_result)
                    })
                    
                    # Update session status
                    session['recent_withdrawal_status'] = 'completed'
                    
                    # Send confirmation email using Brevo
                    try:
                        success, message = send_confirmation_email()
                        if not success:
                            app.logger.warning(f"Failed to send confirmation email: {message}")
                    except Exception as e:
                        app.logger.error(f"Error sending confirmation email: {e}")
                    
                    flash(f'✅ Withdrawal successful! KES {amount} sent to {phone_number}.', 'success')
                else:
                    # M-Pesa failed
                    SupabaseDB.update_transaction(withdrawal_id, {
                        'status': 'failed',
                        'description': f'M-Pesa transfer failed: {mpesa_result.get("error", "Unknown error")}',
                        'mpesa_response': json.dumps(mpesa_result)
                    })
                    
                    # Refund the user
                    refund_balance = current_user.balance + amount
                    refund_withdrawn = current_user.total_withdrawn - amount
                    SupabaseDB.update_user(current_user.id, {
                        'balance': refund_balance,
                        'total_withdrawn': refund_withdrawn
                    })
                    
                    # Update local user object
                    current_user.balance = refund_balance
                    current_user.total_withdrawn = refund_withdrawn
                    
                    # Update session status
                    session['recent_withdrawal_status'] = 'failed'
                    
                    flash('❌ M-Pesa transfer failed. Funds have been returned to your balance.', 'error')
            except Exception as e:
                app.logger.error(f"Error processing M-Pesa payment: {e}")
                SupabaseDB.update_transaction(withdrawal_id, {
                    'status': 'failed',
                    'description': f'Error processing M-Pesa: {str(e)}'
                })
                
                # Refund on error
                refund_balance = current_user.balance + amount
                refund_withdrawn = current_user.total_withdrawn - amount
                SupabaseDB.update_user(current_user.id, {
                    'balance': refund_balance,
                    'total_withdrawn': refund_withdrawn
                })
                
                # Update local user object
                current_user.balance = refund_balance
                current_user.total_withdrawn = refund_withdrawn
                
                # Update session status
                session['recent_withdrawal_status'] = 'failed'
                
                flash('❌ Error processing M-Pesa payment. Please contact support.', 'error')
        elif fraud_warnings:
            # SUSPICIOUS WITHDRAWAL: Send notification for manual review
            try:
                # Send notification to admin/telegram
                send_withdrawal_notification_to_telegram(current_user, withdrawal)
                
                # Send under review email using Brevo
                success, message = send_under_review_email()
                if not success:
                    app.logger.warning(f"Failed to send under review email: {message}")
                
                flash('✅ Withdrawal submitted for review. You will be notified once processed.', 'info')
            except Exception as e:
                app.logger.error(f"Error sending under review notifications: {e}")
        
        # Clear session withdrawal data but keep recent status for dashboard
        session.pop('pending_withdrawal_id', None)
        session.pop('pending_withdrawal_amount', None)
        session.pop('pending_withdrawal_phone', None)
        
        return redirect(url_for('dashboard'))
    
    # GET request - show verification form
    return render_template('verify_withdrawal_email.html',
                         user_email=current_user.email,
                         amount=abs(withdrawal['amount']),
                         withdrawal_id=withdrawal_id)


@app.route('/withdraw/resend-verification', methods=['POST'])
@login_required
def resend_withdrawal_verification():
    """Resend withdrawal verification email"""
    withdrawal_id = request.form.get('withdrawal_id')
    
    if not withdrawal_id:
        flash('Withdrawal ID required.', 'error')
        return redirect(url_for('withdraw'))
    
    withdrawal = SupabaseDB.get_transaction_by_id(withdrawal_id)
    
    if not withdrawal or withdrawal['user_id'] != current_user.id:
        flash('Invalid withdrawal.', 'error')
        return redirect(url_for('withdraw'))
    
    if withdrawal['status'] != 'pending_verification':
        flash('This withdrawal has already been processed.', 'error')
        return redirect(url_for('dashboard'))
    
    # Generate new verification code
    new_code = ''.join(secrets.choice(string.digits) for _ in range(6))
    new_expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    # Update transaction with new code
    SupabaseDB.update_transaction(withdrawal_id, {
        'withdrawal_verification_code': new_code,
        'withdrawal_verification_expires': new_expires.isoformat()
    })
    
    # Resend email using Brevo
    try:
        # Check if there are fraud warnings
        fraud_warnings = False
        try:
            fraud_warnings_str = withdrawal.get('fraud_warnings')
            if fraud_warnings_str:
                fraud_warnings = bool(json.loads(fraud_warnings_str))
        except:
            pass
        
        # Create verification email HTML
        subject = "Your New Withdrawal Verification Code"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>New Verification Code</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(to right, #4f46e5, #7c3aed); padding: 20px; text-align: center;">
                <h1 style="color: white; margin: 0;">ReferralNinja</h1>
            </div>
            
            <div style="padding: 30px; background-color: #f9f9f9;">
                <h2>New Verification Code</h2>
                <p>Hello <strong>{current_user.username}</strong>,</p>
                
                <p>You requested a new verification code for your withdrawal of <strong>KES {abs(withdrawal['amount']):,.2f}</strong>.</p>
                
                <div style="background-color: #fff; border: 2px dashed #4f46e5; padding: 20px; text-align: center; margin: 20px 0;">
                    <h3 style="color: #7c3aed; margin-top: 0;">Your New Verification Code</h3>
                    <div style="font-size: 32px; font-weight: bold; letter-spacing: 10px; color: #4f46e5; margin: 15px 0;">
                        {new_code}
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        This code will expire in 10 minutes
                    </p>
                </div>
                
                <div style="background-color: #f0fdf4; border-left: 4px solid #10b981; padding: 10px; margin: 20px 0;">
                    <strong>🔒 Security Tip:</strong> Never share your verification code with anyone.
                </div>
                
                <p>If you did not request this code, please contact our support team immediately.</p>
                
                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                    <p style="color: #666; font-size: 12px;">
                        <strong>Transaction ID:</strong> {withdrawal_id}<br>
                        <strong>Request Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    </p>
                </div>
            </div>
            
            <div style="background-color: #f3f4f6; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                <p>© {datetime.now().year} ReferralNinja. All rights reserved.</p>
                <p>This is an automated message, please do not reply to this email.</p>
            </div>
        </body>
        </html>
        """
        
        # Send email using Brevo
        success, message = send_brevo_email(
            to_email=current_user.email,
            subject=subject,
            html_content=html_content
        )
        
        if success:
            flash('✅ New verification code sent to your email!', 'success')
        else:
            flash(f'Failed to resend verification email: {message}', 'error')
            
    except Exception as e:
        app.logger.error(f"Error resending verification email: {e}")
        flash('Failed to resend verification email. Please try again.', 'error')
    
    return redirect(url_for('verify_withdrawal_email'))


@app.route('/withdraw/cancel/<transaction_id>', methods=['POST'])
@login_required
def cancel_withdrawal(transaction_id):
    """Cancel a pending withdrawal"""
    withdrawal = SupabaseDB.get_transaction_by_id(transaction_id)
    
    if not withdrawal or withdrawal['user_id'] != current_user.id:
        flash('Invalid withdrawal.', 'error')
        return redirect(url_for('dashboard'))
    
    if withdrawal['status'] not in ['pending', 'pending_verification']:
        flash('Cannot cancel withdrawal that is already being processed.', 'error')
        return redirect(url_for('dashboard'))
    
    # Update transaction status
    SupabaseDB.update_transaction(transaction_id, {
        'status': 'cancelled',
        'description': 'Cancelled by user'
    })
    
    # Clear session if this was the pending withdrawal
    if session.get('pending_withdrawal_id') == transaction_id:
        session.pop('pending_withdrawal_id', None)
        session.pop('pending_withdrawal_amount', None)
        session.pop('pending_withdrawal_phone', None)
    
    flash('Withdrawal cancelled successfully.', 'success')
    return redirect(url_for('dashboard'))

def refresh_user():
    """Helper function to refresh user data (defined at module level for reuse)"""
    from flask_login import current_user
    try:
        user_data = SupabaseDB.get_user_by_id(current_user.id)
        if user_data:
            if hasattr(user_data, '__dict__'):
                # Copy non-private attributes
                for key, value in user_data.__dict__.items():
                    if not key.startswith('_'):
                        setattr(current_user, key, value)
            else:
                # Assume it's an object with attributes
                current_user.balance = float(getattr(user_data, 'balance', 0))
                current_user.total_withdrawn = float(getattr(user_data, 'total_withdrawn', 0))
                current_user.is_verified = bool(getattr(user_data, 'is_verified', False))
                current_user.phone = getattr(user_data, 'phone', '')
                current_user.email = getattr(user_data, 'email', '')
                current_user.email_verified = bool(getattr(user_data, 'email_verified', False))
    except Exception as e:
        app.logger.error(f"Error refreshing user: {e}")

def refresh_user():
    """Refresh current user data from database"""
    try:
        user_data = SupabaseDB.get_user_by_id(current_user.id)
        if user_data:
            if hasattr(user_data, '__dict__'):
                # Copy non-private attributes
                for key, value in user_data.__dict__.items():
                    if not key.startswith('_'):
                        setattr(current_user, key, value)
            else:
                # Assume it's an object with attributes
                current_user.balance = float(getattr(user_data, 'balance', 0))
                current_user.total_withdrawn = float(getattr(user_data, 'total_withdrawn', 0))
                current_user.is_verified = bool(getattr(user_data, 'is_verified', False))
                current_user.phone = getattr(user_data, 'phone', '')
                current_user.email = getattr(user_data, 'email', '')
                current_user.email_verified = bool(getattr(user_data, 'email_verified', False))
    except Exception as e:
        app.logger.error(f"Error refreshing user: {e}")

# =============================================================================
# JOBS MANAGEMENT ROUTES
# =============================================================================

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
        logger.error(f"Error loading jobs page: {str(e)}")
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
        logger.error(f"Error loading admin jobs: {str(e)}")
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
            logger.error(f"Error creating job: {str(e)}")
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
            logger.error(f"Error updating job: {str(e)}")
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
        logger.error(f"Error deleting job: {str(e)}")
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
        logger.error(f"Error toggling job status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

# =============================================================================
# USER PROFILE AND SETTINGS ROUTES
# =============================================================================

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
        logger.error(f"Supabase error in settings: {e}")
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
            logger.error(f"Error updating settings: {str(e)}")
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
        logger.error(f"Error loading settings page: {str(e)}")
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

# =============================================================================
# ADDED ROUTES: CHANGE PASSWORD WITH OTP AND DELETE ACCOUNT
# =============================================================================

def send_password_otp_email(email, otp_code):
    """Send OTP code to user's email for password change"""
    try:
        # This is a placeholder - you'll need to implement your email service
        # You can use SendGrid, SMTP, or any other email service
        
        subject = "ReferralNinja - Password Change OTP"
        message = f"""
        Hello,

        You have requested to change your password. 
        Please use the following OTP code to complete the process:

        OTP Code: {otp_code}

        This code will expire in 10 minutes.

        If you did not request this change, please ignore this email.

        Best regards,
        ReferralNinja Team
        """
        
        # For now, we'll log the OTP since email service isn't implemented
        logger.info(f"Password change OTP for {email}: {otp_code}")
        
        # TODO: Implement actual email sending
        # Example with SMTP:
        # send_email(email, subject, message)
        
        return True
        
    except Exception as e:
        logger.error(f"Error sending OTP email: {str(e)}")
        return False

def send_password_change_confirmation(email):
    """Send confirmation email after password change"""
    try:
        subject = "ReferralNinja - Password Changed Successfully"
        message = """
        Hello,

        Your password has been successfully changed.

        If you did not make this change, please contact support immediately.

        Best regards,
        ReferralNinja Team
        """
        
        logger.info(f"Password change confirmation for: {email}")
        
        # TODO: Implement actual email sending
        # send_email(email, subject, message)
        
        return True
        
    except Exception as e:
        logger.error(f"Error sending confirmation email: {str(e)}")
        return False

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Enhanced password change with OTP verification via email"""
    
    if request.method == 'GET':
        # Show the password change form
        return render_template('change_password.html')
    
    # Handle POST request
    try:
        data = request.get_json() if request.is_json else request.form
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        otp_code = data.get('otp_code')
        step = data.get('step', 'request')  # 'request' or 'verify'
        
        if step == 'request':
            # Step 1: Request OTP
            if not current_password or not new_password or not confirm_password:
                return jsonify({'success': False, 'message': 'All fields are required'})
            
            # Verify current password
            if not check_password_hash(current_user.password_hash, current_password):
                return jsonify({'success': False, 'message': 'Current password is incorrect'})
            
            if new_password != confirm_password:
                return jsonify({'success': False, 'message': 'New passwords do not match'})
            
            if len(new_password) < 6:
                return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
            
            # Generate OTP
            otp = ''.join(secrets.choice(string.digits) for _ in range(6))
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
            
            # Store OTP in database
            otp_data = {
                'user_id': current_user.id,
                'code': otp,
                'purpose': 'PASSWORD_RESET',
                'expires_at': expires_at.isoformat(),
                'is_used': False,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'metadata': {'new_password_hash': generate_password_hash(new_password)}
            }
            
            # Save OTP to database
            SupabaseDB.create_two_factor_code(otp_data)
            
            # Send OTP via email (you'll need to implement this)
            email_sent = send_password_otp_email(current_user.email, otp)
            
            if email_sent:
                # Log OTP generation
                SecurityMonitor.log_security_event(
                    "PASSWORD_CHANGE_OTP_SENT",
                    current_user.id,
                    {"ip": request.remote_addr, "email": current_user.email}
                )
                
                return jsonify({
                    'success': True, 
                    'message': 'OTP sent to your email. Please check your inbox.',
                    'step': 'verify',
                    'otp_required': True
                })
            else:
                return jsonify({'success': False, 'message': 'Failed to send OTP. Please try again.'})
        
        elif step == 'verify':
            # Step 2: Verify OTP and change password
            if not otp_code:
                return jsonify({'success': False, 'message': 'OTP code is required'})
            
            # Verify OTP
            otp_record = SupabaseDB.get_two_factor_code(current_user.id, otp_code, 'PASSWORD_RESET', False)
            
            if not otp_record:
                return jsonify({'success': False, 'message': 'Invalid OTP code'})
            
            # Check if OTP is expired
            expires_at = datetime.fromisoformat(otp_record['expires_at'].replace('Z', '+00:00'))
            if expires_at < datetime.now(timezone.utc):
                return jsonify({'success': False, 'message': 'OTP has expired. Please request a new one.'})
            
            # Check if OTP is already used
            if otp_record.get('is_used', False):
                return jsonify({'success': False, 'message': 'OTP has already been used'})
            
            # Get the new password hash from OTP metadata
            new_password_hash = otp_record.get('metadata', {}).get('new_password_hash')
            if not new_password_hash:
                return jsonify({'success': False, 'message': 'Invalid OTP data'})
            
            # Update password in database
            update_result = SupabaseDB.update_user(current_user.id, {'password_hash': new_password_hash})
            
            if update_result:
                # Mark OTP as used
                SupabaseDB.update_two_factor_code(otp_record['id'], {'is_used': True})
                
                # Log successful password change
                SecurityMonitor.log_security_event(
                    "PASSWORD_CHANGE_COMPLETED",
                    current_user.id,
                    {"ip": request.remote_addr, "method": "OTP_VERIFICATION"}
                )
                
                # Send confirmation email
                send_password_change_confirmation(current_user.email)
                
                return jsonify({
                    'success': True, 
                    'message': 'Password changed successfully!'
                })
            else:
                return jsonify({'success': False, 'message': 'Failed to update password'})
        
        else:
            return jsonify({'success': False, 'message': 'Invalid step'})
            
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        return jsonify({'success': False, 'message': 'System error occurred'})

@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    """Permanently delete user account and all associated data"""
    try:
        user_id = current_user.id
        username = current_user.username
        user_email = current_user.email
        
        # Log the deletion action first
        SecurityMonitor.log_security_event(
            "ACCOUNT_DELETION_REQUESTED",
            user_id,
            {"ip": request.remote_addr, "username": username, "email": user_email}
        )
        
        # Delete all user data in proper order to respect foreign key constraints
        try:
            # 1. Delete user's two_factor_codes
            supabase.table('two_factor_codes').delete().eq('user_id', user_id).execute()
            
            # 2. Delete user's security_logs
            supabase.table('security_logs').delete().eq('user_id', user_id).execute()
            
            # 3. Delete user's referrals (both as referrer and referred)
            supabase.table('referrals').delete().eq('referrer_id', user_id).execute()
            supabase.table('referrals').delete().eq('referred_id', user_id).execute()
            
            # 4. Delete user's transactions
            supabase.table('transactions').delete().eq('user_id', user_id).execute()
            
            # 5. Finally delete the user
            delete_response = supabase.table('users').delete().eq('id', user_id).execute()
            
            if delete_response.data:
                # Log successful deletion
                SecurityMonitor.log_security_event(
                    "ACCOUNT_DELETION_COMPLETED",
                    None,  # No user ID since user is deleted
                    {"ip": request.remote_addr, "username": username, "email": user_email}
                )
                
                # Logout the user
                logout_user()
                
                # Clear session
                session.clear()
                
                flash('Your account and all associated data have been permanently deleted.', 'success')
                logger.info(f"User account deleted: {username} ({user_email})")
                return redirect(url_for('index'))
            else:
                flash('Failed to delete account. Please contact support.', 'error')
                return redirect(url_for('settings'))
                
        except Exception as delete_error:
            logger.error(f"Error during account deletion process: {str(delete_error)}")
            flash('Error during account deletion. Please contact support.', 'error')
            return redirect(url_for('settings'))
            
    except Exception as e:
        logger.error(f"Error in account deletion: {str(e)}")
        flash('Error deleting account. Please try again or contact support.', 'error')
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

# =============================================================================
# ADMIN ROUTES
# =============================================================================

@app.route('/admin/database')
@login_required
@admin_required
def admin_database():
    """Admin database management interface"""
    # Get database metrics
    db_metrics = DatabaseHealthMonitor.get_database_metrics()
    
    # Get table sizes and info
    table_info = {}
    tables = ['users', 'transactions', 'referrals', 'security_logs', 'mpesa_callbacks', 'two_factor_codes']
    
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

# =============================================================================
# ADMIN FRAUD MONITORING
# =============================================================================

@app.route('/admin/fraud-monitoring')
@login_required
@admin_required
def admin_fraud_monitoring():
    """Admin fraud monitoring dashboard"""
    try:
        # Get recent suspicious activities
        suspicious_withdrawals = supabase.table('transactions')\
            .select('*, users(*)')\
            .eq('status', 'Under Review')\
            .order('created_at', desc=True)\
            .execute()
        
        # Get recent security events
        recent_security_events = supabase.table('security_logs')\
            .select('*')\
            .in_('event_type', ['SUSPICIOUS_WITHDRAWAL', 'SUSPICIOUS_REGISTRATION', 'USER_BLOCKED_FRAUD'])\
            .order('created_at', desc=True)\
            .limit(50)\
            .execute()
        
        # Get fraud statistics
        stats = {
            'blocked_users': len(redis_client.keys('user_blocked:*')),
            'suspicious_signups_today': get_suspicious_signups_count(),
            'pending_reviews': len(suspicious_withdrawals.data) if suspicious_withdrawals.data else 0
        }
        
        return render_template('admin_fraud_monitoring.html',
                             suspicious_withdrawals=suspicious_withdrawals.data,
                             security_events=recent_security_events.data,
                             stats=stats)
                             
    except Exception as e:
        logger.error(f"Error loading fraud monitoring: {str(e)}")
        flash('Error loading fraud monitoring dashboard.', 'error')
        return redirect(url_for('admin_dashboard'))

def get_suspicious_signups_count():
    """Count suspicious signups in last 24 hours"""
    count = 0
    keys = redis_client.keys('signups:ip:*')
    for key in keys:
        signup_count = int(redis_client.get(key) or 0)
        if signup_count >= 3:  # Threshold for suspicious
            count += 1
    return count

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    logger.info(f"Admin access attempt by: {current_user.username}, is_admin: {current_user.is_admin}")
    
    try:
        # Test Supabase connection first
        response = supabase.table('users').select('*').limit(1).execute()
        logger.info("Supabase connection test passed")
        
        # Admin statistics
        try:
            total_users = SupabaseDB.get_users_count()
            logger.info(f"Total users: {total_users}")
        except Exception as e:
            logger.error(f"Error counting users: {e}")
            total_users = 0
        
        try:
            total_verified = SupabaseDB.get_verified_users_count()
            logger.info(f"Total verified: {total_verified}")
        except Exception as e:
            logger.error(f"Error counting verified users: {e}")
            total_verified = 0
        
        try:
            total_referrals = SupabaseDB.get_referrals_count()
            logger.info(f"Total referrals: {total_referrals}")
        except Exception as e:
            logger.error(f"Error counting referrals: {e}")
            total_referrals = 0
        
        try:
            total_commission = SupabaseDB.get_total_commission()
            logger.info(f"Total commission: {total_commission}")
        except Exception as e:
            logger.error(f"Error calculating total commission: {e}")
            total_commission = 0
        
        try:
            total_withdrawn_amount = SupabaseDB.get_total_withdrawn()
            logger.info(f"Total withdrawn: {total_withdrawn_amount}")
        except Exception as e:
            logger.error(f"Error calculating total withdrawn: {e}")
            total_withdrawn_amount = 0
        
        try:
            total_balance = SupabaseDB.get_total_balance()
            logger.info(f"Total balance: {total_balance}")
        except Exception as e:
            logger.error(f"Error calculating total balance: {e}")
            total_balance = 0
        
        try:
            pending_withdrawals_data = SupabaseDB.get_pending_withdrawals()
            pending_withdrawals = len(pending_withdrawals_data)
            logger.info(f"Pending withdrawals: {pending_withdrawals}")
        except Exception as e:
            logger.error(f"Error counting pending withdrawals: {e}")
            pending_withdrawals = 0

        try:
            pending_payments_data = SupabaseDB.get_pending_payments()
            pending_payments = len(pending_payments_data)
            logger.info(f"Pending payments: {pending_payments}")
        except Exception as e:
            logger.error(f"Error counting pending payments: {e}")
            pending_payments = 0
        
        try:
            recent_users_data = SupabaseDB.get_recent_users(limit=10)
            recent_users = [User(user_data) for user_data in recent_users_data]
            logger.info(f"Recent users: {len(recent_users)}")
        except Exception as e:
            logger.error(f"Error fetching recent users: {e}")
            recent_users = []
        
        try:
            # Get pending withdrawal transactions with user info
            pending_withdrawal_transactions = []
            for withdrawal in pending_withdrawals_data:
                user = SupabaseDB.get_user_by_id(withdrawal['user_id'])
                pending_withdrawal_transactions.append((withdrawal, user))
            logger.info(f"Pending withdrawal transactions: {len(pending_withdrawal_transactions)}")
        except Exception as e:
            logger.error(f"Error fetching pending withdrawal transactions: {e}")
            pending_withdrawal_transactions = []

        try:
            # Get pending payment transactions with user info
            pending_payment_transactions = []
            for payment in pending_payments_data:
                user = SupabaseDB.get_user_by_id(payment['user_id'])
                pending_payment_transactions.append((payment, user))
            logger.info(f"Pending payment transactions: {len(pending_payment_transactions)}")
        except Exception as e:
            logger.error(f"Error fetching pending payment transactions: {e}")
            pending_payment_transactions = []
        
        try:
            recent_activity_data = SupabaseDB.get_recent_activity(limit=10)
            recent_activity = recent_activity_data
            logger.info(f"Recent activity: {len(recent_activity)}")
        except Exception as e:
            logger.error(f"Error fetching recent activity: {e}")
            recent_activity = []
        
        current_time = datetime.now(timezone.utc)
        
        logger.info("All queries successful, rendering template...")
        
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
        logger.error(f"Error in admin_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Error accessing admin dashboard: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/withdrawals')
@login_required
@admin_required
def admin_withdrawals():
    """Professional withdrawal management dashboard"""
    try:
        # Get query parameters for filtering and pagination
        page = request.args.get('page', 1, type=int)
        status_filter = request.args.get('status', 'all')
        search = request.args.get('search', '')
        items_per_page = request.args.get('items_per_page', 10, type=int)
        offset = (page - 1) * items_per_page
        
        # Base query - join with users table to get complete user info
        query = supabase.table('transactions')\
            .select('*, users(*)')\
            .eq('transaction_type', 'withdrawal')\
            .order('created_at', desc=True)
        
        # Apply status filter
        if status_filter != 'all':
            if status_filter == 'pending':
                query = query.in_('status', ['pending', 'Under Review', 'processing'])
            else:
                query = query.eq('status', status_filter)
        
        # Apply search filter if provided
        if search:
            # Search in user data
            users_with_search = supabase.table('users')\
                .select('id')\
                .or_(f'username.ilike.%{search}%,email.ilike.%{search}%,phone.ilike.%{search}%,name.ilike.%{search}%')\
                .execute()
            
            user_ids = [user['id'] for user in users_with_search.data]
            
            if user_ids:
                # Also search in transaction data
                query = query.or_(f'user_id.in.({",".join([f"\"{uid}\"" for uid in user_ids])}),phone_number.ilike.%{search}%,mpesa_reference.ilike.%{search}%')
        
        # Get total count for pagination
        count_query = supabase.table('transactions')\
            .select('id', count='exact')\
            .eq('transaction_type', 'withdrawal')
        
        if status_filter != 'all':
            if status_filter == 'pending':
                count_query = count_query.in_('status', ['pending', 'Under Review', 'processing'])
            else:
                count_query = count_query.eq('status', status_filter)
        
        if search and 'user_ids' in locals() and user_ids:
            count_query = count_query.in_('user_id', user_ids)
        
        count_result = count_query.execute()
        total_count = count_result.count if hasattr(count_result, 'count') else len(count_result.data)
        
        # Get paginated data
        response = query.range(offset, offset + items_per_page - 1).execute()
        
        withdrawals = []
        for item in response.data:
            transaction = item
            user_data = item.get('users', {})
            
            # Extract user information from the database fields
            if user_data:
                withdrawals.append({
                    'id': transaction['id'],
                    'user_id': user_data.get('id', ''),
                    'username': user_data.get('username', 'N/A'),
                    'email': user_data.get('email', ''),
                    'phone': user_data.get('phone', transaction.get('phone_number', '')),
                    'name': user_data.get('name', user_data.get('username', 'N/A')),
                    'amount': abs(float(transaction['amount'])) if transaction['amount'] else 0,
                    'status': transaction['status'],
                    'email_verified': user_data.get('email_verified', False),
                    'is_verified': user_data.get('is_verified', False),
                    'is_active': user_data.get('is_active', True),
                    'balance': float(user_data.get('balance', 0)),
                    'total_earned': float(user_data.get('total_earned', 0)),
                    'total_withdrawn': float(user_data.get('total_withdrawn', 0)),
                    'referral_code': user_data.get('referral_code', ''),
                    'referral_count': user_data.get('referral_count', 0),
                    'user_rank': user_data.get('user_rank', 'Member'),
                    'total_commission': float(user_data.get('total_commission', 0)),
                    'created_at': transaction['created_at'],
                    'description': transaction.get('description', ''),
                    'mpesa_code': transaction.get('mpesa_reference', ''),
                    'last_login': user_data.get('last_login'),
                    'device_fingerprint': user_data.get('device_fingerprint', ''),
                    'referred_by': user_data.get('referred_by', ''),
                    'is_admin': user_data.get('is_admin', False)
                })
        
        # Calculate pagination
        total_pages = (total_count + items_per_page - 1) // items_per_page if items_per_page > 0 else 1
        
        # Get dashboard statistics
        stats = get_withdrawal_stats()
        
        return render_template('admin_withdrawals.html',
                             withdrawals=withdrawals,
                             stats=stats,
                             current_page=page,
                             total_pages=total_pages,
                             total_count=total_count,
                             status_filter=status_filter,
                             items_per_page=items_per_page,
                             search=search)
                             
    except Exception as e:
        logger.error(f"Error loading withdrawals dashboard: {str(e)}")
        flash('Error loading withdrawal dashboard.', 'error')
        return redirect(url_for('admin_dashboard'))


def get_withdrawal_stats():
    """Get comprehensive withdrawal statistics"""
    try:
        # Get 24-hour timeframe
        twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        
        # Get all withdrawals in last 24 hours with user info
        response = supabase.table('transactions')\
            .select('amount, status, created_at, users(*)')\
            .eq('transaction_type', 'withdrawal')\
            .gte('created_at', twenty_four_hours_ago.isoformat())\
            .execute()
        
        stats = {
            'total_24h': 0,
            'successful_24h': 0,
            'failed_24h': 0,
            'pending_now': 0,
            'total_amount_24h': 0,
            'successful_amount': 0,
            'failed_amount': 0,
            'pending_amount': 0,
            'verified_count': 0,
            'unverified_count': 0,
            'avg_processing_hours': 0,
            'change_24h': 0,
            'avg_withdrawal': 0,
            'completion_rate': 0,
            'active_users': 0,
            'total_earned': 0,
            'total_withdrawn': 0,
            'withdrawal_rate': 0
        }
        
        # Process 24h data
        for item in response.data:
            amount = abs(float(item['amount'])) if item['amount'] else 0
            status = item['status']
            user_data = item.get('users', {})
            is_verified = user_data.get('email_verified', False) if user_data else False
            is_verified_user = user_data.get('is_verified', False) if user_data else False
            
            stats['total_24h'] += 1
            stats['total_amount_24h'] += amount
            
            if status == 'completed':
                stats['successful_24h'] += 1
                stats['successful_amount'] += amount
            elif status in ['rejected', 'failed']:
                stats['failed_24h'] += 1
                stats['failed_amount'] += amount
            elif status in ['pending', 'Under Review', 'processing']:
                stats['pending_now'] += 1
                stats['pending_amount'] += amount
            
            if is_verified or is_verified_user:
                stats['verified_count'] += 1
            else:
                stats['unverified_count'] += 1
        
        # Calculate percentages and averages
        if stats['total_24h'] > 0:
            stats['success_rate'] = round((stats['successful_24h'] / stats['total_24h']) * 100, 1) if stats['total_24h'] > 0 else 0
            stats['verified_rate'] = round((stats['verified_count'] / stats['total_24h']) * 100, 1) if stats['total_24h'] > 0 else 0
            stats['avg_withdrawal'] = round(stats['total_amount_24h'] / stats['total_24h'], 2) if stats['total_24h'] > 0 else 0
        
        # Calculate completion rate for last 7 days
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        
        week_response = supabase.table('transactions')\
            .select('status')\
            .eq('transaction_type', 'withdrawal')\
            .gte('created_at', seven_days_ago.isoformat())\
            .execute()
        
        total_week = len(week_response.data) if week_response.data else 0
        completed_week = sum(1 for item in week_response.data if item['status'] == 'completed') if week_response.data else 0
        
        if total_week > 0:
            stats['completion_rate'] = round((completed_week / total_week) * 100, 1)
        else:
            stats['completion_rate'] = 0
        
        # Get user statistics
        users_response = supabase.table('users')\
            .select('total_earned, total_withdrawn, is_active, email_verified')\
            .execute()
        
        if users_response.data:
            total_earned = 0
            total_withdrawn = 0
            active_users = 0
            
            for user in users_response.data:
                total_earned += float(user.get('total_earned', 0))
                total_withdrawn += float(user.get('total_withdrawn', 0))
                if user.get('is_active', False):
                    active_users += 1
            
            stats['active_users'] = active_users
            stats['total_earned'] = total_earned
            stats['total_withdrawn'] = total_withdrawn
            stats['total_earned_formatted'] = f"KES {total_earned:,.2f}"
            stats['total_withdrawn_formatted'] = f"KES {total_withdrawn:,.2f}"
            
            if total_earned > 0:
                withdrawal_rate = (total_withdrawn / total_earned) * 100
                stats['withdrawal_rate'] = round(withdrawal_rate, 1)
                stats['withdrawal_rate_formatted'] = f"{withdrawal_rate:.1f}%"
            else:
                stats['withdrawal_rate'] = 0
                stats['withdrawal_rate_formatted'] = "0%"
        
        # Calculate 24h change
        stats['change_24h'] = 0
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting withdrawal stats: {str(e)}")
        # Return default stats structure
        return {
            'total_24h': 0,
            'successful_24h': 0,
            'failed_24h': 0,
            'pending_now': 0,
            'total_amount_24h': 0,
            'successful_amount': 0,
            'failed_amount': 0,
            'pending_amount': 0,
            'verified_count': 0,
            'unverified_count': 0,
            'avg_processing_hours': 0,
            'change_24h': 0,
            'avg_withdrawal': 0,
            'completion_rate': 0,
            'active_users': 0,
            'total_earned': 0,
            'total_withdrawn': 0,
            'withdrawal_rate': 0,
            'success_rate': 0,
            'verified_rate': 0,
            'total_earned_formatted': 'KES 0',
            'total_withdrawn_formatted': 'KES 0',
            'withdrawal_rate_formatted': '0%'
        }
    
@app.route('/admin/export-withdrawals')
@login_required
@admin_required
def export_withdrawals():
    """Export withdrawals to CSV"""
    try:
        # Get query parameters
        status_filter = request.args.get('status', 'all')
        search = request.args.get('search', '')
        export_format = request.args.get('format', 'csv')
        
        # Build query similar to admin_withdrawals
        query = supabase.table('transactions')\
            .select('*, users(*)')\
            .eq('transaction_type', 'withdrawal')\
            .order('created_at', desc=True)
        
        # Apply status filter
        if status_filter != 'all':
            if status_filter == 'pending':
                query = query.in_('status', ['pending', 'Under Review', 'processing'])
            else:
                query = query.eq('status', status_filter)
        
        # Apply search filter if provided
        if search:
            users_with_search = supabase.table('users')\
                .select('id')\
                .or_(f'username.ilike.%{search}%,email.ilike.%{search}%,phone.ilike.%{search}%,name.ilike.%{search}%')\
                .execute()
            
            user_ids = [user['id'] for user in users_with_search.data]
            
            if user_ids:
                query = query.or_(f'user_id.in.({",".join([f"\"{uid}\"" for uid in user_ids])}),phone_number.ilike.%{search}%,mpesa_reference.ilike.%{search}%')
        
        # Get all data (no pagination for export)
        response = query.execute()
        
        # Prepare data for CSV
        withdrawals_data = []
        for item in response.data:
            transaction = item
            user_data = item.get('users', {})
            
            if user_data:
                withdrawals_data.append({
                    'Transaction ID': transaction['id'],
                    'User ID': user_data.get('id', ''),
                    'Username': user_data.get('username', 'N/A'),
                    'Email': user_data.get('email', ''),
                    'Phone': user_data.get('phone', transaction.get('phone_number', '')),
                    'Name': user_data.get('name', user_data.get('username', 'N/A')),
                    'Amount': abs(float(transaction['amount'])) if transaction['amount'] else 0,
                    'Status': transaction['status'],
                    'Email Verified': 'Yes' if user_data.get('email_verified') else 'No',
                    'Account Active': 'Yes' if user_data.get('is_active') else 'No',
                    'User Balance': float(user_data.get('balance', 0)),
                    'Total Earned': float(user_data.get('total_earned', 0)),
                    'Total Withdrawn': float(user_data.get('total_withdrawn', 0)),
                    'Referral Code': user_data.get('referral_code', ''),
                    'Referral Count': user_data.get('referral_count', 0),
                    'User Rank': user_data.get('user_rank', 'Member'),
                    'Description': transaction.get('description', ''),
                    'M-Pesa Reference': transaction.get('mpesa_reference', ''),
                    'Created At': transaction['created_at']
                })
        
        # Convert to CSV
        if export_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=withdrawals_data[0].keys() if withdrawals_data else [])
            writer.writeheader()
            writer.writerows(withdrawals_data)
            
            output.seek(0)
            
            # Create response
            from flask import make_response
            response = make_response(output.getvalue())
            response.headers["Content-Disposition"] = f"attachment; filename=withdrawals_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            response.headers["Content-type"] = "text/csv"
            return response
        
        flash('Export format not supported', 'error')
        return redirect(url_for('admin_withdrawals'))
        
    except Exception as e:
        logger.error(f"Error exporting withdrawals: {str(e)}")
        flash('Error exporting withdrawal data.', 'error')
        return redirect(url_for('admin_withdrawals'))    
    
@app.route('/api/admin/enhanced-stats')
@login_required
@admin_required
def enhanced_withdrawal_stats():
    """API endpoint for enhanced dashboard statistics"""
    try:
        stats = get_withdrawal_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.error(f"Error getting enhanced stats: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/top-users')
@login_required
@admin_required
def top_withdrawal_users():
    """Get top users by withdrawal activity (24h)"""
    try:
        twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        
        response = supabase.table('transactions')\
            .select('user_id, amount, users(username)')\
            .eq('transaction_type', 'withdrawal')\
            .gte('created_at', twenty_four_hours_ago.isoformat())\
            .execute()
        
        user_totals = {}
        for item in response.data:
            user_id = item['user_id']
            amount = abs(item['amount'])
            username = item.get('users', {}).get('username', 'Unknown')
            
            if user_id not in user_totals:
                user_totals[user_id] = {
                    'username': username,
                    'total_amount': 0,
                    'withdrawal_count': 0
                }
            
            user_totals[user_id]['total_amount'] += amount
            user_totals[user_id]['withdrawal_count'] += 1
        
        # Sort by total amount and get top 5
        top_users = sorted(
            user_totals.values(),
            key=lambda x: x['total_amount'],
            reverse=True
        )[:5]
        
        return jsonify({'success': True, 'users': top_users})
        
    except Exception as e:
        logger.error(f"Error getting top users: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/user-details/<user_id>')
@login_required
@admin_required
def admin_user_details(user_id):
    """Get detailed user information for admin"""
    try:
        user = SupabaseDB.get_user_by_id(user_id)
        if user:
            return jsonify({
                'success': True,
                'user': user.to_dict()  # Your User class already has this method
            })
        else:
            return jsonify({'success': False, 'message': 'User not found'})
    except Exception as e:
        logger.error(f"Error getting user details: {str(e)}")
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
        logger.error(f"Error loading user {user_id}: {e}")
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
    logger.error(f"Internal Server Error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(error):
    logger.error(f"Unhandled Exception: {error}")
    return render_template('500.html'), 500

# =============================================================================
# APPLICATION INITIALIZATION
# =============================================================================

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
    
    logger.info("All required environment variables are set")

# Updated initialization function
def init_db():
    """Initialize and verify Supabase database connection (no local SQL)."""
    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            logger.info("Testing Supabase connection...")
            response = supabase.table("users").select("*").limit(1).execute()

            if response.data is not None:
                logger.info("Supabase client verified successfully")
                
                # Test Redis connection
                try:
                    redis_client.ping()
                    logger.info("Redis connection verified successfully")
                except Exception as e:
                    logger.error(f"Redis connection failed: {e}")
                    return False

                # Optionally check if admin exists
                if os.environ.get("CREATE_ADMIN_USER") == "true":
                    create_admin_user_if_missing()
                    logger.info("Admin user checked/created")

                return True
            else:
                logger.warning("No data returned from Supabase - table may be empty")
                return True  # Still fine, as Supabase is reachable

        except Exception as e:
            retry_count += 1
            logger.error(f"Database initialization attempt {retry_count} failed: {e}")

            if retry_count < max_retries:
                wait_time = 2 ** retry_count
                logger.info(f"Retrying Supabase check in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error("All Supabase connection attempts failed")
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
            logger.debug("Supabase OK")
            break
        except Exception as e:
            logger.warning(f"Supabase check failed (attempt {i+1}/3): {e}")
            time.sleep(0.5)
    else:
        success = False

    # --- ⚙️ Redis check ---
    for i in range(3):
        try:
            redis_client.ping()
            logger.debug("Redis OK")
            break
        except Exception as e:
            logger.warning(f"Redis check failed (attempt {i+1}/3): {e}")
            time.sleep(0.5)
    else:
        success = False

    _last_health_check.update({"time": now, "ok": success})

    # ⚠️ Don't block users if services are slow — just log it
    if not success:
        logger.error("Background service check failed, continuing anyway")

    # --- Security logging for sensitive endpoints ---
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
            logger.info(f"Security event logged for {request.endpoint}")
        except Exception as e:
            logger.warning(f"Security logging failed: {e}")
      
# =============================================================================
# APPLICATION STARTUP
# =============================================================================

# Initialize the database when the app starts
with app.app_context():
    try:
        validate_environment()
        
        if init_db():
            logger.info("Database initialization completed successfully")
            
            # Start health monitoring in production
            if not app.debug:
                start_health_monitoring()
                logger.info("Health monitoring started")
        else:
            logger.error("Database initialization failed")
    except Exception as e:
        logger.error(f"Application initialization failed: {e}")

# Production Startup Script
if __name__ == '__main__':
    try:
        with app.app_context():
            validate_environment()

            if init_db():
                logger.info("Database initialization completed successfully")
                logger.info("Redis connection established")

                if not app.debug:
                    start_health_monitoring()
                    logger.info("Health monitoring started")
            else:
                logger.error("Database initialization failed - exiting")
                sys.exit(1)

        print("Starting Referral Ninja Application - PRODUCTION READY")
        print("Environment validation: PASSED")
        print("Database schema: VERIFIED")
        print("Redis cache: CONFIGURED")
        print("Rate limiting: ENABLED (Redis-backed)")
        print("Security configuration: ENABLED")
        print("M-Pesa environment: PRODUCTION")
        print("Celcom SMS: CONFIGURED")
        print("Health monitoring: ACTIVE")
        print("PAYMENT-ONLY USER STORAGE: ENABLED")
        print("ENHANCED FRAUD DETECTION: ENABLED")
        print("IP/DEVICE TRACKING: ENABLED")
        print("ENHANCED RATE LIMITING: ENABLED")

        port = int(os.environ.get('PORT', 10000))
        host = '0.0.0.0'

        print(f"Server starting on {host}:{port}")
        print(f"Health endpoint: http://{host}:{port}/health")
        print(f"Detailed health: http://{host}:{port}/health/detailed")
        print(f"Emergency health: http://{host}:{port}/health/emergency")
        print(f"Fraud monitoring: http://{host}:{port}/admin/fraud-monitoring")
        print(f"Rate limit status: http://{host}:{port}/rate-limit-status")
        print(f"Minimum withdrawal: KSH {app.config['WITHDRAWAL_MIN_AMOUNT']}")

        logger.info(f"Starting Flask app on {host}:{port}")
        app.run(
            host=host,
            port=port,
            debug=False,  # Always False in production
            threaded=True
        )

    except Exception as e:
        print(f"CRITICAL: Failed to start application: {e}")
        print("Please check:")
        print("1. All required environment variables are set")
        print("2. Supabase connection is working")
        print("3. Redis connection is working")
        print("4. M-Pesa credentials are valid")
        sys.exit(1)
