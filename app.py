from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
import uuid
import re
import hashlib
import os
import math
import asyncio
from telegram import Bot
import threading
import requests
import secrets
from sqlalchemy import text
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'referral-ninja-secret-key-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///referralninja.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session configuration for network access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Telegram Configuration
TELEGRAM_BOT_TOKEN = '7870070553:AAGjMBMB2oDhmA7bxrm0ibzNya_D3hTM2Ec'
TELEGRAM_CHAT_ID = '7716238167'

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Admin Required Decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

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

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    balance = db.Column(db.Float, default=0.0)
    referral_code = db.Column(db.String(10), unique=True)
    referred_by = db.Column(db.String(10))
    referral_balance = db.Column(db.Float, default=0.0)
    total_earned = db.Column(db.Float, default=0.0)
    total_withdrawn = db.Column(db.Float, default=0.0)
    referral_count = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Ranking system fields
    user_rank = db.Column(db.String(20), default='Bronze')
    total_commission = db.Column(db.Float, default=0.0)
    
    # Referral source tracking
    referral_source = db.Column(db.String(20), default='direct')
    
    # Password reset fields
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expires = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_phone_linked_referral_code(self):
        phone_hash = hashlib.md5(self.phone_number.encode()).hexdigest()[:6].upper()
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

class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    referred_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    referral_code_used = db.Column(db.String(10))
    commission_earned = db.Column(db.Float, default=50.0)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    referrer = db.relationship('User', foreign_keys=[referrer_id], backref='referrals_made')
    referred = db.relationship('User', foreign_keys=[referred_id], backref='referrals_received')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    mpesa_code = db.Column(db.String(50))
    phone_number = db.Column(db.String(20))
    description = db.Column(db.Text)
    mpesa_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    user = db.relationship('User', backref='transactions')

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        print(f"Error loading user {user_id}: {e}")
        return None

# Database health check
@app.before_request
def before_request():
    try:
        db.session.execute(text('SELECT 1'))
    except Exception as e:
        print(f"Database connection error: {e}")
        db.session.rollback()

# Telegram Functions
async def send_telegram_message_async(message):
    try:
        if TELEGRAM_BOT_TOKEN == 'your_bot_token_here' or TELEGRAM_CHAT_ID == 'your_chat_id_here':
            print("Telegram notifications disabled - please configure bot token and chat ID")
            return
            
        bot = Bot(token=TELEGRAM_BOT_TOKEN)
        async with bot:
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode='HTML')
    except Exception as e:
        print(f"Telegram notification failed: {str(e)}")

def send_telegram_notification(message):
    try:
        asyncio.run(send_telegram_message_async(message))
    except Exception as e:
        print(f"Failed to send Telegram notification: {str(e)}")

def send_mpesa_notification_to_telegram(user, transaction):
    try:
        message = f"""
🔔 <b>🚨 IMMEDIATE: New M-PESA Payment Submitted</b>

👤 <b>User Details:</b>
• Username: {user.username}
• Email: {user.email}
• Phone: {user.phone_number}
• User ID: #{user.id}
• Referral Code: {user.referral_code}

💳 <b>Payment Information:</b>
• MPESA Code: <code>{transaction.mpesa_code}</code>
• Amount: KSH {transaction.amount}
• Status: ⏳ Pending Verification

📝 <b>MPESA Message:</b>
<pre>{transaction.mpesa_message}</pre>

🕒 <b>Time Submitted:</b>
{transaction.created_at.strftime('%Y-%m-%d %H:%M:%S')}

⚠️ <i>Please verify this payment in the admin dashboard.</i>
"""
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        return True
    except Exception as e:
        print(f"Error sending M-PESA notification to Telegram: {str(e)}")
        return False

def send_registration_notification_to_telegram(user, referral_code=None):
    try:
        message = f"""
🎯 <b>New User Registration</b>

👤 <b>User Details:</b>
• Username: {user.username}
• Email: {user.email} 
• Phone: {user.phone_number}
• User Referral Code: {user.referral_code}

🕒 <b>Registration Time:</b>
{user.created_at.strftime('%Y-%m-%d %H:%M:%S')}
"""
        if referral_code:
            referrer = User.query.filter_by(referral_code=referral_code).first()
            if referrer:
                message += f"\n🔗 <b>Referred by:</b> {referral_code} (User: {referrer.username} - ID: {referrer.id})"
                message += f"\n💰 <b>Referral Status:</b> ✅ Valid - Commission will be awarded after payment"
            else:
                message += f"\n⚠️ <b>Referral Code:</b> {referral_code} (Invalid - No referrer found)"
        else:
            message += "\n📝 <b>Referral:</b> No referral code used"
        
        message += f"\n📊 <b>Referral Source:</b> {user.referral_source}"
        message += "\n\n💳 <i>Waiting for payment verification.</i>"
        
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        return True
    except Exception as e:
        print(f"Error sending registration notification to Telegram: {str(e)}")
        return False

def send_admin_action_notification(action, user, transaction, admin_user):
    try:
        if action == 'approved':
            message = f"""
✅ <b>Payment Approved by Admin</b>

👤 <b>Admin:</b> {admin_user.username}
👤 <b>User Activated:</b>
• Username: {user.username}
• Email: {user.email}
• User ID: #{user.id}

💳 <b>Payment Details:</b>
• MPESA Code: <code>{transaction.mpesa_code}</code>
• Amount: KSH {transaction.amount}
• Status: ✅ Approved

🕒 <b>Approval Time:</b>
{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}

🎉 <i>User account has been activated successfully!</i>
"""
        else:
            message = f"""
❌ <b>Payment Rejected by Admin</b>

👤 <b>Admin:</b> {admin_user.username}
👤 <b>User:</b>
• Username: {user.username}
• Email: {user.email}
• User ID: #{user.id}

💳 <b>Payment Details:</b>
• MPESA Code: <code>{transaction.mpesa_code}</code>
• Amount: KSH {transaction.amount}
• Status: ❌ Rejected

🕒 <b>Rejection Time:</b>
{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}

⚠️ <i>User needs to submit a new payment message.</i>
"""
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        return True
    except Exception as e:
        print(f"Error sending admin action notification to Telegram: {str(e)}")
        return False

# Password Reset Functions
def generate_reset_token():
    return secrets.token_urlsafe(32)

def send_password_reset_email(user, reset_url):
    try:
        print(f"Password reset for {user.email}: {reset_url}")
        message = f"""
🔐 <b>Password Reset Request</b>

👤 <b>User Details:</b>
• Username: {user.username}
• Email: {user.email}
• User ID: #{user.id}

🔄 <b>Reset Link:</b>
<code>{reset_url}</code>

🕒 <b>Request Time:</b>
{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}

⚠️ <i>This link will expire in 1 hour.</i>
"""
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        return True
    except Exception as e:
        print(f"Error sending password reset email: {str(e)}")
        return False

def send_password_reset_confirmation(user):
    try:
        message = f"""
✅ <b>Password Reset Successful</b>

👤 <b>User Details:</b>
• Username: {user.username}
• Email: {user.email}
• User ID: #{user.id}

🕒 <b>Reset Time:</b>
{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}

📍 <b>Location:</b> {request.remote_addr}

🔒 <i>If you did not perform this action, please contact support immediately.</i>
"""
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        return True
    except Exception as e:
        print(f"Error sending password reset confirmation: {str(e)}")
        return False

# Helper Functions
def validate_referral_code(code):
    if not code:
        return None
    referrer = User.query.filter_by(referral_code=code).first()
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

# Debug and Health Check Routes
@app.route('/health')
def health_check():
    try:
        db.session.execute(text('SELECT 1'))
        user_count = User.query.count()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'user_count': user_count,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'error',
            'error': str(e)
        }), 500

@app.route('/debug')
def debug_info():
    try:
        db_status = "connected"
        db.session.execute(text('SELECT 1'))
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return jsonify({
        'flask_env': os.environ.get('FLASK_ENV', 'production'),
        'database_status': db_status,
        'current_user_authenticated': current_user.is_authenticated,
        'session_keys': list(session.keys()),
        'total_users': User.query.count(),
        'total_transactions': Transaction.query.count()
    })

@app.route('/debug-admin')
@login_required
def debug_admin():
    if not current_user.is_admin:
        return "Not admin"
    
    try:
        print("Testing User.query.count()...")
        total_users = User.query.count()
        print(f"Total users: {total_users}")
        
        print("Testing User.query.filter_by(is_verified=True).count()...")
        total_verified = User.query.filter_by(is_verified=True).count()
        print(f"Total verified: {total_verified}")
        
        print("Testing Referral.query.count()...")
        total_referrals = Referral.query.count()
        print(f"Total referrals: {total_referrals}")
        
        print("Testing commission sum...")
        total_commission = db.session.query(db.func.sum(User.total_commission)).scalar() or 0
        print(f"Total commission: {total_commission}")
        
        return jsonify({
            'status': 'success',
            'total_users': total_users,
            'total_verified': total_verified,
            'total_referrals': total_referrals,
            'total_commission': total_commission
        })
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Debug error: {error_details}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'traceback': error_details
        })

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    print(f"Internal Server Error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(error):
    db.session.rollback()
    print(f"Unhandled Exception: {error}")
    return render_template('500.html'), 500

# Application Routes
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
        return redirect(url_for('payment_instructions'))
    
    total_withdrawn = db.session.query(db.func.sum(Transaction.amount)).filter(
        Transaction.user_id == current_user.id,
        Transaction.transaction_type == 'withdrawal',
        Transaction.status == 'completed'
    ).scalar() or 0.0
    
    pending_withdrawals = Transaction.query.filter_by(
        user_id=current_user.id,
        transaction_type='withdrawal',
        status='pending'
    ).count()
    
    withdrawals = Transaction.query.filter_by(
        user_id=current_user.id,
        transaction_type='withdrawal'
    ).order_by(Transaction.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html',
                         total_withdrawn=abs(total_withdrawn),
                         pending_withdrawals=pending_withdrawals,
                         withdrawals=withdrawals)

def get_user_ranking(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return None
    
    ranked_users = User.query.filter(User.is_active==True)\
        .order_by(User.total_commission.desc())\
        .all()
    
    for index, ranked_user in enumerate(ranked_users):
        if ranked_user.id == user_id:
            return {
                'position': index + 1,
                'total_users': len(ranked_users),
                'user_rank': user.user_rank
            }
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = bool(request.form.get('remember_me'))
        
        print(f"Login attempt for username: {username}")
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('auth/login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            print(f"User found: {user.username}, is_verified: {user.is_verified}")
            if user.check_password(password):
                if not user.is_verified:
                    flash('Please complete your payment verification before logging in.', 'warning')
                    session['pending_verification_user'] = user.id
                    return redirect(url_for('payment_instructions'))
                
                login_user(user, remember=remember_me)
                next_page = request.args.get('next')
                
                flash('Login successful!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                print("Password incorrect")
                flash('Invalid username or password.', 'error')
        else:
            print("User not found")
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    referral_code = request.args.get('ref', '')
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        referral_code = request.form.get('referral_code')
        
        if not re.match(r'^254[0-9]{9}$', phone_number) and not re.match(r'^07[0-9]{8}$', phone_number):
            flash('Please enter a valid Kenyan phone number.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if phone_number.startswith('07'):
            phone_number = '254' + phone_number[1:]
        
        if User.query.filter_by(phone_number=phone_number).first():
            flash('Phone number already registered.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        referrer = None
        if referral_code:
            referrer = validate_referral_code(referral_code)
            if not referrer:
                flash('Invalid referral code. Please check and try again.', 'error')
                return render_template('auth/register.html', referral_code=referral_code)
        
        user = User(
            username=username,
            email=email,
            phone_number=phone_number,
            is_verified=False
        )
        user.set_password(password)
        user.generate_phone_linked_referral_code()
        
        if referrer:
            user.referred_by = referral_code
        
        if referral_code:
            if request.args.get('ref'):
                user.referral_source = 'referral_link'
            else:
                user.referral_source = 'manual_entry'
        else:
            user.referral_source = 'direct'
        
        try:
            db.session.add(user)
            db.session.commit()
            
            send_registration_notification_to_telegram(user, referral_code)
            
            flash('Registration successful! Please complete KSH 200 payment to activate your account.', 'success')
            session['pending_verification_user'] = user.id
            return redirect(url_for('payment_instructions'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error during registration: {str(e)}', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
    
    return render_template('auth/register.html', referral_code=referral_code)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('auth/forgot_password.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            reset_token = generate_reset_token()
            user.reset_token = reset_token
            user.reset_token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
            
            try:
                db.session.commit()
                
                reset_url = url_for('reset_password', token=reset_token, _external=True)
                send_password_reset_email(user, reset_url)
                
                flash('Password reset instructions have been sent to your email.', 'success')
                return redirect(url_for('login'))
                
            except Exception as e:
                db.session.rollback()
                print(f"Error in forgot_password: {str(e)}")
                flash('Error generating reset token. Please try again.', 'error')
                return render_template('auth/forgot_password.html')
        else:
            flash('If an account with that email exists, reset instructions have been sent.', 'success')
            return redirect(url_for('login'))
    
    return render_template('auth/forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or not user.reset_token_expires or user.reset_token_expires < datetime.now(timezone.utc):
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or not confirm_password:
            flash('Please fill in all fields.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expires = None
        
        try:
            db.session.commit()
            send_password_reset_confirmation(user)
            flash('Your password has been reset successfully! You can now login with your new password.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in reset_password: {str(e)}")
            flash('Error resetting password. Please try again.', 'error')
            return render_template('auth/reset_password.html', token=token)
    
    return render_template('auth/reset_password.html', token=token)

@app.route('/payment-instructions')
def payment_instructions():
    user_id = session.get('pending_verification_user')
    if not user_id:
        flash('Invalid access. Please register or login first.', 'error')
        return redirect(url_for('register'))
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('register'))
    
    if current_user.is_authenticated and current_user.id != user_id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if user.is_verified:
        flash('Your account is already verified.', 'info')
        session.pop('pending_verification_user', None)
        return redirect(url_for('login'))
    
    referrer_info = None
    if user.referred_by:
        referrer = User.query.filter_by(referral_code=user.referred_by).first()
        if referrer:
            referrer_info = {
                'username': referrer.username,
                'referral_code': referrer.referral_code
            }
    
    return render_template('payment_instructions.html', user=user, referrer_info=referrer_info)

@app.route('/submit-mpesa-message', methods=['POST'])
def submit_mpesa_message():
    user_id = session.get('pending_verification_user')
    if not user_id:
        return jsonify({'success': False, 'message': 'Session expired. Please register again.'})
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    mpesa_message = request.form.get('mpesa_message', '').strip()
    
    if not mpesa_message:
        return jsonify({'success': False, 'message': 'Please provide M-PESA message'})
    
    transaction_code = extract_mpesa_code(mpesa_message)
    
    try:
        existing_transaction = Transaction.query.filter_by(
            user_id=user.id, 
            transaction_type='registration_fee',
            status='pending'
        ).first()
        
        if existing_transaction:
            existing_transaction.mpesa_code = transaction_code
            existing_transaction.mpesa_message = mpesa_message
            existing_transaction.phone_number = user.phone_number
            existing_transaction.created_at = datetime.now(timezone.utc)
            transaction = existing_transaction
        else:
            transaction = Transaction(
                user_id=user.id,
                amount=200.0,
                transaction_type='registration_fee',
                status='pending',
                mpesa_code=transaction_code,
                phone_number=user.phone_number,
                mpesa_message=mpesa_message,
                description='Account registration fee - Pending verification'
            )
            db.session.add(transaction)
        
        db.session.commit()
        send_mpesa_notification_to_telegram(user, transaction)
        
        return jsonify({
            'success': True, 
            'message': 'M-PESA message submitted successfully! Please wait for admin verification.'
        })
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in submit_mpesa_message: {str(e)}")
        return jsonify({'success': False, 'message': f'Error submitting payment: {str(e)}'})

@app.route('/submit-mpesa-message/<int:user_id>', methods=['POST'])
def submit_mpesa_message_old(user_id):
    session['pending_verification_user'] = user_id
    return submit_mpesa_message()

@app.route('/api/payment-status')
def api_payment_status():
    user_id = session.get('pending_verification_user')
    if not user_id:
        return jsonify({'verified': False, 'error': 'Session expired'})
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'verified': False, 'error': 'User not found'})
    
    if user.is_verified:
        session.pop('pending_verification_user', None)
    
    return jsonify({'verified': user.is_verified})

@app.route('/api/payment-status/<int:user_id>')
def api_payment_status_old(user_id):
    session['pending_verification_user'] = user_id
    return api_payment_status()

@app.route('/referral-system')
@login_required
def referral_system():
    if not current_user.is_verified:
        flash('Please complete payment verification to access referral system.', 'warning')
        return redirect(url_for('payment_instructions'))
    
    referrals = Referral.query.filter_by(referrer_id=current_user.id)\
        .order_by(Referral.created_at.desc())\
        .all()
    
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
        return redirect(url_for('payment_instructions'))
    
    top_users = User.query.filter(User.is_active==True, User.total_commission>0)\
        .order_by(User.total_commission.desc())\
        .limit(50)\
        .all()
    
    user_ranking = get_user_ranking(current_user.id)
    
    return render_template('leaderboard.html',
                         top_users=top_users,
                         user_ranking=user_ranking)

@app.route('/statistics')
@login_required
def statistics():
    if not current_user.is_verified:
        flash('Please complete payment verification to view statistics.', 'warning')
        return redirect(url_for('payment_instructions'))
    
    total_earned = current_user.total_commission
    total_withdrawn = current_user.total_withdrawn
    pending_balance = current_user.balance
    
    referral_stats = db.session.query(
        db.func.date(Referral.created_at).label('date'),
        db.func.count(Referral.id).label('count')
    ).filter(Referral.referrer_id == current_user.id)\
     .group_by(db.func.date(Referral.created_at))\
     .order_by(db.func.date(Referral.created_at).desc())\
     .limit(30)\
     .all()
    
    return render_template('statistics.html',
                         total_earned=total_earned,
                         total_withdrawn=total_withdrawn,
                         pending_balance=pending_balance,
                         referral_stats=referral_stats)

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    if not current_user.is_verified:
        flash('Please complete payment verification to withdraw funds.', 'warning')
        return redirect(url_for('payment_instructions'))
    
    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        phone_number = request.form.get('phone_number')
        
        if amount < 100:
            flash('Minimum withdrawal amount is KSH 100.', 'error')
            return redirect(url_for('withdraw'))
        
        if amount > current_user.balance:
            flash('Insufficient balance.', 'error')
            return redirect(url_for('withdraw'))
        
        transaction = Transaction(
            user_id=current_user.id,
            amount=-amount,
            transaction_type='withdrawal',
            status='pending',
            phone_number=phone_number,
            description=f'M-Pesa withdrawal to {phone_number}'
        )
        
        current_user.balance -= amount
        current_user.total_withdrawn += amount
        
        db.session.add(transaction)
        db.session.commit()
        
        flash('Withdrawal request submitted! It will be processed within 24 hours.', 'success')
        return redirect(url_for('dashboard'))
    
    transactions = Transaction.query.filter_by(
        user_id=current_user.id, 
        transaction_type='withdrawal'
    ).order_by(Transaction.created_at.desc()).limit(5).all()
    
    return render_template('withdraw.html', transactions=transactions)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        new_password = request.form.get('new_password')
        
        if not email:
            flash('Email is required.', 'error')
            return redirect(url_for('profile'))
        
        if not phone_number:
            flash('Phone number is required.', 'error')
            return redirect(url_for('profile'))
        
        current_user.email = email
        current_user.phone_number = phone_number
        
        if new_password:
            current_user.set_password(new_password)
            flash('Password updated successfully!', 'success')
        
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile. Please try again.', 'error')
            return redirect(url_for('profile'))
    
    total_earned = current_user.total_commission
    total_withdrawn = current_user.total_withdrawn
    balance = current_user.balance
    
    referred_count = User.query.filter_by(referred_by=current_user.referral_code).count()
    
    return render_template('profile.html', 
                         total_earned=total_earned,
                         total_withdrawn=total_withdrawn,
                         balance=balance,
                         referred_count=referred_count)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        
        if not email:
            flash('Email is required.', 'error')
            return redirect(url_for('settings'))
        
        if not phone_number:
            flash('Phone number is required.', 'error')
            return redirect(url_for('settings'))
        
        current_user.email = email
        current_user.phone_number = phone_number
        
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if new_password:
            if not current_password:
                flash('Current password is required to set a new password.', 'error')
                return redirect(url_for('settings'))
            
            if current_user.check_password(current_password):
                current_user.set_password(new_password)
                flash('Password updated successfully!', 'success')
            else:
                flash('Current password is incorrect.', 'error')
                return redirect(url_for('settings'))
        
        try:
            db.session.commit()
            flash('Settings updated successfully!', 'success')
            return redirect(url_for('settings'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating settings. Please try again.', 'error')
            return redirect(url_for('settings'))
    
    return render_template('settings.html')

# Updated Admin Dashboard Route with Better Error Handling
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    print(f"Admin access attempt by: {current_user.username}, is_admin: {current_user.is_admin}")
    
    try:
        # Test database connection first
        db.session.execute(text('SELECT 1'))
        print("Database connection test passed")
        
        # Admin statistics with individual error handling
        try:
            total_users = User.query.count()
            print(f"Total users: {total_users}")
        except Exception as e:
            print(f"Error counting users: {e}")
            total_users = 0
        
        try:
            total_verified = User.query.filter_by(is_verified=True).count()
            print(f"Total verified: {total_verified}")
        except Exception as e:
            print(f"Error counting verified users: {e}")
            total_verified = 0
        
        try:
            total_referrals = Referral.query.count()
            print(f"Total referrals: {total_referrals}")
        except Exception as e:
            print(f"Error counting referrals: {e}")
            total_referrals = 0
        
        try:
            total_commission = db.session.query(db.func.sum(User.total_commission)).scalar() or 0
            print(f"Total commission: {total_commission}")
        except Exception as e:
            print(f"Error calculating total commission: {e}")
            total_commission = 0
        
        try:
            total_withdrawn_amount = db.session.query(db.func.sum(User.total_withdrawn)).scalar() or 0
            print(f"Total withdrawn: {total_withdrawn_amount}")
        except Exception as e:
            print(f"Error calculating total withdrawn: {e}")
            total_withdrawn_amount = 0
        
        try:
            total_balance = db.session.query(db.func.sum(User.balance)).scalar() or 0
            print(f"Total balance: {total_balance}")
        except Exception as e:
            print(f"Error calculating total balance: {e}")
            total_balance = 0
        
        try:
            pending_withdrawals = Transaction.query.filter_by(
                transaction_type='withdrawal', 
                status='pending'
            ).count()
            print(f"Pending withdrawals: {pending_withdrawals}")
        except Exception as e:
            print(f"Error counting pending withdrawals: {e}")
            pending_withdrawals = 0
        
        try:
            pending_payments = Transaction.query.filter_by(
                transaction_type='registration_fee', 
                status='pending'
            ).count()
            print(f"Pending payments: {pending_payments}")
        except Exception as e:
            print(f"Error counting pending payments: {e}")
            pending_payments = 0
        
        try:
            recent_users = User.query.filter(User.is_verified == True)\
                .order_by(User.created_at.desc())\
                .limit(10)\
                .all()
            print(f"Recent users: {len(recent_users)}")
        except Exception as e:
            print(f"Error fetching recent users: {e}")
            recent_users = []
        
        try:
            pending_transactions = db.session.query(Transaction, User)\
                .join(User, Transaction.user_id == User.id)\
                .filter(Transaction.transaction_type == 'registration_fee', 
                        Transaction.status == 'pending')\
                .order_by(Transaction.created_at.desc())\
                .all()
            print(f"Pending transactions: {len(pending_transactions)}")
        except Exception as e:
            print(f"Error fetching pending transactions: {e}")
            pending_transactions = []
        
        try:
            recent_activity = Transaction.query\
                .order_by(Transaction.created_at.desc())\
                .limit(10)\
                .all()
            print(f"Recent activity: {len(recent_activity)}")
        except Exception as e:
            print(f"Error fetching recent activity: {e}")
            recent_activity = []
        
        current_time = datetime.now(timezone.utc)
        
        print("All queries successful, rendering template...")
        
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
                             pending_transactions=pending_transactions,
                             recent_activity=recent_activity,
                             current_time=current_time)
                             
    except Exception as e:
        print(f"Error in admin_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Error accessing admin dashboard: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/approve-payment/<int:transaction_id>', methods=['POST'])
@login_required
@admin_required
def approve_payment(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    user = User.query.get(transaction.user_id)
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    try:
        user.is_verified = True
        user.is_active = True
        transaction.status = 'completed'
        transaction.description = 'Account registration fee - Approved'
        
        if user.referred_by:
            referrer = User.query.filter_by(referral_code=user.referred_by).first()
            if referrer:
                referrer.referral_balance += 50
                referrer.balance += 50
                referrer.total_commission += 50
                referrer.referral_count += 1
                referrer.update_rank()
                
                referral = Referral(
                    referrer_id=referrer.id,
                    referred_id=user.id,
                    referral_code_used=user.referred_by,
                    commission_earned=50.0
                )
                db.session.add(referral)
                
                commission_tx = Transaction(
                    user_id=referrer.id,
                    amount=50.0,
                    transaction_type='referral_commission',
                    status='completed',
                    description=f'Referral commission from {user.username}'
                )
                db.session.add(commission_tx)
        
        db.session.commit()
        send_admin_action_notification('approved', user, transaction, current_user)
        
        return jsonify({'success': True, 'message': 'Payment approved and user activated'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/reject-payment/<int:transaction_id>', methods=['POST'])
@login_required
@admin_required
def reject_payment(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    user = User.query.get(transaction.user_id)
    
    try:
        transaction.status = 'rejected'
        transaction.description = 'Account registration fee - Rejected'
        
        db.session.commit()
        send_admin_action_notification('rejected', user, transaction, current_user)
        
        return jsonify({'success': True, 'message': 'Payment rejected'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/withdrawals')
@login_required
@admin_required
def admin_withdrawals():
    withdrawals = db.session.query(Transaction, User)\
        .join(User, Transaction.user_id == User.id)\
        .filter(Transaction.transaction_type == 'withdrawal')\
        .order_by(Transaction.created_at.desc())\
        .all()
    
    total_pending_withdrawals = db.session.query(db.func.sum(Transaction.amount))\
        .filter(Transaction.transaction_type == 'withdrawal', Transaction.status == 'pending')\
        .scalar() or 0
    
    return render_template('admin_withdrawals.html',
                         withdrawals=withdrawals,
                         total_pending_withdrawals=abs(total_pending_withdrawals))

@app.route('/admin/approve-withdrawal/<int:transaction_id>', methods=['POST'])
@login_required
@admin_required
def approve_withdrawal(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    
    if transaction.transaction_type != 'withdrawal':
        return jsonify({'success': False, 'message': 'Not a withdrawal transaction'})
    
    try:
        transaction.status = 'completed'
        transaction.description = f'M-Pesa withdrawal approved - Processed to {transaction.phone_number}'
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Withdrawal approved successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/reject-withdrawal/<int:transaction_id>', methods=['POST'])
@login_required
@admin_required
def reject_withdrawal(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    user = User.query.get(transaction.user_id)
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    if transaction.transaction_type != 'withdrawal':
        return jsonify({'success': False, 'message': 'Not a withdrawal transaction'})
    
    try:
        refund_amount = abs(transaction.amount)
        user.balance += refund_amount
        user.total_withdrawn -= refund_amount
        
        transaction.status = 'rejected'
        transaction.description = f'Withdrawal rejected - Amount refunded'
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Withdrawal rejected and amount refunded'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    
    for user in users:
        user.referral_count = Referral.query.filter_by(referrer_id=user.id).count()
        user.pending_withdrawals = Transaction.query.filter_by(
            user_id=user.id, 
            transaction_type='withdrawal', 
            status='pending'
        ).count()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/toggle-user-status/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    
    try:
        user.is_active = not user.is_active
        db.session.commit()
        
        status = "activated" if user.is_active else "deactivated"
        return jsonify({'success': True, 'message': f'User {status} successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/admin/stats')
@login_required
@admin_required
def api_admin_stats():
    stats = {
        'total_users': User.query.count(),
        'total_verified': User.query.filter_by(is_verified=True).count(),
        'pending_payments': Transaction.query.filter_by(
            transaction_type='registration_fee', 
            status='pending'
        ).count(),
        'pending_withdrawals': Transaction.query.filter_by(
            transaction_type='withdrawal', 
            status='pending'
        ).count()
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

def init_db():
    try:
        with app.app_context():
            db.create_all()
            
            if User.query.filter_by(is_admin=True).first() is None:
                admin = User(
                    username='admin',
                    email='admin@referralninja.com',
                    phone_number='254799326074',
                    is_admin=True,
                    is_verified=True,
                    is_active=True
                )
                admin.set_password('admin123')
                admin.generate_phone_linked_referral_code()
                db.session.add(admin)
                db.session.commit()
                print("Admin user created successfully!")
            else:
                print("Admin user already exists: admin")
    except Exception as e:
        print(f"Database initialization error: {e}")

# Initialize the database when the app starts
with app.app_context():
    init_db()

if __name__ == '__main__':
    print("Starting Referral Ninja Application...")
    
    port = int(os.environ.get('PORT', 10000))
    host = '0.0.0.0'
    
    print(f"✓ Application initialized successfully")
    print(f"✓ Starting server on {host}:{port}")
    
    app.run(
        host=host,
        port=port,
        debug=False
    )