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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'referral-ninja-secret-key-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///referralninja.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session configuration for network access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Telegram Configuration - REPLACE WITH YOUR ACTUAL CREDENTIALS
TELEGRAM_BOT_TOKEN = '7870070553:AAGjMBMB2oDhmA7bxrm0ibzNya_D3hTM2Ec'  # Replace with your actual token
TELEGRAM_CHAT_ID = '7716238167'

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Add utility functions to Jinja2 context
@app.context_processor
def utility_processor():
    return {
        'abs': abs,
        'min': min,
        'max': max,
        'round': round,
        'len': len
    }

# FIX: Add context processor for 'now' function
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

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
    referral_source = db.Column(db.String(20), default='direct')  # 'direct', 'referral_link', 'manual_entry'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_phone_linked_referral_code(self):
        # Generate referral code based on phone number
        phone_hash = hashlib.md5(self.phone_number.encode()).hexdigest()[:6].upper()
        self.referral_code = f"RN{phone_hash}"
    
    def update_rank(self):
        # Update user rank based on performance
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
    mpesa_message = db.Column(db.Text)  # Store the full M-PESA message
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    user = db.relationship('User', backref='transactions')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Telegram Functions
async def send_telegram_message_async(message):
    """Send notification to Telegram asynchronously"""
    try:
        # Skip if using placeholder token
        if TELEGRAM_BOT_TOKEN == 'your_bot_token_here' or TELEGRAM_CHAT_ID == 'your_chat_id_here':
            print("Telegram notifications disabled - please configure bot token and chat ID")
            return
            
        bot = Bot(token=TELEGRAM_BOT_TOKEN)
        async with bot:
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode='HTML')
    except Exception as e:
        print(f"Telegram notification failed: {str(e)}")

def send_telegram_notification(message):
    """Wrapper for synchronous calling"""
    try:
        asyncio.run(send_telegram_message_async(message))
    except Exception as e:
        print(f"Failed to send Telegram notification: {str(e)}")

def send_mpesa_notification_to_telegram(user, transaction):
    """Send M-PESA message directly to Telegram - CALLED WHEN USER SUBMITS PAYMENT"""
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

📍 <b>This is an immediate notification when user submitted payment</b>
"""
        
        # Send notification in background thread
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        
        return True
    except Exception as e:
        print(f"Error sending M-PESA notification to Telegram: {str(e)}")
        return False

def send_registration_notification_to_telegram(user, referral_code=None):
    """Send new registration notification to Telegram"""
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
        
        # Send notification in background thread
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        
        return True
    except Exception as e:
        print(f"Error sending registration notification to Telegram: {str(e)}")
        return False

def send_admin_action_notification(action, user, transaction, admin_user):
    """Send notification when admin takes action on payment"""
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
        else:  # rejected
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
        
        # Send notification in background thread
        thread = threading.Thread(target=send_telegram_notification, args=(message,))
        thread.daemon = True
        thread.start()
        
        return True
    except Exception as e:
        print(f"Error sending admin action notification to Telegram: {str(e)}")
        return False

# Helper Functions
def validate_referral_code(code):
    """Validate if a referral code exists and belongs to a verified user"""
    if not code:
        return None
    
    referrer = User.query.filter_by(referral_code=code).first()
    if not referrer:
        return None
    
    if not referrer.is_verified:
        return None
    
    return referrer

# Routes
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
    
    # Calculate total withdrawn from transactions
    total_withdrawn = db.session.query(db.func.sum(Transaction.amount)).filter(
        Transaction.user_id == current_user.id,
        Transaction.transaction_type == 'withdrawal',
        Transaction.status == 'completed'
    ).scalar() or 0.0
    
    # Get pending withdrawals count
    pending_withdrawals = Transaction.query.filter_by(
        user_id=current_user.id,
        transaction_type='withdrawal',
        status='pending'
    ).count()
    
    # Get recent withdrawals for the activity feed
    withdrawals = Transaction.query.filter_by(
        user_id=current_user.id,
        transaction_type='withdrawal'
    ).order_by(Transaction.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html',
                         total_withdrawn=abs(total_withdrawn),
                         pending_withdrawals=pending_withdrawals,
                         withdrawals=withdrawals)

def get_user_ranking(user_id):
    """Calculate user's rank among all users"""
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
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_verified:
                flash('Please complete your payment verification before logging in.', 'warning')
                # Use session instead of URL parameter for security
                session['pending_verification_user'] = user.id
                return redirect(url_for('payment_instructions'))
            
            login_user(user, remember=remember_me)
            next_page = request.args.get('next')
            
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Get referral code from URL parameter or form
    referral_code = request.args.get('ref', '')
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        referral_code = request.form.get('referral_code')
        
        # Validate phone number format (Kenyan)
        if not re.match(r'^254[0-9]{9}$', phone_number) and not re.match(r'^07[0-9]{8}$', phone_number):
            flash('Please enter a valid Kenyan phone number.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        # Convert phone number to standard format (254...)
        if phone_number.startswith('07'):
            phone_number = '254' + phone_number[1:]
        
        # Check if phone number already exists
        if User.query.filter_by(phone_number=phone_number).first():
            flash('Phone number already registered.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        # Validate input
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        # Validate referral code if provided
        referrer = None
        if referral_code:
            referrer = validate_referral_code(referral_code)
            if not referrer:
                flash('Invalid referral code. Please check and try again.', 'error')
                return render_template('auth/register.html', referral_code=referral_code)
        
        # Create new user (unverified until payment)
        user = User(
            username=username,
            email=email,
            phone_number=phone_number,
            is_verified=False
        )
        user.set_password(password)
        user.generate_phone_linked_referral_code()
        
        # Handle referral - only set if referrer exists and is valid
        if referrer:
            user.referred_by = referral_code
        
        # Track referral source
        if referral_code:
            if request.args.get('ref'):  # Came from referral link
                user.referral_source = 'referral_link'
            else:  # Manually entered
                user.referral_source = 'manual_entry'
        else:
            user.referral_source = 'direct'
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Send registration notification to Telegram
            send_registration_notification_to_telegram(user, referral_code)
            
            flash('Registration successful! Please complete KSH 200 payment to activate your account.', 'success')
            # Use session instead of URL parameter for security
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

@app.route('/payment-instructions')
def payment_instructions():
    # Get user ID from session instead of URL for security
    user_id = session.get('pending_verification_user')
    if not user_id:
        flash('Invalid access. Please register or login first.', 'error')
        return redirect(url_for('register'))
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('register'))
    
    # Check if user is the current user or if we're in a registration flow
    if current_user.is_authenticated and current_user.id != user_id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if user is already verified
    if user.is_verified:
        flash('Your account is already verified.', 'info')
        # Clear the session
        session.pop('pending_verification_user', None)
        return redirect(url_for('login'))
    
    # Get referrer information if applicable
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
    # Get user ID from session instead of URL for security
    user_id = session.get('pending_verification_user')
    if not user_id:
        return jsonify({'success': False, 'message': 'Session expired. Please register again.'})
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    mpesa_message = request.form.get('mpesa_message', '').strip()
    
    if not mpesa_message:
        return jsonify({'success': False, 'message': 'Please provide M-PESA message'})
    
    # Extract transaction code from message
    transaction_code = extract_mpesa_code(mpesa_message)
    
    try:
        # Check if transaction already exists for this user
        existing_transaction = Transaction.query.filter_by(
            user_id=user.id, 
            transaction_type='registration_fee',
            status='pending'
        ).first()
        
        if existing_transaction:
            # Update existing transaction
            existing_transaction.mpesa_code = transaction_code
            existing_transaction.mpesa_message = mpesa_message
            existing_transaction.phone_number = user.phone_number
            existing_transaction.created_at = datetime.now(timezone.utc)
            transaction = existing_transaction
        else:
            # Create new pending transaction
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
        
        # Send M-PESA message to Telegram - IMMEDIATE NOTIFICATION
        send_mpesa_notification_to_telegram(user, transaction)
        
        return jsonify({
            'success': True, 
            'message': 'M-PESA message submitted successfully! Please wait for admin verification.'
        })
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in submit_mpesa_message: {str(e)}")  # Debug print
        return jsonify({'success': False, 'message': f'Error submitting payment: {str(e)}'})

# ADD THIS COMPATIBILITY ROUTE FOR OLD FRONTEND REQUESTS
@app.route('/submit-mpesa-message/<int:user_id>', methods=['POST'])
def submit_mpesa_message_old(user_id):
    """Compatibility route for old frontend that sends user_id in URL"""
    # Set session from URL parameter for compatibility
    session['pending_verification_user'] = user_id
    return submit_mpesa_message()

def extract_mpesa_code(message):
    """Extract M-PESA transaction code from message"""
    # Look for patterns like RN49FLT7D7, MPE49FLT7D7, etc.
    patterns = [
        r'[A-Z0-9]{10}',  # Standard M-PESA code
        r'[A-Z0-9]{9}',   # Sometimes 9 characters
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return match.group(0)
    
    return 'PENDING'

@app.route('/api/payment-status')
def api_payment_status():
    """Check if user has been approved"""
    # Get user ID from session
    user_id = session.get('pending_verification_user')
    if not user_id:
        return jsonify({'verified': False, 'error': 'Session expired'})
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'verified': False, 'error': 'User not found'})
    
    # Clear session if user is verified
    if user.is_verified:
        session.pop('pending_verification_user', None)
    
    return jsonify({'verified': user.is_verified})

# ADD THIS COMPATIBILITY ROUTE FOR OLD FRONTEND REQUESTS
@app.route('/api/payment-status/<int:user_id>')
def api_payment_status_old(user_id):
    """Compatibility route for old frontend that sends user_id in URL"""
    # Set session from URL parameter for compatibility
    session['pending_verification_user'] = user_id
    return api_payment_status()

@app.route('/referral-system')
@login_required
def referral_system():
    """Enhanced referral system page"""
    if not current_user.is_verified:
        flash('Please complete payment verification to access referral system.', 'warning')
        return redirect(url_for('payment_instructions'))
    
    referrals = Referral.query.filter_by(referrer_id=current_user.id)\
        .order_by(Referral.created_at.desc())\
        .all()
    
    # Generate shareable links
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
    """Alias for referral_system"""
    return redirect(url_for('referral_system'))

@app.route('/leaderboard')
@login_required
def leaderboard():
    """User ranking leaderboard"""
    if not current_user.is_verified:
        flash('Please complete payment verification to view leaderboard.', 'warning')
        return redirect(url_for('payment_instructions'))
    
    # Get top 50 users by total commission
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
    """Detailed statistics page"""
    if not current_user.is_verified:
        flash('Please complete payment verification to view statistics.', 'warning')
        return redirect(url_for('payment_instructions'))
    
    # Calculate various statistics
    total_earned = current_user.total_commission
    total_withdrawn = current_user.total_withdrawn
    pending_balance = current_user.balance
    
    # Referral growth over time
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
        
        # Create withdrawal transaction
        transaction = Transaction(
            user_id=current_user.id,
            amount=-amount,
            transaction_type='withdrawal',
            status='pending',
            phone_number=phone_number,
            description=f'M-Pesa withdrawal to {phone_number}'
        )
        
        # Reserve the amount (deduct from balance)
        current_user.balance -= amount
        current_user.total_withdrawn += amount
        
        db.session.add(transaction)
        db.session.commit()
        
        flash('Withdrawal request submitted! It will be processed within 24 hours.', 'success')
        return redirect(url_for('dashboard'))
    
    # Get recent withdrawals
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
        
        # Validate required fields
        if not email:
            flash('Email is required.', 'error')
            return redirect(url_for('profile'))
        
        if not phone_number:
            flash('Phone number is required.', 'error')
            return redirect(url_for('profile'))
        
        # Update profile
        current_user.email = email
        current_user.phone_number = phone_number
        
        # Handle password change
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
    
    # Calculate statistics
    total_earned = current_user.total_commission
    total_withdrawn = current_user.total_withdrawn
    balance = current_user.balance
    
    # Get referral count
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
        # Get form data with proper validation
        email = request.form.get('email', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        
        # Validate required fields
        if not email:
            flash('Email is required.', 'error')
            return redirect(url_for('settings'))
        
        if not phone_number:
            flash('Phone number is required.', 'error')
            return redirect(url_for('settings'))
        
        # Update user details
        current_user.email = email
        current_user.phone_number = phone_number
        
        # Handle password change
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

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Admin statistics
    total_users = User.query.count()
    total_verified = User.query.filter_by(is_verified=True).count()
    total_referrals = Referral.query.count()
    total_commission = db.session.query(db.func.sum(User.total_commission)).scalar() or 0
    
    # Calculate total withdrawn amount
    total_withdrawn_amount = db.session.query(db.func.sum(User.total_withdrawn)).scalar() or 0
    
    # Calculate total balance across all users
    total_balance = db.session.query(db.func.sum(User.balance)).scalar() or 0
    
    # Pending withdrawals
    pending_withdrawals = Transaction.query.filter_by(
        transaction_type='withdrawal', 
        status='pending'
    ).count()
    
    # Pending registration payments
    pending_payments = Transaction.query.filter_by(
        transaction_type='registration_fee', 
        status='pending'
    ).count()
    
    # Get recent users for leaderboard
    recent_users = User.query.filter(User.is_verified == True)\
        .order_by(User.created_at.desc())\
        .limit(10)\
        .all()
    
    # Get pending payment transactions with user information
    pending_transactions = db.session.query(Transaction, User)\
        .join(User, Transaction.user_id == User.id)\
        .filter(Transaction.transaction_type == 'registration_fee', 
                Transaction.status == 'pending')\
        .order_by(Transaction.created_at.desc())\
        .all()
    
    # Get recent activity for admin dashboard
    recent_activity = Transaction.query\
        .order_by(Transaction.created_at.desc())\
        .limit(10)\
        .all()
    
    # FIX: Pass current_time to template to avoid 'now' function issues
    current_time = datetime.utcnow()
    
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
                         current_time=current_time)  # Pass current_time to template

@app.route('/admin/approve-payment/<int:transaction_id>', methods=['POST'])
@login_required
def approve_payment(transaction_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin access required'})
    
    transaction = Transaction.query.get_or_404(transaction_id)
    user = User.query.get(transaction.user_id)
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    try:
        # Activate user
        user.is_verified = True
        user.is_active = True
        
        # Update transaction status
        transaction.status = 'completed'
        transaction.description = 'Account registration fee - Approved'
        
        # Process referral commission if applicable
        if user.referred_by:
            referrer = User.query.filter_by(referral_code=user.referred_by).first()
            if referrer:
                # Credit referrer with KSH 50
                referrer.referral_balance += 50
                referrer.balance += 50
                referrer.total_commission += 50
                referrer.referral_count += 1
                referrer.update_rank()
                
                # Create referral record
                referral = Referral(
                    referrer_id=referrer.id,
                    referred_id=user.id,
                    referral_code_used=user.referred_by,
                    commission_earned=50.0
                )
                db.session.add(referral)
                
                # Create commission transaction
                commission_tx = Transaction(
                    user_id=referrer.id,
                    amount=50.0,
                    transaction_type='referral_commission',
                    status='completed',
                    description=f'Referral commission from {user.username}'
                )
                db.session.add(commission_tx)
        
        db.session.commit()
        
        # Send admin action notification to Telegram
        send_admin_action_notification('approved', user, transaction, current_user)
        
        return jsonify({'success': True, 'message': 'Payment approved and user activated'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/reject-payment/<int:transaction_id>', methods=['POST'])
@login_required
def reject_payment(transaction_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin access required'})
    
    transaction = Transaction.query.get_or_404(transaction_id)
    user = User.query.get(transaction.user_id)
    
    try:
        # Update transaction status to rejected
        transaction.status = 'rejected'
        transaction.description = 'Account registration fee - Rejected'
        
        db.session.commit()
        
        # Send admin action notification to Telegram
        send_admin_action_notification('rejected', user, transaction, current_user)
        
        return jsonify({'success': True, 'message': 'Payment rejected'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/withdrawals')
@login_required
def admin_withdrawals():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all withdrawal transactions with user information
    withdrawals = db.session.query(Transaction, User)\
        .join(User, Transaction.user_id == User.id)\
        .filter(Transaction.transaction_type == 'withdrawal')\
        .order_by(Transaction.created_at.desc())\
        .all()
    
    # Calculate total pending withdrawals
    total_pending_withdrawals = db.session.query(db.func.sum(Transaction.amount))\
        .filter(Transaction.transaction_type == 'withdrawal', Transaction.status == 'pending')\
        .scalar() or 0
    
    return render_template('admin_withdrawals.html',
                         withdrawals=withdrawals,
                         total_pending_withdrawals=abs(total_pending_withdrawals))

@app.route('/admin/approve-withdrawal/<int:transaction_id>', methods=['POST'])
@login_required
def approve_withdrawal(transaction_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin access required'})
    
    transaction = Transaction.query.get_or_404(transaction_id)
    
    if transaction.transaction_type != 'withdrawal':
        return jsonify({'success': False, 'message': 'Not a withdrawal transaction'})
    
    try:
        # Update transaction status to completed
        transaction.status = 'completed'
        transaction.description = f'M-Pesa withdrawal approved - Processed to {transaction.phone_number}'
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Withdrawal approved successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/reject-withdrawal/<int:transaction_id>', methods=['POST'])
@login_required
def reject_withdrawal(transaction_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin access required'})
    
    transaction = Transaction.query.get_or_404(transaction_id)
    user = User.query.get(transaction.user_id)
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    if transaction.transaction_type != 'withdrawal':
        return jsonify({'success': False, 'message': 'Not a withdrawal transaction'})
    
    try:
        # Refund the amount back to user's balance
        refund_amount = abs(transaction.amount)
        user.balance += refund_amount
        user.total_withdrawn -= refund_amount
        
        # Update transaction status to rejected
        transaction.status = 'rejected'
        transaction.description = f'Withdrawal rejected - Amount refunded'
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Withdrawal rejected and amount refunded'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all users with their referral counts
    users = User.query.all()
    
    # Add referral counts to each user
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
def toggle_user_status(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin access required'})
    
    user = User.query.get_or_404(user_id)
    
    try:
        user.is_active = not user.is_active
        db.session.commit()
        
        status = "activated" if user.is_active else "deactivated"
        return jsonify({'success': True, 'message': f'User {status} successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

# API Routes for real-time updates
@app.route('/api/admin/stats')
@login_required
def api_admin_stats():
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
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

# SIMPLIFIED ERROR HANDLERS - REMOVE TEMPLATE DEPENDENCIES
@app.errorhandler(404)
def not_found_error(error):
    return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return "Internal server error", 500

# Favicon route to prevent 404 errors
@app.route('/favicon.ico')
def favicon():
    return '', 204

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create admin user if none exists
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

if __name__ == '__main__':
    init_db()
    app.run(
        debug=True, 
        host='0.0.0.0', 
        port=5000,
        threaded=True  # Handle multiple connections
    )