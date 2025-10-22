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
app.config['SESSION_COOKIE_SECURE'] = False
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

# Database initialization and health check
@app.before_first_request
def create_tables():
    try:
        print("Creating database tables...")
        db.create_all()
        print("Database tables created successfully!")
        
        # Create admin user if it doesn't exist
        if not User.query.filter_by(is_admin=True).first():
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
            print("Admin user already exists")
            
    except Exception as e:
        print(f"Error creating database tables: {e}")
        db.session.rollback()

@app.before_request
def before_request():
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
    except Exception as e:
        print(f"Database connection error: {e}")
        db.session.rollback()
        # Try to recreate tables if there's an error
        try:
            db.create_all()
        except Exception as create_error:
            print(f"Failed to recreate tables: {create_error}")

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

def generate_reset_token():
    return secrets.token_urlsafe(32)

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
    """Health check endpoint"""
    try:
        # Test database
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
    """Debug information endpoint"""
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
    try:
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('landing.html')
    except Exception as e:
        print(f"Error in index route: {e}")
        return "Welcome to Referral Ninja - System is starting up...", 200

@app.route('/dashboard')
@login_required
def dashboard():
    try:
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
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = bool(request.form.get('remember_me'))
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('auth/login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_verified:
                flash('Please complete your payment verification before logging in.', 'warning')
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
    
    referral_code = request.args.get('ref', '')
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        referral_code = request.form.get('referral_code')
        
        # Validate phone number
        if not re.match(r'^254[0-9]{9}$', phone_number) and not re.match(r'^07[0-9]{8}$', phone_number):
            flash('Please enter a valid Kenyan phone number.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if phone_number.startswith('07'):
            phone_number = '254' + phone_number[1:]
        
        # Check for existing user
        if User.query.filter_by(phone_number=phone_number).first():
            flash('Phone number already registered.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
        
        # Validate referral code
        referrer = None
        if referral_code:
            referrer = validate_referral_code(referral_code)
            if not referrer:
                flash('Invalid referral code. Please check and try again.', 'error')
                return render_template('auth/register.html', referral_code=referral_code)
        
        # Create user
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
        
        try:
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Please complete KSH 200 payment to activate your account.', 'success')
            session['pending_verification_user'] = user.id
            return redirect(url_for('payment_instructions'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error during registration: {str(e)}', 'error')
            return render_template('auth/register.html', referral_code=referral_code)
    
    return render_template('auth/register.html', referral_code=referral_code)

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
    try:
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
        
        # Send Telegram notification
        send_mpesa_notification_to_telegram(user, transaction)
        
        return jsonify({
            'success': True, 
            'message': 'M-PESA message submitted successfully! Please wait for admin verification.'
        })
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in submit_mpesa_message: {str(e)}")
        return jsonify({'success': False, 'message': f'Error submitting payment: {str(e)}'})

# Add other routes (logout, forgot-password, reset-password, etc.) following the same pattern...

# Admin Routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    try:
        total_users = User.query.count()
        total_verified = User.query.filter_by(is_verified=True).count()
        total_referrals = Referral.query.count()
        total_commission = db.session.query(db.func.sum(User.total_commission)).scalar() or 0
        total_withdrawn_amount = db.session.query(db.func.sum(User.total_withdrawn)).scalar() or 0
        total_balance = db.session.query(db.func.sum(User.balance)).scalar() or 0
        
        pending_withdrawals = Transaction.query.filter_by(
            transaction_type='withdrawal', 
            status='pending'
        ).count()
        
        pending_payments = Transaction.query.filter_by(
            transaction_type='registration_fee', 
            status='pending'
        ).count()
        
        recent_users = User.query.filter(User.is_verified == True)\
            .order_by(User.created_at.desc())\
            .limit(10)\
            .all()
        
        pending_transactions = db.session.query(Transaction, User)\
            .join(User, Transaction.user_id == User.id)\
            .filter(Transaction.transaction_type == 'registration_fee', 
                    Transaction.status == 'pending')\
            .order_by(Transaction.created_at.desc())\
            .all()
        
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
                             pending_transactions=pending_transactions)
                             
    except Exception as e:
        flash(f'Error accessing admin dashboard: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/approve-payment/<int:transaction_id>', methods=['POST'])
@login_required
@admin_required
def approve_payment(transaction_id):
    try:
        transaction = Transaction.query.get_or_404(transaction_id)
        user = User.query.get(transaction.user_id)
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
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
        return jsonify({'success': True, 'message': 'Payment approved and user activated'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

# Add other admin routes...

# Initialize the application
def init_app():
    """Initialize the application with proper error handling"""
    try:
        with app.app_context():
            db.create_all()
            
            # Create admin user if it doesn't exist
            if not User.query.filter_by(is_admin=True).first():
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
                print("✓ Admin user created successfully")
            else:
                print("✓ Admin user already exists")
                
            print("✓ Database initialized successfully")
            return True
            
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        return False

if __name__ == '__main__':
    print("Starting Referral Ninja Application...")
    
    # Initialize the application
    if init_app():
        port = int(os.environ.get('PORT', 10000))
        host = '0.0.0.0'
        
        print(f"✓ Application initialized successfully")
        print(f"✓ Starting server on {host}:{port}")
        
        app.run(
            host=host,
            port=port,
            debug=False
        )
    else:
        print("✗ Failed to initialize application")