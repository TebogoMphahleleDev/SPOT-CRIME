from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from forms import RequestResetForm, ResetPasswordForm
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from datetime import datetime
from dotenv import load_dotenv
import os
import pymysql
import requests
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from sqlalchemy.orm import scoped_session, sessionmaker
from datetime import datetime, timezone, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_socketio import SocketIO, emit, join_room

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder='Templates')

# app.config.from_pyfile('config.py')  # Load normal config
app.config.from_prefixed_env() 
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'true').lower() == 'true',
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),  # From .env
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),  # From .env
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', 'tcpetja@gmail.com'),
    MAIL_DEBUG=int(os.getenv('MAIL_DEBUG', '0'))
)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize Flask-Login
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================ CONFIGURATION ================
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 5,
    'max_overflow': 10,
    'pool_timeout': 30,
    'pool_recycle': 1800,
    'pool_pre_ping': True
}

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS').lower() == 'true'
app.config['MAIL_USERNAME'] = 'tcpetja@gmail.com'  # Hardcoded email
app.config['MAIL_PASSWORD'] = 'yfcgqaqngddqqter'  # Hardcoded password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['MAIL_DEBUG'] = int(os.getenv('MAIL_DEBUG', '0'))

# File uploads
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'mp3', 'wav'}
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25MB

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
mail = Mail(app)

# ================ DATABASE MODELS ================
class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100)) 
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    profile_image = db.Column(db.String(255), nullable=True)
    points = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    emergency_contacts = db.relationship('EmergencyContact', backref='user', lazy=True, cascade="all, delete-orphan")
    incidents = db.relationship('Incident', backref='user', lazy=True)
    reset_token = db.Column(db.String(200))
    reset_token_expiry = db.Column(db.DateTime)

    def get_reset_token(self, expires_sec=3600):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}, salt=app.config['SECURITY_PASSWORD_SALT'])

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)['user_id']
        except Exception:
            return None
        return User.query.get(user_id)

class CommunityChatMessage(db.Model):
    __tablename__ = 'community_chat_messages'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='chat_messages')

class IncidentType(db.Model):
    __tablename__ = 'incident_types'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Admin(db.Model):
    #__bind_key__ = 'admin'
    __tablename__ = 'admins'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LawEnforcement(db.Model):
    #__bind_key__ = 'police'
    __tablename__ = 'officers'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    station = db.Column(db.String(100))
    badge_number = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class EmergencyContact(db.Model):
    __tablename__ = 'emergency_contacts'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    relationship = db.Column(db.String(100), nullable=False)

class Incident(db.Model):
    __tablename__ = 'incidents'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    crime_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(200))
    status = db.Column(db.String(50), default='reported')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    assigned_officer_id = db.Column(db.Integer, nullable=True)
    evidence = db.relationship('IncidentEvidence', backref='incident', lazy=True, cascade="all, delete-orphan")

class IncidentEvidence(db.Model):
    __tablename__ = 'incident_evidence'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id', ondelete='CASCADE'))
    file_path = db.Column(db.String(255))
    file_type = db.Column(db.String(50))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class EmergencyAlert(db.Model):
    __tablename__ = 'emergency_alerts'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    triggered_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='active')

class Voucher(db.Model):
    __tablename__ = 'vouchers'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=True)
    reward_type = db.Column(db.String(100), default='Incident Report Reward')
    points_cost = db.Column(db.Integer, default=100)
    voucher_code = db.Column(db.String(100), nullable=False, unique=True)
    is_approved = db.Column(db.Boolean, default=False)
    is_redeemed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    redeemed_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='vouchers')

# ================ HELPER FUNCTIONS ================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_uploaded_file(file, incident_id):
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{incident_id}_{datetime.now().timestamp()}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return filename
    return None

def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except Exception:
        return False

# ================ DATABASE INITIALIZATION ================
def initialize_database():
    with app.app_context():
        try:
            db.create_all()
            
            # Common incident types
            common_incident_types = [
                "Gender-Based Violence",
                "Theft",
                "Burglary",
                "Assault",
                "Vandalism",
                "Drug Activity"
            ]
            for incident_name in common_incident_types:
                existing_type = IncidentType.query.filter_by(name=incident_name).first()
                if not existing_type:
                    new_type = IncidentType(name=incident_name)
                    db.session.add(new_type)
            db.session.commit()
            
            # Sample user
            user_email = "tebogo@gmail.com"
            user_password = bcrypt.generate_password_hash("tebogo").decode('utf-8')
            regular_user = User.query.filter_by(email=user_email).first()
            if not regular_user:
                regular_user = User(
                    email=user_email,
                    password=user_password,
                    name="Tebogo",
                    phone="0123456789",
                    address="123 Main St"
                )
                db.session.add(regular_user)
                db.session.commit()
                
                emergency_contact = EmergencyContact(
                    user_id=regular_user.id,
                    name="Emergency Contact",
                    phone="9876543210",
                    relationship="Family"
                )
                db.session.add(emergency_contact)
                
                incident = Incident(
                    crime_type="Theft",
                    description="Stolen phone at the mall",
                    latitude=-26.2041,
                    longitude=28.0473,
                    address="Sandton City Mall",
                    status="reported",
                    user_id=regular_user.id
                )
                db.session.add(incident)
                db.session.commit()

            # Sample admin
            if not Admin.query.filter_by(email=user_email).first():
                admin = Admin(
                    email=user_email,
                    password=user_password
                )
                db.session.add(admin)
                db.session.commit()

            # Sample officer
            if not LawEnforcement.query.filter_by(email=user_email).first():
                officer = LawEnforcement(
                    email=user_email,
                    password=user_password,
                    station="Johannesburg Central",
                    badge_number="JHB1234"
                )
                db.session.add(officer)
                db.session.commit()

            print("Database initialization successful with sample data!")
            
        except Exception as e:
            print(f"Error during initialization: {e}")
            raise

# ================ MIDDLEWARE ================
@app.after_request
def set_csrf_cookie(response):
    if request.method == "GET":
        token = generate_csrf()
        response.set_cookie('csrf_token', token)
    return response

# ================ CHAT FUNCTIONALITY ================
@app.route('/api/chat/users')
def get_chat_users():
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    # Get distinct users who have sent messages
    users = db.session.query(
        CommunityChatMessage.user_id,
        CommunityChatMessage.username
    ).filter(
        CommunityChatMessage.user_id.isnot(None)
    ).distinct().all()
    
    user_list = [{'user_id': u.user_id, 'username': u.username} for u in users]
    return jsonify(user_list)

# API endpoint to get chat history with a specific user
@app.route('/api/chat/history/<int:user_id>')
def get_chat_history(user_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    messages = CommunityChatMessage.query.filter(
        (CommunityChatMessage.user_id == user_id) | 
        (CommunityChatMessage.is_admin == True)
    ).order_by(CommunityChatMessage.timestamp.asc()).all()
    
    message_list = []
    for msg in messages:
        message_list.append({
            'id': msg.id,
            'user_id': msg.user_id,
            'username': msg.username if msg.username else 'Admin',
            'message': msg.message,
            'timestamp': msg.timestamp.isoformat(),
            'is_admin': msg.is_admin
        })
    
    return jsonify(message_list)

# SocketIO event handlers
@socketio.on('join_admin_room')
def handle_join_admin_room():
    if 'admin_id' not in session:
        return False
    join_room('admin_room')

@socketio.on('admin_send_message')
def handle_admin_send_message(data):
    if 'admin_id' not in session:
        return False
    
    user_id = data.get('user_id')
    message = data.get('message')
    
    if not user_id or not message:
        return
    
    # Save admin message to database
    chat_message = CommunityChatMessage(
        user_id=None,  # Null user_id indicates admin message
        username='Admin',
        message=message,
        is_admin=True
    )
    db.session.add(chat_message)
    db.session.commit()
    
    # Emit message to admin room and user room
    emit('new_message', {
        'id': chat_message.id,
        'user_id': user_id,
        'username': 'Admin',
        'message': message,
        'timestamp': chat_message.timestamp.isoformat(),
        'is_admin': True
    }, room='admin_room')
    
    emit('new_message', {
        'id': chat_message.id,
        'user_id': user_id,
        'username': 'Admin',
        'message': message,
        'timestamp': chat_message.timestamp.isoformat(),
        'is_admin': True
    }, room=f'user_{user_id}')

@socketio.on('user_send_message')
def handle_user_send_message(data):
    user_id = data.get('user_id')
    username = data.get('username')
    message = data.get('message')

    if not user_id or not message or not username:
        return

    chat_message = CommunityChatMessage(
        user_id=user_id,
        username=username,
        message=message,
        is_admin=False
    )
    db.session.add(chat_message)
    db.session.commit()

    emit('new_message', {
        'id': chat_message.id,
        'user_id': chat_message.user_id,
        'username': chat_message.username,
        'message': chat_message.message,
        'timestamp': chat_message.timestamp.isoformat(),
        'is_admin': chat_message.is_admin
    }, room='admin_room')
    emit('new_message', {
        'id': chat_message.id,
        'user_id': chat_message.user_id,
        'username': chat_message.username,
        'message': chat_message.message,
        'timestamp': chat_message.timestamp.isoformat(),
        'is_admin': chat_message.is_admin
    }, room=f'user_{user_id}')

@socketio.on('join_admin_room')
def join_admin_room():
    join_room('admin_room')

@socketio.on('join_user_room')
def join_user_room(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')

# ================ ROUTES ================
@app.route('/')
def home():
    return redirect(url_for('login'))

# API endpoint to get evidence files for an incident
@app.route('/api/incident_evidence/<int:incident_id>')
def api_incident_evidence(incident_id):
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({'success': False, 'message': 'Incident not found', 'evidence': []}), 404
    evidence_list = []
    for ev in incident.evidence:
        evidence_list.append({
            'file_path': ev.file_path,
            'file_type': ev.file_type
        })
    return jsonify({'success': True, 'evidence': evidence_list})

# Emergency Contacts API routes
@app.route('/api/emergency-contacts', methods=['GET', 'POST'])
@csrf.exempt

@app.route('/api/emergency-contacts/<int:contact_id>', methods=['GET', 'PUT', 'DELETE'])
@csrf.exempt
def emergency_contact(contact_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    contact = EmergencyContact.query.filter_by(id=contact_id, user_id=session['user_id']).first()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'contact': {
                'id': contact.id,
                'name': contact.name,
                'phone': contact.phone,
                'relationship': contact.relationship
            }
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        try:
            if 'name' in data:
                contact.name = data['name']
            if 'phone' in data:
                contact.phone = data['phone']
            if 'relationship' in data:
                contact.relationship = data['relationship']
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'Contact updated successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            db.session.delete(contact)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Contact deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            # Check admin login
            admin = db.session.execute(
                db.select(Admin).where(Admin.email == email)
            ).scalar_one_or_none()
            
            if admin and bcrypt.check_password_hash(admin.password, password):
                session.clear()
                session['admin_id'] = admin.id
                session['admin_email'] = admin.email
                flash("Admin login successful!", "success")
                return redirect(url_for('admin_dashboard'))
            
            # Check law enforcement login
            officer = db.session.execute(
                db.select(LawEnforcement).where(LawEnforcement.email == email)
            ).scalar_one_or_none()
            
            if officer and bcrypt.check_password_hash(officer.password, password):
                session.clear()
                session['officer_id'] = officer.id
                session['officer_email'] = officer.email
                session['officer_station'] = officer.station
                flash("Law enforcement login successful!", "success")
                return redirect(url_for('law_enforcement_dashboard'))
            
            # Check regular user login
            user = db.session.execute(
                db.select(User).where(User.email == email)
            ).scalar_one_or_none()
            
            if user and bcrypt.check_password_hash(user.password, password):
                session.clear()
                session['user_id'] = user.id
                session['user_email'] = user.email
                flash("Login Successful!", "success")
                return redirect(url_for('dashboard'))
            
            flash("Invalid credentials. Try again.", "danger")
        
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during login. Please try again.", "danger")
            app.logger.error(f"Login error: {str(e)}")
    
    return render_template('login.html')


@app.route('/law_enforcement_login', methods=['GET', 'POST'])
def law_enforcement_login():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            
            if not email or not password:
                flash("Both email and password are required", "danger")
                return redirect(url_for('law_enforcement_login'))
            
            # Query the police database
            officer = db.session.execute(
                db.select(LawEnforcement).where(LawEnforcement.email == email)
            ).scalar_one_or_none()
            
            if officer and bcrypt.check_password_hash(officer.password, password):
                session.clear()
                session['officer_id'] = officer.id
                session['officer_email'] = officer.email
                session['officer_station'] = officer.station
                flash("Login successful!", "success")
                return redirect(url_for('law_enforcement_dashboard'))
            
            flash("Invalid credentials", "danger")
            
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash("Login failed. Please try again.", "danger")
    
    return render_template('law_enforcement_login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            admin = db.session.execute(
                db.select(Admin).where(Admin.email == email)
            ).scalar_one_or_none()
            
            if admin and bcrypt.check_password_hash(admin.password, password):
                session.clear()
                session['admin_id'] = admin.id
                session['admin_email'] = admin.email
                flash("Admin login successful!", "success")
                return redirect(url_for('admin_dashboard'))
            
            flash("Invalid credentials. Try again.", "danger")
        
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during login. Please try again.", "danger")
            app.logger.error(f"Admin login error: {str(e)}")
    
    return render_template('admin_login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if User.query.filter_by(email=email).first():
            flash("User already exists! Try logging in.", "warning")
            return redirect(url_for('signup'))

        if password == confirm_password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

# Password Reset Routes
import re
from itsdangerous import SignatureExpired, BadSignature

@app.route('/reset_password', methods=['GET', 'POST'])
@csrf.exempt
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            secret_key = os.getenv('SECRET_KEY')
       
            serializer = URLSafeTimedSerializer(secret_key)
            token = serializer.dumps(email, salt='password-reset')
            user.reset_token = token
            user.reset_token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
            db.session.commit()
       
            msg = Message("Password Reset Request",
                    sender=os.getenv('MAIL_USERNAME'),
                    recipients=[email])
            msg.body = f"Reset link: {url_for('reset_password_token', token=token, _external=True)}"
   
            mail.send(msg)
           
       
            flash("A password reset link has been sent to your email.", "success")
            return redirect(url_for('login'))  
        else:
            flash("No account found with that email address.", "danger")
           
       
   
    return render_template('reset_password.html')

@app.route('/reset_password_token', methods=['GET', 'POST'])
@csrf.exempt
def reset_password_token():
    # Get token from URL parameters
    token = request.args.get('token')
   
   
    if not token:
        flash('Invalid reset token', 'danger')
        return redirect(url_for('reset_password_request'))
 
    try:
        # Verify token validity
        secret_key = os.getenv('SECRET_KEY')
        serializer = URLSafeTimedSerializer(secret_key)
        email = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour expiration
    except (SignatureExpired, BadSignature):
        flash('The reset link is invalid or has expired', 'danger')
        return redirect(url_for('reset_password_request'))
   
    # Find user by email from token
    user = User.query.filter_by(email=email).first()
    if not user or user.reset_token != token:
        flash('Invalid reset request', 'danger')
        return redirect(url_for('reset_password_request'))
   
    # Check token expiry
    if user.reset_token_expiry.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        flash('The reset link has expired', 'danger')
        return redirect(url_for('reset_password_request'))
   
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
       
        # Validate passwords match
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('reset_password_token.html', token=token)
       
        try:
            # Update password and clear reset token
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.commit()
           
            flash('Your password has been updated successfully!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating password', 'danger')
            app.logger.error(f"Password reset error: {str(e)}")
   
    # For GET requests, render the form
    return render_template('reset_password_token.html', token=token)

# User Routes
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = db.session.query(User).options(
        db.joinedload(User.emergency_contacts),
        db.joinedload(User.incidents)
    ).get(user_id)
    if user and (not user.name or user.name.strip() == ''):
        user.name = "Community Member"
    return user

@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        flash("Please log in to access the dashboard.", "warning")
        app.logger.warning(f"Dashboard access attempt without valid user. Session: {dict(session)}")
        return redirect(url_for('login'))
    
    try:
        # Get all incidents reported by the user (recent activity)
        recent_incidents = db.session.query(Incident).filter_by(user_id=user.id).order_by(Incident.created_at.desc()).all()
        
        # Get emergency contacts
        emergency_contacts = EmergencyContact.query.filter_by(user_id=user.id).all()
        
        # Determine primary contact (first contact or None)
        primary_contact = emergency_contacts[0] if emergency_contacts else None
        
        # Calculate reports this month
        from datetime import datetime
        from sqlalchemy import extract
        now = datetime.utcnow()
        reports_this_month = db.session.query(Incident).filter(
            Incident.user_id == user.id,
            extract('year', Incident.created_at) == now.year,
            extract('month', Incident.created_at) == now.month
        ).count()
        
        # Placeholder for active patrols count
        active_patrols = 5 
        
        return render_template('Dashboard.html', 
                               user=user, 
                               recent_incidents=recent_incidents,
                               emergency_contacts=emergency_contacts,
                               primary_contact=primary_contact,
                               reports_this_month=reports_this_month,
                               active_patrols=active_patrols)
    except Exception as e:
        app.logger.error(f"Error loading dashboard: {str(e)}")
        flash("An error occurred while loading the dashboard.", "danger")
        return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash("Please log in to access your profile.", "warning")
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))
    
    # Handle profile update
    if request.method == 'POST':
        try:
            user.name = request.form.get('name', user.name)
            user.email = request.form.get('email', user.email)
            user.phone = request.form.get('phone', user.phone)
            user.address = request.form.get('address', user.address)
            
            db.session.commit()
            flash("Profile updated successfully!", "success")
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating profile: {str(e)}", "danger")
    
    return render_template('profile.html', user=user)

@app.route('/api/user/profile', methods=['GET', 'PUT'])
@csrf.exempt
def user_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if request.method == 'GET':
        return jsonify({
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'address': user.address,
            ' Date': user.created_at.isoformat(),
            'profilePic': url_for('uploaded_file', filename=user.profile_image) if user.profile_image else None
        })
    elif request.method == 'PUT':
        try:
            data = request.get_json()
            
            # Update fields if provided
            if 'name' in data:
                user.name = data['name']
            if 'email' in data:
                # Check if email already exists for another user
                existing_user = User.query.filter(User.email == data['email'], User.id != user.id).first()
                if existing_user:
                    return jsonify({'error': 'Email already in use'}), 400
                user.email = data['email']
            if 'phone' in data:
                user.phone = data['phone']
            if 'address' in data:
                user.address = data['address']
                
            db.session.commit()
            return jsonify({'success': True, 'message': 'Profile updated successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500


# API endpoint for changing user password
@app.route('/api/change-password', methods=['POST'])
@csrf.exempt
def change_password():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    if not data or not all(key in data for key in ['current_password', 'new_password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Verify current password
    if not bcrypt.check_password_hash(user.password, data['current_password']):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    try:
        # Update password with new hashed password
        user.password = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
        db.session.commit()
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# API endpoint for uploading profile image
@app.route('/api/upload-profile-image', methods=['POST'])
@csrf.exempt
def upload_profile_image():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if 'profile_image' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['profile_image']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    try:
        # Create unique filename with user ID
        filename = secure_filename(f"{session['user_id']}_{datetime.now().timestamp()}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Update user profile_image field in the database
        user = User.query.get(session['user_id'])
        if user:
            user.profile_image = filename
            db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Profile image uploaded successfully',
            'image_url': url_for('uploaded_file', filename=filename)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Incident Reporting Routes
@app.route('/report-incident', methods=['GET', 'POST'])
def report_incident():
    if 'user_id' not in session:
        flash('Please login to report an incident', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # Get form data
            crime_type = request.form.get('incident-type')
            if crime_type == 'other':
                other_crime = request.form.get('other-crime', 'Unknown').strip()
                crime_type = other_crime
                
                # Check if the other_crime already exists in IncidentType
                existing_type = IncidentType.query.filter_by(name=other_crime).first()
                if not existing_type:
                    new_type = IncidentType(name=other_crime)
                    db.session.add(new_type)
                    db.session.commit()
            else:
                # Map numeric crime_type id to name if digit
                if crime_type and str(crime_type).isdigit():
                    incident_type = IncidentType.query.get(int(crime_type))
                    if incident_type:
                        crime_type = incident_type.name
            
            description = request.form.get('description', '')
            location = request.form.get('location', '')
            
            # Parse coordinates from location or use default
            lat_lng = location.split(',')
            latitude = float(lat_lng[0].strip()) if len(lat_lng) == 2 else 0.0
            longitude = float(lat_lng[1].strip()) if len(lat_lng) == 2 else 0.0
            
            # Create new incident
            new_incident = Incident(
                crime_type=crime_type,
                description=description,
                latitude=latitude,
                longitude=longitude,
                address=location,
                user_id=session['user_id']
            )
            db.session.add(new_incident)
            db.session.commit()

            # Automatic random assignment of officer
            import random
            officers = db.session.query(LawEnforcement).all()
            if officers:
                assigned_officer = random.choice(officers)
                new_incident.assigned_officer_id = assigned_officer.id
                db.session.commit()

            # Emit socketio event to notify law enforcement dashboard
            from flask_socketio import emit
            from __main__ import socketio
            incident_data = {
                'id': new_incident.id,
                'crime_type': new_incident.crime_type,
                'description': new_incident.description,
                'latitude': new_incident.latitude,
                'longitude': new_incident.longitude,
                'address': new_incident.address,
                'status': new_incident.status,
                'user_id': new_incident.user_id,
                'created_at': new_incident.created_at.isoformat() if new_incident.created_at else None
            }
            socketio.emit('new_incident', incident_data, broadcast=True)
            
            # Handle file uploads
            if 'media-upload' in request.files:
                for file in request.files.getlist('media-upload'):
                    if file.filename != '':
                        filename = save_uploaded_file(file, new_incident.id)
                        if filename:
                            file_type = file.content_type.split('/')[0]
                            evidence = IncidentEvidence(
                                incident_id=new_incident.id,
                                file_path=filename,
                                file_type=file_type
                            )
                            db.session.add(evidence)
            
            # Handle audio upload
            if 'audio-upload' in request.files:
                file = request.files['audio-upload']
                if file.filename != '':
                    filename = save_uploaded_file(file, new_incident.id)
                    if filename:
                        evidence = IncidentEvidence(
                            incident_id=new_incident.id,
                            file_path=filename,
                            file_type='audio'
                        )
                        db.session.add(evidence)
            
            db.session.commit()
            flash('Incident reported successfully!', 'success')
            # Redirect to ThankYou Page.html before dashboard
            return redirect(url_for('thank_you_page'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Error reporting incident: {str(e)}', 'danger')
    
    # On GET, load incident types from DB
    incident_types = IncidentType.query.order_by(IncidentType.name).all()
    return render_template('reportincident.html', incident_types=incident_types)

@app.route('/crime-map')
def crime_map():
    if 'user_id' not in session:
        flash("Please log in to access the crime map.", "warning")
        return redirect(url_for('login'))
    return render_template('crimemapPage.html')

@app.route('/law_enforcement_crime_map')
def law_enforcement_crime_map():
    if 'officer_id' not in session:
        flash("Please log in to access the law enforcement crime map.", "warning")
        return redirect(url_for('law_enforcement_login'))
    try:
        officer = db.session.execute(
            db.select(LawEnforcement).where(LawEnforcement.id == session['officer_id'])
        ).scalar_one_or_none()
        if not officer:
            flash("Officer not found. Please log in again.", "warning")
            return redirect(url_for('law_enforcement_login'))
        incidents = db.session.query(Incident).order_by(Incident.created_at.desc()).all()
        return render_template('law_enforcement_crimemap.html', incidents=incidents)
    except Exception as e:
        app.logger.error(f"Error loading law enforcement crime map: {str(e)}")
        flash("An error occurred while loading the crime map.", "danger")
        return redirect(url_for('law_enforcement_dashboard'))

@app.route('/get_crime_data')
def get_crime_data():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify([])  # or return an error if preferred
    crimes = Incident.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'crime_type': crime.crime_type,
        'description': crime.description,
        'latitude': crime.latitude,
        'longitude': crime.longitude,
        'address': crime.address,
        'timestamp': crime.created_at.isoformat()
    } for crime in crimes])

# Emergency Routes
@app.route('/emergency', methods=['GET', 'POST'])
def emergency():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            latitude = data.get('latitude')
            longitude = data.get('longitude')
            
            # Create emergency alert
            new_alert = EmergencyAlert(
                user_id=session['user_id'],
                latitude=latitude,
                longitude=longitude
            )
            db.session.add(new_alert)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Emergency alert triggered!',
                'alert_id': new_alert.id
            })
        
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500
    
    contacts = EmergencyContact.query.filter_by(user_id=session['user_id']).all()
    return render_template('emergency.html', contacts=contacts)

@app.route('/reverse-geocode', methods=['POST'])
def reverse_geocode():
    data = request.get_json()
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    
    try:
        # Use Nominatim or another geocoding service
        response = requests.get(
            f'https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}&zoom=18&addressdetails=1'
        )
        
        if response.status_code == 200:
            data = response.json()
            address = data.get('display_name', '')
            return jsonify({'address': address})
        return jsonify({'address': f'{latitude}, {longitude}'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin Routes
# Update the existing admin_dashboard function
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.", "danger")
        return redirect(url_for('admin_login'))
    
    # Get all users
    users = User.query.order_by(User.created_at.desc()).all()
    
    # Get all incidents with reporter info and evidence
    incidents_with_users = db.session.query(Incident).options(
        db.joinedload(Incident.user),
        db.joinedload(Incident.evidence)
    ).order_by(Incident.created_at.desc()).all()
    
    # Prepare incidents as tuples (incident, user) for template compatibility
    incidents = [(incident, incident.user) for incident in incidents_with_users]
    
    # Get all vouchers with user info
    vouchers = db.session.query(Voucher)\
        .options(db.joinedload(Voucher.user))\
        .order_by(Voucher.created_at.desc())\
        .all()
    
    # Get all admins from admin database
    admin_engine = db.engines['admin']
    admin_session_maker = sessionmaker(bind=admin_engine)
    admin_session = admin_session_maker()
    try:
        admins = admin_session.query(Admin).order_by(Admin.created_at.desc()).all()
    finally:
        admin_session.close()
    
    # Get all law enforcement officers from police database
    police_engine = db.engines['police']
    police_session_maker = sessionmaker(bind=police_engine)
    police_session = police_session_maker()
    try:
        officers = police_session.query(LawEnforcement).order_by(LawEnforcement.created_at.desc()).all()
    finally:
        police_session.close()
    
    # Get statistics for dashboard cards
    incident_count = Incident.query.count()
    user_count = User.query.count()
    pending_rewards = Voucher.query.filter_by(is_approved=False, is_redeemed=False).count()
    
    return render_template('admindashboard.html',
                     incidents=incidents,
                     users=users,
                     vouchers=vouchers,
                     admins=admins,
                     officers=officers,
                     incident_count=incident_count,
                     user_count=user_count,
                     pending_rewards=pending_rewards,
                     admin_email=session['admin_email'])

# Add these new routes after the admin_dashboard function
@app.route('/admin/create_incident', methods=['POST'])
@csrf.exempt
def admin_create_incident():
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    try:
        data = request.json
        
        crime_type = data.get('crime_type')
        # Map crime_type id to name if digit
        if crime_type and str(crime_type).isdigit():
            incident_type = IncidentType.query.get(int(crime_type))
            if incident_type:
                crime_type = incident_type.name
        
        # Create new incident
        new_incident = Incident(
            crime_type=crime_type,
            description=data.get('description'),
            latitude=data.get('latitude'),
            longitude=data.get('longitude'),
            address=data.get('address'),
            status=data.get('status', 'reported')
        )
        
        # Associate with user if provided
        if 'user_id' in data and data['user_id']:
            new_incident.user_id = data['user_id']
        
        db.session.add(new_incident)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Incident created successfully',
            'incident_id': new_incident.id
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e), 'success': False, 'message': 'Error creating incident'}), 500

# Admin CRUD routes

@app.route('/admin/create_admin', methods=['POST'])
@csrf.exempt
def admin_create_admin():
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Check if email already exists
        existing = db.session.query(Admin).filter_by(email=email).first()
        if existing:
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_admin = Admin(
            email=email,
            password=hashed_password
        )
        db.session.add(new_admin)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Admin created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/get_admin/<int:admin_id>', methods=['GET'])
@csrf.exempt
def admin_get_admin(admin_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    admin = db.session.query(Admin).filter_by(id=admin_id).first()
    if not admin:
        return jsonify({'success': False, 'message': 'Admin not found'}), 404
    admin_data = {
        'id': admin.id,
        'email': admin.email
    }
    return jsonify({'success': True, 'admin': admin_data})

@app.route('/admin/update_admin/<int:admin_id>', methods=['POST'])
@csrf.exempt
def admin_update_admin(admin_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    try:
        data = request.json
        admin = db.session.query(Admin).filter_by(id=admin_id).first()
        if not admin:
            return jsonify({'success': False, 'message': 'Admin not found'}), 404
        
        if 'email' in data:
            # Check if email is unique
            existing = db.session.query(Admin).filter(Admin.email == data['email'], Admin.id != admin_id).first()
            if existing:
                return jsonify({'success': False, 'message': 'Email already exists'}), 400
            admin.email = data['email']
        if 'password' in data and data['password']:
            admin.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Admin updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/delete_admin/<int:admin_id>', methods=['DELETE'])
@csrf.exempt
def admin_delete_admin(admin_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    try:
        admin = db.session.query(Admin).filter_by(id=admin_id).first()
        if not admin:
            return jsonify({'success': False, 'message': 'Admin not found'}), 404
        db.session.delete(admin)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Admin deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# Law Enforcement CRUD routes

@app.route('/admin/create_officer', methods=['POST'])
@csrf.exempt
def admin_create_officer():
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        station = data.get('station')
        badge_number = data.get('badge_number')
        if not email or not password or not station or not badge_number:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Check if email already exists
        existing = db.session.execute(
            db.select(LawEnforcement).where(LawEnforcement.email == email)
        ).scalar_one_or_none()
        if existing:
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_officer = LawEnforcement(
            email=email,
            password=hashed_password,
            station=station,
            badge_number=badge_number
        )
        police_engine = db.engines['police']
        police_session_maker = sessionmaker(bind=police_engine)
        police_session = police_session_maker()
        try:
            police_session.add(new_officer)
            police_session.commit()
        finally:
            police_session.close()
        
        return jsonify({'success': True, 'message': 'Officer created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/get_officer/<int:officer_id>', methods=['GET'])
@csrf.exempt
def admin_get_officer(officer_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    police_engine = db.engines['police']
    police_session_maker = sessionmaker(bind=police_engine)
    police_session = police_session_maker()
    try:
        officer = police_session.query(LawEnforcement).filter_by(id=officer_id).first()
        if not officer:
            return jsonify({'success': False, 'message': 'Officer not found'}), 404
        officer_data = {
            'id': officer.id,
            'email': officer.email,
            'station': officer.station,
            'badge_number': officer.badge_number
        }
        return jsonify({'success': True, 'officer': officer_data})
    finally:
        police_session.close()

@app.route('/admin/update_officer/<int:officer_id>', methods=['POST'])
@csrf.exempt
def admin_update_officer(officer_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    police_engine = db.engines['police']
    police_session_maker = sessionmaker(bind=police_engine)
    police_session = police_session_maker()
    try:
        data = request.json
        officer = police_session.query(LawEnforcement).filter_by(id=officer_id).first()
        if not officer:
            return jsonify({'success': False, 'message': 'Officer not found'}), 404
        
        if 'email' in data:
            # Check if email is unique
            existing = police_session.query(LawEnforcement).filter(LawEnforcement.email == data['email'], LawEnforcement.id != officer_id).first()
            if existing:
                return jsonify({'success': False, 'message': 'Email already exists'}), 400
            officer.email = data['email']
        if 'password' in data and data['password']:
            officer.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        if 'station' in data:
            officer.station = data['station']
        if 'badge_number' in data:
            officer.badge_number = data['badge_number']
        
        police_session.commit()
        return jsonify({'success': True, 'message': 'Officer updated successfully'})
    except Exception as e:
        police_session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        police_session.close()

@app.route('/admin/delete_officer/<int:officer_id>', methods=['DELETE'])
@csrf.exempt
def admin_delete_officer(officer_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    police_engine = db.engines['police']
    police_session_maker = sessionmaker(bind=police_engine)
    police_session = police_session_maker()
    try:
        officer = police_session.query(LawEnforcement).filter_by(id=officer_id).first()
        if not officer:
            return jsonify({'success': False, 'message': 'Officer not found'}), 404
        police_session.delete(officer)
        police_session.commit()
        return jsonify({'success': True, 'message': 'Officer deleted successfully'})
    except Exception as e:
        police_session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        police_session.close()

@app.route('/admin/get_incident/<int:id>', methods=['GET'])
@csrf.exempt
def admin_get_incident(id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(id)
    if not incident:
        return jsonify({'error': 'Incident not found', 'success': False}), 404
    
    user = None
    if incident.user_id:
        user_obj = User.query.get(incident.user_id)
        if user_obj:
            user = {
                'id': user_obj.id,
                'name': user_obj.name,
                'email': user_obj.email,
                'phone': user_obj.phone,
                'address': user_obj.address
            }
    
    return jsonify({
        'success': True,
        'incident': {
            'id': incident.id,
            'crime_type': incident.crime_type,
            'description': incident.description,
            'latitude': incident.latitude,
            'longitude': incident.longitude,
            'address': incident.address,
            'status': incident.status,
            'user_id': incident.user_id,
            'created_at': incident.created_at.isoformat() if incident.created_at else None,
            'user': user
        }
    })
@app.route('/admin/verify_incident/<int:incident_id>', methods=['POST'])
@csrf.exempt
def verify_incident(incident_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    incident.status = 'verified'
    db.session.commit()
    return jsonify({'success': True, 'message': 'Incident verified'})

@app.route('/admin/update_incident/<int:incident_id>', methods=['POST'])
@csrf.exempt
def admin_update_incident(incident_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    try:
        data = request.json
        
        # Update incident details if provided
        if 'crime_type' in data:
            crime_type = data['crime_type']
            # Map crime_type id to name if digit
            if crime_type and str(crime_type).isdigit():
                incident_type = IncidentType.query.get(int(crime_type))
                if incident_type:
                    crime_type = incident_type.name
            incident.crime_type = crime_type
        if 'description' in data:
            incident.description = data['description']
        if 'address' in data:
            incident.address = data['address']
        if 'status' in data:
            incident.status = data['status']
            
            # Award points if status changed to resolved
            if data['status'] == 'resolved' and incident.user_id:
                user = User.query.get(incident.user_id)
                if user:
                    # Award points based on incident type or complexity
                    points_to_award = 100
                    if user.points is None:
                        user.points = points_to_award
                    else:
                        user.points += points_to_award
                    
                    # Create a pending voucher entry for approval
                    voucher_code = f"RWD-{user.id}-{incident.id}-{int(datetime.utcnow().timestamp())}"
                    new_voucher = Voucher(
                        user_id=user.id,
                        incident_id=incident.id,
                        reward_type="Incident Report Reward",
                        points_cost=points_to_award,
                        voucher_code=voucher_code
                    )
                    db.session.add(new_voucher)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Incident updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete_incident/<int:incident_id>', methods=['DELETE'])
@csrf.exempt
def delete_incident(incident_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    db.session.delete(incident)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Incident deleted'})

@app.route('/admin/users/<int:user_id>', methods=['GET', 'DELETE'])
@csrf.exempt
def manage_user(user_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401

    if request.method == 'GET':
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        user_data = {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'address': user.address
        }
        return jsonify({'success': True, 'user': user_data})

    elif request.method == 'DELETE':
        try:
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            db.session.delete(user)
            db.session.commit()
            return jsonify({'success': True, 'message': 'User deleted successfully'})
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

# Add a new column to User model for is_active status if it doesn't exist
# This would typically be done via a migration
if not hasattr(User, 'is_active'):
    is_active = db.Column(db.Boolean, default=True)
    setattr(User, 'is_active', is_active)

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@csrf.exempt
def toggle_user_status(user_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Toggle the user's active status
        if hasattr(user, 'is_active'):
            user.is_active = not user.is_active
            is_active = user.is_active
        else:
            # Fallback if column doesn't exist
            is_active = True
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f"User {'activated' if is_active else 'deactivated'} successfully",
            'is_active': is_active
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@csrf.exempt
def update_user(user_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Update all provided fields
        if 'name' in data:
            user.name = data['name']
        if 'email' in data:
            user.email = data['email']
        if 'phone' in data:
            user.phone = data['phone']
        if 'address' in data:
            user.address = data['address']
            
        db.session.commit()
        return jsonify({'success': True, 'message': 'User updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Law Enforcement Routes
@app.route('/law_enforcement_dashboard')
def law_enforcement_dashboard():
    if 'officer_id' not in session:
        flash("Please log in to access the dashboard.", "danger")
        return redirect(url_for('law_enforcement_login'))
    
    try:
        # Get officer info
        officer = db.session.execute(
            db.select(LawEnforcement).where(LawEnforcement.id == session['officer_id'])
        ).scalar_one_or_none()
        
        if not officer:
            flash("Officer not found. Please log in again.", "warning")
            return redirect(url_for('law_enforcement_login'))
        
        # Get incidents with user data using joinedload
        incidents = db.session.query(Incident).options(
            db.joinedload(Incident.user),
            db.joinedload(Incident.evidence)
        ).order_by(Incident.created_at.desc()).limit(50).all()
        
        # Serialize incidents to dicts for JSON serialization in template
        def serialize_incident(incident):
            return {
                'id': incident.id,
                'crime_type': incident.crime_type,
                'description': incident.description,
                'latitude': incident.latitude,
                'longitude': incident.longitude,
                'address': incident.address,
                'status': incident.status,
                'user': {
                    'id': incident.user.id if incident.user else None,
                    'name': incident.user.name if incident.user else 'Unknown',
                    'email': incident.user.email if incident.user else ''
                },
                'assigned_officer': {
                    'id': incident.assigned_officer_id,
                    'email': None
                },
                'evidence': [{
                    'file_path': ev.file_path,
                    'file_type': ev.file_type
                } for ev in incident.evidence]
            }
        
        # Fetch assigned officer emails for incidents with assigned_officer_id
        assigned_officer_ids = [inc.assigned_officer_id for inc in incidents if inc.assigned_officer_id]
        assigned_officers = {}
        if assigned_officer_ids:
            officers = db.session.query(LawEnforcement).filter(LawEnforcement.id.in_(assigned_officer_ids)).all()
            assigned_officers = {officer.id: officer.email for officer in officers}
        
        incidents_serialized = []
        for inc in incidents:
            inc_dict = serialize_incident(inc)
            if inc_dict['assigned_officer']['id'] in assigned_officers:
                inc_dict['assigned_officer']['email'] = assigned_officers[inc_dict['assigned_officer']['id']]
            incidents_serialized.append(inc_dict)
        
        return render_template('law_enforcement_dashboard.html',
                            officer=officer,
                            incidents=incidents_serialized)
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error loading dashboard: {str(e)}", "danger")
        app.logger.error(f"Law enforcement dashboard error: {str(e)}")
        return redirect(url_for('law_enforcement_login'))

# New route to list officers
@app.route('/law_enforcement_officers')
def law_enforcement_officers():
    if 'officer_id' not in session:
        flash("Please log in to access officers list.", "danger")
        return redirect(url_for('law_enforcement_login'))
    try:
        officers = db.session.execute(
            db.select(LawEnforcement).order_by(LawEnforcement.created_at.desc())
        ).scalars().all()
        return render_template('law_enforcement_officers.html', officers=officers)
    except Exception as e:
        db.session.rollback()
        flash(f"Error loading officers list: {str(e)}", "danger")
        app.logger.error(f"Law enforcement officers error: {str(e)}")
        return redirect(url_for('law_enforcement_dashboard'))

# New API endpoint to get officers as JSON
@app.route('/api/law_enforcement_officers')
def api_law_enforcement_officers():
    if 'officer_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    try:
        officers = db.session.query(LawEnforcement).order_by(LawEnforcement.created_at.desc()).all()
        officers_list = [{'id': o.id, 'email': o.email, 'station': o.station, 'badge_number': o.badge_number} for o in officers]
        return jsonify({'success': True, 'officers': officers_list})
    except Exception as e:
        app.logger.error(f"Error fetching officers JSON: {str(e)}")
        return jsonify({'error': 'Failed to fetch officers'}), 500

# New route for law enforcement settings
@app.route('/law_enforcement_settings')
def law_enforcement_settings():
    if 'officer_id' not in session:
        flash("Please log in to access settings.", "danger")
        return redirect(url_for('law_enforcement_login'))
    try:
        return render_template('law_enforcement_settings.html')
    except Exception as e:
        flash(f"Error loading settings: {str(e)}", "danger")
        app.logger.error(f"Law enforcement settings error: {str(e)}")
        return redirect(url_for('law_enforcement_dashboard'))


# ... existing code ...

@app.route('/officer/assign_case/<int:incident_id>', methods=['POST'])
@csrf.exempt
def assign_case(incident_id):
    if 'officer_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    try:
        data = request.get_json()
        officer_id = data.get('officer_id', session['officer_id'])
        
        # Validate officer_id exists
        officer = db.session.execute(
            db.select(LawEnforcement).where(LawEnforcement.id == officer_id)
        ).scalar_one_or_none()
        if not officer:
            return jsonify({'error': 'Officer not found'}), 404
        
        incident.assigned_officer_id = officer_id
        incident.status = 'assigned'
        db.session.commit()
        return jsonify({
            'success': True, 
            'message': f'Case assigned to {officer.email}', 
            'officer_name': officer.email
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/officer/update_incident/<int:incident_id>', methods=['POST'])
@csrf.exempt
def officer_update_incident(incident_id):
    print(f"[DEBUG] Update incident request received for ID: {incident_id}")
    print(f"[DEBUG] Session data: {session}")
    
    if 'officer_id' not in session:
        print(f"[DEBUG] Not authorized - no officer_id in session")
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(incident_id)
    if not incident:
        print(f"[DEBUG] Incident not found with ID: {incident_id}")
        return jsonify({'error': 'Incident not found'}), 404
    
    try:
        # Debug the request type and form data
        print(f"[DEBUG] Request method: {request.method}")
        print(f"[DEBUG] Request content type: {request.content_type}")
        
        if request.is_json:
            data = request.get_json()
            print(f"[DEBUG] JSON data received: {data}")
        else:
            # Try to parse form data
            data = request.form.to_dict()
            print(f"[DEBUG] Form data received: {data}")
            
            # If no form data, try to get raw data and parse it
            if not data and request.data:
                try:
                    import json
                    data = json.loads(request.data)
                    print(f"[DEBUG] Raw data parsed as JSON: {data}")
                except Exception as json_error:
                    print(f"[DEBUG] Error parsing raw data: {str(json_error)}")
                    data = {}
        
        new_status = data.get('status')
        notes = data.get('notes', '')
        
        print(f"[DEBUG] Current status: {incident.status}, New status: {new_status}")
        
        if new_status:
            print(f"[DEBUG] Setting new status to: {new_status}")
            incident.status = new_status
            
            # If case is resolved, reward the reporter with points
            if new_status == 'resolved' and incident.user_id:
                user = User.query.get(incident.user_id)
                if user:
                    # Award points based on incident type or complexity
                    points_to_award = 100
                    print(f"[DEBUG] Awarding {points_to_award} points to user {user.id}")
                    print(f"[DEBUG] User current points: {user.points if user.points is not None else 0}")
                    if user.points is None:
                        user.points = points_to_award
                    else:
                        user.points += points_to_award
                    print(f"[DEBUG] User new points: {user.points}")
                    db.session.add(user)
        
        if notes:
            # In a real app, you would save notes to a separate table
            print(f"[DEBUG] Case notes: {notes}")
            # TODO: Create a Notes model and save notes
            pass
        
        # Make sure to explicitly update the incident in the session
        db.session.add(incident)
        print("[DEBUG] Committing changes to database...")
        db.session.commit()
        db.session.refresh(incident)
        print(f"[DEBUG] Database committed successfully. New status: {incident.status}")
        
        # Return success response
        return jsonify({'success': True, 'message': 'Incident updated', 'new_status': incident.status})
    
    except Exception as e:
        db.session.rollback()
        print(f"[DEBUG] Error updating incident: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500




# Voucher Management Routes
@app.route('/admin/approve_voucher/<int:voucher_id>', methods=['POST'])
@csrf.exempt
def approve_voucher(voucher_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    voucher = Voucher.query.get(voucher_id)
    if not voucher:
        return jsonify({'error': 'Voucher not found'}), 404
    
    try:
        voucher.is_approved = True
        voucher.approved_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Voucher approved successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/reject_voucher/<int:voucher_id>', methods=['POST'])
@csrf.exempt
def reject_voucher(voucher_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    voucher = Voucher.query.get(voucher_id)
    if not voucher:
        return jsonify({'error': 'Voucher not found'}), 404
    
    try:
        # Refund points to user if voucher is rejected
        user = User.query.get(voucher.user_id)
        if user:
            user.points += voucher.points_cost
        
        # Delete the voucher
        db.session.delete(voucher)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Voucher rejected and points refunded'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Community Features
@app.route('/communitychat')
def communitychat():
    if 'user_id' not in session:
        flash("Please log in to access the community chat.", "warning")
        return redirect(url_for('login'))
    return render_template('communitychat.html')

from flask import jsonify

# API endpoint to get list of users who have sent chat messages
# Renamed to avoid endpoint function name conflict
@app.route('/api/chat/users')
def get_chat_users_api():
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    # Query distinct users from CommunityChatMessage
    users = db.session.query(
        CommunityChatMessage.user_id,
        CommunityChatMessage.username
    ).distinct().all()
    user_list = [{'user_id': u.user_id, 'username': u.username} for u in users]
    return jsonify(user_list)

# API endpoint to get chat history with a specific user
# Renamed to avoid endpoint function name conflict
@app.route('/api/chat/history/<int:user_id>')
def get_chat_history_api(user_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    messages = CommunityChatMessage.query.filter(
        (CommunityChatMessage.user_id == user_id) | 
        ((CommunityChatMessage.user_id == None) & (CommunityChatMessage.is_admin == True))
    ).order_by(CommunityChatMessage.timestamp.asc()).all()
    message_list = []
    for msg in messages:
        message_list.append({
            'id': msg.id,
            'user_id': msg.user_id,
            'username': msg.username if msg.username else 'Admin',
            'message': msg.message,
            'timestamp': msg.timestamp.isoformat(),
            'is_admin': msg.is_admin
        })
    return jsonify(message_list)

from flask_socketio import join_room, leave_room

@socketio.on('join_admin_room')
def handle_join_admin_room():
    if 'admin_id' not in session:
        return False  # Unauthorized
    join_room('admin_room')

@socketio.on('admin_send_message')
def handle_admin_send_message(data):
    if 'admin_id' not in session:
        return False  # Unauthorized
    user_id = data.get('user_id')
    message = data.get('message')
    if not user_id or not message:
        return
    # Save message to DB
    chat_msg = CommunityChatMessage(
        user_id=user_id,
        username='Admin',
        message=message,
        is_admin=True
    )
    db.session.add(chat_msg)
    db.session.commit()
    # Emit message to admin room and user room
    emit('new_message', {
        'id': chat_msg.id,
        'user_id': user_id,
        'username': 'Admin',
        'message': message,
        'timestamp': chat_msg.timestamp.isoformat(),
        'is_admin': True
    }, room='admin_room')
    emit('new_message', {
        'id': chat_msg.id,
        'user_id': user_id,
        'username': 'Admin',
        'message': message,
        'timestamp': chat_msg.timestamp.isoformat(),
        'is_admin': True
    }, room=f'user_{user_id}')

@socketio.on('join_user_room')
def join_user_room(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')

# API endpoint to get chat messages for logged-in user
@app.route('/api/chat/messages')
def get_user_chat_messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user_id = session['user_id']
    messages = CommunityChatMessage.query.filter_by(user_id=user_id).order_by(CommunityChatMessage.timestamp.asc()).all()
    result = []
    for msg in messages:
        result.append({
            'id': msg.id,
            'user_id': msg.user_id,
            'username': msg.username,
            'message': msg.message,
            'timestamp': msg.timestamp.isoformat(),
            'is_admin': msg.is_admin
        })
    return jsonify(result)


# Serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/thank_you_page')
def thank_you_page():
    return render_template('ThankYou Page.html')

from flask import request, jsonify


@app.route('/admin/_report', methods=['POST'])
@csrf.exempt
def generate_report_obsolete():
    # This is the older, simpler generate_report function that is now obsolete.
    # It is renamed to avoid conflict and can be removed later if desired.
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401

    data = request.get_json()
    
    # Initialize base query
    query = db.session.query(Incident).join(User, isouter=True)
    
    # Apply filters if they exist in the request
    if 'case_type' in data and data['case_type']:
        query = query.filter(Incident.crime_type == data['case_type'])
    
    if 'user_id' in data and data['user_id']:
        query = query.filter(Incident.user_id == data['user_id'])
    
    if 'date_from' in data and data['date_from']:
        query = query.filter(Incident.created_at >= data['date_from'])
    
    if 'date_to' in data and data['date_to']:
        query = query.filter(Incident.created_at <= data['date_to'])
    
    if 'status' in data and data['status']:
        query = query.filter(Incident.status == data['status'])
    
    if 'location' in data and data['location']:
        query = query.filter(Incident.address.ilike(f"%{data['location']}%"))
    
    # Execute the query
    incidents = query.all()

    # If no incidents found, return empty response
    if not incidents:
        return jsonify({
            'success': True,
            'message': 'No incidents found matching the criteria',
            'incident_summary': {},
            'user_activity': {},
            'officer_performance': {},
            'reward_vouchers': {}
        })

    # Incident summary: counts by crime_type and status
    incident_summary = {}
    for incident in incidents:
        ct = incident.crime_type or 'Unknown'
        if ct not in incident_summary:
            incident_summary[ct] = {
                'reported': 0, 
                'verified': 0, 
                'resolved': 0, 
                'false_alarm': 0
            }
        status_key = incident.status.lower() if incident.status else 'reported'
        if status_key not in incident_summary[ct]:
            incident_summary[ct][status_key] = 0
        incident_summary[ct][status_key] += 1

    # User activity: count of incidents reported by user
    user_activity = {}
    for incident in incidents:
        uid = incident.user_id
        if uid:
            user_activity[uid] = user_activity.get(uid, 0) + 1

    # Officer performance: counts of verified and resolved cases by officer
    officer_performance = {}
    for incident in incidents:
        officer_id = incident.assigned_officer_id
        if officer_id:
            if officer_id not in officer_performance:
                officer_performance[officer_id] = {'verified': 0, 'resolved': 0}
            status_key = incident.status.lower() if incident.status else ''
            if status_key == 'verified':
                officer_performance[officer_id]['verified'] += 1
            elif status_key == 'resolved':
                officer_performance[officer_id]['resolved'] += 1

    # Reward vouchers: counts by reward_type and status
    vouchers_query = db.session.query(Voucher)
    if 'user_id' in data and data['user_id']:
        vouchers_query = vouchers_query.filter(Voucher.user_id == data['user_id'])
    vouchers = vouchers_query.all()

    reward_vouchers = {}
    for voucher in vouchers:
        rt = voucher.reward_type or 'Unknown'
        if rt not in reward_vouchers:
            reward_vouchers[rt] = {'pending': 0, 'approved': 0, 'redeemed': 0}
        if voucher.is_redeemed:
            reward_vouchers[rt]['redeemed'] += 1
        elif voucher.is_approved:
            reward_vouchers[rt]['approved'] += 1
        else:
            reward_vouchers[rt]['pending'] += 1

    return jsonify({
        'success': True,
        'incident_summary': incident_summary,
        'user_activity': user_activity,
        'officer_performance': officer_performance,
        'reward_vouchers': reward_vouchers
    })

    
    # Get all vouchers with user info
    vouchers = db.session.query(Voucher).options(db.joinedload(Voucher.user)).order_by(Voucher.created_at.desc()).all()
    
    # Get current user for points display
    user = User.query.get(session['user_id'])
    
    # Define available rewards
    reward_options = [
        {
            'id': 1,
            'title': 'Shoprite R50 Voucher',
            'points': 500,
            'description': 'R50 voucher to spend at any Shoprite store'
        },
        {
            'id': 2,
            'title': 'Takealot R100 Voucher',
            'points': 1000,
            'description': 'R100 voucher to spend online at Takealot'
        },
        {
            'id': 3,
            'title': 'Cash Reward: R200',
            'points': 2000,
            'description': 'R200 cash reward via EFT'
        }
    ]
    
    return render_template('rewardspage.html', user=user, vouchers=vouchers, reward_options=reward_options)

@app.route('/rewards')
def rewards():
    if 'user_id' not in session:
        flash("Please log in to access the rewards page.", "warning")
        return redirect(url_for('login'))
    # Prepare data for rewards page
    user = User.query.get(session['user_id'])
    vouchers = db.session.query(Voucher).options(db.joinedload(Voucher.user)).filter(Voucher.user_id == user.id).order_by(Voucher.created_at.desc()).all()
    reward_options = [
        {
            'id': 1,
            'title': 'Shoprite R50 Voucher',
            'points': 500,
            'description': 'R50 voucher to spend at any Shoprite store'
        },
        {
            'id': 2,
            'title': 'Takealot R100 Voucher',
            'points': 1000,
            'description': 'R100 voucher to spend online at Takealot'
        },
        {
            'id': 3,
            'title': 'Cash Reward: R200',
            'points': 2000,
            'description': 'R200 cash reward via EFT'
        }
    ]
    return render_template('rewardspage.html', user=user, vouchers=vouchers, reward_options=reward_options)

from flask import jsonify, request, session
from datetime import datetime

@app.route('/admin/generate_report', methods=['POST'])
@csrf.exempt
def generate_report():
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401

    try:
        filters = request.get_json()

        # Query incidents and users from main session
        query = db.session.query(Incident, User).join(User, Incident.user_id == User.id, isouter=True)

        # Apply filters on incidents and users
        if filters.get('case_type'):
            query = query.filter(Incident.crime_type == filters['case_type'])

        if filters.get('user_id'):
            query = query.filter(Incident.user_id == filters['user_id'])

        if filters.get('user_name'):
            query = query.filter(User.name.ilike(f"%{filters['user_name']}%"))

        if filters.get('date_from'):
            try:
                date_from = datetime.strptime(filters['date_from'], '%m/%d/%Y')
                query = query.filter(Incident.created_at >= date_from)
            except ValueError:
                return jsonify({'error': 'Invalid date_from format. Use mm/dd/yyyy'}), 400

        if filters.get('date_to'):
            try:
                date_to = datetime.strptime(filters['date_to'], '%m/%d/%Y')
                date_to = date_to.replace(hour=23, minute=59, second=59)
                query = query.filter(Incident.created_at <= date_to)
            except ValueError:
                return jsonify({'error': 'Invalid date_to format. Use mm/dd/yyyy'}), 400

        if filters.get('status'):
            query = query.filter(Incident.status == filters['status'])

        if filters.get('location'):
            query = query.filter(
                db.or_(
                    Incident.address.ilike(f"%{filters['location']}%"),
                    Incident.latitude.ilike(f"%{filters['location']}%"),
                    Incident.longitude.ilike(f"%{filters['location']}%")
                )
            )

        # Execute query to get incidents and users
        results = query.order_by(Incident.created_at.desc()).all()

        # If no results, return empty response
        if not results:
            return jsonify({
                'success': True,
                'message': 'No incidents found matching the criteria',
                'report_data': {
                    'incidents': [],
                    'summary': {},
                    'statistics': {}
                }
            })

        # Fetch officers from police session
        police_session = scoped_session(sessionmaker(bind=db.engines['police']))
        officers = police_session.query(LawEnforcement).all()
        officer_map = {officer.id: officer for officer in officers}

        # Prepare detailed incident data
        incidents = []
        for incident, user in results:
            officer = officer_map.get(incident.assigned_officer_id)
            incident_data = {
                'id': incident.id,
                'crime_type': incident.crime_type,
                'description': incident.description,
                'location': {
                    'latitude': incident.latitude,
                    'longitude': incident.longitude,
                    'address': incident.address
                },
                'status': incident.status,
                'created_at': incident.created_at.strftime('%m/%d/%Y %H:%M:%S'),
                'user': {
                    'id': user.id if user else None,
                    'name': user.name if user else 'Anonymous',
                    'email': user.email if user else None
                },
                'officer': {
                    'id': officer.id if officer else None,
                    'email': officer.email if officer else None,
                    'station': officer.station if officer else None,
                    'badge_number': officer.badge_number if officer else None
                }
            }
            incidents.append(incident_data)

        # Generate summary statistics
        summary = {
            'total_incidents': len(results),
            'by_status': {},
            'by_crime_type': {},
            'by_officer': {}
        }

        for incident, _ in results:
            status = incident.status or 'unknown'
            summary['by_status'][status] = summary['by_status'].get(status, 0) + 1

            crime_type = incident.crime_type or 'unknown'
            summary['by_crime_type'][crime_type] = summary['by_crime_type'].get(crime_type, 0) + 1

            officer = officer_map.get(incident.assigned_officer_id)
            if officer:
                officer_key = f"{officer.email} ({officer.station})"
                summary['by_officer'][officer_key] = summary['by_officer'].get(officer_key, 0) + 1

        resolved_count = sum(1 for i, _ in results if i.status == 'resolved')
        resolution_rate = (resolved_count / len(results)) * 100 if results else 0

        statistics = {
            'resolution_rate': round(resolution_rate, 2),
            'average_response_time': None,
            'reports_per_day': None
        }

        return jsonify({
            'success': True,
            'report_data': {
                'incidents': incidents,
                'summary': summary,
                'statistics': statistics
            }
        })

    except Exception as e:
        app.logger.error(f"Error generating report: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'An error occurred while generating the report'
        }), 500

from flask import jsonify, request, session
import random
import string
from datetime import datetime

@app.route('/redeem_reward', methods=['POST'])
@csrf.exempt
def redeem_reward():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'User not logged in'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    reward_id = data.get('reward_id')
    reward_title = data.get('reward_title')
    points_cost = data.get('points_cost')
    
    if not reward_id or not reward_title or points_cost is None:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    if user.points is None or user.points < points_cost:
        return jsonify({'success': False, 'error': 'Insufficient points'}), 400
    
    try:
        # Deduct points
        user.points -= points_cost
        
        # Generate unique voucher code
        def generate_voucher_code(length=8):
            chars = string.ascii_uppercase + string.digits
            return ''.join(random.choice(chars) for _ in range(length))
        
        voucher_code = generate_voucher_code()
        
        # Ensure voucher_code is unique
        while Voucher.query.filter_by(voucher_code=voucher_code).first():
            voucher_code = generate_voucher_code()
        
        # Create voucher
        new_voucher = Voucher(
            user_id=user.id,
            reward_type=reward_title,
            points_cost=points_cost,
            voucher_code=voucher_code,
            is_approved=False,
            is_redeemed=False,
            created_at=datetime.utcnow()
        )
        db.session.add(new_voucher)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'voucher_code': voucher_code,
            'remaining_points': user.points
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    initialize_database()
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        ssl_context='adhoc' if os.getenv('USE_HTTPS') == 'true' else None
    )
