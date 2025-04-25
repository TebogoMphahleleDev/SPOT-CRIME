from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from datetime import datetime
from dotenv import load_dotenv
import os
import pymysql
import requests
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from sqlalchemy.orm import scoped_session, sessionmaker

# Load environment variables
load_dotenv()

app = Flask(__name__)

# ================ CONFIGURATION ================
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:"
    f"{os.getenv('DB_PASSWORD', 'Mokgaga.082')}@"
    f"{os.getenv('DB_HOST', 'localhost')}:"
    f"{os.getenv('DB_PORT', '3306')}/"
    f"{os.getenv('DB_NAME', 'community_safety')}"
)

app.config['SQLALCHEMY_BINDS'] = {
    'admin': (
        f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:"
        f"{os.getenv('DB_PASSWORD', 'your_mysql_root_password_here')}@"
        f"{os.getenv('DB_HOST', 'localhost')}:"
        f"{os.getenv('DB_PORT', '3306')}/admin_db"
    ),
    'police': (
        f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:"
        f"{os.getenv('DB_PASSWORD', 'your_mysql_root_password_here')}@"
        f"{os.getenv('DB_HOST', 'localhost')}:"
        f"{os.getenv('DB_PORT', '3306')}/police_db"
    )
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 5,
    'max_overflow': 10,
    'pool_recycle': 300,
    'pool_pre_ping': True
}

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

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
    points = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    emergency_contacts = db.relationship('EmergencyContact', backref='user', lazy=True, cascade="all, delete-orphan")
    incidents = db.relationship('Incident', backref='user', lazy=True)

class Admin(db.Model):
    __bind_key__ = 'admin'
    __tablename__ = 'admins'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LawEnforcement(db.Model):
    __bind_key__ = 'police'
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
    
    # Add relationship to User model
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
            # Initialize all databases
            db.create_all()
            
            # Common user details
            user_email = "tebogo@gmail.com"
            user_password = bcrypt.generate_password_hash("tebogo").decode('utf-8')

            # 1. Main database - Create regular user
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
                db.session.commit()  # Commit to get the user ID
                
                # Now add emergency contact with the valid user_id
                emergency_contact = EmergencyContact(
                    user_id=regular_user.id,
                    name="Emergency Contact",
                    phone="9876543210",
                    relationship="Family"
                )
                db.session.add(emergency_contact)
                
                # Add a sample incident
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

            # 2. Admin database - Create admin user
            admin_engine = db.engines['admin']
            Admin.metadata.create_all(bind=admin_engine)
            admin_session_maker = sessionmaker(bind=admin_engine)
            admin_session = admin_session_maker()
            try:
                if not admin_session.query(Admin).filter_by(email=user_email).first():
                    admin = Admin(
                        email=user_email,
                        password=user_password
                    )
                    admin_session.add(admin)
                    admin_session.commit()
            finally:
                admin_session.close()

            # 3. Police database - Create law enforcement user
            police_engine = db.engines['police']
            LawEnforcement.metadata.create_all(bind=police_engine)
            police_session_maker = sessionmaker(bind=police_engine)
            police_session = police_session_maker()
            try:
                if not police_session.query(LawEnforcement).filter_by(email=user_email).first():
                    officer = LawEnforcement(
                        email=user_email,
                        password=user_password,
                        station="Johannesburg Central",
                        badge_number="JHB1234"
                    )
                    police_session.add(officer)
                    police_session.commit()
            finally:
                police_session.close()

            print("Database initialization successful with sample data!")
            
        except Exception as e:
            print(f"Error during initialization: {e}")
            # Fallback to SQLite
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///community_safety.db'
            app.config['SQLALCHEMY_BINDS'] = {
                'admin': 'sqlite:///admin.db',
                'police': 'sqlite:///police.db'
            }
            try:
                db.create_all()
                print("Using SQLite as fallback database")
            except Exception as sqlite_error:
                print(f"SQLite fallback failed: {sqlite_error}")
                raise

# ================ MIDDLEWARE ================
@app.before_request
def security_checks():
    # Enforce HTTPS in production
    if not request.is_secure and app.debug is False:
        return redirect(request.url.replace('http://', 'https://'), 301)
    
    # Check database connection
    try:
        db.session.execute(db.text('SELECT 1'))
    except Exception as e:
        db.session.rollback()
        try:
            db.session.remove()
            db.engine.dispose()
            db.create_all()
        except Exception as reconnect_error:
            return render_template('database_error.html'), 503

# ================ ROUTES ================
@app.route('/')
def home():
    return redirect(url_for('login'))

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
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_token(email)
            reset_url = url_for('reset_password_token', token=token, _external=True)
            
            msg = Message('Password Reset Request',
                          recipients=[email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request then simply ignore this email and no changes will be made.
'''
            try:
                mail.send(msg)
                flash('If an account with that email exists, a password reset link has been sent.', 'success')
            except Exception as e:
                flash('Failed to send reset email. Please try again later.', 'danger')
                app.logger.error(f"Failed to send password reset email: {str(e)}")
        else:
            flash('If an account with that email exists, a password reset link has been sent.', 'success')
        
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    email = confirm_token(token)
    if not email:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid email address.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password_token', token=token))
        
        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))
    
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
        
        # Calculate reports this month
        from datetime import datetime
        from sqlalchemy import extract
        now = datetime.utcnow()
        reports_this_month = db.session.query(Incident).filter(
            Incident.user_id == user.id,
            extract('year', Incident.created_at) == now.year,
            extract('month', Incident.created_at) == now.month
        ).count()
        
        # Calculate active patrols (assuming a model or method exists)
        # For now, set to a placeholder value
        active_patrols = 5  # Placeholder, replace with actual query if available
        
        return render_template('Dashboard.html', 
                               user=user, 
                               recent_incidents=recent_incidents,
                               emergency_contacts=emergency_contacts,
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
            'joinDate': user.created_at.isoformat(),
            'profilePic': None  # You can implement profile pictures later
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

@app.route('/api/emergency-contacts', methods=['GET', 'POST'])
@csrf.exempt
def emergency_contacts():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if request.method == 'GET':
        try:
            contacts = EmergencyContact.query.filter_by(user_id=session['user_id']).all()
            return jsonify([{
                'id': contact.id,
                'name': contact.name,
                'phone': contact.phone,
                'relationship': contact.relationship
            } for contact in contacts])
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        data = request.get_json()
        if not data or not all(key in data for key in ['name', 'phone', 'relationship']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        try:
            # Check if user already has 5 contacts (limit)
            contact_count = EmergencyContact.query.filter_by(user_id=session['user_id']).count()
            if contact_count >= 5:
                return jsonify({'error': 'Maximum of 5 emergency contacts allowed'}), 400
            
            contact = EmergencyContact(
                user_id=session['user_id'],
                name=data['name'],
                phone=data['phone'],
                relationship=data['relationship']
            )
            db.session.add(contact)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'contact': {
                    'id': contact.id,
                    'name': contact.name,
                    'phone': contact.phone,
                    'relationship': contact.relationship
                }
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

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
            'id': contact.id,
            'name': contact.name,
            'phone': contact.phone,
            'relationship': contact.relationship
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
        
        # You could also update a user profile_image field in the database here
        # user = User.query.get(session['user_id'])
        # user.profile_image = filename
        # db.session.commit()
        
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
                crime_type = request.form.get('other-crime', 'Unknown')
            
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
            return redirect(url_for('thank_you_page'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Error reporting incident: {str(e)}', 'danger')
    
    return render_template('reportincident.html')

@app.route('/crime-map')
def crime_map():
    if 'user_id' not in session:
        flash("Please log in to access the crime map.", "warning")
        return redirect(url_for('login'))
    return render_template('crimemapPage.html')

@app.route('/get_crime_data')
def get_crime_data():
    crimes = Incident.query.filter_by(status='verified').all()
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
    
    # Get all incidents with reporter info
    incidents = db.session.query(Incident, User)\
        .join(User, Incident.user_id == User.id, isouter=True)\
        .order_by(Incident.created_at.desc())\
        .all()
    
    # Get all vouchers with user info
    vouchers = db.session.query(Voucher)\
        .options(db.joinedload(Voucher.user))\
        .order_by(Voucher.created_at.desc())\
        .all()
    
    # Get statistics for dashboard cards
    incident_count = Incident.query.count()
    user_count = User.query.count()
    pending_rewards = Voucher.query.filter_by(is_approved=False, is_redeemed=False).count()
    
    return render_template('admindashboard.html',
                     incidents=incidents,
                     users=users,
                     vouchers=vouchers,
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
        
        # Create new incident
        new_incident = Incident(
            crime_type=data.get('crime_type'),
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

@app.route('/admin/get_incident/<int:id>', methods=['GET'])
@csrf.exempt
def admin_get_incident(id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(id)
    if not incident:
        return jsonify({'error': 'Incident not found', 'success': False}), 404
    
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
            'created_at': incident.created_at.isoformat() if incident.created_at else None
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
            incident.crime_type = data['crime_type']
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

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@csrf.exempt
def delete_user(user_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
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
            db.joinedload(Incident.user)
        ).order_by(Incident.created_at.desc()).limit(50).all()
        
        return render_template('law_enforcement_dashboard.html',
                            officer=officer,
                            incidents=incidents)
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error loading dashboard: {str(e)}", "danger")
        app.logger.error(f"Law enforcement dashboard error: {str(e)}")
        return redirect(url_for('law_enforcement_login'))

@app.route('/officer/assign_case/<int:incident_id>', methods=['POST'])
def assign_case(incident_id):
    if 'officer_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    try:
        incident.assigned_officer_id = session['officer_id']
        incident.status = 'assigned'
        db.session.commit()
        return jsonify({
            'success': True, 
            'message': 'Case assigned to you', 
            'officer_name': session.get('officer_email', 'Officer')
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

@app.route('/rewards')
def rewards():
    if 'user_id' not in session:
        flash("Please log in to access the rewards page.", "warning")
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Get user's vouchers
    vouchers = Voucher.query.filter_by(user_id=session['user_id']).order_by(Voucher.created_at.desc()).all()
    
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

# Serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize database
    initialize_database()
    
    # Run application
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        ssl_context='adhoc' if os.getenv('USE_HTTPS') == 'true' else None
    )
