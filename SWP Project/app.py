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

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:{os.getenv('DB_PASSWORD', '')}@{os.getenv('DB_HOST', 'localhost')}:{os.getenv('DB_PORT', '3306')}/{os.getenv('DB_NAME', 'community_safety')}"
app.config['SQLALCHEMY_BINDS'] = {
    'admin': f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:{os.getenv('DB_PASSWORD', '')}@{os.getenv('DB_HOST', 'localhost')}:{os.getenv('DB_PORT', '3306')}/admin_db"
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'max_overflow': 20,
    'pool_recycle': 3600,
    'pool_pre_ping': True
}
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'mp3', 'wav'}
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25MB
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', 'password-reset-salt')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'no-reply@example.com')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
mail = Mail(app)

# Models
class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
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

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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

# Database initialization
def initialize_database():
    with app.app_context():
        try:
            # Create databases if they don't exist
            connection = pymysql.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'root'),
                password=os.getenv('DB_PASSWORD', ''),
                port=int(os.getenv('DB_PORT', '3306'))
            )
            
            with connection.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {os.getenv('DB_NAME', 'community_safety')}")
                cursor.execute("CREATE DATABASE IF NOT EXISTS admin_db")
            
            connection.close()
            
            # Create tables for default bind
            db.create_all()
            
            # Create tables for admin bind
            admin_engine = db.engines['admin']
            db.metadata.create_all(admin_engine)
            
            # Create admin user if not exists
            admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
            admin_password = bcrypt.generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin_password')).decode('utf-8')
            
            # Use the admin bind to create the admin user
            with db.session(bind=db.engines['admin']) as admin_session:
                admin = admin_session.query(Admin).filter_by(email=admin_email).first()
                if not admin:
                    new_admin = Admin(email=admin_email, password=admin_password)
                    admin_session.add(new_admin)
                    admin_session.commit()
                    print("Admin user created successfully!")
                
        except Exception as e:
            print(f"Database initialization error: {str(e)}")
            # Fallback to SQLite if MySQL fails
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///community_safety.db'
            app.config['SQLALCHEMY_BINDS'] = {
                'admin': 'sqlite:///admin.db'
            }
            db.create_all()
            print("Using SQLite as fallback database")

# Authentication Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # First try admin login
        admin = Admin.query.filter_by(email=email).first()
        if admin and bcrypt.check_password_hash(admin.password, password):
            session.clear()  # Clear any existing session
            session['admin_id'] = admin.id
            session['admin_email'] = admin.email
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_dashboard'))
        
        # Then try regular user login
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session.clear()  # Clear any existing session
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash("Login Successful!", "success")
            return redirect(url_for('dashboard'))
        
        flash("Invalid credentials. Try again.", "danger")
    
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        admin = Admin.query.filter_by(email=email).first()
        if admin and bcrypt.check_password_hash(admin.password, password):
            session.clear()  # Clear any existing session
            session['admin_id'] = admin.id
            session['admin_email'] = admin.email
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid credentials. Try again.", "danger")
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
@csrf.exempt  # Temporarily exempt for testing, remove in production
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
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard.", "warning")
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    incidents = Incident.query.filter_by(user_id=session['user_id']).order_by(Incident.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', user=user, incidents=incidents)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash("Please log in to access your profile.", "warning")
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        user.name = request.form['name']
        user.phone = request.form['phone']
        user.address = request.form['address']
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

# Incident Reporting Routes
@app.route('/report-incident', methods=['GET', 'POST'])
@csrf.exempt  # Temporarily exempt for testing, remove in production
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
            return redirect(url_for('dashboard'))
        
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
            # Get CSRF token from headers
            csrf_token = request.headers.get('X-CSRFToken')
            if not csrf_token or not validate_csrf(csrf_token):
                return jsonify({'error': 'Invalid CSRF token'}), 403
            
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
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.", "danger")
        return redirect(url_for('admin_login'))
    
    incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    return render_template('admindashboard.html',
                         incidents=incidents, 
                         users=users,
                         admin_email=session['admin_email'])

@app.route('/admin/verify_incident/<int:incident_id>', methods=['POST'])
def verify_incident(incident_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    incident.status = 'verified'
    db.session.commit()
    return jsonify({'success': True, 'message': 'Incident verified'})

@app.route('/admin/delete_incident/<int:incident_id>', methods=['DELETE'])
def delete_incident(incident_id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    db.session.delete(incident)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Incident deleted'})

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
    return render_template('rewardspage.html')

# Serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    initialize_database()
    # Create upload folder if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(host='0.0.0.0', port=5000, debug=True)