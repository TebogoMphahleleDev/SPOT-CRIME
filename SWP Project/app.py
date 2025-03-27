from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_BINDS'] = {
    'admin': 'sqlite:///admin.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    emergency_contacts = db.relationship('EmergencyContact', backref='user', lazy=True)
    incidents = db.relationship('Incident', backref='user', lazy=True)

class Admin(db.Model):
    __bind_key__ = 'admin'
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class EmergencyContact(db.Model):
    __tablename__ = 'emergency_contacts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    relationship = db.Column(db.String(100), nullable=False)

class Incident(db.Model):
    __tablename__ = 'incidents'
    id = db.Column(db.Integer, primary_key=True)
    crime_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='reported')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# Database initialization
def initialize_database():
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin_email = "admin@example.com"
        admin_password = bcrypt.generate_password_hash("admin_password").decode('utf-8')
        admin = Admin.query.filter_by(email=admin_email).first()
        if not admin:
            admin = Admin(email=admin_email, password=admin_password)
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Login Successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Try again.", "danger")
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        admin = Admin.query.filter_by(email=email).first()
        if admin and bcrypt.check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
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

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard.", "warning")
        return redirect(url_for('login'))
    return render_template('Dashboard.html')

@app.route('/report_incident')
def report_incident():
    if 'user_id' not in session:
        flash("Please log in to report an incident.", "warning")
        return redirect(url_for('login'))
    return render_template('reportincident.html')

@app.route('/rewards')
def rewards():
    if 'user_id' not in session:
        flash("Please log in to access the rewards page.", "warning")
        return redirect(url_for('login'))
    return render_template('rewardspage.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("Please log in to access your profile.", "warning")
        return redirect(url_for('login'))
    return render_template('profile.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.", "danger")
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/communitychat')
def communitychat():
    return render_template('communitychat.html')

@app.route('/get_emergency_contacts')
def get_emergency_contacts():
    if 'user_id' not in session:
        return jsonify([])
    
    contacts = EmergencyContact.query.filter_by(user_id=session['user_id']).all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'phone': c.phone,
        'relationship': c.relationship
    } for c in contacts])

@app.route('/add_emergency_contact', methods=['POST'])
def add_emergency_contact():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    contact_count = EmergencyContact.query.filter_by(user_id=session['user_id']).count()
    if contact_count >= 5:
        return jsonify({'error': 'Maximum 5 contacts allowed'}), 400
    
    new_contact = EmergencyContact(
        user_id=session['user_id'],
        name=data['name'],
        phone=data['phone'],
        relationship=data['relationship']
    )
    db.session.add(new_contact)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/trigger_emergency', methods=['POST'])
def trigger_emergency():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    user = User.query.get(session['user_id'])
    contacts = EmergencyContact.query.filter_by(user_id=session['user_id']).all()
    
    return jsonify({
        'success': True,
        'message': 'Emergency alert triggered',
        'contacts_notified': len(contacts),
        'location': data.get('location')
    })

@app.route('/emergency')
def emergency():
    if 'user_id' not in session:
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))
    return render_template('emergency.html')

@app.route('/get_crime_data')
def get_crime_data():
    crimes = Incident.query.filter_by(status='verified').all()
    return jsonify([{
        'crime_type': crime.crime_type,
        'description': crime.description,
        'latitude': crime.latitude,
        'longitude': crime.longitude,
        'timestamp': crime.created_at.isoformat()
    } for crime in crimes])

@app.route('/crime-map')  
def crime_map(): 
    if 'user_id' not in session:
        flash("Please log in to access the crime map.", "warning")
        return redirect(url_for('login'))
    return render_template('crimemapPage.html')

if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)