from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)

# Set paths for HTML templates and static files
app.template_folder = r"C:\School\School\SWP\THUSANG-HELP-Java-Varsity-Journey\SWP Project\templates"
app.static_folder = r"E:\School\flask-react-auth\SWP Project\Styling side"

# Secret key for session security
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SECURITY_PASSWORD_SALT'] = 'your_password_salt_here'  # For password reset tokens

# Configure Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///login_details.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create the database
with app.app_context():
    db.create_all()

# Password Reset Token Generator
def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
        return email
    except Exception:
        return None

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
            session['user_id'] = user.id  # Store user ID in session
            flash("Login Successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Try again.", "danger")
    return render_template('login.html')

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

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a password reset token
            token = generate_token(user.email)
            reset_url = url_for('reset_password_token', token=token, _external=True)
            # In a real app, you would send an email with the reset URL
            flash(f"Password reset link sent to {user.email}.", "success")
            return redirect(url_for('login'))
        else:
            flash("No account found with that email.", "danger")
    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    email = verify_token(token)
    if not email:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password == confirm_password:
            user = User.query.filter_by(email=email).first()
            if user:
                user.password = bcrypt.generate_password_hash(password).decode('utf-8')
                db.session.commit()
                flash("Password updated successfully! Please log in.", "success")
                return redirect(url_for('login'))
            else:
                flash("User not found.", "danger")
        else:
            flash("Passwords do not match.", "danger")
    return render_template('reset_password_token.html', token=token)

@app.route('/rewards')
def rewards():
    if 'user_id' not in session:
        flash("Please log in to access the rewards page.", "warning")
        return redirect(url_for('login'))
    return render_template('rewardspage.html')

@app.route('/report_incident', methods=['GET', 'POST'])
def report_incident():
    if 'user_id' not in session:
        flash("Please log in to report an incident.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Handle form submission
        incident_type = request.form.get('incident-type')
        location = request.form.get('location')
        description = request.form.get('description')
        witness_info = request.form.get('witness-info')
        contact_info = request.form.get('contact-info')
        vehicle_make = request.form.get('vehicle-make')
        vehicle_model = request.form.get('vehicle-model')
        vehicle_color = request.form.get('vehicle-color')
        license_plate = request.form.get('license-plate')
        evidence = request.files.getlist('evidence-upload')
        voice_note = request.files.get('voice-note')

        # Process the form data (e.g., save to database, handle file uploads, etc.)
        flash("Incident reported successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('reportincident.html')

# Run the application
if __name__ == '__main__':
    app.run(debug=True)