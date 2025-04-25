from app import app, db, LawEnforcement
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

with app.app_context():
    # Create law enforcement user
    officer = LawEnforcement(
        email='police@gmail.com',
        password=bcrypt.generate_password_hash('police').decode('utf-8'),
        station='Main Police Station',
        badge_number='POL1234'
    )
    
    db.session.add(officer)
    db.session.commit()
    print("Successfully created law enforcement user: police@gmail.com")
