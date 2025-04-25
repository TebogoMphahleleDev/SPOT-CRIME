from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Fixed configuration with proper f-string syntax
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:"
    f"{os.getenv('DB_PASSWORD', '')}@"
    f"{os.getenv('DB_HOST', 'localhost')}:"
    f"{os.getenv('DB_PORT', '3306')}/"
    f"{os.getenv('DB_NAME', 'community_safety')}"
)

app.config['SQLALCHEMY_BINDS'] = {
    'admin': (
        f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:"
        f"{os.getenv('DB_PASSWORD', '')}@"
        f"{os.getenv('DB_HOST', 'localhost')}:"
        f"{os.getenv('DB_PORT', '3306')}/admin_db"
    ),
    'police': (
        f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:"
        f"{os.getenv('DB_PASSWORD', '')}@"
        f"{os.getenv('DB_HOST', 'localhost')}:"
        f"{os.getenv('DB_PORT', '3306')}/police_db"
    )
}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Model definitions would go here
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    # ... other columns

class Admin(db.Model):
    __bind_key__ = 'admin'
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    # ... other columns

class LawEnforcement(db.Model):
    __bind_key__ = 'police'
    __tablename__ = 'officers'
    id = db.Column(db.Integer, primary_key=True)
    # ... other columns

def initialize_database():
    with app.app_context():
        # SQLAlchemy 2.0 compatible initialization
        db.create_all()
        db.session.commit()

if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)
