import pymysql
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def add_is_active_column():
    try:
        # Connect to the MySQL database
        conn = pymysql.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', 3306)),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', 'Mokgaga.082'),
            database=os.getenv('DB_NAME', 'community_safety')
        )
        
        cursor = conn.cursor()
        
        # Check if the column already exists
        cursor.execute("SHOW COLUMNS FROM users LIKE 'is_active'")
        column_exists = cursor.fetchone()
        
        if not column_exists:
            # Add the is_active column if it doesn't exist
            cursor.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE")
            conn.commit()
            print("Successfully added 'is_active' column to the users table")
        else:
            print("The 'is_active' column already exists in the users table")
        
        conn.close()
        return True
    
    except Exception as e:
        print(f"Error adding column: {str(e)}")
        return False

if __name__ == "__main__":
    add_is_active_column()
