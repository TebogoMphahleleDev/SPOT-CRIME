import pymysql
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def add_incident_id_column():
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
        
        # Check if the table exists
        cursor.execute("SHOW TABLES LIKE 'vouchers'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            # Create the vouchers table if it doesn't exist
            cursor.execute("""
            CREATE TABLE vouchers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                reward_type VARCHAR(100) DEFAULT 'Incident Report Reward',
                points_cost INT DEFAULT 100,
                voucher_code VARCHAR(100) UNIQUE NOT NULL,
                is_approved BOOLEAN DEFAULT FALSE,
                is_redeemed BOOLEAN DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                approved_at DATETIME NULL,
                redeemed_at DATETIME NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            print("Created vouchers table")
            
            # Add the incident_id column
            cursor.execute("ALTER TABLE vouchers ADD COLUMN incident_id INT NULL, ADD FOREIGN KEY (incident_id) REFERENCES incidents(id)")
            print("Added incident_id column to the newly created vouchers table")
        else:
            # Check if the column already exists
            cursor.execute("SHOW COLUMNS FROM vouchers LIKE 'incident_id'")
            column_exists = cursor.fetchone()
            
            if not column_exists:
                # Add the incident_id column if it doesn't exist
                cursor.execute("ALTER TABLE vouchers ADD COLUMN incident_id INT NULL, ADD FOREIGN KEY (incident_id) REFERENCES incidents(id)")
                print("Successfully added 'incident_id' column to the vouchers table")
            else:
                print("The 'incident_id' column already exists in the vouchers table")
        
        conn.commit()
        conn.close()
        return True
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

if __name__ == "__main__":
    add_incident_id_column()
