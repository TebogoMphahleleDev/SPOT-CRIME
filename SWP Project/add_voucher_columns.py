import pymysql
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def add_voucher_columns():
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
            print("The vouchers table does not exist. Please create it first.")
            return False
        
        # Add approved_at column if it doesn't exist
        cursor.execute("SHOW COLUMNS FROM vouchers LIKE 'approved_at'")
        approved_at_exists = cursor.fetchone()
        if not approved_at_exists:
            cursor.execute("ALTER TABLE vouchers ADD COLUMN approved_at DATETIME NULL")
            print("Added approved_at column to the vouchers table")
        else:
            print("The approved_at column already exists")
            
        # Add redeemed_at column if it doesn't exist
        cursor.execute("SHOW COLUMNS FROM vouchers LIKE 'redeemed_at'")
        redeemed_at_exists = cursor.fetchone()
        if not redeemed_at_exists:
            cursor.execute("ALTER TABLE vouchers ADD COLUMN redeemed_at DATETIME NULL")
            print("Added redeemed_at column to the vouchers table")
        else:
            print("The redeemed_at column already exists")
        
        conn.commit()
        conn.close()
        return True
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

if __name__ == "__main__":
    add_voucher_columns()
