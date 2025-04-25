import os
import pymysql
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
db_user = os.getenv('DB_USER', 'root')
db_password = os.getenv('DB_PASSWORD', 'Mokgaga.082')
db_host = os.getenv('DB_HOST', 'localhost')
db_port = int(os.getenv('DB_PORT', '3306'))
db_name = os.getenv('DB_NAME', 'community_safety')

def update_incident_status(incident_id, new_status):
    try:
        # Connect to the database
        connection = pymysql.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            port=db_port,
            cursorclass=pymysql.cursors.DictCursor
        )
        
        with connection.cursor() as cursor:
            # Update the incident status
            sql = "UPDATE incidents SET status = %s WHERE id = %s"
            cursor.execute(sql, (new_status, incident_id))
            
            # Commit the changes
            connection.commit()
            
            # Verify the update
            cursor.execute("SELECT id, crime_type, status, user_id FROM incidents WHERE id = %s", (incident_id,))
            result = cursor.fetchone()
            print(f"Updated incident: {result}")
            
            return True
    except Exception as e:
        print(f"Error updating incident: {str(e)}")
        return False
    finally:
        connection.close()

if __name__ == "__main__":
    incident_id = 4
    new_status = "resolved"
    
    print(f"Updating incident {incident_id} to status: {new_status}")
    success = update_incident_status(incident_id, new_status)
    
    if success:
        print("✅ Status updated successfully!")
    else:
        print("❌ Failed to update status. Check the error message above.")
