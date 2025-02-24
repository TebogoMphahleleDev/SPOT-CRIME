import sqlite3

# Path to your database file
db_path = r"E:\School\flask-react-auth\SWP Project\database.db"

try:
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # List all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("Tables in database:", tables)

    # If there's a 'users' table, fetch all data (change 'users' if needed)
    table_name = "user"  # Change to your actual table name
    cursor.execute(f"SELECT * FROM {table_name};")
    rows = cursor.fetchall()

    print(f"\nData in '{table_name}' table:")
    for row in rows:
        print(row)

except sqlite3.Error as e:
    print("Error accessing database:", e)

finally:
    # Close the connection
    conn.close()
