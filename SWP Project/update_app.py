import os

def add_routes_to_app():
    # Read the original app.py file
    with open('app.py', 'r') as f:
        app_content = f.read()
    
    # Read the admin routes to add
    with open('admin_routes_to_add.py', 'r') as f:
        routes_content = f.read()
    
    # Find the admin_dashboard function in app.py
    admin_dashboard_start = app_content.find("@app.route('/admin_dashboard')")
    admin_dashboard_end = app_content.find("@app.route", admin_dashboard_start + 1)
    
    if admin_dashboard_start != -1 and admin_dashboard_end != -1:
        # Get content before the function
        before_content = app_content[:admin_dashboard_start]
        # Get content after the function
        after_content = app_content[admin_dashboard_end:]
        
        # Create the new content by replacing the admin_dashboard function and adding new routes
        new_content = before_content + routes_content + after_content
        
        # Write the updated content back to app.py
        with open('app.py', 'w') as f:
            f.write(new_content)
        
        return True
    else:
        return False

if __name__ == "__main__":
    success = add_routes_to_app()
    if success:
        print("Successfully added new admin routes to app.py")
    else:
        print("Failed to add routes. Could not find admin_dashboard function.")

