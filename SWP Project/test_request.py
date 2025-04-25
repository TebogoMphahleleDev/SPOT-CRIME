import requests
import json

url = "http://localhost:5000/officer/update_incident/4"
headers = {"Content-Type": "application/json"}
data = {"status": "resolved", "notes": "Test note"}

print("Sending test request...")
response = requests.post(url, headers=headers, json=data)
print(f"Status code: {response.status_code}")
print(f"Response: {response.text}")
