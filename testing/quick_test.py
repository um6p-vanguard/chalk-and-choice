#!/usr/bin/env python3
"""
Quick diagnostic test - checks one thing at a time
"""

import requests
import re

BASE_URL = "http://localhost:5000"

print("=" * 70)
print("STEP 1: Check if app is running")
print("=" * 70)
try:
    resp = requests.get(f"{BASE_URL}/login", timeout=5)
    print(f"✅ App is running - Status: {resp.status_code}")
except Exception as e:
    print(f"❌ App not accessible: {e}")
    print("\nMake sure to run: python app.py")
    exit(1)

print("\n" + "=" * 70)
print("STEP 2: Extract CSRF token from login page")
print("=" * 70)
session = requests.Session()
resp = session.get(f"{BASE_URL}/login")
html = resp.text

# Try different patterns
patterns = [
    r'name="csrf"\s+value="([^"]+)"',
    r'value="([^"]+)"\s+name="csrf"',
    r'<input[^>]*name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']',
    r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']csrf["\']',
]

csrf_token = None
for i, pattern in enumerate(patterns):
    match = re.search(pattern, html)
    if match:
        csrf_token = match.group(1)
        print(f"✅ Found CSRF token using pattern {i+1}: {csrf_token[:20]}...")
        break

if not csrf_token:
    print("❌ Could not extract CSRF token")
    print("\nFirst 500 chars of login page:")
    print(html[:500])
    exit(1)

print("\n" + "=" * 70)
print("STEP 3: Check if test students exist in database")
print("=" * 70)
try:
    from app import create_app
    from models import db, Student
    
    app = create_app()
    with app.app_context():
        student1 = Student.query.filter_by(email='student1@test.edu').first()
        if student1:
            print(f"✅ Test student exists: {student1.email}")
            print(f"   Name: {student1.name}")
            print(f"   ID: {student1.id}")
            print(f"   First login: {student1.first_login}")
        else:
            print("❌ student1@test.edu not found in database")
            print("\nRun this to create test students:")
            print("   python seed_test_students.py 100")
            exit(1)
except Exception as e:
    print(f"❌ Database check failed: {e}")
    exit(1)

print("\n" + "=" * 70)
print("STEP 4: Attempt login with student1@test.edu")
print("=" * 70)

login_data = {
    'email': 'student1@test.edu',
    'password': 'TestPass1!23',
    'csrf': csrf_token
}

resp = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=False)
print(f"Response status: {resp.status_code}")
print(f"Response headers: {dict(resp.headers)}")

if resp.status_code in (302, 303):
    location = resp.headers.get('Location', '')
    print(f"✅ Login successful - redirected to: {location}")
    
    if '/password/new' in location:
        print("\n⚠️  WARNING: Student requires password change (first_login=True)")
        print("Solution: Update seed_test_students.py to set first_login=False")
    else:
        print("\n🎉 Login fully successful!")
        
elif resp.status_code == 200:
    print("❌ Login failed (status 200 = no redirect)")
    # Check for error messages
    if 'Invalid credentials' in resp.text:
        print("   Error: Invalid credentials")
    elif 'Account not found' in resp.text:
        print("   Error: Account not found")
    else:
        print("   Unknown error - printing response snippet:")
        print(resp.text[:500])
else:
    print(f"❌ Unexpected status code: {resp.status_code}")

print("\n" + "=" * 70)
print("DIAGNOSTICS COMPLETE")
print("=" * 70)
