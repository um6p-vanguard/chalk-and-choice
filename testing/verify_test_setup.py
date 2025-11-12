#!/usr/bin/env python3
"""
Verify test setup - check if students exist and app is running
"""

import requests
import sys
import os

# Add parent directory to path to import app and models
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from models import db, Student

def check_database():
    """Check if test students exist in database"""
    app = create_app()
    with app.app_context():
        total_students = Student.query.count()
        test_students = Student.query.filter(Student.email.like('student%@test.edu')).count()
        
        print("=" * 60)
        print("DATABASE CHECK")
        print("=" * 60)
        print(f"Total students in DB: {total_students}")
        print(f"Test students (student*@test.edu): {test_students}")
        
        if test_students > 0:
            # Show first few
            sample = Student.query.filter(Student.email.like('student%@test.edu')).limit(3).all()
            print(f"\nSample students:")
            for s in sample:
                print(f"  - {s.email} (ID: {s.id}, first_login: {s.first_login})")
            print(f"\n✅ Test students found!")
            return True
        else:
            print(f"\n❌ No test students found!")
            print(f"Run: python seed_test_students.py 100")
            return False

def check_app_running(base_url="http://localhost:5000"):
    """Check if the Flask app is running"""
    print("\n" + "=" * 60)
    print("APPLICATION CHECK")
    print("=" * 60)
    try:
        resp = requests.get(f"{base_url}/login", timeout=5)
        if resp.status_code == 200:
            print(f"✅ App is running at {base_url}")
            print(f"   Status: {resp.status_code}")
            return True
        else:
            print(f"⚠️  App responded but with status: {resp.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"❌ App is NOT running at {base_url}")
        print(f"   Start it with: python app.py")
        return False
    except Exception as e:
        print(f"❌ Error checking app: {e}")
        return False

def test_single_login(base_url="http://localhost:5000"):
    """Test login with one student"""
    print("\n" + "=" * 60)
    print("SINGLE LOGIN TEST")
    print("=" * 60)
    
    try:
        session = requests.Session()
        
        # Get login page
        resp = session.get(f"{base_url}/login")
        if resp.status_code != 200:
            print(f"❌ Failed to get login page: {resp.status_code}")
            return False
        
        # Extract CSRF token
        import re
        match = re.search(r'name="csrf"\s+value="([^"]+)"', resp.text)
        if not match:
            match = re.search(r'value="([^"]+)"\s+name="csrf"', resp.text)
        
        if not match:
            print(f"❌ Could not find CSRF token in login page")
            return False
        
        csrf_token = match.group(1)
        print(f"✓ Got CSRF token")
        
        # Try to login
        login_data = {
            'email': 'student1@test.edu',
            'password': 'TestPass1!23',
            'csrf': csrf_token
        }
        
        resp = session.post(f"{base_url}/login", data=login_data, allow_redirects=False)
        print(f"✓ Login response: {resp.status_code}")
        
        if resp.status_code in (302, 303):
            location = resp.headers.get('Location', '')
            print(f"✓ Redirected to: {location}")
            
            if '/password/new' in location:
                print(f"⚠️  First login requires password change")
                print(f"   Updating seed script to set first_login=False")
                return False
            else:
                print(f"✅ Login successful!")
                return True
        elif resp.status_code == 200:
            if 'Invalid credentials' in resp.text:
                print(f"❌ Invalid credentials")
            elif 'Account not found' in resp.text:
                print(f"❌ Account not found")
            else:
                print(f"❌ Login failed (no redirect)")
            return False
        else:
            print(f"❌ Unexpected status: {resp.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Login test failed: {e}")
        return False

if __name__ == '__main__':
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    
    db_ok = check_database()
    app_ok = check_app_running(base_url)
    
    if db_ok and app_ok:
        login_ok = test_single_login(base_url)
        
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Database: {'✅ OK' if db_ok else '❌ FAILED'}")
        print(f"App Running: {'✅ OK' if app_ok else '❌ FAILED'}")
        print(f"Login Test: {'✅ OK' if login_ok else '❌ FAILED'}")
        
        if db_ok and app_ok and login_ok:
            print(f"\n🎉 All checks passed! Ready for load testing.")
            print(f"Run: python test_load.py --students 100 --scenario full")
            sys.exit(0)
        else:
            print(f"\n⚠️  Some checks failed. Fix issues above before load testing.")
            sys.exit(1)
    else:
        print(f"\n⚠️  Setup incomplete. See errors above.")
        sys.exit(1)
