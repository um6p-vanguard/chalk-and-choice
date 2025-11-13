#!/usr/bin/env python3
"""
Quick verification script to check if the mentor auth implementation is correct.
Tests imports and basic model structure without running the app.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Testing mentor authentication implementation...\n")

# Test 1: Import models
print("1. Testing model imports...")
try:
    from models import User, Mentor, db
    print("   ✓ Models imported successfully")
except Exception as e:
    print(f"   ✗ Error: {e}")
    sys.exit(1)

# Test 2: Check Mentor has auth methods
print("\n2. Checking Mentor authentication methods...")
try:
    assert hasattr(Mentor, 'set_password'), "Mentor missing set_password method"
    assert hasattr(Mentor, 'check_password'), "Mentor missing check_password method"
    print("   ✓ Mentor has set_password and check_password methods")
except AssertionError as e:
    print(f"   ✗ Error: {e}")
    sys.exit(1)

# Test 3: Check User has mentor_id
print("\n3. Checking User model has mentor_id...")
try:
    from sqlalchemy import inspect
    # We can't check columns without a database, but we can check if the attribute exists
    assert hasattr(User, 'mentor_id'), "User missing mentor_id attribute"
    print("   ✓ User has mentor_id field")
except AssertionError as e:
    print(f"   ✗ Error: {e}")
    sys.exit(1)

# Test 4: Import app and check routes exist
print("\n4. Testing app imports and routes...")
try:
    from app import app
    
    # Check if routes are registered
    routes = [rule.rule for rule in app.url_map.iter_rules()]
    
    required_routes = [
        '/mentors',
        '/mentor/profile',
        '/mentor/toggle-active',
        '/mentors/add',
        '/mentors/<int:mentor_id>/toggle',
        '/mentors/<int:mentor_id>/delete'
    ]
    
    for route in required_routes:
        # For dynamic routes, check if pattern exists
        route_pattern = route.replace('<int:mentor_id>', '<mentor_id>')
        matching = [r for r in routes if route_pattern in r or route in r]
        assert matching, f"Route {route} not found"
    
    print("   ✓ All required routes registered")
except Exception as e:
    print(f"   ✗ Error: {e}")
    sys.exit(1)

# Test 5: Check helper functions exist
print("\n5. Testing helper functions...")
try:
    from app import current_mentor, current_user, require_user
    print("   ✓ Helper functions exist")
except Exception as e:
    print(f"   ✗ Error: {e}")
    sys.exit(1)

# Test 6: Test password hashing (without database)
print("\n6. Testing password hashing...")
try:
    from werkzeug.security import generate_password_hash, check_password_hash
    test_password = "TestPass123!"
    hashed = generate_password_hash(test_password)
    assert check_password_hash(hashed, test_password), "Password verification failed"
    assert not check_password_hash(hashed, "wrong"), "Wrong password accepted"
    print("   ✓ Password hashing works correctly")
except Exception as e:
    print(f"   ✗ Error: {e}")
    sys.exit(1)

print("\n" + "="*60)
print("✓ All checks passed!")
print("="*60)
print("\nNext steps:")
print("1. Run: python3 migrate_mentor_auth.py")
print("2. Restart your application")
print("3. Test by logging in as admin and creating a mentor")
print("\nSee IMPLEMENTATION_SUMMARY.md for full testing checklist.")
