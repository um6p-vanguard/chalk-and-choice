#!/usr/bin/env python3
"""
Create test students in the database for load testing
"""

import json
import sys
import os

# Add parent directory to path to import app and models
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from models import db, Student

def create_test_students(num_students: int = 100):
    """Create test students with predictable credentials"""
    app = create_app()
    
    with app.app_context():
        created = 0
        updated = 0
        
        for i in range(1, num_students + 1):
            email = f'student{i}@test.edu'
            name = f'Test Student {i}'
            password = f'TestPass{i}!23'
            
            student = Student.query.filter_by(email=email).first()
            
            if student:
                # Update existing
                student.name = name
                student.set_password(password)
                student.first_login = False  # Skip password change for testing
                updated += 1
            else:
                # Create new
                student = Student(
                    email=email,
                    name=name,
                    first_login=False  # Skip password change for testing
                )
                student.set_password(password)
                db.session.add(student)
                created += 1
            
            if i % 50 == 0:
                db.session.commit()
                print(f"Processed {i}/{num_students} students...")
        
        db.session.commit()
        
        print(f"\n✅ Test students ready!")
        print(f"   Created: {created}")
        print(f"   Updated: {updated}")
        print(f"   Total: {num_students}")
        print(f"\nCredentials format:")
        print(f"   Email: student[N]@test.edu")
        print(f"   Password: TestPass[N]!23")
        print(f"   Example: student1@test.edu / TestPass1!23")

if __name__ == '__main__':
    num = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    create_test_students(num)
