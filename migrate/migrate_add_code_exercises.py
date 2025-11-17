#!/usr/bin/env python3
"""
Migration: Add code exercises feature
Adds three tables: code_exercises, code_submissions, student_progress
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db
from models import CodeExercise, CodeSubmission, StudentProgress

def migrate():
    with app.app_context():
        print("Creating code exercise tables...")
        
        # Create tables
        db.create_all()
        
        print("✓ Tables created successfully!")
        print("  - code_exercises")
        print("  - code_submissions")
        print("  - student_progress")

if __name__ == '__main__':
    migrate()
