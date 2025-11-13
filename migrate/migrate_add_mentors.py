#!/usr/bin/env python3
"""
Migration: Add Mentor support with round-robin assignment

This migration:
1. Creates the mentors table
2. Adds mentor assignment columns to student_homeworks table
"""

import sys
import os

# Add parent directory to path to import models
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models import Mentor
from sqlalchemy import text

def migrate():
    with app.app_context():
        print("Starting migration: Add Mentor support")
        
        # Create mentors table
        print("Creating mentors table...")
        with db.engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS mentors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(120) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    created_at DATETIME NOT NULL
                )
            """))
            
            print("Creating index on mentors.email...")
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_mentors_email ON mentors (email)
            """))
            
            # Check if columns already exist
            print("Checking student_homeworks table columns...")
            result = conn.execute(text("PRAGMA table_info(student_homeworks)"))
            columns = [row[1] for row in result.fetchall()]
            
            # Add assigned_mentor_id column if it doesn't exist
            if 'assigned_mentor_id' not in columns:
                print("Adding assigned_mentor_id column to student_homeworks...")
                conn.execute(text("""
                    ALTER TABLE student_homeworks 
                    ADD COLUMN assigned_mentor_id INTEGER
                """))
                
                print("Creating foreign key and index...")
                conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_student_homeworks_assigned_mentor_id 
                    ON student_homeworks (assigned_mentor_id)
                """))
            else:
                print("assigned_mentor_id column already exists")
            
            # Add assigned_at column if it doesn't exist
            if 'assigned_at' not in columns:
                print("Adding assigned_at column to student_homeworks...")
                conn.execute(text("""
                    ALTER TABLE student_homeworks 
                    ADD COLUMN assigned_at DATETIME
                """))
            else:
                print("assigned_at column already exists")
            
            conn.commit()
        
        print("\nMigration completed successfully!")
        print("\nNext steps:")
        print("1. Go to /mentors to add mentors")
        print("2. Mentors will be automatically assigned when students submit homework")
        print("3. Assignment is round-robin per homework (1st->Mentor1, 2nd->Mentor2, etc.)")

def rollback():
    """Rollback this migration (use with caution in production)"""
    with app.app_context():
        print("Rolling back migration: Add Mentor support")
        
        # Note: SQLite doesn't support DROP COLUMN easily, so we'd need to recreate tables
        # For safety, we just drop the mentors table
        confirm = input("This will DROP the mentors table. Continue? (yes/no): ")
        if confirm.lower() == 'yes':
            with db.engine.connect() as conn:
                conn.execute(text("DROP TABLE IF EXISTS mentors"))
                conn.commit()
            print("Mentors table dropped.")
            print("Note: mentor columns in student_homeworks are left in place (SQLite limitation)")
        else:
            print("Rollback cancelled.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "rollback":
        rollback()
    else:
        migrate()
