#!/usr/bin/env python3
"""
Migration script to add mentor authentication support.

Changes:
1. Add password_hash, first_login, last_login to mentors table
2. Add mentor_id column to users table
"""

import sys
import os
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User, Mentor

def migrate():
    db_path = os.path.abspath(os.environ.get("CLASSVOTE_DB", "classvote.db"))
    print(f"Migrating database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("\n1. Checking mentors table...")
    
    # Check if password_hash column exists in mentors
    cursor.execute("PRAGMA table_info(mentors)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if 'password_hash' not in columns:
        print("   Adding password_hash to mentors...")
        cursor.execute("ALTER TABLE mentors ADD COLUMN password_hash VARCHAR(255) NOT NULL DEFAULT ''")
    else:
        print("   ✓ password_hash already exists")
    
    if 'first_login' not in columns:
        print("   Adding first_login to mentors...")
        cursor.execute("ALTER TABLE mentors ADD COLUMN first_login BOOLEAN NOT NULL DEFAULT 1")
    else:
        print("   ✓ first_login already exists")
    
    if 'last_login' not in columns:
        print("   Adding last_login to mentors...")
        cursor.execute("ALTER TABLE mentors ADD COLUMN last_login DATETIME")
    else:
        print("   ✓ last_login already exists")
    
    print("\n2. Checking users table...")
    
    # Check if mentor_id column exists in users
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if 'mentor_id' not in columns:
        print("   Adding mentor_id to users...")
        cursor.execute("ALTER TABLE users ADD COLUMN mentor_id INTEGER")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_users_mentor_id ON users(mentor_id)")
    else:
        print("   ✓ mentor_id already exists")
    
    conn.commit()
    conn.close()
    
    print("\n✓ Migration completed successfully!")
    print("\nNext steps:")
    print("1. Restart your application")
    print("2. Admin users can now create mentor accounts with passwords")
    print("3. Mentors can log in and manage their assignments")

if __name__ == "__main__":
    migrate()
