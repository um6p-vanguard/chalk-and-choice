#!/usr/bin/env python3
"""
Migration script to add enhanced flag tracking columns to the students table.

Run with: python scripts/migrate_add_flag_status.py
"""

import os
import sys

# Add parent directory to path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from sqlalchemy import text

def migrate():
    """Add new flag columns to students table."""
    
    columns_to_add = [
        ("flag_status", "VARCHAR(32) NOT NULL DEFAULT 'none'"),
        ("flag_history_json", "TEXT"),
        ("flagged_at", "DATETIME"),
        ("flagged_by_user_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ]
    
    with app.app_context():
        conn = db.engine.connect()
        
        for col_name, col_def in columns_to_add:
            try:
                # Check if column exists
                result = conn.execute(text(f"PRAGMA table_info(students)"))
                columns = [row[1] for row in result.fetchall()]
                
                if col_name in columns:
                    print(f"  ✓ Column '{col_name}' already exists, skipping.")
                    continue
                
                # Add the column
                sql = f"ALTER TABLE students ADD COLUMN {col_name} {col_def}"
                conn.execute(text(sql))
                conn.commit()
                print(f"  ✓ Added column '{col_name}'")
                
            except Exception as e:
                print(f"  ✗ Error adding column '{col_name}': {e}")
        
        # Update existing flagged students to have 'under_review' status
        try:
            conn.execute(text("""
                UPDATE students 
                SET flag_status = 'under_review' 
                WHERE is_flagged = 1 AND (flag_status IS NULL OR flag_status = 'none')
            """))
            conn.commit()
            print("  ✓ Updated existing flagged students to 'under_review' status")
        except Exception as e:
            print(f"  ✗ Error updating existing flags: {e}")
        
        conn.close()
        print("\n✓ Migration completed successfully!")

if __name__ == "__main__":
    print("Running migration: Add flag status columns to students table\n")
    migrate()
