#!/usr/bin/env python3
"""
Migration script to add homework acceptance fields to student_homeworks table.

This adds:
- acceptance_status: String field for 'accepted' or 'rejected'
- acceptance_comment: Text field for review comments
- reviewed_at: DateTime field for when the review was done
- reviewed_by_user_id: Foreign key to users table for tracking who reviewed

Usage:
    python migrate_homework_acceptance.py
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = "classvote.db"

def migrate():
    """Add acceptance tracking columns to student_homeworks table."""
    
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at {DB_PATH}")
        return False
    
    print(f"🔍 Migrating database at {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(student_homeworks)")
        columns = [row[1] for row in cursor.fetchall()]
        
        migrations_needed = []
        if 'acceptance_status' not in columns:
            migrations_needed.append('acceptance_status')
        if 'acceptance_comment' not in columns:
            migrations_needed.append('acceptance_comment')
        if 'reviewed_at' not in columns:
            migrations_needed.append('reviewed_at')
        if 'reviewed_by_user_id' not in columns:
            migrations_needed.append('reviewed_by_user_id')
        
        if not migrations_needed:
            print("✅ All acceptance columns already exist. No migration needed.")
            return True
        
        print(f"📝 Adding columns: {', '.join(migrations_needed)}")
        
        # Add acceptance_status column
        if 'acceptance_status' in migrations_needed:
            cursor.execute("""
                ALTER TABLE student_homeworks 
                ADD COLUMN acceptance_status VARCHAR(20)
            """)
            print("   ✓ Added acceptance_status column")
        
        # Add acceptance_comment column
        if 'acceptance_comment' in migrations_needed:
            cursor.execute("""
                ALTER TABLE student_homeworks 
                ADD COLUMN acceptance_comment TEXT
            """)
            print("   ✓ Added acceptance_comment column")
        
        # Add reviewed_at column
        if 'reviewed_at' in migrations_needed:
            cursor.execute("""
                ALTER TABLE student_homeworks 
                ADD COLUMN reviewed_at DATETIME
            """)
            print("   ✓ Added reviewed_at column")
        
        # Add reviewed_by_user_id column
        if 'reviewed_by_user_id' in migrations_needed:
            cursor.execute("""
                ALTER TABLE student_homeworks 
                ADD COLUMN reviewed_by_user_id INTEGER
            """)
            print("   ✓ Added reviewed_by_user_id column")
        
        conn.commit()
        
        # Verify the migration
        cursor.execute("PRAGMA table_info(student_homeworks)")
        columns_after = [row[1] for row in cursor.fetchall()]
        
        all_present = all(col in columns_after for col in ['acceptance_status', 'acceptance_comment', 'reviewed_at', 'reviewed_by_user_id'])
        
        if all_present:
            print("\n✅ Migration completed successfully!")
            print("\nNew columns added:")
            print("  • acceptance_status - Stores 'accepted' or 'rejected'")
            print("  • acceptance_comment - Optional comment from mentor")
            print("  • reviewed_at - Timestamp of review")
            print("  • reviewed_by_user_id - Foreign key to users table")
            return True
        else:
            print("\n❌ Migration verification failed!")
            return False
            
    except sqlite3.Error as e:
        print(f"\n❌ Migration failed: {e}")
        conn.rollback()
        return False
        
    finally:
        conn.close()

def verify():
    """Verify the migration by checking table structure."""
    
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at {DB_PATH}")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("PRAGMA table_info(student_homeworks)")
        columns = cursor.fetchall()
        
        print("\n📊 Current student_homeworks table structure:")
        print("-" * 70)
        for col in columns:
            col_id, name, dtype, notnull, default, pk = col
            print(f"  {name:25} {dtype:15} {'NOT NULL' if notnull else ''}")
        print("-" * 70)
        
        # Count homeworks by acceptance status
        cursor.execute("""
            SELECT 
                acceptance_status,
                COUNT(*) as count
            FROM student_homeworks
            WHERE submitted_at IS NOT NULL
            GROUP BY acceptance_status
        """)
        status_counts = cursor.fetchall()
        
        print("\n📈 Homework Review Status:")
        print("-" * 70)
        total_submitted = 0
        for status, count in status_counts:
            status_label = status if status else "Pending Review"
            print(f"  {status_label:20} {count} submission(s)")
            total_submitted += count
        
        if total_submitted == 0:
            print("  No submitted homeworks yet")
        print("-" * 70)
        
    except sqlite3.Error as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    print("=" * 70)
    print("  Homework Acceptance Migration")
    print("=" * 70)
    print()
    
    success = migrate()
    
    if success:
        print()
        verify()
        print("\n✅ You can now use the homework acceptance feature!")
        print("   Mentors can accept/reject homework submissions from their profile page.")
    else:
        print("\n❌ Migration failed. Please check the errors above.")
