"""
Migration script to add feedback and reopen columns to student_homeworks table.
Run this after pulling the new code: python migrate_add_feedback.py
"""
import sqlite3
import os

DB_PATH = os.path.abspath(os.environ.get("CLASSVOTE_DB", "classvote.db"))

def migrate():
    print(f"Migrating database: {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if columns already exist
    cursor.execute("PRAGMA table_info(student_homeworks)")
    columns = [row[1] for row in cursor.fetchall()]
    
    migrations = []
    
    if 'feedback' not in columns:
        migrations.append("ALTER TABLE student_homeworks ADD COLUMN feedback TEXT")
    
    if 'feedback_by_user_id' not in columns:
        migrations.append("ALTER TABLE student_homeworks ADD COLUMN feedback_by_user_id INTEGER REFERENCES users(id)")
    
    if 'feedback_at' not in columns:
        migrations.append("ALTER TABLE student_homeworks ADD COLUMN feedback_at DATETIME")
    
    if 'reopened_at' not in columns:
        migrations.append("ALTER TABLE student_homeworks ADD COLUMN reopened_at DATETIME")
    
    if 'reopened_by_user_id' not in columns:
        migrations.append("ALTER TABLE student_homeworks ADD COLUMN reopened_by_user_id INTEGER REFERENCES users(id)")
    
    if not migrations:
        print("✓ Database already up to date!")
        conn.close()
        return
    
    print(f"Applying {len(migrations)} migration(s)...")
    
    for sql in migrations:
        print(f"  - {sql}")
        cursor.execute(sql)
    
    conn.commit()
    conn.close()
    
    print("✓ Migration complete!")

if __name__ == "__main__":
    migrate()
