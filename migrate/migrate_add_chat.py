"""
Migration script to add homework_messages table for chat functionality.
Run this after pulling the new code: python migrate_add_chat.py
"""
import sqlite3
import os

DB_PATH = os.path.abspath(os.environ.get("CLASSVOTE_DB", "classvote.db"))

def migrate():
    print(f"Migrating database: {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if table already exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='homework_messages'")
    table_exists = cursor.fetchone() is not None
    
    if table_exists:
        print("✓ homework_messages table already exists!")
        conn.close()
        return
    
    print("Creating homework_messages table...")
    
    # Create the homework_messages table
    cursor.execute("""
        CREATE TABLE homework_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_homework_id INTEGER NOT NULL,
            sender_type VARCHAR(20) NOT NULL,
            sender_user_id INTEGER,
            sender_student_id INTEGER,
            sender_name VARCHAR(120) NOT NULL,
            message TEXT NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (student_homework_id) REFERENCES student_homeworks(id) ON DELETE CASCADE,
            FOREIGN KEY (sender_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (sender_student_id) REFERENCES students(id) ON DELETE SET NULL
        )
    """)
    
    # Create indexes for better performance
    cursor.execute("""
        CREATE INDEX ix_homework_messages_student_homework_id 
        ON homework_messages(student_homework_id)
    """)
    
    cursor.execute("""
        CREATE INDEX ix_homework_messages_created_at 
        ON homework_messages(created_at)
    """)
    
    conn.commit()
    conn.close()
    
    print("✓ Migration completed successfully!")
    print("\nNew table created:")
    print("  - homework_messages: Stores chat messages between students and instructors")

if __name__ == "__main__":
    migrate()
