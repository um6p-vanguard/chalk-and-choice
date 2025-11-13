"""
Migration: Add read status tracking to homework messages
- student_read_at: when student last read messages
- instructor_read_at: when instructor last read messages
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from models import db

def migrate():
    with app.app_context():
        # Add new columns for tracking read status
        with db.engine.connect() as conn:
            # Check if columns already exist
            result = conn.execute(db.text("PRAGMA table_info(homework_messages)"))
            columns = [row[1] for row in result]
            
            if 'student_read_at' not in columns:
                print("Adding student_read_at column...")
                conn.execute(db.text("""
                    ALTER TABLE homework_messages 
                    ADD COLUMN student_read_at DATETIME NULL
                """))
                conn.commit()
                print("✓ Added student_read_at")
            else:
                print("✓ student_read_at already exists")
            
            if 'instructor_read_at' not in columns:
                print("Adding instructor_read_at column...")
                conn.execute(db.text("""
                    ALTER TABLE homework_messages 
                    ADD COLUMN instructor_read_at DATETIME NULL
                """))
                conn.commit()
                print("✓ Added instructor_read_at")
            else:
                print("✓ instructor_read_at already exists")
        
        print("\n✅ Migration completed successfully!")

if __name__ == "__main__":
    migrate()
