"""
Optional: Migrate existing feedback messages to the new chat system.
This converts the old single-message feedback into chat messages.

Run after migrate_add_chat.py: python migrate_feedback_to_chat.py
"""
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.abspath(os.environ.get("CLASSVOTE_DB", "classvote.db"))

def migrate_feedback_to_chat():
    print(f"Migrating feedback to chat: {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if homework_messages table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='homework_messages'")
    if not cursor.fetchone():
        print("❌ Error: homework_messages table does not exist!")
        print("   Run 'python migrate_add_chat.py' first.")
        conn.close()
        return
    
    # Get all student_homeworks with feedback
    cursor.execute("""
        SELECT 
            sh.id,
            sh.feedback,
            sh.feedback_by_user_id,
            sh.feedback_at,
            u.name as instructor_name
        FROM student_homeworks sh
        LEFT JOIN users u ON sh.feedback_by_user_id = u.id
        WHERE sh.feedback IS NOT NULL AND sh.feedback != ''
    """)
    
    feedbacks = cursor.fetchall()
    
    if not feedbacks:
        print("✓ No feedback messages to migrate.")
        conn.close()
        return
    
    print(f"Found {len(feedbacks)} feedback messages to migrate...")
    migrated = 0
    skipped = 0
    
    for sh_id, feedback, user_id, feedback_at, instructor_name in feedbacks:
        # Check if already migrated
        cursor.execute("""
            SELECT id FROM homework_messages 
            WHERE student_homework_id = ? AND message = ?
        """, (sh_id, feedback))
        
        if cursor.fetchone():
            skipped += 1
            continue
        
        # Create chat message from feedback
        sender_name = instructor_name or "Instructor"
        created_at = feedback_at or datetime.now().isoformat()
        
        cursor.execute("""
            INSERT INTO homework_messages 
            (student_homework_id, sender_type, sender_user_id, sender_student_id, 
             sender_name, message, created_at)
            VALUES (?, 'instructor', ?, NULL, ?, ?, ?)
        """, (sh_id, user_id, sender_name, feedback, created_at))
        
        migrated += 1
    
    conn.commit()
    conn.close()
    
    print(f"\n✓ Migration completed!")
    print(f"  - Migrated: {migrated} messages")
    print(f"  - Skipped (already migrated): {skipped} messages")
    print(f"\nNote: Original feedback field is preserved in student_homeworks table.")

if __name__ == "__main__":
    try:
        migrate_feedback_to_chat()
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
