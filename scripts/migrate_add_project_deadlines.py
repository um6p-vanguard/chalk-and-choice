#!/usr/bin/env python3
"""
Migration script to add deadline fields to projects table.
Adds: starts_at, due_at, hard_deadline_at, late_penalty_percent
"""

import sys
import os

# Add parent directory to path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db

def migrate():
    with app.app_context():
        try:
            # Check if columns already exist
            result = db.session.execute(db.text("PRAGMA table_info(projects)"))
            existing_columns = [row[1] for row in result]
            
            migrations = []
            
            if 'starts_at' not in existing_columns:
                migrations.append("ALTER TABLE projects ADD COLUMN starts_at DATETIME")
            
            if 'due_at' not in existing_columns:
                migrations.append("ALTER TABLE projects ADD COLUMN due_at DATETIME")
            
            if 'hard_deadline_at' not in existing_columns:
                migrations.append("ALTER TABLE projects ADD COLUMN hard_deadline_at DATETIME")
            
            if 'late_penalty_percent' not in existing_columns:
                migrations.append("ALTER TABLE projects ADD COLUMN late_penalty_percent REAL DEFAULT 0.0 NOT NULL")
            
            if not migrations:
                print("✓ All deadline columns already exist. No migration needed.")
                return
            
            # Run migrations
            for sql in migrations:
                print(f"Running: {sql}")
                db.session.execute(db.text(sql))
            
            db.session.commit()
            print(f"✅ Migration completed successfully! Added {len(migrations)} column(s).")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Migration failed: {e}")
            raise

if __name__ == "__main__":
    migrate()
