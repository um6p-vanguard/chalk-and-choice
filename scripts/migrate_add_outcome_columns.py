#!/usr/bin/env python3
"""
Migrate existing database to add outcome-based columns.
Adds new columns to proficiency_exercises and proficiency_test_attempts tables.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db

def migrate_database():
    """Add new columns for learning outcomes system."""
    with app.app_context():
        print("🔧 Migrating database for learning outcomes system...")
        
        # Get database connection
        connection = db.engine.raw_connection()
        cursor = connection.cursor()
        
        try:
            # Check if learning_outcomes table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='learning_outcomes'")
            if not cursor.fetchone():
                print("⚠️  learning_outcomes table doesn't exist. Creating all tables...")
                db.create_all()
                print("✅ Created all tables including learning_outcomes")
            
            # Check if student_outcome_progress table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='student_outcome_progress'")
            if not cursor.fetchone():
                print("⚠️  student_outcome_progress table doesn't exist. Creating...")
                db.create_all()
                print("✅ Created student_outcome_progress table")
            
            # Add outcome_tag column to proficiency_exercises if it doesn't exist
            cursor.execute("PRAGMA table_info(proficiency_exercises)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'outcome_tag' not in columns:
                print("Adding outcome_tag column to proficiency_exercises...")
                cursor.execute("""
                    ALTER TABLE proficiency_exercises 
                    ADD COLUMN outcome_tag VARCHAR(64)
                """)
                print("✅ Added outcome_tag to proficiency_exercises")
            else:
                print("✓ outcome_tag already exists in proficiency_exercises")
            
            if 'difficulty_level' not in columns:
                print("Adding difficulty_level column to proficiency_exercises...")
                cursor.execute("""
                    ALTER TABLE proficiency_exercises 
                    ADD COLUMN difficulty_level INTEGER NOT NULL DEFAULT 1
                """)
                print("✅ Added difficulty_level to proficiency_exercises")
            else:
                print("✓ difficulty_level already exists in proficiency_exercises")
            
            # Add outcome_tag and final_score columns to proficiency_test_attempts if they don't exist
            cursor.execute("PRAGMA table_info(proficiency_test_attempts)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'outcome_tag' not in columns:
                print("Adding outcome_tag column to proficiency_test_attempts...")
                cursor.execute("""
                    ALTER TABLE proficiency_test_attempts 
                    ADD COLUMN outcome_tag VARCHAR(64)
                """)
                print("✅ Added outcome_tag to proficiency_test_attempts")
            else:
                print("✓ outcome_tag already exists in proficiency_test_attempts")
            
            if 'final_score' not in columns:
                print("Adding final_score column to proficiency_test_attempts...")
                cursor.execute("""
                    ALTER TABLE proficiency_test_attempts 
                    ADD COLUMN final_score FLOAT
                """)
                print("✅ Added final_score to proficiency_test_attempts")
            else:
                print("✓ final_score already exists in proficiency_test_attempts")
            
            # Commit changes
            connection.commit()
            print("\n✅ Migration completed successfully!")
            print("\n📊 Next steps:")
            print("   1. Run: python scripts/seed_learning_outcomes.py (if not done)")
            print("   2. Visit: /student/proficiency/outcomes")
            print("   3. Create exercises and assign outcome_tag to them")
            
        except Exception as e:
            connection.rollback()
            print(f"\n❌ Migration failed: {e}")
            raise
        finally:
            cursor.close()
            connection.close()

if __name__ == "__main__":
    migrate_database()
