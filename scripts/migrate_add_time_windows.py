#!/usr/bin/env python3
"""
Migration script to add time window availability fields to projects table.
Adds: availability_enabled (BOOLEAN), availability_rules (TEXT)
"""
import sqlite3
import os
import sys

# Add parent directory to path to import models
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DB_PATH = "classvote.db"

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at {DB_PATH}")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check current schema
    cursor.execute("PRAGMA table_info(projects)")
    columns = [row[1] for row in cursor.fetchall()]
    
    fields_to_add = []
    
    if "availability_enabled" not in columns:
        fields_to_add.append(("availability_enabled", "INTEGER NOT NULL DEFAULT 0"))
    
    if "availability_rules" not in columns:
        fields_to_add.append(("availability_rules", "TEXT"))
    
    if not fields_to_add:
        print("✅ All time window fields already exist in projects table.")
        conn.close()
        return
    
    print(f"Adding {len(fields_to_add)} column(s) to projects table...")
    
    for field_name, field_type in fields_to_add:
        try:
            cursor.execute(f"ALTER TABLE projects ADD COLUMN {field_name} {field_type}")
            print(f"  ✓ Added {field_name}")
        except sqlite3.OperationalError as e:
            print(f"  ⚠ {field_name}: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"✅ Migration completed successfully! Added {len(fields_to_add)} column(s).")

if __name__ == "__main__":
    migrate()
