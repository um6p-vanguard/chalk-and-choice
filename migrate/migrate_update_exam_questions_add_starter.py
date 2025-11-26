#!/usr/bin/env python3
"""
Migration: Add code_starter_code to exam_questions

Adds a new nullable TEXT column 'code_starter_code' to support inline
starter code for code-type exam questions that are not linked to a
CodeExercise.
"""
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db  # noqa: E402
from sqlalchemy import text  # noqa: E402


def migrate():
    with app.app_context():
        print("Starting migration: Add code_starter_code to exam_questions")
        with db.engine.connect() as conn:
            # SQLite-safe: check existing columns
            res = conn.execute(text("PRAGMA table_info(exam_questions)"))
            cols = [row[1] for row in res.fetchall()]
            if 'code_starter_code' not in cols:
                print("Adding column exam_questions.code_starter_code ...")
                conn.execute(text("ALTER TABLE exam_questions ADD COLUMN code_starter_code TEXT"))
                conn.commit()
                print("✓ Column added")
            else:
                print("Column already exists; nothing to do")
        print("Migration completed.")


if __name__ == "__main__":
    migrate()
