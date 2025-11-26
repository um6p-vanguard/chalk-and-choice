#!/usr/bin/env python3
"""
Migration: Add Exam feature (exams, exam_questions, exam_submissions, exam_answers)

This script creates all tables required for the Exam feature and their indexes.
Compatible with SQLite; uses IF NOT EXISTS guards for idempotency.
"""

import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db  # noqa: E402
from sqlalchemy import text  # noqa: E402


def migrate():
    with app.app_context():
        print("Starting migration: Add Exam feature")
        with db.engine.connect() as conn:
            # Ensure foreign_keys pragma is on for SQLite
            conn.execute(text("PRAGMA foreign_keys = ON"))

            # --- exams table --------------------------------------------------
            print("Creating 'exams' table if not exists...")
            conn.execute(text(
                """
                CREATE TABLE IF NOT EXISTS exams (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code VARCHAR(12) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    start_at DATETIME NOT NULL,
                    end_at DATETIME,
                    is_published BOOLEAN NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL,
                    creator_user_id INTEGER,
                    FOREIGN KEY (creator_user_id) REFERENCES users (id) ON DELETE SET NULL
                )
                """
            ))
            # Unique index on code
            conn.execute(text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS uq_exams_code ON exams (code)
                """
            ))
            # Index for creator_user_id
            conn.execute(text(
                """
                CREATE INDEX IF NOT EXISTS ix_exams_creator_user_id ON exams (creator_user_id)
                """
            ))

            # --- exam_questions table ----------------------------------------
            print("Creating 'exam_questions' table if not exists...")
            conn.execute(text(
                """
                CREATE TABLE IF NOT EXISTS exam_questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    exam_id INTEGER NOT NULL,
                    "order" INTEGER NOT NULL,
                    q_type VARCHAR(10) NOT NULL,
                    title VARCHAR(255),
                    prompt TEXT,
                    points INTEGER NOT NULL DEFAULT 1,
                    options_json TEXT,
                    correct_indices_json TEXT,
                    multiple_select BOOLEAN NOT NULL DEFAULT 0,
                    code_exercise_id INTEGER,
                    FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE,
                    FOREIGN KEY (code_exercise_id) REFERENCES code_exercises (id) ON DELETE SET NULL
                )
                """
            ))
            conn.execute(text(
                """
                CREATE INDEX IF NOT EXISTS ix_exam_questions_exam_id ON exam_questions (exam_id)
                """
            ))
            conn.execute(text(
                """
                CREATE INDEX IF NOT EXISTS ix_exam_questions_code_exercise_id ON exam_questions (code_exercise_id)
                """
            ))

            # --- exam_submissions table --------------------------------------
            print("Creating 'exam_submissions' table if not exists...")
            conn.execute(text(
                """
                CREATE TABLE IF NOT EXISTS exam_submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    exam_id INTEGER NOT NULL,
                    student_id INTEGER NOT NULL,
                    started_at DATETIME NOT NULL,
                    submitted_at DATETIME,
                    score FLOAT NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL,
                    CONSTRAINT uq_exam_student_unique_submission UNIQUE (exam_id, student_id),
                    FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE,
                    FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE
                )
                """
            ))
            conn.execute(text(
                """
                CREATE INDEX IF NOT EXISTS ix_exam_submissions_exam_id ON exam_submissions (exam_id)
                """
            ))
            conn.execute(text(
                """
                CREATE INDEX IF NOT EXISTS ix_exam_submissions_student_id ON exam_submissions (student_id)
                """
            ))

            # --- exam_answers table ------------------------------------------
            print("Creating 'exam_answers' table if not exists...")
            conn.execute(text(
                """
                CREATE TABLE IF NOT EXISTS exam_answers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    submission_id INTEGER NOT NULL,
                    question_id INTEGER NOT NULL,
                    answer_json TEXT,
                    score_awarded FLOAT NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY (submission_id) REFERENCES exam_submissions (id) ON DELETE CASCADE,
                    FOREIGN KEY (question_id) REFERENCES exam_questions (id) ON DELETE CASCADE
                )
                """
            ))
            conn.execute(text(
                """
                CREATE INDEX IF NOT EXISTS ix_exam_answers_submission_id ON exam_answers (submission_id)
                """
            ))
            conn.execute(text(
                """
                CREATE INDEX IF NOT EXISTS ix_exam_answers_question_id ON exam_answers (question_id)
                """
            ))

            conn.commit()
        print("\nMigration completed successfully!\n")
        print("Created/ensured tables:")
        print("  - exams")
        print("  - exam_questions")
        print("  - exam_submissions")
        print("  - exam_answers")
        print("\nRun: python migrate/migrate_add_exams.py")


if __name__ == "__main__":
    migrate()
