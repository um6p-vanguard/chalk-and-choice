#!/usr/bin/env python3
import os
import sqlite3
import sys

def _column_exists(conn, table, column):
    cur = conn.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())

def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CLASSVOTE_DB", "classvote.db")
    if not os.path.exists(db_path):
        raise SystemExit(f"Database not found: {db_path}")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS student_log_sessions (
                id INTEGER PRIMARY KEY,
                student_id INTEGER NOT NULL,
                started_at DATETIME NOT NULL,
                last_activity_at DATETIME NOT NULL,
                ended_at DATETIME NOT NULL,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_sessions_student ON student_log_sessions(student_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_sessions_last_activity ON student_log_sessions(last_activity_at)")
        if not _column_exists(conn, "leaderboards", "params_json"):
            conn.execute("ALTER TABLE leaderboards ADD COLUMN params_json TEXT")
        conn.commit()
        print("Migrations applied: student_log_sessions + leaderboards.params_json")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
