#!/usr/bin/env python3
"""
Analyze database performance during load tests
"""

import sqlite3
import json
import sys
import os
from datetime import datetime

# Add parent directory to path to import app and models
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from models import db, Student, Notebook, Vote, Form, FormResponse


def analyze_database():
    """Analyze current database state and performance"""
    app = create_app()
    
    with app.app_context():
        print("=" * 60)
        print("DATABASE ANALYSIS")
        print("=" * 60)
        print()
        
        # Count records
        print("📊 Record Counts:")
        print(f"  Students: {Student.query.count()}")
        print(f"  Notebooks: {Notebook.query.count()}")
        print(f"  Votes: {Vote.query.count()}")
        print(f"  Forms: {Form.query.count()}")
        print(f"  Form Responses: {FormResponse.query.count()}")
        print()
        
        # Notebook statistics
        notebooks = Notebook.query.all()
        if notebooks:
            total_size = 0
            max_size = 0
            max_nb = None
            
            for nb in notebooks:
                size = len(json.dumps(nb.content_json))
                total_size += size
                if size > max_size:
                    max_size = size
                    max_nb = nb
            
            avg_size = total_size / len(notebooks)
            
            print("📓 Notebook Statistics:")
            print(f"  Total notebooks: {len(notebooks)}")
            print(f"  Average size: {avg_size/1024:.2f} KB")
            print(f"  Largest notebook: {max_size/1024:.2f} KB (ID: {max_nb.id})")
            print(f"  Total storage: {total_size/1024/1024:.2f} MB")
            print()
            
            # Notebooks per student
            from collections import Counter
            student_counts = Counter(nb.student_id for nb in notebooks)
            if student_counts:
                avg_per_student = sum(student_counts.values()) / len(student_counts)
                max_student = max(student_counts.items(), key=lambda x: x[1])
                print(f"  Notebooks per student (avg): {avg_per_student:.1f}")
                print(f"  Max notebooks (student {max_student[0]}): {max_student[1]}")
                print()
        
        # Recent activity
        print("⏰ Recent Activity (last 24 hours):")
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(hours=24)
        
        recent_notebooks = Notebook.query.filter(Notebook.created_at >= cutoff).count()
        recent_updates = Notebook.query.filter(Notebook.updated_at >= cutoff).count()
        
        print(f"  New notebooks: {recent_notebooks}")
        print(f"  Notebook updates: {recent_updates}")
        print()
        
        # Database file size
        import os
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if os.path.exists(db_path):
            db_size = os.path.getsize(db_path)
            print(f"💾 Database File:")
            print(f"  Path: {db_path}")
            print(f"  Size: {db_size/1024/1024:.2f} MB")
            print()
        
        # Check for potential issues
        print("🔍 Potential Issues:")
        issues = []
        
        if Notebook.query.count() > 10000:
            issues.append("⚠️  Large number of notebooks (>10k) - consider archiving old ones")
        
        if total_size / (1024 * 1024) > 500:  # 500 MB
            issues.append("⚠️  Notebook storage exceeds 500MB - consider cleanup or optimization")
        
        # Check for orphaned notebooks (student deleted but notebooks remain)
        all_student_ids = {s.id for s in Student.query.all()}
        orphaned = sum(1 for nb in notebooks if nb.student_id not in all_student_ids)
        if orphaned > 0:
            issues.append(f"⚠️  {orphaned} orphaned notebooks (student no longer exists)")
        
        if not issues:
            print("  ✅ No issues detected")
        else:
            for issue in issues:
                print(f"  {issue}")
        
        print()
        print("=" * 60)


def analyze_performance():
    """Analyze database performance metrics"""
    app = create_app()
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    
    print("\n" + "=" * 60)
    print("PERFORMANCE ANALYSIS")
    print("=" * 60)
    print()
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check indexes
    print("📑 Indexes:")
    cursor.execute("""
        SELECT name, tbl_name 
        FROM sqlite_master 
        WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
        ORDER BY tbl_name
    """)
    indexes = cursor.fetchall()
    
    index_by_table = {}
    for idx_name, tbl_name in indexes:
        if tbl_name not in index_by_table:
            index_by_table[tbl_name] = []
        index_by_table[tbl_name].append(idx_name)
    
    for table, indexes in sorted(index_by_table.items()):
        print(f"  {table}: {', '.join(indexes)}")
    print()
    
    # Table sizes
    print("📊 Table Sizes:")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [row[0] for row in cursor.fetchall()]
    
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  {table}: {count} rows")
    print()
    
    # Fragmentation
    print("🔧 Database Health:")
    cursor.execute("PRAGMA integrity_check")
    result = cursor.fetchone()[0]
    print(f"  Integrity: {result}")
    
    cursor.execute("PRAGMA page_count")
    page_count = cursor.fetchone()[0]
    cursor.execute("PRAGMA page_size")
    page_size = cursor.fetchone()[0]
    cursor.execute("PRAGMA freelist_count")
    freelist = cursor.fetchone()[0]
    
    total_pages = page_count
    used_pages = page_count - freelist
    fragmentation = (freelist / page_count * 100) if page_count > 0 else 0
    
    print(f"  Pages: {used_pages}/{total_pages} used")
    print(f"  Fragmentation: {fragmentation:.1f}%")
    
    if fragmentation > 20:
        print(f"  ⚠️  High fragmentation - consider running VACUUM")
    print()
    
    conn.close()
    
    print("=" * 60)


def cleanup_test_data():
    """Clean up test data"""
    app = create_app()
    
    with app.app_context():
        print("\n🧹 Cleanup Test Data")
        print("=" * 60)
        
        # Count test students
        test_students = Student.query.filter(Student.email.like('%@test.edu')).all()
        
        if not test_students:
            print("No test students found.")
            return
        
        print(f"Found {len(test_students)} test students")
        
        response = input("Delete test students and their notebooks? (yes/no): ")
        
        if response.lower() == 'yes':
            # Delete notebooks first (cascade should handle this, but being explicit)
            for student in test_students:
                Notebook.query.filter_by(student_id=student.id).delete()
            
            # Delete students
            Student.query.filter(Student.email.like('%@test.edu')).delete()
            
            db.session.commit()
            print(f"✅ Deleted {len(test_students)} test students and their data")
        else:
            print("Cleanup cancelled")


def vacuum_database():
    """Run VACUUM to optimize database"""
    app = create_app()
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    
    print("\n🔧 Database Optimization")
    print("=" * 60)
    print("Running VACUUM (this may take a while)...")
    
    import os
    size_before = os.path.getsize(db_path)
    
    conn = sqlite3.connect(db_path)
    conn.execute("VACUUM")
    conn.close()
    
    size_after = os.path.getsize(db_path)
    saved = size_before - size_after
    
    print(f"✅ VACUUM complete")
    print(f"  Size before: {size_before/1024/1024:.2f} MB")
    print(f"  Size after: {size_after/1024/1024:.2f} MB")
    print(f"  Space saved: {saved/1024/1024:.2f} MB ({saved/size_before*100:.1f}%)")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'analyze':
            analyze_database()
            analyze_performance()
        elif cmd == 'cleanup':
            cleanup_test_data()
        elif cmd == 'vacuum':
            vacuum_database()
        elif cmd == 'all':
            analyze_database()
            analyze_performance()
        else:
            print(f"Unknown command: {cmd}")
            print("Usage: python db_analysis.py [analyze|cleanup|vacuum|all]")
    else:
        analyze_database()
        analyze_performance()
