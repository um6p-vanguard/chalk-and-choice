#!/usr/bin/env python3
"""
Script to reset proficiency test attempts for students.
Usage:
  python scripts/reset_proficiency_test.py --student-id 123
  python scripts/reset_proficiency_test.py --student-email john@example.com
  python scripts/reset_proficiency_test.py --all
  python scripts/reset_proficiency_test.py --attempt-id 456
  python scripts/reset_proficiency_test.py --remove-tags --student-id 123
"""

import sys
import os

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from app import app, db
from models import (
    ProficiencyTestAttempt, 
    ProficiencyExerciseSubmission,
    StudentProficiencyTag,
    Student
)


def reset_attempt(attempt_id, remove_tags=False):
    """Reset a specific proficiency test attempt."""
    attempt = ProficiencyTestAttempt.query.get(attempt_id)
    if not attempt:
        print(f"❌ Attempt ID {attempt_id} not found")
        return False
    
    student_id = attempt.student_id
    student_name = attempt.student.name
    
    # Delete submissions
    subs = ProficiencyExerciseSubmission.query.filter_by(attempt_id=attempt_id).all()
    for sub in subs:
        db.session.delete(sub)
    
    # Delete attempt
    db.session.delete(attempt)
    
    # Optionally remove proficiency tags
    if remove_tags:
        tags = StudentProficiencyTag.query.filter_by(student_id=student_id).all()
        for tag in tags:
            db.session.delete(tag)
        print(f"  🏷️  Removed {len(tags)} proficiency tag(s)")
    
    db.session.commit()
    print(f"✅ Reset attempt #{attempt_id} for {student_name} ({len(subs)} submissions deleted)")
    return True


def reset_student_attempts(student_id, remove_tags=False):
    """Reset all proficiency test attempts for a student."""
    student = Student.query.get(student_id)
    if not student:
        print(f"❌ Student ID {student_id} not found")
        return False
    
    attempts = ProficiencyTestAttempt.query.filter_by(student_id=student_id).all()
    if not attempts:
        print(f"ℹ️  No attempts found for {student.name}")
        return True
    
    total_subs = 0
    for attempt in attempts:
        subs = ProficiencyExerciseSubmission.query.filter_by(attempt_id=attempt.id).all()
        for sub in subs:
            db.session.delete(sub)
        total_subs += len(subs)
        db.session.delete(attempt)
    
    # Optionally remove proficiency tags
    if remove_tags:
        tags = StudentProficiencyTag.query.filter_by(student_id=student_id).all()
        for tag in tags:
            db.session.delete(tag)
        print(f"  🏷️  Removed {len(tags)} proficiency tag(s)")
    
    db.session.commit()
    print(f"✅ Reset {len(attempts)} attempt(s) for {student.name} ({total_subs} submissions deleted)")
    return True


def reset_all_attempts(remove_tags=False):
    """Reset all proficiency test attempts in the database."""
    if not confirm("⚠️  Reset ALL proficiency test attempts?"):
        print("Cancelled")
        return False
    
    attempts = ProficiencyTestAttempt.query.all()
    submissions = ProficiencyExerciseSubmission.query.all()
    
    for sub in submissions:
        db.session.delete(sub)
    
    for attempt in attempts:
        db.session.delete(attempt)
    
    # Optionally remove all proficiency tags
    if remove_tags:
        tags = StudentProficiencyTag.query.all()
        for tag in tags:
            db.session.delete(tag)
        print(f"  🏷️  Removed {len(tags)} proficiency tag(s)")
    
    db.session.commit()
    print(f"✅ Reset {len(attempts)} attempt(s) and {len(submissions)} submission(s)")
    return True


def confirm(message):
    """Ask for user confirmation."""
    response = input(f"{message} [y/N]: ").strip().lower()
    return response in ['y', 'yes']


def main():
    parser = argparse.ArgumentParser(
        description='Reset proficiency test attempts from database'
    )
    
    # Mutually exclusive group for selection
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--student-id',
        type=int,
        help='Reset all attempts for student by ID'
    )
    group.add_argument(
        '--student-email',
        type=str,
        help='Reset all attempts for student by email'
    )
    group.add_argument(
        '--attempt-id',
        type=int,
        help='Reset specific attempt by ID'
    )
    group.add_argument(
        '--all',
        action='store_true',
        help='Reset ALL proficiency test attempts (use with caution)'
    )
    
    parser.add_argument(
        '--remove-tags',
        action='store_true',
        help='Also remove proficiency tags earned by the student(s)'
    )
    
    parser.add_argument(
        '--list',
        action='store_true',
        help='List all attempts before resetting'
    )
    
    args = parser.parse_args()
    
    with app.app_context():
        # List mode
        if args.list:
            attempts = ProficiencyTestAttempt.query.order_by(
                ProficiencyTestAttempt.created_at.desc()
            ).all()
            
            if not attempts:
                print("No proficiency test attempts found.")
                return
            
            print(f"\n📋 Found {len(attempts)} proficiency test attempt(s):\n")
            for a in attempts:
                status = "✅ Submitted" if a.submitted else "⏳ In Progress"
                print(f"  ID: {a.id:4d} | {a.student.name:30s} | {status} | {a.created_at.strftime('%Y-%m-%d %H:%M')}")
            print()
            return
        
        # Reset operations
        if args.attempt_id:
            reset_attempt(args.attempt_id, remove_tags=args.remove_tags)
        
        elif args.student_id:
            reset_student_attempts(args.student_id, remove_tags=args.remove_tags)
        
        elif args.student_email:
            student = Student.query.filter_by(email=args.student_email).first()
            if not student:
                print(f"❌ Student with email '{args.student_email}' not found")
                return
            reset_student_attempts(student.id, remove_tags=args.remove_tags)
        
        elif args.all:
            reset_all_attempts(remove_tags=args.remove_tags)


if __name__ == '__main__':
    main()
