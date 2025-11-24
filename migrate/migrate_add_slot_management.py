#!/usr/bin/env python3
"""
Migration: Add mentor slot management tables

Creates:
- mentor_slots: Availability slots created by mentors
- slot_bookings: Student bookings for mentor slots
"""

import sys
import os

# Add parent directory to path to import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models import MentorSlot, SlotBooking

def migrate():
    with app.app_context():
        print("Creating mentor slot management tables...")
        
        # Create tables
        db.create_all()
        
        print("✓ Tables created successfully!")
        print("\nNew tables:")
        print("  - mentor_slots: Availability slots created by mentors")
        print("  - slot_bookings: Student bookings for mentor slots")
        print("\nMigration complete!")

if __name__ == "__main__":
    migrate()
