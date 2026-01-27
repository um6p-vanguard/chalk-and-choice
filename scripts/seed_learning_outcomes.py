#!/usr/bin/env python3
"""
Seed learning outcomes based on the comprehensive curriculum.
Run this script to populate the database with the 5 domains and their specific outcomes.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models import LearningOutcome

# Comprehensive learning outcomes based on curriculum
LEARNING_OUTCOMES = [
    # Domain 1: Programming Fundamentals & Python Proficiency
    {
        "tag_name": "computing_context",
        "display_name": "Computing Context",
        "description": "Understanding the history and applications of computing",
        "icon_emoji": "🖥️",
        "domain": "fundamentals",
        "domain_display": "Programming Fundamentals & Python Proficiency",
        "difficulty_level": 1,
        "week_number": 1,
        "prerequisites": [],
        "exercise_count": 2,
        "duration_minutes": 10,
        "cooldown_hours": 12,
        "passing_threshold": 0.75,
        "display_order": 10,
    },
    {
        "tag_name": "core_syntax",
        "display_name": "Core Python Syntax",
        "description": "Mastery of basic Python syntax, variables, data types, and Input/Output operations",
        "icon_emoji": "📝",
        "domain": "fundamentals",
        "domain_display": "Programming Fundamentals & Python Proficiency",
        "difficulty_level": 1,
        "week_number": 2,
        "prerequisites": ["computing_context"],
        "exercise_count": 3,
        "duration_minutes": 20,
        "cooldown_hours": 24,
        "passing_threshold": 0.80,
        "display_order": 20,
    },
    {
        "tag_name": "control_flow",
        "display_name": "Control Flow",
        "description": "Ability to implement logic using conditionals (if statements) and loops (for/while)",
        "icon_emoji": "🔀",
        "domain": "fundamentals",
        "domain_display": "Programming Fundamentals & Python Proficiency",
        "difficulty_level": 1,
        "week_number": 3,
        "prerequisites": ["core_syntax"],
        "exercise_count": 3,
        "duration_minutes": 20,
        "cooldown_hours": 24,
        "passing_threshold": 0.80,
        "display_order": 30,
    },
    {
        "tag_name": "file_io",
        "display_name": "File I/O",
        "description": "Competence in safely reading from and writing to files",
        "icon_emoji": "📁",
        "domain": "fundamentals",
        "domain_display": "Programming Fundamentals & Python Proficiency",
        "difficulty_level": 2,
        "week_number": 10,
        "prerequisites": ["core_syntax", "control_flow"],
        "exercise_count": 2,
        "duration_minutes": 15,
        "cooldown_hours": 24,
        "passing_threshold": 0.75,
        "display_order": 40,
    },
    
    # Domain 2: Data Structures & Modular Design
    {
        "tag_name": "functions",
        "display_name": "Functions & Modular Code",
        "description": "Ability to define functions, manage variable scope, and understand the basics of modular code",
        "icon_emoji": "⚙️",
        "domain": "data_structures",
        "domain_display": "Data Structures & Modular Design",
        "difficulty_level": 1,
        "week_number": 4,
        "prerequisites": ["core_syntax", "control_flow"],
        "exercise_count": 3,
        "duration_minutes": 20,
        "cooldown_hours": 24,
        "passing_threshold": 0.80,
        "display_order": 100,
    },
    {
        "tag_name": "lists_basic",
        "display_name": "Lists (Basic)",
        "description": "Working with lists: indexing, slicing, basic operations, and iteration",
        "icon_emoji": "📋",
        "domain": "data_structures",
        "domain_display": "Data Structures & Modular Design",
        "difficulty_level": 1,
        "week_number": 5,
        "prerequisites": ["functions"],
        "exercise_count": 3,
        "duration_minutes": 20,
        "cooldown_hours": 24,
        "passing_threshold": 0.80,
        "display_order": 110,
    },
    {
        "tag_name": "lists_advanced",
        "display_name": "Lists (Advanced)",
        "description": "Advanced list operations and list comprehensions",
        "icon_emoji": "📊",
        "domain": "data_structures",
        "domain_display": "Data Structures & Modular Design",
        "difficulty_level": 2,
        "week_number": 5,
        "prerequisites": ["lists_basic"],
        "exercise_count": 3,
        "duration_minutes": 20,
        "cooldown_hours": 24,
        "passing_threshold": 0.75,
        "display_order": 120,
    },
    {
        "tag_name": "dictionaries_basic",
        "display_name": "Dictionaries & Sets",
        "description": "Understanding key-value mappings, unique collections, and their specific applications",
        "icon_emoji": "🗂️",
        "domain": "data_structures",
        "domain_display": "Data Structures & Modular Design",
        "difficulty_level": 1,
        "week_number": 6,
        "prerequisites": ["lists_basic"],
        "exercise_count": 3,
        "duration_minutes": 20,
        "cooldown_hours": 24,
        "passing_threshold": 0.80,
        "display_order": 130,
    },
    {
        "tag_name": "oop_basics",
        "display_name": "Object-Oriented Programming",
        "description": "Understanding classes, objects, and basic OOP principles",
        "icon_emoji": "🎯",
        "domain": "data_structures",
        "domain_display": "Data Structures & Modular Design",
        "difficulty_level": 2,
        "week_number": 11,
        "prerequisites": ["functions", "dictionaries_basic"],
        "exercise_count": 3,
        "duration_minutes": 25,
        "cooldown_hours": 48,
        "passing_threshold": 0.75,
        "display_order": 140,
    },
    
    # Domain 3: Recursion & Complexity Analysis
    {
        "tag_name": "recursion_logic",
        "display_name": "Recursive Logic",
        "description": "Understanding recursion as a function that calls itself to solve smaller instances of a problem",
        "icon_emoji": "🔁",
        "domain": "recursion",
        "domain_display": "Recursion & Complexity Analysis",
        "difficulty_level": 2,
        "week_number": 7,
        "prerequisites": ["functions", "lists_basic"],
        "exercise_count": 3,
        "duration_minutes": 25,
        "cooldown_hours": 48,
        "passing_threshold": 0.75,
        "display_order": 200,
    },
    {
        "tag_name": "recursion_execution",
        "display_name": "Recursion Execution & Call Stack",
        "description": "Visualizing the function call stack to understand runtime behavior and stack overflow risks",
        "icon_emoji": "📚",
        "domain": "recursion",
        "domain_display": "Recursion & Complexity Analysis",
        "difficulty_level": 2,
        "week_number": 7,
        "prerequisites": ["recursion_logic"],
        "exercise_count": 2,
        "duration_minutes": 20,
        "cooldown_hours": 48,
        "passing_threshold": 0.75,
        "display_order": 210,
    },
    {
        "tag_name": "recursion_analysis",
        "display_name": "Algorithm Analysis & Recurrence Relations",
        "description": "Deriving recurrence relations to estimate algorithm cost (e.g., T(n) = 2T(n-1) + 1)",
        "icon_emoji": "📐",
        "domain": "recursion",
        "domain_display": "Recursion & Complexity Analysis",
        "difficulty_level": 3,
        "week_number": 7,
        "prerequisites": ["recursion_execution"],
        "exercise_count": 2,
        "duration_minutes": 20,
        "cooldown_hours": 48,
        "passing_threshold": 0.70,
        "display_order": 220,
    },
    {
        "tag_name": "recursion_patterns",
        "display_name": "Classic Recursive Patterns",
        "description": "Implementing standard recursive algorithms: Factorial, GCD (Euclid), Fibonacci, Towers of Hanoi",
        "icon_emoji": "🎲",
        "domain": "recursion",
        "domain_display": "Recursion & Complexity Analysis",
        "difficulty_level": 2,
        "week_number": 7,
        "prerequisites": ["recursion_logic"],
        "exercise_count": 4,
        "duration_minutes": 30,
        "cooldown_hours": 48,
        "passing_threshold": 0.75,
        "display_order": 230,
    },
    {
        "tag_name": "recursion_optimization",
        "display_name": "Recursion Optimization & Memoization",
        "description": "Recognizing inefficient recursion and applying memoization to reduce complexity",
        "icon_emoji": "⚡",
        "domain": "recursion",
        "domain_display": "Recursion & Complexity Analysis",
        "difficulty_level": 3,
        "week_number": 7,
        "prerequisites": ["recursion_patterns", "dictionaries_basic"],
        "exercise_count": 3,
        "duration_minutes": 25,
        "cooldown_hours": 48,
        "passing_threshold": 0.70,
        "display_order": 240,
    },
    
    # Domain 4: Algorithms & Computational Thinking
    {
        "tag_name": "algorithms_sorting",
        "display_name": "Sorting Algorithms",
        "description": "Implementing basic sorting algorithms like Bubble Sort, Selection Sort",
        "icon_emoji": "🔢",
        "domain": "algorithms",
        "domain_display": "Algorithms & Computational Thinking",
        "difficulty_level": 2,
        "week_number": 8,
        "prerequisites": ["lists_advanced", "control_flow"],
        "exercise_count": 3,
        "duration_minutes": 25,
        "cooldown_hours": 48,
        "passing_threshold": 0.75,
        "display_order": 300,
    },
    {
        "tag_name": "algorithms_searching",
        "display_name": "Searching Algorithms",
        "description": "Implementing various searching techniques (linear, binary)",
        "icon_emoji": "🔍",
        "domain": "algorithms",
        "domain_display": "Algorithms & Computational Thinking",
        "difficulty_level": 2,
        "week_number": 8,
        "prerequisites": ["lists_advanced", "control_flow"],
        "exercise_count": 3,
        "duration_minutes": 20,
        "cooldown_hours": 48,
        "passing_threshold": 0.75,
        "display_order": 310,
    },
    {
        "tag_name": "pattern_recognition",
        "display_name": "Pattern Recognition",
        "description": "Solving 'tiny cases' by hand to identify hidden rules or invariants",
        "icon_emoji": "🔎",
        "domain": "algorithms",
        "domain_display": "Algorithms & Computational Thinking",
        "difficulty_level": 2,
        "week_number": 9,
        "prerequisites": ["control_flow", "lists_basic"],
        "exercise_count": 2,
        "duration_minutes": 20,
        "cooldown_hours": 24,
        "passing_threshold": 0.75,
        "display_order": 320,
    },
    {
        "tag_name": "problem_decomposition",
        "display_name": "Problem Decomposition",
        "description": "Breaking complex problems into manageable sub-parts (prefix sums, meet-in-the-middle)",
        "icon_emoji": "🧩",
        "domain": "algorithms",
        "domain_display": "Algorithms & Computational Thinking",
        "difficulty_level": 3,
        "week_number": 9,
        "prerequisites": ["pattern_recognition", "lists_advanced"],
        "exercise_count": 3,
        "duration_minutes": 30,
        "cooldown_hours": 48,
        "passing_threshold": 0.70,
        "display_order": 330,
    },
    {
        "tag_name": "abstraction",
        "display_name": "Abstraction & Modeling",
        "description": "Modeling messy real-world problems into clean mathematical models",
        "icon_emoji": "🎨",
        "domain": "algorithms",
        "domain_display": "Algorithms & Computational Thinking",
        "difficulty_level": 3,
        "week_number": 9,
        "prerequisites": ["pattern_recognition", "functions"],
        "exercise_count": 2,
        "duration_minutes": 25,
        "cooldown_hours": 48,
        "passing_threshold": 0.70,
        "display_order": 340,
    },
    {
        "tag_name": "algorithm_design_workflow",
        "display_name": "Algorithm Design Workflow",
        "description": "Following structured problem-solving: tiny case → naive algorithm → identify bottleneck → optimize",
        "icon_emoji": "🛠️",
        "domain": "algorithms",
        "domain_display": "Algorithms & Computational Thinking",
        "difficulty_level": 3,
        "week_number": 9,
        "prerequisites": ["abstraction", "problem_decomposition"],
        "exercise_count": 3,
        "duration_minutes": 30,
        "cooldown_hours": 48,
        "passing_threshold": 0.70,
        "display_order": 350,
    },
    
    # Domain 5: Computer Systems
    {
        "tag_name": "systems_overview",
        "display_name": "Computer Systems Overview",
        "description": "Understanding the relationship between hardware, software, and operating systems",
        "icon_emoji": "💻",
        "domain": "systems",
        "domain_display": "Computer Systems",
        "difficulty_level": 1,
        "week_number": 12,
        "prerequisites": ["computing_context"],
        "exercise_count": 2,
        "duration_minutes": 15,
        "cooldown_hours": 24,
        "passing_threshold": 0.75,
        "display_order": 400,
    },
]

def seed_learning_outcomes():
    """Populate database with learning outcomes."""
    with app.app_context():
        print("🌱 Seeding learning outcomes...")
        
        # Check if outcomes already exist
        existing_count = LearningOutcome.query.count()
        if existing_count > 0:
            response = input(f"⚠️  Found {existing_count} existing learning outcomes. Delete and recreate? (yes/no): ")
            if response.lower() != 'yes':
                print("❌ Aborted.")
                return
            
            # Delete existing outcomes
            LearningOutcome.query.delete()
            db.session.commit()
            print(f"🗑️  Deleted {existing_count} existing outcomes.")
        
        # Insert new outcomes
        created_count = 0
        for outcome_data in LEARNING_OUTCOMES:
            # Extract prerequisites before creating the object
            prerequisites = outcome_data.pop('prerequisites', [])
            outcome = LearningOutcome(**outcome_data)
            outcome.prerequisites_json = prerequisites
            db.session.add(outcome)
            created_count += 1
        
        db.session.commit()
        print(f"✅ Successfully created {created_count} learning outcomes!")
        
        # Print summary by domain
        print("\n📊 Summary by domain:")
        domains = db.session.query(
            LearningOutcome.domain_display,
            db.func.count(LearningOutcome.id)
        ).group_by(LearningOutcome.domain_display).all()
        
        for domain_name, count in domains:
            print(f"   - {domain_name}: {count} outcomes")
        
        print("\n🎯 Students can now take targeted proficiency tests!")
        print("   Run the app and navigate to /proficiency/outcomes (admin) or /student/proficiency/outcomes (student)")

if __name__ == "__main__":
    seed_learning_outcomes()
