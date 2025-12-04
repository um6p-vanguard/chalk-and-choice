#!/usr/bin/env python3
"""
Quick launcher for the Student Submission Analysis Platform
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    print("🚀 Starting Student Submission Analysis Platform...")
    print()
    
    # Check if we're in the right directory
    if not Path("app.py").exists():
        print("❌ Error: Please run this script from the analysis directory")
        sys.exit(1)
    
    # Check if student_submission folder exists
    if not Path("student_submission").exists():
        print("⚠️  Warning: student_submission folder not found!")
        print("   Please ensure JSON files are in the student_submission directory")
        print()
    
    # Check for required dependencies
    try:
        import flask
        print("✅ Flask is installed")
    except ImportError:
        print("📥 Installing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "-r", "requirements.txt"])
        print("✅ Dependencies installed")
    
    print()
    print("🌐 Starting the web server...")
    print("   Access the platform at: http://localhost:5001")
    print()
    print("   Press Ctrl+C to stop the server")
    print()
    print("━" * 60)
    print()
    
    # Start the Flask app
    try:
        subprocess.run([sys.executable, "app.py"])
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped. Goodbye!")

if __name__ == "__main__":
    main()
