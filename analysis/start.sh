#!/bin/bash

# Student Submission Analysis Platform - Quick Start Script

echo "🚀 Starting Student Submission Analysis Platform..."
echo ""

# Check if we're in the right directory
if [ ! -f "app.py" ]; then
    echo "❌ Error: Please run this script from the analysis directory"
    exit 1
fi

if [ ! -f ".venv" ]; then
    python3 -m venv .venv
    echo "✅ Virtual environment created using python3"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -q -r requirements.txt

# Check if student_submission folder exists
if [ ! -d "student_submission" ]; then
    echo "⚠️  Warning: student_submission folder not found!"
    echo "   Please ensure JSON files are in the student_submission directory"
fi

# Start the Flask app
echo ""
echo "✅ Setup complete!"
echo ""
echo "🌐 Starting the web server..."
echo "   Access the platform at: http://localhost:5001"
echo ""
echo "   Press Ctrl+C to stop the server"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python app.py
