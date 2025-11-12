#!/bin/bash
# Quick start script for load testing

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the project root (parent of testing/)
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Chalk-and-Choice Load Testing Setup"
echo "========================================"
echo "Project root: $PROJECT_ROOT"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Check if virtual environment exists
if [ ! -d "venv" ] && [ ! -d ".venv" ]; then
    echo "   No virtual environment detected."
    echo "   Run: python -m venv venv && source venv/bin/activate"
    exit 1
fi

# Install test dependencies
echo "📦 Installing test dependencies..."
pip install -q -r testing/requirements-test.txt

# Check if app is running
echo ""
echo "🔍 Checking if application is running..."
if ! curl -s http://localhost:5000 > /dev/null; then
    echo "❌ Application is not running on http://localhost:5000"
    echo ""
    echo "Start your application first:"
    echo "   python app.py"
    echo ""
    exit 1
fi

echo "✅ Application is running"
echo ""

# Ask about test students
read -p "Create/update 300 test students? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Creating test students..."
    python testing/seed_test_students.py 300
    echo ""
fi

# Choose test type
echo "Select test scenario:"
echo "  1) Full test (login + notebooks + updates)"
echo "  2) Notebooks only"
echo "  3) Login only"
echo "  4) Custom"
echo ""
read -p "Enter choice (1-4): " choice

case $choice in
    1)
        SCENARIO="full"
        STUDENTS=100
        BATCH=20
        ;;
    2)
        SCENARIO="notebooks"
        STUDENTS=300
        BATCH=70
        ;;
    3)
        SCENARIO="login"
        STUDENTS=100
        BATCH=30
        ;;
    4)
        read -p "Number of students (default 100): " STUDENTS
        STUDENTS=${STUDENTS:-100}
        read -p "Batch size (default 20): " BATCH
        BATCH=${BATCH:-20}
        read -p "Scenario (full/notebooks/login, default full): " SCENARIO
        SCENARIO=${SCENARIO:-full}
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "Starting load test..."
echo "   Students: $STUDENTS"
echo "   Batch: $BATCH"
echo "   Scenario: $SCENARIO"
echo ""

python testing/test_load.py \
    --url http://localhost:5000 \
    --students $STUDENTS \
    --batch-size $BATCH \
    --scenario $SCENARIO

echo ""
echo "✅ Load test completed!"
echo ""
echo "Tips:"
echo "   - Check testing/LOAD_TESTING.md for detailed analysis"
echo "   - Check your database size: ls -lh *.db"
echo "   - Monitor server resources during testing"
echo ""
