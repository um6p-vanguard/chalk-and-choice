"""
Analysis Platform for Student Submissions
A Flask web application for mentors to view and analyze student exam results.
"""

from flask import Flask, render_template, jsonify
import json
import os
from pathlib import Path
from datetime import datetime

app = Flask(__name__)

# Path to student submissions
SUBMISSION_DIR = Path(__file__).parent / "student_submission"


def load_all_submissions():
    """Load all student submission JSON files."""
    submissions = []
    
    if not SUBMISSION_DIR.exists():
        return submissions
    
    for json_file in SUBMISSION_DIR.glob("*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                data['filename'] = json_file.stem
                submissions.append(data)
        except Exception as e:
            print(f"Error loading {json_file}: {e}")
    
    return submissions


def load_submission(student_name):
    """Load a specific student's submission."""
    file_path = SUBMISSION_DIR / f"{student_name}.json"
    
    if not file_path.exists():
        return None
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            data['filename'] = student_name
            return data
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return None


def get_summary_stats(submissions):
    """Calculate summary statistics from all submissions."""
    if not submissions:
        return {}
    
    total_students = len(submissions)
    scores = [s.get('score', 0) for s in submissions]
    max_scores = [s.get('max_score', 0) for s in submissions]
    
    avg_score = sum(scores) / total_students if total_students > 0 else 0
    avg_max = max_scores[0] if max_scores else 0
    
    # Count question types
    question_types = {}
    manual_review_count = 0
    
    for sub in submissions:
        for grade in sub.get('grading', []):
            q_type = grade.get('type', 'unknown')
            question_types[q_type] = question_types.get(q_type, 0) + 1
            if grade.get('manual_review', False):
                manual_review_count += 1
    
    return {
        'total_students': total_students,
        'average_score': round(avg_score, 2),
        'max_score': avg_max,
        'highest_score': max(scores) if scores else 0,
        'lowest_score': min(scores) if scores else 0,
        'question_types': question_types,
        'manual_review_needed': manual_review_count
    }


def get_question_analysis(submissions):
    """Analyze performance by question across all students."""
    question_stats = {}
    
    for sub in submissions:
        for grade in sub.get('grading', []):
            q_id = grade.get('question_id')
            if not q_id:
                continue
            
            if q_id not in question_stats:
                question_stats[q_id] = {
                    'question_id': q_id,
                    'type': grade.get('type'),
                    'total_points': 0,
                    'earned_points': 0,
                    'attempts': 0,
                    'manual_review': grade.get('manual_review', False)
                }
            
            question_stats[q_id]['total_points'] += grade.get('points', 0)
            question_stats[q_id]['earned_points'] += grade.get('earned', 0)
            question_stats[q_id]['attempts'] += 1
    
    # Calculate success rate
    for q_id, stats in question_stats.items():
        if stats['total_points'] > 0:
            stats['success_rate'] = round(
                (stats['earned_points'] / stats['total_points']) * 100, 2
            )
        else:
            stats['success_rate'] = 0
    
    return list(question_stats.values())


@app.route('/')
def index():
    """Main dashboard showing overview of all submissions."""
    submissions = load_all_submissions()
    submissions.sort(key=lambda x: x.get('score', 0), reverse=True)
    
    stats = get_summary_stats(submissions)
    
    return render_template('index.html', 
                         submissions=submissions, 
                         stats=stats,
                         exam_title=submissions[0].get('exam', {}).get('title', 'Exam') if submissions else 'Exam')


@app.route('/student/<student_name>')
def student_detail(student_name):
    """Detailed view of a specific student's submission."""
    submission = load_submission(student_name)
    
    if not submission:
        return "Student not found", 404
    
    # Organize grading by type
    grading_by_type = {}
    for grade in submission.get('grading', []):
        q_type = grade.get('type', 'unknown')
        if q_type not in grading_by_type:
            grading_by_type[q_type] = []
        
        # Add the answer to the grade info
        q_id = grade.get('question_id')
        grade['answer'] = submission.get('answers', {}).get(q_id, 'No answer')
        grading_by_type[q_type].append(grade)
    
    return render_template('student_detail.html', 
                         submission=submission,
                         grading_by_type=grading_by_type)


@app.route('/questions')
def questions_analysis():
    """Analysis view showing performance by question."""
    submissions = load_all_submissions()
    question_stats = get_question_analysis(submissions)
    
    # Sort by success rate (lowest first to highlight problem areas)
    question_stats.sort(key=lambda x: x['success_rate'])
    
    return render_template('questions_analysis.html', 
                         questions=question_stats,
                         total_students=len(submissions))


@app.route('/api/submissions')
def api_submissions():
    """API endpoint to get all submissions as JSON."""
    submissions = load_all_submissions()
    return jsonify(submissions)


@app.route('/api/student/<student_name>')
def api_student(student_name):
    """API endpoint to get a specific student's submission."""
    submission = load_submission(student_name)
    if not submission:
        return jsonify({'error': 'Student not found'}), 404
    return jsonify(submission)


@app.route('/api/stats')
def api_stats():
    """API endpoint to get summary statistics."""
    submissions = load_all_submissions()
    stats = get_summary_stats(submissions)
    return jsonify(stats)


if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
