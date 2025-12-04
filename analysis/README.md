# 📊 Student Submission Analysis Platform

A web-based platform for mentors to easily view and analyze student exam submissions and performance.

## Features

### 🎯 Dashboard
- **Overview Statistics**: Total students, average score, highest/lowest scores
- **Student List**: Searchable and sortable table of all students
- **Performance Visualization**: Progress bars showing score percentages
- **Quick Access**: Direct links to detailed student views

### 👤 Student Detail View
- **Complete Submission Data**: All answers and grading information
- **Question Type Breakdown**: Organized by MCQ, Multi-select, Text, Tokens, and Code questions
- **Visual Indicators**: Color-coded cards (green for correct, red for incorrect, yellow for partial)
- **Manual Review Flags**: Highlights questions that need mentor review
- **Performance Summary**: Statistics by question type

### 📈 Questions Analysis
- **Question Performance**: Success rate for each question across all students
- **Problem Identification**: Questions sorted by success rate to highlight difficult areas
- **Performance Categories**: Visual categorization (High ≥80%, Medium 50-79%, Low <50%)
- **Question Type Insights**: See which types of questions students struggle with

## Installation

1. **Navigate to the analysis folder**:
   ```bash
   cd analysis
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Platform

1. **Start the Flask application**:
   ```bash
   python app.py
   ```

2. **Access the platform**:
   - Open your browser and go to: `http://localhost:5001`
   - Or from another device on the same network: `http://your-ip:5001`

3. **Stop the server**:
   - Press `Ctrl+C` in the terminal

## Usage Guide

### Dashboard View
- **Search**: Use the search box to filter students by name
- **Sort**: Choose from different sorting options (score, name)
- **View Details**: Click "View Details" button for any student

### Student Detail View
- Review all answers organized by question type
- Check scores for each question
- Identify questions flagged for manual review
- See performance breakdown by question type

### Questions Analysis View
- Identify problematic questions with low success rates
- Understand which question types are most challenging
- Plan targeted review sessions based on data

## API Endpoints

The platform also provides JSON API endpoints:

- `GET /api/submissions` - All student submissions
- `GET /api/student/<name>` - Specific student data
- `GET /api/stats` - Summary statistics

Example:
```bash
curl http://localhost:5001/api/stats
```

## File Structure

```
analysis/
├── app.py                      # Flask application
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── templates/                  # HTML templates
│   ├── base.html              # Base template
│   ├── index.html             # Dashboard
│   ├── student_detail.html    # Student view
│   └── questions_analysis.html # Questions view
├── static/                     # Static assets
│   └── style.css              # Styling
└── student_submission/         # JSON data files
    ├── Student Name.json
    └── ...
```

## Data Format

The platform expects JSON files in `student_submission/` with this structure:
```json
{
  "student": {
    "id": 1,
    "name": "Student Name"
  },
  "exam": {
    "code": "exam123",
    "title": "Exam Title"
  },
  "score": 15.0,
  "max_score": 24.0,
  "status": "submitted",
  "answers": { ... },
  "grading": [ ... ]
}
```

## Troubleshooting

### Port Already in Use
If port 5001 is already in use, you can change it in `app.py`:
```python
app.run(debug=True, port=5002, host='0.0.0.0')
```

### Templates Not Found
Make sure you're running the app from the `analysis` directory.

### No Data Showing
Verify that JSON files exist in `student_submission/` folder.

## Security Note

This platform is designed for local/internal use. If deploying to production:
- Set `debug=False` in `app.py`
- Add authentication
- Use a production WSGI server (e.g., Gunicorn)
- Configure proper firewall rules

## Future Enhancements

Potential features to add:
- Export data to CSV/Excel
- Filtering by score range
- Detailed analytics charts
- Comparison between students
- Comment/notes system for mentors
- Email notifications for manual reviews

## Support

For issues or questions, please contact the development team.
