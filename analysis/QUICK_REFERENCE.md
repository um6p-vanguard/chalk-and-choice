# 🚀 Quick Reference - Analysis Platform

## Start the Platform

```bash
cd analysis
python start.py
```

Then open: **http://localhost:5001**

## Platform Navigation

| Page | URL | Purpose |
|------|-----|---------|
| Dashboard | `/` | Overview of all students |
| Student Detail | `/student/<name>` | Individual student analysis |
| Questions Analysis | `/questions` | Question performance metrics |

## API Endpoints

```bash
# Get all submissions
curl http://localhost:5001/api/submissions

# Get specific student
curl http://localhost:5001/api/student/Adam%20Nahi

# Get statistics
curl http://localhost:5001/api/stats
```

## Dashboard Features

- 🔍 **Search**: Type student name in search box
- 🔄 **Sort**: Use dropdown to sort by score/name
- 📊 **Stats**: View cards at top for overview
- 👤 **Details**: Click "View Details" button

## Understanding the Data

### Question Types
- **MCQ**: Multiple choice (single answer)
- **Multi**: Multiple select (multiple answers)
- **Text**: Free text response
- **Tokens**: Specific keywords/phrases
- **Code**: Programming questions

### Color Codes
- 🟢 **Green**: Fully correct answer
- 🔴 **Red**: Incorrect answer
- 🟡 **Yellow**: Partially correct
- ⚠️ **Orange Banner**: Needs manual review

### Score Display
- Format: `earned / total` (e.g., 15 / 24)
- Percentage shown as progress bar
- Final score in student header

## Common Tasks

### Find Struggling Students
1. Go to Dashboard
2. Sort by "Score (Lowest First)"
3. Review bottom students

### Identify Difficult Questions
1. Go to Questions Analysis
2. Look at bottom of list (lowest success rate)
3. Note question IDs in red

### Review Code Submissions
1. Open student detail
2. Scroll to "CODE Questions" section
3. Review flagged items

### Manual Review Queue
1. Check dashboard stat card
2. Visit each student with manual review items
3. Look for orange "⚠️ Manual Review" banners

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+F` | Search (browser) |
| `Ctrl+R` | Refresh page |
| `Ctrl+C` | Stop server (in terminal) |
| `Alt+←` | Back to previous page |

## File Locations

```
analysis/
├── student_submission/     # JSON data files
├── templates/             # HTML files
├── static/               # CSS files
├── app.py               # Main application
└── *.md                 # Documentation
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Can't connect | Check server is running |
| No data | Verify JSON files exist |
| Wrong port | Edit `app.py` line 218 |
| Slow loading | Reduce number of JSON files |

## Stop the Server

Press `Ctrl+C` in the terminal running the app

## Tips

✅ Keep browser window open while working
✅ Refresh page after adding new JSON files
✅ Use Questions Analysis to plan review sessions
✅ Export via API for custom reports
✅ Bookmark frequently accessed students

## Support

- 📚 Full docs: `README.md`
- 📋 Overview: `PLATFORM_OVERVIEW.md`
- 💻 Code: `app.py`

---

**Version**: 1.0  
**Last Updated**: December 2025
