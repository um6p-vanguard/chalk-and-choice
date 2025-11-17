/**
 * ExerciseInterface - Main controller for code exercise page
 */
class ExerciseInterface {
    constructor(exerciseCode, exerciseNum, totalExercises, csrfToken) {
        this.exerciseCode = exerciseCode; // Exercise set code
        this.exerciseNum = exerciseNum; // Current exercise number (1-based)
        this.totalExercises = totalExercises; // Total exercises in set
        this.csrfToken = csrfToken;
        this.exercise = null;
        this.executor = null;
        this.editor = null;
        this.isSubmitting = false;
    }
    
    async initialize() {
        try {
            // Show initialization status
            const statusDiv = document.getElementById('initialization-status');
            const mainContent = document.getElementById('main-content');
            if (statusDiv) statusDiv.style.display = 'block';
            if (mainContent) mainContent.style.display = 'none';
            
            // Show loading
            this.showLoading('Loading exercise data...');
            
            // Fetch exercise data for current exercise in set
            const response = await fetch(`/api/ex/${this.exerciseCode}/${this.exerciseNum}/data`);
            if (!response.ok) {
                throw new Error(`Failed to load exercise (HTTP ${response.status})`);
            }
            this.exercise = await response.json();
            
            console.log('Exercise data loaded:', this.exercise);
            
            // Render problem description
            this.renderProblemDescription();
            
            // Initialize Pyodide
            this.showLoading('Initializing Python environment...<br><small>This may take a moment on first load</small>');
            this.executor = new CodeExecutor();
            await this.executor.initialize();
            
            // Setup Monaco Editor
            this.showLoading('Setting up code editor...');
            await this.setupEditor();
            
            // Setup input/output
            this.setupInputOutput();
            
            // Setup event handlers
            this.setupEventHandlers();
            
            // Render progress info
            this.renderProgress();
            
            // Setup navigation
            this.setupNavigation();
            
            this.hideLoading();
            
            // Hide status, show main content
            if (statusDiv) statusDiv.style.display = 'none';
            if (mainContent) mainContent.style.display = 'grid';
            
            console.log('✓ Exercise interface fully initialized');
        } catch (error) {
            console.error('Initialization error:', error);
            this.hideLoading();
            
            // Show error in status div
            const statusDiv = document.getElementById('initialization-status');
            const statusMsg = document.getElementById('status-message');
            const statusSpinner = document.getElementById('status-spinner');
            
            if (statusDiv && statusMsg && statusSpinner) {
                statusDiv.style.display = 'block';
                statusMsg.innerHTML = `<h2 style="color: #f48771;">Failed to Load Exercise</h2><p>${this.escapeHtml(error.message)}</p><p><a href="/exercises" style="color: #007acc;">← Back to Exercises</a></p>`;
                statusSpinner.style.display = 'none';
            } else {
                this.showError('Failed to initialize exercise: ' + error.message);
            }
        }
    }
    
    renderProblemDescription() {
        const titleEl = document.getElementById('exercise-title');
        const pointsEl = document.getElementById('points');
        const descEl = document.getElementById('problem-description');
        
        if (!titleEl || !pointsEl || !descEl) {
            console.error('Missing DOM elements for problem description');
            return;
        }
        
        titleEl.textContent = `Exercise ${this.exerciseNum}/${this.totalExercises}: ${this.exercise.title}`;
        pointsEl.textContent = `${this.exercise.points} points`;
        
        // Remove difficulty badge from view (it's per-set now, not per-exercise)
        const difficultyEl = document.getElementById('difficulty');
        if (difficultyEl) {
            difficultyEl.style.display = 'none';
        }
        
        // Render markdown description with better fallback
        const description = this.exercise.description || '';
        
        // Simple markdown-like rendering if marked library not available
        const renderSimpleMarkdown = (text) => {
            return text
                .split('\n')
                .map(line => {
                    line = line.trim();
                    // H1
                    if (line.startsWith('# ')) {
                        return `<h1>${line.substring(2)}</h1>`;
                    }
                    // H2
                    if (line.startsWith('## ')) {
                        return `<h2>${line.substring(3)}</h2>`;
                    }
                    // H3
                    if (line.startsWith('### ')) {
                        return `<h3>${line.substring(4)}</h3>`;
                    }
                    // Code block (inline)
                    if (line.includes('`')) {
                        line = line.replace(/`([^`]+)`/g, '<code>$1</code>');
                    }
                    // Empty line - skip it (don't render anything)
                    if (line === '') {
                        return '';
                    }
                    // Regular paragraph
                    return `<p>${line}</p>`;
                })
                .filter(line => line !== '') // Remove empty strings
                .join('\n');
        };
        
        try {
            let descHtml;
            
            // Check if marked is available in window scope
            if (typeof window.marked !== 'undefined') {
                const markedLib = window.marked;
                // Try different marked API versions
                if (typeof markedLib.parse === 'function') {
                    descHtml = markedLib.parse(description);
                    console.log('✓ Used marked.parse()');
                } else if (typeof markedLib === 'function') {
                    descHtml = markedLib(description);
                    console.log('✓ Used marked()');
                } else if (markedLib.marked && typeof markedLib.marked === 'function') {
                    descHtml = markedLib.marked(description);
                    console.log('✓ Used marked.marked()');
                }
            }
            
            if (descHtml) {
                descEl.innerHTML = descHtml;
                console.log('✓ Markdown rendered successfully with marked library');
            } else {
                // Use simple markdown renderer
                descHtml = renderSimpleMarkdown(description);
                descEl.innerHTML = descHtml;
                console.log('✓ Markdown rendered with simple parser (marked library not available)');
            }
        } catch (error) {
            console.warn('Failed to render markdown:', error);
            console.log('Using simple markdown parser as fallback');
            // Fallback: use simple markdown renderer
            const descHtml = renderSimpleMarkdown(description);
            descEl.innerHTML = descHtml;
        }
    }
    
    async setupEditor() {
        return new Promise((resolve, reject) => {
            if (typeof require === 'undefined') {
                reject(new Error('Monaco loader not found'));
                return;
            }
            
            require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' }});
            
            require(['vs/editor/editor.main'], () => {
                try {
                    const editorContainer = document.getElementById('code-editor');
                    if (!editorContainer) {
                        reject(new Error('Editor container not found'));
                        return;
                    }
                    
                    this.editor = monaco.editor.create(editorContainer, {
                        value: this.exercise.starter_code || '# Write your code here\n',
                        language: 'python',
                        theme: 'vs-dark',
                        automaticLayout: true,
                        minimap: { enabled: false },
                        fontSize: 14,
                        lineNumbers: 'on',
                        scrollBeyondLastLine: false,
                        wordWrap: 'on',
                        folding: true,
                        renderWhitespace: 'selection',
                        tabSize: 4
                    });
                    
                    console.log('✓ Monaco editor initialized');
                    resolve();
                } catch (error) {
                    reject(error);
                }
            }, (error) => {
                reject(new Error('Failed to load Monaco editor: ' + error));
            });
        });
    }
    
    setupInputOutput() {
        const inputArea = document.getElementById('custom-input');
        if (inputArea) {
            inputArea.value = this.exercise.default_input || '';
            inputArea.dataset.default = this.exercise.default_input || '';
        }
    }
    
    setupEventHandlers() {
        console.log('Setting up event handlers...');
        
        const buttons = {
            'run-code': () => this.runCode(),
            'run-tests': () => this.runVisibleTests(),
            'submit-solution': () => this.submitSolution(),
            'reset-code': () => this.resetCode(),
            'reset-input': () => this.resetInput()
        };
        
        for (const [id, handler] of Object.entries(buttons)) {
            const btn = document.getElementById(id);
            if (btn) {
                btn.addEventListener('click', handler);
                console.log(`✓ Event handler attached to #${id}`);
            } else {
                console.error(`✗ Button not found: #${id}`);
            }
        }
    }
    
    renderProgress() {
        if (this.exercise.progress) {
            document.getElementById('attempts').textContent = this.exercise.progress.attempts;
            const bestScore = this.exercise.progress.best_score;
            document.getElementById('best-score').textContent = 
                bestScore > 0 ? `${bestScore.toFixed(1)}/${this.exercise.points}` : '-';
            
            if (this.exercise.progress.completed) {
                const badge = document.createElement('div');
                badge.className = 'completed-badge';
                badge.innerHTML = '✓ Completed';
                document.querySelector('.exercise-header').appendChild(badge);
            }
        }
    }
    
    async runCode() {
        console.log('▶ Running code...');
        
        if (!this.editor) {
            console.error('Editor not initialized');
            alert('Editor not ready. Please wait for initialization to complete.');
            return;
        }
        
        if (!this.executor || !this.executor.isReady) {
            console.error('Python executor not initialized');
            alert('Python environment not ready. Please wait...');
            return;
        }
        
        const code = this.editor.getValue();
        const input = document.getElementById('custom-input').value;
        
        console.log('Code length:', code.length, 'bytes');
        console.log('Input length:', input.length, 'bytes');
        
        const outputDisplay = document.getElementById('output-display');
        const timeDisplay = document.getElementById('execution-time');
        
        if (!outputDisplay) {
            console.error('Output display element not found');
            return;
        }
        
        outputDisplay.textContent = 'Running...';
        outputDisplay.className = '';
        timeDisplay.textContent = '';
        
        try {
            const result = await this.executor.runCode(code, input);
            console.log('Execution result:', result);
            
            if (result.success) {
                outputDisplay.textContent = result.output || '(no output)';
                outputDisplay.className = 'success';
                timeDisplay.textContent = `Executed in ${result.executionTime}ms`;
            } else {
                outputDisplay.textContent = `Error:\n${result.error}`;
                outputDisplay.className = 'error';
                timeDisplay.textContent = `Failed after ${result.executionTime}ms`;
            }
        } catch (error) {
            console.error('Error running code:', error);
            outputDisplay.textContent = `Error:\n${error.message}`;
            outputDisplay.className = 'error';
        }
    }
    
    async runVisibleTests() {
        if (!this.editor) return;
        
        const code = this.editor.getValue();
        const visibleTests = this.exercise.visible_test_cases;
        
        if (visibleTests.length === 0) {
            this.showMessage('No visible test cases available. Use "Run Code" to test with custom input.');
            return;
        }
        
        const testResultsDiv = document.getElementById('test-results');
        const testListDiv = document.getElementById('test-list');
        
        testListDiv.innerHTML = '<div class="test-running">Running tests...</div>';
        testResultsDiv.style.display = 'block';
        
        const results = await this.executor.runTestCases(code, visibleTests);
        
        this.displayTestResults(results, false);
    }
    
    displayTestResults(results, showAll = false) {
        const testListDiv = document.getElementById('test-list');
        testListDiv.innerHTML = '';
        
        const visibleResults = showAll ? results : results.filter(r => !r.hidden);
        
        visibleResults.forEach(result => {
            const testDiv = document.createElement('div');
            testDiv.className = `test-item ${result.passed ? 'passed' : 'failed'}`;
            
            const icon = result.passed ? '✓' : '✗';
            const statusClass = result.passed ? 'success' : 'error';
            
            let html = `
                <div class="test-header">
                    <span class="test-icon ${statusClass}">${icon}</span>
                    <span class="test-name">Test ${result.test_num}</span>
                    <span class="test-time">${result.execution_time_ms}ms</span>
                </div>
            `;
            
            if (!result.passed && !result.hidden) {
                html += `
                    <div class="test-details">
                        <div><strong>Input:</strong> <code>${this.escapeHtml(result.input)}</code></div>
                        <div><strong>Expected:</strong> <code>${this.escapeHtml(result.expected)}</code></div>
                        <div><strong>Got:</strong> <code>${this.escapeHtml(result.actual)}</code></div>
                    </div>
                `;
            }
            
            testDiv.innerHTML = html;
            testListDiv.appendChild(testDiv);
        });
    }
    
    async submitSolution() {
        if (this.isSubmitting) return;
        
        if (!confirm('Submit your solution? This will test against all test cases including hidden ones.')) {
            return;
        }
        
        this.isSubmitting = true;
        
        try {
            const code = this.editor.getValue();
            
            // Show loading modal
            this.showModal(`
                <h2>🧪 Running All Tests</h2>
                <p>Testing your code against visible and hidden test cases...</p>
                <div class="spinner"></div>
            `);
            
            // Fetch all test cases
            const testsResponse = await fetch(`/api/ex/${this.exerciseCode}/${this.exerciseNum}/all-tests`, {
                headers: { 'X-CSRF': this.csrfToken }
            });
            
            if (!testsResponse.ok) {
                throw new Error('Failed to fetch test cases');
            }
            
            const testsData = await testsResponse.json();
            
            // Run all tests
            const testResults = await this.executor.runTestCases(code, testsData.test_cases);
            
            // Submit to server
            const submitResponse = await fetch(`/api/ex/${this.exerciseCode}/${this.exerciseNum}/submit`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF': this.csrfToken
                },
                body: JSON.stringify({
                    code: code,
                    test_results: testResults
                })
            });
            
            if (!submitResponse.ok) {
                const error = await submitResponse.json();
                throw new Error(error.description || 'Submission failed');
            }
            
            const result = await submitResponse.json();
            
            // Display results
            this.displaySubmissionResults(result);
            
            // Update progress display
            this.updateProgressDisplay(result);
            
        } catch (error) {
            console.error('Submission error:', error);
            this.showModal(`
                <h2>❌ Submission Failed</h2>
                <p>${this.escapeHtml(error.message)}</p>
                <button onclick="exerciseInterface.closeModal()" class="btn-primary">Close</button>
            `);
        } finally {
            this.isSubmitting = false;
        }
    }
    
    displaySubmissionResults(result) {
        const isComplete = result.all_passed;
        const icon = isComplete ? '🎉' : '📊';
        
        let html = `
            <div class="results-modal">
                <h2>${icon} ${isComplete ? 'Perfect Solution!' : 'Submission Results'}</h2>
                <div class="attempt-info">Attempt #${result.attempt_number}</div>
                
                <div class="score-display ${isComplete ? 'perfect' : ''}">
                    <div class="score-big">${result.score}/${result.max_score}</div>
                    <div class="score-percentage">${Math.round(result.score / result.max_score * 100)}%</div>
                </div>
                
                <div class="test-summary">
                    <div class="summary-section visible">
                        <h3>✅ Visible Test Cases</h3>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${result.visible.percentage}%"></div>
                        </div>
                        <div class="summary-text">
                            ${result.visible.passed}/${result.visible.total} passed (${result.visible.percentage}%)
                        </div>
                    </div>
                    
                    <div class="summary-section hidden">
                        <h3>🔒 Hidden Test Cases</h3>
                        <div class="progress-bar">
                            <div class="progress-fill ${result.hidden.passed === result.hidden.total ? 'complete' : ''}" style="width: ${result.hidden.percentage}%"></div>
                        </div>
                        <div class="summary-text">
                            ${result.hidden.passed}/${result.hidden.total} passed (${result.hidden.percentage}%)
                        </div>
                        ${result.hidden.passed < result.hidden.total ? 
                            '<p class="hint">💡 Keep trying! Consider edge cases and special inputs.</p>' : 
                            '<p class="success">✓ All hidden tests passed!</p>'
                        }
                    </div>
                </div>
                
                <div class="test-details">
                    <h3>Visible Test Results:</h3>
                    <div class="test-list">
        `;
        
        // Show detailed results for visible tests only
        result.test_results.forEach(test => {
            if (!test.hidden) {
                const statusIcon = test.passed ? '✓' : '✗';
                const statusClass = test.passed ? 'passed' : 'failed';
                
                html += `
                    <div class="test-item ${statusClass}">
                        <div class="test-header">
                            <span class="test-icon">${statusIcon}</span>
                            <span class="test-name">Test ${test.test_num}</span>
                            <span class="test-time">${test.time_ms}ms</span>
                        </div>
                `;
                
                if (test.description) {
                    html += `<div class="test-description">${this.escapeHtml(test.description)}</div>`;
                }
                
                if (!test.passed) {
                    html += `
                        <div class="test-details">
                            <div><strong>Input:</strong> <code>${this.escapeHtml(test.input)}</code></div>
                            <div><strong>Expected:</strong> <code>${this.escapeHtml(test.expected)}</code></div>
                            <div><strong>Got:</strong> <code>${this.escapeHtml(test.actual)}</code></div>
                        </div>
                    `;
                }
                
                html += `</div>`;
            }
        });
        
        html += `
                    </div>
                </div>
                
                <div class="modal-actions">
        `;
        
        if (isComplete) {
            html += `
                <button class="btn-success" onclick="window.location.href='/exercises'">
                    🎯 Browse More Exercises
                </button>
            `;
        } else {
            html += `
                <button class="btn-primary" onclick="exerciseInterface.closeModal()">
                    ✏️ Revise Code
                </button>
            `;
        }
        
        html += `
                    <button class="btn-secondary" onclick="exerciseInterface.viewSubmissions()">
                        📜 View All Attempts
                    </button>
                </div>
            </div>
        `;
        
        this.showModal(html);
    }
    
    updateProgressDisplay(result) {
        document.getElementById('attempts').textContent = result.attempt_number;
        if (result.is_best_score) {
            document.getElementById('best-score').textContent = `${result.score}/${result.max_score}`;
        }
        
        if (result.completed && !document.querySelector('.completed-badge')) {
            const badge = document.createElement('div');
            badge.className = 'completed-badge';
            badge.innerHTML = '✓ Completed';
            document.querySelector('.exercise-header').appendChild(badge);
        }
    }
    
    async viewSubmissions() {
        try {
            const response = await fetch(`/api/ex/${this.exerciseCode}/${this.exerciseNum}/my-submissions`);
            if (!response.ok) {
                throw new Error(`Failed to load submissions (HTTP ${response.status})`);
            }
            const data = await response.json();
            
            let html = `
                <div class="submissions-modal">
                    <div class="modal-header">
                        <h2>� Submission History</h2>
                        <p class="modal-subtitle">Exercise ${this.exerciseNum} - ${data.submissions.length} attempt${data.submissions.length !== 1 ? 's' : ''}</p>
                    </div>
            `;
            
            if (data.submissions.length === 0) {
                html += `
                    <div class="empty-state">
                        <div class="empty-icon">📝</div>
                        <p class="empty-text">No submissions yet</p>
                        <p class="empty-hint">Submit your solution to track your progress here!</p>
                    </div>
                `;
            } else {
                html += '<div class="submissions-list">';
                
                data.submissions.forEach((sub, index) => {
                    const percentage = Math.round((sub.score / sub.max_score) * 100);
                    const visiblePercentage = Math.round((sub.visible_passed / sub.visible_total) * 100);
                    const hiddenPercentage = Math.round((sub.hidden_passed / sub.hidden_total) * 100);
                    const statusClass = sub.all_passed ? 'complete' : percentage >= 75 ? 'good' : percentage >= 50 ? 'ok' : 'needs-work';
                    
                    html += `
                        <div class="submission-card ${sub.is_best ? 'best-submission' : ''} ${statusClass}">
                            <div class="submission-header">
                                <div class="submission-number">
                                    <span class="attempt-label">Attempt</span>
                                    <span class="attempt-num">#${sub.attempt_number}</span>
                                </div>
                                <div class="submission-badges">
                                    ${sub.is_best ? '<span class="badge badge-best">🏆 Best Score</span>' : ''}
                                    ${sub.all_passed ? '<span class="badge badge-complete">✅ Perfect</span>' : ''}
                                </div>
                            </div>
                            
                            <div class="submission-score">
                                <div class="score-circle ${statusClass}">
                                    <div class="score-value">${percentage}<span class="score-percent">%</span></div>
                                    <div class="score-fraction">${sub.score}/${sub.max_score}</div>
                                </div>
                            </div>
                            
                            <div class="submission-details">
                                <div class="detail-row">
                                    <div class="detail-item">
                                        <div class="detail-label">👁️ Visible Tests</div>
                                        <div class="detail-value">
                                            <span class="test-count">${sub.visible_passed}/${sub.visible_total}</span>
                                            <div class="mini-progress">
                                                <div class="mini-progress-fill" style="width: ${visiblePercentage}%"></div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="detail-item">
                                        <div class="detail-label">🔒 Hidden Tests</div>
                                        <div class="detail-value">
                                            <span class="test-count">${sub.hidden_passed}/${sub.hidden_total}</span>
                                            <div class="mini-progress">
                                                <div class="mini-progress-fill ${sub.hidden_passed === sub.hidden_total ? 'complete' : ''}" style="width: ${hiddenPercentage}%"></div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="submission-footer">
                                <div class="submission-time">
                                    <span class="time-icon">🕒</span>
                                    ${this.formatDate(sub.submitted_at)}
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                html += '</div>';
            }
            
            html += `
                    <div class="modal-actions">
                        <button onclick="exerciseInterface.closeModal()" class="btn-primary">Close</button>
                    </div>
                </div>
            `;
            
            this.showModal(html);
        } catch (error) {
            console.error('Failed to load submissions:', error);
            this.showModal(`
                <div class="error-modal">
                    <h2>❌ Failed to Load Submissions</h2>
                    <p>${this.escapeHtml(error.message)}</p>
                    <button onclick="exerciseInterface.closeModal()" class="btn-primary">Close</button>
                </div>
            `);
        }
    }
    
    formatDate(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
        if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
        if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
        
        return date.toLocaleDateString('en-US', { 
            month: 'short', 
            day: 'numeric', 
            year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined,
            hour: '2-digit',
            minute: '2-digit'
        });
    }
    
    resetCode() {
        if (confirm('Reset code to starting template? Your current code will be lost.')) {
            this.editor.setValue(this.exercise.starter_code);
        }
    }
    
    resetInput() {
        const inputArea = document.getElementById('custom-input');
        inputArea.value = inputArea.dataset.default || '';
    }
    
    showLoading(message) {
        const modal = document.getElementById('loading-modal');
        const content = document.getElementById('loading-content');
        if (!modal || !content) {
            console.error('Loading modal elements not found');
            return;
        }
        content.innerHTML = `
            <div class="spinner"></div>
            <div style="margin-top: 10px;">${message}</div>
        `;
        modal.style.display = 'flex';
    }
    
    hideLoading() {
        const modal = document.getElementById('loading-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }
    
    showModal(html) {
        const modal = document.getElementById('results-modal');
        if (!modal) {
            console.error('Results modal not found');
            return;
        }
        modal.innerHTML = html;
        modal.style.display = 'flex';
    }
    
    closeModal() {
        const modal = document.getElementById('results-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }
    
    showMessage(message) {
        this.showModal(`
            <div class="message-modal" style="background: var(--vscode-sidebar); padding: 30px; border-radius: 8px; max-width: 500px; border: 1px solid var(--vscode-border);">
                <p style="margin: 0 0 20px 0; font-size: 14px;">${message}</p>
                <button onclick="exerciseInterface.closeModal()" class="btn-primary">OK</button>
            </div>
        `);
    }
    
    showError(message) {
        this.showModal(`
            <div class="error-modal" style="background: var(--vscode-sidebar); padding: 30px; border-radius: 8px; max-width: 500px; border: 1px solid var(--vscode-red);">
                <h2 style="margin: 0 0 16px 0; color: var(--vscode-red); font-size: 18px;">❌ Error</h2>
                <p style="margin: 0 0 20px 0; font-size: 14px;">${this.escapeHtml(message)}</p>
                <button onclick="exerciseInterface.closeModal()" class="btn-primary">Close</button>
            </div>
        `);
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    }
    
    setupNavigation() {
        // Add navigation buttons if we have multiple exercises
        if (this.totalExercises <= 1) return;
        
        const actionBar = document.querySelector('.action-bar');
        if (!actionBar) return;
        
        // Create navigation container
        const navDiv = document.createElement('div');
        navDiv.style.cssText = 'display: flex; gap: 10px; margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1);';
        
        // Previous button
        if (this.exerciseNum > 1) {
            const prevBtn = document.createElement('a');
            prevBtn.href = `/ex/${this.exerciseCode}/${this.exerciseNum - 1}`;
            prevBtn.className = 'btn-secondary';
            prevBtn.style.cssText = 'text-decoration: none; padding: 10px 20px;';
            prevBtn.textContent = `← Previous Exercise`;
            navDiv.appendChild(prevBtn);
        }
        
        // Position indicator
        const posDiv = document.createElement('div');
        posDiv.style.cssText = 'flex: 1; text-align: center; display: flex; align-items: center; justify-content: center; color: #94a3b8;';
        posDiv.textContent = `Exercise ${this.exerciseNum} of ${this.totalExercises}`;
        navDiv.appendChild(posDiv);
        
        // Next button
        if (this.exerciseNum < this.totalExercises) {
            const nextBtn = document.createElement('a');
            nextBtn.href = `/ex/${this.exerciseCode}/${this.exerciseNum + 1}`;
            nextBtn.className = 'btn-secondary';
            nextBtn.style.cssText = 'text-decoration: none; padding: 10px 20px;';
            nextBtn.textContent = `Next Exercise →`;
            navDiv.appendChild(nextBtn);
        }
        
        actionBar.appendChild(navDiv);
    }
}

// Global instance
let exerciseInterface;
