/**
 * CodeExecutor - Handles Python code execution in the browser using Pyodide
 */
class CodeExecutor {
    constructor() {
        this.pyodide = null;
        this.isReady = false;
        this.isLoading = false;
    }
    
    async initialize() {
        if (this.isReady) return;
        if (this.isLoading) {
            // Wait for existing initialization
            while (this.isLoading) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            return;
        }
        
        this.isLoading = true;
        
        try {
            // Load Pyodide from CDN
            this.pyodide = await loadPyodide({
                indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.24.1/full/'
            });
            
            this.isReady = true;
        } catch (error) {
            throw error;
        } finally {
            this.isLoading = false;
        }
    }
    
    async runCode(code, stdin = '') {
        if (!this.isReady) {
            await this.initialize();
        }
        
        const startTime = performance.now();
        
        try {
            // Setup stdin if provided
            if (stdin) {
                this.pyodide.runPython(`
import sys
from io import StringIO
sys.stdin = StringIO("""${stdin.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}""")
                `);
            }
            
            // Capture stdout/stderr
            this.pyodide.runPython(`
import sys
from io import StringIO
_stdout = StringIO()
_stderr = StringIO()
sys.stdout = _stdout
sys.stderr = _stderr
            `);
            
            // Execute student code
            this.pyodide.runPython(code);
            
            // Get output
            const stdout = this.pyodide.runPython('_stdout.getvalue()');
            const stderr = this.pyodide.runPython('_stderr.getvalue()');
            const executionTime = performance.now() - startTime;
            
            return {
                success: true,
                output: stdout,
                error: stderr || null,
                executionTime: Math.round(executionTime)
            };
        } catch (error) {
            const executionTime = performance.now() - startTime;
            return {
                success: false,
                output: null,
                error: error.message || String(error),
                executionTime: Math.round(executionTime)
            };
        } finally {
            // Reset stdout/stderr
            try {
                this.pyodide.runPython(`
import sys
sys.stdout = sys.__stdout__
sys.stderr = sys.__stderr__
                `);
            } catch (e) {
            }
        }
    }
    
    /**
     * Smart comparison of outputs that handles Python data structures
     * Normalizes whitespace and evaluates Python literals when possible
     */
    compareOutputs(actual, expected) {
        if (!actual && !expected) return true;
        if (!actual || !expected) return false;
        
        // Trim both
        const actualTrimmed = actual.trim();
        const expectedTrimmed = expected.trim();
        
        // Exact match (fastest path)
        if (actualTrimmed === expectedTrimmed) {
            return true;
        }
        
        // Normalize whitespace in Python data structures
        // Remove spaces after [ { ( and before ] } )
        // Remove spaces around commas and colons
        const normalize = (str) => {
            return str
                .replace(/\[\s+/g, '[')      // [ x -> [x
                .replace(/\s+\]/g, ']')      // x ] -> x]
                .replace(/\{\s+/g, '{')      // { x -> {x
                .replace(/\s+\}/g, '}')      // x } -> x}
                .replace(/\(\s+/g, '(')      // ( x -> (x
                .replace(/\s+\)/g, ')')      // x ) -> x)
                .replace(/\s*,\s*/g, ',')    // x , y -> x,y
                .replace(/\s*:\s*/g, ':')    // x : y -> x:y
                .replace(/\s+/g, ' ')        // multiple spaces -> single space
                .trim();
        };
        
        const actualNormalized = normalize(actualTrimmed);
        const expectedNormalized = normalize(expectedTrimmed);
        
        if (actualNormalized === expectedNormalized) {
            return true;
        }
        
        // Try to evaluate as Python literals if they look like data structures
        if (this.isPythonDataStructure(actualTrimmed) && this.isPythonDataStructure(expectedTrimmed)) {
            try {
                // Use Pyodide to evaluate and compare
                const comparison = this.pyodide.runPython(`
import json
def compare_python_values(actual_str, expected_str):
    try:
        actual = eval(actual_str)
        expected = eval(expected_str)
        return actual == expected
    except:
        return False

compare_python_values(${JSON.stringify(actualTrimmed)}, ${JSON.stringify(expectedTrimmed)})
                `);
                
                if (comparison) {
                    return true;
                }
            } catch (e) {
                // If evaluation fails, fall through to string comparison
            }
        }
        
        // Case-insensitive comparison as last resort (for text outputs)
        const caseInsensitiveMatch = actualNormalized.toLowerCase() === expectedNormalized.toLowerCase();
        if (caseInsensitiveMatch) {
        } else {
        }
        return caseInsensitiveMatch;
    }
    
    /**
     * Check if a string looks like a Python data structure
     */
    isPythonDataStructure(str) {
        const trimmed = str.trim();
        return (
            (trimmed.startsWith('[') && trimmed.endsWith(']')) ||  // List
            (trimmed.startsWith('(') && trimmed.endsWith(')')) ||  // Tuple
            (trimmed.startsWith('{') && trimmed.endsWith('}')) ||  // Dict/Set
            /^\d+$/.test(trimmed) ||                                // Integer
            /^\d+\.\d+$/.test(trimmed) ||                          // Float
            trimmed === 'True' || trimmed === 'False' ||           // Boolean
            trimmed === 'None'                                      // None
        );
    }
    
    async runTestCases(code, testCases) {
        const results = [];
        
        
        for (let i = 0; i < testCases.length; i++) {
            const test = testCases[i];
            const result = await this.runCode(code, test.input);
            
            // Use smart comparison
            const passed = result.success && 
                          this.compareOutputs(result.output || '', test.expected_output || '');
            
            results.push({
                test_num: i + 1,
                passed: passed,
                input: test.input,
                expected: test.expected_output,
                actual: result.output || result.error || '',
                execution_time_ms: result.executionTime,
                hidden: test.hidden || false
            });
            
        }
        
        const passedCount = results.filter(r => r.passed).length;
        
        return results;
    }
}
