#!/usr/bin/env python3
"""
Load Testing Suite for Chalk-and-Choice Application
Tests concurrent student operations, especially notebook functionality
"""

import asyncio
import aiohttp
import json
import time
import random
import string
from datetime import datetime
from typing import List, Dict, Any
import argparse
import sys
from collections import defaultdict

# Sample notebook content for testing
SAMPLE_NOTEBOOK = {
    "cells": [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": ["# Test Notebook\n", "This is a test notebook for load testing."]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": ["import numpy as np\n", "import pandas as pd\n", "print('Hello World')"]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": ["# Data analysis\n", "data = np.random.rand(100)\n", "print(f'Mean: {data.mean():.2f}')"]
        }
    ],
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.10.0"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 4
}


class StudentSimulator:
    """Simulates a single student's interactions with the platform"""
    
    def __init__(self, student_id: int, email: str, password: str, base_url: str):
        self.student_id = student_id
        self.email = email
        self.password = password
        self.base_url = base_url.rstrip('/')
        self.session = None
        self.csrf_token = None
        self.metrics = {
            'login_time': 0,
            'notebook_create_time': 0,
            'notebook_update_time': 0,
            'notebook_read_time': 0,
            'homework_access_time': 0,
            'homework_submit_time': 0,
            'errors': []
        }
    
    async def setup_session(self):
        """Create an aiohttp session"""
        self.session = aiohttp.ClientSession()
    
    async def close_session(self):
        """Close the aiohttp session"""
        if self.session:
            await self.session.close()
    
    async def login(self) -> bool:
        """Login as a student"""
        start = time.time()
        try:
            # First, get the login page to establish session and cookies
            async with self.session.get(f"{self.base_url}/login") as resp:
                if resp.status != 200:
                    self.metrics['errors'].append(f"Login page failed: {resp.status}")
                    return False
                
                # Extract CSRF token from the page
                html = await resp.text()
                # The token is in: <input type="hidden" name="csrf" value="TOKEN">
                import re
                match = re.search(r'name="csrf"\s+value="([^"]+)"', html)
                if not match:
                    # Try alternative pattern
                    match = re.search(r'value="([^"]+)"\s+name="csrf"', html)
                if not match:
                    self.metrics['errors'].append("CSRF token not found in login page")
                    return False
                csrf = match.group(1)
            
            # Now login with form data
            data = {
                'email': self.email,
                'password': self.password,
                'csrf': csrf
            }
            
            async with self.session.post(
                f"{self.base_url}/login", 
                data=data, 
                allow_redirects=False
            ) as resp:
                # Successful login redirects (302/303)
                if resp.status in (302, 303):
                    location = resp.headers.get('Location', '')
                    if '/password/new' in location:
                        # First time login - need to set password
                        return await self.set_initial_password()
                    
                    self.metrics['login_time'] = time.time() - start
                    return True
                elif resp.status == 200:
                    # No redirect means login failed - check for error message
                    html = await resp.text()
                    if 'Invalid credentials' in html or 'Account not found' in html:
                        self.metrics['errors'].append("Invalid credentials or account not found")
                    else:
                        self.metrics['errors'].append(f"Login returned 200 but no redirect")
                    return False
                else:
                    self.metrics['errors'].append(f"Login failed with status: {resp.status}")
                    return False
                
        except Exception as e:
            self.metrics['errors'].append(f"Login exception: {str(e)}")
            return False
    
    async def set_initial_password(self) -> bool:
        """Handle first-time password change"""
        try:
            async with self.session.get(f"{self.base_url}/password/new") as resp:
                html = await resp.text()
                import re
                match = re.search(r'name="csrf"\s+value="([^"]+)"', html)
                if not match:
                    return False
                csrf = match.group(1)
            
            new_password = self.password  # Keep the same password
            data = {
                'password1': new_password,
                'password2': new_password,
                'csrf': csrf
            }
            
            async with self.session.post(f"{self.base_url}/password/new", data=data, allow_redirects=False) as resp:
                return resp.status in (302, 303)
                
        except Exception as e:
            self.metrics['errors'].append(f"Password change failed: {str(e)}")
            return False
    
    async def get_csrf_token(self) -> str:
        """Get CSRF token for API requests"""
        try:
            async with self.session.get(f"{self.base_url}/api/csrf") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.csrf_token = data.get('csrf')
                    return self.csrf_token
        except Exception as e:
            self.metrics['errors'].append(f"CSRF token fetch failed: {str(e)}")
        return None
    
    async def create_notebook(self) -> int:
        """Create a new notebook"""
        start = time.time()
        try:
            if not self.csrf_token:
                await self.get_csrf_token()
            
            notebook_data = json.loads(json.dumps(SAMPLE_NOTEBOOK))  # Deep copy
            notebook_data['metadata']['chalk_name'] = f"Student{self.student_id}_Notebook_{int(time.time())}.ipynb"
            
            headers = {'X-CSRF': self.csrf_token, 'Content-Type': 'application/json'}
            payload = {'content': notebook_data}
            
            async with self.session.post(
                f"{self.base_url}/api/notebooks",
                json=payload,
                headers=headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.metrics['notebook_create_time'] = time.time() - start
                    return data.get('id')
                else:
                    error_text = await resp.text()
                    self.metrics['errors'].append(f"Notebook create failed ({resp.status}): {error_text}")
                    return None
                    
        except Exception as e:
            self.metrics['errors'].append(f"Notebook create exception: {str(e)}")
            return None
    
    async def update_notebook(self, notebook_id: int, iterations: int = 5) -> bool:
        """Update a notebook multiple times (simulating student work)"""
        start = time.time()
        try:
            if not self.csrf_token:
                await self.get_csrf_token()
            
            for i in range(iterations):
                notebook_data = json.loads(json.dumps(SAMPLE_NOTEBOOK))
                # Add some dynamic content
                notebook_data['cells'].append({
                    "cell_type": "code",
                    "execution_count": None,
                    "metadata": {},
                    "outputs": [],
                    "source": [f"# Update {i+1}\n", f"result = {random.randint(1, 1000)}\n", f"print('Iteration {i+1}, result:', result)"]
                })
                notebook_data['metadata']['chalk_name'] = f"Student{self.student_id}_Updated.ipynb"
                
                headers = {'X-CSRF': self.csrf_token, 'Content-Type': 'application/json'}
                payload = {'content': notebook_data}
                
                async with self.session.put(
                    f"{self.base_url}/api/notebooks/{notebook_id}",
                    json=payload,
                    headers=headers
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        self.metrics['errors'].append(f"Notebook update failed ({resp.status}): {error_text}")
                        return False
                
                # Small delay between updates (realistic student behavior)
                await asyncio.sleep(random.uniform(0.5, 2.0))
            
            self.metrics['notebook_update_time'] = time.time() - start
            return True
            
        except Exception as e:
            self.metrics['errors'].append(f"Notebook update exception: {str(e)}")
            return False
    
    async def read_notebook(self, notebook_id: int) -> bool:
        """Read a notebook"""
        start = time.time()
        try:
            async with self.session.get(f"{self.base_url}/api/notebooks/{notebook_id}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.metrics['notebook_read_time'] = time.time() - start
                    return True
                else:
                    self.metrics['errors'].append(f"Notebook read failed: {resp.status}")
                    return False
                    
        except Exception as e:
            self.metrics['errors'].append(f"Notebook read exception: {str(e)}")
            return False
    
    async def access_homework(self, homework_code: str) -> bool:
        """Access a homework assignment"""
        start = time.time()
        try:
            # Get homework page
            async with self.session.get(f"{self.base_url}/hw/{homework_code}") as resp:
                if resp.status != 200:
                    self.metrics['errors'].append(f"Homework page access failed: {resp.status}")
                    return False
            
            # Get homework notebook
            async with self.session.get(f"{self.base_url}/api/hw/{homework_code}/my") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.metrics['homework_access_time'] = time.time() - start
                    return data.get('notebook_id') is not None
                else:
                    self.metrics['errors'].append(f"Homework API access failed: {resp.status}")
                    return False
                    
        except Exception as e:
            self.metrics['errors'].append(f"Homework access exception: {str(e)}")
            return False
    
    async def submit_homework(self, homework_code: str) -> bool:
        """Submit homework"""
        start = time.time()
        try:
            if not self.csrf_token:
                await self.get_csrf_token()
            
            headers = {'X-CSRF': self.csrf_token, 'Content-Type': 'application/json'}
            
            async with self.session.post(
                f"{self.base_url}/api/hw/{homework_code}/submit",
                headers=headers
            ) as resp:
                if resp.status == 200:
                    self.metrics['homework_submit_time'] = time.time() - start
                    return True
                else:
                    self.metrics['errors'].append(f"Homework submit failed: {resp.status}")
                    return False
                    
        except Exception as e:
            self.metrics['errors'].append(f"Homework submit exception: {str(e)}")
            return False
    
    async def list_notebooks(self) -> int:
        """List all notebooks for this student"""
        try:
            async with self.session.get(f"{self.base_url}/api/notebooks") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return len(data.get('items', []))
                return 0
        except Exception as e:
            self.metrics['errors'].append(f"Notebook list exception: {str(e)}")
            return 0


class LoadTester:
    """Orchestrates load testing with multiple concurrent students"""
    
    def __init__(self, base_url: str, num_students: int):
        self.base_url = base_url
        self.num_students = num_students
        self.students = []
        self.results = {
            'total_students': num_students,
            'successful_logins': 0,
            'failed_logins': 0,
            'notebooks_created': 0,
            'notebooks_updated': 0,
            'total_errors': 0,
            'avg_login_time': 0,
            'avg_notebook_create_time': 0,
            'avg_notebook_update_time': 0,
            'student_metrics': []
        }
    
    def generate_student_data(self) -> List[Dict[str, str]]:
        """Generate test student data"""
        students = []
        for i in range(1, self.num_students + 1):
            students.append({
                'student_id': i,
                'email': f'student{i}@test.edu',
                'password': f'TestPass{i}!23'
            })
        return students
    
    async def run_student_scenario(self, student_data: Dict[str, str], scenario: str = 'full'):
        """Run a complete scenario for a single student"""
        student = StudentSimulator(
            student_data['student_id'],
            student_data['email'],
            student_data['password'],
            self.base_url
        )
        
        await student.setup_session()
        
        try:
            # Login
            login_success = await student.login()
            if login_success:
                self.results['successful_logins'] += 1
                
                if scenario in ['full', 'notebooks']:
                    # Create notebook
                    notebook_id = await student.create_notebook()
                    if notebook_id:
                        self.results['notebooks_created'] += 1
                        
                        # Update notebook multiple times
                        update_success = await student.update_notebook(notebook_id, iterations=3)
                        if update_success:
                            self.results['notebooks_updated'] += 1
                        
                        # Read notebook back
                        await student.read_notebook(notebook_id)
                
                # Get final notebook count
                await student.list_notebooks()
                
            else:
                self.results['failed_logins'] += 1
            
            self.results['total_errors'] += len(student.metrics['errors'])
            self.results['student_metrics'].append(student.metrics)
            
        except Exception as e:
            print(f"Student {student.student_id} scenario failed: {str(e)}")
            self.results['total_errors'] += 1
        
        finally:
            await student.close_session()
    
    async def run_concurrent_test(self, scenario: str = 'full', batch_size: int = 20):
        """Run tests with multiple concurrent students in batches"""
        student_data_list = self.generate_student_data()
        
        print(f"\n{'='*60}")
        print(f"Starting Load Test: {self.num_students} students")
        print(f"Scenario: {scenario}")
        print(f"Batch size: {batch_size}")
        print(f"Target URL: {self.base_url}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        # Process in batches to avoid overwhelming the server
        for i in range(0, len(student_data_list), batch_size):
            batch = student_data_list[i:i+batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(student_data_list) + batch_size - 1) // batch_size
            
            print(f"Processing batch {batch_num}/{total_batches} ({len(batch)} students)...")
            
            tasks = [self.run_student_scenario(student, scenario) for student in batch]
            await asyncio.gather(*tasks)
            
            # Brief pause between batches
            if i + batch_size < len(student_data_list):
                await asyncio.sleep(2)
        
        total_time = time.time() - start_time
        
        # Calculate averages
        self.calculate_statistics()
        
        # Print results
        self.print_results(total_time)
    
    def calculate_statistics(self):
        """Calculate average metrics"""
        metrics = self.results['student_metrics']
        
        if self.results['successful_logins'] > 0:
            self.results['avg_login_time'] = sum(
                m['login_time'] for m in metrics if m['login_time'] > 0
            ) / self.results['successful_logins']
        
        if self.results['notebooks_created'] > 0:
            self.results['avg_notebook_create_time'] = sum(
                m['notebook_create_time'] for m in metrics if m['notebook_create_time'] > 0
            ) / self.results['notebooks_created']
        
        if self.results['notebooks_updated'] > 0:
            self.results['avg_notebook_update_time'] = sum(
                m['notebook_update_time'] for m in metrics if m['notebook_update_time'] > 0
            ) / self.results['notebooks_updated']
    
    def print_results(self, total_time: float):
        """Print test results"""
        print(f"\n{'='*60}")
        print(f"LOAD TEST RESULTS")
        print(f"{'='*60}")
        print(f"Total Time: {total_time:.2f}s")
        print(f"Total Students: {self.results['total_students']}")
        print(f"Successful Logins: {self.results['successful_logins']}")
        print(f"Failed Logins: {self.results['failed_logins']}")
        print(f"\nNotebook Operations:")
        print(f"  Created: {self.results['notebooks_created']}")
        print(f"  Updated: {self.results['notebooks_updated']}")
        print(f"\nAverage Response Times:")
        print(f"  Login: {self.results['avg_login_time']:.3f}s")
        print(f"  Notebook Create: {self.results['avg_notebook_create_time']:.3f}s")
        print(f"  Notebook Update: {self.results['avg_notebook_update_time']:.3f}s")
        print(f"\nErrors: {self.results['total_errors']}")
        
        if self.results['total_errors'] > 0:
            print(f"\nSample Errors:")
            error_count = defaultdict(int)
            for m in self.results['student_metrics']:
                for err in m['errors'][:3]:  # First 3 errors per student
                    error_count[err] += 1
            
            for err, count in sorted(error_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  [{count}x] {err}")
        
        print(f"{'='*60}\n")
        
        # Performance assessment
        success_rate = (self.results['successful_logins'] / self.results['total_students']) * 100
        print(f"Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 95 and self.results['avg_notebook_create_time'] < 1.0:
            print("✅ EXCELLENT: System handles load well!")
        elif success_rate >= 80 and self.results['avg_notebook_create_time'] < 2.0:
            print("⚠️  ACCEPTABLE: System works but may need optimization")
        else:
            print("❌ POOR: System struggles with this load. Optimization needed!")


def main():
    parser = argparse.ArgumentParser(description='Load test Chalk-and-Choice application')
    parser.add_argument('--url', default='http://localhost:5000', help='Base URL of the application')
    parser.add_argument('--students', type=int, default=100, help='Number of concurrent students')
    parser.add_argument('--batch-size', type=int, default=20, help='Number of students per batch')
    parser.add_argument('--scenario', choices=['full', 'notebooks', 'login'], default='full',
                        help='Test scenario to run')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed per-student output')
    
    args = parser.parse_args()
    
    # Quick pre-check
    if args.verbose:
        print("🔍 Running pre-flight checks...")
        import requests
        try:
            resp = requests.get(f"{args.url}/login", timeout=5)
            if resp.status_code == 200:
                print(f"✅ App is accessible at {args.url}")
            else:
                print(f"⚠️  App returned status {resp.status_code}")
        except Exception as e:
            print(f"❌ Cannot connect to {args.url}: {e}")
            print(f"   Make sure the app is running!")
            sys.exit(1)
    
    tester = LoadTester(args.url, args.students)
    
    try:
        asyncio.run(tester.run_concurrent_test(args.scenario, args.batch_size))
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)


if __name__ == '__main__':
    main()
