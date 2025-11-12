#!/usr/bin/env python3
"""
Notebook-specific stress test
Tests concurrent notebook operations in detail
"""

import asyncio
import aiohttp
import json
import time
import random
from datetime import datetime
from test_load import StudentSimulator, SAMPLE_NOTEBOOK


class NotebookStressTest:
    """Focused stress test for notebook operations"""
    
    def __init__(self, base_url: str, num_students: int):
        self.base_url = base_url
        self.num_students = num_students
        self.results = {
            'notebook_operations': [],
            'concurrent_writes': 0,
            'concurrent_reads': 0,
            'conflicts': 0,
            'errors': []
        }
    
    async def test_concurrent_writes(self):
        """Test multiple students writing notebooks simultaneously"""
        print("Testing concurrent notebook writes...")
        
        students = []
        for i in range(1, min(self.num_students + 1, 51)):  # Max 50 for this test
            student = StudentSimulator(
                i,
                f'student{i}@test.edu',
                f'TestPass{i}!23',
                self.base_url
            )
            await student.setup_session()
            await student.login()
            students.append(student)
        
        # All students create notebooks simultaneously
        start = time.time()
        tasks = [s.create_notebook() for s in students]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start
        
        successful = sum(1 for r in results if r and not isinstance(r, Exception))
        failed = len(results) - successful
        
        print(f"  Created {successful} notebooks in {elapsed:.2f}s")
        print(f"  Failed: {failed}")
        print(f"  Rate: {successful/elapsed:.2f} notebooks/sec")
        
        self.results['concurrent_writes'] = successful
        
        # Cleanup
        for s in students:
            await s.close_session()
        
        return successful, failed
    
    async def test_concurrent_updates(self):
        """Test multiple students updating different notebooks simultaneously"""
        print("\nTesting concurrent notebook updates...")
        
        students = []
        notebook_ids = []
        
        # Setup: Each student creates one notebook
        for i in range(1, min(self.num_students + 1, 51)):
            student = StudentSimulator(
                i,
                f'student{i}@test.edu',
                f'TestPass{i}!23',
                self.base_url
            )
            await student.setup_session()
            await student.login()
            nb_id = await student.create_notebook()
            students.append(student)
            notebook_ids.append(nb_id)
        
        # All students update their notebooks simultaneously
        start = time.time()
        tasks = [s.update_notebook(nb_id, iterations=5) 
                 for s, nb_id in zip(students, notebook_ids)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start
        
        successful = sum(1 for r in results if r and not isinstance(r, Exception))
        failed = len(results) - successful
        
        print(f"  Updated {successful} notebooks (5 iterations each) in {elapsed:.2f}s")
        print(f"  Failed: {failed}")
        print(f"  Total operations: {successful * 5}")
        print(f"  Rate: {(successful * 5)/elapsed:.2f} updates/sec")
        
        # Cleanup
        for s in students:
            await s.close_session()
        
        return successful, failed
    
    async def test_read_while_write(self):
        """Test reading notebooks while others are being written"""
        print("\nTesting concurrent reads during writes...")
        
        # Setup one student with a notebook
        writer = StudentSimulator(1, 'student1@test.edu', 'TestPass1!23', self.base_url)
        await writer.setup_session()
        await writer.login()
        nb_id = await writer.create_notebook()
        
        # Setup reader students
        readers = []
        for i in range(2, min(self.num_students + 1, 21)):
            student = StudentSimulator(
                i,
                f'student{i}@test.edu',
                f'TestPass{i}!23',
                self.base_url
            )
            await student.setup_session()
            await student.login()
            # Each reader also needs their own notebook to read
            reader_nb = await student.create_notebook()
            readers.append((student, reader_nb))
        
        # Start: writer updates continuously, readers read continuously
        start = time.time()
        
        async def continuous_write():
            for _ in range(10):
                await writer.update_notebook(nb_id, iterations=1)
                await asyncio.sleep(0.1)
        
        async def continuous_read(student, nb_id):
            reads = 0
            for _ in range(10):
                success = await student.read_notebook(nb_id)
                if success:
                    reads += 1
                await asyncio.sleep(0.1)
            return reads
        
        write_task = asyncio.create_task(continuous_write())
        read_tasks = [continuous_read(s, nb_id) for s, nb_id in readers]
        
        read_results = await asyncio.gather(*read_tasks)
        await write_task
        
        elapsed = time.time() - start
        
        total_reads = sum(read_results)
        print(f"  Completed {total_reads} reads while performing 10 writes in {elapsed:.2f}s")
        print(f"  Read rate: {total_reads/elapsed:.2f} reads/sec")
        
        self.results['concurrent_reads'] = total_reads
        
        # Cleanup
        await writer.close_session()
        for s, _ in readers:
            await s.close_session()
        
        return total_reads
    
    async def test_notebook_size_scaling(self):
        """Test performance with increasingly large notebooks"""
        print("\nTesting notebook size scaling...")
        
        student = StudentSimulator(1, 'student1@test.edu', 'TestPass1!23', self.base_url)
        await student.setup_session()
        await student.login()
        
        sizes = [10, 50, 100, 200]  # Number of cells
        
        for size in sizes:
            # Create large notebook
            large_notebook = json.loads(json.dumps(SAMPLE_NOTEBOOK))
            large_notebook['cells'] = [
                {
                    "cell_type": "code",
                    "execution_count": None,
                    "metadata": {},
                    "outputs": [],
                    "source": [f"# Cell {i}\n", f"data_{i} = list(range({i * 100}))\n"]
                }
                for i in range(size)
            ]
            large_notebook['metadata']['chalk_name'] = f"Large_{size}_cells.ipynb"
            
            # Test create
            if not student.csrf_token:
                await student.get_csrf_token()
            
            headers = {'X-CSRF': student.csrf_token, 'Content-Type': 'application/json'}
            payload = {'content': large_notebook}
            
            start = time.time()
            async with student.session.post(
                f"{self.base_url}/api/notebooks",
                json=payload,
                headers=headers
            ) as resp:
                create_time = time.time() - start
                if resp.status == 200:
                    data = await resp.json()
                    nb_id = data.get('id')
                    
                    # Test read
                    start = time.time()
                    async with student.session.get(
                        f"{self.base_url}/api/notebooks/{nb_id}"
                    ) as read_resp:
                        read_time = time.time() - start
                        
                        print(f"  {size:3d} cells: Create={create_time:.3f}s, Read={read_time:.3f}s")
        
        await student.close_session()
    
    async def run_all_tests(self):
        """Run all stress tests"""
        print(f"\n{'='*60}")
        print(f"NOTEBOOK STRESS TEST")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        await self.test_concurrent_writes()
        await self.test_concurrent_updates()
        await self.test_read_while_write()
        await self.test_notebook_size_scaling()
        
        total_time = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"STRESS TEST COMPLETED in {total_time:.2f}s")
        print(f"{'='*60}")
        
        # Overall assessment
        if (self.results['concurrent_writes'] >= self.num_students * 0.95 and
            self.results['concurrent_reads'] >= 100):
            print("✅ EXCELLENT: Notebook system handles concurrent load well!")
        elif (self.results['concurrent_writes'] >= self.num_students * 0.80):
            print("⚠️  ACCEPTABLE: System works but may struggle under heavy load")
        else:
            print("❌ POOR: Notebook system needs optimization for concurrent users")


async def main():
    import argparse
    parser = argparse.ArgumentParser(description='Stress test notebook operations')
    parser.add_argument('--url', default='http://localhost:5000', help='Base URL')
    parser.add_argument('--students', type=int, default=50, help='Number of students')
    args = parser.parse_args()
    
    tester = NotebookStressTest(args.url, args.students)
    await tester.run_all_tests()


if __name__ == '__main__':
    asyncio.run(main())
