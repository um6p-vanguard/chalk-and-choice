#!/usr/bin/env python3
"""Test proficiency code execution to debug the None issue."""

# Simulate the code execution environment
code_text = """def factorial(n):
    # Your recursive code here
    if n == 0:
        return 1
    return n * factorial(n-1)
"""

# Test 1: Simple exec/eval
print("Test 1: Simple exec/eval")
env = {"__builtins__": __builtins__}
exec(code_text, env, env)
result = eval("factorial(0)", env, env)
print(f"factorial(0) = {result}")
print(f"Type: {type(result)}")
print()

# Test 2: Using dict copy like in the code
print("Test 2: With dict copy")
env_base = {"__builtins__": __builtins__}
exec(code_text, env_base, env_base)
env = dict(env_base)
result = eval("factorial(5)", env, env)
print(f"factorial(5) = {result}")
print(f"Type: {type(result)}")
print()

# Test 3: Check what's in env_base
print("Test 3: Check environment contents")
env_base = {"__builtins__": __builtins__}
exec(code_text, env_base, env_base)
print(f"Keys in env_base: {[k for k in env_base.keys() if not k.startswith('__')]}")
print(f"'factorial' in env_base: {'factorial' in env_base}")
if 'factorial' in env_base:
    print(f"factorial function: {env_base['factorial']}")
    print(f"Calling directly: {env_base['factorial'](3)}")
print()

# Test 4: Using safe_env simulation
print("Test 4: Using safe_env-like dict")
import builtins

UNSAFE_BUILTINS = {
    "__import__", "eval", "exec", "compile", "open", 
    "help", "quit", "exit", "globals", "locals", "vars",
    "dir", "input", "breakpoint",
}

REQUIRED_DUNDER_BUILTINS = {"__build_class__", "__name__"}

def build_safe_builtins():
    safe = {}
    for name in dir(builtins):
        if name.startswith("_") and name not in REQUIRED_DUNDER_BUILTINS:
            continue
        if name in UNSAFE_BUILTINS:
            continue
        safe[name] = getattr(builtins, name)
    return safe

safe_builtins = build_safe_builtins()

env_base = {"__builtins__": dict(safe_builtins)}
exec(code_text, env_base, env_base)
env = dict(env_base)
result = eval("factorial(4)", env, env)
print(f"factorial(4) = {result}")
print(f"Type: {type(result)}")
print(f"Result is None: {result is None}")
