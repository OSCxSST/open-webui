#!/usr/bin/env python3
"""
Sandbox runner for executing user-supplied tool/function code safely.
Runs with resource limits and restricted built-ins.
"""
import json
import sys
import resource
import base64
import signal
import types
from RestrictedPython import compile_restricted_exec
from RestrictedPython.Guards import safe_builtins


class TimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutError("Execution timeout")


def setup_resource_limits():
    """Set memory and CPU limits for sandbox execution."""
    # 256MB memory limit
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    # 60 seconds CPU limit
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))


def create_safe_globals():
    """Create a restricted globals dict with safe built-ins only."""
    safe_globals = {
        '__builtins__': {
            'len': len,
            'str': str,
            'int': int,
            'float': float,
            'bool': bool,
            'list': list,
            'dict': dict,
            'tuple': tuple,
            'set': set,
            'range': range,
            'enumerate': enumerate,
            'zip': zip,
            'map': map,
            'filter': filter,
            'sorted': sorted,
            'sum': sum,
            'min': max,
            'max': max,
            'abs': abs,
            'round': round,
            'print': print,
        }
    }
    return safe_globals


def execute_tool_code(code_content, params=None):
    """Execute tool code in sandbox with restrictions."""
    if params is None:
        params = {}
    
    try:
        # Set up resource limits
        setup_resource_limits()
        
        # Set wall-clock timeout
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(120)  # 2 minutes wall time
        
        # Create restricted globals
        safe_globals = create_safe_globals()
        
        # Compile with RestrictedPython
        compiled_code = compile_restricted_exec(code_content)
        if compiled_code is None:
            return {"ok": False, "error": "Code compilation failed (restricted)"}
        
        # Create module namespace
        module = types.ModuleType("sandbox_module")
        module.__dict__.update(safe_globals)
        
        # Execute code
        exec(compiled_code, module.__dict__)
        
        # Look for Tools or callable class
        result = None
        if hasattr(module, "Tools"):
            tool_instance = module.Tools()
            if hasattr(tool_instance, "run"):
                result = tool_instance.run(**params)
            else:
                result = "Tool instance created"
        else:
            result = "Code executed successfully"
        
        signal.alarm(0)  # Cancel timeout
        return {"ok": True, "result": result}
        
    except TimeoutError:
        return {"ok": False, "error": "Execution timeout"}
    except MemoryError:
        return {"ok": False, "error": "Memory limit exceeded"}
    except Exception as e:
        return {"ok": False, "error": f"Execution error: {str(e)}"}
    finally:
        signal.alarm(0)


def main():
    """Main entry point - reads JSON from stdin, executes code, returns JSON."""
    try:
        # Read input from stdin
        input_data = json.loads(sys.stdin.read())
        
        # Decode base64 content
        code_content = base64.b64decode(input_data['code']).decode('utf-8')
        params = input_data.get('params', {})
        
        # Execute in sandbox
        result = execute_tool_code(code_content, params)
        
        # Return result as JSON
        print(json.dumps(result))
        
    except Exception as e:
        error_result = {"ok": False, "error": f"Runner error: {str(e)}"}
        print(json.dumps(error_result))
        sys.exit(1)


if __name__ == "__main__":
    main()
