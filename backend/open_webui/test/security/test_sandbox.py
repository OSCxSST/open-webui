"""
Security tests for sandbox execution to prevent RCE vulnerabilities.
"""
import pytest
import asyncio
import json
import base64
import subprocess
import sys
from unittest.mock import patch

from open_webui.utils.plugin import execute_in_sandbox


class TestSandboxSecurity:
    """Test cases to verify sandbox prevents RCE attacks."""
    
    @pytest.mark.asyncio
    async def test_file_access_blocked(self):
        """Test that sandbox blocks file system access."""
        malicious_code = '''
import os
class Tools:
    def run(self):
        return open("/etc/passwd").read()
'''
        result = await execute_in_sandbox(malicious_code)
        assert not result.get("ok", True), "File access should be blocked"
        assert "error" in result
    
    @pytest.mark.asyncio 
    async def test_network_access_blocked(self):
        """Test that sandbox blocks network access."""
        malicious_code = '''
import socket
class Tools:
    def run(self):
        s = socket.socket()
        s.connect(("google.com", 80))
        return "connected"
'''
        result = await execute_in_sandbox(malicious_code)
        assert not result.get("ok", True), "Network access should be blocked"
        assert "error" in result
    
    @pytest.mark.asyncio
    async def test_subprocess_blocked(self):
        """Test that sandbox blocks subprocess execution."""
        malicious_code = '''
import subprocess
class Tools:
    def run(self):
        return subprocess.check_output(["whoami"]).decode()
'''
        result = await execute_in_sandbox(malicious_code)
        assert not result.get("ok", True), "Subprocess should be blocked"
        assert "error" in result
        
    @pytest.mark.asyncio
    async def test_os_system_blocked(self):
        """Test that sandbox blocks os.system calls."""
        malicious_code = '''
import os
class Tools:
    def run(self):
        os.system("touch /tmp/pwned")
        return "executed"
'''
        result = await execute_in_sandbox(malicious_code)
        assert not result.get("ok", True), "os.system should be blocked"
        assert "error" in result
        
    @pytest.mark.asyncio
    async def test_safe_code_works(self):
        """Test that legitimate code still works in sandbox."""
        safe_code = '''
class Tools:
    def run(self):
        return "Hello, safe world!"
'''
        result = await execute_in_sandbox(safe_code)
        assert result.get("ok", False), "Safe code should execute"
        assert result.get("result") == "Hello, safe world!"
        
    @pytest.mark.asyncio
    async def test_memory_limit_enforced(self):
        """Test that memory limits are enforced."""
        memory_bomb = '''
class Tools:
    def run(self):
        big_list = [0] * (500 * 1024 * 1024)  # Try to allocate 500MB
        return len(big_list)
'''
        result = await execute_in_sandbox(memory_bomb)
        assert not result.get("ok", True), "Memory bomb should be blocked"
        assert "error" in result
        
    @pytest.mark.asyncio
    async def test_timeout_enforced(self):
        """Test that execution timeout is enforced."""
        infinite_loop = '''
class Tools:
    def run(self):
        while True:
            pass
        return "never reached"
'''
        result = await execute_in_sandbox(infinite_loop)
        assert not result.get("ok", True), "Infinite loop should timeout"
        assert "timeout" in result.get("error", "").lower()


if __name__ == "__main__":
    pytest.main([__file__])
