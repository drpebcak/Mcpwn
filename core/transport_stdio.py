"""Stdio transport implementation for MCP protocol"""

import json
import logging
import select
import subprocess
import threading
import time

from core.transport import Transport

logger = logging.getLogger("mcpwn")

PROCESS_TERMINATION_TIMEOUT = 5


class StdioTransport(Transport):
    """Stdio-based transport using subprocess pipes"""

    def __init__(self, server_cmd):
        """
        Initialize stdio transport

        Args:
            server_cmd: Command array to launch MCP server subprocess
        """
        self.server_cmd = server_cmd
        self.proc = None
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self._request_id = 0

    def start(self):
        """Start MCP server subprocess"""
        try:
            self.proc = subprocess.Popen(
                self.server_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise RuntimeError(f"Failed to start MCP server: {e}")

    def stop(self):
        """Stop MCP server subprocess"""
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=PROCESS_TERMINATION_TIMEOUT)
            except subprocess.TimeoutExpired as e:
                logger.warning("Process cleanup timeout, forcing kill: %s", e)
                if self.proc:
                    try:
                        self.proc.kill()
                    except OSError as e:
                        logger.error("Process kill failed: %s", e, exc_info=True)
            except OSError as e:
                logger.error("Process termination failed: %s", e, exc_info=True)

    def is_alive(self):
        """Check if subprocess is running"""
        return self.proc is not None and self.proc.poll() is None

    def get_next_request_id(self):
        """Get next request ID (thread-safe)"""
        with self.lock:
            self._request_id += 1
            return self._request_id

    def send_notification(self, method, params):
        """Send JSON-RPC notification"""
        if not self.proc or not self.proc.stdin:
            raise RuntimeError("MCP server process not initialized")

        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}

        with self.send_lock:
            try:
                self.proc.stdin.write(json.dumps(msg) + "\n")
                self.proc.stdin.flush()
            except (IOError, OSError, BrokenPipeError) as e:
                raise RuntimeError(f"Communication with MCP server failed: {e}")

    def send_request(self, method, params, timeout):
        """Send JSON-RPC request and wait for response"""
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("MCP server process not initialized")

        req_id = self.get_next_request_id()
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}

        deadline = time.time() + timeout
        start = time.time()

        with self.send_lock:
            try:
                self.proc.stdin.write(json.dumps(msg) + "\n")
                self.proc.stdin.flush()

                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError(f"Server unresponsive after {timeout}s")

                try:
                    ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
                except (OSError, ValueError) as e:
                    raise RuntimeError(f"Select operation failed: {e}")

                if not ready:
                    raise TimeoutError(f"Server unresponsive after {timeout}s")

                try:
                    response_str = self.proc.stdout.readline()
                except (IOError, OSError) as e:
                    raise RuntimeError(f"Failed to read response: {e}")
            except (IOError, OSError, BrokenPipeError) as e:
                raise RuntimeError(f"Communication with MCP server failed: {e}")

        elapsed = time.time() - start

        try:
            parsed = json.loads(response_str) if response_str else {}
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug(f"JSON parse error: {e}")
            parsed = response_str

        return parsed, elapsed
