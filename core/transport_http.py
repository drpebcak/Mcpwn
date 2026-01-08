"""Streamable-HTTP transport implementation for MCP protocol"""

import http.client
import json
import logging
import threading
import time
import urllib.parse

from core.transport import Transport

logger = logging.getLogger("mcpwn")

DEFAULT_HTTP_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_INITIAL_BACKOFF = 0.5  # seconds
DEFAULT_BACKOFF_MULTIPLIER = 2.0
DEFAULT_MAX_BACKOFF = 10.0  # seconds

# Errors that should trigger a retry
RETRYABLE_ERRORS = (
    ConnectionError,
    ConnectionResetError,
    ConnectionAbortedError,
    ConnectionRefusedError,
    http.client.HTTPException,
    OSError,
    IOError,
    TimeoutError,
)


class HTTPTransport(Transport):
    """HTTP-based transport using streamable-http protocol with retry logic"""

    def __init__(
        self,
        url,
        max_retries=DEFAULT_MAX_RETRIES,
        initial_backoff=DEFAULT_INITIAL_BACKOFF,
        backoff_multiplier=DEFAULT_BACKOFF_MULTIPLIER,
        max_backoff=DEFAULT_MAX_BACKOFF,
    ):
        """
        Initialize HTTP transport

        Args:
            url: Full URL to MCP server endpoint (e.g., http://localhost:8080/mcp)
            max_retries: Maximum number of retry attempts (default: 3)
            initial_backoff: Initial backoff delay in seconds (default: 0.5)
            backoff_multiplier: Multiplier for exponential backoff (default: 2.0)
            max_backoff: Maximum backoff delay in seconds (default: 10.0)
        """
        self.url = url
        parsed = urllib.parse.urlparse(url)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.path = parsed.path or "/"
        self.connection = None
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self._request_id = 0
        self._session_id = None

        # Retry configuration
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff
        self.backoff_multiplier = backoff_multiplier
        self.max_backoff = max_backoff

        if self.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme: {self.scheme}")

    def start(self):
        """Initialize HTTP connection"""
        try:
            if self.scheme == "https":
                self.connection = http.client.HTTPSConnection(
                    self.host, self.port, timeout=DEFAULT_HTTP_TIMEOUT
                )
            else:
                self.connection = http.client.HTTPConnection(
                    self.host, self.port, timeout=DEFAULT_HTTP_TIMEOUT
                )
        except (OSError, http.client.HTTPException) as e:
            raise RuntimeError(f"Failed to connect to HTTP server: {e}")

    def stop(self):
        """Close HTTP connection"""
        if self.connection:
            try:
                self.connection.close()
            except Exception as e:
                logger.error("Connection close failed: %s", e, exc_info=True)
            finally:
                self.connection = None

    def is_alive(self):
        """Check if HTTP connection is operational"""
        # For HTTP, we consider it alive if connection object exists
        # Actual connectivity is checked on each request
        return self.connection is not None

    def get_next_request_id(self):
        """Get next request ID (thread-safe)"""
        with self.lock:
            self._request_id += 1
            return self._request_id

    def _calculate_backoff(self, attempt):
        """
        Calculate exponential backoff delay for retry attempt

        Args:
            attempt: Current attempt number (0-indexed)

        Returns:
            float: Backoff delay in seconds
        """
        backoff = self.initial_backoff * (self.backoff_multiplier**attempt)
        return min(backoff, self.max_backoff)

    def _reconnect(self):
        """Recreate HTTP connection after failure"""
        try:
            if self.connection:
                try:
                    self.connection.close()
                except Exception:
                    pass  # Ignore errors during cleanup

            if self.scheme == "https":
                self.connection = http.client.HTTPSConnection(
                    self.host, self.port, timeout=DEFAULT_HTTP_TIMEOUT
                )
            else:
                self.connection = http.client.HTTPConnection(
                    self.host, self.port, timeout=DEFAULT_HTTP_TIMEOUT
                )
        except (OSError, http.client.HTTPException) as e:
            raise RuntimeError(f"Failed to reconnect to HTTP server: {e}")

    def _make_http_request(self, json_rpc_msg, timeout):
        """
        Make HTTP POST request with JSON-RPC payload (with retry logic)

        Returns:
            tuple: (response_dict, elapsed_time)
        """
        if not self.connection:
            raise RuntimeError("HTTP connection not initialized")

        body = json.dumps(json_rpc_msg)
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }

        # Add session ID if established (for stateful servers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        start = time.time()
        last_error = None

        # Retry loop with exponential backoff
        for attempt in range(self.max_retries + 1):
            try:
                # Set timeout for this specific request
                self.connection.timeout = timeout

                self.connection.request("POST", self.path, body=body, headers=headers)
                response = self.connection.getresponse()

                # Read response body
                response_body = response.read().decode("utf-8")
                elapsed = time.time() - start

                # Check for session ID in response headers (try both variants)
                session_id = response.getheader("Mcp-Session-Id") or response.getheader(
                    "X-MCP-Session-ID"
                )
                if session_id:
                    self._session_id = session_id

                # Check HTTP status - 5xx errors are retryable, 4xx are not
                if response.status >= 500:
                    error_msg = f"HTTP error {response.status}: {response.reason}"
                    if attempt < self.max_retries:
                        logger.warning(
                            f"{error_msg} (attempt {attempt + 1}/{self.max_retries + 1})"
                        )
                        last_error = RuntimeError(error_msg)
                        # Reconnect before retry
                        self._reconnect()
                        # Calculate and apply backoff
                        backoff = self._calculate_backoff(attempt)
                        time.sleep(backoff)
                        continue
                    else:
                        raise RuntimeError(error_msg)
                elif response.status != 200:
                    # 4xx errors are not retryable (client error)
                    raise RuntimeError(
                        f"HTTP error {response.status}: {response.reason}"
                    )

                # Parse JSON response
                try:
                    parsed = json.loads(response_body)
                except (json.JSONDecodeError, ValueError) as e:
                    logger.debug(f"JSON parse error: {e}")
                    parsed = response_body

                # Success - log retry info if this wasn't the first attempt
                if attempt > 0:
                    logger.info(f"Request succeeded after {attempt + 1} attempts")

                return parsed, elapsed

            except RETRYABLE_ERRORS as e:
                last_error = e

                # Check if we should retry
                if attempt < self.max_retries:
                    error_type = type(e).__name__
                    logger.warning(
                        f"{error_type}: {e} (attempt {attempt + 1}/{self.max_retries + 1}, "
                        f"retrying...)"
                    )

                    # Reconnect before retry
                    try:
                        self._reconnect()
                    except Exception as reconnect_error:
                        logger.warning(f"Reconnection failed: {reconnect_error}")

                    # Calculate and apply exponential backoff
                    backoff = self._calculate_backoff(attempt)
                    logger.debug(f"Backing off for {backoff:.2f}s before retry")
                    time.sleep(backoff)
                else:
                    # No more retries - raise the error
                    logger.error(
                        f"Request failed after {self.max_retries + 1} attempts: {e}"
                    )
                    if isinstance(e, TimeoutError):
                        raise TimeoutError(f"HTTP request timeout after {timeout}s")
                    elif isinstance(e, http.client.HTTPException):
                        raise RuntimeError(f"HTTP request failed: {e}")
                    elif isinstance(e, (IOError, OSError)):
                        raise RuntimeError(f"Network error: {e}")
                    else:
                        raise RuntimeError(f"Request failed: {e}")

        # Should not reach here, but just in case
        if last_error:
            raise RuntimeError(f"Request failed after all retries: {last_error}")
        raise RuntimeError("Request failed for unknown reason")

    def send_notification(self, method, params):
        """
        Send JSON-RPC notification via HTTP

        Note: HTTP is request-response, so we send notification as a request
        but don't wait for meaningful response
        """
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}

        with self.send_lock:
            try:
                # Use short timeout for notifications since we don't care about response
                self._make_http_request(msg, timeout=5)
            except (RuntimeError, TimeoutError) as e:
                logger.debug(f"Notification send failed (expected): {e}")

    def send_request(self, method, params, timeout):
        """Send JSON-RPC request via HTTP and wait for response"""
        req_id = self.get_next_request_id()
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}

        with self.send_lock:
            return self._make_http_request(msg, timeout)
