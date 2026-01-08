"""SSE (Server-Sent Events) transport implementation for MCP protocol"""

import http.client
import json
import logging
import queue
import re
import threading
import time
import urllib.parse

from core.transport import Transport

logger = logging.getLogger("mcpwn")

DEFAULT_HTTP_TIMEOUT = 30
DEFAULT_CONNECTION_TIMEOUT = 10


class SSETransport(Transport):
    """SSE-based transport using Server-Sent Events for server-to-client messages"""

    def __init__(self, url):
        """
        Initialize SSE transport

        Args:
            url: Full URL to MCP server endpoint (e.g., http://localhost:8080/mcp)
        """
        self.url = url
        parsed = urllib.parse.urlparse(url)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.path = parsed.path or "/"
        self.connection = None
        self.sse_connection = None
        self.lock = threading.Lock()
        self._request_id = 0
        self._session_id = None
        self._message_queue = queue.Queue()
        self._sse_thread = None
        self._stop_sse = threading.Event()
        self._sse_connected = threading.Event()

        if self.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme: {self.scheme}")

    def start(self):
        """Initialize SSE connection and establish session"""
        try:
            # Create SSE connection for receiving messages
            if self.scheme == "https":
                self.sse_connection = http.client.HTTPSConnection(
                    self.host, self.port, timeout=DEFAULT_HTTP_TIMEOUT
                )
                self.connection = http.client.HTTPSConnection(
                    self.host, self.port, timeout=DEFAULT_HTTP_TIMEOUT
                )
            else:
                self.sse_connection = http.client.HTTPConnection(
                    self.host, self.port, timeout=DEFAULT_HTTP_TIMEOUT
                )
                self.connection = http.client.HTTPConnection(
                    self.host, self.port, timeout=DEFAULT_HTTP_TIMEOUT
                )

            # Start SSE stream to get session ID
            headers = {
                "Accept": "text/event-stream",
                "Cache-Control": "no-cache",
            }

            logger.debug(f"Opening SSE connection to {self.path}")
            self.sse_connection.request("GET", self.path, headers=headers)
            response = self.sse_connection.getresponse()

            if response.status != 200:
                error_body = response.read().decode("utf-8", errors="replace")
                raise RuntimeError(
                    f"SSE connection failed: {response.status} {response.reason} - {error_body}"
                )

            # Extract session ID from response headers
            session_id = response.getheader("Mcp-Session-Id")
            if session_id:
                self._session_id = session_id
                logger.debug(f"Received session ID: {session_id}")

            # Check content type
            content_type = response.getheader("Content-Type", "")
            if "text/event-stream" not in content_type:
                raise RuntimeError(f"Expected text/event-stream, got {content_type}")

            # Start thread to read SSE stream
            self._stop_sse.clear()
            self._sse_thread = threading.Thread(
                target=self._read_sse_stream, args=(response,), daemon=True
            )
            self._sse_thread.start()

            # Wait for SSE connection to be established
            if not self._sse_connected.wait(timeout=DEFAULT_CONNECTION_TIMEOUT):
                raise RuntimeError("SSE connection timeout")

            logger.debug("SSE transport started successfully")

        except (OSError, http.client.HTTPException) as e:
            raise RuntimeError(f"Failed to connect to SSE server: {e}")

    def stop(self):
        """Close SSE connection"""
        self._stop_sse.set()

        if self._sse_thread and self._sse_thread.is_alive():
            self._sse_thread.join(timeout=2)

        if self.sse_connection:
            try:
                self.sse_connection.close()
            except Exception as e:
                logger.debug(f"SSE connection close error: {e}")
            finally:
                self.sse_connection = None

        if self.connection:
            try:
                self.connection.close()
            except Exception as e:
                logger.debug(f"Connection close error: {e}")
            finally:
                self.connection = None

    def is_alive(self):
        """Check if SSE connection is operational"""
        return (
            self.connection is not None
            and self.sse_connection is not None
            and self._sse_thread is not None
            and self._sse_thread.is_alive()
            and not self._stop_sse.is_set()
        )

    def get_next_request_id(self):
        """Get next request ID (thread-safe)"""
        with self.lock:
            self._request_id += 1
            return self._request_id

    def _read_sse_stream(self, response):
        """
        Read SSE stream in background thread

        Args:
            response: HTTPResponse object from SSE connection
        """
        try:
            logger.debug("SSE stream reader started")
            self._sse_connected.set()

            buffer = ""
            event_type = None
            event_data = []

            while not self._stop_sse.is_set():
                try:
                    # Read line from stream
                    line = response.readline()
                    if not line:
                        logger.warning("SSE stream closed by server")
                        break

                    line = line.decode("utf-8", errors="replace").rstrip("\r\n")

                    # Empty line signals end of event
                    if not line:
                        if event_data:
                            data = "\n".join(event_data)
                            self._process_sse_event(event_type, data)
                            event_type = None
                            event_data = []
                        continue

                    # Parse SSE field
                    if ":" in line:
                        field, value = line.split(":", 1)
                        value = value.lstrip()

                        if field == "event":
                            event_type = value
                        elif field == "data":
                            event_data.append(value)
                        elif field == "id":
                            # Store last event ID for resumability
                            pass
                        elif field == "retry":
                            # Reconnection time in milliseconds
                            pass
                    else:
                        # Field with no colon
                        if line == "event":
                            event_type = None
                        elif line == "data":
                            event_data.append("")

                except Exception as e:
                    if not self._stop_sse.is_set():
                        logger.error(f"Error reading SSE stream: {e}", exc_info=True)
                    break

        except Exception as e:
            logger.error(f"SSE stream reader fatal error: {e}", exc_info=True)
        finally:
            logger.debug("SSE stream reader stopped")

    def _process_sse_event(self, event_type, data):
        """
        Process received SSE event

        Args:
            event_type: Event type (or None for 'message')
            data: Event data
        """
        try:
            # Parse JSON-RPC message
            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                logger.debug(f"Non-JSON SSE data: {data[:100]}")
                return

            # Queue JSON-RPC responses and notifications
            if "jsonrpc" in message:
                self._message_queue.put(message)
                logger.debug(
                    f"Queued SSE message: {message.get('method', message.get('id'))}"
                )
            else:
                logger.debug(f"Ignoring non-JSON-RPC message: {message}")

        except Exception as e:
            logger.error(f"Error processing SSE event: {e}", exc_info=True)

    def _make_http_request(self, json_rpc_msg, timeout):
        """
        Make HTTP POST request with JSON-RPC payload

        Returns:
            tuple: (response_dict, elapsed_time)
        """
        if not self.connection:
            raise RuntimeError("HTTP connection not initialized")

        body = json.dumps(json_rpc_msg)
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Accept": "application/json, text/event-stream",
        }

        # Add session ID if established
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        start = time.time()

        try:
            # Set timeout for this specific request
            self.connection.timeout = timeout

            self.connection.request("POST", self.path, body=body, headers=headers)
            response = self.connection.getresponse()

            # Read response body
            response_body = response.read().decode("utf-8")
            elapsed = time.time() - start

            # Check for session ID in response headers (first request)
            session_id = response.getheader("Mcp-Session-Id")
            if session_id and not self._session_id:
                self._session_id = session_id
                logger.debug(f"Received session ID from POST: {session_id}")

            # Check HTTP status
            if response.status == 202:
                # Accepted - wait for response via SSE
                logger.debug("Request accepted, waiting for SSE response")
                return None, elapsed
            elif response.status != 200:
                raise RuntimeError(
                    f"HTTP error {response.status}: {response.reason} - {response_body}"
                )

            # Parse JSON response (immediate response, not via SSE)
            try:
                parsed = json.loads(response_body)
            except (json.JSONDecodeError, ValueError) as e:
                logger.debug(f"JSON parse error: {e}")
                parsed = response_body

            return parsed, elapsed

        except (OSError, http.client.HTTPException, TimeoutError) as e:
            elapsed = time.time() - start
            if isinstance(e, TimeoutError):
                raise TimeoutError(f"HTTP request timeout after {timeout}s")
            raise RuntimeError(f"HTTP request failed: {e}")

    def send_notification(self, method, params):
        """
        Send JSON-RPC notification via HTTP POST

        Notifications don't expect a response
        """
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}

        with self.lock:
            try:
                # Use short timeout for notifications
                self._make_http_request(msg, timeout=5)
            except (RuntimeError, TimeoutError) as e:
                logger.debug(f"Notification send failed (expected): {e}")

    def send_request(self, method, params, timeout):
        """Send JSON-RPC request via HTTP POST and wait for response from SSE"""
        req_id = self.get_next_request_id()
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}

        with self.lock:
            # Clear any old messages from queue
            while not self._message_queue.empty():
                try:
                    old_msg = self._message_queue.get_nowait()
                    logger.debug(f"Discarding old queued message: {old_msg}")
                except queue.Empty:
                    break

            # Send request
            start = time.time()
            response, post_elapsed = self._make_http_request(msg, timeout)

            # If we got immediate response (not 202), return it
            if response is not None:
                return response, post_elapsed

            # Wait for response via SSE
            remaining_timeout = max(0, timeout - post_elapsed)
            try:
                while True:
                    try:
                        # Wait for message from SSE stream
                        sse_msg = self._message_queue.get(timeout=remaining_timeout)
                        elapsed = time.time() - start

                        # Check if this is the response we're waiting for
                        if sse_msg.get("id") == req_id:
                            return sse_msg, elapsed

                        # Not our response, put it back for potential other waiters
                        # or discard if it's a notification
                        if "id" in sse_msg:
                            logger.debug(
                                f"Response ID mismatch: expected {req_id}, got {sse_msg.get('id')}"
                            )
                        else:
                            logger.debug(
                                f"Received notification: {sse_msg.get('method')}"
                            )

                        # Update remaining timeout
                        elapsed = time.time() - start
                        remaining_timeout = max(0, timeout - elapsed)

                    except queue.Empty:
                        elapsed = time.time() - start
                        raise TimeoutError(f"SSE response timeout after {elapsed:.2f}s")

            except queue.Empty:
                elapsed = time.time() - start
                raise TimeoutError(f"SSE response timeout after {elapsed:.2f}s")
