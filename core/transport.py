"""Transport abstraction layer for MCP protocol"""

from abc import ABC, abstractmethod


class Transport(ABC):
    """Abstract transport interface for MCP protocol"""

    @abstractmethod
    def send_request(self, method, params, timeout):
        """
        Send JSON-RPC request and return response with timing

        Args:
            method: JSON-RPC method name
            params: Method parameters dict
            timeout: Request timeout in seconds

        Returns:
            tuple: (response_dict, elapsed_time)

        Raises:
            RuntimeError: Communication or protocol error
            TimeoutError: Request timeout exceeded
        """
        pass

    @abstractmethod
    def send_notification(self, method, params):
        """
        Send JSON-RPC notification (no response expected)

        Args:
            method: JSON-RPC method name
            params: Method parameters dict

        Raises:
            RuntimeError: Communication error
        """
        pass

    @abstractmethod
    def is_alive(self):
        """
        Check if transport is operational

        Returns:
            bool: True if transport can send/receive, False otherwise
        """
        pass

    @abstractmethod
    def start(self):
        """
        Initialize transport connection

        Raises:
            RuntimeError: Failed to initialize transport
        """
        pass

    @abstractmethod
    def stop(self):
        """
        Close transport connection

        Note: Should not raise exceptions, log errors internally
        """
        pass

    @abstractmethod
    def get_next_request_id(self):
        """
        Get next request ID (thread-safe)

        Returns:
            int: Monotonically increasing request ID
        """
        pass
