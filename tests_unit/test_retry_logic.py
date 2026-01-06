"""Unit tests for HTTP retry logic with exponential backoff"""

import http.client
import json
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

from core.transport_http import RETRYABLE_ERRORS, HTTPTransport


class TestRetryLogic(unittest.TestCase):
    """Test retry logic and exponential backoff"""

    def test_retry_configuration_defaults(self):
        """Test default retry configuration values"""
        transport = HTTPTransport("http://localhost:8080")
        self.assertEqual(transport.max_retries, 3)
        self.assertEqual(transport.initial_backoff, 0.5)
        self.assertEqual(transport.backoff_multiplier, 2.0)
        self.assertEqual(transport.max_backoff, 10.0)

    def test_retry_configuration_custom(self):
        """Test custom retry configuration"""
        transport = HTTPTransport(
            "http://localhost:8080",
            max_retries=5,
            initial_backoff=1.0,
            backoff_multiplier=3.0,
            max_backoff=30.0,
        )
        self.assertEqual(transport.max_retries, 5)
        self.assertEqual(transport.initial_backoff, 1.0)
        self.assertEqual(transport.backoff_multiplier, 3.0)
        self.assertEqual(transport.max_backoff, 30.0)

    def test_backoff_calculation(self):
        """Test exponential backoff calculation"""
        transport = HTTPTransport(
            "http://localhost:8080",
            initial_backoff=1.0,
            backoff_multiplier=2.0,
            max_backoff=10.0,
        )

        # Test exponential growth
        self.assertEqual(transport._calculate_backoff(0), 1.0)  # 1.0 * 2^0
        self.assertEqual(transport._calculate_backoff(1), 2.0)  # 1.0 * 2^1
        self.assertEqual(transport._calculate_backoff(2), 4.0)  # 1.0 * 2^2
        self.assertEqual(transport._calculate_backoff(3), 8.0)  # 1.0 * 2^3

        # Test max backoff cap
        self.assertEqual(transport._calculate_backoff(4), 10.0)  # Capped at max_backoff
        self.assertEqual(transport._calculate_backoff(5), 10.0)

    def test_backoff_calculation_different_multiplier(self):
        """Test backoff calculation with different multiplier"""
        transport = HTTPTransport(
            "http://localhost:8080",
            initial_backoff=0.5,
            backoff_multiplier=3.0,
            max_backoff=20.0,
        )

        self.assertEqual(transport._calculate_backoff(0), 0.5)  # 0.5 * 3^0
        self.assertEqual(transport._calculate_backoff(1), 1.5)  # 0.5 * 3^1
        self.assertEqual(transport._calculate_backoff(2), 4.5)  # 0.5 * 3^2
        self.assertEqual(transport._calculate_backoff(3), 13.5)  # 0.5 * 3^3
        self.assertEqual(transport._calculate_backoff(4), 20.0)  # Capped

    @patch("core.transport_http.time.sleep")
    def test_retry_on_connection_error(self, mock_sleep):
        """Test retry logic triggers on connection errors"""
        transport = HTTPTransport(
            "http://localhost:8080", max_retries=2, initial_backoff=0.5
        )

        # Mock connection to fail then succeed
        mock_connection = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        mock_response.getheader.return_value = None

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise ConnectionError("Connection failed")
            return None

        mock_connection.request.side_effect = side_effect
        mock_connection.getresponse.return_value = mock_response
        transport.connection = mock_connection

        # Mock reconnect to not fail
        with patch.object(transport, "_reconnect"):
            # Make request - should retry and succeed
            msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}
            result, elapsed = transport._make_http_request(msg, timeout=10)

            # Verify retry happened
            self.assertEqual(call_count[0], 2)
            mock_sleep.assert_called_once()
            self.assertEqual(mock_sleep.call_args[0][0], 0.5)  # First backoff

    @patch("core.transport_http.time.sleep")
    def test_retry_exhaustion(self, mock_sleep):
        """Test that retries are exhausted and error is raised"""
        transport = HTTPTransport(
            "http://localhost:8080", max_retries=2, initial_backoff=0.5
        )

        # Mock connection to always fail
        mock_connection = MagicMock()
        mock_connection.request.side_effect = ConnectionError("Connection failed")
        transport.connection = mock_connection

        msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}

        # Mock reconnect to not fail
        with patch.object(transport, "_reconnect"):
            # Should raise after exhausting retries
            with self.assertRaises(RuntimeError) as context:
                transport._make_http_request(msg, timeout=10)

            self.assertIn("Network error", str(context.exception))

            # Should have slept for backoff on each retry (2 retries = 2 sleeps)
            self.assertEqual(mock_sleep.call_count, 2)

    @patch("core.transport_http.time.sleep")
    def test_exponential_backoff_progression(self, mock_sleep):
        """Test that backoff increases exponentially on retries"""
        transport = HTTPTransport(
            "http://localhost:8080",
            max_retries=3,
            initial_backoff=1.0,
            backoff_multiplier=2.0,
        )

        # Mock connection to always fail
        mock_connection = MagicMock()
        mock_connection.request.side_effect = ConnectionError("Connection failed")
        transport.connection = mock_connection

        msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}

        with patch.object(transport, "_reconnect"):
            with self.assertRaises(RuntimeError):
                transport._make_http_request(msg, timeout=10)

            # Verify exponential backoff: 1.0, 2.0, 4.0
            self.assertEqual(mock_sleep.call_count, 3)
            self.assertEqual(mock_sleep.call_args_list[0][0][0], 1.0)
            self.assertEqual(mock_sleep.call_args_list[1][0][0], 2.0)
            self.assertEqual(mock_sleep.call_args_list[2][0][0], 4.0)

    @patch("core.transport_http.time.sleep")
    def test_retry_on_timeout(self, mock_sleep):
        """Test retry logic triggers on timeout errors"""
        transport = HTTPTransport(
            "http://localhost:8080", max_retries=2, initial_backoff=0.5
        )

        mock_connection = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        mock_response.getheader.return_value = None

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise TimeoutError("Request timeout")
            return None

        mock_connection.request.side_effect = side_effect
        mock_connection.getresponse.return_value = mock_response
        transport.connection = mock_connection

        with patch.object(transport, "_reconnect"):
            msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}
            result, elapsed = transport._make_http_request(msg, timeout=10)

            # Verify retry happened
            self.assertEqual(call_count[0], 2)
            mock_sleep.assert_called_once_with(0.5)

    @patch("core.transport_http.time.sleep")
    def test_retry_on_http_exception(self, mock_sleep):
        """Test retry logic triggers on HTTP exceptions"""
        transport = HTTPTransport(
            "http://localhost:8080", max_retries=2, initial_backoff=0.5
        )

        mock_connection = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        mock_response.getheader.return_value = None

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise http.client.HTTPException("HTTP error")
            return None

        mock_connection.request.side_effect = side_effect
        mock_connection.getresponse.return_value = mock_response
        transport.connection = mock_connection

        with patch.object(transport, "_reconnect"):
            msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}
            result, elapsed = transport._make_http_request(msg, timeout=10)

            # Verify retry happened
            self.assertEqual(call_count[0], 2)
            mock_sleep.assert_called_once_with(0.5)

    @patch("core.transport_http.time.sleep")
    def test_retry_on_5xx_status(self, mock_sleep):
        """Test retry logic triggers on 5xx HTTP status codes"""
        transport = HTTPTransport(
            "http://localhost:8080", max_retries=2, initial_backoff=0.5
        )

        mock_connection = MagicMock()
        mock_response_fail = MagicMock()
        mock_response_fail.status = 503
        mock_response_fail.reason = "Service Unavailable"
        mock_response_fail.read.return_value = b"Service unavailable"

        mock_response_success = MagicMock()
        mock_response_success.status = 200
        mock_response_success.read.return_value = (
            b'{"jsonrpc":"2.0","id":1,"result":{}}'
        )
        mock_response_success.getheader.return_value = None

        call_count = [0]

        def side_effect():
            call_count[0] += 1
            if call_count[0] < 2:
                return mock_response_fail
            return mock_response_success

        mock_connection.getresponse.side_effect = side_effect
        mock_connection.request.return_value = None
        transport.connection = mock_connection

        with patch.object(transport, "_reconnect"):
            msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}
            result, elapsed = transport._make_http_request(msg, timeout=10)

            # Verify retry happened
            self.assertEqual(call_count[0], 2)
            mock_sleep.assert_called_once_with(0.5)
            self.assertEqual(result["id"], 1)

    @patch("core.transport_http.time.sleep")
    def test_no_retry_on_4xx_status(self, mock_sleep):
        """Test retry logic does NOT trigger on 4xx HTTP status codes"""
        transport = HTTPTransport(
            "http://localhost:8080", max_retries=2, initial_backoff=0.5
        )

        mock_connection = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 404
        mock_response.reason = "Not Found"
        mock_response.read.return_value = b"Not found"

        mock_connection.getresponse.return_value = mock_response
        mock_connection.request.return_value = None
        transport.connection = mock_connection

        msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}

        # Should raise immediately without retry
        with self.assertRaises(RuntimeError) as context:
            transport._make_http_request(msg, timeout=10)

        self.assertIn("404", str(context.exception))
        # Should NOT have retried (no sleep calls)
        mock_sleep.assert_not_called()

    def test_zero_retries(self):
        """Test that max_retries=0 means no retries"""
        transport = HTTPTransport("http://localhost:8080", max_retries=0)

        mock_connection = MagicMock()
        mock_connection.request.side_effect = ConnectionError("Connection failed")
        transport.connection = mock_connection

        msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}

        # Should fail immediately without retrying
        with self.assertRaises(RuntimeError):
            transport._make_http_request(msg, timeout=10)

        # Only 1 attempt (no retries)
        self.assertEqual(mock_connection.request.call_count, 1)

    @patch("core.transport_http.time.sleep")
    def test_reconnect_on_retry(self, mock_sleep):
        """Test that connection is recreated on retry"""
        transport = HTTPTransport(
            "http://localhost:8080", max_retries=2, initial_backoff=0.5
        )

        mock_connection = MagicMock()

        # First call fails, triggering retry and reconnect
        call_count = [0]

        def request_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionError("Connection failed")
            return None

        mock_connection.request.side_effect = request_side_effect

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        mock_response.getheader.return_value = None
        mock_connection.getresponse.return_value = mock_response

        transport.connection = mock_connection

        with patch.object(transport, "_reconnect") as mock_reconnect:
            msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}
            result, elapsed = transport._make_http_request(msg, timeout=10)

            # Verify reconnect was called
            mock_reconnect.assert_called_once()

    def test_max_backoff_cap(self):
        """Test that backoff is capped at max_backoff"""
        transport = HTTPTransport(
            "http://localhost:8080",
            initial_backoff=5.0,
            backoff_multiplier=10.0,
            max_backoff=15.0,
        )

        # Even with large multiplier, should cap at max_backoff
        self.assertEqual(transport._calculate_backoff(0), 5.0)
        self.assertEqual(transport._calculate_backoff(1), 15.0)  # Would be 50, capped
        self.assertEqual(transport._calculate_backoff(2), 15.0)  # Would be 500, capped


class TestRetryLoggingAndMetrics(unittest.TestCase):
    """Test retry logging and success metrics"""

    @patch("core.transport_http.time.sleep")
    @patch("core.transport_http.logger")
    def test_retry_logging(self, mock_logger, mock_sleep):
        """Test that retry attempts are logged"""
        transport = HTTPTransport(
            "http://localhost:8080", max_retries=2, initial_backoff=0.5
        )

        mock_connection = MagicMock()
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise ConnectionError("Connection failed")
            return None

        mock_connection.request.side_effect = side_effect
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        mock_response.getheader.return_value = None
        mock_connection.getresponse.return_value = mock_response

        transport.connection = mock_connection

        with patch.object(transport, "_reconnect"):
            msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}
            result, elapsed = transport._make_http_request(msg, timeout=10)

            # Verify warning was logged
            mock_logger.warning.assert_called()
            warning_call = mock_logger.warning.call_args_list[0][0][0]
            self.assertIn("ConnectionError", warning_call)
            self.assertIn("retrying", warning_call)

    @patch("core.transport_http.time.sleep")
    @patch("core.transport_http.logger")
    def test_success_after_retry_logging(self, mock_logger, mock_sleep):
        """Test that success after retry is logged"""
        transport = HTTPTransport(
            "http://localhost:8080", max_retries=2, initial_backoff=0.5
        )

        mock_connection = MagicMock()
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise ConnectionError("Connection failed")
            return None

        mock_connection.request.side_effect = side_effect
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        mock_response.getheader.return_value = None
        mock_connection.getresponse.return_value = mock_response

        transport.connection = mock_connection

        with patch.object(transport, "_reconnect"):
            msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}
            result, elapsed = transport._make_http_request(msg, timeout=10)

            # Verify success message was logged
            mock_logger.info.assert_called()
            info_call = mock_logger.info.call_args[0][0]
            self.assertIn("succeeded after", info_call)
            self.assertIn("2 attempts", info_call)


if __name__ == "__main__":
    unittest.main()
