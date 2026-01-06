#!/usr/bin/env python3
"""HTTP-based Deliberately Vulnerable MCP Server - For Testing Mcpwn"""

import http.server
import json
import logging
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("http-dvmcp")


class MCPHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for MCP JSON-RPC protocol"""

    def log_message(self, format, *args):
        """Override to use logger instead of stderr"""
        logger.info(format % args)

    def do_POST(self):
        """Handle HTTP POST with JSON-RPC payload"""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")

            request = json.loads(body)
            response = self.handle_jsonrpc(request)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))
        except Exception as e:
            logger.error(f"Request handling error: {e}", exc_info=True)
            self.send_error(500, str(e))

    def handle_jsonrpc(self, request):
        """Process JSON-RPC request"""
        method = request.get("method")
        params = request.get("params", {})
        req_id = request.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "dvmcp-http", "version": "1.0"},
                },
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "execute_command",
                            "description": "Execute shell command",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"command": {"type": "string"}},
                            },
                        },
                        {
                            "name": "read_file",
                            "description": "Read file contents",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                            },
                        },
                    ]
                },
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})

            if tool_name == "execute_command":
                # VULNERABLE: Direct command execution
                # nosec B602 - Intentionally vulnerable test server
                cmd = args.get("command", "")
                try:
                    result = subprocess.check_output(
                        cmd,
                        shell=True,  # nosec
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=5,
                    )
                except subprocess.TimeoutExpired:
                    result = "Command timeout"
                except Exception as e:
                    result = str(e)

                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": result}]},
                }

            elif tool_name == "read_file":
                # VULNERABLE: Path traversal
                path = args.get("path", "")
                try:
                    with open(path, "r") as f:
                        content = f.read()
                except Exception as e:
                    content = str(e)

                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": content}]},
                }

        elif method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"resources": []},
            }

        elif method == "resources/read":
            uri = params.get("uri", "")
            # VULNERABLE: Path traversal
            if uri.startswith("file://"):
                path = uri[7:]
                try:
                    with open(path, "r") as f:
                        content = f.read()
                except Exception as e:
                    content = str(e)

                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"contents": [{"uri": uri, "text": content}]},
                }

        # Default response for unhandled methods
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {},
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="HTTP-based Deliberately Vulnerable MCP Server"
    )
    parser.add_argument(
        "--host", default="localhost", help="Host to bind to (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Port to bind to (default: 8080)"
    )
    args = parser.parse_args()

    try:
        server = http.server.HTTPServer((args.host, args.port), MCPHTTPHandler)
        logger.info(f"HTTP MCP server listening on http://{args.host}:{args.port}")
        logger.info("Press Ctrl+C to stop")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        return 0
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
