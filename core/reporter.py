"""Report generation for findings"""

import json
from datetime import datetime, timezone
from html import escape


class Reporter:
    """Generate structured reports from findings"""

    def __init__(self):
        self.findings = []

    def add_findings(self, test_name, findings):
        """Add findings from a test"""
        for finding in findings:
            finding["test"] = test_name
            finding["timestamp"] = datetime.now(timezone.utc).isoformat()
            self.findings.append(finding)

    def to_json(self, filepath):
        """Export findings as JSON"""
        report = {
            "tool": "Mcpwn",
            "version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": self.findings,
            "summary": {
                "total": len(self.findings),
                "by_type": self._count_by_type(),
                "by_severity": self.summary(),
            },
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

    def to_html(self, filepath):
        """Export findings as HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head><title>Mcpwn Report</title>
<style>
body {{ font-family: monospace; margin: 20px; }}
.finding {{ border: 1px solid #ccc; margin: 10px 0; padding: 10px; }}
.critical {{ background: #fee; }}
.high {{ background: #ffd; }}
</style>
</head>
<body>
<h1>Mcpwn Security Report</h1>
<p>Total Findings: {len(self.findings)}</p>
"""
        for f in self.findings:
            severity = escape(str(f.get("type", "INFO")))
            test_name = escape(str(f.get("test", "")))
            finding_json = escape(json.dumps(f, indent=2))
            html += f'<div class="finding {severity.lower()}">'
            html += f"<strong>{test_name}</strong><br>"
            html += f"<pre>{finding_json}</pre></div>"
        html += "</body></html>"

        with open(filepath, "w") as f:
            f.write(html)

    def _count_by_type(self):
        """Count findings by type"""
        counts = {}
        for f in self.findings:
            ftype = f.get("type", "UNKNOWN")
            counts[ftype] = counts.get(ftype, 0) + 1
        return counts

    def summary(self):
        """Return severity breakdown"""
        from collections import Counter

        severities = Counter(f.get("severity", "UNKNOWN") for f in self.findings)
        return dict(severities)

    def to_sarif(self, filepath):
        """Export findings as SARIF for CI/CD integration"""

        # Build rules catalog
        rules = self._build_sarif_rules()

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Mcpwn",
                            "version": "1.0",
                            "informationUri": "https://github.com/mcpwn/mcpwn",
                            "rules": rules,
                        }
                    },
                    "results": [self._to_sarif_result(f) for f in self.findings],
                }
            ],
        }
        with open(filepath, "w") as f:
            json.dump(sarif, f, indent=2)

    def _build_sarif_rules(self):
        """Build SARIF rules catalog with metadata for each finding type"""
        # Map finding types to CWE, descriptions, and help text
        rule_metadata = {
            "BLIND_RCE_TIMING": {
                "name": "Blind Remote Code Execution (Timing-based)",
                "shortDescription": "Server executes injected commands, detectable via timing delays",
                "fullDescription": 'The MCP server executes injected shell commands in tool arguments. This was detected through timing analysis when commands like "sleep" were injected and caused observable delays.',
                "help": "Implement strict input validation and sanitization. Use allowlists for permitted characters. Avoid passing user input directly to shell commands. Consider using parameterized APIs instead of shell execution.",
                "cwe": "78",
                "security_severity": "9.8",
                "precision": "high",
            },
            "RCE": {
                "name": "Remote Code Execution",
                "shortDescription": "Server executes arbitrary code from user input",
                "fullDescription": "The MCP server executes arbitrary code or commands provided through tool arguments without proper validation or sanitization.",
                "help": "Implement strict input validation. Use allowlists for permitted operations. Avoid dynamic code execution with user input. Apply principle of least privilege.",
                "cwe": "94",
                "security_severity": "10.0",
                "precision": "very-high",
            },
            "FILE_READ": {
                "name": "Arbitrary File Read",
                "shortDescription": "Unauthorized file system access through path manipulation",
                "fullDescription": "The MCP server allows reading arbitrary files through path traversal or insufficient access controls in file operation tools.",
                "help": 'Implement strict path validation. Use allowlists for permitted directories. Resolve paths canonically and check they remain within allowed boundaries. Reject paths containing ".." or absolute paths.',
                "cwe": "22",
                "security_severity": "7.5",
                "precision": "high",
            },
            "RESOURCE_TRAVERSAL": {
                "name": "Resource Path Traversal",
                "shortDescription": "Path traversal in resource URIs",
                "fullDescription": "The MCP server resource handlers do not properly validate URI paths, allowing access to resources outside intended boundaries through path traversal.",
                "help": "Validate and sanitize resource URIs. Reject URIs containing path traversal sequences. Use canonical path resolution.",
                "cwe": "22",
                "security_severity": "7.5",
                "precision": "high",
            },
            "CAPABILITY_VALIDATION_BYPASS": {
                "name": "Capability Validation Bypass",
                "shortDescription": "MCP protocol capability checks can be bypassed",
                "fullDescription": "The MCP server does not properly validate client capabilities, allowing clients to use features they should not have access to.",
                "help": "Implement proper capability validation. Check client capabilities before executing privileged operations. Follow MCP protocol specifications strictly.",
                "cwe": "862",
                "security_severity": "6.5",
                "precision": "medium",
            },
            "SUBSCRIPTION_DOS": {
                "name": "Subscription-based Denial of Service",
                "shortDescription": "Resource exhaustion through subscription flooding",
                "fullDescription": "The MCP server does not limit subscription requests, allowing clients to exhaust server resources through excessive subscriptions.",
                "help": "Implement rate limiting for subscriptions. Set maximum subscription counts per client. Add resource monitoring and automatic cleanup.",
                "cwe": "400",
                "security_severity": "5.0",
                "precision": "high",
            },
            "RACE_CREATION_COLLISION": {
                "name": "Race Condition in Resource Creation",
                "shortDescription": "Concurrent resource creation causes inconsistent state",
                "fullDescription": "The MCP server does not properly handle concurrent resource creation requests, leading to race conditions and potential data corruption.",
                "help": "Implement proper locking mechanisms. Use atomic operations for resource creation. Add uniqueness constraints at database level.",
                "cwe": "362",
                "security_severity": "4.0",
                "precision": "medium",
            },
            "UNHANDLED_DB_LOCK": {
                "name": "Unhandled Database Lock Error",
                "shortDescription": "Database lock errors not properly handled",
                "fullDescription": "The MCP server exposes internal database lock errors to clients without proper error handling.",
                "help": "Implement proper error handling for database operations. Add retry logic with exponential backoff. Avoid exposing internal implementation details.",
                "cwe": "209",
                "security_severity": "3.0",
                "precision": "low",
            },
            "PROMPT_INJECTION": {
                "name": "Prompt Injection Risk",
                "shortDescription": "Tool output may be used to manipulate LLM behavior",
                "fullDescription": "Tool responses contain instructions or structured content that could influence LLM decision-making if the MCP server is used with an LLM client.",
                "help": "Sanitize tool outputs before returning to LLM clients. Consider output encoding. Document that tool outputs should be treated as untrusted data by LLM systems.",
                "cwe": "74",
                "security_severity": "4.5",
                "precision": "low",
            },
        }

        # Build unique rules list from findings
        rule_ids = set()
        for finding in self.findings:
            rule_id = finding.get("type", finding.get("category", "UNKNOWN"))
            rule_ids.add(rule_id)

        rules = []
        for rule_id in sorted(rule_ids):
            metadata = rule_metadata.get(
                rule_id,
                {
                    "name": rule_id.replace("_", " ").title(),
                    "shortDescription": f"Security issue detected: {rule_id}",
                    "fullDescription": f"The MCP server has a security vulnerability classified as {rule_id}.",
                    "help": "Review the finding details and implement appropriate security controls.",
                    "cwe": "1035",  # Generic "Vulnerable Code" CWE
                    "security_severity": "5.0",
                    "precision": "medium",
                },
            )

            rule = {
                "id": rule_id,
                "name": metadata["name"],
                "shortDescription": {"text": metadata["shortDescription"]},
                "fullDescription": {"text": metadata["fullDescription"]},
                "help": {
                    "text": metadata["help"],
                    "markdown": f"## {metadata['name']}\n\n{metadata['fullDescription']}\n\n### Recommendation\n\n{metadata['help']}\n\n### References\n\n- [CWE-{metadata['cwe']}](https://cwe.mitre.org/data/definitions/{metadata['cwe']}.html)",
                },
                "properties": {
                    "tags": ["security", "mcp"],
                    "precision": metadata["precision"],
                    "security-severity": metadata["security_severity"],
                },
            }

            # Add CWE relationship
            if metadata["cwe"]:
                rule["relationships"] = [
                    {
                        "target": {
                            "id": metadata["cwe"],
                            "toolComponent": {
                                "name": "CWE",
                                "guid": "25F72D7E-8A92-459D-AD67-64853F788765",
                            },
                        },
                        "kinds": ["superset"],
                    }
                ]

            rules.append(rule)

        return rules

    def _to_sarif_result(self, finding):
        """Convert finding to SARIF result format"""
        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }

        # Build comprehensive message with tool call context
        message_parts = [
            f"{finding.get('test', 'test')}: {finding.get('type', 'issue')}"
        ]

        # Add tool call information if available
        if "tool" in finding and finding["tool"] != finding.get("test"):
            message_parts.append(f"Tool: {finding['tool']}")

        if "arg" in finding:
            message_parts.append(f"Argument: {finding['arg']}")

        if "payload" in finding:
            payload_str = str(finding["payload"])
            # Truncate very long payloads
            if len(payload_str) > 100:
                payload_str = payload_str[:97] + "..."
            message_parts.append(f"Payload: {payload_str}")

        if "category" in finding:
            message_parts.append(f"Category: {finding['category']}")

        if "detections" in finding and finding["detections"]:
            detections = finding["detections"]
            if isinstance(detections, list) and detections:
                message_parts.append(
                    f"Detections: {', '.join(str(d) for d in detections)}"
                )

        message_text = " | ".join(message_parts)

        # Build properties object with structured data
        properties = {}
        if "tool" in finding:
            properties["tool_name"] = finding["tool"]
        if "arg" in finding:
            properties["argument_path"] = finding["arg"]
        if "payload" in finding:
            properties["payload"] = str(finding["payload"])
        if "category" in finding:
            properties["vulnerability_category"] = finding["category"]
        if "detections" in finding:
            properties["detections"] = finding["detections"]
        if "uri" in finding:
            properties["resource_uri"] = finding["uri"]
        if "risk" in finding:
            properties["risk_assessment"] = finding["risk"]

        result = {
            "ruleId": finding.get("type", finding.get("category", "UNKNOWN")),
            "level": severity_map.get(finding.get("severity", "MEDIUM"), "warning"),
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("tool", finding.get("test", "unknown"))
                        }
                    }
                }
            ],
        }

        # Add rank for result prioritization (0.0 to 100.0, higher = more important)
        severity_rank = {"CRITICAL": 95.0, "HIGH": 80.0, "MEDIUM": 50.0, "LOW": 20.0}
        result["rank"] = severity_rank.get(finding.get("severity", "MEDIUM"), 50.0)

        # Add partial fingerprints for result tracking across scans
        # Use a combination of test, type, tool, and arg for stable identity
        fingerprint_parts = [
            finding.get("test", ""),
            finding.get("type", ""),
            finding.get("tool", ""),
            finding.get("arg", ""),
        ]
        fingerprint_base = "/".join(str(p) for p in fingerprint_parts if p)

        # Generate a simple hash-like value from the fingerprint base
        fingerprint_hash = str(hash(fingerprint_base) & 0xFFFFFFFF)
        result["partialFingerprints"] = {"primaryLocationLineHash": fingerprint_hash}

        # Add properties if we have any
        if properties:
            result["properties"] = properties

        # Add timestamp if available
        if "timestamp" in finding:
            result["properties"] = result.get("properties", {})
            result["properties"]["timestamp"] = finding["timestamp"]

        return result
