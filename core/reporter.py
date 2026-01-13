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
                        }
                    },
                    "results": [self._to_sarif_result(f) for f in self.findings],
                }
            ],
        }
        with open(filepath, "w") as f:
            json.dump(sarif, f, indent=2)

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

        # Add properties if we have any
        if properties:
            result["properties"] = properties

        return result
