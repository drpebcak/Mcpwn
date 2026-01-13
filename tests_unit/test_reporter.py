"""Unit tests for reporter"""

import json
import os
import tempfile

import pytest

from core.reporter import Reporter


def test_reporter_initialization():
    """Test reporter initializes correctly"""
    reporter = Reporter()
    assert reporter.findings == []


def test_add_findings():
    """Test adding findings"""
    reporter = Reporter()
    findings = [
        {"type": "RCE", "severity": "CRITICAL"},
        {"type": "FILE_READ", "severity": "HIGH"},
    ]
    reporter.add_findings("test", findings)

    assert len(reporter.findings) == 2
    assert all("test" in str(f) for f in reporter.findings)


def test_json_export():
    """Test JSON report export"""
    reporter = Reporter()
    reporter.add_findings("test", [{"type": "RCE", "severity": "CRITICAL"}])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        report_file = f.name

    try:
        reporter.to_json(report_file)
        assert os.path.exists(report_file)

        with open(report_file) as f:
            report = json.load(f)

        assert "tool" in report
        assert "findings" in report
        assert "summary" in report
        assert report["summary"]["total"] == 1
    finally:
        os.unlink(report_file)


def test_html_export():
    """Test HTML report export"""
    reporter = Reporter()
    reporter.add_findings("test", [{"type": "RCE", "severity": "CRITICAL"}])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
        report_file = f.name

    try:
        reporter.to_html(report_file)
        assert os.path.exists(report_file)

        with open(report_file) as f:
            html = f.read()

        assert "Mcpwn" in html
        assert "RCE" in html
    finally:
        os.unlink(report_file)


def test_sarif_export():
    """Test SARIF report export"""
    reporter = Reporter()
    reporter.add_findings("test", [{"type": "RCE", "severity": "CRITICAL"}])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        report_file = f.name

    try:
        reporter.to_sarif(report_file)
        assert os.path.exists(report_file)

        with open(report_file) as f:
            sarif = json.load(f)

        assert "version" in sarif
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
    finally:
        os.unlink(report_file)


def test_severity_summary():
    """Test severity aggregation"""
    reporter = Reporter()
    reporter.add_findings(
        "test",
        [
            {"type": "RCE", "severity": "CRITICAL"},
            {"type": "XSS", "severity": "HIGH"},
            {"type": "INFO", "severity": "LOW"},
        ],
    )

    summary = reporter.summary()
    assert summary["CRITICAL"] == 1
    assert summary["HIGH"] == 1
    assert summary["LOW"] == 1


def test_type_counting():
    """Test finding type counting"""
    reporter = Reporter()
    reporter.add_findings(
        "test",
        [
            {"type": "RCE", "severity": "CRITICAL"},
            {"type": "RCE", "severity": "HIGH"},
            {"type": "FILE_READ", "severity": "MEDIUM"},
        ],
    )

    counts = reporter._count_by_type()
    assert counts["RCE"] == 2
    assert counts["FILE_READ"] == 1


def test_sarif_tool_call_context():
    """Test SARIF export includes tool call context"""
    reporter = Reporter()

    # Simulate a tool injection finding with full context
    reporter.add_findings(
        "tool_injection",
        [
            {
                "type": "BLIND_RCE_TIMING",
                "severity": "CRITICAL",
                "tool": "execute_command",
                "arg": "command",
                "payload": "sleep 10",
                "category": "command_injection",
                "detections": ["Timing delay: 10.2s", "Sleep pattern detected"],
            }
        ],
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        report_file = f.name

    try:
        reporter.to_sarif(report_file)

        with open(report_file) as f:
            sarif = json.load(f)

        # Verify structure
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 1

        result = sarif["runs"][0]["results"][0]

        # Verify basic fields
        assert result["ruleId"] == "BLIND_RCE_TIMING"
        assert result["level"] == "error"

        # Verify message includes context
        message = result["message"]["text"]
        assert "Tool: execute_command" in message
        assert "Argument: command" in message
        assert "Payload: sleep 10" in message
        assert "Category: command_injection" in message
        assert "Detections:" in message

        # Verify properties object contains structured data
        assert "properties" in result
        props = result["properties"]
        assert props["tool_name"] == "execute_command"
        assert props["argument_path"] == "command"
        assert props["payload"] == "sleep 10"
        assert props["vulnerability_category"] == "command_injection"
        assert props["detections"] == ["Timing delay: 10.2s", "Sleep pattern detected"]

    finally:
        os.unlink(report_file)


def test_sarif_minimal_finding():
    """Test SARIF export with minimal finding data"""
    reporter = Reporter()
    reporter.add_findings("test", [{"type": "UNKNOWN"}])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        report_file = f.name

    try:
        reporter.to_sarif(report_file)

        with open(report_file) as f:
            sarif = json.load(f)

        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "UNKNOWN"
        assert "message" in result

    finally:
        os.unlink(report_file)


def test_sarif_payload_truncation():
    """Test SARIF export truncates long payloads"""
    reporter = Reporter()

    long_payload = "A" * 200
    reporter.add_findings(
        "test",
        [
            {
                "type": "TEST",
                "severity": "HIGH",
                "tool": "test_tool",
                "arg": "test_arg",
                "payload": long_payload,
            }
        ],
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        report_file = f.name

    try:
        reporter.to_sarif(report_file)

        with open(report_file) as f:
            sarif = json.load(f)

        result = sarif["runs"][0]["results"][0]
        message = result["message"]["text"]

        # Message should have truncated payload
        assert "..." in message
        assert len([part for part in message.split("|") if "Payload:" in part][0]) < 150

        # Properties should have full payload
        assert result["properties"]["payload"] == long_payload

    finally:
        os.unlink(report_file)


def test_sarif_enhanced_features():
    """Test SARIF export includes enhanced features (rules, rank, fingerprints)"""
    reporter = Reporter()

    reporter.add_findings(
        "tool_injection",
        [
            {
                "type": "BLIND_RCE_TIMING",
                "severity": "CRITICAL",
                "tool": "execute_command",
                "arg": "command",
                "payload": "; sleep 10",
                "category": "command_injection",
                "detections": ["Timing delay: 10.2s"],
            }
        ],
    )

    reporter.add_findings(
        "tool_injection",
        [
            {
                "type": "FILE_READ",
                "severity": "HIGH",
                "tool": "read_file",
                "arg": "path",
                "payload": "../../../etc/passwd",
            }
        ],
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        report_file = f.name

    try:
        reporter.to_sarif(report_file)

        with open(report_file) as f:
            sarif = json.load(f)

        # Check rules catalog exists
        driver = sarif["runs"][0]["tool"]["driver"]
        assert "rules" in driver
        assert len(driver["rules"]) == 2

        # Check rule metadata
        rce_rule = next(r for r in driver["rules"] if r["id"] == "BLIND_RCE_TIMING")
        assert rce_rule["name"] == "Blind Remote Code Execution (Timing-based)"
        assert "shortDescription" in rce_rule
        assert "fullDescription" in rce_rule
        assert "help" in rce_rule
        assert "markdown" in rce_rule["help"]
        assert "properties" in rce_rule
        assert rce_rule["properties"]["precision"] == "high"
        assert rce_rule["properties"]["security-severity"] == "9.8"
        assert "tags" in rce_rule["properties"]
        assert "security" in rce_rule["properties"]["tags"]

        # Check CWE relationships
        assert "relationships" in rce_rule
        assert rce_rule["relationships"][0]["target"]["id"] == "78"
        assert rce_rule["relationships"][0]["target"]["toolComponent"]["name"] == "CWE"

        # Check result enhancements
        results = sarif["runs"][0]["results"]
        assert len(results) == 2

        rce_result = results[0]
        assert rce_result["ruleId"] == "BLIND_RCE_TIMING"

        # Check rank
        assert "rank" in rce_result
        assert rce_result["rank"] == 95.0  # CRITICAL severity

        # Check fingerprints
        assert "partialFingerprints" in rce_result
        assert "primaryLocationLineHash" in rce_result["partialFingerprints"]

        # Check timestamp in properties
        assert "timestamp" in rce_result["properties"]

        # Verify different findings have different fingerprints
        file_read_result = results[1]
        assert file_read_result["rank"] == 80.0  # HIGH severity
        assert (
            file_read_result["partialFingerprints"]["primaryLocationLineHash"]
            != rce_result["partialFingerprints"]["primaryLocationLineHash"]
        )

    finally:
        os.unlink(report_file)


def test_sarif_snippets():
    """Test SARIF export includes code snippets for context"""
    reporter = Reporter()

    # Test tool injection snippet
    reporter.add_findings(
        "tool_injection",
        [
            {
                "type": "BLIND_RCE_TIMING",
                "severity": "CRITICAL",
                "tool": "execute_command",
                "arg": "command",
                "payload": "; sleep 10",
                "category": "command_injection",
                "detections": ["Timing delay: 10.2s"],
            }
        ],
    )

    # Test path traversal snippet
    reporter.add_findings(
        "path_traversal",
        [
            {
                "type": "RESOURCE_TRAVERSAL",
                "severity": "HIGH",
                "uri": "file://../../../etc/passwd",
                "detections": ["Path traversal detected"],
            }
        ],
    )

    # Test capability fuzzing snippet
    reporter.add_findings(
        "capability_fuzzing",
        [
            {
                "type": "CAPABILITY_VALIDATION_BYPASS",
                "severity": "HIGH",
                "method": "tools/call",
            }
        ],
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        report_file = f.name

    try:
        reporter.to_sarif(report_file)

        with open(report_file) as f:
            sarif = json.load(f)

        results = sarif["runs"][0]["results"]
        assert len(results) == 3

        # Check tool injection snippet
        rce_result = results[0]
        assert "region" in rce_result["locations"][0]["physicalLocation"]
        rce_snippet = rce_result["locations"][0]["physicalLocation"]["region"][
            "snippet"
        ]["text"]
        assert "MCP Tool Call" in rce_snippet
        assert "METHOD: tools/call" in rce_snippet
        assert "REQUEST:" in rce_snippet
        assert '"name": "execute_command"' in rce_snippet
        assert '"command": "; sleep 10"' in rce_snippet
        assert "RESULT:" in rce_snippet
        assert "✗ Timing delay: 10.2s" in rce_snippet

        # Check path traversal snippet
        traversal_result = results[1]
        assert "region" in traversal_result["locations"][0]["physicalLocation"]
        traversal_snippet = traversal_result["locations"][0]["physicalLocation"][
            "region"
        ]["snippet"]["text"]
        assert "MCP Resource Access" in traversal_snippet
        assert "METHOD: resources/read" in traversal_snippet
        assert "REQUEST:" in traversal_snippet
        assert "file://../../../etc/passwd" in traversal_snippet
        assert "RESULT:" in traversal_snippet
        assert "✗ Path traversal detected" in traversal_snippet

        # Check capability fuzzing snippet
        cap_result = results[2]
        assert "region" in cap_result["locations"][0]["physicalLocation"]
        cap_snippet = cap_result["locations"][0]["physicalLocation"]["region"][
            "snippet"
        ]["text"]
        assert "MCP Protocol" in cap_snippet
        assert "CAPABILITY_VALIDATION_BYPASS" in cap_snippet
        assert "METHOD: initialize" in cap_snippet
        assert "REQUEST:" in cap_snippet
        assert "✗ Server accepted invalid capabilities" in cap_snippet

    finally:
        os.unlink(report_file)
