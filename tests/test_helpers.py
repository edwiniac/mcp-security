"""Tests for helper functions."""

import pytest
from mcp_security.server import format_severity, is_valid_ip, is_valid_domain


class TestFormatSeverity:
    """Tests for format_severity function."""

    def test_critical_severity(self):
        assert "CRITICAL" in format_severity(9.5)
        assert "🔴" in format_severity(9.0)

    def test_high_severity(self):
        assert "HIGH" in format_severity(8.0)
        assert "🟠" in format_severity(7.0)

    def test_medium_severity(self):
        assert "MEDIUM" in format_severity(5.5)
        assert "🟡" in format_severity(4.0)

    def test_low_severity(self):
        assert "LOW" in format_severity(2.0)
        assert "🟢" in format_severity(0.1)

    def test_none_severity(self):
        assert "NONE" in format_severity(0.0)
        assert "⚪" in format_severity(0.0)

    def test_null_score(self):
        assert format_severity(None) == "N/A"

    def test_boundary_values(self):
        # Exact boundaries
        assert "CRITICAL" in format_severity(9.0)
        assert "HIGH" in format_severity(7.0)
        assert "MEDIUM" in format_severity(4.0)
        assert "LOW" in format_severity(0.1)


class TestIsValidIP:
    """Tests for is_valid_ip function."""

    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("8.8.8.8") is True
        assert is_valid_ip("255.255.255.255") is True

    def test_valid_ipv6(self):
        assert is_valid_ip("::1") is True
        assert is_valid_ip("2001:db8::1") is True
        assert is_valid_ip("fe80::1") is True

    def test_invalid_ip(self):
        assert is_valid_ip("not.an.ip") is False
        assert is_valid_ip("256.256.256.256") is False
        assert is_valid_ip("192.168.1") is False
        assert is_valid_ip("") is False
        assert is_valid_ip("example.com") is False


class TestIsValidDomain:
    """Tests for is_valid_domain function."""

    def test_valid_domains(self):
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.com") is True
        assert is_valid_domain("deep.sub.example.com") is True
        assert is_valid_domain("example.co.uk") is True
        assert is_valid_domain("test-domain.com") is True

    def test_invalid_domains(self):
        assert is_valid_domain("") is False
        assert is_valid_domain("localhost") is False
        assert is_valid_domain("-invalid.com") is False
        assert is_valid_domain("192.168.1.1") is False
        assert is_valid_domain("http://example.com") is False
        assert is_valid_domain("example") is False
