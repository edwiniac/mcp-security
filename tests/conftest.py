"""Shared test fixtures for mcp-security."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_httpx_response():
    """Create a mock httpx response."""
    def _create_response(json_data, status_code=200):
        response = MagicMock()
        response.json.return_value = json_data
        response.status_code = status_code
        response.raise_for_status = MagicMock()
        response.headers = {}
        return response
    return _create_response


@pytest.fixture
def mock_httpx_client(mock_httpx_response):
    """Mock httpx client for API tests."""
    with patch("mcp_security.server.httpx.AsyncClient") as mock_class:
        mock_client = AsyncMock()
        mock_class.return_value.__aenter__.return_value = mock_client
        mock_class.return_value.__aexit__.return_value = None
        yield mock_client, mock_httpx_response


@pytest.fixture
def mock_socket():
    """Mock socket operations."""
    with patch("socket.create_connection") as mock_conn, \
         patch("socket.gethostbyname") as mock_resolve, \
         patch("socket.gethostbyaddr") as mock_reverse:
        mock_resolve.return_value = "93.184.216.34"
        mock_reverse.return_value = ("example.com", [], ["93.184.216.34"])
        yield {
            "connection": mock_conn,
            "resolve": mock_resolve,
            "reverse": mock_reverse
        }


@pytest.fixture
def sample_cve_response():
    """Sample NVD CVE response."""
    return {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"value": "A test vulnerability in Example Software."}],
                "published": "2024-01-15T10:00:00.000",
                "lastModified": "2024-01-20T12:00:00.000",
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 7.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                        }
                    }]
                },
                "references": [
                    {"url": "https://example.com/advisory/1234"},
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"}
                ],
                "weaknesses": [{
                    "description": [{"value": "CWE-79"}]
                }]
            }
        }]
    }


@pytest.fixture
def sample_abuseipdb_response():
    """Sample AbuseIPDB response."""
    return {
        "data": {
            "ipAddress": "192.168.1.1",
            "abuseConfidenceScore": 75,
            "isWhitelisted": False,
            "countryCode": "US",
            "isp": "Example ISP",
            "domain": "example.com",
            "totalReports": 150,
            "lastReportedAt": "2024-01-15T10:00:00+00:00"
        }
    }


@pytest.fixture
def sample_shodan_response():
    """Sample Shodan host response."""
    return {
        "ip_str": "93.184.216.34",
        "hostnames": ["example.com"],
        "country_name": "United States",
        "city": "Los Angeles",
        "org": "Example Org",
        "isp": "Example ISP",
        "asn": "AS12345",
        "ports": [80, 443],
        "vulns": ["CVE-2024-1234"],
        "last_update": "2024-01-15T10:00:00.000000",
        "data": [
            {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.18.0"},
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0"}
        ]
    }
