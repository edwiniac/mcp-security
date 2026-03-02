"""Tests for MCP security tools."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import json

from mcp_security.server import (
    port_scan,
    cve_lookup,
    cve_search,
    ip_reputation,
    ssl_check,
    security_headers,
    dns_lookup,
    whois_lookup,
    shodan_host,
    generate_report,
    list_tools,
    call_tool,
)


class TestListTools:
    """Tests for list_tools."""

    @pytest.mark.asyncio
    async def test_list_tools_returns_all_tools(self):
        tools = await list_tools()
        assert len(tools) == 10
        
        tool_names = [t.name for t in tools]
        assert "port_scan" in tool_names
        assert "cve_lookup" in tool_names
        assert "cve_search" in tool_names
        assert "ip_reputation" in tool_names
        assert "ssl_check" in tool_names
        assert "security_headers" in tool_names
        assert "dns_lookup" in tool_names
        assert "whois_lookup" in tool_names
        assert "shodan_host" in tool_names
        assert "generate_report" in tool_names

    @pytest.mark.asyncio
    async def test_tools_have_required_fields(self):
        tools = await list_tools()
        for tool in tools:
            assert tool.name
            assert tool.description
            assert tool.inputSchema


class TestCallTool:
    """Tests for call_tool dispatcher."""

    @pytest.mark.asyncio
    async def test_call_unknown_tool(self):
        result = await call_tool("nonexistent_tool", {})
        assert len(result) == 1
        content = json.loads(result[0].text)
        assert "error" in content
        assert "Unknown tool" in content["error"]


class TestPortScan:
    """Tests for port_scan tool."""

    @pytest.mark.asyncio
    async def test_port_scan_returns_structure(self):
        with patch("asyncio.open_connection", side_effect=OSError("Connection refused")):
            result = await port_scan("127.0.0.1", "80,443", "quick")
            
            assert "target" in result
            assert "scan_type" in result
            assert "timestamp" in result
            assert "open_ports" in result
            assert "method" in result
            assert result["target"] == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_port_scan_with_range(self):
        with patch("asyncio.open_connection", side_effect=OSError("Connection refused")):
            result = await port_scan("127.0.0.1", "1-100", "quick")
            assert "open_ports" in result


class TestCVELookup:
    """Tests for cve_lookup tool."""

    @pytest.mark.asyncio
    async def test_cve_lookup_valid(self, mock_httpx_client, sample_cve_response):
        mock_response = AsyncMock()
        mock_response.json.return_value = sample_cve_response
        mock_response.raise_for_status = MagicMock()
        mock_httpx_client.get.return_value = mock_response

        result = await cve_lookup("CVE-2024-1234")
        
        assert result["cve_id"] == "CVE-2024-1234"
        assert "description" in result
        assert "cvss_v3" in result
        assert result["cvss_v3"]["score"] == 7.5

    @pytest.mark.asyncio
    async def test_cve_lookup_invalid_format(self):
        result = await cve_lookup("invalid-cve")
        assert "error" in result
        assert "Invalid CVE format" in result["error"]

    @pytest.mark.asyncio
    async def test_cve_lookup_uppercase_conversion(self, mock_httpx_client, sample_cve_response):
        mock_response = AsyncMock()
        mock_response.json.return_value = sample_cve_response
        mock_response.raise_for_status = MagicMock()
        mock_httpx_client.get.return_value = mock_response

        result = await cve_lookup("cve-2024-1234")
        assert result["cve_id"] == "CVE-2024-1234"


class TestCVESearch:
    """Tests for cve_search tool."""

    @pytest.mark.asyncio
    async def test_cve_search_returns_results(self, mock_httpx_client, sample_cve_response):
        mock_response = AsyncMock()
        mock_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": sample_cve_response["vulnerabilities"]
        }
        mock_response.raise_for_status = MagicMock()
        mock_httpx_client.get.return_value = mock_response

        result = await cve_search("nginx", None, 10)
        
        assert "keyword" in result
        assert "results" in result
        assert result["keyword"] == "nginx"


class TestIPReputation:
    """Tests for ip_reputation tool."""

    @pytest.mark.asyncio
    async def test_ip_reputation_invalid_ip(self):
        result = await ip_reputation("not.an.ip")
        assert "error" in result
        assert "Invalid IP address" in result["error"]

    @pytest.mark.asyncio
    async def test_ip_reputation_no_api_key(self):
        with patch("mcp_security.server.ABUSEIPDB_API_KEY", None):
            result = await ip_reputation("8.8.8.8")
            assert "checks" in result
            assert "abuseipdb" in result["checks"]
            assert "error" in result["checks"]["abuseipdb"]

    @pytest.mark.asyncio
    async def test_ip_reputation_with_api(self, mock_httpx_client, sample_abuseipdb_response):
        with patch("mcp_security.server.ABUSEIPDB_API_KEY", "test-key"):
            mock_response = AsyncMock()
            mock_response.json.return_value = sample_abuseipdb_response
            mock_response.raise_for_status = MagicMock()
            mock_httpx_client.get.return_value = mock_response

            result = await ip_reputation("192.168.1.1")
            
            assert "checks" in result
            assert "abuseipdb" in result["checks"]


class TestSSLCheck:
    """Tests for ssl_check tool."""

    @pytest.mark.asyncio
    async def test_ssl_check_invalid_domain(self):
        result = await ssl_check("not-a-domain", 443)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_ssl_check_connection_error(self):
        with patch("socket.create_connection", side_effect=OSError("Connection refused")):
            result = await ssl_check("example.com", 443)
            assert "error" in result


class TestSecurityHeaders:
    """Tests for security_headers tool."""

    @pytest.mark.asyncio
    async def test_security_headers_good_site(self, mock_httpx_client):
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
        mock_httpx_client.get.return_value = mock_response

        result = await security_headers("https://example.com")
        
        assert "headers_present" in result
        assert "headers_missing" in result
        assert "score" in result
        assert "grade" in result

    @pytest.mark.asyncio
    async def test_security_headers_adds_https(self, mock_httpx_client):
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_httpx_client.get.return_value = mock_response

        result = await security_headers("example.com")
        assert result["url"] == "https://example.com"


class TestDNSLookup:
    """Tests for dns_lookup tool."""

    @pytest.mark.asyncio
    async def test_dns_lookup_invalid_domain(self):
        result = await dns_lookup("not-valid", ["A"])
        assert "error" in result

    @pytest.mark.asyncio
    async def test_dns_lookup_fallback(self, mock_socket):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = await dns_lookup("example.com", ["A"])
            assert "records" in result


class TestWhoisLookup:
    """Tests for whois_lookup tool."""

    @pytest.mark.asyncio
    async def test_whois_lookup_invalid_domain(self):
        result = await whois_lookup("not-valid")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_whois_lookup_command_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = await whois_lookup("example.com")
            assert "error" in result
            assert "not available" in result["error"]

    @pytest.mark.asyncio
    async def test_whois_lookup_parses_output(self):
        mock_output = MagicMock()
        mock_output.stdout = """
        Domain Name: EXAMPLE.COM
        Registrar: Example Registrar
        Creation Date: 1995-08-14T00:00:00Z
        Registry Expiry Date: 2025-08-13T00:00:00Z
        Name Server: NS1.EXAMPLE.COM
        Name Server: NS2.EXAMPLE.COM
        """
        
        with patch("subprocess.run", return_value=mock_output):
            result = await whois_lookup("example.com")
            assert "registrar" in result
            assert "creation_date" in result


class TestShodanHost:
    """Tests for shodan_host tool."""

    @pytest.mark.asyncio
    async def test_shodan_no_api_key(self):
        with patch("mcp_security.server.SHODAN_API_KEY", None):
            result = await shodan_host("8.8.8.8")
            assert "error" in result
            assert "not configured" in result["error"]

    @pytest.mark.asyncio
    async def test_shodan_invalid_ip(self):
        with patch("mcp_security.server.SHODAN_API_KEY", "test-key"):
            result = await shodan_host("not-an-ip")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_shodan_success(self, mock_httpx_client, sample_shodan_response):
        with patch("mcp_security.server.SHODAN_API_KEY", "test-key"):
            mock_response = AsyncMock()
            mock_response.json.return_value = sample_shodan_response
            mock_response.raise_for_status = MagicMock()
            mock_httpx_client.get.return_value = mock_response

            result = await shodan_host("93.184.216.34")
            
            assert "hostnames" in result
            assert "ports" in result
            assert "services" in result


class TestGenerateReport:
    """Tests for generate_report tool."""

    @pytest.mark.asyncio
    async def test_generate_report_structure(self):
        with patch("mcp_security.server.dns_lookup", return_value={"records": {"A": ["93.184.216.34"]}}), \
             patch("mcp_security.server.whois_lookup", return_value={}), \
             patch("mcp_security.server.ssl_check", return_value={"security_issues": []}), \
             patch("mcp_security.server.security_headers", return_value={"grade": "A"}), \
             patch("mcp_security.server.port_scan", return_value={"open_ports": []}), \
             patch("mcp_security.server.ip_reputation", return_value={}):
            
            result = await generate_report("example.com", True)
            
            assert "target" in result
            assert "timestamp" in result
            assert "sections" in result
            assert "summary" in result

    @pytest.mark.asyncio
    async def test_generate_report_ip_target(self):
        with patch("mcp_security.server.port_scan", return_value={"open_ports": []}), \
             patch("mcp_security.server.ip_reputation", return_value={}):
            
            result = await generate_report("93.184.216.34", True)
            assert "sections" in result
