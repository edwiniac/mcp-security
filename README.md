# 🔐 MCP Security

[![CI](https://github.com/edwiniac/mcp-security/actions/workflows/ci.yml/badge.svg)](https://github.com/edwiniac/mcp-security/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io)

**Security tools for AI assistants** — vulnerability scanning, CVE lookups, network analysis, and security assessments via the Model Context Protocol.

Let Claude, ChatGPT, or any MCP-compatible AI run security audits through natural language.

---

## ✨ Features

- **🔍 Port Scanning** — Network reconnaissance with nmap or socket fallback
- **🛡️ CVE Lookup** — Search and analyze vulnerabilities from NVD
- **🌐 IP Reputation** — Check IPs for malicious activity (AbuseIPDB)
- **🔒 SSL/TLS Analysis** — Certificate validity, expiry, security issues
- **📋 Security Headers** — HTTP header audit with grades
- **🌍 DNS Enumeration** — A, MX, TXT, NS records + SPF/DMARC checks
- **📜 WHOIS** — Domain registration and ownership data
- **👁️ Shodan Integration** — Deep host intelligence
- **📊 Full Reports** — Comprehensive security assessments

## 🚀 Quick Start

### Installation

```bash
pip install mcp-security
```

Or install from source:

```bash
git clone https://github.com/edwiniac/mcp-security.git
cd mcp-security
pip install -e .
```

### Usage with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security": {
      "command": "mcp-security",
      "env": {
        "SHODAN_API_KEY": "your-shodan-key",
        "NVD_API_KEY": "your-nvd-key",
        "ABUSEIPDB_API_KEY": "your-abuseipdb-key"
      }
    }
  }
}
```

### Example Prompts

Once configured, ask Claude:

> "Scan example.com for open ports and check their SSL certificate"

> "Look up CVE-2024-1234 and tell me how severe it is"

> "Check the security headers on https://mysite.com"

> "Generate a full security report for 192.168.1.1"

> "Search for recent critical vulnerabilities in nginx"

## 🛠️ Available Tools

| Tool | Description |
|------|-------------|
| `port_scan` | Scan for open ports and services |
| `cve_lookup` | Get detailed CVE information |
| `cve_search` | Search CVEs by keyword/severity |
| `ip_reputation` | Check IP for malicious activity |
| `ssl_check` | Analyze SSL/TLS certificates |
| `security_headers` | Audit HTTP security headers |
| `dns_lookup` | DNS enumeration with security notes |
| `whois_lookup` | Domain registration info |
| `shodan_host` | Shodan intelligence for IPs |
| `generate_report` | Comprehensive security assessment |

## 🔑 API Keys (Optional)

For full functionality, set these environment variables:

| Variable | Service | Get it from |
|----------|---------|-------------|
| `SHODAN_API_KEY` | Shodan | [shodan.io](https://shodan.io) |
| `NVD_API_KEY` | NVD CVE Database | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/api) |

The server works without API keys but with reduced functionality.

## 📊 Example Output

### Security Headers Check

```
Ask: "Check security headers for github.com"

✅ Strict-Transport-Security: Present
✅ Content-Security-Policy: Present  
✅ X-Frame-Options: DENY
✅ X-Content-Type-Options: nosniff
⚠️ Permissions-Policy: Missing (optional)

Grade: A - Good
Score: 5/6 (83%)
```

### CVE Lookup

```
Ask: "Tell me about CVE-2024-1234"

CVE-2024-1234
🟠 HIGH (7.5)

Description: A vulnerability in Example Software allows...
Published: 2024-01-15
CWE: CWE-79 (Cross-site Scripting)

References:
- https://nvd.nist.gov/vuln/detail/CVE-2024-1234
- https://example.com/advisory
```

## 🏗️ Architecture

```
src/mcp_security/
├── __init__.py
└── server.py      # MCP server with all security tools

tests/
├── conftest.py    # Shared fixtures
├── test_helpers.py
└── test_tools.py
```

## 🧪 Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=mcp_security --cov-report=term-missing
```

## ⚠️ Security Considerations

- **Only scan targets you own or have permission to scan**
- Port scanning without permission may be illegal in some jurisdictions
- This tool is for authorized security assessments only
- API keys are sensitive — don't commit them to version control

## 🗺️ Roadmap

- [ ] Nuclei template scanning
- [ ] Subdomain enumeration
- [ ] Web vulnerability scanning (XSS, SQLi detection)
- [ ] Compliance checks (PCI-DSS, HIPAA basics)
- [ ] Integration with more threat intel sources
- [ ] Export reports to PDF/HTML

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 👤 Author

**Edwin Isac** — AI Engineer  
[GitHub](https://github.com/edwiniac) · [Email](mailto:edwinisac007@gmail.com)

---

*Part of [MCP Finance](https://github.com/edwiniac/mcp-finance) family of MCP servers.*
