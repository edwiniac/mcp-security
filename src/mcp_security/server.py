#!/usr/bin/env python3
"""
MCP Security Server - Security tools for AI assistants.

Provides vulnerability scanning, CVE lookups, network analysis, and security
assessments through the Model Context Protocol (MCP).
"""

import asyncio
import json
import os
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Initialize MCP server
server = Server("mcp-security")

# API keys from environment
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def format_severity(score: float | None) -> str:
    """Format CVSS score with severity label."""
    if score is None:
        return "N/A"
    if score >= 9.0:
        return f"🔴 CRITICAL ({score})"
    if score >= 7.0:
        return f"🟠 HIGH ({score})"
    if score >= 4.0:
        return f"🟡 MEDIUM ({score})"
    if score >= 0.1:
        return f"🟢 LOW ({score})"
    return f"⚪ NONE ({score})"


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False


def is_valid_domain(domain: str) -> bool:
    """Check if string looks like a valid domain."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List all available security tools."""
    return [
        Tool(
            name="port_scan",
            description="Scan a target for open ports and services. "
                       "Use for network reconnaissance and vulnerability assessment.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname to scan"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range to scan (e.g., '22,80,443' or '1-1000')",
                        "default": "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "standard", "thorough"],
                        "description": "Scan intensity level",
                        "default": "quick"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="cve_lookup",
            description="Look up CVE vulnerability details from the National Vulnerability Database. "
                       "Use for researching known vulnerabilities.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE identifier (e.g., CVE-2024-1234)"
                    }
                },
                "required": ["cve_id"]
            }
        ),
        Tool(
            name="cve_search",
            description="Search for CVEs by keyword, product, or vendor. "
                       "Use for finding vulnerabilities affecting specific software.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Search keyword (product name, vendor, etc.)"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Filter by CVSS severity"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return",
                        "default": 10
                    }
                },
                "required": ["keyword"]
            }
        ),
        Tool(
            name="ip_reputation",
            description="Check IP address reputation for malicious activity, abuse reports, and threat intel. "
                       "Use for assessing if an IP is potentially dangerous.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to check"
                    }
                },
                "required": ["ip"]
            }
        ),
        Tool(
            name="ssl_check",
            description="Analyze SSL/TLS certificate and configuration for a domain. "
                       "Use for checking certificate validity, expiry, and security issues.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to check (e.g., example.com)"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port to connect to",
                        "default": 443
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="security_headers",
            description="Check HTTP security headers for a website. "
                       "Use for assessing web application security posture.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to check (e.g., https://example.com)"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="dns_lookup",
            description="Perform DNS lookups for a domain including A, AAAA, MX, NS, TXT records. "
                       "Use for domain reconnaissance and email security checks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to look up"
                    },
                    "record_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Record types to query",
                        "default": ["A", "AAAA", "MX", "NS", "TXT"]
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="whois_lookup",
            description="Get WHOIS information for a domain including registrar, dates, and contacts. "
                       "Use for domain ownership research.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to look up"
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="shodan_host",
            description="Get Shodan intelligence for an IP including open ports, services, vulnerabilities. "
                       "Requires SHODAN_API_KEY environment variable.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to look up"
                    }
                },
                "required": ["ip"]
            }
        ),
        Tool(
            name="generate_report",
            description="Generate a security assessment report for a target. "
                       "Combines multiple checks into a comprehensive report.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain or IP to assess"
                    },
                    "include_port_scan": {
                        "type": "boolean",
                        "description": "Include port scan in report",
                        "default": True
                    }
                },
                "required": ["target"]
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls."""
    try:
        if name == "port_scan":
            result = await port_scan(
                arguments["target"],
                arguments.get("ports", "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443"),
                arguments.get("scan_type", "quick")
            )
        elif name == "cve_lookup":
            result = await cve_lookup(arguments["cve_id"])
        elif name == "cve_search":
            result = await cve_search(
                arguments["keyword"],
                arguments.get("severity"),
                arguments.get("limit", 10)
            )
        elif name == "ip_reputation":
            result = await ip_reputation(arguments["ip"])
        elif name == "ssl_check":
            result = await ssl_check(
                arguments["domain"],
                arguments.get("port", 443)
            )
        elif name == "security_headers":
            result = await security_headers(arguments["url"])
        elif name == "dns_lookup":
            result = await dns_lookup(
                arguments["domain"],
                arguments.get("record_types", ["A", "AAAA", "MX", "NS", "TXT"])
            )
        elif name == "whois_lookup":
            result = await whois_lookup(arguments["domain"])
        elif name == "shodan_host":
            result = await shodan_host(arguments["ip"])
        elif name == "generate_report":
            result = await generate_report(
                arguments["target"],
                arguments.get("include_port_scan", True)
            )
        else:
            result = {"error": f"Unknown tool: {name}"}
        
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


async def port_scan(target: str, ports: str, scan_type: str) -> dict:
    """Perform port scan using nmap or fallback to socket scan."""
    results = {
        "target": target,
        "scan_type": scan_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "open_ports": [],
        "method": "socket"
    }
    
    # Try nmap first
    try:
        import nmap
        nm = nmap.PortScanner()
        
        scan_args = {
            "quick": "-T4 -F",
            "standard": "-T3 -sV",
            "thorough": "-T2 -sV -sC"
        }.get(scan_type, "-T4 -F")
        
        nm.scan(target, ports, arguments=scan_args)
        results["method"] = "nmap"
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_info = nm[host][proto][port]
                    if port_info["state"] == "open":
                        results["open_ports"].append({
                            "port": port,
                            "protocol": proto,
                            "service": port_info.get("name", "unknown"),
                            "version": port_info.get("version", ""),
                            "state": port_info["state"]
                        })
        
        return results
    
    except (ImportError, Exception):
        pass
    
    # Fallback to socket scan
    port_list = []
    if "-" in ports:
        start, end = map(int, ports.split("-"))
        port_list = list(range(start, min(end + 1, start + 100)))  # Limit range
    else:
        port_list = [int(p.strip()) for p in ports.split(",")]
    
    async def check_port(port: int) -> Optional[dict]:
        try:
            conn = asyncio.open_connection(target, port)
            await asyncio.wait_for(conn, timeout=2.0)
            return {"port": port, "protocol": "tcp", "state": "open", "service": "unknown"}
        except:
            return None
    
    tasks = [check_port(p) for p in port_list[:50]]  # Limit concurrent checks
    port_results = await asyncio.gather(*tasks)
    results["open_ports"] = [r for r in port_results if r]
    
    return results


async def cve_lookup(cve_id: str) -> dict:
    """Look up CVE details from NVD."""
    cve_id = cve_id.upper().strip()
    if not re.match(r"^CVE-\d{4}-\d+$", cve_id):
        return {"error": f"Invalid CVE format: {cve_id}. Expected format: CVE-YYYY-NNNNN"}
    
    async with httpx.AsyncClient() as client:
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        
        try:
            resp = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers=headers,
                timeout=30.0
            )
            resp.raise_for_status()
            data = resp.json()
            
            if not data.get("vulnerabilities"):
                return {"error": f"CVE not found: {cve_id}"}
            
            vuln = data["vulnerabilities"][0]["cve"]
            
            # Extract CVSS scores
            cvss_v3 = None
            cvss_v2 = None
            if "metrics" in vuln:
                if "cvssMetricV31" in vuln["metrics"]:
                    cvss_v3 = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]
                elif "cvssMetricV30" in vuln["metrics"]:
                    cvss_v3 = vuln["metrics"]["cvssMetricV30"][0]["cvssData"]
                if "cvssMetricV2" in vuln["metrics"]:
                    cvss_v2 = vuln["metrics"]["cvssMetricV2"][0]["cvssData"]
            
            return {
                "cve_id": vuln["id"],
                "description": vuln["descriptions"][0]["value"] if vuln.get("descriptions") else "N/A",
                "published": vuln.get("published"),
                "last_modified": vuln.get("lastModified"),
                "cvss_v3": {
                    "score": cvss_v3.get("baseScore") if cvss_v3 else None,
                    "severity": format_severity(cvss_v3.get("baseScore") if cvss_v3 else None),
                    "vector": cvss_v3.get("vectorString") if cvss_v3 else None
                },
                "cvss_v2": {
                    "score": cvss_v2.get("baseScore") if cvss_v2 else None,
                    "vector": cvss_v2.get("vectorString") if cvss_v2 else None
                } if cvss_v2 else None,
                "references": [ref["url"] for ref in vuln.get("references", [])[:5]],
                "cwe": [w.get("description", [{}])[0].get("value") 
                       for w in vuln.get("weaknesses", []) 
                       if w.get("description")][:3]
            }
        
        except httpx.HTTPStatusError as e:
            return {"error": f"NVD API error: {e.response.status_code}"}
        except Exception as e:
            return {"error": f"Failed to fetch CVE: {str(e)}"}


async def cve_search(keyword: str, severity: Optional[str], limit: int) -> dict:
    """Search CVEs by keyword."""
    async with httpx.AsyncClient() as client:
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 20)
        }
        if severity:
            params["cvssV3Severity"] = severity.upper()
        
        try:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers,
                timeout=30.0
            )
            resp.raise_for_status()
            data = resp.json()
            
            results = []
            for v in data.get("vulnerabilities", []):
                cve = v["cve"]
                score = None
                if "metrics" in cve:
                    if "cvssMetricV31" in cve["metrics"]:
                        score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in cve["metrics"]:
                        score = cve["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]
                
                results.append({
                    "cve_id": cve["id"],
                    "description": cve["descriptions"][0]["value"][:200] + "..." 
                                  if len(cve["descriptions"][0]["value"]) > 200 
                                  else cve["descriptions"][0]["value"],
                    "severity": format_severity(score),
                    "published": cve.get("published", "")[:10]
                })
            
            return {
                "keyword": keyword,
                "total_results": data.get("totalResults", 0),
                "results": results
            }
        
        except Exception as e:
            return {"error": f"CVE search failed: {str(e)}"}


async def ip_reputation(ip: str) -> dict:
    """Check IP reputation using AbuseIPDB."""
    if not is_valid_ip(ip):
        return {"error": f"Invalid IP address: {ip}"}
    
    result = {
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {}
    }
    
    # AbuseIPDB check
    if ABUSEIPDB_API_KEY:
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": ABUSEIPDB_API_KEY,
                        "Accept": "application/json"
                    },
                    timeout=15.0
                )
                resp.raise_for_status()
                data = resp.json()["data"]
                
                result["checks"]["abuseipdb"] = {
                    "abuse_confidence_score": data["abuseConfidenceScore"],
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt"),
                    "risk_level": "HIGH" if data["abuseConfidenceScore"] >= 50 
                                 else "MEDIUM" if data["abuseConfidenceScore"] >= 20 
                                 else "LOW"
                }
            except Exception as e:
                result["checks"]["abuseipdb"] = {"error": str(e)}
    else:
        result["checks"]["abuseipdb"] = {"error": "ABUSEIPDB_API_KEY not configured"}
    
    # Basic reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        result["reverse_dns"] = hostname
    except:
        result["reverse_dns"] = None
    
    return result


async def ssl_check(domain: str, port: int) -> dict:
    """Check SSL/TLS certificate for a domain."""
    if not is_valid_domain(domain):
        return {"error": f"Invalid domain: {domain}"}
    
    result = {
        "domain": domain,
        "port": port,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Parse dates
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (not_after - datetime.now()).days
                
                result["certificate"] = {
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                    "san": [x[1] for x in cert.get("subjectAltName", [])],
                }
                
                result["tls_version"] = ssock.version()
                result["cipher"] = ssock.cipher()
                
                # Security assessment
                issues = []
                if days_until_expiry < 0:
                    issues.append("🔴 CRITICAL: Certificate has expired!")
                elif days_until_expiry < 7:
                    issues.append(f"🔴 CRITICAL: Certificate expires in {days_until_expiry} days")
                elif days_until_expiry < 30:
                    issues.append(f"🟠 WARNING: Certificate expires in {days_until_expiry} days")
                
                if "TLSv1.0" in ssock.version() or "TLSv1.1" in ssock.version():
                    issues.append(f"🟠 WARNING: Using deprecated TLS version: {ssock.version()}")
                
                result["security_issues"] = issues if issues else ["✅ No issues found"]
                
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {str(e)}"
    except socket.error as e:
        result["error"] = f"Connection Error: {str(e)}"
    except Exception as e:
        result["error"] = f"Error: {str(e)}"
    
    return result


async def security_headers(url: str) -> dict:
    """Check HTTP security headers."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    
    # Important security headers to check
    important_headers = {
        "Strict-Transport-Security": {
            "required": True,
            "description": "Enforces HTTPS connections",
            "recommendation": "max-age=31536000; includeSubDomains; preload"
        },
        "Content-Security-Policy": {
            "required": True,
            "description": "Prevents XSS and injection attacks",
            "recommendation": "Define a strict policy"
        },
        "X-Frame-Options": {
            "required": True,
            "description": "Prevents clickjacking",
            "recommendation": "DENY or SAMEORIGIN"
        },
        "X-Content-Type-Options": {
            "required": True,
            "description": "Prevents MIME type sniffing",
            "recommendation": "nosniff"
        },
        "X-XSS-Protection": {
            "required": False,
            "description": "Legacy XSS filter (use CSP instead)",
            "recommendation": "1; mode=block"
        },
        "Referrer-Policy": {
            "required": True,
            "description": "Controls referrer information",
            "recommendation": "strict-origin-when-cross-origin"
        },
        "Permissions-Policy": {
            "required": False,
            "description": "Controls browser features",
            "recommendation": "Define based on needs"
        },
        "Cross-Origin-Embedder-Policy": {
            "required": False,
            "description": "Controls embedding policy",
            "recommendation": "require-corp"
        },
        "Cross-Origin-Opener-Policy": {
            "required": False,
            "description": "Controls window references",
            "recommendation": "same-origin"
        }
    }
    
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            resp = await client.get(url, timeout=15.0)
            headers = dict(resp.headers)
            
            results = {
                "url": url,
                "status_code": resp.status_code,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "headers_present": [],
                "headers_missing": [],
                "details": {}
            }
            
            score = 0
            max_score = 0
            
            for header, info in important_headers.items():
                max_score += 1 if info["required"] else 0.5
                
                # Check case-insensitive
                found_value = None
                for h, v in headers.items():
                    if h.lower() == header.lower():
                        found_value = v
                        break
                
                if found_value:
                    results["headers_present"].append(header)
                    results["details"][header] = {
                        "value": found_value[:200],
                        "status": "✅ Present"
                    }
                    score += 1 if info["required"] else 0.5
                else:
                    results["headers_missing"].append(header)
                    results["details"][header] = {
                        "status": "❌ Missing" if info["required"] else "⚠️ Missing (optional)",
                        "description": info["description"],
                        "recommendation": info["recommendation"]
                    }
            
            results["score"] = f"{int(score)}/{int(max_score)} ({int(score/max_score*100)}%)"
            
            if score >= max_score * 0.8:
                results["grade"] = "A - Good"
            elif score >= max_score * 0.6:
                results["grade"] = "B - Acceptable"
            elif score >= max_score * 0.4:
                results["grade"] = "C - Needs Improvement"
            else:
                results["grade"] = "D - Poor"
            
            return results
            
        except Exception as e:
            return {"error": f"Failed to check headers: {str(e)}"}


async def dns_lookup(domain: str, record_types: list[str]) -> dict:
    """Perform DNS lookups."""
    if not is_valid_domain(domain):
        return {"error": f"Invalid domain: {domain}"}
    
    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "records": {}
    }
    
    import subprocess
    
    for rtype in record_types:
        try:
            output = subprocess.run(
                ["dig", "+short", domain, rtype.upper()],
                capture_output=True,
                text=True,
                timeout=10
            )
            records = [r.strip() for r in output.stdout.strip().split("\n") if r.strip()]
            result["records"][rtype.upper()] = records if records else []
        except FileNotFoundError:
            # Fallback to socket for A records
            if rtype.upper() == "A":
                try:
                    ips = socket.gethostbyname_ex(domain)[2]
                    result["records"]["A"] = ips
                except:
                    result["records"]["A"] = []
            else:
                result["records"][rtype.upper()] = ["dig not available"]
        except Exception as e:
            result["records"][rtype.upper()] = [f"Error: {str(e)}"]
    
    # Security notes
    security_notes = []
    if "TXT" in result["records"]:
        txt_records = result["records"]["TXT"]
        has_spf = any("v=spf1" in r for r in txt_records)
        has_dmarc = any("v=DMARC1" in r for r in txt_records)
        has_dkim = any("DKIM" in r for r in txt_records)
        
        if not has_spf:
            security_notes.append("⚠️ No SPF record found - email spoofing possible")
        else:
            security_notes.append("✅ SPF record present")
        
        if not has_dmarc:
            security_notes.append("⚠️ No DMARC record found")
        else:
            security_notes.append("✅ DMARC record present")
    
    result["security_notes"] = security_notes
    
    return result


async def whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup."""
    if not is_valid_domain(domain):
        return {"error": f"Invalid domain: {domain}"}
    
    try:
        output = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        whois_text = output.stdout
        
        # Parse common fields
        result = {
            "domain": domain,
            "raw_length": len(whois_text),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "expiration_date": r"(?:Registry Expiry Date|Expiration Date):\s*(.+)",
            "updated_date": r"Updated Date:\s*(.+)",
            "name_servers": r"Name Server:\s*(.+)",
            "status": r"Status:\s*(.+)",
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, whois_text, re.IGNORECASE)
            if matches:
                result[key] = matches if key in ["name_servers", "status"] else matches[0]
        
        return result
        
    except FileNotFoundError:
        return {"error": "whois command not available"}
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}


async def shodan_host(ip: str) -> dict:
    """Get Shodan information for an IP."""
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not configured"}
    
    if not is_valid_ip(ip):
        return {"error": f"Invalid IP address: {ip}"}
    
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": SHODAN_API_KEY},
                timeout=15.0
            )
            resp.raise_for_status()
            data = resp.json()
            
            return {
                "ip": ip,
                "hostnames": data.get("hostnames", []),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "last_update": data.get("last_update"),
                "services": [
                    {
                        "port": svc.get("port"),
                        "protocol": svc.get("transport"),
                        "service": svc.get("product", "unknown"),
                        "version": svc.get("version", "")
                    }
                    for svc in data.get("data", [])[:10]
                ]
            }
        
        except httpx.HTTPStatusError as e:
            return {"error": f"Shodan API error: {e.response.status_code}"}
        except Exception as e:
            return {"error": f"Shodan lookup failed: {str(e)}"}


async def generate_report(target: str, include_port_scan: bool) -> dict:
    """Generate comprehensive security report."""
    report = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sections": {}
    }
    
    is_ip = is_valid_ip(target)
    
    # DNS/WHOIS for domains
    if not is_ip:
        report["sections"]["dns"] = await dns_lookup(target, ["A", "MX", "TXT", "NS"])
        report["sections"]["whois"] = await whois_lookup(target)
        report["sections"]["ssl"] = await ssl_check(target, 443)
        report["sections"]["headers"] = await security_headers(f"https://{target}")
    
    # Port scan
    if include_port_scan:
        scan_target = target
        if not is_ip:
            # Resolve domain to IP
            try:
                scan_target = socket.gethostbyname(target)
            except:
                scan_target = target
        report["sections"]["ports"] = await port_scan(scan_target, "22,80,443,8080,8443", "quick")
    
    # IP reputation
    ip_to_check = target if is_ip else report["sections"].get("dns", {}).get("records", {}).get("A", [None])[0]
    if ip_to_check and is_valid_ip(str(ip_to_check)):
        report["sections"]["reputation"] = await ip_reputation(ip_to_check)
    
    # Shodan if available
    if SHODAN_API_KEY and ip_to_check:
        report["sections"]["shodan"] = await shodan_host(ip_to_check)
    
    # Summary
    issues = []
    if "ssl" in report["sections"]:
        ssl_issues = report["sections"]["ssl"].get("security_issues", [])
        issues.extend([i for i in ssl_issues if "No issues" not in i])
    
    if "headers" in report["sections"]:
        grade = report["sections"]["headers"].get("grade", "")
        if "C" in grade or "D" in grade:
            issues.append(f"⚠️ Security headers grade: {grade}")
    
    if "dns" in report["sections"]:
        dns_notes = report["sections"]["dns"].get("security_notes", [])
        issues.extend([n for n in dns_notes if "⚠️" in n])
    
    report["summary"] = {
        "total_issues": len(issues),
        "issues": issues,
        "risk_level": "HIGH" if len(issues) >= 3 else "MEDIUM" if len(issues) >= 1 else "LOW"
    }
    
    return report


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
