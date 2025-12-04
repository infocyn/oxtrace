#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗ ██╗  ██╗████████╗██████╗  █████╗  ██████╗███████╗                ║
║    ██╔═══██╗╚██╗██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝                ║
║    ██║   ██║ ╚███╔╝    ██║   ██████╔╝███████║██║     █████╗                  ║
║    ██║   ██║ ██╔██╗    ██║   ██╔══██╗██╔══██║██║     ██╔══╝                  ║
║    ╚██████╔╝██╔╝ ██╗   ██║   ██║  ██║██║  ██║╚██████╗███████╗                ║
║     ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝                ║
║                                                                               ║
║               🔥 Ultimate Penetration Testing Framework v5.0 🔥               ║
║                   Advanced Vulnerability Scanner & Exploit Kit                ║
║                                                                               ║
║  ⚠️  WARNING: FOR AUTHORIZED SECURITY TESTING ONLY                           ║
║  ⚠️  Unauthorized access to computer systems is ILLEGAL                       ║
║  ⚠️  You are responsible for your own actions                                 ║
║  ⚠️  The developer assumes NO liability for misuse                            ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import aiohttp
import argparse
import base64
import binascii
import concurrent.futures
import hashlib
import hmac
import json
import logging
import os
import pickle
import platform
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import warnings
import zlib
from abc import ABC, abstractmethod
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse, urlsplit, parse_qs, urlencode
import traceback
from queue import Queue
import multiprocessing

# Third-party imports
try:
    import httpx
    import dns.resolver
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich import print as rprint
    from rich.live import Live
    from rich.layout import Layout
    from rich.tree import Tree
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.align import Align
    from rich.spinner import Spinner
    from rich.status import Status
    import cloudscraper
    from colorama import init, Fore, Style, Back
    from tqdm.asyncio import tqdm as async_tqdm
    from tqdm import tqdm
    import yaml
    from pydantic import BaseModel, validator
    from jinja2 import Template, Environment, FileSystemLoader
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as e:
    print(f"[!] Missing required library: {e}")
    print("[*] Please install requirements: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

# Suppress warnings
warnings.filterwarnings('ignore')

# =============================================================================
# 🎨 REAL-TIME DISPLAY SYSTEM (Feature #7)
# =============================================================================
class RealTimeDisplay:
    """Real-time terminal display system with live updates"""
    
    def __init__(self):
        self.console = Console()
        self.live = None
        self.scan_status = {}
        self.vulnerabilities_found = []
        self.current_module = ""
        self.start_time = None
        self.requests_count = 0
        self.lock = threading.Lock()
        
    def create_dashboard(self) -> Layout:
        """Create the main dashboard layout"""
        layout = Layout()
        
        layout.split(
            Layout(name="header", size=8),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=5)
        )
        
        layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        
        return layout
    
    def generate_header(self) -> Panel:
        """Generate header panel"""
        elapsed = ""
        if self.start_time:
            elapsed_sec = time.time() - self.start_time
            elapsed = f" | ⏱️  {elapsed_sec:.1f}s"
        
        header_text = Text()
        header_text.append("🔥 OxTrace v5.0 ", style="bold cyan")
        header_text.append("| ", style="dim")
        header_text.append(f"Module: {self.current_module}", style="bold yellow")
        header_text.append(f" | 📡 Requests: {self.requests_count}", style="green")
        header_text.append(elapsed, style="magenta")
        
        return Panel(
            Align.center(header_text),
            title="[bold blue]Security Scanner[/bold blue]",
            border_style="blue"
        )
    
    def generate_status_panel(self) -> Panel:
        """Generate scan status panel"""
        table = Table(show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Module", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Findings", justify="right", style="red")
        
        for module, status in self.scan_status.items():
            status_icon = "✅" if status.get("completed") else "🔄"
            findings = str(status.get("findings", 0))
            table.add_row(module, f"{status_icon} {status.get('status', 'Pending')}", findings)
        
        return Panel(table, title="[bold green]Scan Progress[/bold green]", border_style="green")
    
    def generate_vuln_panel(self) -> Panel:
        """Generate vulnerabilities panel"""
        if not self.vulnerabilities_found:
            content = Text("No vulnerabilities found yet...", style="dim")
        else:
            content = Text()
            for vuln in self.vulnerabilities_found[-10:]:  # Last 10 vulns
                severity = vuln.get("severity", "info").upper()
                color = {
                    "CRITICAL": "red bold",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "cyan",
                    "INFO": "blue"
                }.get(severity, "white")
                content.append(f"[{severity}] ", style=color)
                content.append(f"{vuln.get('name', 'Unknown')}\n", style="white")
        
        return Panel(content, title="[bold red]Vulnerabilities[/bold red]", border_style="red")
    
    def generate_activity_log(self) -> Panel:
        """Generate real-time activity log"""
        # This would show real-time requests being made
        log_content = Text()
        log_content.append("🔍 Scanning in progress...\n", style="bold green")
        log_content.append(f"   Current: {self.current_module}\n", style="cyan")
        log_content.append(f"   Requests: {self.requests_count}\n", style="yellow")
        
        return Panel(log_content, title="[bold yellow]Activity[/bold yellow]", border_style="yellow")
    
    def update_display(self, layout: Layout):
        """Update all panels in the layout"""
        layout["header"].update(self.generate_header())
        layout["left"].update(self.generate_status_panel())
        layout["right"].update(self.generate_vuln_panel())
        layout["footer"].update(self.generate_activity_log())
    
    def start_live_display(self):
        """Start the live display"""
        self.start_time = time.time()
        layout = self.create_dashboard()
        self.live = Live(layout, refresh_per_second=4, console=self.console)
        return self.live
    
    def update_module_status(self, module: str, status: str, findings: int = 0, completed: bool = False):
        """Update a module's status"""
        with self.lock:
            self.scan_status[module] = {
                "status": status,
                "findings": findings,
                "completed": completed
            }
            self.current_module = module
    
    def add_vulnerability(self, vuln: dict):
        """Add a vulnerability to the display"""
        with self.lock:
            self.vulnerabilities_found.append(vuln)
    
    def increment_requests(self):
        """Increment request counter"""
        with self.lock:
            self.requests_count += 1


# =============================================================================
# 🔄 MULTI-THREADING ENGINE (Feature #8)
# =============================================================================
class MultiThreadEngine:
    """Advanced multi-threading engine for parallel scanning"""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) * 4)
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        self.process_pool = None
        self.results_queue = Queue()
        self.lock = threading.Lock()
        self.active_tasks = 0
        self.completed_tasks = 0
        
    def submit_task(self, func: Callable, *args, **kwargs) -> concurrent.futures.Future:
        """Submit a task to the thread pool"""
        with self.lock:
            self.active_tasks += 1
        
        future = self.thread_pool.submit(self._wrapped_task, func, *args, **kwargs)
        return future
    
    def _wrapped_task(self, func: Callable, *args, **kwargs):
        """Wrapper to track task completion"""
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            with self.lock:
                self.active_tasks -= 1
                self.completed_tasks += 1
    
    def map_tasks(self, func: Callable, items: List, chunk_size: int = 10) -> List:
        """Map a function over items in parallel"""
        results = []
        futures = []
        
        for item in items:
            future = self.submit_task(func, item)
            futures.append(future)
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result(timeout=60)
                if result:
                    results.append(result)
            except Exception as e:
                pass
        
        return results
    
    async def async_map(self, coro_func: Callable, items: List, max_concurrent: int = 50) -> List:
        """Async map with concurrency limit"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_coro(item):
            async with semaphore:
                return await coro_func(item)
        
        tasks = [limited_coro(item) for item in items]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]
    
    def shutdown(self):
        """Shutdown the thread pool"""
        self.thread_pool.shutdown(wait=True)
        if self.process_pool:
            self.process_pool.shutdown(wait=True)


# =============================================================================
# ⚖️ INTERACTIVE LEGAL FRAMEWORK (Feature #9)
# =============================================================================
class LegalFramework:
    """Interactive legal framework and consent management"""
    
    LEGAL_DISCLAIMER = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        ⚠️  LEGAL DISCLAIMER ⚠️                                 ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  This tool is designed for AUTHORIZED SECURITY TESTING ONLY.                 ║
║                                                                               ║
║  By using OxTrace, you agree to the following terms:                         ║
║                                                                               ║
║  1. You have explicit written permission from the system owner               ║
║  2. You will NOT use this tool for illegal activities                        ║
║  3. You understand that unauthorized access is a CRIMINAL OFFENSE            ║
║  4. You accept FULL RESPONSIBILITY for your actions                          ║
║  5. The developers are NOT liable for any misuse or damage                   ║
║                                                                               ║
║  Violations may result in:                                                   ║
║  • Criminal prosecution under computer crime laws                            ║
║  • Civil lawsuits and financial penalties                                    ║
║  • Imprisonment (varies by jurisdiction)                                     ║
║                                                                               ║
║  Relevant Laws:                                                              ║
║  • USA: Computer Fraud and Abuse Act (CFAA)                                  ║
║  • EU: Directive 2013/40/EU on attacks against information systems           ║
║  • UK: Computer Misuse Act 1990                                              ║
║  • UAE: Federal Law No. 5 of 2012 on Combating Cybercrimes                   ║
║  • KSA: Anti-Cyber Crime Law (Royal Decree No. M/17)                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

    def __init__(self):
        self.console = Console()
        self.consent_given = False
        self.consent_log = []
        self.target_authorization = {}
        
    def display_disclaimer(self):
        """Display the legal disclaimer"""
        self.console.print(self.LEGAL_DISCLAIMER, style="yellow")
    
    def get_consent(self) -> bool:
        """Get user consent interactively"""
        self.display_disclaimer()
        
        self.console.print("\n[bold red]Do you understand and accept these terms?[/bold red]")
        self.console.print("[yellow]Type 'I AGREE' to continue or 'EXIT' to quit:[/yellow]")
        
        response = input("\n> ").strip().upper()
        
        if response == "I AGREE":
            self.consent_given = True
            self.consent_log.append({
                "timestamp": datetime.now().isoformat(),
                "action": "consent_given",
                "response": response
            })
            self.console.print("\n[green]✅ Consent recorded. Proceeding...[/green]\n")
            return True
        else:
            self.console.print("\n[red]❌ Consent not given. Exiting...[/red]\n")
            return False
    
    def verify_authorization(self, target: str) -> bool:
        """Verify authorization for a specific target"""
        self.console.print(f"\n[bold yellow]Target Authorization Check[/bold yellow]")
        self.console.print(f"[cyan]Target: {target}[/cyan]\n")
        
        questions = [
            "Do you have written authorization to test this target? (yes/no)",
            "Is this target owned by you or your organization? (yes/no)",
            "Have you informed the target owner about this test? (yes/no)"
        ]
        
        answers = []
        for q in questions:
            self.console.print(f"[yellow]? {q}[/yellow]")
            ans = input("> ").strip().lower()
            answers.append(ans == "yes")
        
        authorized = all(answers)
        
        self.target_authorization[target] = {
            "timestamp": datetime.now().isoformat(),
            "authorized": authorized,
            "answers": answers
        }
        
        if authorized:
            self.console.print("\n[green]✅ Authorization verified. Proceeding with scan...[/green]\n")
        else:
            self.console.print("\n[red]⚠️  WARNING: You have indicated you may not have full authorization.[/red]")
            self.console.print("[red]Proceeding may be illegal. Type 'PROCEED ANYWAY' to continue at your own risk:[/red]")
            
            override = input("> ").strip().upper()
            if override == "PROCEED ANYWAY":
                self.console.print("\n[yellow]⚠️  Proceeding at your own risk...[/yellow]\n")
                return True
            else:
                return False
        
        return authorized
    
    def generate_audit_log(self) -> str:
        """Generate an audit log of all actions"""
        log = {
            "tool": "OxTrace v5.0",
            "session_start": datetime.now().isoformat(),
            "consent_log": self.consent_log,
            "target_authorizations": self.target_authorization
        }
        return json.dumps(log, indent=2)


# =============================================================================
# 🔧 CONFIGURATION & CONSTANTS
# =============================================================================
class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Config:
    """Global configuration settings"""
    VERSION = "5.0.0"
    CODENAME = "Shadow Phoenix"
    AUTHOR = "OxTrace Security Team"
    
    # Request settings
    DEFAULT_TIMEOUT = 30
    MAX_RETRIES = 3
    MAX_THREADS = 100
    MAX_ASYNC_TASKS = 200
    RATE_LIMIT_DELAY = 0.05
    
    # Cache settings
    CACHE_ENABLED = True
    CACHE_DIR = Path.home() / ".oxtrace" / "cache"
    CACHE_TTL = 3600
    CACHE_MAX_SIZE = 1000
    
    # Proxy & Stealth settings
    USE_PROXY = False
    PROXY_LIST = []
    USE_TOR = False
    TOR_PROXY = "socks5://127.0.0.1:9050"
    ROTATE_USER_AGENT = True
    RANDOM_DELAY = True
    DELAY_MIN = 0.1
    DELAY_MAX = 0.5
    
    # Evasion settings
    EVASION_MODE = True
    WAF_BYPASS = True
    ENCODING_EVASION = True
    CASE_MANIPULATION = True
    
    # Logging
    LOG_LEVEL = logging.INFO
    LOG_FILE = "oxtrace.log"
    
    # User agents pool
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]
    
    # JWT Secrets for testing (Feature #3)
    JWT_COMMON_SECRETS = [
        "secret", "password", "123456", "admin", "key", "private",
        "jwt_secret", "jwt-secret", "jwtSecret", "token_secret",
        "auth_secret", "app_secret", "api_secret", "signing_key",
        "HS256_SECRET", "SECRET_KEY", "JWT_SECRET_KEY",
    ]
    
    # Common file upload extensions (Feature #4)
    DANGEROUS_EXTENSIONS = [
        ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
        ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx",
        ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
        ".exe", ".dll", ".bat", ".cmd", ".sh", ".pl", ".py",
        ".cgi", ".htaccess", ".config", ".ini",
        ".svg", ".xml", ".xsl", ".xslt",
    ]
    
    # Session cookie names (Feature #5)
    SESSION_COOKIE_NAMES = [
        "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "ASPSESSIONID",
        "session", "sessionid", "session_id", "sid", "sess",
        "token", "auth_token", "access_token", "jwt", "bearer",
        "csrftoken", "csrf_token", "_csrf", "XSRF-TOKEN",
        "remember_token", "remember_me", "persistent_token",
    ]
    
    # Weak cipher suites (Feature #6)
    WEAK_CIPHERS = [
        "DES", "3DES", "RC4", "RC2", "MD5", "SHA1",
        "EXPORT", "NULL", "ANON", "ADH", "AECDH",
    ]
    
    # SQL Injection payloads
    SQLI_PAYLOADS = {
        "basic": [
            "'", "\"", "`", "' OR '1'='1", "\" OR \"1\"=\"1",
            "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#", "\" OR 1=1#",
            "') OR ('1'='1", "\") OR (\"1\"=\"1", "' OR 'x'='x",
        ],
        "union": [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT 1,2,3--",
        ],
        "blind_time": [
            "' AND SLEEP(5)--", "' AND SLEEP(5)#",
            "'; WAITFOR DELAY '0:0:5'--",
        ],
    }
    
    # XSS payloads
    XSS_PAYLOADS = {
        "basic": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ],
        "event_handlers": [
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
        ],
    }
    
    # Security headers
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "description": "HSTS - Forces HTTPS connections",
            "severity": "high",
            "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
        },
        "Content-Security-Policy": {
            "description": "CSP - Prevents XSS and injection attacks",
            "severity": "high",
            "recommendation": "Implement a strict Content-Security-Policy"
        },
        "X-Frame-Options": {
            "description": "Prevents Clickjacking attacks",
            "severity": "medium",
            "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'"
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME-type sniffing",
            "severity": "medium",
            "recommendation": "Add 'X-Content-Type-Options: nosniff'"
        },
    }


# =============================================================================
# 🗄️ DATA CLASSES
# =============================================================================
@dataclass
class ScanResult:
    """Data class for storing scan results"""
    target: str
    scan_type: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "pending"
    data: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "status": self.status,
            "data": self.data,
            "vulnerabilities": self.vulnerabilities,
            "errors": self.errors,
            "duration": self.duration
        }


@dataclass
class Vulnerability:
    """Data class for storing vulnerability information"""
    name: str
    severity: SeverityLevel
    description: str
    url: str
    evidence: str = ""
    payload: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss: float = 0.0
    parameter: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "payload": self.payload,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "parameter": self.parameter
        }


# =============================================================================
# 📝 LOGGER WITH REAL-TIME OUTPUT
# =============================================================================
class Logger:
    """Custom logger with colored output and real-time display"""
    
    def __init__(self, verbose: bool = False, realtime_display: RealTimeDisplay = None):
        self.verbose = verbose
        self.console = Console()
        self.realtime = realtime_display
        self._setup_file_logging()
    
    def _setup_file_logging(self):
        logging.basicConfig(
            filename=Config.LOG_FILE,
            level=Config.LOG_LEVEL,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def _print_with_timestamp(self, prefix: str, message: str, style: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [{style}]{prefix}[/{style}] {message}")
    
    def info(self, message: str):
        self._print_with_timestamp("[*]", message, "blue")
        logging.info(message)
    
    def success(self, message: str):
        self._print_with_timestamp("[+]", message, "green")
        logging.info(f"SUCCESS: {message}")
    
    def warning(self, message: str):
        self._print_with_timestamp("[!]", message, "yellow")
        logging.warning(message)
    
    def error(self, message: str):
        self._print_with_timestamp("[-]", message, "red")
        logging.error(message)
    
    def debug(self, message: str):
        if self.verbose:
            self._print_with_timestamp("[DEBUG]", message, "dim")
        logging.debug(message)
    
    def critical(self, message: str):
        self._print_with_timestamp("[CRITICAL]", message, "red bold")
        logging.critical(message)
    
    def vuln(self, severity: str, message: str):
        colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "blue"
        }
        color = colors.get(severity.lower(), "white")
        self._print_with_timestamp(f"[VULN:{severity.upper()}]", message, color)
        logging.warning(f"VULNERABILITY [{severity}]: {message}")
    
    def scan_progress(self, module: str, current: int, total: int, item: str = ""):
        """Show scan progress in real-time"""
        percentage = (current / total) * 100 if total > 0 else 0
        bar_length = 30
        filled = int(bar_length * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_length - filled)
        
        self.console.print(
            f"\r[cyan]{module}[/cyan] [{bar}] {percentage:.1f}% ({current}/{total}) [dim]{item[:50]}[/dim]",
            end=""
        )


# =============================================================================
# 🌐 HTTP CLIENT
# =============================================================================
class HTTPClient:
    """Advanced HTTP client with stealth features"""
    
    def __init__(self, realtime_display: RealTimeDisplay = None):
        self.session = None
        self.proxy_index = 0
        self.request_count = 0
        self.last_request_time = 0
        self.realtime = realtime_display
        self.cloudscraper = cloudscraper.create_scraper()
    
    def get_random_user_agent(self) -> str:
        return random.choice(Config.USER_AGENTS)
    
    def get_random_headers(self) -> Dict[str, str]:
        """Generate randomized headers for stealth"""
        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }
        return headers
    
    def get_proxy(self) -> Optional[Dict]:
        if Config.USE_TOR:
            return {"http://": Config.TOR_PROXY, "https://": Config.TOR_PROXY}
        if Config.USE_PROXY and Config.PROXY_LIST:
            proxy = Config.PROXY_LIST[self.proxy_index % len(Config.PROXY_LIST)]
            self.proxy_index += 1
            return {"http://": proxy, "https://": proxy}
        return None
    
    def apply_delay(self):
        """Apply random delay between requests for stealth"""
        if Config.RANDOM_DELAY:
            delay = random.uniform(Config.DELAY_MIN, Config.DELAY_MAX)
            time.sleep(delay)
    
    async def async_request(
        self, 
        method: str,
        url: str, 
        headers: Dict = None,
        data: Any = None,
        json_data: Dict = None,
        follow_redirects: bool = True,
        timeout: int = None,
    ) -> Optional[httpx.Response]:
        """Async HTTP request with retries and stealth"""
        
        self.apply_delay()
        
        request_headers = self.get_random_headers()
        if headers:
            request_headers.update(headers)
        
        proxy = self.get_proxy()
        timeout = timeout or Config.DEFAULT_TIMEOUT
        
        for attempt in range(Config.MAX_RETRIES):
            try:
                async with httpx.AsyncClient(
                    timeout=timeout,
                    follow_redirects=follow_redirects,
                    verify=False,
                    proxies=proxy
                ) as client:
                    if method.upper() == "GET":
                        response = await client.get(url, headers=request_headers)
                    elif method.upper() == "POST":
                        response = await client.post(
                            url, headers=request_headers, 
                            data=data, json=json_data
                        )
                    else:
                        response = await client.request(
                            method, url, headers=request_headers,
                            data=data, json=json_data
                        )
                    
                    self.request_count += 1
                    if self.realtime:
                        self.realtime.increment_requests()
                    
                    return response
                    
            except httpx.TimeoutException:
                if attempt == Config.MAX_RETRIES - 1:
                    return None
                await asyncio.sleep(1 * (attempt + 1))
            except Exception as e:
                if attempt == Config.MAX_RETRIES - 1:
                    return None
                await asyncio.sleep(1 * (attempt + 1))
        
        return None
    
    async def async_get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.async_request("GET", url, **kwargs)
    
    async def async_post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.async_request("POST", url, **kwargs)


# =============================================================================
# 🔐 AUTHENTICATION SECURITY TESTING (Feature #1)
# =============================================================================
class AuthenticationScanner:
    """Authentication security testing scanner"""
    
    def __init__(self, http_client: HTTPClient, logger: Logger):
        self.http = http_client
        self.logger = logger
        self.vulnerabilities = []
    
    async def scan(self, target: str) -> ScanResult:
        result = ScanResult(target=target, scan_type="authentication_security")
        start_time = time.time()
        
        self.logger.info(f"Starting Authentication Security scan for {target}")
        
        # Find login endpoints
        login_endpoints = await self._find_login_endpoints(target)
        self.logger.info(f"Found {len(login_endpoints)} potential login endpoints")
        
        vulnerabilities_found = []
        
        for endpoint in login_endpoints:
            # Test for various auth vulnerabilities
            vulns = await self._test_auth_vulnerabilities(endpoint)
            vulnerabilities_found.extend(vulns)
        
        # Test for default credentials
        default_cred_vulns = await self._test_default_credentials(target, login_endpoints)
        vulnerabilities_found.extend(default_cred_vulns)
        
        # Test for brute force protection
        bruteforce_vulns = await self._test_bruteforce_protection(target, login_endpoints)
        vulnerabilities_found.extend(bruteforce_vulns)
        
        # Test for account enumeration
        enum_vulns = await self._test_account_enumeration(target, login_endpoints)
        vulnerabilities_found.extend(enum_vulns)
        
        result.data = {
            "login_endpoints": login_endpoints,
            "vulnerabilities_count": len(vulnerabilities_found),
        }
        result.vulnerabilities = [v.to_dict() for v in vulnerabilities_found]
        result.status = "completed"
        result.duration = time.time() - start_time
        
        return result
    
    async def _find_login_endpoints(self, target: str) -> List[str]:
        """Find potential login endpoints"""
        endpoints = []
        common_paths = [
            "/login", "/signin", "/auth", "/authenticate", "/user/login",
            "/admin/login", "/api/login", "/api/auth", "/api/v1/login",
            "/account/login", "/member/login", "/portal/login",
            "/wp-login.php", "/administrator", "/admin",
            "/login.php", "/login.html", "/signin.php",
        ]
        
        for path in common_paths:
            url = urljoin(target, path)
            try:
                response = await self.http.async_get(url)
                if response and response.status_code in [200, 401, 403]:
                    endpoints.append(url)
                    self.logger.debug(f"Found login endpoint: {url}")
            except:
                pass
        
        return endpoints
    
    async def _test_auth_vulnerabilities(self, endpoint: str) -> List[Vulnerability]:
        """Test for common authentication vulnerabilities"""
        vulns = []
        
        # Test 1: Check for HTTPS
        if endpoint.startswith("http://"):
            vulns.append(Vulnerability(
                name="Login Over HTTP",
                severity=SeverityLevel.HIGH,
                description="Login form transmits credentials over unencrypted HTTP",
                url=endpoint,
                evidence="Endpoint uses HTTP instead of HTTPS",
                remediation="Always use HTTPS for authentication endpoints",
                cwe="CWE-319",
                cvss=7.5
            ))
        
        # Test 2: Check for SQL injection in login
        sqli_payloads = ["' OR '1'='1", "admin'--", "' OR 1=1--"]
        for payload in sqli_payloads:
            try:
                response = await self.http.async_post(
                    endpoint,
                    data={"username": payload, "password": "test"}
                )
                if response and ("error" in response.text.lower() or 
                                "sql" in response.text.lower() or
                                "syntax" in response.text.lower()):
                    vulns.append(Vulnerability(
                        name="SQL Injection in Login",
                        severity=SeverityLevel.CRITICAL,
                        description="Login form vulnerable to SQL injection",
                        url=endpoint,
                        payload=payload,
                        evidence="SQL error message in response",
                        remediation="Use parameterized queries",
                        cwe="CWE-89",
                        cvss=9.8
                    ))
                    break
            except:
                pass
        
        return vulns
    
    async def _test_default_credentials(self, target: str, endpoints: List[str]) -> List[Vulnerability]:
        """Test for default credentials"""
        vulns = []
        
        default_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("root", "root"), ("root", "password"), ("root", "toor"),
            ("administrator", "administrator"), ("test", "test"),
            ("guest", "guest"), ("user", "user"), ("demo", "demo"),
        ]
        
        for endpoint in endpoints[:3]:  # Limit to first 3 endpoints
            for username, password in default_creds:
                try:
                    response = await self.http.async_post(
                        endpoint,
                        data={"username": username, "password": password}
                    )
                    
                    if response and response.status_code == 200:
                        # Check for successful login indicators
                        success_indicators = ["dashboard", "welcome", "logout", "profile"]
                        if any(ind in response.text.lower() for ind in success_indicators):
                            vulns.append(Vulnerability(
                                name="Default Credentials",
                                severity=SeverityLevel.CRITICAL,
                                description=f"Default credentials work: {username}:{password}",
                                url=endpoint,
                                evidence=f"Login successful with {username}:{password}",
                                remediation="Change default credentials immediately",
                                cwe="CWE-798",
                                cvss=9.8
                            ))
                            self.logger.critical(f"Default credentials found: {username}:{password}")
                except:
                    pass
        
        return vulns
    
    async def _test_bruteforce_protection(self, target: str, endpoints: List[str]) -> List[Vulnerability]:
        """Test for brute force protection"""
        vulns = []
        
        for endpoint in endpoints[:2]:
            try:
                # Send multiple failed login attempts
                blocked = False
                for i in range(10):
                    response = await self.http.async_post(
                        endpoint,
                        data={"username": "testuser", "password": f"wrongpass{i}"}
                    )
                    
                    if response and response.status_code in [429, 403]:
                        blocked = True
                        break
                    
                    await asyncio.sleep(0.1)
                
                if not blocked:
                    vulns.append(Vulnerability(
                        name="No Brute Force Protection",
                        severity=SeverityLevel.MEDIUM,
                        description="No rate limiting or account lockout detected",
                        url=endpoint,
                        evidence="10 failed login attempts without blocking",
                        remediation="Implement rate limiting and account lockout",
                        cwe="CWE-307",
                        cvss=5.3
                    ))
            except:
                pass
        
        return vulns
    
    async def _test_account_enumeration(self, target: str, endpoints: List[str]) -> List[Vulnerability]:
        """Test for account enumeration"""
        vulns = []
        
        for endpoint in endpoints[:2]:
            try:
                # Test with known-invalid user
                response1 = await self.http.async_post(
                    endpoint,
                    data={"username": "definitelynotauser123456", "password": "test"}
                )
                
                # Test with common username
                response2 = await self.http.async_post(
                    endpoint,
                    data={"username": "admin", "password": "wrongpassword123"}
                )
                
                if response1 and response2:
                    # If responses differ significantly, account enumeration may be possible
                    if len(response1.text) != len(response2.text) or \
                       response1.status_code != response2.status_code:
                        vulns.append(Vulnerability(
                            name="Account Enumeration",
                            severity=SeverityLevel.MEDIUM,
                            description="Different responses for valid/invalid usernames",
                            url=endpoint,
                            evidence="Response differs based on username validity",
                            remediation="Use generic error messages",
                            cwe="CWE-204",
                            cvss=5.3
                        ))
            except:
                pass
        
        return vulns
    
    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        self.logger.vuln(vuln.severity.value, f"{vuln.name} found at {vuln.url}")


# =============================================================================
# 🔌 API SECURITY SCANNER (Feature #2)
# =============================================================================
class APISecurityScanner:
    """API security testing scanner"""
    
    def __init__(self, http_client: HTTPClient, logger: Logger):
        self.http = http_client
        self.logger = logger
        self.vulnerabilities = []
    
    async def scan(self, target: str) -> ScanResult:
        result = ScanResult(target=target, scan_type="api_security")
        start_time = time.time()
        
        self.logger.info(f"Starting API Security scan for {target}")
        
        # Find API endpoints
        api_endpoints = await self._discover_api_endpoints(target)
        self.logger.info(f"Found {len(api_endpoints)} API endpoints")
        
        vulnerabilities_found = []
        
        # Test each endpoint
        for endpoint in api_endpoints:
            # Test for BOLA/IDOR
            bola_vulns = await self._test_bola(endpoint)
            vulnerabilities_found.extend(bola_vulns)
            
            # Test for broken authentication
            auth_vulns = await self._test_broken_auth(endpoint)
            vulnerabilities_found.extend(auth_vulns)
            
            # Test for excessive data exposure
            exposure_vulns = await self._test_data_exposure(endpoint)
            vulnerabilities_found.extend(exposure_vulns)
            
            # Test for rate limiting
            rate_vulns = await self._test_rate_limiting(endpoint)
            vulnerabilities_found.extend(rate_vulns)
        
        # Test for API documentation exposure
        doc_vulns = await self._test_api_docs_exposure(target)
        vulnerabilities_found.extend(doc_vulns)
        
        result.data = {
            "api_endpoints": api_endpoints,
            "vulnerabilities_count": len(vulnerabilities_found),
        }
        result.vulnerabilities = [v.to_dict() for v in vulnerabilities_found]
        result.status = "completed"
        result.duration = time.time() - start_time
        
        return result
    
    async def _discover_api_endpoints(self, target: str) -> List[str]:
        """Discover API endpoints"""
        endpoints = []
        
        common_api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/graphql", "/graphiql",
            "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
            "/openapi", "/openapi.json", "/api-docs",
            "/v1", "/v2", "/v3",
            "/.well-known/openapi.json",
        ]
        
        for path in common_api_paths:
            url = urljoin(target, path)
            try:
                response = await self.http.async_get(url)
                if response and response.status_code in [200, 401, 403]:
                    endpoints.append(url)
                    self.logger.debug(f"Found API endpoint: {url}")
            except:
                pass
        
        # Try to discover from robots.txt
        try:
            robots_url = urljoin(target, "/robots.txt")
            response = await self.http.async_get(robots_url)
            if response and response.status_code == 200:
                for line in response.text.split("\n"):
                    if "api" in line.lower():
                        path = line.split(":")[-1].strip()
                        if path.startswith("/"):
                            endpoints.append(urljoin(target, path))
        except:
            pass
        
        return list(set(endpoints))
    
    async def _test_bola(self, endpoint: str) -> List[Vulnerability]:
        """Test for Broken Object Level Authorization (BOLA/IDOR)"""
        vulns = []
        
        # Try to access resources with different IDs
        test_ids = ["1", "2", "100", "admin", "0", "-1"]
        
        for test_id in test_ids:
            try:
                test_url = f"{endpoint}/{test_id}"
                response = await self.http.async_get(test_url)
                
                if response and response.status_code == 200:
                    # Check if we got actual data
                    if len(response.text) > 50 and "{" in response.text:
                        vulns.append(Vulnerability(
                            name="Potential BOLA/IDOR",
                            severity=SeverityLevel.HIGH,
                            description="API endpoint may be vulnerable to BOLA/IDOR",
                            url=test_url,
                            evidence=f"Accessed resource with ID: {test_id}",
                            remediation="Implement proper authorization checks",
                            cwe="CWE-639",
                            cvss=7.5
                        ))
                        break
            except:
                pass
        
        return vulns
    
    async def _test_broken_auth(self, endpoint: str) -> List[Vulnerability]:
        """Test for broken authentication"""
        vulns = []
        
        try:
            # Test without authentication
            response = await self.http.async_get(endpoint)
            
            if response and response.status_code == 200:
                # Check if endpoint returns sensitive data without auth
                sensitive_patterns = ["user", "email", "password", "token", "secret", "key"]
                if any(pattern in response.text.lower() for pattern in sensitive_patterns):
                    vulns.append(Vulnerability(
                        name="Unauthenticated API Access",
                        severity=SeverityLevel.HIGH,
                        description="API endpoint accessible without authentication",
                        url=endpoint,
                        evidence="Sensitive data returned without authentication",
                        remediation="Require authentication for all sensitive endpoints",
                        cwe="CWE-306",
                        cvss=7.5
                    ))
        except:
            pass
        
        return vulns
    
    async def _test_data_exposure(self, endpoint: str) -> List[Vulnerability]:
        """Test for excessive data exposure"""
        vulns = []
        
        try:
            response = await self.http.async_get(endpoint)
            
            if response and response.status_code == 200:
                # Check for sensitive fields in response
                sensitive_fields = [
                    "password", "secret", "token", "api_key", "private_key",
                    "ssn", "credit_card", "cvv", "bank_account",
                    "internal_id", "debug", "trace"
                ]
                
                for field in sensitive_fields:
                    if field in response.text.lower():
                        vulns.append(Vulnerability(
                            name="Excessive Data Exposure",
                            severity=SeverityLevel.MEDIUM,
                            description=f"API exposes potentially sensitive field: {field}",
                            url=endpoint,
                            evidence=f"Found '{field}' in API response",
                            remediation="Filter sensitive data from API responses",
                            cwe="CWE-200",
                            cvss=5.3
                        ))
                        break
        except:
            pass
        
        return vulns
    
    async def _test_rate_limiting(self, endpoint: str) -> List[Vulnerability]:
        """Test for rate limiting"""
        vulns = []
        
        try:
            # Send rapid requests
            blocked = False
            for i in range(20):
                response = await self.http.async_get(endpoint)
                if response and response.status_code == 429:
                    blocked = True
                    break
            
            if not blocked:
                vulns.append(Vulnerability(
                    name="No API Rate Limiting",
                    severity=SeverityLevel.LOW,
                    description="API endpoint lacks rate limiting",
                    url=endpoint,
                    evidence="20 rapid requests without throttling",
                    remediation="Implement rate limiting on API endpoints",
                    cwe="CWE-770",
                    cvss=4.3
                ))
        except:
            pass
        
        return vulns
    
    async def _test_api_docs_exposure(self, target: str) -> List[Vulnerability]:
        """Test for exposed API documentation"""
        vulns = []
        
        doc_paths = [
            "/swagger-ui.html", "/swagger-ui/", "/swagger.json",
            "/api-docs", "/openapi.json", "/openapi.yaml",
            "/graphql", "/graphiql", "/__schema",
        ]
        
        for path in doc_paths:
            try:
                url = urljoin(target, path)
                response = await self.http.async_get(url)
                
                if response and response.status_code == 200:
                    vulns.append(Vulnerability(
                        name="Exposed API Documentation",
                        severity=SeverityLevel.LOW,
                        description=f"API documentation exposed at {path}",
                        url=url,
                        evidence="API documentation publicly accessible",
                        remediation="Restrict access to API documentation in production",
                        cwe="CWE-200",
                        cvss=3.7
                    ))
            except:
                pass
        
        return vulns
    
    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        self.logger.vuln(vuln.severity.value, f"{vuln.name} found at {vuln.url}")


# =============================================================================
# 🎫 JWT TOKEN ANALYSIS (Feature #3)
# =============================================================================
class JWTAnalyzer:
    """JWT Token security analyzer"""
    
    def __init__(self, http_client: HTTPClient, logger: Logger):
        self.http = http_client
        self.logger = logger
        self.vulnerabilities = []
    
    async def scan(self, target: str) -> ScanResult:
        result = ScanResult(target=target, scan_type="jwt_analysis")
        start_time = time.time()
        
        self.logger.info(f"Starting JWT Analysis for {target}")
        
        # Find JWT tokens
        tokens = await self._find_jwt_tokens(target)
        self.logger.info(f"Found {len(tokens)} JWT tokens")
        
        vulnerabilities_found = []
        
        for token in tokens:
            # Analyze token structure
            token_vulns = self._analyze_token(token)
            vulnerabilities_found.extend(token_vulns)
            
            # Test for algorithm confusion
            alg_vulns = await self._test_algorithm_confusion(target, token)
            vulnerabilities_found.extend(alg_vulns)
            
            # Test for weak secrets
            secret_vulns = self._test_weak_secrets(token)
            vulnerabilities_found.extend(secret_vulns)
        
        result.data = {
            "tokens_found": len(tokens),
            "vulnerabilities_count": len(vulnerabilities_found),
        }
        result.vulnerabilities = [v.to_dict() for v in vulnerabilities_found]
        result.status = "completed"
        result.duration = time.time() - start_time
        
        return result
    
    async def _find_jwt_tokens(self, target: str) -> List[str]:
        """Find JWT tokens in responses and cookies"""
        tokens = []
        
        try:
            response = await self.http.async_get(target)
            if response:
                # Check response body
                jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
                matches = re.findall(jwt_pattern, response.text)
                tokens.extend(matches)
                
                # Check cookies
                if hasattr(response, 'cookies'):
                    for cookie in response.cookies:
                        if cookie.value and cookie.value.startswith('eyJ'):
                            tokens.append(cookie.value)
                
                # Check headers
                for header in ['Authorization', 'X-Auth-Token', 'X-JWT-Token']:
                    if header in response.headers:
                        value = response.headers[header]
                        if 'Bearer ' in value:
                            tokens.append(value.replace('Bearer ', ''))
                        elif value.startswith('eyJ'):
                            tokens.append(value)
        except:
            pass
        
        return list(set(tokens))
    
    def _decode_jwt(self, token: str) -> Tuple[Dict, Dict, str]:
        """Decode JWT token without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {}, {}, ""
            
            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))
            
            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            
            return header, payload, parts[2]
        except:
            return {}, {}, ""
    
    def _analyze_token(self, token: str) -> List[Vulnerability]:
        """Analyze JWT token for vulnerabilities"""
        vulns = []
        
        header, payload, signature = self._decode_jwt(token)
        
        if not header:
            return vulns
        
        # Check algorithm
        alg = header.get('alg', '')
        
        if alg == 'none':
            vulns.append(Vulnerability(
                name="JWT None Algorithm",
                severity=SeverityLevel.CRITICAL,
                description="JWT uses 'none' algorithm - no signature verification",
                url="",
                evidence=f"Algorithm: {alg}",
                remediation="Always use secure algorithms (RS256, ES256)",
                cwe="CWE-327",
                cvss=9.8
            ))
        
        if alg in ['HS256', 'HS384', 'HS512']:
            vulns.append(Vulnerability(
                name="JWT Uses Symmetric Algorithm",
                severity=SeverityLevel.MEDIUM,
                description="JWT uses symmetric algorithm - vulnerable to brute force",
                url="",
                evidence=f"Algorithm: {alg}",
                remediation="Consider using asymmetric algorithms (RS256, ES256)",
                cwe="CWE-327",
                cvss=5.3
            ))
        
        # Check for sensitive data in payload
        sensitive_fields = ['password', 'secret', 'private_key', 'api_key']
        for field in sensitive_fields:
            if field in str(payload).lower():
                vulns.append(Vulnerability(
                    name="Sensitive Data in JWT",
                    severity=SeverityLevel.HIGH,
                    description=f"JWT payload contains sensitive field: {field}",
                    url="",
                    evidence=f"Found '{field}' in payload",
                    remediation="Never store sensitive data in JWT payloads",
                    cwe="CWE-200",
                    cvss=7.5
                ))
        
        # Check expiration
        exp = payload.get('exp')
        if not exp:
            vulns.append(Vulnerability(
                name="JWT No Expiration",
                severity=SeverityLevel.MEDIUM,
                description="JWT token has no expiration claim",
                url="",
                evidence="Missing 'exp' claim",
                remediation="Always set token expiration",
                cwe="CWE-613",
                cvss=5.3
            ))
        elif exp < time.time():
            vulns.append(Vulnerability(
                name="JWT Expired Token Accepted",
                severity=SeverityLevel.HIGH,
                description="Server may accept expired JWT tokens",
                url="",
                evidence=f"Token expired at: {datetime.fromtimestamp(exp)}",
                remediation="Validate token expiration on server",
                cwe="CWE-613",
                cvss=7.5
            ))
        
        return vulns
    
    async def _test_algorithm_confusion(self, target: str, token: str) -> List[Vulnerability]:
        """Test for algorithm confusion attacks"""
        vulns = []
        
        header, payload, _ = self._decode_jwt(token)
        
        if not header:
            return vulns
        
        # Try changing algorithm to 'none'
        try:
            header['alg'] = 'none'
            new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
            
            forged_token = f"{new_header}.{payload_b64}."
            
            # Try using the forged token
            response = await self.http.async_get(
                target,
                headers={"Authorization": f"Bearer {forged_token}"}
            )
            
            if response and response.status_code in [200, 201]:
                vulns.append(Vulnerability(
                    name="JWT Algorithm Confusion",
                    severity=SeverityLevel.CRITICAL,
                    description="Server accepts JWT with 'none' algorithm",
                    url=target,
                    evidence="Forged token with 'none' algorithm accepted",
                    remediation="Whitelist allowed algorithms server-side",
                    cwe="CWE-327",
                    cvss=9.8
                ))
        except:
            pass
        
        return vulns
    
    def _test_weak_secrets(self, token: str) -> List[Vulnerability]:
        """Test for weak JWT secrets"""
        vulns = []
        
        header, payload, signature = self._decode_jwt(token)
        
        if not header or header.get('alg') not in ['HS256', 'HS384', 'HS512']:
            return vulns
        
        # Get the algorithm
        alg = header.get('alg')
        hash_func = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }.get(alg, hashlib.sha256)
        
        # Try common secrets
        header_b64 = token.split('.')[0]
        payload_b64 = token.split('.')[1]
        message = f"{header_b64}.{payload_b64}".encode()
        
        for secret in Config.JWT_COMMON_SECRETS:
            try:
                computed_sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message, hash_func).digest()
                ).rstrip(b'=').decode()
                
                if computed_sig == signature:
                    vulns.append(Vulnerability(
                        name="Weak JWT Secret",
                        severity=SeverityLevel.CRITICAL,
                        description=f"JWT signed with weak/common secret: {secret}",
                        url="",
                        evidence=f"Secret: {secret}",
                        remediation="Use strong, random secrets (min 256 bits)",
                        cwe="CWE-798",
                        cvss=9.8
                    ))
                    break
            except:
                pass
        
        return vulns
    
    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        self.logger.vuln(vuln.severity.value, f"{vuln.name}")


# =============================================================================
# 📤 ADVANCED FILE UPLOAD TESTING (Feature #4)
# =============================================================================
class FileUploadScanner:
    """Advanced file upload security testing"""
    
    def __init__(self, http_client: HTTPClient, logger: Logger):
        self.http = http_client
        self.logger = logger
        self.vulnerabilities = []
    
    async def scan(self, target: str) -> ScanResult:
        result = ScanResult(target=target, scan_type="file_upload")
        start_time = time.time()
        
        self.logger.info(f"Starting File Upload scan for {target}")
        
        # Find upload endpoints
        upload_endpoints = await self._find_upload_endpoints(target)
        self.logger.info(f"Found {len(upload_endpoints)} upload endpoints")
        
        vulnerabilities_found = []
        
        for endpoint in upload_endpoints:
            # Test for dangerous file type uploads
            type_vulns = await self._test_dangerous_file_types(endpoint)
            vulnerabilities_found.extend(type_vulns)
            
            # Test for bypass techniques
            bypass_vulns = await self._test_bypass_techniques(endpoint)
            vulnerabilities_found.extend(bypass_vulns)
            
            # Test for path traversal in filename
            traversal_vulns = await self._test_path_traversal(endpoint)
            vulnerabilities_found.extend(traversal_vulns)
        
        result.data = {
            "upload_endpoints": upload_endpoints,
            "vulnerabilities_count": len(vulnerabilities_found),
        }
        result.vulnerabilities = [v.to_dict() for v in vulnerabilities_found]
        result.status = "completed"
        result.duration = time.time() - start_time
        
        return result
    
    async def _find_upload_endpoints(self, target: str) -> List[str]:
        """Find file upload endpoints"""
        endpoints = []
        
        common_paths = [
            "/upload", "/file-upload", "/api/upload", "/files/upload",
            "/media/upload", "/image/upload", "/document/upload",
            "/avatar/upload", "/profile/upload", "/attachment",
        ]
        
        for path in common_paths:
            url = urljoin(target, path)
            try:
                response = await self.http.async_get(url)
                if response and response.status_code in [200, 405]:
                    endpoints.append(url)
            except:
                pass
        
        # Crawl for forms with file inputs
        try:
            response = await self.http.async_get(target)
            if response and response.text:
                soup = BeautifulSoup(response.text, 'html.parser')
                for form in soup.find_all('form', enctype='multipart/form-data'):
                    action = form.get('action', '')
                    if action:
                        endpoints.append(urljoin(target, action))
                
                for input_field in soup.find_all('input', type='file'):
                    form = input_field.find_parent('form')
                    if form:
                        action = form.get('action', '')
                        if action:
                            endpoints.append(urljoin(target, action))
        except:
            pass
        
        return list(set(endpoints))
    
    async def _test_dangerous_file_types(self, endpoint: str) -> List[Vulnerability]:
        """Test uploading dangerous file types"""
        vulns = []
        
        test_files = [
            ("test.php", b"<?php echo 'test'; ?>", "application/x-php"),
            ("test.jsp", b"<% out.println(\"test\"); %>", "application/x-jsp"),
            ("test.aspx", b"<% Response.Write(\"test\") %>", "application/x-aspx"),
            ("test.svg", b'<svg onload="alert(1)">', "image/svg+xml"),
        ]
        
        for filename, content, mimetype in test_files:
            try:
                files = {'file': (filename, content, mimetype)}
                response = await self.http.async_post(endpoint, data={'submit': 'Upload'})
                
                if response and response.status_code == 200:
                    if "success" in response.text.lower() or "uploaded" in response.text.lower():
                        vulns.append(Vulnerability(
                            name=f"Dangerous File Upload: {filename}",
                            severity=SeverityLevel.CRITICAL,
                            description=f"Server accepts dangerous file type: {filename}",
                            url=endpoint,
                            payload=filename,
                            evidence="File upload appeared successful",
                            remediation="Whitelist allowed file types, validate content",
                            cwe="CWE-434",
                            cvss=9.8
                        ))
            except:
                pass
        
        return vulns
    
    async def _test_bypass_techniques(self, endpoint: str) -> List[Vulnerability]:
        """Test file upload bypass techniques"""
        vulns = []
        
        bypass_files = [
            # Double extension
            ("test.php.jpg", b"<?php echo 'test'; ?>"),
            # Null byte
            ("test.php%00.jpg", b"<?php echo 'test'; ?>"),
            # Case variation
            ("test.PHP", b"<?php echo 'test'; ?>"),
            ("test.pHp", b"<?php echo 'test'; ?>"),
            # Alternative extensions
            ("test.php5", b"<?php echo 'test'; ?>"),
            ("test.phtml", b"<?php echo 'test'; ?>"),
            # MIME type mismatch
            ("test.gif", b"GIF89a<?php echo 'test'; ?>"),
        ]
        
        for filename, content in bypass_files:
            try:
                response = await self.http.async_post(endpoint, data={'submit': 'Upload'})
                
                if response and response.status_code == 200:
                    if "success" in response.text.lower():
                        vulns.append(Vulnerability(
                            name="File Upload Filter Bypass",
                            severity=SeverityLevel.HIGH,
                            description=f"Filter bypass successful with: {filename}",
                            url=endpoint,
                            payload=filename,
                            evidence="Bypass technique accepted",
                            remediation="Use robust file type validation",
                            cwe="CWE-434",
                            cvss=8.6
                        ))
            except:
                pass
        
        return vulns
    
    async def _test_path_traversal(self, endpoint: str) -> List[Vulnerability]:
        """Test for path traversal in uploaded filename"""
        vulns = []
        
        traversal_filenames = [
            "../../../etc/passwd.txt",
            "..\\..\\..\\windows\\system32\\config\\sam.txt",
            "....//....//....//etc/passwd.txt",
        ]
        
        for filename in traversal_filenames:
            try:
                response = await self.http.async_post(endpoint, data={'submit': 'Upload'})
                
                if response and response.status_code == 200:
                    # This would need more sophisticated detection
                    pass
            except:
                pass
        
        return vulns
    
    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        self.logger.vuln(vuln.severity.value, f"{vuln.name} found at {vuln.url}")


# =============================================================================
# 🔐 DEEP SESSION MANAGEMENT (Feature #5)
# =============================================================================
class SessionManagementScanner:
    """Deep session management security testing"""
    
    def __init__(self, http_client: HTTPClient, logger: Logger):
        self.http = http_client
        self.logger = logger
        self.vulnerabilities = []
    
    async def scan(self, target: str) -> ScanResult:
        result = ScanResult(target=target, scan_type="session_management")
        start_time = time.time()
        
        self.logger.info(f"Starting Session Management scan for {target}")
        
        vulnerabilities_found = []
        
        # Analyze session cookies
        cookie_vulns = await self._analyze_session_cookies(target)
        vulnerabilities_found.extend(cookie_vulns)
        
        # Test session fixation
        fixation_vulns = await self._test_session_fixation(target)
        vulnerabilities_found.extend(fixation_vulns)
        
        # Test session timeout
        timeout_vulns = await self._test_session_timeout(target)
        vulnerabilities_found.extend(timeout_vulns)
        
        # Test concurrent sessions
        concurrent_vulns = await self._test_concurrent_sessions(target)
        vulnerabilities_found.extend(concurrent_vulns)
        
        result.data = {
            "vulnerabilities_count": len(vulnerabilities_found),
        }
        result.vulnerabilities = [v.to_dict() for v in vulnerabilities_found]
        result.status = "completed"
        result.duration = time.time() - start_time
        
        return result
    
    async def _analyze_session_cookies(self, target: str) -> List[Vulnerability]:
        """Analyze session cookie security"""
        vulns = []
        
        try:
            response = await self.http.async_get(target)
            
            if response and hasattr(response, 'cookies'):
                for cookie in response.cookies.jar:
                    name = cookie.name
                    
                    # Check if it's a session cookie
                    if not any(sess in name.lower() for sess in ['sess', 'session', 'sid', 'token', 'auth']):
                        continue
                    
                    # Check Secure flag
                    if not cookie.secure and target.startswith('https'):
                        vulns.append(Vulnerability(
                            name="Session Cookie Missing Secure Flag",
                            severity=SeverityLevel.MEDIUM,
                            description=f"Cookie '{name}' missing Secure flag",
                            url=target,
                            evidence=f"Cookie: {name}",
                            remediation="Set Secure flag on session cookies",
                            cwe="CWE-614",
                            cvss=5.3
                        ))
                    
                    # Check HttpOnly flag
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        vulns.append(Vulnerability(
                            name="Session Cookie Missing HttpOnly Flag",
                            severity=SeverityLevel.MEDIUM,
                            description=f"Cookie '{name}' missing HttpOnly flag",
                            url=target,
                            evidence=f"Cookie: {name}",
                            remediation="Set HttpOnly flag to prevent XSS cookie theft",
                            cwe="CWE-1004",
                            cvss=5.3
                        ))
                    
                    # Check SameSite attribute
                    samesite = cookie.get_nonstandard_attr('SameSite')
                    if not samesite or samesite.lower() == 'none':
                        vulns.append(Vulnerability(
                            name="Session Cookie Weak SameSite",
                            severity=SeverityLevel.LOW,
                            description=f"Cookie '{name}' has weak SameSite attribute",
                            url=target,
                            evidence=f"SameSite: {samesite or 'Not set'}",
                            remediation="Set SameSite=Strict or SameSite=Lax",
                            cwe="CWE-1275",
                            cvss=4.3
                        ))
                    
                    # Check session ID entropy
                    if len(cookie.value) < 16:
                        vulns.append(Vulnerability(
                            name="Weak Session ID",
                            severity=SeverityLevel.HIGH,
                            description=f"Session ID appears to have low entropy",
                            url=target,
                            evidence=f"Session ID length: {len(cookie.value)}",
                            remediation="Use cryptographically secure random session IDs",
                            cwe="CWE-330",
                            cvss=7.5
                        ))
        except:
            pass
        
        return vulns
    
    async def _test_session_fixation(self, target: str) -> List[Vulnerability]:
        """Test for session fixation vulnerability"""
        vulns = []
        
        try:
            # Get initial session
            response1 = await self.http.async_get(target)
            session1 = None
            
            if response1 and hasattr(response1, 'cookies'):
                for cookie in response1.cookies.jar:
                    if any(s in cookie.name.lower() for s in ['sess', 'session', 'sid']):
                        session1 = cookie.value
                        break
            
            if session1:
                # Try to authenticate (simulated)
                login_url = urljoin(target, "/login")
                response2 = await self.http.async_post(login_url, data={})
                
                session2 = None
                if response2 and hasattr(response2, 'cookies'):
                    for cookie in response2.cookies.jar:
                        if any(s in cookie.name.lower() for s in ['sess', 'session', 'sid']):
                            session2 = cookie.value
                            break
                
                # If session didn't change after auth, it might be fixation
                if session2 and session1 == session2:
                    vulns.append(Vulnerability(
                        name="Potential Session Fixation",
                        severity=SeverityLevel.HIGH,
                        description="Session ID not regenerated after authentication",
                        url=target,
                        evidence="Same session ID before and after login attempt",
                        remediation="Regenerate session ID after authentication",
                        cwe="CWE-384",
                        cvss=7.5
                    ))
        except:
            pass
        
        return vulns
    
    async def _test_session_timeout(self, target: str) -> List[Vulnerability]:
        """Test session timeout handling"""
        vulns = []
        # This would require maintaining a session over time
        # For now, just check for logout functionality
        
        logout_paths = ["/logout", "/signout", "/api/logout", "/auth/logout"]
        has_logout = False
        
        for path in logout_paths:
            try:
                url = urljoin(target, path)
                response = await self.http.async_get(url)
                if response and response.status_code in [200, 302]:
                    has_logout = True
                    break
            except:
                pass
        
        if not has_logout:
            vulns.append(Vulnerability(
                name="No Logout Functionality Found",
                severity=SeverityLevel.LOW,
                description="No obvious logout endpoint detected",
                url=target,
                evidence="Common logout paths not found",
                remediation="Implement proper session termination",
                cwe="CWE-613",
                cvss=3.7
            ))
        
        return vulns
    
    async def _test_concurrent_sessions(self, target: str) -> List[Vulnerability]:
        """Test concurrent session handling"""
        vulns = []
        # This would require actual authentication
        # Placeholder for the test
        return vulns
    
    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        self.logger.vuln(vuln.severity.value, f"{vuln.name}")


# =============================================================================
# 🔒 ADVANCED CRYPTOGRAPHY TESTING (Feature #6)
# =============================================================================
class CryptographyScanner:
    """Advanced cryptography security testing"""
    
    def __init__(self, http_client: HTTPClient, logger: Logger):
        self.http = http_client
        self.logger = logger
        self.vulnerabilities = []
    
    async def scan(self, target: str) -> ScanResult:
        result = ScanResult(target=target, scan_type="cryptography")
        start_time = time.time()
        
        self.logger.info(f"Starting Cryptography scan for {target}")
        
        vulnerabilities_found = []
        
        # Analyze SSL/TLS configuration
        ssl_vulns = await self._analyze_ssl_tls(target)
        vulnerabilities_found.extend(ssl_vulns)
        
        # Check certificate validity
        cert_vulns = await self._check_certificate(target)
        vulnerabilities_found.extend(cert_vulns)
        
        # Check for weak ciphers
        cipher_vulns = await self._check_weak_ciphers(target)
        vulnerabilities_found.extend(cipher_vulns)
        
        result.data = {
            "vulnerabilities_count": len(vulnerabilities_found),
        }
        result.vulnerabilities = [v.to_dict() for v in vulnerabilities_found]
        result.status = "completed"
        result.duration = time.time() - start_time
        
        return result
    
    async def _analyze_ssl_tls(self, target: str) -> List[Vulnerability]:
        """Analyze SSL/TLS configuration"""
        vulns = []
        
        parsed = urlparse(target)
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        if parsed.scheme != 'https':
            vulns.append(Vulnerability(
                name="No HTTPS",
                severity=SeverityLevel.HIGH,
                description="Target does not use HTTPS",
                url=target,
                evidence="HTTP scheme detected",
                remediation="Enable HTTPS with valid certificate",
                cwe="CWE-319",
                cvss=7.5
            ))
            return vulns
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get SSL version
                    ssl_version = ssock.version()
                    
                    if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulns.append(Vulnerability(
                            name="Outdated TLS Version",
                            severity=SeverityLevel.HIGH,
                            description=f"Server supports outdated protocol: {ssl_version}",
                            url=target,
                            evidence=f"Protocol: {ssl_version}",
                            remediation="Disable TLS 1.0/1.1, use TLS 1.2+",
                            cwe="CWE-326",
                            cvss=7.5
                        ))
                    
                    # Get cipher
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for weak in Config.WEAK_CIPHERS:
                            if weak in cipher_name.upper():
                                vulns.append(Vulnerability(
                                    name="Weak Cipher Suite",
                                    severity=SeverityLevel.MEDIUM,
                                    description=f"Server uses weak cipher: {cipher_name}",
                                    url=target,
                                    evidence=f"Cipher: {cipher_name}",
                                    remediation="Disable weak cipher suites",
                                    cwe="CWE-327",
                                    cvss=5.9
                                ))
                                break
        except Exception as e:
            self.logger.debug(f"SSL analysis error: {str(e)}")
        
        return vulns
    
    async def _check_certificate(self, target: str) -> List[Vulnerability]:
        """Check SSL certificate validity"""
        vulns = []
        
        parsed = urlparse(target)
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or 443
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    # Check expiration
                    if cert.not_valid_after_utc < datetime.now(cert.not_valid_after_utc.tzinfo):
                        vulns.append(Vulnerability(
                            name="Expired SSL Certificate",
                            severity=SeverityLevel.HIGH,
                            description="SSL certificate has expired",
                            url=target,
                            evidence=f"Expired: {cert.not_valid_after_utc}",
                            remediation="Renew SSL certificate",
                            cwe="CWE-295",
                            cvss=7.5
                        ))
                    
                    # Check if expires soon (30 days)
                    days_until_expiry = (cert.not_valid_after_utc - datetime.now(cert.not_valid_after_utc.tzinfo)).days
                    if 0 < days_until_expiry < 30:
                        vulns.append(Vulnerability(
                            name="SSL Certificate Expiring Soon",
                            severity=SeverityLevel.LOW,
                            description=f"Certificate expires in {days_until_expiry} days",
                            url=target,
                            evidence=f"Expires: {cert.not_valid_after_utc}",
                            remediation="Renew certificate before expiration",
                            cwe="CWE-295",
                            cvss=3.7
                        ))
                    
                    # Check key size
                    public_key = cert.public_key()
                    if hasattr(public_key, 'key_size'):
                        if public_key.key_size < 2048:
                            vulns.append(Vulnerability(
                                name="Weak SSL Key Size",
                                severity=SeverityLevel.MEDIUM,
                                description=f"RSA key size is weak: {public_key.key_size} bits",
                                url=target,
                                evidence=f"Key size: {public_key.key_size}",
                                remediation="Use minimum 2048-bit RSA keys",
                                cwe="CWE-326",
                                cvss=5.9
                            ))
        except Exception as e:
            self.logger.debug(f"Certificate check error: {str(e)}")
        
        return vulns
    
    async def _check_weak_ciphers(self, target: str) -> List[Vulnerability]:
        """Test for weak cipher support"""
        vulns = []
        
        parsed = urlparse(target)
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or 443
        
        weak_cipher_tests = [
            ('RC4', 'RC4-SHA'),
            ('DES', 'DES-CBC3-SHA'),
            ('NULL', 'NULL-SHA'),
        ]
        
        for cipher_type, cipher_name in weak_cipher_tests:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers(cipher_name)
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        vulns.append(Vulnerability(
                            name=f"Weak Cipher Supported: {cipher_type}",
                            severity=SeverityLevel.MEDIUM,
                            description=f"Server supports weak cipher: {cipher_name}",
                            url=target,
                            evidence=f"Cipher: {cipher_name}",
                            remediation=f"Disable {cipher_type} cipher suites",
                            cwe="CWE-327",
                            cvss=5.9
                        ))
            except:
                pass  # Cipher not supported, which is good
        
        return vulns
    
    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        self.logger.vuln(vuln.severity.value, f"{vuln.name}")


# =============================================================================
# 📊 ADVANCED REPORTS (Feature #14)
# =============================================================================
class AdvancedReportGenerator:
    """Advanced report generation with multiple formats and visualizations"""
    
    def __init__(self, results: List[ScanResult], target: str):
        self.results = results
        self.target = target
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.console = Console()
    
    def generate(self, format: str = "html") -> str:
        """Generate report in specified format"""
        if format == "html":
            return self._generate_advanced_html()
        elif format == "json":
            return self._generate_json()
        elif format == "pdf":
            return self._generate_pdf_ready_html()
        elif format == "executive":
            return self._generate_executive_summary()
        else:
            return self._generate_json()
    
    def _generate_advanced_html(self) -> str:
        """Generate advanced HTML report with charts and visualizations"""
        total_vulns = sum(len(r.vulnerabilities) for r in self.results)
        
        severity_counts = {
            "critical": sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "critical"),
            "high": sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "high"),
            "medium": sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "medium"),
            "low": sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "low"),
        }
        
        # Calculate risk score
        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 7 +
            severity_counts["medium"] * 4 +
            severity_counts["low"] * 1
        )
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OxTrace Security Report - {self.target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', system-ui, sans-serif; 
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
            color: #e0e0e0; 
            min-height: 100vh;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 30px; }}
        
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 50px;
            border-radius: 20px;
            margin-bottom: 40px;
            border: 1px solid #00d4ff33;
            position: relative;
            overflow: hidden;
        }}
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 100%;
            height: 200%;
            background: radial-gradient(circle, #00d4ff11 0%, transparent 70%);
        }}
        .header h1 {{ 
            color: #00d4ff; 
            font-size: 3em; 
            margin-bottom: 15px;
            position: relative;
        }}
        .header p {{ color: #888; position: relative; }}
        
        .risk-score {{
            background: linear-gradient(135deg, #ff004033, #ff6b0033);
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 40px;
            border: 1px solid #ff004066;
        }}
        .risk-score h2 {{ color: #ff6b00; font-size: 4em; }}
        .risk-score p {{ color: #aaa; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: #1a1a2e;
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            border: 1px solid #333;
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,212,255,0.2);
        }}
        .stat-card.critical {{ border-color: #ff0040; }}
        .stat-card.high {{ border-color: #ff6b00; }}
        .stat-card.medium {{ border-color: #ffcc00; }}
        .stat-card.low {{ border-color: #00ff88; }}
        .stat-number {{ font-size: 3.5em; font-weight: bold; }}
        .stat-card.critical .stat-number {{ color: #ff0040; }}
        .stat-card.high .stat-number {{ color: #ff6b00; }}
        .stat-card.medium .stat-number {{ color: #ffcc00; }}
        .stat-card.low .stat-number {{ color: #00ff88; }}
        
        .charts-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 40px;
        }}
        .chart-card {{
            background: #1a1a2e;
            padding: 25px;
            border-radius: 15px;
            border: 1px solid #333;
        }}
        .chart-card h3 {{ color: #00d4ff; margin-bottom: 20px; }}
        
        .vuln-list {{
            background: #1a1a2e;
            border-radius: 15px;
            padding: 30px;
            border: 1px solid #333;
        }}
        .vuln-item {{
            background: #0a0a0f;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            border-left: 5px solid #00d4ff;
            transition: transform 0.2s;
        }}
        .vuln-item:hover {{ transform: translateX(5px); }}
        .vuln-item.critical {{ border-left-color: #ff0040; }}
        .vuln-item.high {{ border-left-color: #ff6b00; }}
        .vuln-item.medium {{ border-left-color: #ffcc00; }}
        .vuln-item.low {{ border-left-color: #00ff88; }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .severity-badge.critical {{ background: #ff004033; color: #ff0040; }}
        .severity-badge.high {{ background: #ff6b0033; color: #ff6b00; }}
        .severity-badge.medium {{ background: #ffcc0033; color: #ffcc00; }}
        .severity-badge.low {{ background: #00ff8833; color: #00ff88; }}
        
        code {{ 
            background: #0a0a0f; 
            padding: 3px 8px; 
            border-radius: 5px; 
            font-family: 'Fira Code', monospace;
            color: #00ff88;
        }}
        
        .footer {{
            text-align: center;
            padding: 40px;
            color: #666;
            border-top: 1px solid #333;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 OxTrace Security Report</h1>
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
        </div>
        
        <div class="risk-score">
            <h2>{risk_score}</h2>
            <p>Overall Risk Score</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-number">{severity_counts['critical']}</div>
                <div>Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{severity_counts['high']}</div>
                <div>High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{severity_counts['medium']}</div>
                <div>Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{severity_counts['low']}</div>
                <div>Low</div>
            </div>
        </div>
        
        <div class="charts-container">
            <div class="chart-card">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Vulnerabilities by Module</h3>
                <canvas id="moduleChart"></canvas>
            </div>
        </div>
        
        <div class="vuln-list">
            <h2 style="color: #00d4ff; margin-bottom: 25px;">📋 Detailed Findings</h2>
"""
        
        # Add vulnerabilities
        all_vulns = sorted(
            [v for r in self.results for v in r.vulnerabilities],
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "low"), 4)
        )
        
        for vuln in all_vulns:
            severity = vuln.get("severity", "low")
            html += f"""
            <div class="vuln-item {severity}">
                <h3>{vuln.get("name", "Unknown")}</h3>
                <span class="severity-badge {severity}">{severity.upper()}</span>
                <span class="severity-badge" style="background: #00d4ff33; color: #00d4ff;">CVSS: {vuln.get("cvss", "N/A")}</span>
                <p style="margin: 15px 0;"><strong>URL:</strong> <code>{vuln.get("url", "N/A")}</code></p>
                <p><strong>Description:</strong> {vuln.get("description", "N/A")}</p>
                <p><strong>Evidence:</strong> <code>{vuln.get("evidence", "N/A")[:200]}</code></p>
                <p style="color: #00ff88;"><strong>Remediation:</strong> {vuln.get("remediation", "N/A")}</p>
            </div>
"""
        
        # Module data for chart
        module_counts = {}
        for r in self.results:
            module_counts[r.scan_type] = len(r.vulnerabilities)
        
        html += f"""
        </div>
        
        <div class="footer">
            <p>Generated by OxTrace v5.0 - Advanced Security Reconnaissance Tool</p>
            <p>⚠️ Use responsibly and only on authorized targets</p>
        </div>
    </div>
    
    <script>
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{severity_counts['critical']}, {severity_counts['high']}, {severity_counts['medium']}, {severity_counts['low']}],
                    backgroundColor: ['#ff0040', '#ff6b00', '#ffcc00', '#00ff88'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                plugins: {{
                    legend: {{
                        labels: {{ color: '#e0e0e0' }}
                    }}
                }}
            }}
        }});
        
        // Module Chart
        new Chart(document.getElementById('moduleChart'), {{
            type: 'bar',
            data: {{
                labels: {list(module_counts.keys())},
                datasets: [{{
                    label: 'Vulnerabilities',
                    data: {list(module_counts.values())},
                    backgroundColor: '#00d4ff',
                    borderRadius: 5
                }}]
            }},
            options: {{
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        ticks: {{ color: '#e0e0e0' }},
                        grid: {{ color: '#333' }}
                    }},
                    x: {{
                        ticks: {{ color: '#e0e0e0' }},
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        return html
    
    def _generate_json(self) -> str:
        """Generate JSON report"""
        report = {
            "meta": {
                "tool": "OxTrace",
                "version": Config.VERSION,
                "target": self.target,
                "timestamp": self.timestamp,
            },
            "summary": {
                "total_vulnerabilities": sum(len(r.vulnerabilities) for r in self.results),
                "by_severity": {
                    "critical": sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "critical"),
                    "high": sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "high"),
                    "medium": sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "medium"),
                    "low": sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "low"),
                }
            },
            "scans": [r.to_dict() for r in self.results],
        }
        return json.dumps(report, indent=2, default=str)
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary report"""
        total_vulns = sum(len(r.vulnerabilities) for r in self.results)
        critical = sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "critical")
        high = sum(1 for r in self.results for v in r.vulnerabilities if v.get("severity") == "high")
        
        summary = f"""
════════════════════════════════════════════════════════════════════════════════
                         EXECUTIVE SECURITY SUMMARY
════════════════════════════════════════════════════════════════════════════════

TARGET: {self.target}
DATE: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
ASSESSED BY: OxTrace v5.0

────────────────────────────────────────────────────────────────────────────────
                              RISK OVERVIEW
────────────────────────────────────────────────────────────────────────────────

Total Vulnerabilities Found: {total_vulns}
Critical Issues: {critical}
High Issues: {high}

RISK RATING: {"CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM"}

────────────────────────────────────────────────────────────────────────────────
                           KEY FINDINGS
────────────────────────────────────────────────────────────────────────────────
"""
        
        # Add top 5 critical findings
        critical_vulns = [v for r in self.results for v in r.vulnerabilities if v.get("severity") == "critical"][:5]
        
        for i, vuln in enumerate(critical_vulns, 1):
            summary += f"""
{i}. {vuln.get("name", "Unknown")}
   Severity: CRITICAL
   URL: {vuln.get("url", "N/A")}
   Recommendation: {vuln.get("remediation", "N/A")}
"""
        
        summary += """
────────────────────────────────────────────────────────────────────────────────
                          RECOMMENDATIONS
────────────────────────────────────────────────────────────────────────────────

1. Address all CRITICAL vulnerabilities immediately
2. Implement security headers on all web resources
3. Review authentication and session management
4. Conduct regular security assessments
5. Implement a vulnerability management program

════════════════════════════════════════════════════════════════════════════════
                          END OF REPORT
════════════════════════════════════════════════════════════════════════════════
"""
        
        return summary
    
    def _generate_pdf_ready_html(self) -> str:
        """Generate HTML optimized for PDF conversion"""
        # Returns the same as advanced HTML but with print-friendly styles
        return self._generate_advanced_html()
    
    def save(self, format: str = "html", output_dir: str = "reports") -> str:
        """Save report to file"""
        os.makedirs(output_dir, exist_ok=True)
        
        content = self.generate(format)
        
        safe_target = re.sub(r'[^\w\-.]', '_', self.target.replace("https://", "").replace("http://", ""))[:50]
        ext = "html" if format in ["html", "pdf"] else format if format != "executive" else "txt"
        filename = f"{output_dir}/oxtrace_{safe_target}_{self.timestamp}.{ext}"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        
        return filename


# =============================================================================
# 🔍 BASE SCANNER CLASS
# =============================================================================
class BaseScanner(ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self, http_client: HTTPClient, logger: Logger):
        self.http = http_client
        self.logger = logger
        self.results = []
        self.vulnerabilities = []
    
    @abstractmethod
    async def scan(self, target: str) -> ScanResult:
        pass
    
    def add_vulnerability(self, vuln: Vulnerability):
        if any(v.name == vuln.name and v.url == vuln.url for v in self.vulnerabilities):
            return
        self.vulnerabilities.append(vuln)
        self.logger.vuln(vuln.severity.value, f"{vuln.name} found at {vuln.url}")


# =============================================================================
# 🏠 MAIN OXTRACE ENGINE
# =============================================================================
class OxTrace:
    """Main OxTrace scanner engine"""
    
    def __init__(self, config: Optional[Dict] = None, verbose: bool = False):
        self.config = config or {}
        self.realtime_display = RealTimeDisplay()
        self.logger = Logger(verbose=verbose, realtime_display=self.realtime_display)
        self.http = HTTPClient(realtime_display=self.realtime_display)
        self.thread_engine = MultiThreadEngine()
        self.legal = LegalFramework()
        self.results: List[ScanResult] = []
        
        # Register all scanners
        self.scanners = {
            "auth": AuthenticationScanner,
            "api": APISecurityScanner,
            "jwt": JWTAnalyzer,
            "upload": FileUploadScanner,
            "session": SessionManagementScanner,
            "crypto": CryptographyScanner,
        }
    
    async def scan(self, target: str, modules: List[str] = None) -> List[ScanResult]:
        """Run security scan on target"""
        
        self.logger.info(f"Starting OxTrace v5.0 scan on {target}")
        
        # Determine modules to run
        if modules is None or "all" in modules or "full" in modules:
            modules_to_run = list(self.scanners.keys())
        else:
            modules_to_run = [m for m in modules if m in self.scanners]
        
        if not modules_to_run:
            self.logger.error(f"No valid modules specified. Available: {', '.join(self.scanners.keys())}")
            return []
        
        # Start live display
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.realtime_display.console
        ) as progress:
            
            main_task = progress.add_task(f"[cyan]Scanning {target}...", total=len(modules_to_run))
            
            for module_name in modules_to_run:
                self.realtime_display.update_module_status(module_name, "Running...")
                
                scanner_class = self.scanners[module_name]
                scanner = scanner_class(self.http, self.logger)
                
                progress.update(main_task, description=f"[cyan]Running {module_name} scanner...")
                
                try:
                    result = await scanner.scan(target)
                    self.results.append(result)
                    
                    # Update display
                    findings = len(result.vulnerabilities)
                    self.realtime_display.update_module_status(
                        module_name, 
                        "Completed", 
                        findings=findings, 
                        completed=True
                    )
                    
                    # Add vulns to display
                    for v in result.vulnerabilities:
                        self.realtime_display.add_vulnerability(v)
                    
                    if findings > 0:
                        self.logger.success(f"Module '{module_name}': Found {findings} vulnerabilities")
                    else:
                        self.logger.info(f"Module '{module_name}': No vulnerabilities found")
                        
                except Exception as e:
                    self.logger.error(f"Module '{module_name}' failed: {str(e)}")
                    self.realtime_display.update_module_status(module_name, f"Failed: {str(e)}", completed=True)
                
                progress.advance(main_task)
        
        return self.results
    
    def generate_report(self, format: str = "html", output_dir: str = "reports") -> str:
        """Generate scan report"""
        if not self.results:
            self.logger.warning("No scan results available")
            return ""
        
        target = self.results[0].target if self.results else "unknown"
        generator = AdvancedReportGenerator(self.results, target)
        report_path = generator.save(format, output_dir)
        
        if report_path:
            self.logger.success(f"Report generated: {report_path}")
        
        return report_path


# =============================================================================
# 🖥️ CLI INTERFACE
# =============================================================================
def print_banner():
    """Print OxTrace banner"""
    banner = """\033[1;36m
   ██████╗ ██╗  ██╗████████╗██████╗  █████╗  ██████╗███████╗
  ██╔═══██╗╚██╗██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██║   ██║ ╚███╔╝    ██║   ██████╔╝███████║██║     █████╗  
  ██║   ██║ ██╔██╗    ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
  ╚██████╔╝██╔╝ ██╗   ██║   ██║  ██║██║  ██║╚██████╗███████╗
   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
\033[0m
\033[1;33m        [ Ultimate Penetration Testing Framework v5.0 ]\033[0m
\033[1;34m              With Advanced Security Testing Modules\033[0m

\033[1;32m  ✓ Authentication Testing    ✓ API Security Scanner\033[0m
\033[1;32m  ✓ JWT Token Analysis        ✓ File Upload Testing\033[0m
\033[1;32m  ✓ Session Management        ✓ Cryptography Testing\033[0m
\033[1;32m  ✓ Real-Time Display         ✓ Multi-Threading Engine\033[0m
\033[1;32m  ✓ Interactive Legal         ✓ Advanced Reports\033[0m

\033[1;31m  ╔══════════════════════════════════════════════════════════╗
  ║  WARNING: This tool is for authorized testing only.      ║
  ║  Unauthorized access to computer systems is illegal.     ║
  ╚══════════════════════════════════════════════════════════╝\033[0m
"""
    print(banner)


def print_menu():
    """Print interactive menu"""
    menu = """
\033[1;36m╔══════════════════════════════════════════════════════════════╗
║                     SCAN MODULES                             ║
╠══════════════════════════════════════════════════════════════╣\033[0m
\033[1;33m║  [1]  Full Scan           - Run all security modules        ║
║  [2]  Auth Testing        - Authentication security          ║
║  [3]  API Security        - API vulnerability testing        ║
║  [4]  JWT Analysis        - JWT token security               ║
║  [5]  File Upload         - Upload vulnerability testing     ║
║  [6]  Session Mgmt        - Session security analysis        ║
║  [7]  Cryptography        - SSL/TLS and crypto testing       ║\033[0m
\033[1;36m╠══════════════════════════════════════════════════════════════╣
║                     OTHER OPTIONS                            ║
╠══════════════════════════════════════════════════════════════╣\033[0m
\033[1;32m║  [98] Generate Report     - Create scan report              ║
║  [99] Exit                - Exit OxTrace                     ║\033[0m
\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m
"""
    print(menu)


async def interactive_mode(oxtrace: OxTrace):
    """Run OxTrace in interactive mode"""
    print_banner()
    
    # Get legal consent
    if not oxtrace.legal.get_consent():
        return
    
    current_target = None
    
    while True:
        print_menu()
        
        try:
            choice = input("\n\033[1;36m[OxTrace]\033[0m Enter choice: ").strip()
            
            if choice == "99":
                print("\n\033[1;32m[+] Thank you for using OxTrace. Stay safe!\033[0m\n")
                break
            
            if choice == "98":
                if oxtrace.results:
                    fmt = input("\033[1;33m[?] Report format (html/json/executive) [default: html]: \033[0m").strip() or "html"
                    report_path = oxtrace.generate_report(fmt)
                    if report_path:
                        print(f"\033[1;32m[+] Report saved to: {report_path}\033[0m")
                else:
                    print("\033[1;31m[-] No scan results available. Run a scan first.\033[0m")
                continue
            
            if not current_target:
                current_target = input("\n\033[1;33m[?] Enter target (domain/IP/URL): \033[0m").strip()
                if not current_target:
                    print("\033[1;31m[-] Target is required.\033[0m")
                    continue
                
                # Verify authorization
                if not oxtrace.legal.verify_authorization(current_target):
                    current_target = None
                    continue
            
            module_map = {
                "1": ["full"],
                "2": ["auth"],
                "3": ["api"],
                "4": ["jwt"],
                "5": ["upload"],
                "6": ["session"],
                "7": ["crypto"],
            }
            
            if choice in module_map:
                modules = module_map[choice]
                print(f"\n\033[1;34m[*] Starting scan on {current_target}...\033[0m\n")
                await oxtrace.scan(current_target, modules)
                
                total_vulns = sum(len(r.vulnerabilities) for r in oxtrace.results)
                print(f"\n\033[1;32m[+] Scan complete! Found {total_vulns} vulnerabilities.\033[0m")
            else:
                print("\033[1;31m[-] Invalid option. Please try again.\033[0m")
                
        except KeyboardInterrupt:
            print("\n\n\033[1;33m[!] Scan interrupted by user.\033[0m")
            continue
        except Exception as e:
            print(f"\033[1;31m[-] Error: {str(e)}\033[0m")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="OxTrace v5.0 - Ultimate Penetration Testing Framework"
    )
    
    parser.add_argument("-t", "--target", help="Target URL/domain/IP")
    parser.add_argument("-m", "--modules", help="Comma-separated modules (auth,api,jwt,upload,session,crypto,full)")
    parser.add_argument("-r", "--report", choices=["html", "json", "executive"], help="Report format")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--skip-legal", action="store_true", help="Skip legal disclaimer (not recommended)")
    
    args = parser.parse_args()
    
    oxtrace = OxTrace(verbose=args.verbose)
    
    if args.interactive or (not args.target and len(sys.argv) == 1):
        asyncio.run(interactive_mode(oxtrace))
    else:
        if not args.target:
            print("\033[1;31m[-] Target is required. Use -t or --target\033[0m")
            return
        
        print_banner()
        
        if not args.skip_legal:
            if not oxtrace.legal.get_consent():
                return
        
        modules = args.modules.split(",") if args.modules else ["full"]
        asyncio.run(oxtrace.scan(args.target, modules))
        
        if args.report:
            oxtrace.generate_report(args.report, args.output or "reports")
        
        total_vulns = sum(len(r.vulnerabilities) for r in oxtrace.results)
        print(f"\n\033[1;32m[+] Scan complete! Found {total_vulns} vulnerabilities.\033[0m")


if __name__ == "__main__":
    main()
