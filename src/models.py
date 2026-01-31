"""
Resurface data models
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class VulnType(str, Enum):
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    IDOR = "idor"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    SQLI = "sqli"
    INFO_DISCLOSURE = "info_disclosure"
    PATH_TRAVERSAL = "path_traversal"
    RCE = "rce"
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNKNOWN = "unknown"


class ReplayMethod(str, Enum):
    HTTP = "http"
    BROWSER = "browser"
    MANUAL = "manual"


class ReplayResult(str, Enum):
    VULNERABLE = "vulnerable"       # Bug still exists
    FIXED = "fixed"                 # Bug is fixed
    PARTIAL = "partial"             # Partially fixed / bypassable
    INCONCLUSIVE = "inconclusive"   # Could not determine
    ERROR = "error"                 # Replay failed


@dataclass
class PoC_Step:
    """A single step in a PoC reproduction"""
    order: int
    description: str
    method: Optional[str] = None        # GET, POST, etc.
    url: Optional[str] = None
    headers: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    body: Optional[str] = None
    payload: Optional[str] = None
    expected_behavior: Optional[str] = None
    browser_action: Optional[str] = None  # For browser-based steps


@dataclass
class ParsedReport:
    """LLM-parsed structure from a raw report"""
    report_id: int
    title: str
    vuln_type: VulnType
    severity: str
    target_url: Optional[str] = None
    target_domain: Optional[str] = None
    weakness: Optional[str] = None
    description: str = ""
    impact: str = ""
    steps: list[PoC_Step] = field(default_factory=list)
    replay_method: ReplayMethod = ReplayMethod.HTTP
    requires_auth: bool = False
    auth_details: Optional[str] = None
    original_report_text: str = ""
    parsed_at: Optional[datetime] = None
    confidence: float = 0.0  # LLM confidence in parsing


@dataclass
class ReplayEvidence:
    """Evidence captured during replay"""
    step_number: int
    request_sent: Optional[str] = None
    response_received: Optional[str] = None
    status_code: Optional[int] = None
    screenshot_path: Optional[str] = None
    notes: str = ""


@dataclass
class ReplayReport:
    """Result of replaying a report"""
    report_id: int
    parsed_report: ParsedReport
    result: ReplayResult
    confidence: float = 0.0
    evidence: list[ReplayEvidence] = field(default_factory=list)
    llm_analysis: str = ""
    replayed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    target_url: Optional[str] = None
    error_message: Optional[str] = None
