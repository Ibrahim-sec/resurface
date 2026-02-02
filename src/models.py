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
class AuthEvidence:
    """Evidence captured during authentication attempts"""
    profile_name: str
    auth_type: str
    success: bool
    log: str = ""
    timestamp: Optional[datetime] = None


@dataclass
class MutationAttempt:
    """A single payload mutation attempt"""
    attempt_number: int
    original_payload: str
    mutated_payload: str
    strategy: str = ""          # e.g. "encoding_bypass", "tag_alternative", "case_manipulation"
    rationale: str = ""         # LLM's reasoning for this mutation
    response_snippet: str = ""  # What the server returned
    status_code: Optional[int] = None
    success: bool = False       # Did the mutated payload bypass the filter?
    blocked: bool = False       # Was the mutated payload also blocked?


@dataclass
class MutationResult:
    """Result of an adaptive mutation loop"""
    original_payload: str
    final_payload: Optional[str] = None      # The payload that worked (if any)
    bypassed: bool = False                    # Did we find a bypass?
    attempts: list[MutationAttempt] = field(default_factory=list)
    analysis_summary: str = ""                # LLM's overall analysis of the filtering
    total_attempts: int = 0


@dataclass
class SessionState:
    """Persistent session state across replay steps"""
    cookies: dict = field(default_factory=dict)         # Cookie jar
    extracted_values: dict = field(default_factory=dict) # Named values (csrf_token, session_id, etc.)
    headers: dict = field(default_factory=dict)          # Persistent headers (auth tokens, etc.)
    history: list[str] = field(default_factory=list)     # Step execution history for context


@dataclass
class ReplayReport:
    """Result of replaying a report"""
    report_id: int
    parsed_report: ParsedReport
    result: ReplayResult
    confidence: float = 0.0
    evidence: list[ReplayEvidence] = field(default_factory=list)
    auth_evidence: Optional[AuthEvidence] = None
    llm_analysis: str = ""
    replayed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    target_url: Optional[str] = None
    error_message: Optional[str] = None
    mutation_results: list[MutationResult] = field(default_factory=list)
    session_state: Optional[SessionState] = None
