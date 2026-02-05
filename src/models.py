"""
Resurface data models — Pydantic v2

All models are Pydantic BaseModel for:
- Automatic validation
- JSON serialization
- JSON Schema generation (for instructor/structured output)
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


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
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    UNKNOWN = "unknown"


class ReplayMethod(str, Enum):
    HTTP = "http"
    BROWSER = "browser"
    MANUAL = "manual"


class ReplayResult(str, Enum):
    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class PoC_Step(BaseModel):
    """A single step in a PoC reproduction"""
    model_config = ConfigDict(use_enum_values=True)
    
    order: int
    description: str
    method: Optional[str] = None
    url: Optional[str] = None
    headers: dict = Field(default_factory=dict)
    params: dict = Field(default_factory=dict)
    body: Optional[str] = None
    payload: Optional[str] = None
    expected_behavior: Optional[str] = None
    browser_action: Optional[str] = None


class ParsedReport(BaseModel):
    """LLM-parsed structure from a raw report"""
    model_config = ConfigDict()
    
    report_id: int
    title: str
    vuln_type: VulnType = VulnType.UNKNOWN
    severity: str = "none"
    target_url: Optional[str] = None
    target_domain: Optional[str] = None
    weakness: Optional[str] = None
    description: str = ""
    impact: str = ""
    steps: list[PoC_Step] = Field(default_factory=list)
    replay_method: ReplayMethod = ReplayMethod.HTTP
    requires_auth: bool = False
    auth_details: Optional[str] = None
    original_report_text: str = ""
    parsed_at: Optional[datetime] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ReplayEvidence(BaseModel):
    """Evidence captured during replay"""
    step_number: int
    request_sent: Optional[str] = None
    response_received: Optional[str] = None
    status_code: Optional[int] = None
    screenshot_path: Optional[str] = None
    notes: str = ""


class AuthEvidence(BaseModel):
    """Evidence captured during authentication attempts"""
    profile_name: str
    auth_type: str
    success: bool
    log: str = ""
    timestamp: Optional[datetime] = None


class MutationAttempt(BaseModel):
    """A single payload mutation attempt"""
    attempt_number: int
    original_payload: str
    mutated_payload: str
    strategy: str = ""
    rationale: str = ""
    response_snippet: str = ""
    status_code: Optional[int] = None
    success: bool = False
    blocked: bool = False


class MutationResult(BaseModel):
    """Result of an adaptive mutation loop"""
    original_payload: str
    final_payload: Optional[str] = None
    bypassed: bool = False
    attempts: list[MutationAttempt] = Field(default_factory=list)
    analysis_summary: str = ""
    total_attempts: int = 0


class SessionState(BaseModel):
    """Persistent session state across replay steps"""
    cookies: dict = Field(default_factory=dict)
    extracted_values: dict = Field(default_factory=dict)
    headers: dict = Field(default_factory=dict)
    history: list[str] = Field(default_factory=list)


class ReplayReport(BaseModel):
    """Result of replaying a report"""
    model_config = ConfigDict(use_enum_values=True)
    
    report_id: int
    parsed_report: ParsedReport
    result: ReplayResult = ReplayResult.INCONCLUSIVE
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: list[ReplayEvidence] = Field(default_factory=list)
    auth_evidence: Optional[AuthEvidence] = None
    llm_analysis: str = ""
    replayed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    target_url: Optional[str] = None
    error_message: Optional[str] = None
    mutation_results: list[MutationResult] = Field(default_factory=list)
    session_state: Optional[SessionState] = None


# ─────────────────────────────────────────────────────────────────────
# Structured Output Models (for instructor)
# ─────────────────────────────────────────────────────────────────────

class LLMParsedReport(BaseModel):
    """Schema for LLM to parse a vulnerability report"""
    vuln_type: VulnType = Field(description="Type of vulnerability")
    target_url: Optional[str] = Field(default=None, description="Main URL/endpoint being targeted")
    target_domain: Optional[str] = Field(default=None, description="Target domain")
    description: str = Field(description="Brief 1-2 sentence description of the vulnerability")
    impact: str = Field(description="What an attacker could achieve")
    requires_auth: bool = Field(default=False, description="Does the PoC need authentication?")
    auth_details: Optional[str] = Field(default=None, description="What kind of auth is needed")
    replay_method: ReplayMethod = Field(default=ReplayMethod.HTTP, description="http or browser")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence that steps are complete")
    steps: list[PoC_Step] = Field(default_factory=list, description="Steps to reproduce")


class LLMValidationResult(BaseModel):
    """Schema for LLM validation of replay results"""
    result: ReplayResult = Field(description="vulnerable, fixed, partial, or inconclusive")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the result")
    analysis: str = Field(description="Detailed explanation referencing specific evidence")
    indicators: list[str] = Field(default_factory=list, description="Specific indicators that led to conclusion")


class LLMBlockDetection(BaseModel):
    """Schema for LLM block/WAF detection"""
    blocked: bool = Field(description="Was the payload blocked?")
    reason: str = Field(description="Why it was blocked or not")
    filter_type: str = Field(description="waf_block, payload_stripped, payload_escaped, error_page, none")
    payload_reflected: bool = Field(description="Is the payload present unmodified?")
    payload_modified: Optional[str] = Field(default=None, description="How the payload was modified/escaped")


class LLMMutationVariant(BaseModel):
    """A single mutation variant from LLM"""
    payload: str = Field(description="The bypass payload")
    strategy: str = Field(description="encoding_bypass, tag_alternative, etc.")
    rationale: str = Field(description="Why this might bypass the filter")


class LLMMutationAnalysis(BaseModel):
    """Schema for LLM mutation analysis"""
    filter_analysis: str = Field(description="What specific filtering/WAF rules were identified")
    blocked_elements: list[str] = Field(default_factory=list, description="Specific tokens/patterns blocked")
    variants: list[LLMMutationVariant] = Field(default_factory=list, description="Bypass variant payloads")


class LLMValueExtraction(BaseModel):
    """Schema for LLM session value extraction"""
    
    class ExtractedValue(BaseModel):
        value: str
        source: str = Field(description="header, form_field, json_body, meta_tag, cookie, url_param")
        description: str
    
    extracted_values: dict[str, ExtractedValue] = Field(default_factory=dict)
    cookies_to_set: dict[str, str] = Field(default_factory=dict)
    notes: str = ""
