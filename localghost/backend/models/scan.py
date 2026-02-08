"""Pydantic models for scan requests and responses."""

from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictInt, field_validator, model_validator


class ScanModules(BaseModel):
    """Toggle individual scan modules on/off."""
    model_config = ConfigDict(extra='forbid')
    port_scan: bool = True
    vuln_scan: bool = True
    ssl_scan: bool = True
    cors_scan: bool = True
    cookie_scan: bool = True
    tech_detect: bool = True
    dns_scan: bool = True
    source_scan: bool = False
    browser_check: bool = False
    load_test: bool = False  # Off by default — it's destructive
    ddos_test: bool = False  # Off by default — aggressive
    rate_limit_test: bool = False  # Off by default — sends many requests
    xss_scan: bool = False  # Off by default — sends injection payloads


class BenchmarkConfig(BaseModel):
    """Configuration for the load test module."""
    model_config = ConfigDict(extra='forbid')
    concurrency: StrictInt = Field(default=50, ge=1, le=500, description="Number of concurrent workers")
    duration_seconds: StrictInt = Field(default=5, ge=1, le=60, description="Test duration in seconds")


class BrowserLogin(BaseModel):
    model_config = ConfigDict(extra='forbid')
    path: str = Field(default='/login', max_length=2048)
    username: SecretStr = Field(max_length=4096)
    password: SecretStr = Field(max_length=4096)
    username_selector: str = Field(default='input[name="username"]', max_length=512)
    password_selector: str = Field(default='input[type="password"]', max_length=512)
    submit_selector: str = Field(default='button[type="submit"]', max_length=512)
    success_selector: str = Field(min_length=1, max_length=512)
    allowed_post_paths: List[str] = Field(default_factory=list, max_length=10)


class ScanSession(BaseModel):
    """Credentials are used for this run only and never stored in a report."""
    model_config = ConfigDict(extra='forbid')
    cookie: SecretStr = Field(default_factory=lambda: SecretStr(''), max_length=8192)
    authorization: SecretStr = Field(default_factory=lambda: SecretStr(''), max_length=8192)
    login: Optional[BrowserLogin] = None
    storage_state: Optional[SecretStr] = Field(default=None, max_length=32768)
    check_path: Optional[str] = Field(default=None, max_length=2048)
    check_selector: Optional[str] = Field(default=None, max_length=512)
    refresh_path: Optional[str] = Field(default=None, max_length=2048)
    authorization_storage_key: Optional[str] = Field(default=None, max_length=256)

    @model_validator(mode='after')
    def local_paths(self):
        from urllib.parse import unquote, urlsplit
        values = [self.check_path, self.refresh_path]
        if self.login:
            values.extend([self.login.path, *self.login.allowed_post_paths])
        for value in filter(None, values):
            if not value.startswith('/') or unquote(value).startswith('//') or urlsplit(value).netloc or '\\' in unquote(value) or any(ord(char) < 32 for char in unquote(value)):
                raise ValueError('Session URLs must be paths on the selected app')
        return self

    @field_validator('cookie', 'authorization')
    @classmethod
    def header_value(cls, value):
        if any(ord(char) < 32 or ord(char) == 127 for char in value.get_secret_value()):
            raise ValueError('Session headers must not contain control characters')
        return value

    def headers(self):
        return {key: value.get_secret_value() for key, value in
                [('Cookie', self.cookie), ('Authorization', self.authorization)] if value.get_secret_value()}


class ScanRequest(BaseModel):
    """Request body for initiating a scan."""
    model_config = ConfigDict(extra='forbid')
    target_url: str = Field(..., description="Target URL to scan (must be localhost/private IP)")
    modules: ScanModules = Field(default_factory=ScanModules)
    benchmark_config: BenchmarkConfig = Field(default_factory=BenchmarkConfig)
    source_path: Optional[str] = Field(default=None, max_length=4096)
    environment: Literal['development', 'production'] = 'development'
    paths: List[str] = Field(default_factory=list, max_length=20)
    session: Optional[ScanSession] = Field(default=None, exclude=True, repr=False)
    ports_to_scan: Optional[List[Annotated[StrictInt, Field(ge=1, le=65535)]]] = Field(
        default=None, min_length=1, max_length=1024,
        description="Up to 1024 custom TCP ports (None = common ports plus target port)",
    )

    @field_validator('paths')
    @classmethod
    def relative_paths(cls, paths):
        from urllib.parse import unquote, urlsplit
        for path in paths:
            decoded = unquote(path)
            if (len(path) > 2048 or not path.startswith('/') or decoded.startswith('//')
                    or '\\' in decoded or any(ord(char) < 32 or ord(char) == 127 for char in decoded)
                    or urlsplit(path).netloc or (urlsplit(path).fragment and not urlsplit(path).fragment.startswith('/'))):
                raise ValueError('Routes must be paths on this app, such as /account; at most 2048 characters')
        return list(dict.fromkeys(paths))

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        from backend.utils.validators import validate_target_url
        return validate_target_url(value)

    @field_validator("ports_to_scan")
    @classmethod
    def unique_ports(cls, value):
        return sorted(set(value)) if value is not None else None

    @model_validator(mode="after")
    def require_module(self):
        if not any(self.modules.model_dump().values()):
            raise ValueError("Select at least one scan module")
        if self.modules.source_scan and not self.source_path:
            raise ValueError('Source checks require a source folder')
        return self


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"


class Evidence(BaseModel):
    method: str = 'GET'
    url: str = ''
    status: Optional[int] = None
    observation: str
    captured: bool = False
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body_excerpt: Optional[str] = None
    response_body_truncated: bool = False
    page_url: str = ''
    error: Optional[str] = None
    source_file: str = ''
    source_line: Optional[int] = None
    source_excerpt: str = ''
    request_details: Dict[str, Any] = Field(default_factory=dict)
    response_details: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """A single security finding."""
    title: str
    severity: Severity
    description: str
    recommendation: str = ""
    id: str = ''
    rule_id: str = ''
    module: str = ''
    verification: Literal['confirmed', 'review', 'not_checked'] = 'review'
    location: str = ''
    evidence: List[Evidence] = Field(default_factory=list)
    fix_file: str = ''
    fix_line: Optional[int] = None
    fix_example: str = ''
    recheckable: bool = False
    affected_pages: List[str] = Field(default_factory=list)
    fix_diff: str = ''
    fix_notes: List[str] = Field(default_factory=list)


class ModuleResult(BaseModel):
    """Distinguish completed checks from unavailable or incomplete evidence."""
    status: Literal["success", "partial", "error"] = "success"
    error: Optional[str] = None
    http_status: Optional[int] = None
    evidence: List[Evidence] = Field(default_factory=list)


class PortScanResult(ModuleResult):
    """Results from port scanning."""
    open_ports: List[Dict[str, Any]] = []  # [{port, service, state}]
    total_scanned: int = 0
    ports_checked: List[int] = Field(default_factory=list)
    closed_count: int = 0
    inconclusive_ports: List[int] = Field(default_factory=list)
    scan_time_ms: float = 0


class HeaderCheckResult(BaseModel):
    """Results for a single header check."""
    present: bool
    valid: Optional[bool] = None
    applicable: bool = True
    note: str = ""
    value: Optional[str] = None
    severity: Severity = Severity.INFO


class VulnScanResult(ModuleResult):
    """Results from vulnerability scanning."""
    security_headers: Dict[str, HeaderCheckResult] = {}
    sensitive_files: Dict[str, Optional[bool]] = {}
    server_fingerprint: str = "Not Disclosed"
    findings: List[Finding] = []
    runtime_observations: List[Dict[str, Any]] = Field(default_factory=list)


class SSLScanResult(ModuleResult):
    """Results from SSL/TLS analysis."""
    has_ssl: bool = False
    certificate: Dict[str, Any] = {}
    protocol_version: str = ""
    cipher_suite: str = ""
    cert_valid: bool = False
    cert_expired: bool = False
    days_until_expiry: Optional[int] = None
    findings: List[Finding] = []


class CORSScanResult(ModuleResult):
    """Results from CORS misconfiguration detection."""
    cors_enabled: bool = False
    allow_origin: str = ""
    allow_credentials: bool = False
    allow_methods: List[str] = []
    allow_headers: List[str] = []
    observations: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Finding] = []


class CookieScanResult(ModuleResult):
    """Results from cookie security audit."""
    cookies: List[Dict[str, Any]] = []
    findings: List[Finding] = []


class TechDetectResult(ModuleResult):
    """Results from technology fingerprinting."""
    technologies: List[Dict[str, str]] = []  # [{name, version, category}]
    findings: List[Finding] = []


class DNSScanResult(ModuleResult):
    """Results from DNS enumeration."""
    records: Dict[str, List[str]] = {}  # {A: [...], AAAA: [...], MX: [...]}
    findings: List[Finding] = []


class BenchmarkResult(ModuleResult):
    """Results from load testing."""
    requests_attempted: int = 0
    requests_successful: int = 0
    requests_failed: int = 0
    requests_incomplete: int = 0
    duration: float = 0
    req_per_sec: float = 0
    avg_latency_ms: Optional[float] = None
    min_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None
    p50_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    p99_latency_ms: Optional[float] = None
    error_rate: Optional[float] = None
    latency_samples: int = 0
    latency_sampled: bool = False


class ScoreBreakdown(BaseModel):
    """Breakdown of the security score by category."""
    headers: Optional[float] = None
    sensitive_files: Optional[float] = None
    ssl: Optional[float] = None
    cookies: Optional[float] = None
    cors: Optional[float] = None
    ports: Optional[float] = None


class ScoreResult(BaseModel):
    """Overall security score."""
    score: int = Field(default=0, ge=0, le=100)
    version: int = 2
    grade: str = "—"
    coverage: int = Field(default=0, ge=0, le=100)
    available_points: int = Field(default=0, ge=0, le=100)
    breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)


class ScanResponse(BaseModel):
    """Full scan response."""
    scan_id: str
    scanner_version: int = 4
    status: str = "success"
    target: str
    timestamp: str
    resolved_addresses: List[str] = Field(default_factory=list)
    duration_ms: float = 0
    module_status: Dict[str, str] = Field(default_factory=dict)
    errors: Dict[str, str] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    saved: bool = True
    request: Optional[ScanRequest] = None
    authentication_used: bool = False
    findings: List[Finding] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)
    scope: List[str] = Field(default_factory=list)
    recheck_of: Optional[Dict[str, Any]] = None
    source_scan: Optional[Dict[str, Any]] = None
    browser_check: Optional[Dict[str, Any]] = None
    route_results: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    audit_targets: List[str] = Field(default_factory=list)
    environment_observation: Dict[str, Any] = Field(default_factory=dict)
    authentication: Dict[str, Any] = Field(default_factory=dict)
    score: Optional[ScoreResult] = Field(default=None, description='Legacy reports only. New scans do not produce a security grade.')
    port_scan: Optional[PortScanResult] = None
    vuln_scan: Optional[VulnScanResult] = None
    ssl_scan: Optional[SSLScanResult] = None
    cors_scan: Optional[CORSScanResult] = None
    cookie_scan: Optional[CookieScanResult] = None
    tech_detect: Optional[TechDetectResult] = None
    dns_scan: Optional[DNSScanResult] = None
    benchmark: Optional[BenchmarkResult] = None
    ddos_test: Optional[Dict[str, Any]] = None
    rate_limit_test: Optional[Dict[str, Any]] = None
    xss_scan: Optional[Dict[str, Any]] = None


class ScanHistoryItem(BaseModel):
    """Summary item for scan history list."""
    scan_id: str
    target: str
    timestamp: str
    score: int
    grade: str
    coverage: Optional[int] = None
    status: Optional[str] = None
    confirmed: Optional[int] = None
    review: Optional[int] = None
    incomplete: Optional[int] = None
    project_name: Optional[str] = None


class ScanHistoryResponse(BaseModel):
    """Response for scan history list."""
    scans: List[ScanHistoryItem] = []
    total: int = 0
