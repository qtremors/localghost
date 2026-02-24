"""Pydantic models for scan requests and responses."""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class ScanModules(BaseModel):
    """Toggle individual scan modules on/off."""
    port_scan: bool = True
    vuln_scan: bool = True
    ssl_scan: bool = True
    cors_scan: bool = True
    cookie_scan: bool = True
    tech_detect: bool = True
    dns_scan: bool = True
    load_test: bool = False  # Off by default — it's destructive
    ddos_test: bool = False  # Off by default — aggressive
    rate_limit_test: bool = False  # Off by default — sends many requests
    xss_scan: bool = False  # Off by default — sends injection payloads


class BenchmarkConfig(BaseModel):
    """Configuration for the load test module."""
    concurrency: int = Field(default=50, ge=1, le=500, description="Number of concurrent workers")
    duration_seconds: int = Field(default=5, ge=1, le=60, description="Test duration in seconds")


class ScanRequest(BaseModel):
    """Request body for initiating a scan."""
    target_url: str = Field(..., description="Target URL to scan (must be localhost/private IP)")
    modules: ScanModules = Field(default_factory=ScanModules)
    benchmark_config: BenchmarkConfig = Field(default_factory=BenchmarkConfig)
    ports_to_scan: Optional[List[int]] = Field(default=None, description="Custom port list (None = common ports)")


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"


class Finding(BaseModel):
    """A single security finding."""
    title: str
    severity: Severity
    description: str
    recommendation: str = ""


class PortScanResult(BaseModel):
    """Results from port scanning."""
    open_ports: List[Dict[str, Any]] = []  # [{port, service, state}]
    total_scanned: int = 0
    scan_time_ms: float = 0


class HeaderCheckResult(BaseModel):
    """Results for a single header check."""
    present: bool
    value: Optional[str] = None
    severity: Severity = Severity.INFO


class VulnScanResult(BaseModel):
    """Results from vulnerability scanning."""
    security_headers: Dict[str, HeaderCheckResult] = {}
    sensitive_files: Dict[str, bool] = {}
    server_fingerprint: str = "Not Disclosed"
    findings: List[Finding] = []


class SSLScanResult(BaseModel):
    """Results from SSL/TLS analysis."""
    has_ssl: bool = False
    certificate: Dict[str, Any] = {}
    protocol_version: str = ""
    cipher_suite: str = ""
    cert_valid: bool = False
    cert_expired: bool = False
    days_until_expiry: Optional[int] = None
    findings: List[Finding] = []


class CORSScanResult(BaseModel):
    """Results from CORS misconfiguration detection."""
    cors_enabled: bool = False
    allow_origin: str = ""
    allow_credentials: bool = False
    allow_methods: List[str] = []
    allow_headers: List[str] = []
    findings: List[Finding] = []


class CookieScanResult(BaseModel):
    """Results from cookie security audit."""
    cookies: List[Dict[str, Any]] = []
    findings: List[Finding] = []


class TechDetectResult(BaseModel):
    """Results from technology fingerprinting."""
    technologies: List[Dict[str, str]] = []  # [{name, version, category}]
    findings: List[Finding] = []


class DNSScanResult(BaseModel):
    """Results from DNS enumeration."""
    records: Dict[str, List[str]] = {}  # {A: [...], AAAA: [...], MX: [...]}
    findings: List[Finding] = []


class BenchmarkResult(BaseModel):
    """Results from load testing."""
    requests_attempted: int = 0
    requests_successful: int = 0
    requests_failed: int = 0
    duration: float = 0
    req_per_sec: float = 0
    avg_latency_ms: float = 0
    min_latency_ms: float = 0
    max_latency_ms: float = 0
    p50_latency_ms: float = 0
    p95_latency_ms: float = 0
    p99_latency_ms: float = 0
    error_rate: float = 0


class ScoreBreakdown(BaseModel):
    """Breakdown of the security score by category."""
    headers: float = 0
    sensitive_files: float = 0
    ssl: float = 0
    cookies: float = 0
    cors: float = 0
    ports: float = 0


class ScoreResult(BaseModel):
    """Overall security score."""
    score: int = Field(default=0, ge=0, le=100)
    grade: str = "F"
    breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)


class ScanResponse(BaseModel):
    """Full scan response."""
    scan_id: str
    status: str = "success"
    target: str
    timestamp: str
    score: ScoreResult = Field(default_factory=ScoreResult)
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


class ScanHistoryResponse(BaseModel):
    """Response for scan history list."""
    scans: List[ScanHistoryItem] = []
    total: int = 0
