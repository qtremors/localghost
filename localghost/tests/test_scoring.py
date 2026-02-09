import pytest

from backend.models.scan import (
    CookieScanResult,
    CORSScanResult,
    HeaderCheckResult,
    PortScanResult,
    SSLScanResult,
    VulnScanResult,
)
from backend.services.scoring import compute_score


def test_no_evidence_is_unassessed():
    score = compute_score()
    assert score.score == 0
    assert score.grade == '—'
    assert score.coverage == 0
    assert all(value is None for value in score.breakdown.model_dump().values())


def test_skipped_categories_do_not_inflate_score():
    score = compute_score(vuln=VulnScanResult(security_headers={'CSP': HeaderCheckResult(present=False)}))
    assert score.score == 0
    assert score.coverage == 30
    assert score.breakdown.cookies is None


def test_failed_categories_do_not_receive_credit():
    score = compute_score(cors=CORSScanResult(status='error'), cookies=CookieScanResult(status='error'))
    assert score.coverage == 0
    assert score.grade == '—'


def test_complete_healthy_score():
    score = compute_score(
        vuln=VulnScanResult(security_headers={'CSP': HeaderCheckResult(present=True)}, sensitive_files={'/.env': False}),
        ssl=SSLScanResult(has_ssl=True, cert_valid=True, protocol_version='TLSv1.3'),
        cookies=CookieScanResult(), cors=CORSScanResult(), ports=PortScanResult(total_scanned=3, closed_count=3),
    )
    assert (score.score, score.coverage, score.grade) == (100, 100, 'A+')


@pytest.mark.parametrize('path', ['/.env', '/.env.local', '/.env.production', '/wp-config.php'])
def test_all_critical_paths_remove_sensitive_file_credit(path):
    score = compute_score(vuln=VulnScanResult(sensitive_files={path: True}))
    assert score.score == 0
    assert score.coverage == 25


def test_unknown_sensitive_file_is_not_treated_as_protected():
    score = compute_score(vuln=VulnScanResult(status='partial', sensitive_files={'/.env': None, '/config.json': False}))
    assert score.breakdown.sensitive_files is None
    assert score.coverage == 0


def test_untrusted_certificate_is_not_given_trust_credit():
    score = compute_score(ssl=SSLScanResult(has_ssl=True, cert_valid=False, protocol_version='TLSv1.3'))
    assert score.breakdown.ssl == 14


def test_partial_file_checks_do_not_hide_confirmed_critical_exposure():
    result = compute_score(vuln=VulnScanResult(status='partial', sensitive_files={'/.env': True, '/config.json': None}))
    assert result.coverage == 25
    assert result.breakdown.sensitive_files == 0
    assert result.score == 0


def test_empty_port_result_never_receives_scoring_credit():
    score = compute_score(ports=PortScanResult())
    assert score.breakdown.ports is None
    assert score.coverage == 0
    assert score.grade == '—'
