from copy import deepcopy

import pytest
from httpx import ASGITransport, AsyncClient

from backend.database import db
from backend.main import app
from backend.services.comparison import compare_scans


def report(scan_id, findings=(), score=50):
    return {
        'scan_id': scan_id, 'target': 'http://localhost:3000',
        'timestamp': '2026-10-16T12:00:00+00:00',
        'score': {'score': score, 'coverage': 55, 'breakdown': {'headers': 25, 'sensitive_files': 0, 'ssl': None}},
        'request': {'ports_to_scan': [3000, 8080]},
        'module_status': {'vuln_scan': 'success', 'port_scan': 'success'},
        'vuln_scan': {'findings': list(findings)},
        'port_scan': {'open_ports': [{'port': 3000, 'service': 'HTTP', 'state': 'open'}]},
    }


def finding(title, severity):
    return {'title': title, 'severity': severity, 'description': 'Example finding', 'recommendation': 'Fix it'}


def test_compares_additions_resolutions_and_severity_changes():
    baseline = report('before', [finding('Exposed config', 'critical'), finding('Missing CSP', 'high'), finding('Unchanged', 'low')])
    current = report('after', [finding('Missing CSP', 'medium'), finding('New issue', 'high'), finding('Unchanged', 'low')], score=80)
    result = compare_scans(baseline, current)
    assert result['score_delta'] == 30
    assert [item['title'] for item in result['resolved_findings']] == ['Exposed config']
    assert [item['title'] for item in result['new_findings']] == ['New issue']
    assert result['changed_findings'][0]['previous_severity'] == 'high'
    assert result['unchanged_count'] == 1


@pytest.mark.parametrize('state', ['partial', 'error', 'skipped'])
def test_incomplete_checks_cannot_resolve_prior_issues(state):
    baseline = report('before', [finding('Exposed config', 'critical')])
    current = report('after')
    current['module_status']['vuln_scan'] = state
    result = compare_scans(baseline, current)
    assert result['resolved_findings'] == []
    assert result['comparable_modules'] == []
    assert result['excluded_modules'] == ['vuln_scan']


def test_equal_coverage_with_different_categories_is_not_comparable():
    baseline, current = report('before'), report('after')
    current['score']['breakdown'] = {'headers': None, 'ssl': 20, 'sensitive_files': 20, 'cookies': 10}
    assert compare_scans(baseline, current)['score_delta'] is None


def test_legacy_scores_without_coverage_are_not_compared():
    baseline, current = report('before'), report('after')
    del baseline['score']['coverage']
    assert compare_scans(baseline, current)['score_delta'] is None


def test_scanner_update_does_not_claim_that_app_issues_were_fixed():
    before = report('before', [finding('Exposed config', 'critical')])
    after = report('after', score=80)
    after['scanner_version'] = 2
    after['score']['version'] = 2
    result = compare_scans(before, after)
    assert result['rules_changed']
    assert result['score_delta'] is None
    assert result['resolved_findings'] == []
    assert result['new_findings'] == []
    assert not result['ports']['comparable']


def test_port_deltas_use_actual_checked_ports_when_available():
    before, after = report('before'), report('after')
    before['port_scan']['ports_checked'] = [3000, 8080]
    after['port_scan']['ports_checked'] = [3000, 8081]
    assert not compare_scans(before, after)['ports']['comparable']


def test_port_changes_require_matching_selection():
    baseline, current = report('before'), report('after')
    current['port_scan']['open_ports'] = [{'port': 8080}]
    result = compare_scans(baseline, current)
    assert result['ports'] == {'comparable': True, 'opened': [8080], 'closed': [3000]}
    current['request']['ports_to_scan'] = [8080]
    assert compare_scans(baseline, current)['ports'] == {'comparable': False, 'opened': [], 'closed': []}


def test_pass_and_info_entries_do_not_become_resolved_issues():
    baseline = report('before', [finding('Noteworthy', 'info'), finding('Protected', 'pass')])
    assert compare_scans(baseline, report('after'))['resolved_findings'] == []


@pytest.mark.parametrize('target', ['http://other:3000', 'http://localhost:4000', 'https://localhost:3000', 'http://localhost:3000/other'])
def test_different_targets_are_rejected(target):
    current = report('after')
    current['target'] = target
    with pytest.raises(ValueError, match='same target'):
        compare_scans(report('before'), current)


def test_identical_scan_is_rejected_without_mutating_inputs():
    value = report('one')
    original = deepcopy(value)
    with pytest.raises(ValueError, match='different scan'):
        compare_scans(value, value)
    assert value == original


async def test_comparison_route_and_filtered_history():
    before, after = report('before'), report('after', score=70)
    for value in (before, after):
        await db.save_scan(value['scan_id'], value['target'], value['timestamp'], value['score']['score'], 'C', value)
    await db.save_scan('other', 'http://localhost:4000/100%_literal', after['timestamp'], 50, 'D', report('other'))
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://localhost') as client:
        result = await client.get('/api/history/after/comparison/before')
        assert result.status_code == 200
        assert result.json()['score_delta'] == 20
        filtered = await client.get('/api/history', params={'target': 'http://localhost:3000'})
        assert filtered.json()['total'] == 2
        searched = await client.get('/api/history', params={'q': '100%_literal'})
        assert searched.json()['total'] == 1
        assert searched.json()['scans'][0]['scan_id'] == 'other'
        assert (await client.get('/api/history', params={'q': "' OR 1=1--"})).json()['total'] == 0
        assert (await client.get('/api/history/after/comparison/missing')).status_code == 404
        assert (await client.get('/api/history/after/comparison/after')).status_code == 400


def test_comparison_reports_a_changed_server_address():
    baseline, current = report('before'), report('after')
    baseline['resolved_addresses'] = ['127.0.0.1']
    current['resolved_addresses'] = ['127.0.0.2']
    assert compare_scans(baseline, current)['endpoint_changed'] is True
    assert compare_scans(baseline, report('legacy'))['endpoint_changed'] is None
