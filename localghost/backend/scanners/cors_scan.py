"""Check the CORS policy on actual GET responses, not only preflight metadata."""

import aiohttp

from backend.models.scan import CORSScanResult, Finding, Severity
from backend.utils.network import scanner_session

TEST_ORIGINS = ('https://evil-attacker.com', 'https://localghost-cors-test.invalid', 'null')


async def scan_cors(target_url: str) -> CORSScanResult:
    if not target_url.startswith(('http://', 'https://')):
        target_url = f'http://{target_url}'
    result = CORSScanResult()
    async with scanner_session(timeout=aiohttp.ClientTimeout(total=8)) as session:
        for method, origin in [('OPTIONS', TEST_ORIGINS[0]), *(('GET', origin) for origin in TEST_ORIGINS)]:
            item = {'method': method, 'origin': origin, 'status': None, 'allow_origin': '', 'allow_credentials': False}
            try:
                headers = {'Origin': origin}
                if method == 'OPTIONS':
                    headers['Access-Control-Request-Method'] = 'GET'
                async with session.request(method, target_url, headers=headers, allow_redirects=False) as response:
                    item.update(status=response.status, allow_origin=response.headers.get('Access-Control-Allow-Origin', ''),
                                allow_credentials=response.headers.get('Access-Control-Allow-Credentials', '') == 'true')
                    if method == 'OPTIONS':
                        result.allow_methods = [part.strip() for part in response.headers.get('Access-Control-Allow-Methods', '').split(',') if part.strip()]
                        result.allow_headers = [part.strip() for part in response.headers.get('Access-Control-Allow-Headers', '').split(',') if part.strip()]
            except (aiohttp.ClientError, OSError, TimeoutError):
                pass
            result.observations.append(item)
    responses = [item for item in result.observations if item['method'] == 'GET' and item['status'] is not None and 200 <= item['status'] < 300]
    result.http_status = responses[0]['status'] if responses else next((item['status'] for item in result.observations if item['method'] == 'GET'), None)
    if len(responses) != len(TEST_ORIGINS):
        result.status = 'partial' if responses else 'error'
        result.error = f'Only {len(responses)} of {len(TEST_ORIGINS)} GET responses could be checked for CORS'
    if not responses:
        result.findings = [Finding(title='CORS check incomplete', severity=Severity.INFO,
            description='No successful GET response was available. Missing CORS headers on an error or redirect do not establish the app policy.')]
        return result
    reflections = [item for item in responses if item['allow_origin'] == item['origin']]
    wildcards = [item for item in responses if item['allow_origin'] == '*']
    credentialed = [item for item in reflections if item['allow_credentials']]
    selected = (credentialed or reflections or wildcards or responses)[0]
    result.cors_enabled = any(item['allow_origin'] for item in responses)
    result.allow_origin = selected['allow_origin']
    result.allow_credentials = selected['allow_credentials']
    if reflections:
        multiple = len({item['origin'] for item in reflections if item['origin'] != 'null'}) > 1
        result.findings.append(Finding(
            title='CORS: Origin Reflection Detected' if multiple else 'CORS: Test Origin Accepted',
            severity=Severity.HIGH,
            description=f"GET responses allowed {len(reflections)} test origins" + (' with credentials. A page at an allowed origin can read credentialed responses.' if credentialed else '. No credentialed read was demonstrated.'),
            recommendation='Allow only the specific sites that need access. Do not reflect arbitrary Origin values.',
        ))
    elif wildcards:
        invalid_credentials = any(item['allow_credentials'] for item in wildcards)
        result.findings.append(Finding(
            title='CORS: Wildcard Origin with Credentials' if invalid_credentials else 'CORS: Wildcard Origin',
            severity=Severity.MEDIUM,
            description="GET responses allow any origin. Browsers block credentialed reads when Allow-Origin is '*'." if invalid_credentials else 'GET responses allow any site to read responses without credentials.',
            recommendation='Keep wildcard access only for data intended to be public. Use specific origins for private data.',
        ))
    elif result.status == 'success':
        result.findings.append(Finding(
            title='CORS: Specific Origin Configured' if result.cors_enabled else 'No CORS Headers Detected',
            severity=Severity.PASS,
            description='The tested GET responses did not allow the foreign test origins. This does not check every app route.',
        ))
    return result
