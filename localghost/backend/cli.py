"""Run, export, and recheck the same observations without the dashboard."""

import argparse
import asyncio
import html
import json
import sys
from pathlib import Path

from backend.database.db import get_scan, init_db
from backend.models.scan import ScanModules, ScanRequest, ScanSession
from backend.services.docker import discover_containers
from backend.services.rechecks import perform_recheck
from backend.services.scanner import execute_scan

SEVERITIES = ('critical', 'high', 'medium', 'low')


def exit_status(report: dict, threshold='high', include_review=False):
    limit = SEVERITIES.index(threshold)
    if any(finding['severity'] in SEVERITIES[:limit + 1]
           and (finding['verification'] == 'confirmed' or include_review and finding['verification'] == 'review')
           for finding in report['findings']):
        return 1
    return 2 if report['status'] != 'success' else 0


def evidence_text(item):
    lines = [f"{item['method']} {item['url']}"]
    if item.get('source_file'):
        lines += [f"{item['source_file']}:{item.get('source_line') or ''}", item.get('source_excerpt', '')]
    else:
        lines += [f'{key}: {value}' for key, value in item.get('request_headers', {}).items()]
        if item.get('request_body'):
            lines += ['', item['request_body']]
        if item.get('request_details'):
            lines.append(json.dumps(item['request_details'], indent=2))
        lines += ['', f"HTTP {item['status']}" if item.get('status') else f"No response: {item['error']}" if item.get('error') else 'Observed result:']
        lines += [f'{key}: {value}' for key, value in item.get('response_headers', {}).items()]
        if item.get('response_body_excerpt') is not None:
            lines += ['', item['response_body_excerpt']]
        if item.get('response_details'):
            lines.append(json.dumps(item['response_details'], indent=2))
    if item.get('page_url'):
        lines += [f"Affected page: {item['page_url']}"]
    lines += [item['observation']]
    if item.get('response_body_truncated'):
        lines.append('Body excerpt shortened. Credential values redacted.')
    return '\n'.join(lines)


def text_report(report):
    summary = report['summary']
    mode = report.get('environment_observation', {})
    authentication = report.get('authentication', {})
    lines = [f"Localghost: {report['target']}",
             f"{summary['confirmed']} confirmed · {summary['review']} need review · {summary['incomplete']} incomplete checks",
             f"Build mode: {mode.get('observed', 'unknown')} (requested: {mode.get('requested', 'unknown')})",
             f"Session: {authentication.get('status', 'not_supplied')}", '']
    for finding in report['findings']:
        if finding['severity'] == 'pass':
            continue
        lines.extend([f"[{finding['verification']} / {finding['severity']}] {finding['title']} ({finding['id']})", finding['location'],
                      finding['description'], f"Fix: {finding['recommendation']}"])
        if finding.get('fix_file'):
            lines.append(f"File: {finding['fix_file']}" + (f":{finding['fix_line']}" if finding.get('fix_line') else ''))
        for key in ('fix_diff', 'fix_example'):
            if finding.get(key):
                lines.append(finding[key])
        lines += finding.get('fix_notes', [])
        lines += [evidence_text(item) for item in finding['evidence']]
        lines.append('')
    if authentication.get('evidence'):
        lines += ['Session evidence:', *(evidence_text(item) for item in authentication['evidence']), '']
    lines += ['Server routes checked:']
    for url, modules in report.get('route_results', {}).items():
        lines.append(f"{url}: " + ', '.join(f"{key}={data.get('status')} (HTTP {data.get('http_status')})" for key, data in modules.items()))
    pages = [f"{page['status'] or 'Unavailable'} {page['url']}" for page in (report.get('browser_check') or {}).get('pages', [])]
    return '\n'.join([*lines, *(('Pages checked:', *pages, '') if pages else ()), 'Scope:', *report['scope']])


def html_report(report):
    escape = html.escape

    def evidence(items):
        return ''.join(f'<details><summary>{escape(item["method"])} {escape(item["url"])}</summary><pre>{escape(evidence_text(item))}</pre></details>' for item in items)

    cards = []
    for finding in report['findings']:
        fixes = ''.join(f'<pre>{escape(finding[key])}</pre>' for key in ('fix_diff', 'fix_example') if finding.get(key))
        file = f'<p>File: <code>{escape(finding["fix_file"])}:{finding.get("fix_line") or ""}</code></p>' if finding.get('fix_file') else ''
        notes = ''.join(f'<p>{escape(note)}</p>' for note in finding.get('fix_notes', []))
        cards.append(f"<article><small>{escape(finding['verification'])} · {escape(finding['severity'])}</small><h2>{escape(finding['title'])}</h2>"
                     f"<p><code>{escape(finding['id'])}</code></p><p>{escape(finding['description'])}</p>"
                     f"<p><b>Fix:</b> {escape(finding['recommendation'])}</p>{file}{fixes}{notes}{evidence(finding['evidence'])}</article>")
    summary = report['summary']
    page_rows = ''.join(f"<tr><td>{escape(page['url'])}</td><td>{page['status'] or 'Unavailable'}</td><td>{len(page['errors'])}</td><td>{len(page['failed_requests'])}</td></tr>"
                        for page in (report.get('browser_check') or {}).get('pages', []))
    pages = f'<h2>Pages checked</h2><table><tr><th>Page</th><th>HTTP</th><th>JavaScript errors</th><th>Failed requests</th></tr>{page_rows}</table>' if page_rows else ''
    routes = '<h2>Server checks by route</h2><table><tr><th>URL</th><th>Results</th></tr>' + ''.join(
        f'<tr><td>{escape(url)}</td><td>' + '<br>'.join(escape(f"{key}: {data.get('status')} (HTTP {data.get('http_status')})") for key, data in modules.items()) + '</td></tr>'
        for url, modules in report.get('route_results', {}).items()) + '</table>'
    mode = report.get('environment_observation', {})
    authentication = report.get('authentication', {})
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<title>Localghost report</title><style>body{font:16px system-ui;max-width:1100px;margin:48px auto;padding:0 24px;color:#172c25}article{border:1px solid #ccd4cd;padding:24px;margin:16px 0;border-radius:12px}code,p,td{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f1;padding:16px}small,summary{font-weight:700}h1{font-size:28px}td,th{padding:10px;text-align:left;border-bottom:1px solid #ccc}details{margin:12px 0}</style>'
            f"<h1>{escape(report['target'])}</h1><p>{summary['confirmed']} confirmed · {summary['review']} need review · {summary['incomplete']} incomplete checks</p>"
            f"<p>{escape(report['timestamp'])} · {escape(report['scan_id'])}</p>"
            f"<p>Observed build mode: {escape(mode.get('observed', 'unknown'))}. {escape(mode.get('note', ''))}</p>"
            f"<h2>Session: {escape(authentication.get('status', 'not_supplied'))}</h2>{evidence(authentication.get('evidence', []))}"
            '<h2>Scope</h2><ul>' + ''.join(f'<li>{escape(item)}</li>' for item in report['scope']) + '</ul>' + routes + pages + ''.join(cards) + '</html>')


def output_options(command):
    command.add_argument('--session-file', type=Path, help='Private session JSON: headers, explicit browser login, or storage state; never saved')
    command.add_argument('--format', choices=('text', 'json', 'html'), default='text')
    command.add_argument('--output', type=Path)
    command.add_argument('--no-save', action='store_true', help='Do not add the run to local history')


def parser():
    root = argparse.ArgumentParser(description='Check a running local web app and verify its findings.')
    commands = root.add_subparsers(dest='command', required=True)
    scan = commands.add_parser('scan', help='Check a running app')
    scan.add_argument('url', nargs='?')
    scan.add_argument('--config', type=Path, help='ScanRequest JSON using the same options as the API; command options override it')
    scan.add_argument('--source', help='Absolute path to the project source folder')
    scan.add_argument('--environment', choices=('development', 'production'))
    scan.add_argument('--path', action='append', help='Additional route; repeat up to 20 times')
    scan.add_argument('--browser', action='store_true', default=None, help='Visit selected pages with Chromium')
    scan.add_argument('--checks', help='Comma-separated module names; replaces default selection, including optional active tests')
    scan.add_argument('--fail-on', choices=SEVERITIES, default='high')
    scan.add_argument('--include-review', action='store_true', help='Also fail on findings that need review')
    output_options(scan)
    recheck = commands.add_parser('recheck', help='Repeat one finding from a report JSON file or saved scan ID')
    recheck.add_argument('report')
    recheck.add_argument('finding_id')
    output_options(recheck)
    projects = commands.add_parser('projects', help='List running local Docker containers and published ports')
    projects.add_argument('--docker', action='store_true', required=True)
    return root


def read_json(path, limit):
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Configuration or report exceeds the size limit')
    return json.loads(data)


def write_output(args, rendered):
    if args.output:
        args.output.write_text(rendered + '\n')
    else:
        print(rendered)


async def run(args):
    if args.command == 'projects':
        print(json.dumps(await discover_containers(), indent=2))
        return 0
    if args.command == 'recheck' and args.output and Path(args.report).is_file() and Path(args.report).resolve() == args.output.resolve():
        raise ValueError('Choose a separate output file to preserve original evidence')
    session = ScanSession.model_validate(read_json(args.session_file, 49152)) if args.session_file else None
    if not args.no_save or args.command == 'recheck' and not Path(args.report).is_file():
        await init_db()
    if args.command == 'recheck':
        if Path(args.report).is_file():
            original = read_json(Path(args.report), 32 * 1024 * 1024)
        else:
            stored = await get_scan(args.report)
            if not stored:
                raise ValueError('Report not found')
            original = stored['results']
        result = await perform_recheck(original, args.finding_id, session, persist=not args.no_save)
        report = result['report']
        rendered = json.dumps(result, indent=2) if args.format == 'json' else html_report(report) if args.format == 'html' else text_report(report)
        if args.format == 'html':
            rendered = rendered.replace('<h1>', '<p>Recheck: ' + html.escape(result['state']) + '</p><h1>', 1)
        elif args.format == 'text':
            rendered = 'Recheck: ' + result['state'] + '\n\n' + rendered
        write_output(args, rendered)
        return {'resolved': 0, 'still_present': 1, 'not_checked': 2}[result['state']]
    config = read_json(args.config, 65536) if args.config else {}
    if not isinstance(config, dict):
        raise ValueError('Configuration must be a JSON object')
    for field, value in (('target_url', args.url), ('source_path', args.source), ('environment', args.environment), ('paths', args.path), ('session', session)):
        if value is not None:
            config[field] = value
    modules = dict(config.get('modules', {}))
    if args.checks is not None:
        selected = set(args.checks.split(','))
        if selected - ScanModules.model_fields.keys():
            raise ValueError('Unknown check name')
        modules = {name: name in selected for name in ScanModules.model_fields}
    if args.source:
        modules['source_scan'] = True
    if args.browser:
        modules['browser_check'] = True
    config['modules'] = modules
    request = ScanRequest.model_validate(config)
    report = (await execute_scan(request, persist=not args.no_save)).model_dump()
    rendered = json.dumps(report, indent=2) if args.format == 'json' else html_report(report) if args.format == 'html' else text_report(report)
    write_output(args, rendered)
    return exit_status(report, args.fail_on, args.include_review)


def main():
    args = parser().parse_args()
    try:
        return asyncio.run(run(args))
    except (ValueError, OSError, TypeError):
        # Validation errors can contain input values, including credentials. Do not echo them.
        print('Could not run checks. Check the URL, config, source folder, routes, Docker access, and session-file format.', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
