"""Discover published ports and bind-mounted source from a local Docker daemon."""

import asyncio
import json
import os
from pathlib import Path

from backend.utils.validators import is_private_address

SELECTORS = ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')


def local_docker_command():
    if os.name == 'nt':
        endpoint = 'npipe:////./pipe/docker_engine'
    else:
        candidates = [Path('/var/run/docker.sock'), Path.home() / '.docker/desktop/docker.sock', Path('/run/user') / str(os.getuid()) / 'docker.sock']
        socket = next((path for path in candidates if path.exists()), candidates[0])
        endpoint = 'unix://' + str(socket)
    return ['docker', '--host=' + endpoint]


async def docker_json(*args, lines=False):
    environment = {key: value for key, value in os.environ.items() if key not in SELECTORS}
    try:
        process = await asyncio.create_subprocess_exec(*local_docker_command(), *args, env=environment,
                                                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            output, _ = await asyncio.wait_for(process.communicate(), 8)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise ValueError('The local Docker daemon did not respond in time') from None
    except FileNotFoundError:
        raise ValueError('Docker CLI is not installed on the machine running Localghost') from None
    if process.returncode or len(output) > 1024 * 1024:
        raise ValueError('The local Docker daemon is unavailable. Start Docker and check local socket access.')
    return [json.loads(line) for line in output.splitlines() if line.strip()] if lines else json.loads(output)


async def discover_containers():
    rows = await docker_json('ps', '--no-trunc', '--format', '{{json .}}', lines=True)
    containers = []
    # Avoid inspecting Env, labels other than Compose identity, or registry credentials.
    template = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},'
                '"ports":{{json .NetworkSettings.Ports}},"mounts":{{json .Mounts}},'
                '"working_dir":{{json .Config.WorkingDir}},"compose_project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                '"compose_service":{{json (index .Config.Labels "com.docker.compose.service")}}}')
    for row in rows[:50]:
        item = await docker_json('inspect', '--format', template, row['ID'])
        targets = []
        for internal, bindings in (item.get('ports') or {}).items():
            if not internal.endswith('/tcp'):
                continue
            port = int(internal.split('/')[0])
            for binding in bindings or []:
                host = binding['HostIp']
                if host in ('', '0.0.0.0'):
                    host = '127.0.0.1'
                elif host == '::':
                    host = '[::1]'
                elif ':' in host:
                    host = '[' + host + ']'
                if not is_private_address(host.strip('[]')):
                    continue
                scheme = 'https' if port in (443, 8443) else 'http'
                targets.append({'url': f"{scheme}://{host}:{binding['HostPort']}", 'container_port': port})
        mounts = [mount for mount in item.get('mounts', []) if mount.get('Type') == 'bind']
        source = next((mount['Source'] for mount in mounts if item.get('working_dir') == mount.get('Destination')), '')
        containers.append({'id': item['id'], 'name': item['name'].lstrip('/'), 'image': item['image'],
                           'compose_project': item.get('compose_project'), 'compose_service': item.get('compose_service'),
                           'targets': list({target['url']: target for target in targets}.values()),
                           'source_path': source if source and Path(source).is_dir() else '',
                           'mounts': [{'source': mount['Source'], 'destination': mount['Destination']} for mount in mounts],
                           'note': '' if targets else 'No TCP port is published. Publish the web port on localhost to scan this app.'})
    return {'containers': containers, 'truncated': len(rows) > 50}
