"""Group report URLs by the running app's origin, retaining ports and schemes."""

import ipaddress
from urllib.parse import urlsplit


def project_origin(target):
    try:
        url = urlsplit(target)
        if url.scheme not in ('http', 'https') or not url.hostname:
            return target
        host = url.hostname.lower()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            pass
        if ':' in host:
            host = f'[{host}]'
        port = url.port
        if port and port != (443 if url.scheme == 'https' else 80):
            host += f':{port}'
        return f'{url.scheme}://{host}'
    except ValueError:
        return target
