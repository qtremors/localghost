"""Task-local, non-secret context shared by related checks."""

from contextlib import contextmanager
from contextvars import ContextVar

_current = ContextVar('localghost_scan_options', default=None)


def scan_options():
    return _current.get() or {}


@contextmanager
def use_scan_options(environment):
    options = {'environment': environment, 'source': {}}
    token = _current.set(options)
    try:
        yield options
    finally:
        _current.reset(token)
