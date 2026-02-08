"""Recognize reflected HTML tags while excluding comments and inert text."""

import re
from html.parser import HTMLParser


def has_active_html_reflection(body, payload):
    if '<' not in payload:
        return False
    offset = payload.index('<')
    positions = {match.start() + offset for match in re.finditer(re.escape(payload), body)}
    if not positions:
        return False
    line_starts = [0, *(match.end() for match in re.finditer('\n', body))]

    class Detector(HTMLParser):
        found = False

        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.inert = []

        def handle_starttag(self, tag, attrs):
            if tag in ('textarea', 'title', 'xmp', 'noscript', 'template'):
                self.inert.append(tag)
                return
            if self.inert:
                return
            line, column = self.getpos()
            position = line_starts[line - 1] + column
            if position in positions and (tag == 'script' or any(name.startswith('on') or (name in ('src', 'href') and (value or '').lower().startswith('javascript:')) for name, value in attrs)):
                self.found = True

        def handle_endtag(self, tag):
            if self.inert and self.inert[-1] == tag:
                self.inert.pop()

    detector = Detector()
    detector.feed(body)
    return detector.found
