"""Bound response reads and handle unknown character encodings consistently."""


async def read_limited(response, limit=131072):
    chunks, size = [], 0
    while size <= limit:
        chunk = await response.content.read(min(65536, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    body, complete = b''.join(chunks)[:limit], size <= limit
    from backend.utils.evidence import capture_body
    capture_body(response, body, complete)
    return body, complete


def decode_body(body, charset=None):
    try:
        return body.decode(charset or 'utf-8', errors='replace')
    except LookupError:
        return body.decode('utf-8', errors='replace')
