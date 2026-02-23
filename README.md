# Localghost

Check running local/private web apps through the API or CLI, inspect captured evidence, and verify fixes.

## Setup

Requires Python 3.12+ and uv. Run from the inner `localghost/` directory:

```sh
uv sync --extra browser
uv run playwright install chromium
uv run python -m backend.main
```

Open [API documentation](http://127.0.0.1:13666/docs) for request schemas and interactive endpoints.

## CLI

```sh
uv run python -m backend.cli scan http://localhost:3000 --format json --output report.json
```

Reports distinguish confirmed observations, items needing review, and incomplete checks. They do not certify app security.

See the [developer guide](DEVELOPMENT.md) and [changelog](CHANGELOG.md).

## License

Read [LICENSE.md](LICENSE.md) for the Tremors Source License terms.
