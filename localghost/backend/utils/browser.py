"""Chromium launch settings shared by independent browser workflows."""

import os
import shutil
import sys
from pathlib import Path


async def launch_chromium(playwright, *, args=None):
    executable = os.getenv("LOCALGHOST_CHROMIUM_PATH")
    if not executable and not Path(playwright.chromium.executable_path).exists():
        executable = shutil.which("chromium") or shutil.which("chromium-browser")
    arguments = list(args or [])
    if sys.platform.startswith("linux"):
        arguments.append("--no-zygote")
    return await playwright.chromium.launch(
        headless=True,
        args=arguments,
        **({"executable_path": executable} if executable else {}),
    )
