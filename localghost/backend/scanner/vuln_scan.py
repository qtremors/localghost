import aiohttp
import asyncio
from typing import Dict, Any

async def check_vulnerabilities(target_url: str) -> Dict[str, Any]:
    """Check target URL for common security misconfigurations."""
    
    # Prepend http:// if missing just to be safe
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
        
    results = {
        "security_headers": {},
        "sensitive_files": {}
    }
    
    # 1. Check Security Headers
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=5) as response:
                headers = response.headers
                
                # Check for standard security headers
                results["security_headers"] = {
                    "Strict-Transport-Security": "Strict-Transport-Security" in headers,
                    "Content-Security-Policy": "Content-Security-Policy" in headers,
                    "X-Frame-Options": "X-Frame-Options" in headers,
                    "X-Content-Type-Options": "X-Content-Type-Options" in headers,
                    "Server": headers.get("Server", "Not Disclosed")
                }
    except Exception as e:
        results["security_headers_error"] = str(e)

    # 2. Check Sensitive Files (basic directory hunting for local misconfigs)
    sensitive_paths = ["/.env", "/.git/config", "/docker-compose.yml", "/package.json"]
    
    async def check_path(session: aiohttp.ClientSession, base_url: str, path: str):
        full_url = f"{base_url.rstrip('/')}{path}"
        try:
            async with session.get(full_url, timeout=3) as resp:
                if resp.status == 200:
                    return path, True
                return path, False
        except Exception:
            return path, False

    try:
        async with aiohttp.ClientSession() as session:
            tasks = [check_path(session, target_url, path) for path in sensitive_paths]
            path_results = await asyncio.gather(*tasks)
            
            for path, found in path_results:
                results["sensitive_files"][path] = found
    except Exception as e:
         results["sensitive_files_error"] = str(e)

    return results
