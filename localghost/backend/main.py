from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
import os

from backend.scanner.port_scan import scan_ports
from backend.scanner.vuln_scan import check_vulnerabilities
from backend.benchmark.load_test import run_load_test

app = FastAPI(title="Localghost", description="Localhost Pentesting & Benchmarking Tool")

# Ensure frontend directory path is absolute or relative to the current working directory
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

# Mount static files (css, js)
app.mount("/static", StaticFiles(directory=os.path.join(frontend_dir, "static")), name="static")

class ScanRequest(BaseModel):
    target_url: str
    ports_to_scan: Optional[List[int]] = None
    run_benchmark: bool = False
    run_vuln_check: bool = True

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

@app.post("/api/scan")
async def perform_scan(request: ScanRequest):
    try:
        # 1. Port Scanning
        open_ports = await scan_ports(request.target_url, request.ports_to_scan)
        
        # 2. Vulnerability Checking
        vuln_results = {}
        if request.run_vuln_check:
            vuln_results = await check_vulnerabilities(request.target_url)
            
        # 3. Benchmarking
        benchmark_results = {}
        if request.run_benchmark:
            benchmark_results = await run_load_test(request.target_url)

        return {
            "status": "success",
            "target": request.target_url,
            "open_ports": open_ports,
            "vulnerabilities": vuln_results,
            "benchmark": benchmark_results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
