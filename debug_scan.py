
from pathlib import Path
import sys
import logging
from impact_scan.core import static_scan
from impact_scan.utils import schema, logging_config

# Setup basic logging to see what static_scan does
logging.basicConfig(level=logging.INFO)

# Create vulnerable file
test_file = Path("vulnerable_debug.py")
test_file.write_text('''
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Vulnerability: Wildcard CORS with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
''')

print(f"Created {test_file.absolute()}")

try:
    config = schema.ScanConfig(root_path=Path("."))
    # To avoid scanning everything, we can't easily limit semgrep via run_scan arguments 
    # unless we change run_scan to accept files or we just scan the current dir but 
    # semgrep ignore everything else?
    # Actually static_scan scans `root_path`. 
    # I'll let it scan the current dir, but I'll make a temp dir to be safe and fast.
    
    import tempfile
    import shutil
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        target = tmp_path / "vulnerable_debug.py"
        shutil.copy(test_file, target)
        
        print(f"Scanning {tmp_path}...")
        
        config = schema.ScanConfig(root_path=tmp_path)
        findings = static_scan.run_scan(config)

        print(f"\nFound {len(findings)} findings.")
        cors_vulns = [
            f for f in findings
            if "cors" in f.vuln_id.lower() or "cors" in f.title.lower()
        ]
        
        print(f"Found {len(cors_vulns)} CORS vulnerabilities:")
        for v in cors_vulns:
            print(f"  ID: {v.vuln_id}")
            print(f"  Title: {v.title}")
            print(f"  Severity: {v.severity}")
            print("-" * 20)

finally:
    if test_file.exists():
        test_file.unlink()
