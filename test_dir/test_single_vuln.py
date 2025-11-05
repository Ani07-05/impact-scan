#!/usr/bin/env python3
import subprocess
cmd = ["osv-scanner", "--format", "json", "test.txt"]
subprocess.run(cmd, shell=False, timeout=60)