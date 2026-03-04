#!/bin/bash
cd "$(dirname "$0")/.."
echo "Starting VulnCorp Portal on http://127.0.0.1:5001"
venv/bin/python3 vuln_app/app.py
