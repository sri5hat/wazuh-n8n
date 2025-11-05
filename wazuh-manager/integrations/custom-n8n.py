#!/usr/bin/env python3
# Wazuh → n8n + VirusTotal Integration

import sys
import json
import requests
import os
import hashlib

VT_API_KEY = ""  # Remove your actual VT API key before pushing to GitHub

def log_message(msg):
    with open("/var/ossec/logs/integrations.log", "a") as log:
        log.write(f"[custom-n8n] {msg}\n")

def get_file_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        log_message(f"Hash error: {e}")
        return None

def check_virustotal(file_hash):
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.get(vt_url, headers=headers, timeout=15)
        if res.status_code == 200:
            stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats
        return {"error": f"HTTP {res.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def main():
    if len(sys.argv) < 4:
        log_message("Usage: custom-n8n.py <alert_file> <user> <hook_url>")
        sys.exit(1)

    alert_file = sys.argv[1]
    user = sys.argv[2].split(":")[0]
    hook_url = sys.argv[3]

    with open(alert_file, "r") as f:
        content = f.read().strip()
        alert = json.loads(content.splitlines()[-1])

    data = alert.get("data", {})
    file_path = data.get("file", data.get("path", "N/A"))
    file_hash = get_file_hash(file_path) if os.path.exists(file_path) else None
    vt_result = check_virustotal(file_hash) if file_hash else {}

    payload = {
        "agent_name": alert.get("agent", {}).get("name", "unknown"),
        "rule_id": alert.get("rule", {}).get("id", "unknown"),
        "description": alert.get("rule", {}).get("description", "No description"),
        "file_path": file_path,
        "file_hash": file_hash,
        "virustotal_result": vt_result,
        "timestamp": alert.get("timestamp", "")
    }

    res = requests.post(hook_url, json=payload, timeout=15)
    log_message(f"Webhook response: {res.status_code}")

if __name__ == "__main__":
    main()
