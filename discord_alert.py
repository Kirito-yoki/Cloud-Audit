import os
import glob
import json
import requests
import subprocess
from datetime import datetime

def load_env_file(filepath=".env"):
    """
    Lightweight .env loader without external dependencies.
    Loads key=value pairs into os.environ if not already present.
    """
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, val = line.partition("=")
                        key = key.strip()
                        val = val.strip().strip("'\"")
                        if key and key not in os.environ:
                            os.environ[key] = val
        except Exception as e:
            print(f"[!] Warning: Could not read {filepath}: {e}")

# Load .env file automatically if present
load_env_file()

# Retrieve webhook URL from environment variables (never hardcoded)
DISCORD_WEBHOOK_URL = os.environ.get("WEBHOOK_URL") or os.environ.get("DISCORD_WEBHOOK_URL")

def run_prowler_scan():
    print("[*] Running Prowler scan...")
    # Removing DEVNULL so you can see the progress bar in the terminal
    subprocess.run(["make", "scan"])
    print("[+] Scan complete.")

def load_latest_findings():
    output_dir = "output"
    json_files = glob.glob(os.path.join(output_dir, "*.json*"))
    if not json_files:
        return []
    
    latest_file = max(json_files, key=os.path.getmtime)
    findings = []
    with open(latest_file, "r", encoding="utf-8") as f:
        content = f.read().strip()
        try:
            data = json.loads(content)
            findings = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            for line in content.splitlines():
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return findings

def send_discord_report():
    findings = load_latest_findings()
    if not findings:
        print("[!] No findings to report.")
        return

    total_failed = 0
    total_passed = 0

    # Dictionaries to group the specific problems by severity
    issues_by_severity = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": []
    }

    for item in findings:
        # Extract data (Supports both ASFF and standard JSON formats)
        if "Compliance" in item:
            status = item["Compliance"].get("Status", "UNKNOWN").upper()
            severity = item.get("Severity", {}).get("Label", "INFORMATIONAL").upper()
            title = item.get("Title", "Unknown Check")
            resources = item.get("Resources", [])
            service = resources[0].get("Type", "AWS Service") if resources else "AWS Service"
        else:
            status = item.get("Status", "UNKNOWN").upper()
            severity = item.get("Severity", "INFO").upper()
            title = item.get("CheckTitle", "Unknown Check")
            service = item.get("ServiceName", "AWS Service")

        # If it is a failure, format the problem and add it to the correct group
        if "FAIL" in status:
            total_failed += 1
            if severity in issues_by_severity:
                # Formats like: "IAM: Password policy does not require uppercase letters"
                problem_desc = f"• **{service}**: {title}"
                
                # Prevent exact duplicates from flooding the chat
                if problem_desc not in issues_by_severity[severity]: 
                    issues_by_severity[severity].append(problem_desc)
                    
        elif "PASS" in status:
            total_passed += 1

    # Build the main Discord Embed framework
    embed = {
        "title": "🛡️ Detailed Cloud Security Audit Report",
        "description": f"Automated Prowler scan completed.\n✅ **Passed:** {total_passed} checks | ❌ **Failed:** {total_failed} checks\n\n**Breakdown of Vulnerabilities:**",
        "color": 15158332 if len(issues_by_severity["CRITICAL"]) > 0 else (15105570 if len(issues_by_severity["HIGH"]) > 0 else 3066993),
        "fields": []
    }

    # Emojis for the different severity headers
    emojis = {"CRITICAL": "🚨", "HIGH": "🛑", "MEDIUM": "⚠️", "LOW": "ℹ️"}
    
    # Loop through each severity and add its grouped problems to the Discord message
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        issues = issues_by_severity[sev]
        if issues:
            # Discord has a 1024 character limit per field. This safely groups them.
            field_value = ""
            for issue in issues:
                if len(field_value) + len(issue) + 5 > 1000:
                    field_value += "\n*...and more (Check HTML report for full list)*"
                    break
                field_value += issue + "\n"
            
            embed["fields"].append({
                "name": f"{emojis[sev]} {sev} Failures ({len(issues)})",
                "value": field_value,
                "inline": False # Keeps them stacked nicely on top of each other
            })

    embed["footer"] = {
        "text": f"Audit completed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    }

    payload = {"embeds": [embed]}

    if not DISCORD_WEBHOOK_URL:
        print("[!] No Discord webhook URL configured. Set WEBHOOK_URL in .env or environment.")
        return

    # Send it to Discord
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        if response.status_code in [200, 204]:
            print("[+] Discord detailed alert sent successfully!")
        else:
            print(f"[!] Failed to send alert: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"[!] Network error sending alert to Discord: {e}")

if __name__ == "__main__":
    if not DISCORD_WEBHOOK_URL:
        print("[!] Warning: No WEBHOOK_URL found in .env or environment.")
        print("[!] Please set WEBHOOK_URL (e.g. in your .env file) to receive Discord notifications.")
    else:
        run_prowler_scan()
        send_discord_report()
