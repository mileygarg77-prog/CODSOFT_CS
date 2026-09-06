import json
import time
import os
from datetime import datetime

EVE_LOG = r"C:\Program Files\Suricata\log\eve.json"
RESPONSE_LOG = "response_actions.log"

def log_response(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(RESPONSE_LOG, "a") as f:
        f.write(entry + "\n")

def handle_alert(event):
    sig = event["alert"]["signature"]
    src = event.get("src_ip", "unknown")
    dest = event.get("dest_ip", "unknown")
    severity = event["alert"].get("severity", 0)

    log_response(f"ALERT: {sig} | {src} -> {dest} | severity={severity}")

    if severity <= 2:
        log_response(f"  -> HIGH PRIORITY: would block/flag IP {src}")
    else:
        log_response(f"  -> Logged for review")

def tail_file(path):
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    handle_alert(event)
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    print("Watching for Suricata alerts... (Ctrl+C to stop)")
    tail_file(EVE_LOG)