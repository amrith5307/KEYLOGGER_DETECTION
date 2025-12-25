import psutil
import time
from datetime import datetime
import csv
import os

# -------------------------------
# CONFIGURATION
# -------------------------------
RUNTIME_THRESHOLD = 60  # seconds

WHITELIST = [
    "system idle process", "system", "svchost.exe", "explorer.exe",
    "chrome.exe", "msedgewebview2.exe", "runtimebroker.exe", "wininit.exe",
    "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe", "fontdrvhost.exe",
    "wudfhost.exe", "smss.exe", "conhost.exe", "taskhostw.exe", "searchindexer.exe",
    "backgroundtaskhost.exe", "powershell.exe", "code.exe", "discord.exe",
    "onedrive.exe", "spotify.exe", "notepad.exe", "calculator.exe",
    "systemsettings.exe", "dwm.exe", "taskmgr.exe", "audiodg.exe", "nvcontainer.exe",
    "brave.exe", "microsoftedge.exe", "msiexec.exe", "wmiapsrv.exe", "taskhost.exe"
]

# -------------------------------
# SUSPICION CHECK
# -------------------------------
def is_suspicious_process(proc):
    name = proc['name'].lower() if proc['name'] else ""
    runtime = proc['runtime_seconds']
    cmdline = proc['cmdline'].lower()

    if name in [w.lower() for w in WHITELIST]:
        return False, ""

    if "fake_logger.py" in cmdline:
        return True, "Fake keylogger script detected via command line"

    if runtime > RUNTIME_THRESHOLD:
        return True, "Long runtime (non-whitelisted process)"

    return False, ""

# -------------------------------
# PROCESS COLLECTION
# -------------------------------
def get_process_info():
    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline']):
        try:
            pid = proc.info.get('pid')
            name = proc.info.get('name', "")
            create_time = proc.info.get('create_time')
            cmdline_list = proc.info.get('cmdline', [])
            cmdline = " ".join(cmdline_list) if cmdline_list else ""

            # Runtime handling
            if create_time:
                runtime = int(time.time() - create_time)
                runtime_str = datetime.utcfromtimestamp(runtime).strftime("%H:%M:%S")
            else:
                runtime = 0
                runtime_str = "N/A"

            suspicious, reason = is_suspicious_process({
                'name': name,
                'runtime_seconds': runtime,
                'cmdline': cmdline
            })

            processes.append({
                'pid': pid,
                'name': name,
                'runtime_str': runtime_str,
                'suspicious': suspicious,
                'reason': reason
            })

        except Exception as e:
            print(f"Skipped process due to error: {e}")

    return processes

# -------------------------------
# MAIN
# -------------------------------
def main():
    process_list = get_process_info()
    print(f"\nCollected {len(process_list)} processes")

    # Console output
    print(f"{'PID':<10} {'Name':<30} {'Runtime':<10} {'Suspicious':<12} Reason")
    print("-" * 80)
    for p in process_list:
        print(
            f"{p['pid']:<10} {p['name']:<30} {p['runtime_str']:<10} "
            f"{'Yes' if p['suspicious'] else 'No':<12} {p['reason']}"
        )

    # CSV output
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        base_dir = os.getcwd()

    csv_path = os.path.join(base_dir, "process_flags.csv")
    print(f"\nSaving CSV to: {csv_path}")

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["pid", "process_name", "runtime", "suspicious", "reason"])

        for p in process_list:
            writer.writerow([
                p['pid'],
                p['name'],
                p['runtime_str'],
                1 if p['suspicious'] else 0,
                p['reason']
            ])

    print("process_flags.csv generated successfully")

if __name__ == "__main__":
    main()