import psutil
import win32gui
import win32process
import csv
import os
import time

# ----------------------------------
# WHITELIST (CORE WINDOWS ONLY)
# ----------------------------------
WHITELIST = {
    "system",
    "chrome.exe",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe"
}

# ----------------------------------
# GET PIDS THAT HAVE UI
# ----------------------------------
def get_ui_pids():
    ui_pids = set()

    def enum_windows(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            ui_pids.add(pid)

    win32gui.EnumWindows(enum_windows, None)
    return ui_pids

# ----------------------------------
# MAIN
# ----------------------------------
def main():
    print("[INFO] Running Process + UI feature monitor")

    ui_pids = get_ui_pids()
    now = time.time()
    results = []

    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
        try:
            pid = proc.info['pid']
            name = proc.info.get('name') or "UNKNOWN"
            name_l = name.lower()
            cmdline = " ".join(proc.info.get('cmdline') or [])

            # Skip core Windows processes
            if name_l in WHITELIST:
                continue

            # UI feature
            has_ui = "YES" if pid in ui_pids else "NO"

            # Runtime feature
            create_time = proc.info.get('create_time')
            if create_time:
                runtime_seconds = int(now - create_time)
            else:
                runtime_seconds = 0

            results.append([
                pid,
                name,
                has_ui,
                runtime_seconds,
                cmdline
            ])

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # ----------------------------------
    # WRITE CSV (FEATURES ONLY)
    # ----------------------------------
    csv_path = os.path.abspath("process_features.csv")
    print("[INFO] Saving CSV to:", csv_path)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "pid",
            "process_name",
            "has_ui",
            "runtime_seconds",
            "cmdline"
        ])
        writer.writerows(results)

    print("[INFO] Process feature collection completed")

# ----------------------------------
# ENTRY POINT
# ----------------------------------
if __name__ == "__main__":
    main()
