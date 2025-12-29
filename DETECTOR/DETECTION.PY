import csv
from collections import defaultdict
import time
import os

# --- Load network activity counts from network monitor CSV ---
def load_network_activity(csv_path, time_window=60):
    pid_net_counts = defaultdict(int)
    current_time = int(time.time())

    if not os.path.isfile(csv_path):
        print(f"[WARN] Network CSV '{csv_path}' not found. Skipping network activity.")
        return pid_net_counts

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                pid = int(row['pid'])
                timestamp = int(row['timestamp'])
                if current_time - timestamp <= time_window:
                    pid_net_counts[pid] += 1
            except (ValueError, KeyError):
                continue

    return pid_net_counts

# --- Load file flags CSV and map suspicious files to reasons ---
def load_file_flags(csv_path):
    file_flags = defaultdict(list)
    if not os.path.isfile(csv_path):
        print(f"[WARN] File flags CSV '{csv_path}' not found. Skipping file activity.")
        return file_flags

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Expecting columns: filename, current_size_bytes, write_count, reason
            filename = row.get('filename', '').lower()
            reason = row.get('reason', 'Suspicious file activity')
            if filename:
                file_flags[filename].append(reason)
    return file_flags

# --- Calculate risk score for a process ---
def calculate_risk_score(proc, file_flags, net_activity_counts, monitored_folder):
    score = 0
    reasons = []

    pid = proc['pid']
    pname = proc['process_name'].lower()
    cmdline = proc['cmdline'].lower()
    runtime = proc['runtime_seconds']
    has_ui = proc['has_ui']

    # Generic executable names (small risk)
    if pname in ['python.exe', 'powershell.exe', 'cmd.exe']:
        score += 1
        reasons.append("Generic executable name")

    # Suspicious keywords in command line
    suspicious_keywords = ['keylog', 'logger', 'spy', 'dump', 'log']
    if any(k in cmdline for k in suspicious_keywords):
        score += 2
        reasons.append("Suspicious keyword in command line")

    # If cmdline contains suspicious file names flagged by file monitor
    # Look for any suspicious filename in cmdline that matches file monitor flagged files
    for suspicious_file in file_flags:
        if suspicious_file in cmdline or suspicious_file in pname:
            score += 4
            reasons.append(f"Cmdline contains suspicious file '{suspicious_file}' flagged by file monitor")
            break

    # Also check if monitored folder name appears in cmdline (folder path)
    folder_name = os.path.basename(monitored_folder).lower()
    if folder_name and folder_name in cmdline:
        score += 3
        reasons.append(f"Cmdline contains monitored folder name '{folder_name}'")

    # Runtime checks
    if runtime < 30:
        score += 1
        reasons.append("Short runtime (<30s)")
    elif runtime > 3600 * 12:
        score += 1
        reasons.append("Long runtime (>12h)")

    # UI check
    if has_ui == 'NO':
        score += 1
        reasons.append("No UI - suspicious background process")

    # Network activity
    net_count = net_activity_counts.get(pid, 0)
    if net_count > 5:
        score += 2
        reasons.append(f"High network activity ({net_count} connections in recent interval)")

    return score, reasons

# --- Main detection function ---
def main_detection(process_csv, file_csv, network_csv, monitored_folder, score_threshold=5):
    if not os.path.isfile(process_csv):
        print(f"[ERROR] Process CSV '{process_csv}' not found.")
        return

    # Load process data
    processes = []
    with open(process_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                processes.append({
                    'pid': int(row['pid']),
                    'process_name': row['process_name'],
                    'has_ui': row['has_ui'],
                    'runtime_seconds': int(row['runtime_seconds']),
                    'cmdline': row['cmdline'],
                })
            except (ValueError, KeyError):
                continue

    # Load file flags keyed by suspicious filenames (lowercase)
    file_flags = load_file_flags(file_csv)

    # Load network activity counts keyed by pid
    net_activity_counts = load_network_activity(network_csv, time_window=60)

    final_results = []

    for proc in processes:
        pid = proc['pid']
        score, reasons = calculate_risk_score(proc, file_flags, net_activity_counts, monitored_folder)

        if score >= score_threshold:
            final_results.append({
                'pid': pid,
                'process_name': proc['process_name'],
                'score': score,
                'cmdline': proc['cmdline'],
                'runtime_seconds': proc['runtime_seconds'],
                'has_ui': proc['has_ui'],
                'reasons': "; ".join(reasons)
            })

    # Save final suspicious process list to CSV with reasons last
    output_csv = "final_suspicious_processes.csv"
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['pid', 'process_name', 'score', 'cmdline', 'runtime_seconds', 'has_ui', 'reasons']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(final_results)

    print(f"[INFO] Final suspicious processes saved to '{output_csv}'")

if __name__ == "__main__":
    # Set your CSV file paths here
    PROCESS_CSV = "process_features.csv"
    FILE_CSV = "file_flags.csv"
    NETWORK_CSV = "network_activity.csv"
    MONITORED_FOLDER = r"D:\KEYLOGGER DETECTION\SIMULATED_KEYLOGGER"

    main_detection(PROCESS_CSV, FILE_CSV, NETWORK_CSV, MONITORED_FOLDER, score_threshold=4)
