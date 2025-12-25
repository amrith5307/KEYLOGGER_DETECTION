import os
import time
import csv
import signal
import sys

# ----------------------------------
# CONFIGURATION
# ----------------------------------
FOLDER_TO_MONITOR = r"D:\KEYLOGGER DETECTION\SIMULATED_KEYLOGGER"

CHECK_INTERVAL = 10          # seconds
WINDOW_SECONDS = 30          # time window in seconds
MAX_WRITES_IN_WINDOW = 1     # write count threshold
MAX_SIZE_GROWTH = 10         # bytes growth threshold to flag

CSV_NAME = "file_flags.csv"

# ----------------------------------
# GLOBAL STORAGE
# ----------------------------------
file_info = {}
all_flagged = []

# ----------------------------------
# CSV SAVE FUNCTION
# ----------------------------------
def save_csv(rows):
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        base_dir = os.getcwd()

    csv_path = os.path.join(base_dir, CSV_NAME)

    print(f"\n[INFO] Saving CSV to: {csv_path}")

    try:
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "filename",
                "current_size_bytes",
                "write_count",
                "reason"
            ])

            if rows:
                for row in rows:
                    writer.writerow(row)
            else:
                writer.writerow(["-", "-", "-", "No suspicious file activity detected"])

        print("[INFO] file_flags.csv generated successfully")
    except Exception as e:
        print(f"[ERROR] Failed to save CSV: {e}")

# ----------------------------------
# FILE CHECK LOGIC
# ----------------------------------
def check_files():
    global file_info, all_flagged
    suspicious_now = []

    current_time = time.time()

    for filename in os.listdir(FOLDER_TO_MONITOR):
        filepath = os.path.join(FOLDER_TO_MONITOR, filename)

        if not os.path.isfile(filepath):
            continue

        size = os.path.getsize(filepath)

        if filename not in file_info:
            file_info[filename] = {
                "last_size": size,
                "write_times": []
            }
            print(f"[INFO] Tracking new file: {filename}")
            continue

        info = file_info[filename]

        # Clean old timestamps
        info["write_times"] = [
            t for t in info["write_times"]
            if current_time - t <= WINDOW_SECONDS
        ]

        size_growth = size - info["last_size"]

        if size_growth > 0:
            info["write_times"].append(current_time)
            info["last_size"] = size

        print(f"[DEBUG] File={filename}, Writes={len(info['write_times'])}, Last Size={info['last_size']} bytes, Size Growth={size_growth} bytes")

        # Suspicion logic
        if len(info["write_times"]) > MAX_WRITES_IN_WINDOW:
            suspicious_now.append((
                filename,
                size,
                len(info["write_times"]),
                f"Frequent file writes ({len(info['write_times'])} times in {WINDOW_SECONDS}s)"
            ))

        elif size_growth > MAX_SIZE_GROWTH:
            suspicious_now.append((
                filename,
                size,
                len(info["write_times"]),
                f"Large file size growth ({size_growth} bytes)"
            ))

    # Store unique flagged entries
    for item in suspicious_now:
        if item not in all_flagged:
            all_flagged.append(item)

    return suspicious_now

# ----------------------------------
# HANDLE EXIT SIGNAL (CTRL+C)
# ----------------------------------
def signal_handler(sig, frame):
    print("\n[INFO] Stopping file monitor...")
    save_csv(all_flagged)
    sys.exit(0)

# ----------------------------------
# MAIN LOOP
# ----------------------------------
def main():
    print(f"\nMonitoring folder: {FOLDER_TO_MONITOR}")
    print("Press CTRL + C to stop and generate CSV\n")

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        flagged = check_files()

        if flagged:
            print("\n[ALERT] Suspicious file activity detected:")
            for f in flagged:
                print(f" - {f[0]} | Size={f[1]} bytes | Writes={f[2]} | Reason: {f[3]}")

            # Save CSV every time suspicious files are found
            save_csv(all_flagged)
        else:
            print("[INFO] No suspicious activity detected.")

        time.sleep(CHECK_INTERVAL)

# ----------------------------------
# ENTRY POINT
# ----------------------------------
if __name__ == "__main__":
    main()
