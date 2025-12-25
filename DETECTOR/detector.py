import csv
import os

PROCESS_CSV = "process_flags.csv"
NO_UI_CSV = "no_ui_processes.csv"
FILE_CSV = "file_flags.csv"
OUTPUT_CSV = "final_detection.csv"

# ---------------- LOAD NO-UI PIDS ----------------
no_ui_pids = set()

with open(NO_UI_CSV, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        no_ui_pids.add(row["pid"])

# ---------------- LOAD FILE ACTIVITY ----------------
file_activity = []
with open(FILE_CSV, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        file_activity.append(row["reason"])

file_reason = "; ".join(set(file_activity)) if file_activity else ""

# ---------------- FINAL DETECTION ----------------
final_results = []

with open(PROCESS_CSV, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        pid = row["pid"]
        name = row["process_name"]
        suspicious = row["suspicious"]

        verdict = "NORMAL"
        reason = ""

        if suspicious == "1" and pid in no_ui_pids:
            verdict = "SUSPICIOUS_KEYLOGGER"
            reason = "Long runtime + No UI"
            if file_reason:
                reason += " + File activity"

        final_results.append({
            "pid": pid,
            "process_name": name,
            "verdict": verdict,
            "reason": reason
        })

# ---------------- WRITE OUTPUT ----------------
with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["pid", "process_name", "verdict", "reason"]
    )
    writer.writeheader()
    writer.writerows(final_results)

print("FINAL DETECTION COMPLETED")
print(f"Output saved to: {os.path.abspath(OUTPUT_CSV)}")
