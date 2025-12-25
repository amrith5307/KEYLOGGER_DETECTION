import psutil
import win32gui
import win32process
import csv
import os

def get_ui_pids():
    ui_pids = set()

    def enum(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            ui_pids.add(pid)

    win32gui.EnumWindows(enum, None)
    return ui_pids

def main():
    print("Starting NO-UI process checker...")

    ui_pids = get_ui_pids()
    print(f"UI PIDs found: {len(ui_pids)}")

    no_ui = []

    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            pid = p.info['pid']
            name = p.info['name']
            cmdline = " ".join(p.info.get('cmdline') or [])

            if pid not in ui_pids:
                no_ui.append([pid, name, cmdline])

                if "fake_logger.py" in cmdline:
                    print(" FAKE LOGGER FOUND (NO UI)")

        except:
            pass

    csv_path = os.path.abspath("no_ui_processes.csv")
    print("Saving CSV to:", csv_path)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["pid", "process_name", "cmdline"])
        writer.writerows(no_ui)

    print("CSV CREATED SUCCESSFULLY")

if __name__ == "__main__":
    main()
