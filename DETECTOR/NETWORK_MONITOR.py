import psutil
import csv
import time
import os

CSV_NAME = "network_activity.csv"
SCAN_INTERVAL = 10  # seconds

def scan_network_connections():
    rows = []
    timestamp = int(time.time())
    for conn in psutil.net_connections(kind='tcp'):
        # We care about connections that have remote endpoints and associated PIDs
        if conn.raddr and conn.pid:
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            remote_addr = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid
            status = conn.status

            rows.append([
                pid,
                local_addr,
                remote_addr,
                remote_port,
                status,
                timestamp
            ])
    return rows

def save_csv(rows):
    # Append mode, so we accumulate data over time
    file_exists = os.path.isfile(CSV_NAME)
    with open(CSV_NAME, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            # Write header only once
            writer.writerow(['pid', 'local_address', 'remote_address', 'remote_port', 'status', 'timestamp'])
        writer.writerows(rows)

def main():
    print(f"Starting network monitor. Appending data to {CSV_NAME} every {SCAN_INTERVAL}s")
    try:
        while True:
            rows = scan_network_connections()
            if rows:
                save_csv(rows)
                print(f"[{time.ctime()}] Logged {len(rows)} active connections")
            else:
                print(f"[{time.ctime()}] No active remote TCP connections found")
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("\nNetwork monitoring stopped.")

if __name__ == "__main__":
    main()
