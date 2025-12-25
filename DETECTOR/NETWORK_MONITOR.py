import psutil
import time
from collections import deque

MAX_CONNECTIONS = 3
WINDOW_SECONDS = 60
REPEATED_THRESHOLD = 3

connection_history = {}

def get_network_connections():
    print("Getting network connections...")   # DEBUG
    conns = psutil.net_connections(kind='tcp')
    proc_conn_count = {}

    for conn in conns:
        pid = conn.pid
        if pid is None:
            continue
        proc_conn_count[pid] = proc_conn_count.get(pid, 0) + 1
    print(f"Found {len(proc_conn_count)} processes with TCP connections")  # DEBUG
    return proc_conn_count

def update_history_and_check(proc_conn_count):
    print("Updating history and checking flags...")  # DEBUG
    current_time = time.time()
    flagged_procs = []

    for pid, conn_count in proc_conn_count.items():
        if pid not in connection_history:
            connection_history[pid] = deque()

        connection_history[pid].append((current_time, conn_count))

        while connection_history[pid] and current_time - connection_history[pid][0][0] > WINDOW_SECONDS:
            connection_history[pid].popleft()

        times_exceeded = sum(1 for t, c in connection_history[pid] if c > MAX_CONNECTIONS)

        if times_exceeded >= REPEATED_THRESHOLD:
            flagged_procs.append((pid, times_exceeded, conn_count))

    print(f"Flagged processes: {flagged_procs}")  # DEBUG
    return flagged_procs

def main():
    print(f"Monitoring network connections... Threshold: >{MAX_CONNECTIONS} connections")
    print(f"Flag if repeated {REPEATED_THRESHOLD} times in last {WINDOW_SECONDS} seconds.\n")

    try:
        while True:
            proc_conn_count = get_network_connections()
            flagged = update_history_and_check(proc_conn_count)

            if flagged:
                print("Suspicious network activity detected:")
                for pid, count_exceeded, current_conn in flagged:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except psutil.NoSuchProcess:
                        proc_name = "Unknown"
                    print(f"PID: {pid}, Process: {proc_name}, Times Exceeded: {count_exceeded}, Current Connections: {current_conn}")
            else:
                print("No suspicious activity detected.")

            time.sleep(10)

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == "__main__":
    main()
