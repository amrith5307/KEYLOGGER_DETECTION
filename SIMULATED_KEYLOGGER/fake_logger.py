import time
import os
import socket

LOG_FILE = r"D:\KEYLOGGER DETECTION\SIMULATED_KEYLOGGER\key_log.txt"

NUM_CONNECTIONS = 30       # Number of simultaneous connections to open
CONNECTION_HOLD_TIME = 20  # Time to keep connections open (seconds)

def write_to_file(data):
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.ctime()} : {data}\n")

def open_multiple_connections():
    sockets = []
    for i in range(NUM_CONNECTIONS):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("example.com", 80))
            s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            sockets.append(s)
            print(f"Opened connection {i + 1}")
        except Exception as e:
            print(f"Failed to open connection {i + 1}: {e}")

    # Hold connections open so monitor can detect
    time.sleep(CONNECTION_HOLD_TIME)

    # Close all sockets
    for s in sockets:
        s.close()
    print(f"Closed {len(sockets)} connections.")

def main():
    print("Fake keylogger started (for testing only)")
    print("Opening multiple simultaneous connections to trigger monitor... Ctrl+C to stop.\n")

    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    counter = 1
    try:
        while True:
            simulated_input = f"simulated keystroke {counter}"
            write_to_file(simulated_input)
            print(f"Logged: {simulated_input}")
            open_multiple_connections()
            counter += 1
            time.sleep(2)  # small pause between batches
    except KeyboardInterrupt:
        print("\nFake keylogger stopped.")

if __name__ == "__main__":
    main()
