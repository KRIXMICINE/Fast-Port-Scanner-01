from asyncio import futures
from email.policy import HTTP
import socket
import concurrent.futures
from unittest import result

def scan_port(ip, port):
    """Attempts to connect to a specific port and grab it's banner"""
    try:
        # AF_INET for IPV4, SOCK_STREAM for TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)

            # connect_ex is faster than connect() because it returns an error instead of raising an exception.

            if s.connect_ex((ip, port)) == 0:
                try:
                    # sends dummy HTTP request to trigger response from the service
                    s.sendall(b"HEAD /HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.socket.timeout:
                     banner = "service open, no banner"
                return port, banner

    except Exception:
        pass
    return None

def fast_scanner(target_ip, ports):
    """Distribute port scanning across multiple concurrent threads"""
    print(f"[*] scanning {target_ip}...")
    open_ports = []

    #ThreadpoolExecutor handles network-bound concurrency bypassing GIL bottleneck

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, target_ip, p): p for p in ports}
        for futures in concurrent.futures.as_completed(futures):
            result = futures.result()
            if result:
                port, banner = result
                print(f"[+] Port {port} is OPEN | Banner: {banner[:40]}")
                open_ports.append(port)
    return open_ports

# Example usage
# fast_scanner ("192.168.1.10", range(1, 1025))
