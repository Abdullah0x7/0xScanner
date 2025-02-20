#!/usr/bin/env python3

import socket
import ssl
from threading import Thread
import logging

#Logging config: logs will be written to '0xScanner.log'

logging.basicConfig(
    level=logging.INFO,
    filename='0xScanner.log',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

#Scanning TCP

def scan_tcp_port(ip, port):
    try:
        # Create an IPv4 TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Prevent hanging on a port
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[TCP] Port {port} is open")
        sock.close()
    except Exception as e:
        logging.exception("Error scanning port %d on %s", port, ip)

#Scanning UDP

def scan_udp_port(ip, port):
    try:
        # Creating UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # Sending an empty packet (some services might not respond)
        sock.sendto(b'', (ip, port))
        # If a response is received, the port is likely open.
        data, addr = sock.recvfrom(1024)
        logging.info(f"[UDP] Port {port} is open (received response)")
        print(f"[UDP] Port {port} is open (received response)")
        sock.close()
    except socket.timeout:
        # No response could mean open or filtered
        logging.info(f"[UDP] Port {port} is open|filtered (no response)")
        print(f"[UDP] Port {port} is open|filtered (no response)")
    except Exception as e:
        # Any error might indicate the port is closed/unreachable
        logging.info(f"[UDP] Port {port} is closed or unreachable")
        print(f"[UDP] Port {port} is closed or unreachable")

#Checking for port 80

def scan_http_port(ip, port=80):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        if result == 0:
            # Sending a simple HTTP GET request
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            sock.sendall(request.encode())
            data = sock.recv(1024)
            if b"HTTP" in data:
                logging.info(f"[HTTP] Port {port} is open and returned an HTTP response")
                print(f"[HTTP] Port {port} is open and returned an HTTP response")
            else:
                logging.info(f"[HTTP] Port {port} is open but did not return a valid HTTP response")
                print(f"[HTTP] Port {port} is open but did not return a valid HTTP response")
        else:
            print(f"[HTTP] Port {port} is closed")
        sock.close()
    except Exception as e:
        logging.exception(f"[HTTP] Error scanning port {port}: {e}")
        print(f"[HTTP] Error scanning port {port}: {e}")

#Checking for port 443
def scan_https_port(ip, port=443):
    try:
        context = ssl.create_default_context()
        # Creating a normal connection first
        sock = socket.create_connection((ip, port), timeout=2)
        # Wrapping the socket for SSL/TLS
        ssock = context.wrap_socket(sock, server_hostname=ip)
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
        ssock.sendall(request.encode())
        data = ssock.recv(1024)
        if b"HTTP" in data:
            logging.info(f"[HTTPS] Port {port} is open and returned an HTTP response")
            print(f"[HTTPS] Port {port} is open and returned an HTTPS response")
        else:
            logging.info(f"[HTTPS] Port {port} is open but did not return a valid response")
            print(f"[HTTPS] Port {port} is open but did not return a valid response")
        ssock.close()
    except Exception as e:
        logging.exception(f"[HTTPS] Port {port} is closed or error occurred: {e}")
        print(f"[HTTPS] Port {port} is closed or error occurred: {e}")

#checking for port 25
def scan_smtp_port(ip, port=25):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        if result == 0:
            #waiting for smtp banner
            banner = sock.recv(1024)
            if b"SMTP" in banner:
                logging.info(f"[SMTP] Port {port} is open and returned an SMTP banner")
                print(f"[SMTP] Port {port} is open and returned an SMTP banner")
            else:
                logging.info(f"[SMTP] Port {port} is open but did not return an SMTP banner")
                print(f"[SMTP] Port {port} is open but did not return an SMTP banner")
        else:
            logging.info(f"[SMTP] Port {port} is closed")
            print(f"[SMTP] Port {port} is closed")
        sock.close()
    except Exception as e:
        logging.exception(f"[SMTP] Error scanning port {port}: {e}")
        print(f"[SMTP] Error scanning port {port}: {e}")

#running scans with threads
def threaded_scan(scan_func, ip, ports):
    threads = []
    for port in ports:
        thread = Thread(target=scan_func, args=(ip, port))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

def validate_port_range(port_range):
    try:
        start, end = map(int, port_range.split('-'))
        if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
            return start, end
        else:
            raise ValueError
    except ValueError:
        start, end = map(int, port_range.split('-'))
        return None

#Main function
if __name__ == "__main__":
    target_ip = input("Enter target IP address: ")

    # Ask user for port ranges for TCP and UDP scans
    tcp_range = input("Enter TCP port range (e.g. 20-80): ")
    udp_range = input("Enter UDP port range (e.g. 20-80): ")

    tcp_start, tcp_end = map(int, tcp_range.split('-'))
    udp_start, udp_end = map(int, udp_range.split('-'))

    print(f"\nScanning TCP ports {tcp_start} to {tcp_end}")
    threaded_scan(scan_tcp_port, target_ip, range(tcp_start, tcp_end+1))

    print(f"\nScanning UDP ports {udp_start} to {udp_end}")
    threaded_scan(scan_udp_port, target_ip, range(udp_start, udp_end+1))

    # Service-specific scans using default ports
    print("\nScanning HTTP port (80)")
    scan_http_port(target_ip, 80)

    print("\nScanning HTTPS port (443)")
    scan_https_port(target_ip, 443)

    print("\nScanning SMTP port (25)")
    scan_smtp_port(target_ip, 25)
