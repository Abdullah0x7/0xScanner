# 0xScanner

0xScanner is a simple multi-protocol port scanner written in Python. It is designed for educational purposes and for personal reconnaissance during penetration testing activities. The scanner supports TCP, UDP, HTTP, HTTPS, and SMTP port scanning.

---

## Disclaimer

**Important:**  
This tool is intended for use only on networks and systems where you have explicit authorization. Unauthorized scanning can be illegal and unethical. Use this tool responsibly and at your own risk.

---

## Features

- **TCP Scanning:** Checks whether TCP ports are open using socket connections.
- **UDP Scanning:** Sends empty UDP packets to determine if ports are open or filtered.
- **HTTP/HTTPS Scanning:** Sends HTTP GET requests to verify web service responses. HTTPS connections are secured using SSL/TLS.
- **SMTP Scanning:** Connects to SMTP servers and looks for SMTP banners.
- **Multithreading:** Utilizes Python's threading to speed up scanning.
- **Logging:** Logs output and error messages to a log file (`0xScanner.log`).

---

## Requirements

- **Python 3.x**  
  The script uses Python's built-in libraries: `socket`, `ssl`, `threading`, and `logging`. No additional external packages are needed.

---

## Usage

1. **Download or Clone the Repository**

   ```bash
   git clone https://github.com/abdullah0x99/0xScanner.git
   cd 0xScanner
   ```

2. **Make the Script Executable (Optional)**

   On Unix-like systems, you can make the script executable:

   ```bash
   chmod +x 0xScanner.py
   ```

3. **Run the Script**

   You can run the script directly or via the Python interpreter:

   - Directly (if executable):
     ```bash
     ./0xScanner.py
     ```
   - Using Python:
     ```bash
     python3 0xScanner.py
     ```

4. **Follow the Prompts**

   - **Enter the Target IP Address:**  
     The script will prompt you for the IP address you wish to scan.
     
   - **Enter Port Ranges:**  
     You will be asked to provide a TCP port range and a UDP port range in the format `start-end` (e.g., `20-80`).
     
   - **Service-Specific Scans:**  
     After scanning the provided ranges, the script will automatically scan for HTTP (port 80), HTTPS (port 443), and SMTP (port 25) services.

5. **Review the Results**

   - **Console Output:**  
     Open ports and responses for various protocols will be printed to the terminal.
   - **Log File:**  
     Detailed logs, including error messages, are saved in `0xScanner.log`.

---

## Code Overview

- **TCP Scanning:**  
  Uses `socket.connect_ex()` to check port availability.
  
- **UDP Scanning:**  
  Sends an empty UDP packet and waits for a response or a timeout, indicating the port is "open|filtered" if no reply is received.
  
- **HTTP/HTTPS Scanning:**  
  Sends a simple HTTP GET request; for HTTPS, the connection is wrapped with SSL for security.
  
- **SMTP Scanning:**  
  Connects to the SMTP port and checks for a valid SMTP banner.

- **Threaded Scanning:**  
  The `threaded_scan()` function creates and manages threads to perform scans concurrently, improving performance.

- **Logging:**  
  The script logs information and error messages to `0xScanner.log` using Python's `logging` module.

---

## Customization

Feel free to modify or extend the script. Some ideas for further improvements include:
- Adding asynchronous I/O with `asyncio` for enhanced performance.
- Implementing additional protocol scans.
- Improving error handling or output formatting.
- Integrating command-line argument parsing with `argparse`.

---

## Contributing

Contributions are welcome! If you have suggestions or bug fixes, please fork the repository and submit a pull request.

---

## License
This project is licensed under the MIT [LICENSE](./LICENSE).

---

## Disclaimer (Again)

This tool is provided for educational purposes only. The author is not responsible for any misuse or damage resulting from its use.

---