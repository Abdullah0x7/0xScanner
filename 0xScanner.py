#!/usr/bin/env python3

"""
0xScanner - Professional Network Port Scanner

A secure, enterprise-grade port scanner designed for authorized penetration testing
and network security assessments.

Author: Abdullah Bello
Version: 2.0.0
License: MIT

IMPORTANT: This tool is for authorized use only. Unauthorized scanning is illegal.
"""

import argparse
import asyncio
import json
import logging
import socket
import ssl
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import ipaddress
import concurrent.futures
from contextlib import asynccontextmanager


# Configuration and Constants
class ScanConfig:
    """Configuration class for scanner settings"""
    DEFAULT_TIMEOUT = 3.0
    MAX_CONCURRENT_SCANS = 100
    DEFAULT_TCP_PORTS = "1-1000"
    DEFAULT_UDP_PORTS = "53,67,68,69,123,161,162"
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
    
    # Service detection patterns
    SERVICE_BANNERS = {
        21: b"FTP",
        22: b"SSH",
        23: b"Telnet", 
        25: b"SMTP",
        53: b"DNS",
        80: b"HTTP",
        443: b"HTTPS",
        110: b"POP3",
        143: b"IMAP",
        993: b"IMAPS",
        995: b"POP3S"
    }


@dataclass
class ScanResult:
    """Data class to store scan results in a structured way"""
    ip: str
    port: int
    protocol: str
    status: str
    service: Optional[str] = None
    banner: Optional[str] = None
    response_time: Optional[float] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class SecurityValidator:
    """Security validation class to prevent misuse"""
    
    @staticmethod
    def validate_target(target: str) -> bool:
        """
        Validate if target IP is allowed for scanning
        Like having a security guard check if you're allowed to enter
        """
        try:
            ip = ipaddress.ip_address(target)
            
            # Block scanning of critical infrastructure
            blocked_ranges = [
                ipaddress.ip_network("127.0.0.0/8"),    # Localhost
                ipaddress.ip_network("169.254.0.0/16"), # Link-local
                ipaddress.ip_network("224.0.0.0/4"),    # Multicast
            ]
            
            for blocked in blocked_ranges:
                if ip in blocked:
                    return False
                    
            return True
            
        except ValueError:
            return False
    
    @staticmethod
    def validate_port_range(port_range: str) -> bool:
        """
        Check if port range is reasonable
        Like checking if someone is asking to knock on too many doors
        """
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                return 1 <= start <= end <= 65535 and (end - start) <= 10000
            else:
                port = int(port_range)
                return 1 <= port <= 65535
        except ValueError:
            return False


class Logger:
    """Professional logging setup"""
    
    def __init__(self, log_file: str = "0xscanner.log", verbose: bool = False):
        self.logger = logging.getLogger("0xScanner")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(console_formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def get_logger(self):
        return self.logger

class PortScanner:
    """
    Main scanner class - this is like the brain of our scanner
    It coordinates all the different types of scans
    """
    
    def __init__(self, timeout: float = ScanConfig.DEFAULT_TIMEOUT, 
                 max_workers: int = ScanConfig.MAX_CONCURRENT_SCANS,
                 verbose: bool = False):
        self.timeout = timeout
        self.max_workers = max_workers
        self.logger = Logger(verbose=verbose).get_logger()
        self.results: List[ScanResult] = []
        
    async def tcp_scan(self, ip: str, port: int) -> ScanResult:
        """
        TCP scan - like knocking on a door to see if someone answers
        """
        start_time = time.time()
        
        try:
            # Create a connection attempt
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            response_time = time.time() - start_time
            
            # Try to get service banner (like asking "who's there?")
            banner = None
            try:
                writer.write(b"GET / HTTP/1.0\r\n\r\n")  # Simple HTTP request
                await writer.drain()
                
                data = await asyncio.wait_for(
                    reader.read(1024), 
                    timeout=1.0
                )
                banner = data[:100].decode('utf-8', errors='ignore').strip()
            except:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
            
            # Detect service type
            service = self._detect_service(port, banner)
            
            return ScanResult(
                ip=ip, port=port, protocol="TCP", status="Open",
                service=service, banner=banner, response_time=response_time
            )
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return ScanResult(
                ip=ip, port=port, protocol="TCP", status="Closed"
            )
    
    async def udp_scan(self, ip: str, port: int) -> ScanResult:
        """
        UDP scan - like throwing a letter through a mail slot
        If no error comes back, the port might be open
        """
        start_time = time.time()
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty packet
            sock.sendto(b"", (ip, port))
            
            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                response_time = time.time() - start_time
                
                return ScanResult(
                    ip=ip, port=port, protocol="UDP", status="Open",
                    response_time=response_time
                )
            except socket.timeout:
                # No response might mean open or filtered
                return ScanResult(
                    ip=ip, port=port, protocol="UDP", status="Open|Filtered"
                )
                
        except Exception as e:
            return ScanResult(
                ip=ip, port=port, protocol="UDP", status="Closed"
            )
        finally:
            sock.close()
    
    def _detect_service(self, port: int, banner: Optional[str]) -> Optional[str]:
        """
        Detect what service is running on a port
        Like figuring out if a shop is a bakery or bookstore
        """
        # Check common port mappings
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S"
        }
        
        if port in common_services:
            return common_services[port]
        
        # Check banner for service identification
        if banner:
            banner_lower = banner.lower()
            if "http" in banner_lower:
                return "HTTP"
            elif "ftp" in banner_lower:
                return "FTP" 
            elif "ssh" in banner_lower:
                return "SSH"
            elif "smtp" in banner_lower:
                return "SMTP"
        
        return "Unknown"
    
    async def scan_range(self, target: str, port_range: str, 
                        protocol: str = "TCP") -> List[ScanResult]:
        """
        Scan a range of ports
        Like checking multiple doors in a building
        """
        # Validate target
        if not SecurityValidator.validate_target(target):
            self.logger.error(f"Invalid or restricted target: {target}")
            return []
        
        # Parse port range
        ports = self._parse_port_range(port_range)
        if not ports:
            self.logger.error(f"Invalid port range: {port_range}")
            return []
        
        self.logger.info(f"Starting {protocol} scan of {target} for {len(ports)} ports")
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def scan_with_semaphore(port):
            async with semaphore:
                if protocol.upper() == "TCP":
                    return await self.tcp_scan(target, port)
                else:
                    return await self.udp_scan(target, port)
        
        # Run all scans concurrently
        tasks = [scan_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and closed ports
        valid_results = [
            result for result in results 
            if isinstance(result, ScanResult) and result.status != "Closed"
        ]
        
        self.results.extend(valid_results)
        return valid_results
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """
        Convert port range string to list of ports
        Like turning "1-10" into [1,2,3,4,5,6,7,8,9,10]
        """
        ports = []
        
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                ports = list(range(start, end + 1))
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
            else:
                ports = [int(port_range)]
                
            # Validate each port
            return [p for p in ports if 1 <= p <= 65535]
            
        except ValueError:
            return []
    
    def export_results(self, format_type: str = "json", 
                      filename: Optional[str] = None) -> str:
        """
        Export scan results in different formats
        Like saving your homework in different file types
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.{format_type}"
        
        if format_type.lower() == "json":
            data = {
                "scan_info": {
                    "timestamp": datetime.now().isoformat(),
                    "total_results": len(self.results)
                },
                "results": [asdict(result) for result in self.results]
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
                
        elif format_type.lower() == "csv":
            import csv
            with open(filename, 'w', newline='') as f:
                if self.results:
                    writer = csv.DictWriter(f, fieldnames=asdict(self.results[0]).keys())
                    writer.writeheader()
                    for result in self.results:
                        writer.writerow(asdict(result))
        
        self.logger.info(f"Results exported to {filename}")
        return filename

def create_argument_parser():
    """
    Create command line argument parser
    Like creating a menu of options users can choose from
    """
    parser = argparse.ArgumentParser(
        description="0xScanner - Professional Network Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -p 1-1000
  %(prog)s -t 192.168.1.1 -p 80,443,8080 --protocol TCP
  %(prog)s -t 192.168.1.1 --top-ports --export json
        """
    )
    
    parser.add_argument(
        "-t", "--target", 
        required=True,
        help="Target IP address to scan"
    )
    
    parser.add_argument(
        "-p", "--ports",
        default=ScanConfig.DEFAULT_TCP_PORTS,
        help="Port range (e.g., 1-1000, 80,443,8080)"
    )
    
    parser.add_argument(
        "--protocol",
        choices=["TCP", "UDP", "BOTH"],
        default="TCP",
        help="Protocol to scan (default: TCP)"
    )
    
    parser.add_argument(
        "--top-ports",
        action="store_true",
        help="Scan only the most common ports"
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=ScanConfig.DEFAULT_TIMEOUT,
        help="Connection timeout in seconds"
    )
    
    parser.add_argument(
        "--max-workers",
        type=int,
        default=ScanConfig.MAX_CONCURRENT_SCANS,
        help="Maximum concurrent connections"
    )
    
    parser.add_argument(
        "--export",
        choices=["json", "csv"],
        help="Export results to file"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="0xScanner 2.0.0"
    )
    
    return parser


async def main():
    """
    Main function - this is where everything starts
    Like the main entrance to a building
    """
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = PortScanner(
        timeout=args.timeout,
        max_workers=args.max_workers,
        verbose=args.verbose
    )
    
    # Determine ports to scan
    if args.top_ports:
        port_range = ",".join(map(str, ScanConfig.COMMON_PORTS))
    else:
        port_range = args.ports
    
    # Perform scans
    try:
        if args.protocol in ["TCP", "BOTH"]:
            tcp_results = await scanner.scan_range(args.target, port_range, "TCP")
            print(f"\n=== TCP Scan Results ===")
            for result in tcp_results:
                print(f"{result.ip}:{result.port} - {result.status} "
                      f"({result.service or 'Unknown'})")
        
        if args.protocol in ["UDP", "BOTH"]:
            udp_results = await scanner.scan_range(args.target, port_range, "UDP")
            print(f"\n=== UDP Scan Results ===")
            for result in udp_results:
                print(f"{result.ip}:{result.port} - {result.status}")
        
        # Export results if requested
        if args.export:
            filename = scanner.export_results(args.export)
            print(f"\nResults exported to: {filename}")
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        scanner.logger.error(f"Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Show legal disclaimer
    print("="*60)
    print("0xScanner - Professional Network Port Scanner")
    print("="*60)
    print("WARNING: This tool is for authorized use only!")
    print("Unauthorized scanning may be illegal in your jurisdiction.")
    print("="*60)
    
    # Run the async main function
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(0)