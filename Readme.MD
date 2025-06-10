# 0xScanner v2.0 - Professional Network Port Scanner

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-professional-red.svg)](https://github.com/Abdullah0x7/0xScanner)

A professional-grade, asynchronous network port scanner designed for cybersecurity professionals, penetration testers, and network administrators. Built with security, performance, and enterprise standards in mind.

## 🚨 Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing only. Unauthorized port scanning may be illegal in your jurisdiction. Users are responsible for ensuring they have explicit permission to scan target systems. The author assumes no liability for misuse.

## ✨ Features

### Core Capabilities
- **Asynchronous Scanning** - High-performance concurrent scanning
- **Multi-Protocol Support** - TCP, UDP, and service detection
- **Professional Logging** - Structured logging with multiple levels
- **Security Validation** - Built-in target validation and safety checks
- **Export Capabilities** - JSON and CSV export formats
- **Service Detection** - Banner grabbing and service identification

### Security Features
- **Target Validation** - Prevents scanning of restricted IP ranges
- **Rate Limiting** - Configurable concurrent connection limits
- **Safe Defaults** - Conservative timeout and connection settings
- **Legal Compliance** - Clear usage warnings and disclaimers

### Professional Features
- **Command Line Interface** - Full argparse implementation
- **Structured Data** - Clean, exportable scan results
- **Error Handling** - Comprehensive exception management  
- **Performance Metrics** - Response time measurement
- **Extensible Design** - Modular architecture for future enhancements

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Abdullah0x7/0xScanner.git
cd 0xScanner

# Make executable (Linux/macOS)
chmod +x 0xScanner.py

# Run directly
python3 0xScanner.py --help
```

### Basic Usage

```bash
# Scan common ports on a target
python3 0xScanner.py -t 192.168.1.1 --top-ports

# Scan custom port range
python3 0xScanner.py -t 192.168.1.1 -p 1-1000

# Scan specific ports with export
python3 0xScanner.py -t 192.168.1.1 -p 80,443,8080 --export json

# UDP scanning
python3 0xScanner.py -t 192.168.1.1 -p 53,67,123 --protocol UDP

# Comprehensive scan
python3 0xScanner.py -t 192.168.1.1 -p 1-65535 --protocol BOTH --verbose
```

## 📊 Usage Examples

### Web Server Assessment
```bash
# Scan web-related ports
python3 0xScanner.py -t example.com -p 80,443,8080,8443 --export json
```

### Network Discovery
```bash
# Quick network assessment
python3 0xScanner.py -t 192.168.1.1 --top-ports --verbose
```

### Comprehensive Security Scan
```bash
# Full port range with service detection
python3 0xScanner.py -t target.local -p 1-65535 --timeout 2 --max-workers 50
```

## 🛠️ Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-t, --target` | Target IP address (required) | `-t 192.168.1.1` |
| `-p, --ports` | Port range or list | `-p 1-1000` or `-p 80,443` |
| `--protocol` | Protocol to scan (TCP/UDP/BOTH) | `--protocol TCP` |
| `--top-ports` | Scan most common ports only | `--top-ports` |
| `--timeout` | Connection timeout in seconds | `--timeout 3.0` |
| `--max-workers` | Max concurrent connections | `--max-workers 100` |
| `--export` | Export format (json/csv) | `--export json` |
| `-v, --verbose` | Enable verbose logging | `-v` |

## 📁 Output Formats

### Console Output
```
=== TCP Scan Results ===
192.168.1.1:22 - Open (SSH)
192.168.1.1:80 - Open (HTTP)  
192.168.1.1:443 - Open (HTTPS)
```

### JSON Export
```json
{
  "scan_info": {
    "timestamp": "2025-06-10T10:30:00",
    "total_results": 3
  },
  "results": [
    {
      "ip": "192.168.1.1",
      "port": 22,
      "protocol": "TCP",
      "status": "Open",
      "service": "SSH",
      "response_time": 0.025
    }
  ]
}
```

## 🏗️ Architecture

### Core Components

```
0xScanner/
├── scanner.py          # Main scanner class
├── config.py          # Configuration management
├── security.py        # Security validation
├── logger.py          # Professional logging
└── exporters.py       # Result export handlers
```

### Key Classes

- **`PortScanner`** - Main scanning engine with async capabilities
- **`ScanResult`** - Structured data class for results
- **`SecurityValidator`** - Target validation and safety checks
- **`Logger`** - Professional logging with file and console output

## 🔧 Advanced Configuration

### Custom Timeout Settings
```bash
# Fast scan (aggressive)
python3 0xScanner.py -t target --timeout 1 --max-workers 200

# Slow scan (stealthy)  
python3 0xScanner.py -t target --timeout 10 --max-workers 10
```

### Service Detection
The scanner automatically detects common services:
- HTTP/HTTPS web servers
- SSH, FTP, SMTP servers  
- DNS, POP3, IMAP services
- Custom banner analysis

## 📈 Performance

- **Concurrent Scanning** - Up to 1000+ concurrent connections
- **Async I/O** - Non-blocking network operations
- **Memory Efficient** - Minimal resource usage
- **Scalable** - Handles large port ranges efficiently

## 🛡️ Security Considerations

### Built-in Protections
- Validates target IP addresses
- Blocks scanning of localhost and private ranges
- Implements connection rate limiting
- Provides clear legal warnings

### Best Practices
- Always obtain explicit permission before scanning
- Use reasonable timeout and concurrency settings
- Monitor network impact during scans
- Keep scan logs for audit purposes

## 🧪 Testing

```bash
# Run basic functionality test
python3 -m pytest tests/

# Test against localhost (safe)
python3 0xScanner.py -t 127.0.0.1 -p 22,80,443
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with proper documentation
4. Add tests for new functionality  
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -e ".[dev]"

# Run code formatting
black 0xScanner.py

# Run linting
flake8 0xScanner.py
```

## 📝 Changelog

### v2.0.0 (Current)
- Complete rewrite with async/await
- Professional command-line interface
- Structured data classes and JSON export
- Enhanced security validation
- Comprehensive logging system
- Performance optimizations

### v1.0.0 (Legacy)
- Basic port scanning functionality
- Threading-based concurrency
- Simple console output

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Python asyncio community for excellent async networking examples
- Cybersecurity professionals who provided feedback and suggestions
- Open source security tools that inspired this design

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/Abdullah0x7/0xScanner/issues)
- **Documentation**: [Project Wiki](https://github.com/Abdullah0x7/0xScanner/wiki)
- **Security Reports**: Email security issues to belloabdullah76@gmail.com

---

**Made with ❤️ by Abdullah Bello** | **For Authorized Security Testing Only