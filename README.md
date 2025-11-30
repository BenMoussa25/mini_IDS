# miniIDS - Lightweight Intrusion Detection System

A simple, lightweight Intrusion Detection System (IDS) written in C for network packet analysis and threat detection.

## 🚀 Features

- **Real-time Packet Capture** - Monitors network traffic using libpcap
- **Rule-Based Detection** - Flexible rule system for threat identification
- **Content Pattern Matching** - Detects malicious payloads and suspicious patterns
- **TCP Flag Analysis** - Identifies port scans and flag-based attacks
- **Alert Logging** - Records all detected threats with timestamps
- **Colored Console Output** - Visual alerts for immediate threat visibility

## 📁 Project Structure

```
miniids/
├── src/              # Source files
│   ├── main.c        # Main program and initialization
│   ├── packet.c      # Packet capture and parsing
│   ├── rules.c       # Rule loading and matching
│   ├── detect.c      # Threat detection engine
│   └── utils.c       # Utility functions (logging)
├── include/          # Header files
│   ├── packet.h      # Packet structure definitions
│   ├── rules.h       # Rule structure definitions
│   ├── detect.h      # Detection function declarations
│   └── utils.h       # Utility function declarations
├── obj/              # Object files (auto-generated)
├── rules/
│   └── rules.conf    # Detection rules configuration
├── logs/
│   └── alerts.log    # Alert log file (auto-created)
├── Makefile          # Build configuration
└── README.md         # This file
```

## 🔧 Requirements

### System Requirements
- **OS**: Linux (tested on Debian/Ubuntu/Kali)
- **Compiler**: GCC
- **Library**: libpcap

### Installing Dependencies

**Ubuntu/Debian/Kali:**
```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install gcc make libpcap-devel
```

**Arch Linux:**
```bash
sudo pacman -S base-devel libpcap
```

## 📦 Building

```bash
# Clone or navigate to the project directory
cd miniIDS

# Build the project
make

# The executable 'miniids' will be created
```

**Clean build:**
```bash
make clean
make
```

## 🎯 Usage

### Basic Usage

Run miniIDS with root/sudo privileges, specifying the network interface:

```bash
sudo ./miniids <interface>
```

**Examples:**
```bash
# Monitor loopback interface
sudo ./miniids lo

# Monitor ethernet interface
sudo ./miniids eth0

# Monitor wireless interface
sudo ./miniids wlan0
```

### Finding Your Network Interface

```bash
# List all network interfaces
ip link show

# Or use ifconfig
ifconfig
```

### Stopping miniIDS

Press `Ctrl+C` to gracefully stop the IDS.

## ⚙️ Configuration

### Rules File: `rules/rules.conf`

Rules follow this format:
```
alert <protocol> <src_ip> <src_port> -> <dst_ip> <dst_port> (<type>:"<pattern>"; msg:"<description>";)
```

**Rule Types:**
- `content` - Match content in packet payload
- `flags` - Match TCP flags (SYN, FIN, PSH, ACK, URG, RST)

**Protocols:**
- `tcp` - TCP packets
- `udp` - UDP packets
- `icmp` - ICMP packets
- `any` - Any protocol

**Example Rules:**
```bash
# HTTP traffic detection
alert tcp any any -> any 80 (content:"GET"; msg:"HTTP GET Request";)

# Directory traversal attempt
alert tcp any any -> any 80 (content:"../"; msg:"Directory Traversal Attempt";)

# Port scan detection
alert tcp any any -> any 22 (flags:"SYN"; msg:"SSH Port Scan Detected";)

# Malicious content
alert tcp any any -> any 8080 (content:"malware"; msg:"Malware Signature Detected";)
```

### Adding Custom Rules

1. Edit `rules/rules.conf`
2. Add your rules following the format above
3. Restart miniIDS to load new rules

## 📊 Alerts and Logging

### Console Output
Alerts appear in the terminal with:
- 🔴 Red color highlighting
- Timestamp
- Source and destination IP:Port
- Protocol
- Alert message

**Example:**
```
[2025-11-30 17:59:17] ALERT: HTTP Request on port 8080 | 127.0.0.1:43754 → 127.0.0.1:8080 [TCP]
```

### Log File
All alerts are saved to `logs/alerts.log`:
```bash
# View all alerts
cat logs/alerts.log

# Monitor alerts in real-time
tail -f logs/alerts.log

# Search for specific alerts
grep "Port Scan" logs/alerts.log
```

## 🧪 Testing

### Test Scripts

**Simple Test:**
```bash
sudo ./simple_test.sh
```
Generates HTTP traffic on ports 80, 8080, and 8888.

**Enhanced Traffic Generator:**
```bash
sudo ./generate_traffic_v2.sh
```
Generates comprehensive test traffic including:
- ICMP ping
- HTTP requests
- Directory traversal attempts
- Port scanning simulation

### Manual Testing

**Terminal 1 - Run miniIDS:**
```bash
sudo ./miniids lo
```

**Terminal 2 - Generate traffic:**
```bash
# Test HTTP detection
curl http://localhost:8080

# Test directory traversal
curl "http://localhost:8080/../../etc/passwd"

# Test ICMP
ping -c 5 127.0.0.1

# Test port scanning
for port in 22 80 443; do nc -zv localhost $port; done
```

## 🛠️ Makefile Targets

```bash
make          # Build the project
make clean    # Remove object files, executable, and logs
make install  # Install miniids to /usr/local/bin
make run      # Build and run with sudo
```

## 🔍 How It Works

1. **Packet Capture**: Uses libpcap to capture raw network packets
2. **Packet Parsing**: Extracts IP headers, TCP/UDP headers, and payload data
3. **Rule Matching**: Compares packet data against loaded detection rules
4. **Alert Generation**: Logs and displays matches in real-time

### Detection Methods

**Content-Based Detection:**
- Searches packet payloads for suspicious strings
- Identifies attack patterns (SQL injection, XSS, etc.)
- Detects malware signatures

**Flag-Based Detection:**
- Analyzes TCP flags for port scanning
- Detects SYN floods, FIN scans, XMAS scans
- Identifies NULL scans

## ⚠️ Limitations

- Educational/learning tool - not production-ready
- Basic pattern matching only (no regex support)
- No packet reassembly or stream reconstruction
- Limited protocol support (TCP, UDP, ICMP)
- No statistical analysis or anomaly detection
- Single-threaded architecture

## 🔐 Security Considerations

**This is an educational project and should NOT be used as a primary security solution in production environments.**

For production use, consider mature IDS/IPS solutions like:
- Snort
- Suricata
- Zeek (formerly Bro)

## 🐛 Troubleshooting

**Permission Denied:**
```bash
# Ensure you run with sudo
sudo ./miniids lo
```

**Cannot Find Interface:**
```bash
# Check available interfaces
ip link show

# Ensure interface is up
sudo ip link set eth0 up
```

**No Alerts Generated:**
- Verify rules are loaded: Check startup output
- Generate test traffic: Use provided test scripts
- Check logs: `cat logs/alerts.log`
- Verify interface has traffic: `sudo tcpdump -i lo -c 10`

**Compilation Errors:**
```bash
# Ensure dependencies are installed
sudo apt-get install build-essential libpcap-dev

# Clean and rebuild
make clean
make
```

## 📝 License

This project is provided as-is for educational purposes.

## 🤝 Contributing

This is an educational project. Feel free to fork, modify, and enhance it for learning purposes.

## 📚 Learning Resources

- [Libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [TCP/IP Protocol Suite](https://en.wikipedia.org/wiki/Internet_protocol_suite)
- [Snort Rule Writing](https://docs.snort.org/rules/)

## 📧 Support

For issues or questions about this educational project, please open an issue on the repository.

---

**Built with ❤️ for learning network security and intrusion detection systems.**
