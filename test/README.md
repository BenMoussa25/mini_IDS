# MiniIDS/IPS Test Suite

This directory contains traffic generators and test scripts for testing both IDS and IPS modes.

## Test Scripts

### 1. test_ips_mode.sh (Main Test Script)
Interactive test script that starts MiniIDS in either IDS or IPS mode and runs comprehensive tests.

**Usage:**
```bash
sudo ./test_ips_mode.sh
```

**Features:**
- Menu-driven interface to select IDS or IPS mode
- Runs 8 different test scenarios
- Shows real-time iptables rules (IPS mode)
- Displays alerts and blocked IPs
- Automatic cleanup on exit

**Tests included:**
1. Normal HTTP traffic
2. Directory traversal attacks
3. Multiple path traversal attempts
4. Malware signature detection
5. Attack pattern detection
6. Sensitive file access
7. Port scan simulation
8. Multi-port HTTP traffic

---

### 2. generate_attack_traffic.sh
Standalone attack traffic generator for testing detection and blocking capabilities.

**Usage:**
```bash
./generate_attack_traffic.sh [target_ip]
```

**Attack Types:**
1. Directory Traversal Attack
2. Sensitive File Access
3. Malware Signature
4. Port Scan (SYN)
5. Port Scan (FIN)
6. Combined Attack (All types)

**Example:**
```bash
# Test against localhost
./generate_attack_traffic.sh 127.0.0.1

# Combined attack
# Select option 6 from menu
```

---

### 3. normal_traffic.sh
Generates legitimate (non-malicious) HTTP traffic to verify IPS doesn't block normal requests.

**Usage:**
```bash
./normal_traffic.sh [target_ip]
```

**Traffic Generated:**
- Standard HTTP GET requests
- HTTP POST requests
- Various HTTP methods (GET, POST, PUT, DELETE)
- Normal file requests (html, css, js, images)
- API endpoint requests

**Purpose:**
Ensure the IPS doesn't have false positives that block legitimate traffic.

---

### 4. benchmark_ips.sh
Performance benchmark for IPS mode under load.

**Usage:**
```bash
sudo ./benchmark_ips.sh [target_ip] [request_count]
```

**Default:** 100 requests per test

**Benchmark Tests:**
1. Normal HTTP traffic baseline
2. Attack traffic (directory traversal)
3. Malware signatures
4. Mixed traffic (50% normal, 50% malicious)

**Metrics:**
- Duration (seconds)
- Requests per second
- Total blocks

**Example:**
```bash
# Run 500 requests per test
sudo ./benchmark_ips.sh 127.0.0.1 500
```

---

## Prerequisites

### Required for all tests:
- `netcat` (nc) - Install: `sudo apt-get install netcat`
- Root privileges for IPS mode tests

### Optional (for advanced tests):
- `hping3` - For advanced port scanning tests
  ```bash
  sudo apt-get install hping3
  ```
- `bc` - For benchmark calculations
  ```bash
  sudo apt-get install bc
  ```

---

## Quick Start

### Test IPS Mode:
```bash
# 1. Make scripts executable
chmod +x *.sh

# 2. Run main test script
sudo ./test_ips_mode.sh

# 3. Select IPS mode (option 2)

# 4. Review results in logs/alerts.log
```

### Test IDS Mode (Passive):
```bash
# Select IDS mode (option 1) in test_ips_mode.sh
# All traffic will be detected but NOT blocked
```

### Generate Custom Attacks:
```bash
# Terminal 1: Start MiniIDS in IPS mode
sudo ../miniids lo --ips

# Terminal 2: Generate attacks
./generate_attack_traffic.sh 127.0.0.1
```

### Verify No False Positives:
```bash
# Terminal 1: Start IPS
sudo ../miniids lo --ips

# Terminal 2: Send legitimate traffic
./normal_traffic.sh 127.0.0.1

# Verify no blocks occurred
sudo iptables -L MINIIDS -n -v
```

---

## Understanding Results

### IDS Mode (Passive Detection)
- All traffic is **detected** and **alerted**
- No traffic is blocked
- Check `../logs/alerts.log` for detections

### IPS Mode (Active Prevention)
- Malicious traffic is **detected** and **blocked**
- Source IPs are added to iptables DROP rules
- Check:
  - Alerts: `tail -f ../logs/alerts.log`
  - Blocked IPs: `sudo iptables -L MINIIDS -n -v`

### Expected Behavior

**Normal Traffic:**
- ✅ Allowed in both IDS and IPS modes
- May trigger alerts if patterns match rules

**Attack Traffic:**
- ✅ Alerted in IDS mode (allowed to pass)
- 🔒 Blocked in IPS mode (IP added to firewall)

---

## Troubleshooting

### "Command not found: nc"
```bash
sudo apt-get install netcat-openbsd
```

### "Permission denied"
Make scripts executable:
```bash
chmod +x *.sh
```

### "Failed to initialize IPS mode"
- Ensure you're running as root: `sudo ./test_ips_mode.sh`
- Check iptables is installed: `sudo iptables --version`

### No alerts showing
- Verify MiniIDS is running: `ps aux | grep miniids`
- Check logs directory exists: `ls -la ../logs/`
- View MiniIDS output: `tail -f /tmp/miniids_output.log`

### IPS not blocking traffic
- Verify IPS mode is enabled (check startup message)
- Check iptables rules: `sudo iptables -L MINIIDS -n -v`
- Ensure rules.conf has `drop` or `reject` actions

---

## Cleanup

The test scripts automatically cleanup on exit, but if needed:

```bash
# Stop MiniIDS
sudo killall miniids

# Manual cleanup of iptables
sudo iptables -D INPUT -j MINIIDS 2>/dev/null
sudo iptables -F MINIIDS 2>/dev/null
sudo iptables -X MINIIDS 2>/dev/null
```

---

## Rule Testing Matrix

| Attack Type | Rule Action | IDS Behavior | IPS Behavior |
|-------------|-------------|--------------|--------------|
| Normal HTTP | alert | ✓ Alert | ✓ Alert, Allow |
| Directory Traversal | drop | ✓ Alert | 🔒 Alert, Block |
| /etc/passwd access | reject | ✓ Alert | 🔒 Alert, Block+RST |
| Malware signature | drop | ✓ Alert | 🔒 Alert, Block |
| Port scan (SYN) | alert | ✓ Alert | ✓ Alert, Allow |
| Port scan (FIN) | reject | ✓ Alert | 🔒 Alert, Block+RST |

---

## Performance Notes

- IDS mode has minimal performance impact
- IPS mode adds iptables overhead (~5-10% latency)
- Benchmark shows typical handling: 100-500 packets/second
- Memory usage: ~2-5MB for MiniIDS process

---

## Next Steps

1. Run `test_ips_mode.sh` to verify basic functionality
2. Use `normal_traffic.sh` to test false positive rate
3. Run `benchmark_ips.sh` for performance metrics
4. Customize `generate_attack_traffic.sh` for specific scenarios
5. Add custom rules to `../rules/rules.conf` and retest
