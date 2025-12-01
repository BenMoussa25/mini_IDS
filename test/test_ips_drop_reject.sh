#!/bin/bash

# IPS Test with Python HTTP servers

echo "=========================================="
echo "  IPS DROP/REJECT Test"
echo "=========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Must run as root"
    exit 1
fi

cleanup() {
    echo ""
    echo "[+] Cleaning up..."
    kill $SERVER1 $SERVER2 $MINIIDS_PID 2>/dev/null
    pkill -f "python3.*8080" 2>/dev/null
    pkill -f "python3.*9002" 2>/dev/null
    pkill -f "python3.*9003" 2>/dev/null
    wait 2>/dev/null
}

trap cleanup EXIT

echo "[1] Starting HTTP test servers..."

# Start Python HTTP servers
cd /tmp
python3 -m http.server 80 > /dev/null 2>&1 &
SERVER1=$!

python3 -m http.server 8080 > /dev/null 2>&1 &
SERVER2=$!

# Simple TCP servers for ports 9002 and 9003
while true; do nc -l -p 9002 -q 1 < /dev/null > /dev/null 2>&1; done &
SERVER3=$!

while true; do nc -l -p 9003 -q 1 < /dev/null > /dev/null 2>&1; done &
SERVER4=$!

cd - > /dev/null
sleep 2

echo "[2] Starting miniIDS in IPS mode..."
cd ..
./miniids lo --ips > /tmp/miniids_test.log 2>&1 &
MINIIDS_PID=$!
cd test
sleep 3

echo "[3] Sending attack traffic..."
echo ""

# Test 1: Directory Traversal on port 80 (DROP rule)
echo ">>> Test 1: Directory Traversal on port 80 (should be DROPPED)"
(echo -e "GET /../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"; sleep 1) | nc 127.0.0.1 80 > /dev/null 2>&1 &
sleep 2

# Test 2: Directory Traversal on port 8080 (DROP rule)
echo ">>> Test 2: Directory Traversal on port 8080 (should be DROPPED)"
(echo -e "GET /../../../etc/shadow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"; sleep 1) | nc 127.0.0.1 8080 > /dev/null 2>&1 &
sleep 2

# Test 3: Malware pattern on port 9002 (DROP rule)
echo ">>> Test 3: Malware pattern (should be DROPPED)"
echo "This contains malware signature" | nc -w1 127.0.0.1 9002 > /dev/null 2>&1 &
sleep 2

# Test 4: Attack pattern on port 9003 (DROP rule)
echo ">>> Test 4: Attack pattern (should be DROPPED)"
echo "Launching attack payload" | nc -w1 127.0.0.1 9003 > /dev/null 2>&1 &
sleep 2

# Test 5: /etc/passwd access (REJECT rule)
echo ">>> Test 5: Sensitive file /etc/passwd (should be REJECTED)"
(echo -e "GET /etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"; sleep 1) | nc 127.0.0.1 80 > /dev/null 2>&1 &
sleep 2

# Test 6: /etc/shadow access (REJECT rule)
echo ">>> Test 6: Sensitive file /etc/shadow (should be REJECTED)"
(echo -e "GET /etc/shadow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"; sleep 1) | nc 127.0.0.1 8080 > /dev/null 2>&1 &
sleep 3

echo ""
echo "=========================================="
echo "  Results"
echo "=========================================="
echo ""

echo "Recent Detection Alerts:"
echo "-------------------------------------------"
tail -25 ../logs/alerts.log 2>/dev/null | grep -v "SYSTEM"

echo ""
echo "IPS Actions (BLOCKED/REJECTED):"
echo "-------------------------------------------"
tail -25 ../logs/alerts.log 2>/dev/null | grep "IPS"

echo ""
echo "Active IPS Firewall Rules:"
echo "-------------------------------------------"
iptables -L MINIIDS -n -v --line-numbers

echo ""
echo "Note: If you see DROP or REJECT iptables rules above,"
echo "      the IPS successfully blocked those IPs!"
echo ""

read -p "Press Enter to cleanup and exit..."
