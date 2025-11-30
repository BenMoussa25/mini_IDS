#!/bin/bash

echo "========================================"
echo "Enhanced Traffic Generator for miniIDS"
echo "========================================"
echo ""
echo "Make sure miniIDS is running: sudo ./miniids lo"
echo ""

sleep 2

echo "[*] Test 1: Generating ICMP traffic..."
ping -c 5 127.0.0.1 &
PID1=$!
sleep 2

echo ""
echo "[*] Test 2: Starting simple HTTP server and making requests..."
# Start a simple HTTP server in background
python3 -m http.server 8080 >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1

# Make HTTP requests that will trigger rules
echo "   - Normal HTTP request..."
curl -s http://127.0.0.1:8080/ >/dev/null 2>&1
sleep 1

echo "   - Directory traversal attempt..."
curl -s "http://127.0.0.1:8080/../../etc/passwd" >/dev/null 2>&1
sleep 1

echo "   - Another traversal with '../'..."
curl -s "http://127.0.0.1:8080/../../../etc/shadow" >/dev/null 2>&1
sleep 1

# Kill HTTP server
kill $HTTP_PID 2>/dev/null

echo ""
echo "[*] Test 3: Creating TCP connections with suspicious payloads..."

# Start simple listeners and send data
for PORT in 9001 9002 9003; do
    (nc -l 127.0.0.1 $PORT >/dev/null 2>&1) &
    LISTENER_PID=$!
    sleep 0.5
    
    if [ $PORT -eq 9001 ]; then
        echo "GET /malware.exe HTTP/1.1" | nc 127.0.0.1 $PORT 2>/dev/null &
    elif [ $PORT -eq 9002 ]; then
        echo "This is an attack payload" | nc 127.0.0.1 $PORT 2>/dev/null &
    else
        echo "GET /../../../etc/passwd HTTP/1.1" | nc 127.0.0.1 $PORT 2>/dev/null &
    fi
    
    sleep 1
    kill $LISTENER_PID 2>/dev/null
done

echo ""
echo "[*] Test 4: Simulating port scanning..."
for PORT in 22 80 443 21 53 25 110 143; do
    timeout 0.5 nc -zv 127.0.0.1 $PORT 2>/dev/null || true
    sleep 0.2
done

echo ""
echo "[*] Test 5: Generating DNS-like UDP traffic..."
echo "DNS query test" | nc -u 127.0.0.1 53 2>/dev/null &
sleep 1

echo ""
echo "[*] Test 6: Creating web requests with suspicious patterns..."
# Start another HTTP server
python3 -m http.server 8888 >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1

curl -s "http://127.0.0.1:8888/admin.php?id=1' OR '1'='1" >/dev/null 2>&1
curl -s "http://127.0.0.1:8888/shell.php" >/dev/null 2>&1
curl -s "http://127.0.0.1:8888/upload.php?file=../../../../etc/passwd" >/dev/null 2>&1

kill $HTTP_PID 2>/dev/null
sleep 1

echo ""
echo "========================================"
echo "Traffic generation complete!"
echo ""
echo "Now check:"
echo "  1. The miniIDS terminal for real-time alerts"
echo "  2. Run: cat logs/alerts.log"
echo "========================================"
