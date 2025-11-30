#!/bin/bash

echo "=========================================="
echo "Simple miniIDS Alert Generator"
echo "=========================================="
echo ""

# Test 1: HTTP traffic on port 8080
echo "[1] Starting HTTP server on port 8080 and sending GET requests..."
python3 -m http.server 8080 >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1

curl -s http://127.0.0.1:8080/ >/dev/null 2>&1
curl -s http://127.0.0.1:8080/test.html >/dev/null 2>&1
curl -s http://127.0.0.1:8080/index.php >/dev/null 2>&1

kill $HTTP_PID 2>/dev/null
sleep 2

# Test 2: HTTP traffic on port 8888  
echo "[2] Starting HTTP server on port 8888 and sending requests..."
python3 -m http.server 8888 >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1

curl -s http://127.0.0.1:8888/page.html >/dev/null 2>&1
curl -s "http://127.0.0.1:8888/../../etc/passwd" >/dev/null 2>&1

kill $HTTP_PID 2>/dev/null
sleep 2

# Test 3: More aggressive testing
echo "[3] Generating multiple HTTP requests..."
python3 -m http.server 80 >/dev/null 2>&1 &
HTTP80_PID=$!
sleep 1

for i in {1..5}; do
    curl -s http://127.0.0.1:80/ >/dev/null 2>&1
    sleep 0.5
done

kill $HTTP80_PID 2>/dev/null

echo ""
echo "=========================================="
echo "Traffic generation complete!"
echo "Check miniIDS output for alerts"
echo "=========================================="
