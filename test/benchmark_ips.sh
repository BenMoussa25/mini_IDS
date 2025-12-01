#!/bin/bash

# IPS Performance Benchmark
# Tests IPS mode performance under load

echo "=========================================="
echo "  MiniIDS/IPS Performance Benchmark"
echo "=========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Must be run as root"
    exit 1
fi

TARGET="${1:-127.0.0.1}"
REQUESTS="${2:-100}"

echo "Target: $TARGET"
echo "Requests per test: $REQUESTS"
echo ""

# Function to generate traffic
generate_traffic() {
    local port=$1
    local payload=$2
    local count=$3
    
    for ((i=1; i<=$count; i++)); do
        echo "$payload" | nc -w1 $TARGET $port 2>/dev/null &
    done
    wait
}

echo "Test 1: Normal HTTP Traffic Baseline"
echo "-------------------------------------------"
START=$(date +%s.%N)
generate_traffic 80 "GET / HTTP/1.1\r\n\r\n" $REQUESTS
END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc)
RPS=$(echo "$REQUESTS / $DURATION" | bc -l)
printf "Duration: %.3f seconds\n" $DURATION
printf "Requests/sec: %.2f\n\n" $RPS

echo "Test 2: Attack Traffic (Directory Traversal)"
echo "-------------------------------------------"
START=$(date +%s.%N)
generate_traffic 80 "GET /../etc/passwd HTTP/1.1\r\n\r\n" $REQUESTS
END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc)
RPS=$(echo "$REQUESTS / $DURATION" | bc -l)
printf "Duration: %.3f seconds\n" $DURATION
printf "Requests/sec: %.2f\n\n" $RPS

echo "Test 3: Malware Signatures"
echo "-------------------------------------------"
START=$(date +%s.%N)
generate_traffic 9002 "malware payload" $REQUESTS
END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc)
RPS=$(echo "$REQUESTS / $DURATION" | bc -l)
printf "Duration: %.3f seconds\n" $DURATION
printf "Requests/sec: %.2f\n\n" $RPS

echo "Test 4: Mixed Traffic (50% normal, 50% malicious)"
echo "-------------------------------------------"
START=$(date +%s.%N)
for ((i=1; i<=$REQUESTS; i++)); do
    if [ $((i % 2)) -eq 0 ]; then
        echo "GET / HTTP/1.1\r\n\r\n" | nc -w1 $TARGET 80 2>/dev/null &
    else
        echo "GET /../etc/passwd HTTP/1.1\r\n\r\n" | nc -w1 $TARGET 80 2>/dev/null &
    fi
done
wait
END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc)
RPS=$(echo "$REQUESTS / $DURATION" | bc -l)
printf "Duration: %.3f seconds\n" $DURATION
printf "Requests/sec: %.2f\n\n" $RPS

echo "=========================================="
echo "  Benchmark Complete"
echo "=========================================="
echo ""
echo "IPS Statistics:"
iptables -L MINIIDS -n -v

echo ""
echo "Alert Summary:"
grep -c "BLOCKED" ../logs/alerts.log 2>/dev/null && echo "attacks blocked" || echo "No blocks recorded"
