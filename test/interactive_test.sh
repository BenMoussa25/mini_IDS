#!/bin/bash

# MiniIDS/IPS Interactive Attack Testing Suite
# Comprehensive testing with target and attack selection

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "╔════════════════════════════════════════════════════════════════════════════╗"
    echo "║              MiniIDS/IPS Attack Testing Suite - Help                      ║"
    echo "╚════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "USAGE:"
    echo "  sudo ./interactive_test.sh [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  -t, --target <IP>         Target IP address (default: 127.0.0.1)"
    echo "  -i, --interface <IFACE>   Network interface (default: lo)"
    echo "  -m, --mode <MODE>         Mode: ids or ips (default: ids)"
    echo "  -a, --attack <TYPE>       Attack type (see below)"
    echo "  -s, --start               Auto-start servers and miniIDS"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "ATTACK TYPES:"
    echo "  Individual Attacks:"
    echo "    dir-traversal-80        Directory traversal attack on port 80 (DROP)"
    echo "    dir-traversal-8080      Directory traversal attack on port 8080 (DROP)"
    echo "    sensitive-passwd        Access /etc/passwd on port 80 (REJECT)"
    echo "    sensitive-shadow        Access /etc/shadow on port 8080 (REJECT)"
    echo "    malware                 Malware signature on port 9002 (DROP)"
    echo "    attack-pattern          Attack pattern on port 9003 (DROP)"
    echo "    syn-scan                SYN port scan on multiple ports"
    echo "    fin-scan                FIN port scan on multiple ports"
    echo "    http-normal-80          Normal HTTP request on port 80"
    echo "    http-normal-8080        Normal HTTP request on port 8080"
    echo ""
    echo "  Combined Attacks:"
    echo "    all-drop                Run all DROP attacks (traversal + malware + attack)"
    echo "    all-reject              Run all REJECT attacks (sensitive files + scans)"
    echo "    full-suite              Complete attack suite (all attacks)"
    echo ""
    echo "EXAMPLES:"
    echo "  # Run in interactive mode (menu-driven)"
    echo "  sudo ./interactive_test.sh"
    echo ""
    echo "  # Run complete attack suite in IPS mode"
    echo "  sudo ./interactive_test.sh -m ips -a full-suite -s"
    echo ""
    echo "  # Test malware detection against custom target"
    echo "  sudo ./interactive_test.sh -t 192.168.1.10 -m ips -a malware -s"
    echo ""
    echo "  # Run all DROP attacks in IDS mode"
    echo "  sudo ./interactive_test.sh -m ids -a all-drop -s"
    echo ""
    echo "  # Test directory traversal on eth0 interface"
    echo "  sudo ./interactive_test.sh -i eth0 -m ips -a dir-traversal-80 -s"
    echo ""
    echo "MODES:"
    echo "  ids - Detection only (passive, no blocking)"
    echo "  ips - Prevention mode (active blocking with iptables)"
    echo ""
    echo "NOTE:"
    echo "  - Running without parameters starts interactive menu mode"
    echo "  - Use -s flag to automatically start test servers and miniIDS"
    echo "  - IPS mode requires root privileges for iptables management"
    echo ""
    exit 1
fi

# Global variables
MINIIDS_PID=""
SERVER_PIDS=()
TARGET="127.0.0.1"
INTERFACE="lo"
IPS_MODE=0
AUTO_START=0
ATTACK_TYPE=""
NON_INTERACTIVE=0

# Cleanup function
cleanup() {
    echo ""
    echo "[+] Cleaning up..."
    
    # Stop miniIDS
    if [ ! -z "$MINIIDS_PID" ]; then
        kill -SIGINT $MINIIDS_PID 2>/dev/null
        wait $MINIIDS_PID 2>/dev/null
    fi
    
    # Stop all servers
    for pid in "${SERVER_PIDS[@]}"; do
        kill $pid 2>/dev/null
    done
    
    # Kill any remaining servers
    pkill -f "python3.*http.server" 2>/dev/null
    pkill -f "nc -l" 2>/dev/null
    
    wait 2>/dev/null
    echo "[+] Cleanup complete"
}

trap cleanup EXIT

# Function to start test servers
start_servers() {
    echo "[+] Starting test servers..."
    
    # HTTP servers
    cd /tmp
    python3 -m http.server 80 > /dev/null 2>&1 &
    SERVER_PIDS+=($!)
    
    python3 -m http.server 8080 > /dev/null 2>&1 &
    SERVER_PIDS+=($!)
    
    python3 -m http.server 8888 > /dev/null 2>&1 &
    SERVER_PIDS+=($!)
    
    # TCP listeners for malware/attack testing
    while true; do nc -l -p 9002 -q 1 2>/dev/null; done &
    SERVER_PIDS+=($!)
    
    while true; do nc -l -p 9003 -q 1 2>/dev/null; done &
    SERVER_PIDS+=($!)
    
    cd - > /dev/null
    sleep 2
    echo "[+] Servers started on ports: 80, 8080, 8888, 9002, 9003"
}

# Function to start miniIDS
start_miniids() {
    local interface=$1
    local mode_flag=""
    
    if [ $IPS_MODE -eq 1 ]; then
        mode_flag="--ips"
        echo "[+] Starting miniIDS in IPS mode (active blocking)..."
    else
        echo "[+] Starting miniIDS in IDS mode (passive detection)..."
    fi
    
    cd ..
    ./miniids $interface $mode_flag > /tmp/miniids_test.log 2>&1 &
    MINIIDS_PID=$!
    cd test
    sleep 3
    
    if ! kill -0 $MINIIDS_PID 2>/dev/null; then
        echo "[-] Failed to start miniIDS"
        cat /tmp/miniids_test.log
        exit 1
    fi
    
    echo "[+] MiniIDS started (PID: $MINIIDS_PID)"
}

# Attack functions
attack_directory_traversal() {
    local port=$1
    echo "  [*] Sending directory traversal attack to port $port..."
    (echo -e "GET /../../../etc/passwd HTTP/1.1\r\nHost: $TARGET\r\n\r\n"; sleep 1) | nc -w2 $TARGET $port > /dev/null 2>&1 &
    sleep 2
}

attack_sensitive_file() {
    local port=$1
    local file=$2
    echo "  [*] Attempting access to $file on port $port..."
    (echo -e "GET $file HTTP/1.1\r\nHost: $TARGET\r\n\r\n"; sleep 1) | nc -w2 $TARGET $port > /dev/null 2>&1 &
    sleep 2
}

attack_malware_signature() {
    echo "  [*] Sending malware signature to port 9002..."
    (echo "This payload contains malware signature"; sleep 1) | nc -w2 $TARGET 9002 > /dev/null 2>&1 &
    sleep 2
}

attack_pattern() {
    echo "  [*] Sending attack pattern to port 9003..."
    (echo "Initiating attack vector sequence"; sleep 1) | nc -w2 $TARGET 9003 > /dev/null 2>&1 &
    sleep 2
}

attack_port_scan_syn() {
    local port=$1
    echo "  [*] Performing SYN scan on port $port..."
    if command -v hping3 &> /dev/null; then
        hping3 -S -p $port -c 3 $TARGET 2>/dev/null &
    else
        nc -zv -w1 $TARGET $port 2>&1 | head -3
    fi
    sleep 2
}

attack_port_scan_fin() {
    local port=$1
    echo "  [*] Performing FIN scan on port $port..."
    if command -v hping3 &> /dev/null; then
        hping3 -F -p $port -c 3 $TARGET 2>/dev/null &
    else
        echo "  [!] hping3 not installed, skipping FIN scan"
    fi
    sleep 2
}

attack_normal_http() {
    local port=$1
    echo "  [*] Sending normal HTTP request to port $port..."
    (echo -e "GET /index.html HTTP/1.1\r\nHost: $TARGET\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; sleep 1) | nc -w2 $TARGET $port > /dev/null 2>&1 &
    sleep 2
}

# Display results
show_results() {
    echo ""
    echo "=========================================="
    echo "  Test Results"
    echo "=========================================="
    echo ""
    
    echo "Recent Alerts (last 30):"
    echo "-------------------------------------------"
    tail -30 ../logs/alerts.log 2>/dev/null | grep -v "SYSTEM" | tail -20
    
    echo ""
    echo "IPS Actions:"
    echo "-------------------------------------------"
    tail -30 ../logs/alerts.log 2>/dev/null | grep "IPS"
    
    if [ $IPS_MODE -eq 1 ]; then
        echo ""
        echo "Active Firewall Rules:"
        echo "-------------------------------------------"
        iptables -L MINIIDS -n -v --line-numbers | head -15
    fi
    
    echo ""
    echo "MiniIDS Status:"
    echo "-------------------------------------------"
    tail -15 /tmp/miniids_test.log 2>/dev/null
}

# Main menu
main_menu() {
    clear
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║          MiniIDS/IPS Interactive Test Suite                   ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Configuration:"
    echo "  Target:    $TARGET"
    echo "  Interface: $INTERFACE"
    echo "  Mode:      $([ $IPS_MODE -eq 1 ] && echo 'IPS (Active Blocking)' || echo 'IDS (Passive Detection)')"
    echo "  Status:    $([ ! -z "$MINIIDS_PID" ] && echo 'Running (PID: '$MINIIDS_PID')' || echo 'Not started')"
    echo ""
    echo "────────────────────────────────────────────────────────────────"
    echo "  SETUP"
    echo "────────────────────────────────────────────────────────────────"
    echo "  1) Start servers and miniIDS"
    echo "  2) Show results"
    echo "  3) Show live logs (tail -f)"
    echo ""
    echo "────────────────────────────────────────────────────────────────"
    echo "  INDIVIDUAL ATTACKS"
    echo "────────────────────────────────────────────────────────────────"
    echo "  4) Directory Traversal (port 80)       [DROP]"
    echo "  5) Directory Traversal (port 8080)     [DROP]"
    echo "  6) Sensitive File /etc/passwd (80)     [REJECT]"
    echo "  7) Sensitive File /etc/shadow (8080)   [REJECT]"
    echo "  8) Malware Signature (9002)            [DROP]"
    echo "  9) Attack Pattern (9003)               [DROP]"
    echo "  10) Port Scan - SYN                    [ALERT]"
    echo "  11) Port Scan - FIN                    [REJECT]"
    echo "  12) Normal HTTP Traffic (80)           [ALERT]"
    echo "  13) Normal HTTP Traffic (8080)         [ALERT]"
    echo ""
    echo "────────────────────────────────────────────────────────────────"
    echo "  COMBINED ATTACKS"
    echo "────────────────────────────────────────────────────────────────"
    echo "  14) Run all DROP attacks"
    echo "  15) Run all REJECT attacks"
    echo "  16) Run complete attack suite"
    echo ""
    echo "  0) Exit"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -m|--mode)
            if [ "$2" = "ips" ]; then
                IPS_MODE=1
            elif [ "$2" = "ids" ]; then
                IPS_MODE=0
            else
                echo "ERROR: Invalid mode. Use 'ids' or 'ips'"
                exit 1
            fi
            shift 2
            ;;
        -a|--attack)
            ATTACK_TYPE="$2"
            NON_INTERACTIVE=1
            shift 2
            ;;
        -s|--start)
            AUTO_START=1
            shift
            ;;
        -h|--help)
            echo "╔════════════════════════════════════════════════════════════════════════════╗"
            echo "║              MiniIDS/IPS Attack Testing Suite - Help                      ║"
            echo "╚════════════════════════════════════════════════════════════════════════════╝"
            echo ""
            echo "USAGE:"
            echo "  sudo ./interactive_test.sh [OPTIONS]"
            echo ""
            echo "OPTIONS:"
            echo "  -t, --target <IP>         Target IP address (default: 127.0.0.1)"
            echo "  -i, --interface <IFACE>   Network interface (default: lo)"
            echo "  -m, --mode <MODE>         Mode: ids or ips (default: ids)"
            echo "  -a, --attack <TYPE>       Attack type (see below)"
            echo "  -s, --start               Auto-start servers and miniIDS"
            echo "  -h, --help                Show this help message"
            echo ""
            echo "ATTACK TYPES:"
            echo "  Individual Attacks:"
            echo "    dir-traversal-80        Directory traversal attack on port 80 (DROP)"
            echo "    dir-traversal-8080      Directory traversal attack on port 8080 (DROP)"
            echo "    sensitive-passwd        Access /etc/passwd on port 80 (REJECT)"
            echo "    sensitive-shadow        Access /etc/shadow on port 8080 (REJECT)"
            echo "    malware                 Malware signature on port 9002 (DROP)"
            echo "    attack-pattern          Attack pattern on port 9003 (DROP)"
            echo "    syn-scan                SYN port scan on multiple ports"
            echo "    fin-scan                FIN port scan on multiple ports"
            echo "    http-normal-80          Normal HTTP request on port 80"
            echo "    http-normal-8080        Normal HTTP request on port 8080"
            echo ""
            echo "  Combined Attacks:"
            echo "    all-drop                Run all DROP attacks (traversal + malware + attack)"
            echo "    all-reject              Run all REJECT attacks (sensitive files + scans)"
            echo "    full-suite              Complete attack suite (all attacks)"
            echo ""
            echo "EXAMPLES:"
            echo "  # Run in interactive mode (menu-driven)"
            echo "  sudo ./interactive_test.sh"
            echo ""
            echo "  # Run complete attack suite in IPS mode"
            echo "  sudo ./interactive_test.sh -m ips -a full-suite -s"
            echo ""
            echo "  # Test malware detection against custom target"
            echo "  sudo ./interactive_test.sh -t 192.168.1.10 -m ips -a malware -s"
            echo ""
            echo "  # Run all DROP attacks in IDS mode"
            echo "  sudo ./interactive_test.sh -m ids -a all-drop -s"
            echo ""
            echo "  # Test directory traversal on eth0 interface"
            echo "  sudo ./interactive_test.sh -i eth0 -m ips -a dir-traversal-80 -s"
            echo ""
            echo "MODES:"
            echo "  ids - Detection only (passive, no blocking)"
            echo "  ips - Prevention mode (active blocking with iptables)"
            echo ""
            echo "NOTE:"
            echo "  - Running without parameters starts interactive menu mode"
            echo "  - Use -s flag to automatically start test servers and miniIDS"
            echo "  - IPS mode requires root privileges for iptables management"
            echo ""
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1"
            echo "Run with -h for help"
            exit 1
            ;;
    esac
done

# Execute attack based on parameter
execute_attack() {
    case $ATTACK_TYPE in
        dir-traversal-80)
            attack_directory_traversal 80
            ;;
        dir-traversal-8080)
            attack_directory_traversal 8080
            ;;
        sensitive-passwd)
            attack_sensitive_file 80 "/etc/passwd"
            ;;
        sensitive-shadow)
            attack_sensitive_file 8080 "/etc/shadow"
            ;;
        malware)
            attack_malware_signature
            ;;
        attack-pattern)
            attack_pattern
            ;;
        syn-scan)
            for port in 22 23 80 443 8080; do
                attack_port_scan_syn $port
            done
            ;;
        fin-scan)
            for port in 22 80 443; do
                attack_port_scan_fin $port
            done
            ;;
        http-normal-80)
            attack_normal_http 80
            ;;
        http-normal-8080)
            attack_normal_http 8080
            ;;
        all-drop)
            echo "[*] Running all DROP attacks..."
            attack_directory_traversal 80
            attack_directory_traversal 8080
            attack_malware_signature
            attack_pattern
            ;;
        all-reject)
            echo "[*] Running all REJECT attacks..."
            attack_sensitive_file 80 "/etc/passwd"
            attack_sensitive_file 8080 "/etc/shadow"
            attack_port_scan_fin 22
            attack_port_scan_fin 23
            ;;
        full-suite)
            echo "[*] Running complete attack suite..."
            attack_normal_http 80
            attack_normal_http 8080
            attack_directory_traversal 80
            attack_directory_traversal 8080
            attack_sensitive_file 80 "/etc/passwd"
            attack_sensitive_file 8080 "/etc/shadow"
            attack_malware_signature
            attack_pattern
            for port in 22 23 80 443; do
                attack_port_scan_syn $port
            done
            ;;
        *)
            echo "ERROR: Unknown attack type: $ATTACK_TYPE"
            echo "Run with -h to see available attack types"
            exit 1
            ;;
    esac
}

# Non-interactive mode
if [ $NON_INTERACTIVE -eq 1 ]; then
    echo "=========================================="
    echo "  MiniIDS/IPS Test Suite (Non-Interactive)"
    echo "=========================================="
    echo ""
    echo "Target: $TARGET"
    echo "Interface: $INTERFACE"
    echo "Mode: $([ $IPS_MODE -eq 1 ] && echo 'IPS' || echo 'IDS')"
    echo "Attack: $ATTACK_TYPE"
    echo ""
    
    if [ $AUTO_START -eq 1 ]; then
        start_servers
        start_miniids $INTERFACE
        echo ""
    fi
    
    execute_attack
    
    echo ""
    show_results
    
    read -p "Press Enter to cleanup and exit..."
    exit 0
fi

# Interactive mode
echo "=========================================="
echo "  MiniIDS/IPS Interactive Test Suite"
echo "=========================================="
echo ""
echo "Starting in interactive mode..."
echo "Target: $TARGET"
echo "Interface: $INTERFACE"
echo ""

if [ $AUTO_START -eq 1 ]; then
    start_servers
    start_miniids $INTERFACE
    sleep 2
fi

# Main loop
while true; do
    main_menu
    read -p "Select option: " choice
    
    case $choice in
        1)
            if [ ! -z "$MINIIDS_PID" ]; then
                echo "[!] miniIDS already running. Stop it first (option 0)"
                sleep 2
            else
                start_servers
                start_miniids $INTERFACE
                echo "[+] System ready for testing!"
                sleep 2
            fi
            ;;
        2)
            show_results
            echo ""
            read -p "Press Enter to continue..."
            ;;
        3)
            echo "[*] Showing live logs (Ctrl+C to stop)..."
            echo ""
            tail -f ../logs/alerts.log
            ;;
        4)
            echo "[*] Launching directory traversal attack on port 80..."
            attack_directory_traversal 80
            sleep 1
            ;;
        5)
            echo "[*] Launching directory traversal attack on port 8080..."
            attack_directory_traversal 8080
            sleep 1
            ;;
        6)
            echo "[*] Attempting sensitive file access..."
            attack_sensitive_file 80 "/etc/passwd"
            sleep 1
            ;;
        7)
            echo "[*] Attempting sensitive file access..."
            attack_sensitive_file 8080 "/etc/shadow"
            sleep 1
            ;;
        8)
            echo "[*] Sending malware signature..."
            attack_malware_signature
            sleep 1
            ;;
        9)
            echo "[*] Sending attack pattern..."
            attack_pattern
            sleep 1
            ;;
        10)
            echo "[*] Running SYN port scans..."
            for port in 22 23 80 443 8080; do
                attack_port_scan_syn $port
            done
            sleep 1
            ;;
        11)
            echo "[*] Running FIN port scans..."
            for port in 22 80 443; do
                attack_port_scan_fin $port
            done
            sleep 1
            ;;
        12)
            echo "[*] Sending normal HTTP traffic..."
            attack_normal_http 80
            sleep 1
            ;;
        13)
            echo "[*] Sending normal HTTP traffic..."
            attack_normal_http 8080
            sleep 1
            ;;
        14)
            echo "[*] Running all DROP attacks..."
            attack_directory_traversal 80
            attack_directory_traversal 8080
            attack_malware_signature
            attack_pattern
            echo "[+] DROP attacks complete"
            sleep 2
            ;;
        15)
            echo "[*] Running all REJECT attacks..."
            attack_sensitive_file 80 "/etc/passwd"
            attack_sensitive_file 8080 "/etc/shadow"
            attack_port_scan_fin 22
            attack_port_scan_fin 23
            echo "[+] REJECT attacks complete"
            sleep 2
            ;;
        16)
            echo "[*] Running complete attack suite..."
            echo ""
            echo "Phase 1: Normal traffic baseline..."
            attack_normal_http 80
            attack_normal_http 8080
            
            echo "Phase 2: Directory traversal attacks..."
            attack_directory_traversal 80
            attack_directory_traversal 8080
            
            echo "Phase 3: Sensitive file access..."
            attack_sensitive_file 80 "/etc/passwd"
            attack_sensitive_file 8080 "/etc/shadow"
            
            echo "Phase 4: Malware and attack patterns..."
            attack_malware_signature
            attack_pattern
            
            echo "Phase 5: Port scanning..."
            for port in 22 23 80 443; do
                attack_port_scan_syn $port
            done
            
            echo ""
            echo "[+] Complete attack suite finished"
            sleep 2
            ;;
        0)
            echo "[+] Exiting..."
            exit 0
            ;;
        *)
            echo "[!] Invalid option"
            sleep 1
            ;;
    esac
done
