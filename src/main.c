#include <pcap.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include "packet.h"
#include "rules.h"
#include "ips.h"
#include "utils.h"

static pcap_t *global_handle = NULL;
static char interface_name[32] = "eth0";

void cleanup_handler(int signum) {
    (void)signum;
    log_event("Shutting down miniIDS");
    
    if (get_ips_mode() == IPS_MODE_IPS) {
        cleanup_ips();
    }
    
    if (global_handle) {
        pcap_close(global_handle);
    }
    
    exit(0);
}

int main(int argc, char *argv[]) {
    char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int ips_mode = 0;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ips") == 0 || strcmp(argv[i], "-p") == 0) {
            ips_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [interface] [--ips]\n", argv[0]);
            printf("  interface    Network interface to monitor (default: eth0)\n");
            printf("  --ips, -p    Enable IPS mode (active prevention)\n");
            printf("  --help, -h   Show this help message\n");
            return 0;
        } else {
            dev = argv[i];
        }
    }
    
    strncpy(interface_name, dev, sizeof(interface_name) - 1);

    log_event("MiniIDS v1.1 starting on interface: %s", dev);
    
    // Set IPS mode
    if (ips_mode) {
        set_ips_mode(IPS_MODE_IPS);
        log_event("IPS Mode: ACTIVE PREVENTION enabled");
        if (init_ips(dev) != 0) {
            fprintf(stderr, "[-] Failed to initialize IPS mode\n");
            fprintf(stderr, "[-] Make sure you have root privileges and iptables installed\n");
            return 1;
        }
        log_event("IPS initialized successfully");
    } else {
        set_ips_mode(IPS_MODE_IDS);
        log_event("IDS Mode: DETECTION ONLY (passive)");
    }
    
    // Setup signal handlers
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    if (load_rules("rules/rules.conf") < 0) {
        return 1;
    }
    log_event("Loaded %d detection rules", rule_count);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "[-] %s\n", errbuf);
        return 1;
    }

    // Check data link type
    int datalink = pcap_datalink(handle);
    log_event("Data link type: %s", pcap_datalink_val_to_name(datalink));

    struct bpf_program fp;
    char filter[] = "tcp or udp or icmp";
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[-] Filter error: %s\n", pcap_geterr(handle));
    }

    log_event("Packet capture started - Press Ctrl+C to stop");
    printf("\n");
    
    global_handle = handle;
    pcap_loop(handle, 0, process_packet, NULL);

    cleanup_handler(0);
    return 0;
}