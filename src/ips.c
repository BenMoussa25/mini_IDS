#include "ips.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define MAX_BLOCKED_IPS 1000

// Global variables
ips_mode_t current_ips_mode = IPS_MODE_IDS;
static char blocked_ips[MAX_BLOCKED_IPS][16];
static int blocked_count = 0;
static char interface_name[32] = "";

ips_mode_t get_ips_mode(void) {
    return current_ips_mode;
}

void set_ips_mode(ips_mode_t mode) {
    current_ips_mode = mode;
}

int init_ips(const char *interface) {
    strncpy(interface_name, interface, sizeof(interface_name) - 1);
    
    // Create custom iptables chain for miniIDS
    system("iptables -N MINIIDS 2>/dev/null");
    system("iptables -F MINIIDS 2>/dev/null");
    
    // Insert chain into INPUT
    system("iptables -C INPUT -j MINIIDS 2>/dev/null || iptables -I INPUT -j MINIIDS");
    
    return 0;
}

int is_ip_blocked(const char *ip_address) {
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i], ip_address) == 0) {
            return 1;
        }
    }
    return 0;
}

int block_ip(const char *ip_address) {
    if (blocked_count >= MAX_BLOCKED_IPS) {
        fprintf(stderr, "[-] Maximum blocked IPs reached\n");
        return -1;
    }
    
    // Check if already blocked
    if (is_ip_blocked(ip_address)) {
        return 0;
    }
    
    // Add to blocked list
    strncpy(blocked_ips[blocked_count], ip_address, 15);
    blocked_ips[blocked_count][15] = '\0';
    blocked_count++;
    
    // Add iptables rule to drop packets from this IP
    char cmd[256];
    snprintf(cmd, sizeof(cmd), 
             "iptables -A MINIIDS -s %s -j DROP 2>/dev/null", 
             ip_address);
    
    int ret = system(cmd);
    if (ret == 0) {
        log_action("BLOCKED", ip_address);
    }
    
    return ret;
}

int unblock_ip(const char *ip_address) {
    // Remove from blocked list
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i], ip_address) == 0) {
            // Shift remaining entries
            for (int j = i; j < blocked_count - 1; j++) {
                strcpy(blocked_ips[j], blocked_ips[j + 1]);
            }
            blocked_count--;
            break;
        }
    }
    
    // Remove iptables rule
    char cmd[256];
    snprintf(cmd, sizeof(cmd), 
             "iptables -D MINIIDS -s %s -j DROP 2>/dev/null", 
             ip_address);
    
    int ret = system(cmd);
    if (ret == 0) {
        log_action("UNBLOCKED", ip_address);
    }
    
    return ret;
}

int drop_packet(const PacketInfo *pkt) {
    // In IPS mode, block the source IP
    if (current_ips_mode == IPS_MODE_IPS) {
        return block_ip(pkt->src_ip);
    }
    return 0;
}

int reject_packet(const PacketInfo *pkt) {
    if (current_ips_mode == IPS_MODE_IPS) {
        // Check if already blocked
        if (!is_ip_blocked(pkt->src_ip)) {
            // Add to blocked list
            if (blocked_count < MAX_BLOCKED_IPS) {
                size_t len = strlen(pkt->src_ip);
                if (len > 15) len = 15;
                memcpy(blocked_ips[blocked_count], pkt->src_ip, len);
                blocked_ips[blocked_count][len] = '\0';
                blocked_count++;
            }
            
            // Send TCP RST or ICMP unreachable
            char cmd[512];
            if (pkt->protocol == IPPROTO_TCP) {
                snprintf(cmd, sizeof(cmd),
                         "iptables -A MINIIDS -s %s -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null",
                         pkt->src_ip);
            } else {
                snprintf(cmd, sizeof(cmd),
                         "iptables -A MINIIDS -s %s -j REJECT --reject-with icmp-host-unreachable 2>/dev/null",
                         pkt->src_ip);
            }
            
            int ret = system(cmd);
            if (ret == 0) {
                log_action("REJECTED", pkt->src_ip);
            }
            return ret;
        }
    }
    return 0;
}

void cleanup_ips(void) {
    // Flush and remove miniIDS chain
    system("iptables -D INPUT -j MINIIDS 2>/dev/null");
    system("iptables -F MINIIDS 2>/dev/null");
    system("iptables -X MINIIDS 2>/dev/null");
    
    log_event("IPS firewall rules cleaned up");
}
