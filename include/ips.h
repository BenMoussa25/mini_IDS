#ifndef IPS_H
#define IPS_H

#include "packet.h"
#include "rules.h"

typedef enum {
    IPS_MODE_IDS,      // Detection only (default)
    IPS_MODE_IPS       // Prevention (drop/reject)
} ips_mode_t;

typedef enum {
    IPS_ACTION_ALERT,  // Just alert
    IPS_ACTION_DROP,   // Silently drop packet
    IPS_ACTION_REJECT  // Reject with RST/ICMP unreachable
} ips_action_t;

// Global IPS mode
extern ips_mode_t current_ips_mode;

// Initialize IPS functionality
int init_ips(const char *interface);

// Block an IP address
int block_ip(const char *ip_address);

// Unblock an IP address
int unblock_ip(const char *ip_address);

// Drop packet (using iptables)
int drop_packet(const PacketInfo *pkt);

// Reject packet (send RST or ICMP unreachable)
int reject_packet(const PacketInfo *pkt);

// Check if IP is blocked
int is_ip_blocked(const char *ip_address);

// Cleanup IPS rules
void cleanup_ips(void);

// Get current mode
ips_mode_t get_ips_mode(void);

// Set IPS mode
void set_ips_mode(ips_mode_t mode);

#endif
