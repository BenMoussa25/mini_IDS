#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rules.h"
#include "packet.h"

// TCP flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

Rule rules[MAX_RULES];
int rule_count = 0;

int load_rules(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("[-] Cannot open rules file: %s\n", filename);
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), f) && rule_count < MAX_RULES) {
        if (line[0] == '#' || line[0] == '\n') continue;

        Rule *r = &rules[rule_count];
        char pattern_type[16], pattern[MAX_PATTERN];

        // alert tcp any any -> any 80 (content:"../.."; msg:"Directory Traversal";)
        int n = sscanf(line, "%7s %7s %31s %*s -> %31s %d (%15[^:]:\"%255[^\"]\"; msg:\"%255[^\"]\";",
                       r->action, r->proto, r->src_ip, r->dst_ip, &r->dst_port,
                       pattern_type, pattern, r->msg);

        if (n < 7) continue;

        strcpy(r->pattern_type, pattern_type);
        strcpy(r->pattern, pattern);
        if (r->dst_port == 0) r->dst_port = -1;
        
        // Set action type
        if (strcmp(r->action, "drop") == 0) {
            r->action_type = RULE_ACTION_DROP;
        } else if (strcmp(r->action, "reject") == 0) {
            r->action_type = RULE_ACTION_REJECT;
        } else {
            r->action_type = RULE_ACTION_ALERT;
        }

        rule_count++;
    }
    fclose(f);
    return 0;
}

int ip_match(const char *rule_ip, const char *pkt_ip) {
    return strcmp(rule_ip, "any") == 0 || strcmp(rule_ip, pkt_ip) == 0;
}

int match_rule(const PacketInfo *pkt, const Rule *rule) {
    // Accept alert, drop, or reject actions
    if (strcmp(rule->action, "alert") != 0 && 
        strcmp(rule->action, "drop") != 0 && 
        strcmp(rule->action, "reject") != 0) return 0;
    if (strcmp(rule->proto, "any") != 0 && strcasecmp(rule->proto, pkt->protocol == IPPROTO_TCP ? "tcp" :
            pkt->protocol == IPPROTO_UDP ? "udp" : "icmp") != 0) return 0;

    if (!ip_match(rule->src_ip, pkt->src_ip)) return 0;
    if (!ip_match(rule->dst_ip, pkt->dst_ip)) return 0;
    if (rule->dst_port != -1 && rule->dst_port != pkt->dst_port) return 0;

    if (strcmp(rule->pattern_type, "content") == 0 || strcmp(rule->pattern_type, "PAYLOAD") == 0) {
        if (pkt->payload && pkt->payload_len > 0) {
            if (strstr((char*)pkt->payload, rule->pattern)) return 1;
        }
    }
    else if (strcmp(rule->pattern_type, "flags") == 0 || strcmp(rule->pattern_type, "FLAG") == 0) {
        if (pkt->protocol == IPPROTO_TCP) {
            if (strstr(rule->pattern, "SYN") && (pkt->tcp_flags & TH_SYN)) return 1;
            if (strstr(rule->pattern, "FIN") && (pkt->tcp_flags & TH_FIN)) return 1;
            if (strstr(rule->pattern, "PSH") && (pkt->tcp_flags & TH_PUSH)) return 1;
            if (strstr(rule->pattern, "URG") && (pkt->tcp_flags & TH_URG)) return 1;
            if (strstr(rule->pattern, "ACK") && (pkt->tcp_flags & TH_ACK)) return 1;
        }
    }
    return 0;
}