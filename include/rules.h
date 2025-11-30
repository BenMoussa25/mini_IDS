#ifndef RULES_H
#define RULES_H

#include "packet.h"

#define MAX_RULES 100
#define MAX_PATTERN 256

typedef struct {
    char action[8];        // alert
    char proto[8];         // tcp, udp, icmp, any
    char src_ip[32];       // any or IP
    char dst_ip[32];
    int dst_port;          // -1 = any
    char pattern_type[16]; // FLAG, PAYLOAD, SIZE
    char pattern[MAX_PATTERN];
    char msg[256];
} Rule;

extern Rule rules[MAX_RULES];
extern int rule_count;

int load_rules(const char *filename);
int match_rule(const PacketInfo *pkt, const Rule *rule);

#endif