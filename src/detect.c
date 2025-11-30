#include "detect.h"
#include "rules.h"
#include "utils.h"

// TCP flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

void detect_attacks(const PacketInfo *pkt) {
    for (int i = 0; i < rule_count; i++) {
        if (match_rule(pkt, &rules[i])) {
            log_alert("%s | %s:%d → %s:%d [%s]", 
                      rules[i].msg, pkt->src_ip, pkt->src_port,
                      pkt->dst_ip, pkt->dst_port, 
                      pkt->protocol == IPPROTO_TCP ? "TCP" : pkt->protocol == IPPROTO_UDP ? "UDP" : "ICMP");
        }
    }

    // Bonus: Heuristic detections (optional)
    if (pkt->protocol == IPPROTO_TCP) {
        if (pkt->tcp_flags == (TH_FIN | TH_PUSH | TH_URG)) {
            log_alert("XMAS Scan detected! %s → %s", pkt->src_ip, pkt->dst_ip);
        }
        if (pkt->tcp_flags == 0) {
            log_alert("NULL Scan detected! %s → %s", pkt->src_ip, pkt->dst_ip);
        }
    }
}