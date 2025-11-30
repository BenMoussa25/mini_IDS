#ifndef PACKET_H
#define PACKET_H

#include <sys/types.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <stdint.h>

typedef struct {
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;  // IPPROTO_TCP, UDP, ICMP
    const u_char *payload;
    int payload_len;
    uint8_t tcp_flags;
    time_t timestamp;
} PacketInfo;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif