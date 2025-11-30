#include "packet.h"
#include "detect.h"
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;  // Unused parameter
    PacketInfo pkt = {0};
    
    static int packet_count = 0;
    packet_count++;
    
    if (header->len < 34) return;  // Too small for Ethernet + IP + some data
    
    // Ethernet header is 14 bytes
    const uint8_t *ip_start = packet + 14;
    
    struct iphdr *iph = (struct iphdr*)(ip_start);
    
    // Verify this is actually an IP packet (version should be 4)
    if ((iph->version) != 4) {
        return;  // Not IPv4
    }

    inet_ntop(AF_INET, &(iph->saddr), pkt.src_ip, sizeof(pkt.src_ip));
    inet_ntop(AF_INET, &(iph->daddr), pkt.dst_ip, sizeof(pkt.dst_ip));
    pkt.protocol = iph->protocol;
    pkt.timestamp = header->ts.tv_sec;

    unsigned int ip_header_len = iph->ihl * 4;

    if (pkt.protocol == IPPROTO_TCP) {
        // Parse TCP header manually to avoid struct issues
        const uint8_t *tcp_start = ip_start + ip_header_len;
        pkt.src_port = ntohs(*(uint16_t*)(tcp_start));
        pkt.dst_port = ntohs(*(uint16_t*)(tcp_start + 2));
        
        // Extract TCP flags - byte 13 of TCP header
        pkt.tcp_flags = *(tcp_start + 13);

        // TCP header length from data offset field (byte 12, upper 4 bits)
        int tcp_header_len = ((*(tcp_start + 12)) >> 4) * 4;
        pkt.payload = ip_start + ip_header_len + tcp_header_len;
        pkt.payload_len = ntohs(iph->tot_len) - (ip_header_len + tcp_header_len);
    }
    else if (pkt.protocol == IPPROTO_UDP) {
        // Parse UDP header manually
        const uint8_t *udp_start = ip_start + ip_header_len;
        pkt.src_port = ntohs(*(uint16_t*)(udp_start));
        pkt.dst_port = ntohs(*(uint16_t*)(udp_start + 2));
        uint16_t udp_len = ntohs(*(uint16_t*)(udp_start + 4));
        
        pkt.payload = ip_start + ip_header_len + 8;
        pkt.payload_len = udp_len - 8;
    }
    else if (pkt.protocol == IPPROTO_ICMP) {
        pkt.src_port = pkt.dst_port = 0;
        pkt.payload = ip_start + ip_header_len + 8;
        pkt.payload_len = ntohs(iph->tot_len) - (ip_header_len + 8);
    }

    detect_attacks(&pkt);
}