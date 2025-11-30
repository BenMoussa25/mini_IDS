#include <pcap.h>
#include "packet.h"
#include "rules.h"

int main(int argc, char *argv[]) {
    char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc > 1) dev = argv[1];

    printf("[+] MiniIDS v1.0 - Starting on %s\n", dev);

    if (load_rules("rules/rules.conf") < 0) {
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "[-] %s\n", errbuf);
        return 1;
    }

    // Check data link type
    int datalink = pcap_datalink(handle);
    printf("[+] Data link type: %d (%s)\n", datalink, pcap_datalink_val_to_name(datalink));

    struct bpf_program fp;
    char filter[] = "tcp or udp or icmp";
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[-] Filter error: %s\n", pcap_geterr(handle));
    }

    printf("[+] Listening for attacks... Press Ctrl+C to stop.\n\n");
    pcap_loop(handle, 0, process_packet, NULL);

    pcap_close(handle);
    return 0;
}