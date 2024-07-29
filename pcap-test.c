#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "libnet-headers.h"
#include <netinet/ether.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        struct libnet_ethernet_hdr* ethernet = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ipv4 = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
        unsigned char * payload = (unsigned char *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));

        int payload_size = header->len - (sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
        if (payload_size > 20) {
            payload_size = 20;
        }

        u_int8_t *ether_smac = ether_ntoa((const struct ether_addr *) &ethernet->ether_shost);
        u_int8_t *ether_dmac = ether_ntoa((const struct ether_addr *) &ethernet->ether_dhost);
        char *ip_src = inet_ntoa(ipv4->ip_src);
        char *ip_dst = inet_ntoa(ipv4->ip_dst);
        u_int16_t tcp_sport = ntohs(tcp->th_sport);
        u_int16_t tcp_dport = ntohs(tcp->th_dport);

        printf("Ethernet: src mac=%s, dst mac=%s\n", ether_smac, ether_dmac);
        printf("IP: src ip=%s, dst ip=%s\n", ip_src, ip_dst);
        printf("TCP: src port=%d, dst port=%d\n", tcp_sport, tcp_dport);
        printf("Payload (Hex): ");
        for (int i = 0; i < payload_size; i++) {
            printf("%02X ", payload[i]);
        }
        printf("\n\n");
	}

	pcap_close(pcap);
}
