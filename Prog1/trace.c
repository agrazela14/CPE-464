#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "trace.h"

#define IP4TYPE 0x0800
#define ARPTYPE 0x0806

/***************
* REMINDER:
* Bytes are 8 bits, you fool 
***************/

int main(int argc, char **argv) {
    int packetNum = 1;

    //printf("%d %d\n", sizeof(struct ether_addr), sizeof(struct in_addr));
    if (argc < 2) {
        fprintf(stderr, "Please provide a path to a .pcap file to read");
        return -1; 
    }

    char errBuf[PCAP_ERRBUF_SIZE]; 
    pcap_t *traceFile = pcap_open_offline(argv[1], errBuf); 
    int result = 1;

    if (traceFile == NULL) {
        fprintf(stderr, "The filename appears to have been invalid, error:\n%s\n", errBuf);
        pcap_close(traceFile);
        return -2;
    }

    while (result > 0) {
        printf("Packet Number %d ", packetNum++);
        result = readPacket(traceFile);
    } 
    return 0;
}


int readPacket(pcap_t *traceFile) {
    struct pcap_pkthdr *header;
    const unsigned char *data;
    int res = pcap_next_ex(traceFile, &header, &data);
    char *mac;
    short etherType;

    if (res > 0) {
        char *postEther;
        printf("  Packet Len: %d\n\n", header->len);

        printf("\tEthernet Header\n");
        mac = ether_ntoa((void *)data);
        printf("\t\tDest MAC: %s\n", mac); 
        mac = ether_ntoa((void *)(data + sizeof(struct ether_addr)));
        printf("\t\tSource MAC: %s\n", mac); 
        memcpy(&etherType, (data + 2 * sizeof(struct ether_addr)), 2);
        etherType = ntohs(etherType);
        memcpy(postEther, data + (2 * sizeof(struct ether_addr) + 2), header->len - (2 * sizeof(struct ether_addr) + 2)); 
        if (etherType == ARPTYPE) {
            printf("\t\tType: ARP\n\n");
            processARP(postEther);
        }
        else if (etherType == IP4TYPE) {
            printf("\t\tType: IP\n\n");
            processIP(postEther);
        }
    } 
    return res;
}

void processARP(char *packet) {
    uint16_t operation; 

    struct ether_addr SHA;
    struct in_addr SPA;

    struct ether_addr THA;
    struct in_addr TPA;

    memcpy(&operation, packet += 6, 2);
    operation = ntohs(operation);
    memcpy(SHA.ether_addr_octet, packet += 2, sizeof(struct ether_addr));
    memcpy(&(SPA.s_addr), packet += sizeof(struct ether_addr), sizeof(struct in_addr));

    memcpy(THA.ether_addr_octet, packet += sizeof(struct in_addr), sizeof(struct ether_addr));
    memcpy(&(TPA.s_addr), packet += sizeof(struct ether_addr), sizeof(struct in_addr));

    printf("\tARP Header\n");

    if (operation == 1) {
        printf("\t\tOpcode: Request\n");
    }
    else if (operation == 2) {
        printf("\t\tOpcode: Reply\n");
    }
    else {
        printf("\t\tOpcode: %hu\n", operation);
    }
    printf("\t\tSender MAC: %s\n", ether_ntoa(&SHA));
    printf("\t\tSender IP: %s\n", inet_ntoa(SPA));
    printf("\t\tTarget MAC: %s\n", ether_ntoa(&THA));
    printf("\t\tTarget IP: %s\n", inet_ntoa(TPA));
}

void processIP(char *packet) {

}
