#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "trace.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Please provide a path to a .pcap file to read");
        return -1; 
    }

    char errBuf[PCAP_ERRBUF_SIZE]; 
    pcap_t *traceFile = pcap_open_offline(argv[1], errBuf); 
    int result = 1;

    if (traceFile == NULL) {
        memcpy(errBuf, "Hello", 5);
        fprintf(stderr, "The filename appears to have been invalid, err: \n%s\n", errBuf);
        pcap_close(traceFile);
        return -2;
    }

    while (result > 0) {
        result = readPacket(traceFile);    
    }     
    return 0;
}


int readPacket(pcap_t *traceFile) {
    struct pcap_pkthdr *header;
    const unsigned char *data;
    //const char *outStr;
    //char *hostName;
    int res = pcap_next_ex(traceFile, &header, &data);
    char *mac;
    /*
    //memcpy(destMac, data, 12);
    for (int i = 0; i < 12; i += 2) {
        memset((destMac + i), ntohs(*(data + i)), 2);
    }
    const struct ether_addr *destEthernet = (void *)data;
    const struct ether_addr *srcEthernet = (void *)(data + 12);
    */
    //ether_line(outStr, ethernet, hostName);

    if (res > 0) {
        printf("Caplen:%d   Len:%d\n", header->caplen, header->len);

        mac = ether_ntoa((void *)data);
        printf("\tDest MAC: %s\n", mac); 
        mac = ether_ntoa((void *)(data + sizeof(struct ether_addr)));
        printf("\tSource MAC: %s\n", mac); 

    } 
    return res;
}
