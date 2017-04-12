#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include "trace.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Please provide a path to a .pcap file to read");
        return -1; 
    }

    char *errBuf = malloc(PCAP_ERRBUF_SIZE); 
    pcap_t *traceFile = pcap_open_offline(argv[1], errBuf); 
    int result = 1;

    if (traceFile == NULL) {
        memcpy(errBuf, "Hello", 5);
        fprintf(stderr, "The filename appears to have been invalid, err: \n%s\n", errBuf);
        pcap_close(traceFile);
        return -2;
    }
    free(errBuf);

    while (result > 0) {
        result = readPacket(traceFile);    
    }     
    return 0;
}


int readPacket(pcap_t *traceFile) {
    struct pcap_pkthdr *header;// = malloc(sizeof(struct pcap_pkthdr));
    const unsigned char *data;// = malloc(4096);
    int res = pcap_next_ex(traceFile, &header, &data);

    if (res > 0) {
        printf("Caplen:%d   Len:%d\n", header->caplen, header->len);
        printf("%s\n\n", data); 
    } 
    //free(header);
    //free(data);
    return res;
}
