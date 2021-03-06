#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "trace.h"
#include "checksum.h"


#define IP4TYPE 0x0800
#define ARPTYPE 0x0806
#define ICMPPROTOCOL 0x01
#define UDPPROTOCOL 0x11
#define TCPPROTOCOL 0x06
#define DNSPORT 53 
#define HTTPPORT 80 

int main(int argc, char **argv) {
    int packetNum = 1;

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
        result = readPacket(traceFile, packetNum++);
    }
    return 0;
}


int readPacket(pcap_t *traceFile, int num) {
    struct pcap_pkthdr *header;
    const unsigned char *data;
    int res = pcap_next_ex(traceFile, &header, &data);
    char *mac;
    short etherType;

    if (res > 0) {
        char postEther[1540];
        printf("Packet number: %d  Packet Len: %d\n\n", num, header->len);
        printf("\tEthernet Header\n");

        mac = ether_ntoa((void *)data);
        printf("\t\tDest MAC: %s\n", mac); 

        mac = ether_ntoa((void *)(data + sizeof(struct ether_addr)));
        printf("\t\tSource MAC: %s\n", mac); 

        memcpy(&etherType, (data + 2 * sizeof(struct ether_addr)), 2);
        etherType = ntohs(etherType);
        memcpy(postEther, data + (2 * sizeof(struct ether_addr) + 2), 
         header->len - (2 * sizeof(struct ether_addr) + 2)); 

        if (etherType == ARPTYPE) {
            printf("\t\tType: ARP\n\n");
            processARP(postEther);
        }
        else if (etherType == IP4TYPE) {
            printf("\t\tType: IP\n\n");
            processIP(postEther);
        }
        else {
            printf("\t\tType: Unknown\n\n");
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

    printf("\tARP header\n");

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
    printf("\t\tTarget IP: %s\n\n", inet_ntoa(TPA));
}

void processIP(char *packet) {
    uint8_t ver_IHL;
    uint8_t DSCP_ECN;
    uint16_t totalLen;
    uint8_t ttl;
    uint8_t protocol; 
    uint16_t checkSum;
    uint16_t calcCheckSum;

    char *packetForCheck = packet;

    struct in_addr sender;
    struct in_addr dest;

    memcpy(&ver_IHL, packet++, 1); 
    memcpy(&DSCP_ECN, packet++, 1);
    memcpy(&totalLen, packet, 2);
    totalLen = ntohs(totalLen);
    packet += 6;

    memcpy(&ttl, packet++, 1);
    memcpy(&protocol, packet++, 1);

    memcpy(&checkSum, packet, 2);
    calcCheckSum = in_cksum((unsigned short *)packetForCheck, (ver_IHL & 0x0F) * 4);
    checkSum = ntohs(checkSum);
    calcCheckSum = ntohs(calcCheckSum);

    packet += 2;

    memcpy(&(sender.s_addr), packet, 4);
    packet += 4;
    memcpy(&(dest.s_addr), packet, 4);
    packet += 4;

    printf("\tIP Header\n");
    printf("\t\tIP Version: %hu\n", (ver_IHL & 0xF0) >> 4);
    printf("\t\tHeader Len (bytes): %hu\n", (ver_IHL & 0x0F) * 4);
    if ((ver_IHL & 0x0F) * 4 > 20) {
        packet += ((ver_IHL & 0x0F) * 4 - 20);
    }

    printf("\t\tTOS subfields:\n");
    printf("\t\t   Diffserv bits: %hu\n", (DSCP_ECN) >> 2);
    printf("\t\t   ECN bits: %hu\n", DSCP_ECN & 0x03);
    
    printf("\t\tTTL: %hu\n", ttl);

    if (protocol == ICMPPROTOCOL) { 
        printf("\t\tProtocol: ICMP\n");
    }
    else if (protocol == UDPPROTOCOL) { 
        printf("\t\tProtocol: UDP\n");
    }
    else if(protocol == TCPPROTOCOL) {
        printf("\t\tProtocol: TCP\n");
    }
    else {
        printf("\t\tProtocol: Unknown\n");
    }

    if (calcCheckSum == 0x0000) {
        printf("\t\tChecksum: Correct (0x%04x)\n", checkSum);
    }
    else {
        printf("\t\tChecksum: Incorrect (0x%04x)\n", checkSum);
    }

    printf("\t\tSender IP: %s\n", inet_ntoa(sender)); 
    printf("\t\tDest IP: %s\n\n", inet_ntoa(dest)); 

    if (protocol == ICMPPROTOCOL) { 
        processICMP(packet);
    }
    if (protocol == UDPPROTOCOL) { 
        processUDP(packet);
    }
    else if(protocol == TCPPROTOCOL) {
        processTCP(packet, totalLen - (ver_IHL & 0x0F) * 4, &sender, &dest);
    }
}

void processICMP(char *packet) {
    uint8_t type;
    memcpy(&type, packet, 1);
    
    printf("\tICMP Header\n"); 
    if (type == 0) {
        printf("\t\tType: Reply\n\n");
    }
    else if (type == 8) {
        printf("\t\tType: Request\n\n");
    }
    else {
        printf("\t\tType: %hu\n\n", type);
    }
}

void processUDP(char *packet) {
    uint16_t src, dest, len, chksum;

    memcpy(&src, packet, 2);
    src = ntohs(src);
    packet += 2;
    memcpy(&dest, packet, 2);
    dest = ntohs(dest);
    packet += 2;
    memcpy(&len, packet, 2);
    packet += 2;
    memcpy(&chksum, packet, 2);
    packet += 2;

    printf("\tUDP Header\n");

    if (src == DNSPORT) 
        printf("\t\tSource Port:  DNS\n");
    else if (src == HTTPPORT)
        printf("\t\tSource Port:  HTTP\n");
    else
        printf("\t\tSource Port:  %u\n", src);

    if (dest == DNSPORT) 
        printf("\t\tDest Port:  DNS\n\n");
    else if (dest == HTTPPORT)
        printf("\t\tDest Port:  HTTP\n");
    else
        printf("\t\tDest Port:  %u\n\n", dest);
}

void processTCP(char *packet, uint16_t len, 
 struct in_addr *source, struct in_addr *destination) {
    char *checkSumHandle = malloc(len + 12);
    createPseudoHeader(&checkSumHandle, packet, len, &(source->s_addr), &(destination->s_addr));
    uint16_t checksum = in_cksum((unsigned short *)checkSumHandle, len + 12);
    checksum = htons(checksum);
    free(checkSumHandle);
    uint8_t  offset, flags;
    uint16_t chkField, src, dest, winSize;
    uint32_t seqNum, ackNum;

    memcpy(&src, packet, 2);
    src = ntohs(src);
    packet += 2;
    memcpy(&dest, packet, 2);
    dest = ntohs(dest);
    packet += 2;
    memcpy(&seqNum, packet, 4);
    seqNum = ntohl(seqNum);
    packet += 4;
    memcpy(&ackNum, packet, 4);
    ackNum = ntohl(ackNum);
    packet += 4;
    memcpy(&offset, packet, 1);//offset is just the top 4 bits of this
    packet += 1;
    memcpy(&flags, packet, 1);
    packet += 1;
    memcpy(&winSize, packet, 2);
    winSize = ntohs(winSize);
    packet += 2;
    memcpy(&chkField, packet, 2);
    chkField = ntohs(chkField);
    packet += 2;
     
    printf("\tTCP Header\n");

    if (src == DNSPORT) 
        printf("\t\tSource Port:  DNS\n");
    else if (src == HTTPPORT)
        printf("\t\tSource Port:  HTTP\n");
    else
        printf("\t\tSource Port:  %u\n", src);

    if (dest == DNSPORT) 
        printf("\t\tDest Port:  DNS\n\n");
    else if (dest == HTTPPORT)
        printf("\t\tDest Port:  HTTP\n");
    else
        printf("\t\tDest Port:  %u\n\n", dest);

    printf("\t\tSequence Number: %u\n", seqNum);
    printf("\t\tACK Number: %u\n", ackNum);
    printf("\t\tData Offset (bytes): %hu\n", (offset >> 4) * 4);

    if (flags & 0x02)
        printf("\t\tSYN Flag: Yes\n");
    else 
        printf("\t\tSYN Flag: No\n");

    if (flags & 0x04)
        printf("\t\tRST Flag: Yes\n");
    else 
        printf("\t\tRST Flag: No\n");

    if (flags & 0x01)
        printf("\t\tFIN Flag: Yes\n");
    else 
        printf("\t\tFIN Flag: No\n");

    if (flags & 0x10)
        printf("\t\tACK Flag: Yes\n");
    else 
        printf("\t\tACK Flag: No\n");
         
    printf("\t\tWindow Size: %u\n", winSize);
    if (checksum == 0) {
        printf("\t\tChecksum: Correct (0x%04x)\n\n", chkField); 
    }
    else {
        printf("\t\tChecksum: Incorrect (0x%04x)\n\n", chkField); 
    }

}
         
void createPseudoHeader(char **buffer, char *packet, 
 uint16_t len, uint32_t *src, uint32_t *dest) {
    uint16_t zero = 0x00;
    uint8_t six = 6; 

    memcpy(*buffer, src, 4);
    memcpy((*buffer) + 4, dest, 4);
    
    memcpy((*buffer) + 8, &zero, 1);
    memcpy((*buffer) + 9, &six, 1);
    len = htons(len);
    memcpy((*buffer) + 10, &(len), 2);
    
    len = ntohs(len);
    memcpy((*buffer) + 12, packet, len);
}

