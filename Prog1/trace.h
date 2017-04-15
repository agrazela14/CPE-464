#ifndef TRACE_H
#define TRACE_H

int readPacket(pcap_t *traceFile, int num);
void processARP(char *packet);
void processIP(char *packet);
void processUDP(char *packet);
void processICMP(char *packet);
void processTCP(char *packet, uint16_t len, 
 struct in_addr *src, struct in_addr *dest);
void createPseudoHeader(char **buffer, char *packet, uint16_t len, 
 uint32_t *src, uint32_t *dest);
uint16_t ipCheckSumCalc(char *packet);

#endif
