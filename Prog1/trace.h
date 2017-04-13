#ifndef TRACE_H
#define TRACE_H

int readPacket(pcap_t *traceFile, int num);
void processARP(char *packet);
void processIP(char *packet);

#endif
