/* Server side - UDP Code                   */
/* By Hugh Smith    4/1/2017    */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "networks.h"
#include "cpe464.h"

#define MAXBUF 255
#define HEADER_LEN 10

typedef enum State STATE;

enum State {
    START, FILENAME, SEND_DATA, WAIT_FOR_ACK, WAIT_FOR_EOF_ACK, SHUTDOWN, DONE
};


void processClient(int socketNum);

void printClientIP(struct sockaddr_in6 * client);

int checkArgs(int argc, char *argv[], double *error);

void stateLoop(struct sockaddr_in6 client, int sockNum);

STATE initConnection(struct sockaddr_in6 *client, int sockNum);

STATE readFilename(struct sockaddr_in6 *client, int sockNum, 
 uint32_t *window, uint32_t *bufLen, FILE *readFile);

int createPacket(char *buffer, uint32_t seqNum, uint32_t checksum, uint16_t flag, 
 int dataSize, char *data);


int main ( int argc, char *argv[]  )
{ 
    int socketNum = 0;              
    //struct sockaddr_in6 client; // Can be either IPv4 or 6
    int portNumber = 0;
    double error;

    portNumber = checkArgs(argc, argv, &error);
        
    socketNum = udpServerSetup(portNumber);

    processClient(socketNum);

    close(socketNum);
}

void processClient(int socketNum)
{
    //int dataLen = 0; 
    char buffer[MAXBUF + 1];      
    struct sockaddr_in6 client;     
    //socklen_t clientAddrLen = sizeof(client); 
    fd_set servFd;
    //struct timeval timeout;
    //timeout.tv_sec = 0;
    //timeout.tv_usec = 0;
    int retFd;
    
    buffer[0] = '\0';
    while (buffer[0] != '.')
    {
        FD_ZERO(&servFd);
        FD_SET(socketNum, &servFd);

        //recvfrom(socketNum, buffer, 0/*MAXBUF*/, 0, (struct sockaddr *) &client, &clientAddrLen);
        retFd = select(socketNum + 1, &servFd, NULL, NULL, NULL);
        printf("retFd: %d\n", retFd); 

        printClientIP(&client);
        stateLoop(client, socketNum);

        /*
        printf(" Len: %d %s\n", dataLen, buffer);

        // just for fun send back to client number of bytes received
        sprintf(buffer, "bytes: %d", dataLen);
        safeSendto(socketNum, buffer, strlen(buffer)+1, 0, (struct sockaddr *) & client, clientAddrLen);
        */

    }
}

void stateLoop(struct sockaddr_in6 client, int sockNum) {
    STATE state = START;
    //int seqNum = 0;
    FILE *readFile = NULL; 
    uint32_t bufLen;
    uint32_t window[2];

    while (state != DONE) {
        
        switch (state) {
            case (START):
                state = initConnection(&client, sockNum);
                break;
                
            case (FILENAME):
                state = readFilename(&client, sockNum, &bufLen, window, readFile);
                break;
                
            case (SEND_DATA):
                break;

            case (WAIT_FOR_ACK):
                break;

            case (WAIT_FOR_EOF_ACK):
                break;

            case (SHUTDOWN):
                break;

            case (DONE):
                break;

            default:
                printf("Reached default in state loop, should not have happened\n");
                break;

        }
    }
} 

STATE initConnection(struct sockaddr_in6 *client, int sockNum) {
    char recvBuffer[MAXBUF + 1];
    char sendBuffer[MAXBUF + 1];
    socklen_t clientSize = sizeof(*client);

    ssize_t recvBytes = recvfrom(sockNum, recvBuffer, 10, 0, 
     (struct sockaddr *)client, &clientSize); 
    printf("Recv'd Bytes: %d\n", (int)recvBytes);
    printf("checksum field on recv'd data %d\n", (uint32_t)recvBuffer[4]);
    printf("checksum calc on recv'd data: %d\n", 
     in_cksum((unsigned short *)recvBuffer, recvBytes));
    
    if (in_cksum((unsigned short *)recvBuffer, recvBytes) != 0) {
        return START;
    }

    int packetSize = createPacket(sendBuffer, 0, 0, 2, 0, ""); 
    packetSize = createPacket(sendBuffer, 0, in_cksum((unsigned short *)sendBuffer, 10), 
     2, 0, ""); 
    
    ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
     (struct sockaddr *)client, clientSize);

    printf("Bytes Sent: %d\n", (int)bytesSent);
    return FILENAME;
} 

STATE readFilename(struct sockaddr_in6 *client, int sockNum, 
 uint32_t *window, uint32_t *bufLen, FILE *readFile) {
    char recvBuffer[MAXBUF + 1];
    char sendBuffer[MAXBUF + 1];
    uint16_t flag = 8;
    socklen_t clientSize = sizeof(*client);

    ssize_t recvBytes = recvfrom(sockNum, recvBuffer, MAXBUF, 0, 
     (struct sockaddr *)client, &clientSize); 
    printf("Recv'd Bytes: %d\n", (int)recvBytes);
    printf("checksum field on recv'd data %d\n", (uint32_t)recvBuffer[4]);
    printf("checksum calc on recv'd data: %d\n", 
     in_cksum((unsigned short *)recvBuffer, recvBytes));

    if (in_cksum((unsigned short *)recvBuffer, recvBytes) != 0) {
        return FILENAME;
    }

    if ((short)recvBuffer[8] == 1) {
        return START;
    }

    printf("Filename: %s\n", (char *)&recvBuffer[18]);

    *bufLen = (uint32_t)recvBuffer[HEADER_LEN + sizeof(uint32_t)];
    window[0] = 0;
    window[1] = (uint32_t)recvBuffer[HEADER_LEN];
    readFile = fopen(&recvBuffer[HEADER_LEN + 2 * sizeof(uint32_t)], "r");

    printf("winSize: %d bufSize: %d\n", window[1], *bufLen); 

    if (readFile == NULL) {
        flag = 9;
    }
    int packetSize = createPacket(sendBuffer, 0, 0, flag, 0, ""); 
    packetSize = createPacket(sendBuffer, 0, in_cksum((unsigned short *)sendBuffer, HEADER_LEN), 
     flag, 0, ""); 
    
    ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
     (struct sockaddr *)client, clientSize);

    printf("Bytes Sent: %d\n", (int)bytesSent);
    return SEND_DATA;
} 

void printClientIP(struct sockaddr_in6 * client)
{
    char ipString[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &client->sin6_addr, ipString, sizeof(ipString));
    printf("Client info - IP: %s Port: %d ", ipString, ntohs(client->sin6_port));
    
}

int checkArgs(int argc, char *argv[], double *error)
{
    // Checks args and returns port number
    int portNumber = 0;
    char *endptr;

    if (argc > 3)
    {
        fprintf(stderr, "Usage %s [error-percent] [optional port number]\n", argv[0]);
        exit(-1);
    }
    
    if (argc == 3)
    {
        portNumber = atoi(argv[2]);
    }
    
    *error = strtod(argv[1], &endptr);
    
    return portNumber;
}

//Puts the packet into buffer, returns the length of the packet
int createPacket(char *buffer, uint32_t seqNum, uint32_t checksum, uint16_t flag, 
 int dataSize, char *data) {
    int ndx = 0;
    seqNum = htonl(seqNum);
    memcpy(buffer, &seqNum, sizeof(uint32_t)); 
    ndx += sizeof(uint32_t);
    memcpy(buffer + ndx, &checksum, sizeof(uint32_t)); 
    ndx += sizeof(uint32_t);
    memcpy(buffer + ndx, &flag, sizeof(uint16_t)); 
    ndx += sizeof(uint16_t);
    memcpy(buffer + ndx, data, dataSize);
    return ndx + dataSize;
}

