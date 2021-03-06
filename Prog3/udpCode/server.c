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

typedef struct {
    char data[MAXBUF];
    uint32_t sequence;
    int length;
} packet;

typedef struct {
    uint32_t winHi;
    uint32_t winLow;
} windowSize;

enum State {
    START, FILENAME, SEND_DATA, WAIT_FOR_ACK, WAIT_FOR_EOF_ACK, SHUTDOWN, DONE
};

void processClient(int socketNum);

void printClientIP(struct sockaddr_in6 * client);

int checkArgs(int argc, char *argv[], double *error);

void stateLoop(struct sockaddr_in6 client, int sockNum);

STATE initConnection(struct sockaddr_in6 *client, int sockNum);

STATE readFilename(struct sockaddr_in6 *client, int sockNum, 
 windowSize *window, uint32_t *bufLen, packet **fileBuf, FILE **readFile);

STATE sendData(struct sockaddr_in6 *client, int sockNum, packet *fileBuf, 
 windowSize *window, uint32_t bufLen, uint32_t *seqNum, FILE *readFile);

STATE waitForAck(struct sockaddr_in6 *client, int sockNum, uint32_t *seqNum, 
 int attempts, windowSize *window, uint32_t bufLen, FILE *readFile, 
  packet *fileBuf);

void fillFileBuffer(uint32_t newLow, windowSize *window, 
 uint32_t winsize, uint32_t bufSize, 
 FILE *readFile, packet *fileBuf, int first);

int createPacket(char *buffer, uint32_t seqNum, uint32_t checksum, 
 uint16_t flag, int dataSize, char *data);


int main ( int argc, char *argv[]  )
{ 
    int socketNum = 0;              
    int portNumber = 0;
    double error;

    portNumber = checkArgs(argc, argv, &error);

    sendtoErr_init(error, DROP_ON, FLIP_ON, DEBUG_ON, RSEED_ON);
        
    socketNum = udpServerSetup(portNumber);

    processClient(socketNum);

    close(socketNum);
}

void processClient(int socketNum)
{
    char buffer[MAXBUF + 1];      
    struct sockaddr_in6 client;     
    fd_set servFd;
    int retFd;
    
    while (1)
    {
        FD_ZERO(&servFd);
        FD_SET(socketNum, &servFd);

        retFd = select(socketNum + 1, &servFd, NULL, NULL, NULL);
        if (retFd > 0) {
            printClientIP(&client);
            stateLoop(client, socketNum);
        }
    }
}

void stateLoop(struct sockaddr_in6 client, int sockNum) {
    STATE state = START;
    uint32_t seqNum = 0;
    FILE *readFile = NULL; 
    uint32_t bufLen;
    windowSize window;
    packet *fileBuf = malloc(sizeof(packet));

    while (state != DONE) {
        
        switch (state) {
            case (START):
                state = initConnection(&client, sockNum);
                break;
                
            case (FILENAME):
                state = readFilename(&client, sockNum, &window, 
                 &bufLen, &fileBuf, &readFile);
                break;
                
            case (SEND_DATA):
                state = sendData(&client, sockNum, fileBuf, &window, 
                 bufLen, &seqNum, readFile);
                break;

            case (WAIT_FOR_ACK):
                state = waitForAck(&client, sockNum, &seqNum, 0, &window, 
                 bufLen, readFile, fileBuf);
                break;
            case (SHUTDOWN):
                close(sockNum);
                fclose(readFile);
                state = DONE;
                break;

            case (DONE):
                readFile = NULL;
                free(fileBuf);
                break;

            default:
                printf("default in state loop, should not have happened\n");
                exit(-1);
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

    if (recvBytes < 0) {
        return DONE;
    }
    
    if (in_cksum((unsigned short *)recvBuffer, recvBytes) != 0) {
        return START;
    }

    int packetSize = createPacket(sendBuffer, 0, 0, 2, 0, ""); 
    packetSize = createPacket(sendBuffer, 0, 
     in_cksum((unsigned short *)sendBuffer, 10), 2, 0, ""); 
    
    ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
     (struct sockaddr *)client, clientSize);

    return FILENAME;
} 

STATE readFilename(struct sockaddr_in6 *client, int sockNum, 
 windowSize *window, uint32_t *bufLen, packet **fileBuf, FILE **readFile) {
    char recvBuffer[MAXBUF + 1];
    char sendBuffer[MAXBUF + 1];
    uint16_t flag = 8;
    socklen_t clientSize = sizeof(*client);

    ssize_t recvBytes = recvfrom(sockNum, recvBuffer, MAXBUF, 0, 
     (struct sockaddr *)client, &clientSize); 

    if (in_cksum((unsigned short *)recvBuffer, recvBytes) != 0) {
        return FILENAME;
    }

    if ((short)recvBuffer[8] == 1) {
        return START;
    }


    *bufLen = (uint32_t)recvBuffer[HEADER_LEN + sizeof(uint32_t)];
    window->winHi = recvBuffer[HEADER_LEN] - 1;
    window->winLow = 0;
    *readFile = fopen(&recvBuffer[HEADER_LEN + 2 * sizeof(uint32_t)], "r");


    *fileBuf = realloc(*fileBuf, window->winHi * sizeof(packet));
    (*fileBuf)[0].sequence = 0; 

    if (readFile == NULL) {
        flag = 9;
    }

    else {
        fillFileBuffer(0, window, window->winHi, 
         *bufLen, *readFile, (*fileBuf), 1); 
    }


    int packetSize = createPacket(sendBuffer, 0, 0, flag, 0, ""); 
    packetSize = createPacket(sendBuffer, 0, in_cksum((unsigned short *)
     sendBuffer, HEADER_LEN), flag, 0, ""); 
    
    ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
     (struct sockaddr *)client, clientSize);

    if (flag == 9) {
        return SHUTDOWN;
    }

    return SEND_DATA;
} 

STATE sendData(struct sockaddr_in6 *client, int sockNum, packet *fileBuf, 
 windowSize *window, uint32_t bufLen, uint32_t *seqNum, FILE *readFile) {
    char sendBuffer[MAXBUF + 1];
    char dataBuf[MAXBUF + 1];
    socklen_t clientSize = sizeof(*client);
    ssize_t bytesSent;
    uint16_t flag = 3;
    int packetSize;
    int i;
    int dataAdv = 0;
    int found = 0;

    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(sockNum, &fds);
    

    for (i = 0; i < (window->winHi - window->winLow); i++) {
        if (fileBuf[i].sequence == *seqNum) {
            found = 1;
            break;
        }
    }
    
    //This should mean that the seqNum went past the final packet 
    if (found == 0) {
        return WAIT_FOR_ACK;
    }
    
    //This is for putting the length of the data of the final packet in
    if (fileBuf[i].length != bufLen) {
        flag = 10;
        memcpy(dataBuf, &(fileBuf[i].length), 4);
        dataAdv = 4;
    }

    memcpy(dataBuf + dataAdv, fileBuf[i].data, fileBuf[i].length); 

    packetSize = createPacket(sendBuffer, fileBuf[i].sequence, 0, flag, 
     fileBuf[i].length + dataAdv, dataBuf); 
    packetSize = createPacket(sendBuffer, fileBuf[i].sequence, 
     in_cksum((unsigned short *)sendBuffer, packetSize), flag, 
     fileBuf[i].length + dataAdv, dataBuf); 
    
    bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
     (struct sockaddr *)client, clientSize);

        
    (*seqNum) += 1;

    /*
    if (flag == 10) {
        return WAIT_FOR_EOF_ACK; 
    }
    */

    /* If there's any data incoming, we need to read the acks*/
    int retFd = select(sockNum + 1, &fds, NULL, NULL, &timeout);
    if (retFd > 0) {
        return WAIT_FOR_ACK;
    }
        
    if (*seqNum <= window->winHi) {
        //keep sending 
        return SEND_DATA;
    }
    else {
        //Wait for some ACKS
        return WAIT_FOR_ACK;
    }

    return SHUTDOWN;
}


void fillFileBuffer(uint32_t newLow, windowSize *window, uint32_t winsize, 
 uint32_t bufSize, FILE *readFile, packet *packets, int first) {
    int i;
    //int shiftBack = 0;
    //The windowshift is a left shift, new data comes in on the right
    int windowShift = newLow - window->winLow;

    /*
    for (i = 0; i < winsize; i++) {
        if (packets[i].sequence == newLow) {
            windowShift = i;
            break;
        }
    }
    */
    
    if (first) {
        for (i = 0; i < window->winHi - window->winLow; i++) {
            packets[i].length = fread(packets[i].data, 1, bufSize, readFile); 
            packets[i].sequence = newLow + i;
        }
    }

    else {
        for (i = 0; i < winsize - windowShift; i++) {
            memcpy(&packets[i], &packets[i + windowShift], sizeof(packet));
        } 

        for (i = winsize - windowShift; i < winsize; i++) {
            packets[i].length = fread(packets[i].data, 1, bufSize, readFile); 
            packets[i].sequence = newLow + i;
        }
    }

    window->winLow += windowShift;
    window->winHi += windowShift;
}

STATE waitForAck(struct sockaddr_in6 *client, int sockNum, uint32_t *seqNum, 
 int attempts, windowSize *window, uint32_t bufLen, 
  FILE *readFile, packet *fileBuf) {
    char recvBuffer[MAXBUF + 1];
    char sendBuffer[MAXBUF + 1];
    socklen_t clientSize = sizeof(*client);
    int newLow;
    uint16_t flag = 3;
    ssize_t recvBytes;

    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(sockNum, &fds);

    if (attempts == 11) {
        return SHUTDOWN;
    }
    
    int readFds = select(sockNum + 1, &fds, NULL, NULL, &timeout); 
    
    if (readFds <= 0) {
        //Timed out, sending the lowest window packet again
        //Try setting the seqNum here, we need to resend anything above anyways
        *seqNum = fileBuf[0].sequence;

        int packetSize = createPacket(sendBuffer, *seqNum, 0, flag, 
         fileBuf[0].length, fileBuf[0].data); 
        packetSize = createPacket(sendBuffer, *seqNum, 
         in_cksum((unsigned short *)sendBuffer, packetSize), flag, 
          fileBuf[0].length, fileBuf[0].data); 
    
        ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
         (struct sockaddr *)client, clientSize);

        return waitForAck(client, sockNum, seqNum, ++attempts, 
         window, bufLen, readFile, fileBuf);
    }

    while (readFds > 0) {
        recvBytes = recvfrom(sockNum, recvBuffer, 
         HEADER_LEN + sizeof(uint32_t),
          0, (struct sockaddr *)client, &clientSize); 
        readFds = select(sockNum + 1, &fds, NULL, NULL, &timeout); 
        
        newLow = htonl(*(uint32_t *)recvBuffer);;
        
        //SREJ, reset the sequence Number
        if ((uint16_t)recvBuffer[8] == 6) {
            *seqNum = htonl(*(uint32_t *)recvBuffer);
            newLow = *seqNum;
        }
    }

    if (in_cksum((unsigned short *)recvBuffer, recvBytes) != 0) {
        //Bad Checksum in acks 
        return waitForAck(client, sockNum, seqNum, ++attempts, 
         window, bufLen, readFile, fileBuf);
    }


    if ((uint16_t)recvBuffer[8] == 7) {
        //Resend the File Ok
        int packetSize = createPacket(sendBuffer, 0, 0, flag, 0, ""); 
         packetSize = createPacket(sendBuffer, 0, in_cksum((unsigned short *)
          sendBuffer, HEADER_LEN), flag, 0, ""); 
    
        ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
         (struct sockaddr *)client, clientSize);
        *seqNum = 0;
    }

    if ((uint16_t)recvBuffer[8] == 11) {
        return SHUTDOWN;
    }
    
    //This should take care of either an SREJ or an RR tbh
    //newLow = htonl(*(uint32_t *)recvBuffer);
    fillFileBuffer(newLow, window, (window->winHi - window->winLow), 
     bufLen, readFile, fileBuf, 0);
    return SEND_DATA;
}

void printClientIP(struct sockaddr_in6 * client)
{
    char ipString[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &client->sin6_addr, ipString, sizeof(ipString));
    
}

int checkArgs(int argc, char *argv[], double *error)
{
    // Checks args and returns port number
    int portNumber = 0;
    char *endptr;

    if (argc > 3)
    {
        fprintf(stderr, "Usage %s [error-percent] [optional port number]\n",
         argv[0]);
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
int createPacket(char *buffer, uint32_t seqNum, uint32_t checksum, 
 uint16_t flag, int dataSize, char *data) {
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

