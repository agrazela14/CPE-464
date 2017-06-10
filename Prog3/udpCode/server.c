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

STATE waitForAck(struct sockaddr_in6 *client, int sockNum, uint32_t *seqNum, int attempts, 
 windowSize *window, uint32_t bufLen, FILE *readFile, packet *fileBuf);

void fillFileBuffer(uint32_t newLow, windowSize *window, uint32_t winsize, uint32_t bufSize, 
 FILE *readFile, packet *fileBuf, int first);

int createPacket(char *buffer, uint32_t seqNum, uint32_t checksum, uint16_t flag, 
 int dataSize, char *data);


int main ( int argc, char *argv[]  )
{ 
    int socketNum = 0;              
    //struct sockaddr_in6 client; // Can be either IPv4 or 6
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
                state = readFilename(&client, sockNum, &window, &bufLen, &fileBuf, &readFile);
                break;
                
            case (SEND_DATA):
                state = sendData(&client, sockNum, fileBuf, &window, bufLen, &seqNum, readFile);
                break;

            case (WAIT_FOR_ACK):
                state = waitForAck(&client, sockNum, &seqNum, 0, &window, 
                 bufLen, readFile, fileBuf);
                break;
            /*
            case (WAIT_FOR_EOF_ACK):
                break;
            */
            case (SHUTDOWN):
                close(sockNum);
                fclose(readFile);
                free(fileBuf);
                state = DONE;
                break;

            case (DONE):
                break;

            default:
                printf("Reached default in state loop, should not have happened\n");
                state = SHUTDOWN;
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
    printf("Start Recv'd Bytes: %d\n", (int)recvBytes);
    printf("checksum field on recv'd data %d\n", (uint32_t)recvBuffer[4]);
    printf("checksum calc on recv'd data: %d\n", 
     in_cksum((unsigned short *)recvBuffer, recvBytes));

    if (recvBytes < 0) {
        return SHUTDOWN;
    }
    
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
 windowSize *window, uint32_t *bufLen, packet **fileBuf, FILE **readFile) {
    char recvBuffer[MAXBUF + 1];
    char sendBuffer[MAXBUF + 1];
    uint16_t flag = 8;
    socklen_t clientSize = sizeof(*client);

    ssize_t recvBytes = recvfrom(sockNum, recvBuffer, MAXBUF, 0, 
     (struct sockaddr *)client, &clientSize); 
    printf("Filename Recv'd Bytes: %d\n", (int)recvBytes);
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
    window->winHi = recvBuffer[HEADER_LEN] - 1;
    window->winLow = 0;
    *readFile = fopen(&recvBuffer[HEADER_LEN + 2 * sizeof(uint32_t)], "r");

    printf("winSize: %d bufSize: %d\n", window->winHi, *bufLen); 

    *fileBuf = realloc(*fileBuf, window->winHi * sizeof(packet));
    (*fileBuf)[0].sequence = 0; 

    if (readFile == NULL) {
        printf("opeing the file failed\n");
        flag = 9;
    }

    else {
        fillFileBuffer(0, window, window->winHi, *bufLen, *readFile, (*fileBuf), 1); 
    }


    int packetSize = createPacket(sendBuffer, 0, 0, flag, 0, ""); 
    packetSize = createPacket(sendBuffer, 0, in_cksum((unsigned short *)sendBuffer, HEADER_LEN), 
     flag, 0, ""); 
    
    ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
     (struct sockaddr *)client, clientSize);

    if (flag == 9) {
        return SHUTDOWN;
    }

    printf("Bytes Sent: %d, Moving on to Send Data\n", (int)bytesSent);
    return SEND_DATA;
} 

STATE sendData(struct sockaddr_in6 *client, int sockNum, packet *fileBuf, 
 windowSize *window, uint32_t bufLen, uint32_t *seqNum, FILE *readFile) {
    //char recvBuffer[MAXBUF + 1];
    char sendBuffer[MAXBUF + 1];
    char dataBuf[MAXBUF + 1];
    socklen_t clientSize = sizeof(*client);
    ssize_t bytesSent;
    uint16_t flag = 3;
    int packetSize;
    int i;
    int dataAdv = 0;
    int found = 0;
    //int fileBytes = fread(dataBuf, bufLen, 1, readFile);

    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(sockNum, &fds);
    
    printf("Send Data, seqNum = %d\n", *seqNum);
    //printf("fileBuf[0].sequence = %d window[0] = %d, window[1] = %d\n", fileBuf[0].sequence, window[0], window[1]);

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
        printf("Final packet, bufLen vs packetLen: %d v %d\n", bufLen, fileBuf[i].length);
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

    printf("Send Data Bytes Sent: %d\n", (int)bytesSent);
        
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


void fillFileBuffer(uint32_t newLow, windowSize *window, uint32_t winsize, uint32_t bufSize, 
 FILE *readFile, packet *packets, int first) {
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

    printf("Window new Low = %d, windowShift = %d\n", newLow, windowShift);
    window->winLow += windowShift;
    window->winHi += windowShift;
}

STATE waitForAck(struct sockaddr_in6 *client, int sockNum, uint32_t *seqNum, int attempts, 
 windowSize *window, uint32_t bufLen, FILE *readFile, packet *fileBuf) {
    //Use the incoming RR's seqNum as fillFileBuffer's newLow
    //Use a 1 sec timeout select for waiting, if it times out 10 times send a single data pack
    //With seqNum/data of filBuf[0].
    char recvBuffer[MAXBUF + 1];
    char sendBuffer[MAXBUF + 1];
    //char dataBuf[MAXBUF + 1];
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

    printf("Wait for acks, window: [%d, %d]\n", window->winLow, window->winHi);
    printf("Lowest Filebuf Seq: %d\n", fileBuf[0].sequence);
    
    int readFds = select(sockNum + 1, &fds, NULL, NULL, &timeout); 
    
        /*
        int packetSize = createPacket(sendBuffer, *seqNum, 0, flag, 
         fileBuf[0].length, fileBuf[0].data); 
        packetSize = createPacket(sendBuffer, *seqNum, in_cksum((unsigned short *)sendBuffer,
         packetSize), flag, fileBuf[0].length, fileBuf[0].data); 
    
        ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
         (struct sockaddr *)client, clientSize);
        printf("Bytes Sent: %d\n", (int)bytesSent);
        return WAIT_FOR_ACK;    
        */

     
    if (readFds <= 0) {
        //Timed out, sending the lowest window packet again
        //Try setting the seqNum here, we need to resend anything above anyways
        *seqNum = fileBuf[0].sequence;

        int packetSize = createPacket(sendBuffer, *seqNum, 0, flag, 
         fileBuf[0].length, fileBuf[0].data); 
        packetSize = createPacket(sendBuffer, *seqNum, in_cksum((unsigned short *)sendBuffer,
         packetSize), flag, fileBuf[0].length, fileBuf[0].data); 
    
        ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
         (struct sockaddr *)client, clientSize);
        printf("RESENT LOWEST FRAME, Bytes Sent: %d\n", (int)bytesSent);

        return waitForAck(client, sockNum, seqNum, ++attempts, 
         window, bufLen, readFile, fileBuf);
    }

    while (readFds > 0) {
        recvBytes = recvfrom(sockNum, recvBuffer, HEADER_LEN + sizeof(uint32_t), 0, 
         (struct sockaddr *)client, &clientSize); 
        readFds = select(sockNum + 1, &fds, NULL, NULL, &timeout); 
        
        /*
        if (in_cksum((unsigned short *)recvBuffer, recvBytes) != 0) {
            //Bad Checksum in acks 
            continue;
        }
        */

        newLow = htonl(*(uint32_t *)recvBuffer);// + 1;
        
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
         packetSize = createPacket(sendBuffer, 0, in_cksum((unsigned short *)sendBuffer, 
          HEADER_LEN), flag, 0, ""); 
    
        ssize_t bytesSent = sendtoErr(sockNum, sendBuffer, packetSize, 0, 
         (struct sockaddr *)client, clientSize);
        *seqNum = 0;
        //return FILENAME;
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

