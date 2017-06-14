// Client side - UDP Code                   
// By Hugh Smith    4/1/2017        

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "networks.h"
#include "cpe464.h"

#define MAXBUF 255
#define HEADER_LEN 10
#define xstr(a) str(a)
#define str(a) #a

typedef enum State STATE;

enum State {
    START, FILENAME, WAIT_FOR_DATA, WAIT_FOR_SREJ_RESP, SHUTDOWN, DONE
}; 

typedef struct {
    char destFile[255];
    char srcFile[255];
    uint32_t windowSize;
    uint32_t bufSize;
    double error;
    char remoteMachine[255];
    uint32_t remotePort;
} arguments;

void talkToServer(arguments *argu, int socketNum, struct sockaddr_in6 *server);

void checkArgs(int argc, char * argv[], arguments *argu);

STATE initConnection(arguments *argu, int sockNum, 
 struct sockaddr_in6 *server, int attempt);

STATE sendFilename(arguments *argu, int sockNum, 
 struct sockaddr_in6 *server, int attempt);

STATE readData(arguments *argu, int sockNum, struct sockaddr_in6 *server, 
 int *seqNum, FILE *outFile);

STATE srejReadData(arguments *argu, int sockNum, struct sockaddr_in6 *server, 
 int *seqNum, FILE *outFile);

int createPacket(char *buffer, uint32_t seqNum, uint32_t checksum, 
uint16_t flag, int dataSize, char *data);

int main (int argc, char *argv[])
 {
    int socketNum = 0;              
    struct sockaddr_in6 server; 
    arguments *argu = malloc(sizeof(arguments));
    
    checkArgs(argc, argv, argu);
    
    close(3); 
    socketNum = setupUdpClientToServer(&server, argu->remoteMachine, 
     argu->remotePort);
    
    talkToServer(argu, socketNum, &server);
    free(argu);
    return 0;
}

//Change this function to kick off communication
void talkToServer(arguments *argu, int sockNum, struct sockaddr_in6 *server)
{
    STATE state = START;
    int seqNum = 0;
    FILE *writeFile = fopen(argu->destFile, "w+");

    if (writeFile == NULL) {
        fprintf(stderr, "Could not open file for writing\n");
        state = DONE;
    }

    sendtoErr_init(argu->error, DROP_ON, FLIP_ON, DEBUG_ON, RSEED_ON);

    while (state != DONE) {
        
        switch (state) {
            case START:
                state = initConnection(argu, sockNum, server, 0);
                break;

            case FILENAME:
                state = sendFilename(argu, sockNum, server, 0);
                break;

            case WAIT_FOR_DATA:
                state = readData(argu, sockNum, server, &seqNum, writeFile); 
                break;

            case WAIT_FOR_SREJ_RESP:
                state = srejReadData(argu, sockNum, server, 
                 &seqNum, writeFile);
                break;

            case SHUTDOWN: //Do Cleanup
                close(sockNum);
                fclose(writeFile);
                state = DONE;
                break;

            case DONE:
                break;

            default:
                fprintf(stderr, "default in state switch, we'z zogged!\n");
                state = SHUTDOWN;
                break;
        }
    }
}

//Send the initial Packet
//Read for initial packet success
//If response comes go on to filename state
//If timeout and resend 10 times, go to Shutdown state
STATE initConnection(arguments *argu, int sockNum, 
 struct sockaddr_in6 *server, int attempt) {
    unsigned int addrLen = sizeof(*server);
    char buffer[MAXBUF + 1];
    char recvBuffer[MAXBUF + 1];
    /*select Stuff */
    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    int retFd;
    /*End of Select Stuff*/

    int packetLen = createPacket(buffer, 0, 0, 1, 0, ""); 
    packetLen = createPacket(buffer, 0, 
     in_cksum((unsigned short*)buffer, packetLen), 1, 0, ""); 
    ssize_t bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
     (struct sockaddr *)server, addrLen); 
    
    FD_ZERO(&fds);
    FD_SET(sockNum, &fds);
    retFd = select(sockNum + 1, &fds, NULL, NULL, &timeout);
    
    if (retFd > 0) { 
        ssize_t bytesRecv = recvfrom(sockNum, recvBuffer, 10, 0, 
         (struct sockaddr *)server, &addrLen); 

        if ((in_cksum((unsigned short *)recvBuffer, bytesRecv) != 0)) {
            return initConnection(argu, sockNum, server, ++attempt);
        }

        if ((short)recvBuffer[8] == 2) {
            return FILENAME;
        }
    }

    if (attempt == 10) {
        return SHUTDOWN;
    }

    return initConnection(argu, sockNum, server, ++attempt);
} 

//send Filename
//Read for Filename response
//If you get a response Go on to Wait_For_Data state
//If you send fileName with no response 10 times go to Shutdown
//If you get the badFileName response, print error and go to shutdown
STATE sendFilename(arguments *argu, int sockNum, 
 struct sockaddr_in6 *server, int attempt) {
    //in_cksum() on the packet. 
    unsigned int addrLen = sizeof(*server);
    char buffer[MAXBUF + 1];
    char recvBuffer[MAXBUF + 1];
    char dataBuf[MAXBUF + 1];
    /*select Stuff */
    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    int retFd;
    /*End of Select Stuff*/
    int dataLen = strlen(argu->srcFile) + HEADER_LEN + 2 * sizeof(uint32_t); 
    
    memcpy(dataBuf, &(argu->windowSize), sizeof(uint32_t)); 
    memcpy(dataBuf + sizeof(uint32_t), &(argu->bufSize), sizeof(uint32_t)); 
    strcpy(dataBuf + 2 * sizeof(uint32_t), argu->srcFile); 

    int packetLen = createPacket(buffer, 0, 0, 7, dataLen, dataBuf); 
    packetLen = createPacket(buffer, 0, in_cksum((unsigned short *)buffer, 
     packetLen), 7, dataLen, dataBuf); 
    ssize_t bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
     (struct sockaddr *)server, addrLen); 

    FD_ZERO(&fds);
    FD_SET(sockNum, &fds);
    retFd = select(sockNum + 1, &fds, NULL, NULL, &timeout);
    
    if (retFd > 0) { 
        ssize_t bytesRecv = recvfrom(sockNum, recvBuffer, HEADER_LEN, 0, 
         (struct sockaddr *)server, &addrLen); 

        if ((in_cksum((unsigned short *)recvBuffer, bytesRecv) != 0)) {
            return sendFilename(argu, sockNum, server, ++attempt);
        }
        //Use flag 8 for filename conf
        //Use flag 9 for bad filename 
        if ((short)recvBuffer[8] == 9) {
            fprintf(stderr, "File could not be opened on server side\n");
            return SHUTDOWN;
        }

        if (((short)recvBuffer[8] == 8) || ((short)recvBuffer[8] == 3)) {
            return WAIT_FOR_DATA;
        }
    }

    if (attempt == 10) {
        return SHUTDOWN;
    }

    return sendFilename(argu, sockNum, server, ++attempt);
} 

//Read for data packet
//If init success packet, go back to Filename state
//Else check that seqNum correct
//If correct, send RRseqNum, inc seqNum, continue in this state
//If too High, send SREJseqNum, go to Wait_for_srej_resp state
//If too low, discard data and RRSeqNum - 1 (Think more about this one)
STATE readData(arguments *argu, int sockNum, struct sockaddr_in6 *server, 
 int *seqNum, FILE *outFile) {
    unsigned int addrLen = sizeof(*server);
    char buffer[MAXBUF + 1];
    char recvBuffer[MAXBUF + 1];
    int dataLen = sizeof(uint32_t);
    int eofPack = 0;
    char dataBuf[sizeof(uint32_t)];
    int sendflag = 5;
     
    ssize_t bytesRecv = recvfrom(sockNum, recvBuffer, 
     HEADER_LEN + argu->bufSize, 0, (struct sockaddr *)server, &addrLen); 
    ssize_t bytesSent;

    if ((in_cksum((unsigned short *)recvBuffer, bytesRecv) != 0)) {
        fprintf(stderr, "Bad Checksum on data recv\n");
        return WAIT_FOR_DATA;
    }

    uint32_t recvSeq = ntohl(*(uint32_t *)recvBuffer);
    uint16_t flag = (uint16_t)recvBuffer[8];
    int packetLen = 0;
    uint32_t writeLen = argu->bufSize;

    //EOF packet, this one has the length as 4 byte value right before the data
    if (flag == 10) {
        writeLen = (uint32_t)recvBuffer[HEADER_LEN]; 
        sendflag = 11;
        eofPack = 1;
    }

    for (int i = 0; i < writeLen; i++) {
        /*
        if (!(*(recvBuffer + i + HEADER_LEN + sizeof(uint32_t) * eofPack) >0
            &&(*(recvBuffer + i + HEADER_LEN + 
             sizeof(uint32_t) * eofPack) < 127))){
        */
        char cur = (*(recvBuffer + i + HEADER_LEN + 
             sizeof(uint32_t) * eofPack)); 
        if (!(isgraph(cur) || isspace(cur))) {
            recvSeq = *seqNum + 1; 
            printf("Failed because not graph or space %c\n", cur);
            break;
        }
    }

    if (recvSeq == *seqNum) {
        //Ack at seqNum, then increment it
        int writeBytes = fwrite(recvBuffer + HEADER_LEN + 
         sizeof(uint32_t) * eofPack, 1, writeLen, outFile);
        fflush(outFile);

        packetLen = createPacket(buffer, *seqNum, 0, 
         sendflag, dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum, in_cksum((unsigned short *)
         buffer, packetLen), sendflag, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 
        (*seqNum) += 1;

        if (eofPack) {
            return SHUTDOWN;
        }
        return WAIT_FOR_DATA;
    }

    else if (recvSeq > *seqNum) {
    //Out of sequence packet, go into srej mode
        packetLen = createPacket(buffer, *seqNum, 0, 6, dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum, in_cksum((unsigned short *)
         buffer, packetLen), 6, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 

        return WAIT_FOR_SREJ_RESP;
    }

    else if (recvSeq < *seqNum){
        //Send an SREJPacket for the current seqNum to kickstart the server
        packetLen = createPacket(buffer, *seqNum, 0, 6, dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum, in_cksum((unsigned short *)
         buffer, packetLen), 6, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 

        return WAIT_FOR_SREJ_RESP;
    }
    return SHUTDOWN;
}

//Read data packets
//If they aren't the data for seqNum, discard and do not respond
//If it is data for seqNum, RRseqNum, go to Wait_for_data state
STATE srejReadData(arguments *argu, int sockNum, struct sockaddr_in6 *server, 
 int *seqNum, FILE *outFile) {
    unsigned int addrLen = sizeof(*server);
    char buffer[MAXBUF + 1];
    char recvBuffer[MAXBUF + 1];
    int dataLen = sizeof(uint32_t);
    char dataBuf[sizeof(uint32_t)];
    int sendFlag = 0;
     
    ssize_t bytesRecv = recvfrom(sockNum, recvBuffer, MAXBUF, 0, 
     (struct sockaddr *)server, &addrLen); 
    ssize_t bytesSent;


    uint32_t recvSeq = ntohl(*(uint32_t *)recvBuffer);
    uint16_t flag = (uint16_t)recvBuffer[8];
    int packetLen = 0;
    
    //Flag is wrong for a data packet 
    if (flag == 10) {
        //Probably supposed to do some other stuff, but w/e
        sendFlag = 11;
    }

    if (recvSeq == *seqNum) {
        fwrite(recvBuffer + HEADER_LEN, argu->bufSize, 1, outFile);
        (*seqNum) += 1;

        packetLen = createPacket(buffer, *seqNum, 0, sendFlag, 
         dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum, in_cksum((unsigned short *)
         buffer, packetLen), sendFlag, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 

        if (flag == 10) {
            return SHUTDOWN;
        }
        return WAIT_FOR_DATA;
    }
    else if (recvSeq < *seqNum) {
        //Resend the SREJ

        packetLen = createPacket(buffer, *seqNum, 0, 6, dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum, in_cksum((unsigned short *)
         buffer, packetLen), 6, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 

        return WAIT_FOR_SREJ_RESP;
    }
    else {
        return WAIT_FOR_SREJ_RESP;
    }
    return SHUTDOWN;
}

void checkArgs(int argc, char * argv[], arguments *argu)
{
    /* check command line arguments  */
    char *endptr;
    if (argc != 8)
    {
        printf("usage: %s local-to-file remote-from-file windowsize",argv[0]); 
        printf("buffer-size error-percent host-name port-number \n");
        exit(1);
    }
    
    // Checks args and returns port number
    strcpy(argu->destFile, argv[1]);
    strcpy(argu->srcFile, argv[2]);
    argu->windowSize = atoi(argv[3]);
    argu->bufSize = atoi(argv[4]);
    argu->error = strtod(argv[5], &endptr);
    strcpy(argu->remoteMachine, argv[6]);
    argu->remotePort = atoi(argv[7]);
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




