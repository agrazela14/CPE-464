// Client side - UDP Code                   
// By Hugh Smith    4/1/2017        

#include <stdio.h>
#include <stdlib.h>
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

STATE initConnection(arguments *argu, int sockNum, struct sockaddr_in6 *server, int attempt);

STATE sendFilename(arguments *argu, int sockNum, struct sockaddr_in6 *server, int attempt);

STATE readData(arguments *argu, int sockNum, struct sockaddr_in6 *server, 
 int *seqNum, FILE *outFile);

STATE srejReadData(arguments *argu, int sockNum, struct sockaddr_in6 *server, 
 int *seqNum, FILE *outFile);

int createPacket(char *buffer, uint32_t seqNum, uint32_t checksum, uint16_t flag, 
 int dataSize, char *data);

//int getData(char * buffer);


int main (int argc, char *argv[])
 {
    int socketNum = 0;              
    struct sockaddr_in6 server;     // Supports 4 and 6 but requires IPv6 struct
    //int portNumber = 0;             // SockAddrLen used in recvfrom is sizeof(server)
    arguments *argu = malloc(sizeof(arguments));
    
    checkArgs(argc, argv, argu);
    
    socketNum = setupUdpClientToServer(&server, argu->remoteMachine, argu->remotePort);
    
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
                state = srejReadData(argu, sockNum, server, &seqNum, writeFile);
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
STATE initConnection(arguments *argu, int sockNum, struct sockaddr_in6 *server, int attempt) {
    //Apparently Checksum works by just putting a 0 in the field and running the function
    //in_cksum() on the packet. 
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
    printf("Checksum = %d, packetLen: %d\n", in_cksum((unsigned short *)buffer, 10), packetLen);
    packetLen = createPacket(buffer, 0, in_cksum((unsigned short*)buffer, packetLen), 1, 0, ""); 
    ssize_t bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
     (struct sockaddr *)server, addrLen); 
    
    FD_ZERO(&fds);
    FD_SET(sockNum, &fds);
    retFd = select(sockNum + 1, &fds, NULL, NULL, &timeout);
    
    printf("retFd: %d\n", retFd);
    if (retFd > 0) { 
        ssize_t bytesRecv = recvfrom(sockNum, recvBuffer, 10, 0, 
         (struct sockaddr *)server, &addrLen); 
        printf("Recv Flag: %hd, bytes Recv: %d bytes Sent: %d\n", 
         (short)recvBuffer[8], (int)bytesRecv, (int)bytesSent);

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
STATE sendFilename(arguments *argu, int sockNum, struct sockaddr_in6 *server, int attempt) {
    //Apparently Checksum works by just putting a 0 in the field and running the function
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
    strcpy(dataBuf + 2 * sizeof(uint32_t), argu->srcFile);//, strlen(argu->srcFile)); 

    printf("Filename argument: %s\n", argu->srcFile);
    printf("Filename Being Sent: %s\n", dataBuf + 2 * sizeof(uint32_t));

    int packetLen = createPacket(buffer, 0, 0, 7, dataLen, dataBuf); 
    packetLen = createPacket(buffer, 0, in_cksum((unsigned short *)buffer, packetLen), 
     7, dataLen, dataBuf); 
    ssize_t bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
     (struct sockaddr *)server, addrLen); 

    printf("Sent Filename, bytes: %d\n", (int)bytesSent);
    
    FD_ZERO(&fds);
    FD_SET(sockNum, &fds);
    retFd = select(sockNum + 1, &fds, NULL, NULL, &timeout);
    
    printf("retFd: %d\n", retFd);
    if (retFd > 0) { 
        ssize_t bytesRecv = recvfrom(sockNum, recvBuffer, HEADER_LEN, 0, 
         (struct sockaddr *)server, &addrLen); 
        printf("Recv Flag: %hd, bytes Recv: %d bytes Sent: %d\n", 
         (short)recvBuffer[8], (int)bytesRecv, (int)bytesSent);

        if ((in_cksum((unsigned short *)recvBuffer, bytesRecv) != 0)) {
            return sendFilename(argu, sockNum, server, ++attempt);
        }
        //Use flag 8 for filename conf
        //Use flag 9 for bad filename 
        if ((short)recvBuffer[8] == 9) {
            //This might need it's own state, or just wait for timeouts on the other end
            //To figure out that the client is dead
            fprintf(stderr, "File could not be opened on server side\n");
            return SHUTDOWN;
        }

        //Filename OK or data packet, should probably just remove filename ok and use data
        if (((short)recvBuffer[8] == 8) || ((short)recvBuffer[8] == 3)) {
            printf("Got the fileOK\n");
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
     
    ssize_t bytesRecv = recvfrom(sockNum, recvBuffer, HEADER_LEN + argu->bufSize, 0, 
     (struct sockaddr *)server, &addrLen); 
    ssize_t bytesSent;

    if ((in_cksum((unsigned short *)recvBuffer, bytesRecv) != 0)) {
        printf("Bad Checksum on data recv\n");
        return WAIT_FOR_DATA;
    }

    printf("reading data, recv %d Bytes\n", (int)bytesRecv);

    uint32_t recvSeq = ntohl(*(uint32_t *)recvBuffer);
    uint16_t flag = (uint16_t)recvBuffer[8];
    int packetLen = 0;
    uint32_t writeLen = argu->bufSize;

    printf("Looking for packet with seqNum: %d\n", *seqNum);
    
    //Flag is wrong for a data packet 
    /*
    if (flag != 3) {
        //Probably supposed to do some other stuff, but w/e
        return SHUTDOWN;
    }
    */

    //EOF packet, this one has the length as a 4 byte value right before the data
    if (flag == 10) {
        writeLen = (uint32_t)recvBuffer[HEADER_LEN]; 
        eofPack = 1;
    }

    if (recvSeq == *seqNum) {
        //Ack at seqNum, then increment it
        int writeBytes = fwrite(recvBuffer + HEADER_LEN + sizeof(uint32_t) * eofPack, 
         1, writeLen, outFile);
        fflush(outFile);
        printf("wrote %d bytes, should be %d\n", writeBytes, writeLen);

        packetLen = createPacket(buffer, *seqNum, 0, 5, dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum, in_cksum((unsigned short *)buffer, packetLen), 
         5, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 
        (*seqNum) += 1;

        printf("Correct SeqNum, Sent Bytes %d\n", (int)bytesSent);
        return WAIT_FOR_DATA;
    }

    else if (recvSeq > *seqNum) {
    //Out of sequence packet, go into srej mode
        printf("recvSeq: %d, seqNum: %d\n", recvSeq, *seqNum);
        packetLen = createPacket(buffer, *seqNum, 0, 6, dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum, in_cksum((unsigned short *)buffer, packetLen), 
         6, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 

        printf("SeqNum High, Sent Bytes %d\n", (int)bytesSent);
        return WAIT_FOR_SREJ_RESP;
    }

    else if (recvSeq < *seqNum){
        //Send an SREJPacket for the current seqNum to kickstart the server
        printf("recvSeq: %d, seqNum: %d\n", recvSeq, *seqNum);
        packetLen = createPacket(buffer, *seqNum/* - 1*/, 0, 6, dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum/* - 1*/, in_cksum((unsigned short *)buffer, 
         packetLen), 6, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 

        printf("SeqNum Low, Sent Bytes %d\n", (int)bytesSent);
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
     
    ssize_t bytesRecv = recvfrom(sockNum, recvBuffer, MAXBUF, 0, 
     (struct sockaddr *)server, &addrLen); 
    ssize_t bytesSent;


    uint32_t recvSeq = ntohl(*(uint32_t *)recvBuffer);
    uint16_t flag = (uint16_t)recvBuffer[8];
    int packetLen = 0;
    printf("Waiting for SREJ'D packet %d, recv %d bytes, recv seqNum %d\n", *seqNum, (int)bytesRecv, recvSeq);
    
    //Flag is wrong for a data packet 
    if (flag != 3) {
        //Probably supposed to do some other stuff, but w/e
        return SHUTDOWN;
    }

    if (recvSeq == *seqNum) {
        fwrite(recvBuffer + HEADER_LEN, argu->bufSize, 1, outFile);
        (*seqNum) += 1;

        packetLen = createPacket(buffer, *seqNum, 0, 5, dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum, in_cksum((unsigned short *)buffer, packetLen), 
         5, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 

        printf("Sent Bytes %d\n", (int)bytesSent);
        return WAIT_FOR_DATA;
    }
    else if (recvSeq < *seqNum) {
        //Resend the SREJ

        packetLen = createPacket(buffer, *seqNum/* - 1*/, 0, 6, dataLen, dataBuf); 
        packetLen = createPacket(buffer, *seqNum/* - 1*/, in_cksum((unsigned short *)buffer, 
         packetLen), 6, dataLen, dataBuf); 
        bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
         (struct sockaddr *)server, addrLen); 

        printf("SeqNum Low, Sent Bytes %d\n", (int)bytesSent);
        return WAIT_FOR_SREJ_RESP;
    }
    else {
        return WAIT_FOR_SREJ_RESP;
    }
    printf("Shutting down in SREJ\n");
    return SHUTDOWN;
}

/*
int getData(char * buffer)
{
    // Read in the data
    buffer[0] = '\0';
    printf("Enter the data to send: ");
    scanf("%" xstr(MAXBUF) "[^\n]%*[^\n]", buffer);
    getc(stdin);  // eat the \n
        
    return (strlen(buffer)+ 1);
}
*/

void checkArgs(int argc, char * argv[], arguments *argu)
{
    /* check command line arguments  */
    char *endptr;
    if (argc != 8)
    {
        printf("usage: %s local-to-file remot-from-file window-size buffer-size error-percent host-name port-number \n", argv[0]);
        exit(1);
    }
    
    // Checks args and returns port number
    //int portNumber = 0;
    strcpy(argu->destFile, argv[1]);
    strcpy(argu->srcFile, argv[2]);
    argu->windowSize = atoi(argv[3]);
    argu->bufSize = atoi(argv[4]);
    argu->error = strtod(argv[5], &endptr);
    strcpy(argu->remoteMachine, argv[6]);
    argu->remotePort = atoi(argv[7]);
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




