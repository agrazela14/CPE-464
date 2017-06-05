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

#define MAXBUF 80
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
STATE initConnection(arguments *argu, int sockNum, struct sockaddr_in6 *server);
STATE sendFilename(arguments *argu, int sockNum, struct sockaddr_in6 *server);
STATE readData(int *seqNum, FILE *outFile);
STATE srejReadData(int *seqNum, FILE *outFile);
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
    FILE *copyFile = fopen(argu->destFile, "w+");

    sendtoErr_init(argu->error, DROP_ON, FLIP_ON, DEBUG_ON, RSEED_ON);

    while (state != DONE) {
        
        switch (state) {
            case START:
                state = initConnection(argu, sockNum, server);
                break;

            case FILENAME:
                state = sendFilename(argu, sockNum, server);
                break;

            case WAIT_FOR_DATA:
                state = readData(&seqNum, copyFile); 
                break;

            case WAIT_FOR_SREJ_RESP:
                state = srejReadData(&seqNum, copyFile);
                break;

            case SHUTDOWN: //Do Cleanup
                close(sockNum);
                fclose(copyFile);
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
STATE initConnection(arguments *argu, int sockNum, struct sockaddr_in6 *server) {
    //Apparently Checksum works by just putting a 0 in the field and running the function
    //in_cksum() on the packet. 
    unsigned int addrLen = sizeof(*server);
    char buffer[16];
    char recvBuffer[16];
    int packetLen = createPacket(buffer, 0, 0, 1, 0, ""); 
    printf("Checksum = %d, packetLen: %d\n", in_cksum((unsigned short *)buffer, 10), packetLen);
    //Now get a checksum value
    packetLen = createPacket(buffer, 0, in_cksum((unsigned short *)buffer, 10), 1, 0, ""); 
    ssize_t bytesSent = sendtoErr(sockNum, buffer, packetLen, 0, 
     (struct sockaddr *)server, addrLen); 

    ssize_t bytesRecv = recvfrom(sockNum, recvBuffer, 10, 0, 
     (struct sockaddr *)server, &addrLen); 
    printf("Recv Flag: %hd, bytes Recv: %d bytes Sent: %d\n", 
     (short)recvBuffer[8], (int)bytesRecv, (int)bytesSent);
    return DONE;
} 

//send Filename
//Read for Filename response
//If you get a response Go on to Wait_For_Data state
//If you send fileName with no response 10 times go to Shutdown
//If you get the badFileName response, print error and go to shutdown
STATE sendFilename(arguments *argu, int sockNum, struct sockaddr_in6 *server) {
    
    return DONE;
} 

//Read for data packet
//If init success packet, go back to Filename state
//Else check that seqNum correct
//If correct, send RRseqNum, inc seqNum, continue in this state
//If too High, send SREJseqNum, go to Wait_for_srej_resp state
//If too low, discard data and RRSeqNum - 1 (Think more about this one)
STATE readData(int *seqNum, FILE *outFile) {

    return DONE;
}

//Read data packets
//If they aren't the data for seqNum, discard and do not respond
//If it is data for seqNum, RRseqNum, go to Wait_for_data state
STATE srejReadData(int *seqNum, FILE *outFile) {

    return DONE;
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




