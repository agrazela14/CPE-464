/******************************************************************************
* tcp_client.c
*
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
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
#include <arpa/inet.h>
#include <netdb.h>

#include "networks.h"
#include "myClient.h"

#define MAXBUF 1024
#define MAXTARGETS 9
#define DEBUG_FLAG 1
#define xstr(a) str(a)
#define str(a) #a
#define HANDLE_LEN 256

int main(int argc, char * argv[]) {
	int socketNum = 0;         //socket descriptor
    char handle[HANDLE_LEN];
    char serverName[HANDLE_LEN];
    char serverPort[MAXBUF];
    int numClients = 0, tableSize = 10;
    
    client *block = malloc(tableSize * sizeof(client));

    checkArgs(argc, argv, handle, serverName, serverPort);
	/* set up the TCP Client socket  */
	socketNum = tcpClientSetup(serverName, serverPort, DEBUG_FLAG);
    initialPacket(handle, socketNum);
	
	clientLoop(socketNum, handle, block, &numClients, &tableSize);
	
	close(socketNum);
    free(block);
	
	return 0;
}

void initialPacket(char *handle, int fd) {
    char packet[MAXBUF];
    char reply[MAXBUF];
    int size;
    
    createHeader(packet, (short)(strlen(handle) + 3), 1);
        
    memcpy(packet + 3, handle, strlen(handle)); 

    size = send(fd, packet, strlen(handle) + 3, 0);
    printf("Sent Initial Packet\n");
    if (size != strlen(handle) + 3) {
        fprintf(stderr, "initial Packet send, expected size %lu, got %d\n", 
         strlen(handle) + 3, size);
        exit(-1); 
    }
    size = recv(fd, reply, 3, MSG_WAITALL);
    printf("Reply to initial packet received, flag = %d\n", reply[2]);
    if (size != 3) {
        fprintf(stderr, "initial Packet recv, expected size %d, got %d\n", 
         3, size);
        exit(-1); 
    }
    if (reply[2] != 2) {
        fprintf(stderr, "Bad Flag on initial recv: %d\n", reply[2]);
        exit(-1);
    }
}

void createHeader(char *packet, short len, char flag) {
    len = htons(len);
    memcpy(packet, &len, 2);
    packet[2] = flag;
} 

void clientLoop(int sockFd, char *handle, client *block, int *numClients, int *maxClients) {
    int toExit = 0; 
    int toRead;
    fd_set serverSet;

    while (!toExit) {
        printf("$");
        fflush(stdout);
        FD_ZERO(&serverSet);
        FD_SET(sockFd, &serverSet);
        FD_SET(STDIN_FILENO, &serverSet);

        toRead = select(sockFd + 1, &serverSet, NULL, NULL, NULL);
        if (toRead < 0) {
            perror("Selection err\n");
            exit(-1);
        }
        
        if (FD_ISSET(sockFd, &serverSet)) {
            toExit = recvFromServer(sockFd, block, numClients);
        } 
        if (FD_ISSET(STDIN_FILENO, &serverSet)) {
            sendToServer(sockFd, handle, block, numClients, maxClients);
        }
    } 
} 
int recvFromServer(int sockFd, client *block, int *numClients) {
	char recvBuf[MAXBUF];//data buffer
    short recvLen;
    int toExit = 0;
    int recvBytes;

    recvBytes = recv(sockFd, &recvLen, 2, MSG_WAITALL);

    recvLen = ntohs(recvLen);
    recvBytes = recv(sockFd, recvBuf, recvLen - 2, MSG_WAITALL);
    if (recvBytes < 0) {
        perror("recv Error\n");
    }

    switch ((recvBuf[0])) {
        case 5: //Message Success
            mRecv(recvBuf + 1, recvLen, block, numClients); 
            break;
        case 7: //Message Failure
            mFailure(recvBuf + 1);
            break;
        case 9: //Exit
            toExit = eRecv(recvBuf + 1);
            break;
        case 11: //Start of List
            lRecv(recvBuf + 1, sockFd);
            break;
        default:
            break;
    }
    return toExit;
}

//When a buffer makes it's way to here, it's already had its header read off
void mRecv(char *recvBuf, short packetLen, client *block, int *numClients) {
    char printBuf[MAXBUF];
    char sender[MAXHANDLE];
    char senderLen;
    int ndx;

    //Packet recv should be:
    //Header
    //SenderLen
    //Sender
    //Msg
    memcpy(&senderLen, recvBuf++, 1);
    memcpy(sender, recvBuf, senderLen);
    sender[(int)senderLen] = '\0';
    for (ndx = 0; ndx < *numClients; ndx++) {
        if (strcmp(block[ndx].handle, sender) == 0) {
            if (block[ndx].blocked) {
                return;
            }
        }
    }
    recvBuf += senderLen;
    
    memcpy(printBuf, recvBuf, packetLen - 4 - senderLen);

    printBuf[packetLen - 4 - senderLen] = '\0';
    for (ndx = 0; ndx < strlen(printBuf); ndx++) {
        printf("%c", printBuf[ndx]);
    }
    printf("\n");
}

void mFailure(char *recvBuf) {
    char handleLen = *recvBuf++;
    char handleBuf[HANDLE_LEN];
    
    memcpy(handleBuf, recvBuf, handleLen);
    handleBuf[(int)handleLen] = '\0';
    
    printf("Handle %s Does not Exist\n", handleBuf); 
}

int eRecv() {
    return 1;
}

void lRecv(char *buf, int sock) {
    int numHandles;
    int ndx;
    int recvBytes;
    char flag;
    short packetLen;
    char handleLen;
    char handle[HANDLE_LEN];
    char recvBuf[HANDLE_LEN];
    
    //This takes the flag = 10 call, next is a myriad of 11s  
    memcpy(&numHandles, buf, 4);        
    numHandles = ntohl(numHandles);
    printf("Listing Handles\n");
    
    for (ndx = 0; ndx < numHandles; ndx++) {

        recvBytes = recv(sock, &packetLen, 2, MSG_WAITALL); 
        packetLen = ntohs(packetLen);
        recvBytes = recv(sock, recvBuf, packetLen - 2, MSG_WAITALL);
        if (recvBytes != packetLen - 2) {
            fprintf(stderr, "Didn't receive enough in lrecv\n");
        }

        flag = recvBuf[0];//We can use to see if we get a 13 too early
        handleLen = recvBuf[1];
        memcpy(handle, recvBuf + 2, handleLen); 
        handle[(int)handleLen] = '\0';
        printf("%s\n", handle);
    } 

    recvBytes = recv(sock, &packetLen, 2, MSG_WAITALL); 
    packetLen = ntohs(packetLen);
    recvBytes = recv(sock, recvBuf, packetLen - 2, MSG_WAITALL);

    flag = recvBuf[0];//We can use to see if we get a 13 too early
    if (flag != 13) {
        printf("Flag isnt 13 when it should be, it's %c\n", flag);
    }
}

void sendToServer(int socketNum, char *handle, client *block, int *numClients, int *maxClients) {
	char sendBuf[MAXBUF];   //data buffer

    fgets(sendBuf, MAXBUF, stdin);
     
    switch (toupper(sendBuf[1])) {
        case 'M':
            mCommand(sendBuf, handle, socketNum); 
            break;
        case 'B':
            bCommand(sendBuf, block, numClients, maxClients);
            break;
        case 'U':
            uCommand(sendBuf, block, numClients, maxClients);
            break;
        case 'L':
            lCommand(socketNum);
            break;
        case 'E':
            eCommand(socketNum);
            break;
        default:
            break;
    }
    memset(sendBuf, 0, MAXBUF);
}

int mCommand(char *buf, char *sender, int fd) {
    char packet[MAXBUF];
    int msgOffset = 0; //This will eventually reach the message
    short totalLen = 3;
    char *endPtr;
    char numHandles = strtol(buf + 2, &endPtr, 10);
    char *token;
    client handles[MAXTARGETS];
    char message[MAXBUF];
    char senderLen = strlen(sender);
    int ndx, msgLen, sendBytes;
    
    token= strtok(buf, " ");
    msgOffset += strlen(token) + 1;
    if (numHandles != 0) {
        token = strtok(NULL, " ");
        msgOffset += strlen(token) + 1;
    }
    else {
        numHandles = 1;
    } 
    
    for (ndx = 0; ndx < numHandles; ndx++) {
        token = strtok(NULL, " ");
        strcpy(handles[ndx].handle, token);
        handles[ndx].len = (char)strlen(token);
        msgOffset += strlen(token) + 1;
    } 
    if (strlen(buf + msgOffset) > MAXBUF) {
        fprintf(stderr, "Message too long\n");
        return -1;
    }
    msgLen = strlen(buf + msgOffset);
    memcpy(message, buf + msgOffset, msgLen);  
    memcpy(packet + totalLen++, &senderLen, 1);
    memcpy(packet + totalLen, sender, senderLen); 
    totalLen += senderLen;
    memcpy(packet + totalLen++, &numHandles, 1);

    for (ndx = 0; ndx < numHandles; ndx++) {
        memcpy(packet + totalLen++, &handles[ndx].len, 1); 
        memcpy(packet + totalLen, handles[ndx].handle, handles[ndx].len);
        totalLen += handles[ndx].len;
    }

    //Now potentially break up the message
    //Actually fuck that for now  
    memcpy(packet + totalLen, message, msgLen);
    totalLen += msgLen;
    createHeader(packet, totalLen, 5);
    sendBytes = send(fd, packet, totalLen, 0); 
    if (sendBytes != totalLen) {
        perror("mCommand Send\n");
    }
    return 0;
}

void sendMessage(int fd, char *msgStart, char *packet, char *msg, int bytes) {
    int len = msgStart - packet + bytes;
    int sent;
    printf("sending Message\n");
    createHeader(packet, len, 5);
    memcpy(msgStart, msg, bytes);
    sent = send(fd, packet, len, 0);
    printf("Sent %d Bytes\n", sent);
    if (sent != len) {
        fprintf(stderr, "Send didn't send right amount %d, sent %d instead\n",
         len, sent);
        exit(-1);
    }
}

void seekMessage(char **msg, char *buf, int numHandles) {
    int cycles = numHandles;
    int ndx;

    if (numHandles != 1) {
        cycles += 1;
    }

    *msg = buf;

    for (ndx = 0; ndx < cycles; ndx++) {
        while (**msg == ' ') {
            (*msg)++;
        }
        while (**msg != ' ') {
            (*msg)++;
        }
    }
}

void bCommand(char *buf, client *block, int *numClients, int *maxClients) {
    int found = 0, ndx;
    char banHandle[MAXHANDLE];
    
    printf("There are %d clients on the ban list\n", *numClients);
    if (*numClients >= *maxClients) {
        *maxClients *= 2;
        block = realloc(block, *maxClients * sizeof(client));
    } 
    buf += 2;
    while (*buf == ' ') {
        buf++;
    }
    strcpy(banHandle, buf); 
    banHandle[strlen(banHandle) - 1] = '\0';
    printf("Ban Handle = %s\n", banHandle);
    if (strlen(banHandle) != 0) {
        for (ndx = 0; ndx < *numClients; ndx++) { 
            if (strcmp(block[ndx].handle, banHandle) == 0) {
                if (block[ndx].blocked) {
                    fprintf(stderr, "Block Failed, handle %s is already blocked\n"
                     , banHandle);
                }
                else {
                    block[ndx].blocked = 1;
                }
                found = 1;
                break;
            }
        }
        if (!found) {
            strcpy(block[*numClients].handle, banHandle);
            printf("Banned %s\n", block[*numClients].handle);
            block[*numClients].blocked = 1;
            (*numClients)++;
        }
    }
    else {
        fprintf(stderr, "No handle to ban provided\n");
    }
    
    printf("List of Blocked Users: \n");
    for (ndx = 0; ndx < *numClients; ndx++) { 
        if (block[ndx].blocked == 1) {
            printf("%s ", block[ndx].handle);
        }
    }
    printf("\n");
}

void uCommand(char *buf, client *block, int *numClients, int *maxClients) {
    int ndx;
    int found = 0;
    char unBanHandle[MAXHANDLE];
    
    strcpy(unBanHandle, buf + 3);
    unBanHandle[strlen(buf + 3) - 1] = '\0'; 

    for (ndx = 0; ndx < *numClients; ndx++) {
        if (strcmp(block[ndx].handle, unBanHandle) == 0) {
            if (block[ndx].blocked == 1) {
                block[ndx].blocked = 0; 
                found = 1;
            }
        }
    }
    if (!found) {
        fprintf(stderr, "Unblock Failed, Handle %s is not blocked\n", unBanHandle);
    }
}

void lCommand(int socket) {
    char packet[3];
    int sendBytes;

    createHeader(packet, 3, 10);
    sendBytes = send(socket, packet, 3, 0); 

    if (sendBytes != 3) { 
        fprintf(stderr, "Error in List sending\n");
    }
}

void eCommand(int socket) {
    char packet[3];
    int sendBytes;

    createHeader(packet, 3, 8);
    sendBytes = send(socket, packet, 3, 0); 

    if (sendBytes != 3) { 
        fprintf(stderr, "Error in List sending\n");
    }
}

void checkArgs(int argc, char * argv[], char *handle, char *serverName, char *port) {
	if (argc != 4)
	{
		printf("usage: %s host-name port-number \n", argv[0]);
		exit(-1);
	}
    
    if (strlen(argv[1]) > MAXHANDLE) {
        perror("Handle too long, 250 character max\n");
        exit(-1);
    }
    strcpy(handle, argv[1]);
    strcpy(serverName, argv[2]);
    strcpy(port, argv[3]);
}
