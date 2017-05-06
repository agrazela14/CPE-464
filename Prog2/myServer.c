/******************************************************************************
* tcp_server.c
*
* CPE 464 - Program 1
*****************************************************************************/

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
#include <arpa/inet.h>
#include <netdb.h>

#include "networks.h"
#include "myServer.h"

#define MAXBUF 1024
#define MAXMSG 200 
#define MAXDEST 9 
#define DEBUG_FLAG 1
#define BACKLOG_LEN 9

int main(int argc, char *argv[]) {
	int serverSocket = 0;   //socket descriptor for the server socket
	short portNumber;
    
	portNumber = checkArgs(argc, argv);
	
	serverSocket = tcpServerSetup(portNumber);

    readLoop(serverSocket);
	
	close(serverSocket);
    printf("Exited from main\n");
	return 0;
}


void readLoop(int servFd) {
    int ndx, used = 0, clients = 10;
    int selection;
    fd_set fds;
    handle *table = malloc(clients * sizeof(handle));

    while (1) {
        FD_ZERO(&fds);
        FD_SET(servFd, &fds);

        for (ndx = 0; ndx < clients; ndx++) { 
            if (table[ndx].open != 0) {
                FD_SET(table[ndx].fd, &fds);
            }
        }
        selection = select(clients + 1, &fds, NULL, NULL, NULL);
        if (selection < 0) {
            perror("Select Error\n");
            exit(-1);
        }
        
        if (FD_ISSET(servFd, &fds)) {
            table[used].fd =  tcpAccept(servFd, 1); 
            table[used].open = 1;
            if (table[used].fd < 0) {
                perror("Accept Error\n");
                exit(-1);
            }
            else {
                printf("Accept Success\n");
            }
            used++;
            if (used >= clients) {
                clients *= 2;
                table = realloc(table, clients * sizeof(handle));
            }
        }
        for (ndx = 0; ndx < used; ndx++) {
            if (FD_ISSET(table[ndx].fd, &fds)) {
                tcpRecv(table, ndx, used);
            }
        }
    } 
    free(table);
}

void createHeader(char *packet, short len, char flag) {
    len = htons(len);
    memcpy(packet, &len, 2);
    packet[2] = flag;
}

void tcpRecv(handle *table, int recvNdx, int numConnected) {
    char recvBuf[MAXBUF];
    int sendBytes;
    int recvBytes;
    short packetLen;
    char flag; 
    char sendBuf[MAXBUF];

    memset(recvBuf, 0, MAXBUF);
    memset(sendBuf, 0, MAXBUF);
    
    recvBytes = recv(table[recvNdx].fd, (char *)recvBuf, 2, MSG_WAITALL);
    if (recvBytes != 2) {
        perror("recv wrong # bytes\n");
        fprintf(stderr, "Bytes Recv: %d\n", recvBytes);
    }
    packetLen = ntohs(*((short *)recvBuf));
    printf("recv first 2 bytes, packetLen = %hd\n", packetLen);
    
    recvBytes = recv(table[recvNdx].fd, (char *)(recvBuf + 2), packetLen - 2, MSG_WAITALL);
    if (recvBytes != 2) {
        perror("recv wrong # bytes\n");
        fprintf(stderr, "Bytes Recv: %d\n", recvBytes);
    }
    printf("recv second %d bytes\n", (int)packetLen - 2);
    flag = *(recvBuf + 2); 

    if (recvBytes < 0) {
        perror("Recv error\n");
        exit(-1);
    }

    switch (flag) {
        case 1: //Initial Connection
            printf("initial Connection from %s\n", recvBuf + 3);
            memcpy(table[recvNdx].handle, (recvBuf + 3), packetLen - 3); 
            table[recvNdx].handle[packetLen - 2] = '\0';//null terminate
            createHeader(sendBuf, 3, 2);
            sendBytes = send(table[recvNdx].fd, sendBuf, 3, 0); 
            if (sendBytes != 3) {
                perror("Error sending initial response\n");
            }
            break;
        case 5: //Message
            handleMReq(table, recvBuf, numConnected, table[recvNdx].fd);
            break;
        case 8: //Exit
            handleEReq(table[recvNdx].fd, table, recvNdx);
            break;
        case 10: //List
            handleLReq(table, numConnected, table[recvNdx].fd);
            break;
        default:
            break;
    }
}

void handleMReq(handle *table, char *recvBuf, int numConnected, int sendFd) {
    //To each target send:
    //The header
    //The size of the sender
    //The sender
    //The Message

    target targets[MAXDEST]; 
    char msg[MAXMSG];
    char numDest;
    char sender[HANDLE_LEN];
    char senderLen;
    char found;
    int msgLen, ndx, ndx2;
    
    mParse(targets, &numDest, msg, sender, &senderLen, recvBuf, &msgLen);
    for (ndx = 0; ndx < numDest; ndx++) {
        found = 0;
        for (ndx2 = 0; ndx2 < numConnected; ndx2++) {
            if (strcmp(targets[ndx].handle, table[ndx2].handle) == 0) {
                mReply(table, targets[ndx], msg, sender, senderLen, numConnected, msgLen);
                found = 1;
                break;
            }
        }
        if (!found) {
            mError(sender, senderLen, &targets[ndx], sendFd);
        }
    }
}    

void mError(char *sender, char senderLen, target *invalid, int sendFd) {
    char packet[MAXBUF];
    short totalLen = 4 + senderLen + invalid->len;    
    int sendBytes;

    createHeader(packet, totalLen, 7);
    packet[3] = invalid->len;
    memcpy(packet + 4, invalid->handle, invalid->len);
    sendBytes = send(sendFd, packet, totalLen, 0);

    if (sendBytes != totalLen) {
        fprintf(stderr, "Error sending flag 7 packet\n");
    }
}


void mParse(target *targets, char *numDest, 
 char *msg, char *sender, char *senderLen, char *recvBuf, int *msgLen) {
    short recvLen;
    int totalOffset = 3, ndx;
    
    recvLen = ntohs(*(short *)(recvBuf)); 
    *senderLen = *(recvBuf + totalOffset++);
    memcpy(sender, recvBuf + totalOffset, *senderLen); 
    totalOffset += *senderLen;
    *numDest = *(recvBuf + totalOffset++);

    for (ndx = 0; ndx < *numDest; ndx++) {
        memcpy(&(targets[ndx].len), recvBuf + totalOffset++, 1); 
        memcpy((targets[ndx].handle), recvBuf + totalOffset, targets[ndx].len); 
        targets[ndx].handle[(int)targets[ndx].len] = '\0'; 
        totalOffset += targets[ndx].len;
    }

    memcpy(msg, recvBuf + totalOffset, recvLen - totalOffset);
    *msgLen = recvLen - totalOffset;

}

void mReply(handle *table, target trg, char *msg, char *sender, char senderLen, 
 int tblSize, int msgLen) {
    int ndx, totalOffset = 3, sendBytes;
    char packet[MAXBUF];

    for (ndx = 0; ndx < tblSize; ndx++) {
        if (strcmp(table[ndx].handle, trg.handle) == 0) {
            createHeader(packet, msgLen + senderLen + 4, 5);
            memcpy(packet + totalOffset++, &senderLen, 1);
            memcpy(packet + totalOffset, sender, senderLen);
            totalOffset += senderLen;
            memcpy(packet + totalOffset, msg, msgLen);
            sendBytes = send(table[ndx].fd, packet, msgLen + senderLen + 4, 0);
            if (sendBytes != msgLen + senderLen + 4) {
                perror("Send err in M reply\n");
            }
            msg[msgLen] = '\0';
            printf("Sent %s\n", msg);
            printf("Sent %d, shoulda been %d\n", sendBytes, msgLen + senderLen + 4);
        }
    } 
} 

void handleLReq(handle *table, int numConnected, int clientFd) {
    //First get the header only packet with flag 10
    //Then send numConnected in network order with flag 11
    //Then for each of those send header, handleLen, handle
    //Then send header only flag = 13
    char packet[MAXBUF];
    int sendBytes, ndx;
    int conNOrder;
    int handleLen;
    
    //Send flag = 11 packet telling how many there are
    createHeader(packet, 3 + sizeof(int), 11);
    conNOrder = htonl(numConnected);
    memcpy(packet + 3, &conNOrder, sizeof(int));

    sendBytes = send(clientFd, packet, 3 + sizeof(int), 0);
    
    //Send each flag = 12 packet individually
    for (ndx = 0; ndx < numConnected; ndx++) {
        handleLen = strlen(table[ndx].handle);
        createHeader(packet, handleLen + 4, 12);
        memcpy(packet + 3, &handleLen, 1); 
        memcpy(packet + 4, table[ndx].handle, handleLen); 
        sendBytes = send(clientFd, packet, handleLen + 4, 0);
        if (sendBytes != handleLen + 4) {
            fprintf(stderr, "Error sending flag = 12 packets\n");
        }
    } 
    //Send the flag = 13 packet that ends it all
    createHeader(packet, 3, 13);
    sendBytes = send(clientFd, packet, 3, 0);
}

void handleEReq(int socket, handle *table, int ndx) {
    char packet[3];
    int sendBytes;
    
    createHeader(packet, 3, 9);
    sendBytes = send(socket, packet, 3, 0);

    table[ndx].open = 0;
    close(table[ndx].fd); 


    if (sendBytes != 3) {
        fprintf(stderr, "Error in Exit sending, sent %d Bytes\n", sendBytes);
    }
}

void recvFromClient(int clientSocket) {
	char buf[MAXBUF];
	int messageLen = 0;
	
	if ((messageLen = recv(clientSocket, buf, MAXBUF, 0)) < 0)
	{
		perror("recv call");
		exit(-1);
	}

	printf("Message received, length: %d Data: %s\n", messageLen, buf);
}

int checkArgs(int argc, char *argv[]) {
	int portNumber = 0;

	if (argc > 2)
	{
		fprintf(stderr, "Usage %s [optional port number]\n", argv[0]);
		exit(-1);
	}
	
	if (argc == 2)
	{
		portNumber = atoi(argv[1]);
	}
	
	return portNumber;
}

