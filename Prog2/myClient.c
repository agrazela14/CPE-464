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

int main(int argc, char * argv[])
{
	int socketNum = 0;         //socket descriptor
    char handle[HANDLE_LEN];
    char serverName[HANDLE_LEN];
    char serverPort[MAXBUF];
    int numClients = 0, tableSize = 10;
    
    client *others = malloc(tableSize * sizeof(client));

    checkArgs(argc, argv, handle, serverName, serverPort);
	/* set up the TCP Client socket  */
	socketNum = tcpClientSetup(serverName, serverPort, DEBUG_FLAG);
    initialPacket(handle, socketNum);
	
	clientLoop(socketNum, handle, others, &numClients, &tableSize);
	
	close(socketNum);
    free(others);
	
	return 0;
}
/*
int tcpClientSetup(char *handle, char *serverName, int serverPort, int flags) {
    int fd, err;
    struct sockaddr_in addr;
    uint8_t IP;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    //Don't give an IP address, give a name
    //then use provided gethostbyname function to set IP address
    IP = gethostbyname(serverName);
    addr.sin_family = AF_INET;
    addr.sin_addr = IP;
    addr.sin_port = htons(serverPort);//Give port num, 0 (default) for os to assign


    if (fd < 0) {
        perror("socket error\n");
        exit(-1);
    }
    
    err = connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    
    if (err < 0) {
        perror("connect error\n");
        exit(-1);
    }
    
    initialPacket(handle, fd);
    return fd;
}
*/
void initialPacket(char *handle, int fd) {
    char packet[MAXBUF];
    char reply[MAXBUF];
    int size;
    
    createHeader(packet, (short)(strlen(handle) + 3), 1);
        
    memcpy(packet + 3, handle, strlen(handle)); 
    //now send our packet off!

    size = send(fd, packet, strlen(handle) + 3, 0);
    printf("Sent Initial Packet\n");
    if (size != strlen(handle) + 3) {
        fprintf(stderr, "initial Packet send, expected size %lu, got %d\n", 
         strlen(handle) + 3, size);
        exit(-1); 
    }
    //Now we need to receive a reply
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

void clientLoop(int sockFd, char *handle, client *others, int *numClients, int *maxClients) {
    int toExit = 0; 
    int toRead;
    fd_set serverSet;

    while (!toExit) {
        FD_ZERO(&serverSet);
        FD_SET(sockFd, &serverSet);
        FD_SET(STDIN_FILENO, &serverSet);
	    printf("$");

        toRead = select(sockFd + 1, &serverSet, NULL, NULL, NULL);
        printf("Number of FDs %d, should be 2\n", toRead);
        if (toRead < 0) {
            perror("Selection err\n");
            exit(-1);
        }
        
        if (FD_ISSET(sockFd, &serverSet)) {
            toExit = recvFromServer(sockFd);
        } 
        if (FD_ISSET(STDIN_FILENO, &serverSet)) {
            sendToServer(sockFd, handle, others, numClients, maxClients);
        }
        /*
        toExit = recvFromServer(sockFd);
        sendToServer(sockFd, handle, others, numClients, maxClients);
        */
    } 
}

int recvFromServer(int sockFd) {
    printf("Receive called\n");
	char recvBuf[MAXBUF];//data buffer
    short recvLen;
    int toExit = 0;
    int recvBytes;// = recv(sockFd, recvBuf, MAXBUF, 0); 
    /*
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
        printf("errno trapped\n");
        return toExit;
    }	
    */
    //Get the length of the incoming packet
    recvBytes = recv(sockFd, &recvLen, 2, MSG_WAITALL);
    //if (recvBytes != 2) {
    printf("Recv %d bytes\n", recvBytes);
    //}

    recvLen = ntohs(recvLen);
    recvBytes = recv(sockFd, recvBuf, recvLen - 2, MSG_WAITALL);
    printf("Recv %d bytes\n", recvBytes);

    if (recvBytes != recvLen) {
        perror("Wrong # bytes received\n");
    }
    
    printf("Recieved Something, flag = %d\n", recvBuf[0]);
    switch ((recvBuf[0])) {
        case 5: //Message Success
            mRecv(recvBuf + 1, recvLen); 
            break;
        case 7: //Message Failure
            mFailure(recvBuf);
            break;
        case 9: //Exit
            toExit = eRecv();
            break;
        case 11: //Start of List
            lRecv();
            break;
        default:
            break;
    }
    return toExit;
}

void mRecv(char *recvBuf, short packetLen) {
    char printBuf[MAXBUF];
    char sender[MAXHANDLE];
    char senderLen;
    int ndx;

    //Packet recv should be:
    //Header
    //SenderLen
    //Sender
    //Msg
    //packetLen = ntohs(*(short *)(recvBuf));
    printf("Recv Packet Len: %hd\n", packetLen);
    //recvBuf += 3;
    memcpy(&senderLen, recvBuf++, 1);
    memcpy(sender, recvBuf, senderLen);
    sender[(int)senderLen] = '\0';
    printf("Recv senderLen: %c, Recv Sender: %s\n", senderLen, sender);
    recvBuf += senderLen;
    //Now see if it's on the blocked list
    //But add that function later
    
    memcpy(printBuf, recvBuf, packetLen - 4 - senderLen);

    printBuf[packetLen - 4 - senderLen] = '\0';
    printf("Printing out the message: 1 FUCKING BYTE AT A TIME\n");
    printf("Strlen Printbuf = %d\n", strlen(printBuf));
    for (ndx = 0; ndx < strlen(printBuf); ndx++) {
        printf("%c", printBuf[ndx]);
    }
    printf("\n");
}

void mFailure(char *recvBuf) {

}

int eRecv() {
    return 0;
}

void lRecv() {

}

void sendToServer(int socketNum, char *handle, client *others, int *numClients, int *maxClients)
{
	char sendBuf[MAXBUF];   //data buffer
	int sendLen = 0;        //amount of data to send
    //int toExit = 0;
    	
	//printf("Enter the data to send: ");
	//printf("$");
	//scanf("%" xstr(MAXBUF) "[^\n]%*[^\n]", sendBuf);
    //scanf("%s", sendBuf);
    fgets(sendBuf, MAXBUF, stdin);
     
	sendLen = strlen(sendBuf) + 1;
	printf("read: %s len: %d\n", sendBuf, sendLen);
     
    switch (toupper(sendBuf[1])) {
        case 'M':
            mCommand(sendBuf, handle, socketNum); 
            break;
        case 'B':
            bCommand(sendBuf, others, numClients, maxClients);
            break;
        case 'U':
            uCommand(sendBuf, others, numClients, maxClients);
            break;
        case 'L':
            lCommand();
            break;
        case 'E':
            eCommand();
            break;
        default:
            break;
    }
    //fflush(stdin);
    memset(sendBuf, 0, MAXBUF);
    	
	//sent =  send(socketNum, sendBuf, sendLen, 0);
    /*
	if (sent < 0)
	{
		perror("send call");
		exit(-1);
	}

	printf("String sent: %s \n", sendBuf);
	printf("Amount of data sent is: %d\n", sent);
    */
    //return toExit;
}

int mCommand(char *buf, char *sender, int fd) {
    //Remake this function by taking the strlen
    //Of the buf, then adding up strlen token + 1 each token
    //That will get the offset to reach the actual message 
    char packet[MAXBUF];
    int msgOffset = 0; //This will eventually reach the message
    short totalLen = 3;
    //char *packetTemp = packet + 3;
    char *endPtr;
    char numHandles = strtol(buf + 2, &endPtr, 10);
    char *token;
    client handles[MAXTARGETS];
    char message[MAXBUF];
    char senderLen = strlen(sender);
    //int nonMsgLen, msgParts, msgLen; 
    int ndx, sendBytes, msgLen;
    
    token= strtok(buf, " ");
    msgOffset += strlen(token) + 1;
    printf("Token : %s, len: %d\n", token, (int)strlen(token));
    //Skip the %M
    //token = strtok(NULL, " ");
    //Maybe skip a number
    if (numHandles != 0) {
        token = strtok(NULL, " ");
        printf("Token : %s, len: %d\n", token, (int)strlen(token));
        msgOffset += strlen(token) + 1;
    }
    else {
        numHandles = 1;
    } 
    
    //seekMessage(&message, buf, numHandles); //message here might need to be a double pointer
    for (ndx = 0; ndx < numHandles; ndx++) {
        token = strtok(NULL, " ");
        printf("Token : %s, len: %d\n", token, (int)strlen(token));
        strcpy(handles[ndx].handle, token);
        handles[ndx].len = (char)strlen(token);
        msgOffset += strlen(token) + 1;
    } 
    //memcpy(message, token + 1, buf + strlen(buf) - token);
    if (strlen(buf + msgOffset) > MAXBUF) {
        fprintf(stderr, "Message too long\n");
        return -1;
    }
    printf("Message offset = %d\n", msgOffset);
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
    printf("Sent %d Bytes, should have sent %d\n", sendBytes, totalLen);
    /*
    *packetTemp = (char)strlen(handle);//SenderLen
    packetTemp++;
    memcpy(packetTemp, handle, strlen(handle));//Sender
    packetTemp += strlen(handle);
    *packetTemp = numHandles;//Num Targets
    packetTemp++;
    
    for (ndx = 0; ndx < numHandles; ndx++) {
        *packetTemp = strlen(handles[ndx]);//This Dest Len
        packetTemp++;
        memcpy(packetTemp, handles[ndx], strlen(handles[ndx]));//This Destin handle
        packetTemp += strlen(handles[ndx]);
    }
    
    nonMsgLen = packetTemp - packet; 
    if (nonMsgLen >= 1000) {
        perror("Everything up till the message was too long\n");
        return -1;
    }
    msgParts = (nonMsgLen <= 800) ? 200 : 1000 - nonMsgLen;
    msgLen = strlen(message);
    printf("Message = %s, length of that is %d\n", message, msgLen);
    //Now taking everything that's already in the header, we need to send
    //Possibly successive messages of at most 200 bytes 
    
    for (ndx = 0; ndx < ((msgLen / msgParts) > 1 ? msgLen / msgParts : 1); ndx++) {
        sendMessage(fd, packetTemp, packet, message + ndx * msgParts, 
         (msgLen - ndx * msgParts < msgParts) 
         ? msgLen - ndx * msgParts : msgParts);
        //message += msgParts; 
    }
    */
    return 0;
}

void sendMessage(int fd, char *msgStart, char *packet, char *msg, int bytes) {
    int len = msgStart - packet + bytes;
    int sent;
    printf("sending Message\n");
    createHeader(packet, len, 5);
    memcpy(msgStart, msg, bytes);
    sent = send(fd, packet, len, 0 /*MSG_DONTWAIT*/);
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

void bCommand(char *buf, client *clients, int *numClients, int *maxClients) {
    int found, ndx;
    char banHandle[MAXHANDLE];

    if (*numClients >= *maxClients) {
        *maxClients *= 2;
        clients = realloc(clients, *maxClients * sizeof(client));
    } 
    buf += 2;
    while (*buf == ' ') {
        buf++;
    }
    strcpy(banHandle, buf); 
    if (strlen(banHandle) != 0) {
        for (ndx = 0; ndx < *numClients; ndx++) { 
            if (strcmp(clients[ndx].handle, banHandle)) {
                if (clients[ndx].blocked) {
                    fprintf(stderr, "Block Failed, handle %s is already blocked\n"
                     , banHandle);
                }
                else {
                    clients[ndx].blocked = 1;
                }
                found = 1;
                break;
            }
        }
        if (!found) {
            (*numClients)++;
            strcpy(clients[*numClients].handle, banHandle);
            clients[*numClients].blocked = 1;
        }
    }

    printf("List of Blocked Users: \n");
    for (ndx = 0; ndx < *numClients; ndx++) { 
        if (clients[ndx].blocked == 1) {
            printf("%s\n", clients[ndx].handle);
        }
    }
}

void uCommand(char *buf, client *clients, int *numClients, int *maxClients) {

}

void lCommand() {

}

void eCommand() {

}

void checkArgs(int argc, char * argv[], char *handle, char *serverName, char *port)
{
	/* check command line arguments  */
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
    //*port = atoi(argv[3]);
}
