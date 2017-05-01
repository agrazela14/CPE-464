/******************************************************************************
* tcp_client.c
*
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
#include <netdb.h>

#include "networks.h"

#define MAXBUF 1024
#define MAXHANDLE 250 
#define DEBUG_FLAG 1
#define xstr(a) str(a)
#define str(a) #a
#define HANDLE_LEN 256

typedef struct {
    int blocked;
    char handle[MAXHANDLE];
} client;

void sendToServer(int socketNum);
void checkArgs(int argc, char * argv[]);

int main(int argc, char * argv[])
{
	int socketNum = 0;         //socket descriptor
    char handle[HANDLE_LEN];
    char serverName[HANDLE_LEN];
    int serverPort, numClients = 0, tableSize = 10;
    client *others = malloc(tableSize * sizeof(client));

    checkArgs(argc, argv, handle, serverName, &serverPort);
	/* set up the TCP Client socket  */
	socketNum = tcpClientSetup(handle, serverName, serverPort DEBUG_FLAG);
	
	clientLoop(socketNum, handle, others, &numClients, &tableSize);
	
	close(socketNum);
    free(others);
	
	return 0;
}

int tcpClientSetup(char *handle, char *serverName, int serverPort, int flags) {
    int fd, err;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET6;
    addr.sin_addr.saddr = inet_aton(serverName);//Give an IP Address
    addr.sin_port = htons(serverPort);//Give port num, 0 (default) for os to assign

    fd = socket(AF_INET6, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket error\n");
        exit(-1);
    }
    
    err = connect(fd, (struct *sockaddr)&addr, sizeof(struct sockaddr));
    
    if (err < 0) {
        perror("connect error\n");
        exit(-1);
    }
    
    initialPacket(handle, fd);
    return fd;
}

void initialPacket(char *handle, int fd) {
    char packet[MAXBUF];
    char reply[MAXBUF];
    int size;
    
    createHeader(packet, (short)(strlen(handle) + 3), 1);
        
    memcpy(packet + 3, handle, strlen(handle)); 
    //now send our packet off!

    size = send(fd, packet, strlen(handle) + 3, );
    if (size != strlen(handle) + 3) {
        fprintf(stderr, "initial Packet send, expected size %d, got %d\n", 
         strlen(handle) + 3, size);
        exit(-1); 
    }
    //Now we need to receive a reply
    size = recv(fd, reply, 3, MSG_WAITALL);
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
    packet[0] = htons(len);
    packet[2] = flag;
} 

void clientLoop(int sockFd, char *handle, client *others, int *numClients, int *maxClients) {
    int exit = 1 
    while (!exit) {
        exit = sendToServer(sockFd, handle, others, numClients, maxClients);
    } 
}

int sendToServer(int socketNum, char *handle, client *others, int *numClients, int *maxClients)
{
	char sendBuf[MAXBUF];   //data buffer
	int sendLen = 0;        //amount of data to send
	int sent = 0;            //actual amount of data sent/* get the data and send it   */
    int exit = 1;
			
	printf("Enter the data to send: ");
	scanf("%" xstr(MAXBUF) "[^\n]%*[^\n]", sendBuf);
	
	sendLen = strlen(sendBuf) + 1;
	printf("read: %s len: %d\n", sendBuf, sendLen);
    
    switch (toupper(sendBuf[1])) {
        case 'M':
            mCommand(sendBuf, client, sockNum); 
            break;
        case 'B':
            bCommand(sendBuf, clients, numClients, maxClients);
            break;
        case 'U':
            uCommand(sendBuf, clients, numClients, maxClients);
            break;
        case 'L':
            lCommand();
            break;
        case 'E':
            eCommand();
            break;
        default:
            break;
    	
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
    return exit;
}

int mCommand(char *buf, char *handle, int fd) {
    char packet[MAXBUF];
    char *packetTemp = packet + 3;
    char numHandles = strtol(buf + 2);
    char *token;
    char *handles[MAXHANDLE];
    char *message;
    int totalLen = 3;
    int nonMsgLen, msgParts, msgLen;
    
    token = strtok(buf, " ");
    //Skip the %M
    token = strtok(NULL, " ");
    //Maybe skip a number
    if (numHandles != 0) {
        token = strtok(NULL, " ");
    }
    else {
        numHandles = 1;
    } 
    
    seekMessage(&message, buf, numHandles); //message here might need to be a double pointer
    for (ndx = 0; ndx < numHandles; ndx++) {
        strcpy(handles[ndx], token);
        token = strtok(NULL, " ");
    } 

    *packetTemp = strlen(handle);
    packetTemp++;
    memcpy(packetTemp, handle, strlen(handle));
    packetTemp += strlen(handle);
    *packetTemp = numHandles;
    packetTemp++;

    for (ndx = 0; ndx < numHandles; ndx++) {
        *packetTemp = strlen(handles[ndx]);
        packetTemp++;
        memcpy(packetTemp, handles[ndx], strlen(handles[ndx]));
        packetTemp += strlen(handles[ndx]);
    }
    
    nonMsgLen = packetTemp - packet; 
    if (nonMsgLen >= 1000) {
        perror("Everything up till the message was too long\n");
        return -1;
    }
    msgParts = (nonMsgLen <= 800) ? 200 : 1000 - nonMsgLen;
    msgLen = strlen(message);
    //Now taking everything that's already in the header, we need to send
    //Possibly successive messages of at most 200 bytes 

    for (ndx = 0; ndx < msgLen / msgParts; ndx++) {
        sendMessage(fd, packetTemp, packet, message, 
         (msgLen - ndx * msgParts < msgParts) 
         ? msgLen - ndx * msgParts : msgParts);
        message += msgParts; 
    }
    createHeader(packet, totalLen, 5); 
}

void sendMessage(int fd, char *msgStart, char *packet, int bytes) {
    int len = msgStart - packet + bytes;
    createHeader(packet, len, 5);
    memcpy(msgStart, msg, bytes);
    send(fd, packet, len, MSG_DONTWAIT);
}

void seekMessage(char **msg, char *buf, int numHandles) {
    int cycles = numHandles + 1;
    if (numHandles != 1) {
        cycles += 1;
    }

    msg = buf;

    for (ndx = 0; ndx < cycles; ndx++) {
        while (**msg == ' ') {
            *msg++;
        }
        while (**msg != ' ') {
            *msg++;
        }
    }
}

void bCommand(char *buf, client *clients, int numClients, int *maxClients) {
    int found, ndx;
    char banHandle[MAXHANDLE];

    if (numClients >= *maxClients) {
        *maxClients *= 2;
        clients = realloc(clients, *maxClients * sizeof(client));
    } 
    buf += 2;
    while (*buf == ' ') {
        buf++;
    }
    strcpy(banHandle, buf); 
    if (strlen(banHandle != 0)) {
        for (ndx = 0; ndx < numClients; ndx++) { 
            if (strcmp(clients[ndx].handle, banHandle)) {
                if (clients[ndx].blocked) {
                    perror("Block Failed, handle %s is already blocked\n", banHandle);
                }
                else {
                    clients[ndx].blocked = 1;
                }
                found = 1;
                break;
            }
        }
        if (!found) {
            numClients++;
            strcpy(clients[numClients].handle, banHandle);
            clients[numClients].blocked = 1;
        }
    }

    printf("List of Blocked Users: \n");
    for (ndx = 0; ndx < numClients; ndx++) { 
        if (clients[ndx].blocked = 1;) {
            printf("%s\n", clients[ndx].handle);
        }
    }
}

void uCommand(char *buf, client *clients, int numClients, int *maxClients) {

}

void lCommand() {

}

void eCommand() {

}

void checkArgs(int argc, char * argv[], char *handle, char *serverName, int *port )

{
	/* check command line arguments  */
	if (argc != 4)
	{
		printf("usage: %s host-name port-number \n", argv[0]);
		exit(1);
	}
    
    if (strlen(argv[1] > MAXHANDLE)) {
        perror("Handle too long, 250 character max\n");
        exit(1);
    }
    strcpy(handle, argv[1]);
    strcpy(serverName, argv[2]);
    *port = atoi(argv[3]);
    
}
