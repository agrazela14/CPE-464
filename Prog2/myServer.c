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
//#define HANDLE_LEN 256
#define DEBUG_FLAG 1
#define BACKLOG_LEN 9

//For holding the handles that exist on the server
/*
typedef struct {
    int open;
    int clientFD;
    char handle[HANDLE_LEN];
} handle;

typedef struct {
    char len;
    char handle[HANDLE_LEN];
}target;
*/

int main(int argc, char *argv[]) {
	int serverSocket = 0;   //socket descriptor for the server socket
	//int clientSocket = 0;   //socket descriptor for the client socket
	short portNumber;
    
    //table of handles starts at 10, can be expanded by realloc
    //handle *table = malloc(10 * sizeof(handle));
	
	portNumber = checkArgs(argc, argv);
	
	//create the server socket
	serverSocket = tcpServerSetup(portNumber);

	// wait for client to connect
	//clientSocket = tcpAccept(serverSocket, DEBUG_FLAG);

	//recvFromClient(clientSocket);
    readLoop(serverSocket);
	
	/* close the sockets */
	//close(clientSocket);
	close(serverSocket);
    printf("Exited from main\n");
	return 0;
}

/*
int checkArgs(int argc, char **argv) {
    if (argc > 1) {
        return atoi(argv[1]);
    }
    return 0;
}
*/

/*
int tcpServerSetup(int portNum) {
   int fd = socket(AF_INET, SOCK_STREAM, 0);
   int err;
   int temp;
   socklen_t addrLen;

   if (fd < 0) {
       perror("error opening socket\n");
       exit(fd);
   }
   struct sockaddr_in addr;
   memset(&addr, 0, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr = INADDR_ANY;//Give an IP Address
   addr.sin_port = htons(portNum);//Give port num, 0 (default) for os to assign
   addrLen = sizeof(addr);
   
   //IDK about this struct
   err = bind(fd, (struct sockaddr *)&addr, addrLen); 
   if (err < 0) {
       perror("error binding socket\n");
       exit(err);
   }
   err = listen(fd, BACKLOG_LEN);
   if (err < 0) {
       perror("error listening on socket\n");
       exit(err);
   }
   temp = getsockname(fd, (struct sockaddr *)&addr, &addrLen);
   if (temp < 0) {
       perror("getsocketname error\n");
       exit(-1);
   }
   printf("IP is: %s Port Number is: %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

   return fd;
}
*/

void readLoop(int servFd) {
    int ndx, used = 0, clients = 10;
    int selection;
    fd_set fds;
    handle *table = malloc(clients * sizeof(handle));
    //struct sockaddr_in clientSock;
    //socklen_t clientSockLen = sizeof(clientSock);

    while (1) {
        FD_ZERO(&fds);
        FD_SET(servFd, &fds);

        for (ndx = 0; ndx < clients; ndx++) { 
            if (table[ndx].open != 0) {
                FD_SET(table[ndx].fd, &fds);
            }
        }
        //First parameter is number of FDs
        selection = select(clients + 1, &fds, NULL, NULL, NULL);
        if (selection < 0) {
            perror("Select Error\n");
            exit(-1);
        }
        
        //Check if we are waiting for a new connection
        if (FD_ISSET(servFd, &fds)) {
            //Using Dr.Smith's code instead
            table[used].fd =  tcpAccept(servFd, 1);/*accept(servFd, 
             (struct sockaddr *)&clientSock, &clientSockLen);*/
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
                //resize the table
                clients *= 2;
                table = realloc(table, clients * sizeof(handle));
            }
        }
        //Check to receive data by looking at each client fd
        //Types of packets that can be sent:
        //Initial Connection
        //M
        //L
        //E
        for (ndx = 0; ndx < used; ndx++) {
            if (FD_ISSET(table[ndx].fd, &fds)) {
                //There's a read on this fd
                //recvBytes = recv(table[ndx].fd, recvBuf, RECVSIZE, /*flags*/);
                tcpRecv(table, ndx, used);
            }
            /*
            if (recvBytes < 0) {
                perror("Recv Error\n");
                exit(-1);
            }
            if (buf[1].toupper() == 'M') {
                handleMReq(table, buf, table[ndx].handle);
            } 
            else if (buf[1].toupper() == 'L') {
                handleLReq(table, ndx);
            }
            if (buf[1].toupper() == 'E') {
                handleEReq(table, buf, table[ndx].handle);
            } 
            */
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
    //int totalOffset;
    int sendBytes;
    int recvBytes;
    short packetLen;
    char flag; 
    //char senderLen;
    //char numDest;
    //char sender[HANDLE_LEN];
    //char destLens[MAXDEST];
    //char dests[MAXDEST * HANDLE_LEN + MAXDEST];
    //char *tempDests = dests;
    //char *tempBuf = recvBuf;
    //char *targetHandle;
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
            /*
            sendBuf[0] = htons(3);
            sendBuf[2] = 2;
            */
            sendBytes = send(table[recvNdx].fd, sendBuf, 3, 0); 
            if (sendBytes != 3) {
                perror("Error sending initial response\n");
            }
            break;
        case 5: //Message
            handleMReq(table, recvBuf, numConnected, table[recvNdx].fd);
            /*
            totalOffset = 3;
            senderLen = *(recvBuf + totalOffset++);
            memcpy(sender, recvBuf + totalOffset, senderLen);
            totalOffset+= senderLen;
            numDest = *(recvBuf + totalOffset++);
            for (ndx = 0; ndx < numDest; ndx++) {
                targets[ndx].handleLen = *(recvBuf + totalOffset++);
                memcpy(targets[ndx].handle, recvBuf + totalOffset, targets[ndx].handleLen);
                targets[ndx].handle[(int)targets[ndx].handleLen] = '\0';
                totalOffset += targets[ndx].handleLen;
            }
            //Now the total Offset should lead to the actual message

            for (ndx = 0; ndx < numDest; ndx++) {
                for (ndx2 = 0; ndx2 < numConnected; ndx2++) {
                    if (strcmp(table[ndx2].handle, targets[ndx].handle) == 0) {
                        //send to this handle
                        printf("Sending to %s\n", table[ndx2].handle); 
                        memcpy(sendBuf, recvBuf + totalOffset, packetLen - totalOffset);
                        sendBytes = send(table[ndx2].fd, 
                         sendBuf, packetLen - totalOffset, 0);

                        printf("Sent %d Bytes\n", sendBytes);

                        if (sendBytes != packetLen - totalOffset) {
                            perror("Sent wrong # bytes\n");
                        }
                    }
                }
            }
            */

            break;
        case 8: //Exit
            //Do after Messaging to 3 clients is done 
            handleEReq(table[recvNdx].fd, table, recvNdx);
            break;
        case 10: //List
            //Do after Messaging to 3 clients is done 
            break;
        default:
            break;
    }
}

//Figure out the arguments needed for these
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
    
    //Put into the targets, numDest and msg all the approiate things 
    mParse(targets, &numDest, msg, sender, &senderLen, recvBuf, &msgLen);
    for (ndx = 0; ndx < numDest; ndx++) {
        found = 0;
        //This function just sends to 1 target
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
    //Recv: header
    //sender len
    //sender
    //numdest
    //len then dest for each numdest
    //msg
    //char packet[MAXBUF];
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
//Header
//Sender Len
//Sender
//Message
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
    //Remake this as 2 functions
    /*
    int ndx, ndx2, sendBytes;
    int totalOffset = 3;
    char senderLen;
    int numDest;
    char msgLen;
    short recvLen;
    short packetLen = 3;
    //char sender[HANDLE_LEN];
    char packet[MAXBUF];
    target targets[MAXDEST];
    
    printf("Recv M command\n");
    recvLen = ntohs(*(short *)(recvBuf)); 
    senderLen = *(recvBuf + totalOffset++);
    memcpy(packet + 3, &senderLen, 1);//sender size
    memcpy(packet + 4, recvBuf + totalOffset, senderLen);//sender
    totalOffset += senderLen;
    packetLen += senderLen + 1;

    numDest = *(recvBuf + totalOffset++);
    for (ndx = 0; ndx < numDest; ndx++) {
        targets[ndx].handleLen = *(recvBuf + totalOffset++);
        memcpy(targets[ndx].handle, recvBuf + totalOffset, targets[ndx].handleLen);
        targets[ndx].handle[(int)targets[ndx].handleLen] = '\0';
        printf("target found: %s\n", targets[ndx].handle);
        totalOffset += targets[ndx].handleLen;
    }
    //Now the total Offset should lead to the actual message
     
    for (ndx = 0; ndx < numDest; ndx++) {
        for (ndx2 = 0; ndx2 < numConnected; ndx2++) {
            printf("table holds: %s\n", table[ndx2].handle); 
            if (strcmp(table[ndx2].handle, targets[ndx].handle) == 0) {
                //Send:
                //Header
                //Sender Len
                //Sender handle
                //Msg, it'll know msg len by header
                //send to this handle
                printf("Sending to %s\n", table[ndx2].handle); 
                msgLen = recvLen - totalOffset;
                packetLen += msgLen;
                createHeader(packet, packetLen, 5);//header
                memcpy(packet + 3, &senderLen, 1);//Sender Len
                memcpy(packet + 4, table[ndx2].handle, senderLen);//Sender
                
                //After 3 byte header, 1 byte senderLengthField, and the length of the sender
                //memcpy(packet + 4 + senderLen, &msgLen, 1);//msg length
                memcpy(packet + 4 + senderLen, recvBuf + totalOffset, msgLen);//msg

                sendBytes = send(table[ndx2].fd, 
                 packet, packetLen, 0);

                printf("Sent %d Bytes\n", sendBytes);

                if (sendBytes != packetLen) {
                    perror("Sent wrong # bytes\n");
                }
            }
        }
    }
}
*/
/*
    //Send the message in as many packets as necessary to the targets
    char *endptr;
}

//Figure out the arguments needed for these
void handleMReq(handle *table, char *buf, char *senderHandle) {
    //Send the message in as many packets as necessary to the targets
    char *endptr;
    char **destHandles;
    long numDest;
    int ndx;
    
    buf += 2;
    while (*buf == ' ') {
        buf++;
    }
    numDest = strtol(buf, &endptr, 10); 
    if (buf == endptr) {
        //no numdest given, so it's just gonna be 1
        numDest = 1;
    }  

    for (ndx = 0; ndx < numDest; ndx++) {
        while (*buf == ' ') {
            buf++;
        }
        while (*buf != ' ') {
            **destHandles = *buf;
            buf++;
            *destHandles++;
        }
        **destHandles = '\0';
        destHandles++;
    }
    
    printf("Sender is %s, Destinations are ", senderHandle);
    for (ndx = 0; ndx < numDest; ndx++) {
        printf(" %s ", destHandles[ndx]);
        printf("\n");
    }
    printf("Sender is %s, Destinations are", senderHandle);
*/
void handleLReq(handle *table, int ndx) {
    //Send out all the packets in an 'L' Request 
    //to the client at the ndx index in table
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

/*
int tcpAccept(int serverSock, int debug) {
    return 0;     
}
*/

void recvFromClient(int clientSocket) {
	char buf[MAXBUF];
	int messageLen = 0;
	
	//now get the data from the client_socket
	if ((messageLen = recv(clientSocket, buf, MAXBUF, 0)) < 0)
	{
		perror("recv call");
		exit(-1);
	}

	printf("Message received, length: %d Data: %s\n", messageLen, buf);
}

int checkArgs(int argc, char *argv[]) {
	// Checks args and returns port number
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

