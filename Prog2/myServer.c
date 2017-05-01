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

//#include "networks.h"
#include "myServer.h"

#define MAXBUF 1024
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
*/

int main(int argc, char *argv[])
{
	int serverSocket = 0;   //socket descriptor for the server socket
	int clientSocket = 0;   //socket descriptor for the client socket
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
	close(clientSocket);
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

void readLoop(int servFd) {
    int ndx, used = 0, clients = 10;
    int selection;
    fd_set fds;
    handle *table = malloc(clients * sizeof(handle));
    struct sockaddr_in clientSock;
    socklen_t clientSockLen = sizeof(clientSock);

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
            table[used].fd = accept(servFd, 
             (struct sockaddr *)&clientSock, &clientSockLen);
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

void tcpRecv(handle *table, int recvNdx, int numConnected) {
    char recvBuf[MAXBUF];
    int ndx, ndx2, sendBytes;
    int recvBytes = recv(table[recvNdx].fd, recvBuf, MAXBUF, 0 /*MSG_WAITALL*/);
    short packetLen = ntohs(*((short *)recvBuf));
    char flag = *(recvBuf + 2); 
    char senderLen;
    char numDest;
    char sender[HANDLE_LEN];
    char destLens[MAXDEST];
    char dests[MAXDEST * HANDLE_LEN + MAXDEST];
    char *tempDests = dests;
    char *tempBuf = recvBuf;
    char *targetHandle;
    char sendBuf[MAXBUF];

    if (recvBytes < 0) {
        perror("Recv error\n");
        exit(-1);
    }

    switch (flag) {
        case 1: //Initial Connection
            printf("initial Connection from %s\n", recvBuf + 3);
            memcpy(table[recvNdx].handle, (recvBuf + 3), packetLen - 3); 
            table[recvNdx].handle[packetLen - 2] = '\0';//null terminate
            sendBuf[0] = htons(3);
            sendBuf[2] = 2;
            sendBytes = send(table[recvNdx].fd, sendBuf, 3, 0); 
            if (sendBytes != 3) {
                perror("Error sending initial response\n");
            }
            break;
        case 5: //Message
            printf("Received Message command\n");
            tempBuf += 3;
            senderLen = *(tempBuf); 
            memcpy(sender, ++tempBuf, senderLen);
            tempBuf += senderLen;
            numDest = *(tempBuf++);
            //get all the destination lengths
            for (ndx = 0; ndx < numDest; ndx++) {
                destLens[ndx] = *(tempBuf++);
            }
            //Make a list of destinations to send to
            for (ndx = 0; ndx < numDest; ndx++) {
                memcpy(tempDests, tempBuf, destLens[ndx]);
                tempBuf += destLens[ndx];
                tempDests += destLens[ndx];
                *tempDests++ = '-';//for use with strtok
                /*
                tempDests[destLens[ndx]] = '\0';
                tempDests += destLens[ndx] + 1;
                */
            } 
            //search the table for the handle and retransmit
            for (ndx = 0; ndx < numDest; ndx++) {
                targetHandle = strtok(dests, "-");
                for (ndx2 = 0; ndx2 < numConnected; ndx2++) {
                    if (strcmp(table[ndx2].handle, targetHandle) == 0) {
                        //send to this client
                        printf("Sending to %s\n", table[ndx2].handle);
                        send(table[ndx2].fd, tempBuf, strlen(tempBuf), 0 /*MSG_DONTWAIT*/);
                    }
                }
             }

            break;
        case 8: //Exit
            //Do after Messaging to 3 clients is done 
            break;
        case 10: //List
            //Do after Messaging to 3 clients is done 
            break;
        default:
            break;
    }
}

//Figure out the arguments needed for these
void handleMReq(handle *table, char *buf, char *senderHandle) {
/*
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
}
void handleLReq(handle *table, int ndx) {
    //Send out all the packets in an 'L' Request 
    //to the client at the ndx index in table
}

void handleEReq(handle *table, char *buf, char *senderHandle) {

}

int tcpAccept(int serverSock, int debug) {
    return 0;     
}

void recvFromClient(int clientSocket)
{
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

int checkArgs(int argc, char *argv[])
{
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

