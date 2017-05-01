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
#include <netdb.h>

#include "networks.h"

#define MAXBUF 1024
#define HANDLE_LEN 256
#define DEBUG_FLAG 1
#define BACKLOG_LEN 9

void recvFromClient(int clientSocket);
int checkArgs(int argc, char *argv[]);

//For holding the handles that exist on the server
typedef struct {
    int flag;
    int clientFD;
    char handle[HANDLE_LEN];
} handle;

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
	clientSocket = tcpAccept(serverSocket, DEBUG_FLAG);

	recvFromClient(clientSocket);
	
	/* close the sockets */
	close(clientSocket);
	close(serverSocket);
	return 0;
}

int checkArgs(int argc, char **argv) {
    if (argc > 1) {
        return atoi(argv[1]);
    }
    return 0;
}

int tcpServerSetup(int portNum, char *name) {
   int fd = socket(AF_INET6, SOCK_STREAM, 0);
   int err;
   int temp;

   if (fd < 0) {
       perror("error opening socket\n");
       exit(fd);
   }
   struct sockaddr_in addr;
   addr.sin_family = AF_INET6;
   addr.sin_addr.saddr = INADDR_ANY;//Give an IP Address
   addr.sin_port = htons(portNum);//Give port num, 0 (default) for os to assign

   err = bind(fd, (struct *sockaddr)&addr, sizeof(struct sockaddr))//not sure about this struct  
   if (err < 0) {
       perror("error binding socket\n");
       exit(err);
   }
   err = listen(fd, BACKLOG_LEN);
   if (err < 0) {
       perror("error listening on socket\n");
       exit(err);
   }
   temp = getsocketname(fd, (struct *sockaddr)&addr, sizeof(struct sockaddr));
   if (temp < 0) {
       perror("getsocketname error\n");
       exit(-1);
   }
   printf("IP is: %s Port Number is: %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

   return fd;
}

void readLoop() {
    int ndx, used = 0, clients = 10;
    int selection;
    fdset fds;
    handle *table = malloc(clients * sizeof(handle));
    struct sockaddr_in clientSock;
    char recvBuf[RECVSIZE];

    while (1) {
        FD_ZERO(clientFds);
        FD_SET(servFd, &fds);

        for (ndx = 0; ndx < clients, ndx++) { 
            if (table[ndx].flag != 0) {
                FD_SET(table[ndx].fd, &fds);
            }
        }
        //First parameter is number of FDs
        selection = select(clients, fds, NULL, NULL, NULL);
        if (selection < 0) {
            perror("Select Error\n");
            exit(-1);
        }
        
        //Check if we are waiting for a new connection
        if (FD_ISSET(servFd, &fds)) {
            table[used].fd = accept(servFd, 
             (struct *sockaddr)&clientSock, sizeof(clientSock));
            if (table[used].fd < 0) {
                perror("Accept Error\n");
                exit(-1);
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
            if (FD_ISSET(table[ndx].fd)) {
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
    char recvBuf[RECVSIZE];
    int ndx, ndx2;
    int recvBytes = recv(table[recvNdx].fd, recvBuf, RECVSIZE, MSG_WAITALL);
    short packetLen = ntohs(*((short *)recvBuf));
    char flag = recvBuf + 2; 
    char senderLen;
    short packetLen = ntohs((short)(*(buf)));
    char numDest;
    char sender[HANDLE_LEN];
    char destLens[MAXDEST];
    char dests[MAXDEST * HANDLE_LEN];
    char *tempDests = dests;
    char *tempBuf = recvBuf;
    

    switch flag {
        case 1: //Initial Connection
            printf("initial Connection from %s\n", buf + 3);
            strcpy(table[ndx].handle, buf + 3); 
            break;
        case 5: //Message
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
                tempDests[destLens[ndx]] = '\0';
                tempDests += destLens[ndx] + 1;
            } 
            //search the table for the handle and retransmit
            for (ndx = 0; ndx < numDest; ndx++) {
                for (ndx2 = 0; ndx < numConnected; ndx2++) {
                    if (strcmp(table[ndx2].handle, dests[ndx]) == 0) {
                        //send to this client
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
}

void handleLReq(handle *table, int ndx) {
    //Send out all the packets in an 'L' Request 
    //to the client at the ndx index in table
}

void handleEReq(handle *table, char *buf, char *senderHandle) {

}

int tcpAccept(int serverSock, int debug) {
     
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

