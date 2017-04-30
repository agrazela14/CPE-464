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
   if (fd < 0) {
       perror("error opening socket\n");
       exit(fd);
   }
   struct sockaddr_in addr;
   addr.sin_family = AF_INET6;
   addr.sin_addr.saddr = INADDR_ANY;//Give an IP Address
   addr.sin_.port = htons(portNum);//Give an IP Address

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
   return fd;
}

void readLoop() {
    int ndx, clients = 10;
    fdset Fds;
    handle *table = malloc(clients * sizeof(handle));
    while (1) {
        FD_ZERO(clientFds);
        FD_SET(servFd, &Fds);

        for (ndx = 0; ndx < clients, ndx++) { 
            if (table[ndx].flag != 0) {
                FD_SET(table[ndx].fd, &Fds);
            }
        }
     
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

