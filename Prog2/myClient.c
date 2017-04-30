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
#define DEBUG_FLAG 1
#define xstr(a) str(a)
#define str(a) #a

void sendToServer(int socketNum);
void checkArgs(int argc, char * argv[]);

int main(int argc, char * argv[])
{
	int socketNum = 0;         //socket descriptor

	/* set up the TCP Client socket  */
	socketNum = tcpClientSetup(argv[1], argv[2], DEBUG_FLAG);
	
	sendToServer(socketNum);
	
	close(socketNum);
	
	return 0;
}

void sendToServer(int socketNum)
{
	char sendBuf[MAXBUF];   //data buffer
	int sendLen = 0;        //amount of data to send
	int sent = 0;            //actual amount of data sent/* get the data and send it   */
			
	printf("Enter the data to send: ");
	scanf("%" xstr(MAXBUF) "[^\n]%*[^\n]", sendBuf);
	
	sendLen = strlen(sendBuf) + 1;
	printf("read: %s len: %d\n", sendBuf, sendLen);
		
	sent =  send(socketNum, sendBuf, sendLen, 0);
	if (sent < 0)
	{
		perror("send call");
		exit(-1);
	}

	printf("String sent: %s \n", sendBuf);
	printf("Amount of data sent is: %d\n", sent);
}

void checkArgs(int argc, char * argv[])
{
	/* check command line arguments  */
	if (argc != 3)
	{
		printf("usage: %s host-name port-number \n", argv[0]);
		exit(1);
	}
}
