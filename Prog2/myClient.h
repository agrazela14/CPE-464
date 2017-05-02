#ifndef MYCLIENT_H
#define MYCLIENT_H

#define MAXHANDLE 256

typedef struct {
    int blocked;
    char handle[MAXHANDLE];
} client;

int main(int argc, char * argv[]);

int tcpClientSetup(char *handle, char *serverName, int serverPort, int flags);

void initialPacket(char *handle, int fd);

void createHeader(char *packet, short len, char flag);

void clientLoop(int sockFd, char *handle, client *others, int *numClients, int *maxClients);

int recvFromServer(int sockFd);

void mRecv(char *recvBuf);

void mFailure(char *recvBuf);

int eRecv();

void lRecv();

void sendToServer(int socketNum, char *handle, client *others, int *numClients, int *maxClients);

int mCommand(char *buf, char *handle, int fd);

void sendMessage(int fd, char *msgStart, char *packet, char *msg, int bytes);

void seekMessage(char **msg, char *buf, int numHandles);

void bCommand(char *buf, client *clients, int *numClients, int *maxClients);

void uCommand(char *buf, client *clients, int *numClients, int *maxClients);

void lCommand();

void eCommand();

void checkArgs(int argc, char * argv[], char *handle, char *serverName, int *port);

#endif
