#ifndef MYSERVER_H
#define MYSERVER_H

#define HANDLE_LEN 256

typedef struct {
    int open;
    int fd;
    char handle[HANDLE_LEN];
} handle;

int main(int argc, char *argv[]);

int tcpServerSetup(int portNum);

void readLoop(int servFd);

void createHeader(char *packet, short len, char flag);

void tcpRecv(handle *table, int recvNdx, int numConnected);

void handleMReq(handle *table, char *recvBuf, int numConnected);

void handleLReq(handle *table, int ndx);

void handleEReq(handle *table, char *buf, char *senderHandle);

int tcpAccept(int serverSock, int debug);

void recvFromClient(int clientSocket);

int checkArgs(int argc, char *argv[]);

#endif
