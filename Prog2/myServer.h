#ifndef MYSERVER_H
#define MYSERVER_H

#define HANDLE_LEN 256

typedef struct {
    int open;
    int fd;
    char handle[HANDLE_LEN];
} handle;

typedef struct {
    char len;
    char handle[HANDLE_LEN];
}target;

int main(int argc, char *argv[]);

void readLoop(int servFd);

void createHeader(char *packet, short len, char flag);

void tcpRecv(handle *table, int recvNdx, int numConnected);

void mError(char *sender, char senderLen, target *invalid, int sendFd);

void mParse(target *targets, char *numDest, 
 char *msg, char *sender, char *senderLen, char *recvBuf, int *msgLen);

void mReply(handle *table, target trg, char *msg, char *sender, char senderLen, 
 int tblSize, int msgLen);

void handleMReq(handle *table, char *recvBuf, int numConnected, int sendFd);

void handleLReq(handle *table, int numConnected, int clientFd);

void handleEReq(int socket, handle *table, int ndx);

void recvFromClient(int clientSocket);

int checkArgs(int argc, char *argv[]);

#endif
