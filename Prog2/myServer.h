#ifndef MYSERVER_H
#define MYSERVER_H

int main(int argc, char *argv[]);

int checkArgs(int argc, char **argv);

int tcpServerSetup(int portNum, char *name);

void readLoop();

void tcpRecv(handle *table, int recvNdx, int numConnected);

void handleMReq(handle *table, char *buf, char *senderHandle);

void handleLReq(handle *table, int ndx);

void handleEReq(handle *table, char *buf, char *senderHandle);

int tcpAccept(int serverSock, int debug);

void recvFromClient(int clientSocket);

int checkArgs(int argc, char *argv[]);

