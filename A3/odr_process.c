#include "common.h"
#include "odr.h"
#include "api.h"

static FilePortMap filePortMap[100];
static int filePortMapCnt;
static int nextPortNo;

void initFilePortMap() {
    getFullPath(filePortMap[0].filePath, SER_FILE, sizeof(filePortMap[0].filePath), FALSE);
    filePortMap[0].portNo = SER_PORT;
    filePortMapCnt = 1;
    nextPortNo = 4000;
}

static int getPortNoByFilePath(char *filePath) {
    int i;

    for (i = 0; i < filePortMapCnt; i++) {
        if (strcmp(filePath, filePortMap[i].filePath) == 0) {
            return filePortMap[i].portNo;
        }
    }
    strcpy(filePortMap[i].filePath, filePath);
    filePortMap[i].portNo = nextPortNo++;
    filePortMapCnt++;

    return filePortMap[i].portNo;
}

static char* getFilePathByPortNo(int portNo) {
    int i;

    for (i = 0; i < filePortMapCnt; i++) {
        if (filePortMap[i].portNo == portNo) {
            return filePortMap[i].filePath;
        }
    }
    err_quit("Unknown Port number: %d", portNo);
    return NULL;
}

static int readUnixSocket(int sockfd, char *msg, char *destIP, int *destPort, bool *forceRedis, char *srcFile) {
    struct sockaddr_un sockAddr;
    ApiData apiData;
    int len;

    // Receive data from Client/Server
    len = sizeof(sockAddr);
    Recvfrom(sockfd, &apiData, sizeof(apiData), 0, (SA *) &sockAddr, &len);

    memcpy(msg, apiData.data, strlen(apiData.data));
    msg[strlen(apiData.data)] = '\0';
    memcpy(destIP, apiData.canonicalIP, strlen(apiData.canonicalIP));
    destIP[strlen(apiData.canonicalIP)] = '\0';
    *destPort = apiData.port;
    *forceRedis = apiData.forceRediscovery;
    strcpy(srcFile, sockAddr.sun_path);

    return strlen(msg);
}

static int writeUnixSocket(int sockfd, char *srcIP, int srcPort, int destPort, char *msg) {
    ApiData apiData;
    struct sockaddr_un destAddr;
    char *destFile;

    memcpy(apiData.data, msg, strlen(msg));
    apiData.data[strlen(msg)] = '\0';
    memcpy(apiData.canonicalIP, srcIP, strlen(srcIP));
    apiData.canonicalIP[strlen(srcIP)] = '\0';
    apiData.port = srcPort;
    apiData.forceRediscovery = FALSE;
    
    bzero(&destAddr, sizeof(destAddr));
    destAddr.sun_family = AF_LOCAL;
    strcpy(destAddr.sun_path, getFilePathByPortNo(destPort));

    // Send data to Client/Server
    Sendto(sockfd, &apiData, sizeof(apiData), 0, (SA *) &destAddr, sizeof(destAddr));
}

void processUnixPacket(int sockfd) {
    char msg[100], destIP[100], srcFile[1024];
    int srcPort, destPort;
    bool forceRedis;

    readUnixSocket(sockfd, msg, destIP, &destPort, &forceRedis, srcFile);
    srcPort = getPortNoByFilePath(srcFile);
    printf("\nPacket received on Unix Domain Socket\n");

    if (strcmp(destIP, hostIP) == 0) {
        // Send directly to destPort on local process
        printf("Sending packet to %s:%d\n", hostIP, destPort);
        writeUnixSocket(sockfd, hostIP, srcPort, destPort, msg);

    } else {
        // Create a data packet and route the packet to destination
        printf("ODR Routing Needed!\n");
    }
}

