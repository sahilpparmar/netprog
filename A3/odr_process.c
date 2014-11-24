#include "common.h"
#include "odr.h"
#include "api.h"

static FilePortMap filePortMap[100];
static int filePortMapCnt;
static int nextPortNo;
static int nextBroadCastID = FIRST_BCAST_ID;

int getNextBroadCastID() {
    return nextBroadCastID++;
}

void initFilePortMap() {
    // Save server filePath <-> portNo map
    getFullPath(filePortMap[0].filePath, SER_FILE, sizeof(filePortMap[0].filePath), FALSE);
    filePortMap[0].portNo = SER_PORT;
    filePortMap[0].timestamp = time(NULL);
    filePortMap[0].isValid = TRUE;

    filePortMapCnt = 1;
    nextPortNo = FIRST_CLI_PORTNO;
}

static int getPortNoByFilePath(char *filePath) {
    int i;

    // Check for server port number
    if (strcmp(filePath, filePortMap[0].filePath) == 0) {
        return filePortMap[0].portNo;
    }

    for (i = 1; i < filePortMapCnt; i++) {
        if (filePortMap[i].isValid) {
            if (difftime(time(NULL), filePortMap[i].timestamp) < FP_MAP_STALE_VAL) {
                if (strcmp(filePath, filePortMap[i].filePath) == 0) {
                    filePortMap[i].timestamp = time(NULL);
                    return filePortMap[i].portNo;
                }
            } else {
                filePortMap[i].isValid = FALSE;
                break;
            }
        } else {
            break;
        }
    }
    strcpy(filePortMap[i].filePath, filePath);
    filePortMap[i].portNo = nextPortNo++;
    filePortMap[i].timestamp = time(NULL);
    filePortMap[i].isValid = TRUE;
    if (i == filePortMapCnt) filePortMapCnt++;

    return filePortMap[i].portNo;
}

static char* getFilePathByPortNo(int portNo) {
    int i;

    for (i = 0; i < filePortMapCnt; i++) {
        if (filePortMap[i].portNo == portNo) {
            return filePortMap[i].filePath;
        }
    }
    err_msg("Unknown Port number: %d", portNo);
    return "unknown_file_path";
}

static int readUnixSocket(int sockfd, char *msg, char *destIP, int *destPort, bool *forceRedis, char *srcFile) {
    struct sockaddr_un sockAddr;
    ApiData apiData;
    int len;

    // Receive data from Client/Server
    len = sizeof(sockAddr);
    if (recvfrom(sockfd, &apiData, sizeof(apiData), 0, (SA *) &sockAddr, &len) < 0) {
        err_msg("Error in receiving Unix Domain packet");
    }

    memcpy(msg, apiData.data, strlen(apiData.data));
    msg[strlen(apiData.data)] = '\0';
    memcpy(destIP, apiData.canonicalIP, strlen(apiData.canonicalIP));
    destIP[strlen(apiData.canonicalIP)] = '\0';
    *destPort = apiData.port;
    *forceRedis = apiData.forceRediscovery;
    strcpy(srcFile, sockAddr.sun_path);

    return strlen(msg);
}

int writeUnixSocket(int sockfd, char *srcIP, int srcPort, int destPort, char *msg) {
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
    if (sendto(sockfd, &apiData, sizeof(apiData), 0, (SA *) &destAddr, sizeof(destAddr)) == -1) {
        err_msg("Error in sending Unix Domain packet");
    }
}

// Return 1 if packet needs to be routed through ODR 
int processUnixPacket(int sockfd, ODRPacket *packet) {
    char msg[100], destIP[100], srcFile[1024];
    int srcPort, destPort;
    bool forceRedis;

    readUnixSocket(sockfd, msg, destIP, &destPort, &forceRedis, srcFile);
    srcPort = getPortNoByFilePath(srcFile);
    printf("Packet received on Unix Domain Socket\n");

    if (strcmp(destIP, hostIP) == 0) {
        // Send directly to destPort on local process
        printf("Sending DATA to %s:%d (local machine)\n", hostIP, destPort);
        writeUnixSocket(sockfd, hostIP, srcPort, destPort, msg);
        return 0;
    } else {
        packet->type = DATA;
        strcpy(packet->sourceIP, hostIP);
        strcpy(packet->destIP, destIP);
        packet->sourcePort = srcPort;
        packet->destPort = destPort;
        packet->hopCount = 1;
        packet->broadID = 0;
        packet->Asent = FALSE;
        packet->forceRedisc = forceRedis;
        strcpy(packet->data, msg);

        return 1;
    }
}

