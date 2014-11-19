#include "common.h"
#include "api.h"

void printApiData(ApiData *data) {
    printf("\nAPIDATA:\n");
    printf("data => %s\n", data->data);
    printf("IP => %s\n", data->canonicalIP);
    printf("PortNo => %d\n", data->port);
    printf("ForceRediscovery => %s\n", data->forceRediscovery ? "TRUE" : "FALSE");
}

void msg_send(int sockfd, char *destIP, int destPort, char *msg, int forceRediscovery) {
    ApiData apiData;
    struct sockaddr_un destAddr;
    char buffer[1024];

    memcpy(apiData.data, msg, strlen(msg));
    memcpy(apiData.canonicalIP, destIP, strlen(destIP));
    apiData.port = destPort;
    apiData.forceRediscovery = forceRediscovery;
    
    bzero(&destAddr, sizeof(destAddr));
    destAddr.sun_family = AF_LOCAL;
    strcpy(destAddr.sun_path, getFullPath(buffer, ODR_FILE, sizeof(buffer), FALSE));

    // Send data to ODR
    Sendto(sockfd, &apiData, sizeof(apiData), 0, (SA *) &destAddr, sizeof(destAddr));
}

int msg_recv(int sockfd, char *msg, char *srcIP, int *srcPort) {
    ApiData apiData;

    // Receive data from ODR
    Recvfrom(sockfd, &apiData, sizeof(apiData), 0,  NULL, NULL);

    memcpy(msg, apiData.data, strlen(apiData.data));
    memcpy(srcIP, apiData.canonicalIP, strlen(apiData.canonicalIP));
    *srcPort = apiData.port;

    return strlen(msg);
}

