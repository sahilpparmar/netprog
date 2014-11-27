#include "utils.h"
#include "unp.h"
int getVmNodeByIP(char *ip) {
    struct hostent *hostInfo = NULL;
    struct in_addr ipInfo;
    int node = 0;

    if (inet_pton(AF_INET, ip, &ipInfo) > 0) {
        hostInfo = gethostbyaddr(&ipInfo, sizeof(ipInfo), AF_INET);
        sscanf(hostInfo->h_name, "vm%d", &node);
    }
    return node;
}

char* getIPByVmNode(char *ip, int node) {
    struct hostent *hostInfo = NULL;
    char hostName[100];

    sprintf(hostName, "vm%d", node);
    hostInfo = gethostbyname(hostName);

    if (hostInfo && inet_ntop(AF_INET, hostInfo->h_addr, ip, INET_ADDRSTRLEN))
        return ip;
    else
        return NULL;
}

int getHostVmNodeNo() {
    char hostname[1024];
    int nodeNo;

    gethostname(hostname, 10);
    nodeNo = atoi(hostname+2);
    if (nodeNo < 1 || nodeNo > 10) {
        err_msg("Warning: Invalid hostname '%s'", hostname);
    }
    return nodeNo;
}
