#include "utils.h"

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

char* getIPStrByVmNode(char *ip, int node) {
    struct hostent *hostInfo = NULL;
    char hostName[100];

    sprintf(hostName, "vm%d", node);
    hostInfo = gethostbyname(hostName);

    if (hostInfo && inet_ntop(AF_INET, hostInfo->h_addr, ip, INET_ADDRSTRLEN))
        return ip;
    else
        return NULL;
}

IA getIPAddrByVmNode(int node) {
    char ipStr[100];
    IA ipInfo = {0};

    if (getIPStrByVmNode(ipStr, node)) {
        inet_pton(AF_INET, ipStr, &ipInfo);
    }
    return ipInfo;
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

char* getFullPath(char *fullPath, char *fileName, int size, bool isTemp) {

    if (getcwd(fullPath, size) == NULL) {
        err_msg("Unable to get pwd via getcwd()");
    }

    strcat(fullPath, fileName);

    if (isTemp) {
        if (mkstemp(fullPath) == -1) {
            err_msg("Unable to get temp file via mkstemp()");
        }
    }

    return fullPath;
}

bool isSameIPAddr(IA ip1, IA ip2) {
    if (ip1.s_addr == ip2.s_addr)
        return TRUE;
    return FALSE;
}

char* ethAddrNtoP(char *nMAC) {
    static char pMAC[25];
    char buf[10];
    int i;

    pMAC[0] = '\0';
    for (i = 0; i < IF_HADDR; i++) {
        sprintf(buf, "%.2x%s", nMAC[i] & 0xff , i == 5 ? "" : ":");
        strcat(pMAC, buf);
    }
    return pMAC;
}

