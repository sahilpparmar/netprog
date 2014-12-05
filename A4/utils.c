#include "utils.h"

int getVmNodeByIPAddr(IA ipAddr) {
    struct hostent *hostInfo;
    int nodeno = 0;

    hostInfo = gethostbyaddr(&ipAddr, sizeof(ipAddr), AF_INET);
    sscanf(hostInfo->h_name, "vm%d", &nodeno);
    return nodeno;
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

char* getIPStrByIPAddr(IA ipAddr) {
    struct hostent *hostInfo = NULL;
    static char ipStr[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, (void*) &ipAddr, ipStr, INET_ADDRSTRLEN))
        return ipStr;
    else
        return NULL;
}

IA getIPAddrByIPStr(char *ipStr) {
    IA ipAddr = {0};
    inet_pton(AF_INET, ipStr, &ipAddr);
    return ipAddr;
}

IA getIPAddrByVmNode(int node) {
    char ipStr[INET_ADDRSTRLEN];
    IA ipAddr = {0};

    if (getIPStrByVmNode(ipStr, node)) {
        inet_pton(AF_INET, ipStr, &ipAddr);
    }
    return ipAddr;
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

