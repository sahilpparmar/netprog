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

int getEth0IfaceAddrPairs(Eth0AddrPairs *eth0AddrPairs) {
    struct hwa_info *hwahead, *hwa;
    int totalPairs = 0;

    printf("Following are all eth0 interface <IP address, HW address> pairs =>\n");

    hwahead = Get_hw_addrs();
    for (hwa = hwahead; hwa != NULL; hwa = hwa->hwa_next) {
        if (strcmp(hwa->if_name, "eth0") == 0 || strcmp(hwa->if_name, "wlan0") == 0) {
            struct sockaddr     *sa;
            char   *ptr;
            int    i, prflag;

            // Store Pair information
            eth0AddrPairs[totalPairs].ipaddr = ((struct sockaddr_in*) hwa->ip_addr)->sin_addr;
            memcpy(eth0AddrPairs[totalPairs].hwaddr, hwa->if_haddr, IF_HADDR);
            totalPairs++;

            // Print Pair information
#if DEBUG
            printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");
#endif

            if ((sa = hwa->ip_addr) != NULL)
                printf("         IP addr = %s\n", Sock_ntop_host(sa, sizeof(*sa)));

            prflag = 0;
            i = 0;
            do {
                if (hwa->if_haddr[i] != '\0') {
                    prflag = 1;
                    break;
                }
            } while (++i < IF_HADDR);

            if (prflag) {
                printf("         HW addr = ");
                ptr = hwa->if_haddr;
                i = IF_HADDR;
                do {
                    printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
                } while (--i > 0);
            }
#if DEBUG
            printf("\n         interface index = %d\n\n", hwa->if_index);
#endif
        }
    }
    printf("\n");
    free(hwahead);
    return totalPairs;
}

char* curTimeStr() {
    static char timeStr[100];
    time_t timestamp = time(NULL);

    strcpy(timeStr, asctime(localtime((const time_t *) &timestamp)));
    timeStr[strlen(timeStr)-1] = '\0';
    return timeStr;
}

uint16_t in_cksum(uint16_t *addr, int len) {
    int      nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* 4mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(uint8_t *)(&answer) = *(uint8_t *)w ;
        sum += answer;
    }

    /* 4add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);                 /* add carry */
    answer = ~sum;                      /* truncate to 16 bits */
    return answer;
}

void tv_sub(struct timeval *out, struct timeval *in) {
    /* out -= in */
    if ( (out->tv_usec -= in->tv_usec) < 0) {
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}
