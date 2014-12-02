#include "arp.h"

static char filePath[1024], hostNode, hostIP[IPLEN];

static void sig_int(int signo) {
    unlink(filePath);
    exit(0);
}

static int getEth0IfaceAddrPairs(Eth0AddrPairs *eth0AddrPairs) {
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
            strcpy(eth0AddrPairs[totalPairs].ipaddr, Sock_ntop_host(hwa->ip_addr, sizeof(*sa)));
            memcpy(eth0AddrPairs[totalPairs].hwaddr, hwa->if_haddr, IF_HADDR);
            totalPairs++;

            // Print Pair information
            printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");

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

            printf("\n         interface index = %d\n\n", hwa->if_index);
        }
    }

    free(hwahead);
}

void readAllSockets(int pfSockFd, int unixSockFd, fd_set fdSet,
                    Eth0AddrPairs *addrPairs, int totalPairs)
{
    fd_set readFdSet;
    int maxfd;

    printf("\nReading all incoming packets =>\n");
    maxfd = max(pfSockFd, unixSockFd) + 1;

    while (1) {
        printf("\n");
        readFdSet = fdSet;
        Select(maxfd, &readFdSet, NULL, NULL, NULL);

        // Check if got a packet on PF socket
        if (FD_ISSET(pfSockFd, &readFdSet)) {
            // TODO:
            // Check for identification Number
            // If ARP REQUEST
            //      If dest from addrPairs, update cache and send reply message
            //      If dest NOT in addrPairs && src in cache, update cache
            // If ARP REPLY
            //      Update cache and send info to tour via API
        }

        // Check if got a packet on an unix domain socket
        if (FD_ISSET(unixSockFd, &readFdSet)) {
            // TODO:
            // Read and search from ARP cache
            // If found, reply with info to tour via API
            // If Not, send an ARP request on PF socket
        }
    }
}

int main() {
    // TODO: Declare ARP Cache
    Eth0AddrPairs eth0AddrPairs[10] = {0};
    int totalPairs, pfSockFd, unixSockFd;
    fd_set fdSet;

    hostNode = getHostVmNodeNo();
    getIPByVmNode(hostIP, hostNode);
    printf("ARP running on VM%d (%s)\n", hostNode, hostIP);

    totalPairs = getEth0IfaceAddrPairs(eth0AddrPairs);

    Signal(SIGINT, sig_int);
    FD_ZERO(&fdSet);

    // Create PF_PACKET for ARP request/reply packets
    pfSockFd = Socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL_NUMBER));
    FD_SET(pfSockFd, &fdSet);

    // Create Unix Domain socket
    getFullPath(filePath, ARP_FILE, sizeof(filePath), FALSE);
    unixSockFd = createAndBindUnixSocket(filePath);
    FD_SET(unixSockFd, &fdSet);

    // Read incoming packets on all sockets
    readAllSockets(pfSockFd, unixSockFd, fdSet, eth0AddrPairs, totalPairs);

    unlink(filePath);
    Close(pfSockFd);
    Close(unixSockFd);
}
