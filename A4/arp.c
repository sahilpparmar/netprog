#include "arp.h"

static char filePath[1024], hostNode, hostIP[IPLEN];
static int eth0IfaceNum = -1;

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
            eth0AddrPairs[totalPairs].ipaddr = ((struct sockaddr_in*) hwa->ip_addr)->sin_addr;
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

            eth0IfaceNum = hwa->if_index;
        }
    }
    assert(eth0IfaceNum != -1 && "No Eth0 interfaces found");
    printf("\n         interface index = %d\n\n", eth0IfaceNum);

    free(hwahead);
}

static char* ethAddrNtoP(char *nMAC, char *pMAC) {
    char buf[10];
    int i;

    pMAC[0] = '\0';
    for (i = 0; i < IF_HADDR; i++) {
        sprintf(buf, "%.2x%s", nMAC[i] & 0xff , i == 5 ? "" : ":");
        strcat(pMAC, buf);
    }
    return pMAC;
}

static void printEthernetFrame(EthernetFrame *frame) {
    char buffer[25];

    printf ("\nEthernet frame header =>\n");

    printf ("Destination MAC: %s\n", ethAddrNtoP(frame->destMAC, buffer));
    printf ("Source MAC: %s\n", ethAddrNtoP(frame->srcMAC, buffer));
    printf("Ethernet Type Code: %x \n", frame->protocol);
    return;
}

static void sendEthernetPacket(int sockfd, EthernetFrame *frame, int outIfaceNum) {
    struct sockaddr_ll sockAddr;

    bzero(&sockAddr, sizeof(sockAddr));

    sockAddr.sll_family   = PF_PACKET;
    sockAddr.sll_protocol = htons(PROTOCOL_NUMBER);
    sockAddr.sll_hatype   = ARPHRD_ETHER;
    sockAddr.sll_pkttype  = PACKET_OTHERHOST;
    sockAddr.sll_halen    = ETH_ALEN;
    sockAddr.sll_ifindex  = outIfaceNum;
    memcpy(sockAddr.sll_addr, GET_DEST_MAC(frame), IF_HADDR);

    printf("Sending Ethernet Packet ==>\n");
    printEthernetFrame(frame);
    if (sendto(sockfd, (void *)frame, sizeof(EthernetFrame), 0,
               (SA *) &sockAddr, sizeof(sockAddr)) == -1)
    {
        err_msg("Error in sending Ethernet packet");
    }
}

// Returns interface number on which packet was received
static int recvEthernetPacket(int sockfd, EthernetFrame *frame) {
    struct sockaddr_ll sockAddr;
    int salen = sizeof(sockAddr);

    bzero(&sockAddr, salen);
    bzero(frame, sizeof(EthernetFrame));

    if (recvfrom(sockfd, frame, sizeof(EthernetFrame), 0, (SA *) &sockAddr, &salen) < 0) {
        err_msg("Error in receiving Ethernet packet");
        return -1;
    }

    // Check for valid identification Number
    if (GET_IDENT_NUM(frame) != IDENT_NUMBER) {
        err_msg("ARP packet with invalid identification number received");
        return -1;
    }

    assert(((GET_OP_TYPE(frame) == REQUEST) || (GET_OP_TYPE(frame) == REPLY)) &&
                "Invalid ARP OP type in Ethernet Frame");

    printf("Receving Ethernet Packet ==>\n");
    printEthernetFrame(frame);
    return sockAddr.sll_ifindex;
}

static void fillARPPacket(ARPPacket *packet, ARPOpType opType, char *srcMAC,
                        char *destMAC, IA srcIP, IA destIP)
{
    packet->identNum = IDENT_NUMBER;
    packet->hardType = HARD_TYPE;
    packet->protocol = PROTOCOL_NUMBER;
    packet->hardSize = IF_HADDR;
    packet->protSize = sizeof(IA);
    packet->opType   = opType;
    packet->srcIP    = srcIP;
    packet->destIP   = destIP;
    memcpy(packet->srcMAC, srcMAC, IF_HADDR);
    memcpy(packet->destMAC, destMAC, IF_HADDR);
}

static void fillARPRequestPacket(EthernetFrame *frame, char *srcMAC, IA srcIP, IA destIP) {
    uint8_t broadMAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    bzero(frame, sizeof(EthernetFrame));
    memcpy(frame->destMAC, broadMAC, IF_HADDR);
    memcpy(frame->srcMAC, srcMAC, IF_HADDR);
    frame->protocol = htons(PROTOCOL_NUMBER);
    fillARPPacket(&frame->packet, REQUEST, srcMAC, (char *) broadMAC, srcIP, destIP);
}

static void fillARPReplyPacket(EthernetFrame *frame, char *srcMAC, char *destMAC,
                                IA srcIP, IA destIP)
{
    bzero(frame, sizeof(EthernetFrame));
    memcpy(frame->destMAC, destMAC, IF_HADDR);
    memcpy(frame->srcMAC, srcMAC, IF_HADDR);
    frame->protocol = htons(PROTOCOL_NUMBER);
    fillARPPacket(&frame->packet, REPLY, srcMAC, destMAC, srcIP, destIP);
}

static char* checkIfDestNodeReached(IA destIPAddr, Eth0AddrPairs *addrPairs, int totalPairs) {
    int i;

    for (i = 0; i < totalPairs; i++) {
        if (isSameIPAddr(destIPAddr, addrPairs[i].ipaddr)) {
            return addrPairs[i].hwaddr;
        }
    }
    return NULL;
}

static int processARPPacket(int pfSockFd, EthernetFrame *frame, int ifindex,
                    Eth0AddrPairs *addrPairs, int totalPairs)
{
    // ARP Request
    if (GET_OP_TYPE(frame) == REQUEST) {
        char *destHWAddr;

        if ((destHWAddr = checkIfDestNodeReached(GET_DEST_IP(frame), addrPairs, totalPairs)) != NULL) {
            // Reached Destination Node, force update Source Node Info
            updateARPCache(GET_SRC_IP(frame), GET_SRC_MAC(frame),
                            ifindex, HARD_TYPE, 0, TRUE);

            // Send ARP Reply to source node
            EthernetFrame replyPacket;
            fillARPReplyPacket(&replyPacket, destHWAddr, GET_SRC_MAC(frame),
                                GET_DEST_IP(frame), GET_SRC_IP(frame));
            sendEthernetPacket(pfSockFd, &replyPacket, ifindex);

        } else {
            // Reached Intermediate Node, update Source Node Info if present
            updateARPCache(GET_SRC_IP(frame), GET_SRC_MAC(frame),
                            ifindex, HARD_TYPE, 0, FALSE);
        }

    // ARP Reply
    } else {
        // Get connfd from cache entry
        ARPCache *srcEntry = searchARPCache(GET_SRC_IP(frame));
        assert(srcEntry && "Valid Partial Cache Entry Expected");
        int connfd = srcEntry->connfd;

        // Update cache with Source Node Info
        updateARPCache(GET_SRC_IP(frame), GET_SRC_MAC(frame),
                        ifindex, HARD_TYPE, 0, FALSE);

        // TODO: Send info to tour via API

        Close(connfd);
    }
}

void readAllSockets(int pfSockFd, int listenfd, fd_set fdSet,
                    Eth0AddrPairs *addrPairs, int totalPairs)
{
    fd_set readFdSet;
    int maxfd;

    printf("\nReading all incoming packets =>\n");
    maxfd = max(pfSockFd, listenfd) + 1;

    while (1) {
        printf("\n");
        readFdSet = fdSet;
        Select(maxfd, &readFdSet, NULL, NULL, NULL);

        // Check if got a packet on PF socket
        if (FD_ISSET(pfSockFd, &readFdSet)) {
            EthernetFrame frame;
            int ifindex;

            if ((ifindex = recvEthernetPacket(pfSockFd, &frame)) != -1) {
                processARPPacket(pfSockFd, &frame, ifindex, addrPairs, totalPairs);
            }
        }

        // Check if got a packet on an unix domain socket
        if (FD_ISSET(listenfd, &readFdSet)) {
            // Accept new connection on unix domain socket
            int connfd = Accept(listenfd, NULL, NULL);
            IA destIPAddr/* TODO: = ReadClientUnixDomainSocket(connfd) */;
            ARPCache *entry;

            if ((entry = searchARPCache(destIPAddr)) != NULL) {
                // TODO: ARP entry present, reply with info to tour via API
                Close(connfd);
            } else {

                // Update Partial Cache entry
                updateARPCache(destIPAddr, NULL, 0, 0, connfd, TRUE);

                // ARP entry absent, send an ARP request on Eth0 interface
                EthernetFrame requestPacket;
                fillARPRequestPacket(&requestPacket, addrPairs[0].hwaddr,
                                    addrPairs[0].ipaddr, destIPAddr);
                sendEthernetPacket(pfSockFd, &requestPacket, eth0IfaceNum);
            }
        }
    }
}

int bindAndListenUnixSocket(char *filePath) {
    struct sockaddr_un sockAddr;
    int sockfd;

    sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);

    bzero(&sockAddr, sizeof(sockAddr));
    sockAddr.sun_family = AF_LOCAL;
    strcpy(sockAddr.sun_path, filePath);

    unlink(filePath);
    Bind(sockfd, (SA*) &sockAddr, sizeof(sockAddr));

    Listen(sockfd, LISTENQ);

    return sockfd;
}

int main() {
    Eth0AddrPairs eth0AddrPairs[10] = {0};
    int totalPairs, pfSockFd, listenfd;
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
    listenfd = bindAndListenUnixSocket(filePath);
    FD_SET(listenfd, &fdSet);

    // Read incoming packets on all sockets
    readAllSockets(pfSockFd, listenfd, fdSet, eth0AddrPairs, totalPairs);

    unlink(filePath);
    Close(pfSockFd);
    Close(listenfd);
}
