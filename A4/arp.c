#include "arp.h"

static char filePath[1024];
static IA HostIP;

static void sig_int(int signo) {
    unlink(filePath);
    exit(0);
}

static int bindAndListenUnixSocket() {
    struct sockaddr_un sockAddr;
    int sockfd;

    sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);

    bzero(&sockAddr, sizeof(sockAddr));
    sockAddr.sun_family = AF_LOCAL;
    getFullPath(filePath, ARP_FILE, sizeof(filePath), FALSE);
    strcpy(sockAddr.sun_path, filePath);

    unlink(filePath);
    Bind(sockfd, (SA*) &sockAddr, sizeof(sockAddr));

    Listen(sockfd, LISTENQ);

    return sockfd;
}

static void printEthernetFrame(EthernetFrame *frame) {
    printf ("Ethernet frame header =>\n");
    printf ("Destination MAC: %s\n", ethAddrNtoP(frame->destMAC));
    printf ("Source MAC: %s\n", ethAddrNtoP(frame->srcMAC));
    printf("Protocol Number: %x\n", frame->protocol);

    ARPPacket *packet = &frame->packet;
    printf ("ARP header =>\n");
    printf("Ident Num: %x\t", packet->identNum);
    printf("HAType: %d\t", packet->hatype);
    printf("Protocol Num: %x\n", packet->protocol);
    printf("HALen: %d\t", packet->halen);
    printf("ProtSize: %d\t", packet->protSize);
    printf("OPType: %d\n", packet->opType);
    printf("SrcIP: %s\t", getIPStrByIPAddr(packet->srcIP));
    printf("DestIP: %s\n", getIPStrByIPAddr(packet->destIP));
    printf("SrcMAC: %s\t", ethAddrNtoP(packet->srcMAC));
    printf("DestMAC: %s\n", ethAddrNtoP(packet->destMAC));
}

static void sendEthernetPacket(int sockfd, EthernetFrame *frame, int ifindex,
                               uint16_t hatype, uint8_t halen)
{
    struct sockaddr_ll sockAddr;

    bzero(&sockAddr, sizeof(sockAddr));

    sockAddr.sll_family   = PF_PACKET;
    sockAddr.sll_protocol = htons(PROTOCOL_NUMBER);
    sockAddr.sll_hatype   = hatype;
    sockAddr.sll_pkttype  = PACKET_OTHERHOST;
    sockAddr.sll_halen    = halen;
    sockAddr.sll_ifindex  = ifindex;
    memcpy(sockAddr.sll_addr, GET_DEST_MAC(frame), halen);

    printf("Sending Ethernet Packet ==>\n");
    printEthernetFrame(frame);

    if (sendto(sockfd, (void *)frame, sizeof(EthernetFrame), 0,
               (SA *) &sockAddr, sizeof(sockAddr)) == -1)
    {
        err_msg("Error in sending Ethernet packet");
    }
}

// Returns interface number on which packet was received
static bool recvEthernetPacket(int sockfd, EthernetFrame *frame, struct sockaddr_ll *sockAddr) {
    int salen = sizeof(struct sockaddr_ll);

    bzero(sockAddr, salen);
    bzero(frame, sizeof(EthernetFrame));

    if (recvfrom(sockfd, frame, sizeof(EthernetFrame), 0, (SA *) sockAddr, &salen) < 0) {
        err_msg("Error in receiving Ethernet packet");
        return FALSE;
    }

    // Check for valid identification Number
    if (GET_IDENT_NUM(frame) != IDENT_NUMBER) {
        err_msg("ARP packet with invalid identification number received");
        return FALSE;
    }

    assert(((GET_OP_TYPE(frame) == REQUEST) || (GET_OP_TYPE(frame) == REPLY)) &&
                "Invalid ARP OP type in Ethernet Frame");

    printf("Receving Ethernet Packet ==>\n");
    printEthernetFrame(frame);
    return TRUE;
}

static void fillARPPacket(ARPPacket *packet, ARPOpType opType, char *srcMAC, char *destMAC,
                            IA srcIP, IA destIP, uint16_t hatype, uint8_t halen)
{
    packet->identNum = IDENT_NUMBER;
    packet->hatype = hatype;
    packet->protocol = PROTOCOL_NUMBER;
    packet->halen = halen;
    packet->protSize = sizeof(IA);
    packet->opType   = opType;
    packet->srcIP    = srcIP;
    packet->destIP   = destIP;
    memcpy(packet->srcMAC, srcMAC, halen);
    memcpy(packet->destMAC, destMAC, halen);
}

static void fillARPRequestPacket(EthernetFrame *frame, char *srcMAC, IA srcIP, IA destIP,
                                    uint16_t hatype, uint8_t halen)
{
    uint8_t broadMAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    bzero(frame, sizeof(EthernetFrame));
    memcpy(frame->destMAC, broadMAC, halen);
    memcpy(frame->srcMAC, srcMAC, halen);
    frame->protocol = htons(PROTOCOL_NUMBER);
    fillARPPacket(&frame->packet, REQUEST, srcMAC, (char *) broadMAC, srcIP, destIP,
                  hatype, halen);
}

static void fillARPReplyPacket(EthernetFrame *frame, char *srcMAC, char *destMAC,
                                IA srcIP, IA destIP, uint16_t hatype, uint8_t halen)
{
    bzero(frame, sizeof(EthernetFrame));
    memcpy(frame->destMAC, destMAC, halen);
    memcpy(frame->srcMAC, srcMAC, halen);
    frame->protocol = htons(PROTOCOL_NUMBER);
    fillARPPacket(&frame->packet, REPLY, srcMAC, destMAC, srcIP, destIP, hatype, halen);
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

static int processARPPacket(int pfSockFd, EthernetFrame *frame, struct sockaddr_ll *sockAddr,
                    Eth0AddrPairs *addrPairs, int totalPairs)
{
    // ARP Request
    if (GET_OP_TYPE(frame) == REQUEST) {
        printf("Processing ARP packet of REQUEST type\n");

        char *destHWAddr;
        if ((destHWAddr = checkIfDestNodeReached(GET_DEST_IP(frame), addrPairs, totalPairs)) != NULL) {
            // Reached Destination Node, force update Source Node Info
            printf("\nARP Request Reached Destination Node, sending back ARP REPLY\n");
            updateARPCache(GET_SRC_IP(frame), GET_SRC_MAC(frame),
                sockAddr->sll_ifindex, sockAddr->sll_hatype, 0, TRUE);

            // Send ARP Reply to source node
            EthernetFrame replyPacket;
            fillARPReplyPacket(&replyPacket, destHWAddr, GET_SRC_MAC(frame), GET_DEST_IP(frame),
                               GET_SRC_IP(frame), sockAddr->sll_hatype, sockAddr->sll_halen);
            sendEthernetPacket(pfSockFd, &replyPacket, sockAddr->sll_ifindex, sockAddr->sll_hatype,
                               sockAddr->sll_halen);

        } else {
            // Reached Intermediate Node, update Source Node Info if present
            updateARPCache(GET_SRC_IP(frame), GET_SRC_MAC(frame),
                sockAddr->sll_ifindex, sockAddr->sll_hatype, 0, FALSE);
        }
    }

    // ARP Reply
    else {
        printf("Processing ARP packet of REPLY type\n");

        // Get connfd from cache entry
        ARPCache *srcEntry = searchARPCache(GET_SRC_IP(frame));
        assert(srcEntry && "Valid Partial Cache Entry Expected");
        int connfd = srcEntry->connfd;

        // Send hwaddr to tour
        writeUnixSocket(connfd, GET_SRC_MAC(frame));

        // Update cache with Source Node Info
        updateARPCache(GET_SRC_IP(frame), GET_SRC_MAC(frame),
            sockAddr->sll_ifindex, sockAddr->sll_hatype, 0, FALSE);
    }

    return GET_OP_TYPE(frame);
}

static void readAllSockets(int pfSockFd, int listenfd, fd_set fdSet,
                            Eth0AddrPairs *addrPairs, int totalPairs)
{
    fd_set readFdSet;
    int maxfd, connfd;
    IA destIPAddr;

    printf("\nReading all incoming packets =>\n");
    connfd = -1;

    while (1) {
        printf("\n");
        maxfd = max(pfSockFd, listenfd);
        readFdSet = fdSet;
        if (connfd != -1) {
            // Monitor new connfd socket for termination of connection
            maxfd = max(maxfd, connfd);
            FD_SET(connfd, &readFdSet);
        }

        Select(maxfd + 1, &readFdSet, NULL, NULL, NULL);

        // Check if got a FIN packet on connfd
        if (connfd != -1 && FD_ISSET(connfd, &readFdSet)) {
            // Received a FIN packet, remove partial cache entry
            printf("Received FIN packet from Tour Unix domain socket\n");
            invalidateCache(destIPAddr);
            close(connfd);
            connfd = -1;
        }

        // Check if got a packet on PF socket
        else if (FD_ISSET(pfSockFd, &readFdSet)) {
            EthernetFrame frame;
            struct sockaddr_ll sockAddr;

            if (recvEthernetPacket(pfSockFd, &frame, &sockAddr)) {
                if (processARPPacket(pfSockFd, &frame, &sockAddr, addrPairs, totalPairs) == REPLY) {
                    close(connfd);
                    connfd = -1;
                }
            }
        }

        // Check if got a packet on an unix domain socket
        else if (FD_ISSET(listenfd, &readFdSet)) {
            ARPCache *entry;
            int ifindex;
            uint16_t hatype;
            uint8_t halen;

            // Accept new connection on unix domain socket
            connfd = Accept(listenfd, NULL, NULL);
            readUnixSocket(connfd, &destIPAddr, &ifindex, &hatype, &halen);
            printf("Processing Packet on Unix Domain Socket\n");

            if ((entry = searchARPCache(destIPAddr)) != NULL) {
                // ARP entry present, send hwaddr to tour
                printf("ARP Cache entry Present, sending HW addr to Tour process\n");
                writeUnixSocket(connfd, entry->hwAddr);
                close(connfd);
                connfd = -1;
            } else {
                // Update Partial Cache entry
                updateARPCache(destIPAddr, NULL, ifindex, hatype, connfd, TRUE);

                printf("ARP Cache entry Absent, sending ARP Request on Eth0 iface\n");
                // ARP entry absent, send an ARP request on Eth0 interface
                EthernetFrame requestPacket;
                fillARPRequestPacket(&requestPacket, addrPairs[0].hwaddr,
                    addrPairs[0].ipaddr, destIPAddr, hatype, halen);
                sendEthernetPacket(pfSockFd, &requestPacket, ifindex, hatype, halen);
            }
        }
    }
}

int main() {
    Eth0AddrPairs eth0AddrPairs[10] = {0};
    int totalPairs, pfSockFd, listenfd;
    fd_set fdSet;

    // Get Host IP and MAC addresses
    HostIP = getIPAddrByVmNode(getHostVmNodeNo());
    if ((totalPairs = getEth0IfaceAddrPairs(eth0AddrPairs)) <= 0) {
        err_quit("No Eth0 interfaces found!");
    }
    printf("ARP running on VM%d (%s)\n", getHostVmNodeNo(), getIPStrByIPAddr(HostIP));

    Signal(SIGINT, sig_int);
    FD_ZERO(&fdSet);

    // Create PF_PACKET for ARP request/reply packets
    pfSockFd = Socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL_NUMBER));
    FD_SET(pfSockFd, &fdSet);

    // Bind and listen a TCP Unix Domain socket
    listenfd = bindAndListenUnixSocket();
    FD_SET(listenfd, &fdSet);

    // Read incoming packets on all sockets
    readAllSockets(pfSockFd, listenfd, fdSet, eth0AddrPairs, totalPairs);

    unlink(filePath);
    close(pfSockFd);
    close(listenfd);
}
