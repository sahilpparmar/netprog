#include "tour.h"

static IA HostIP;
static char HostMAC[IF_HADDR];
static IA MulticastIP;
static uint16_t MulticastPort;
static struct sockaddr_in GroupSock;
static int RTRouteSD, MulticastSD, PingReplySD;
static bool joinedMulticast = FALSE;
static bool haveSentMyMSG = FALSE;

static void getMulticastInfo() {
    MulticastIP   = getIPAddrByIPStr(MULTICAST_IP);
    MulticastPort = MULTICAST_PORT;
}

static void createSockets() {
    int ok = 1;

    RTRouteSD   = socket(AF_INET, SOCK_RAW, IPPROTO_TOUR);
    MulticastSD = socket(AF_INET, SOCK_DGRAM, 0);
    PingReplySD = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (RTRouteSD < 0)
        err_quit("Opening RT Route socket error");
    else
        printf("Opening RT Route socket....OK.\n");

    if (setsockopt(RTRouteSD, IPPROTO_IP, IP_HDRINCL, &ok, sizeof(ok)) < 0)
        err_quit("Error in setting Sock option for RT Socket");

    if (MulticastSD < 0)
        err_quit("Opening Multicast datagram socket error");
    else
        printf("Opening Multicast datagram socket....OK.\n");

    /* allow multiple sockets to use the same PORT number */
    if (setsockopt(MulticastSD, SOL_SOCKET, SO_REUSEADDR, &ok, sizeof(ok)) < 0)
        err_quit("Reusing ADDR failed");

    if (PingReplySD < 0)
        err_quit("Opening Ping Reply socket error");
    else
        printf("Opening Ping Reply socket....OK.\n");
}

void generateDataPayload(TourPayload *data, IA *IPList, int numNodes) {
    data->multicastIP   = MulticastIP;
    data->multicastPort = MulticastPort;
    data->curIndex = 0;
    memcpy(data->tourList, IPList, (sizeof(IA) * numNodes));
}

static void incrementTourIndex(IPPacket *packet) {
    packet->payload.curIndex++;
}

static IA getCurTourDestIP(IPPacket *packet) {
    return packet->payload.tourList[packet->payload.curIndex];
}

static int getTourNodeCntByPackSize(int nbytes) {
    return MAXHOPS - ((sizeof(IPPacket) - nbytes) / sizeof(IA));
}

static bool isLastTourNode(IPPacket *packet, int nbytes) {

    int totalNodes = getTourNodeCntByPackSize(nbytes);
    int curInd = packet->payload.curIndex;

    assert((curInd < totalNodes) && "Invalid curInd/totalNodes in tour packet");

    if (curInd == (totalNodes - 1))
        return TRUE;
    return FALSE;
}


static void setMultiCast(IA MulIP, uint16_t MulPort) {

    if(joinedMulticast == TRUE) // Already listening on the Listening Socket
        return;

    else 
    {
        const int reuse = 1;
        struct group_req group;
        char interface[] = "ether0";
        struct sockaddr_in saddr;
//        struct ip_mreq mreq;

        unsigned char ttl = 1;
        unsigned char one = 1;
        MulticastIP = MulIP;
        MulticastPort = MulPort;

        // set content of struct saddr and imreq to zero
        memset(&saddr, 0, sizeof(struct sockaddr_in));
//        memset(&mreq, 0, sizeof(struct ip_mreq));

        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(MulPort);
        saddr.sin_addr.s_addr = htonl(INADDR_ANY); // bind socket to any interface
        Bind(MulticastSD, (struct sockaddr *)&saddr, sizeof(saddr));

       setsockopt(MulticastSD, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
               sizeof(unsigned char));

        // send multicast traffic to myself too
        setsockopt(MulticastSD, IPPROTO_IP, IP_MULTICAST_LOOP,
                &one, sizeof(unsigned char));

        /* use setsockopt() to request that the kernel join a multicast group */
        saddr.sin_addr = MulIP; // bind socket to any interface
        Mcast_join(MulticastSD, (const SA *)&saddr, sizeof(saddr), NULL, 0);

        joinedMulticast = TRUE;
    }

}   

static printIPPacket(IPPacket *packet, int nbytes) {
    struct ip *iphdr = &packet->iphead;
    TourPayload *payload = &packet->payload;

    printf("IP Header =>\n");
    printf("Header Len: %d\t", iphdr->ip_hl);
    printf("Version: %d\t", iphdr->ip_v);
    printf("TOS: %d\n", iphdr->ip_tos);
    printf("Total Len: %d\t", ntohs(iphdr->ip_len));
    printf("Ident Num: %x\n", ntohs(iphdr->ip_id));
    printf("Offset: %d\t", iphdr->ip_off);
    printf("TTL: %d\t", iphdr->ip_ttl);
    printf("Protocol Num: %d\n", iphdr->ip_p);
    printf("Src IP: %s\t", getIPStrByIPAddr(iphdr->ip_src));
    printf("Dst IP: %s\t", getIPStrByIPAddr(iphdr->ip_dst));
    printf("Checksum: %x\n", ntohs(iphdr->ip_sum));

    printf("Packet Payload =>\n");
    printf("MCast IP: %s\t", getIPStrByIPAddr(payload->multicastIP));
    printf("MCast Port: %d\n", payload->multicastPort);
    printf("Total TourNodes: %d\t", getTourNodeCntByPackSize(nbytes));
    printf("CurInd: %d\t", payload->curIndex);
    printf("CurTourDest: %s\n", getIPStrByIPAddr(getCurTourDestIP(packet)));
}

static int recvIPPacket(int sockfd, IPPacket *packet) {
    int nbytes;

    nbytes = Recvfrom(RTRouteSD, packet, sizeof(IPPacket), 0, NULL, NULL);

    packet->iphead.ip_len = ntohs(packet->iphead.ip_len);
    packet->iphead.ip_id  = ntohs(packet->iphead.ip_id);
    packet->iphead.ip_sum = ntohs(packet->iphead.ip_sum);

    // Filter packets with unknown identification number
    if (packet->iphead.ip_id != UNIQ_ID) {
        err_msg("IP Packet with Unknown Identification Number received");
        return 0;
    }

#if DEBUG
    printf("Recevied IP Packet of len %d ==>\n", nbytes);
    printIPPacket(packet, nbytes);
#endif

    return nbytes;
}

static void sendIPPacket(int sockfd, IPPacket *packet, SA *sockAddr, int salen, int nbytes) {
#if DEBUG
    printf("Sending IP Packet of len %d ==>\n", nbytes);
    printIPPacket(packet, nbytes);
#endif
    Sendto(RTRouteSD, packet, nbytes, 0, sockAddr, salen);
}

static void fillIPHeader(IPPacket *packet, IA destIP, uint16_t numBytes) {
    struct ip *iphdr = (struct ip *) &packet->iphead;

    iphdr->ip_hl  = sizeof(struct ip) >> 2;
    iphdr->ip_v   = IPVERSION;
    iphdr->ip_tos = 0;
    iphdr->ip_len = htons(numBytes);
    iphdr->ip_id  = htons(UNIQ_ID);
    iphdr->ip_off = 0;
    iphdr->ip_ttl = TTL_OUT;
    iphdr->ip_p   = IPPROTO_TOUR;
    iphdr->ip_src = HostIP;
    iphdr->ip_dst = destIP;
    iphdr->ip_sum = htons(in_cksum((uint16_t *)packet, numBytes));
}

static int forwardPacket(IPPacket *packet, int numNodes) {
    struct sockaddr_in tourSockAddr;
    IA destIP;
    uint16_t bytesToWrite;

    incrementTourIndex(packet);
    destIP = getCurTourDestIP(packet);

    bzero(&tourSockAddr, sizeof(tourSockAddr));
    tourSockAddr.sin_family = AF_INET;
    tourSockAddr.sin_addr = destIP;

    bytesToWrite = sizeof(IPPacket) - ((MAXHOPS - numNodes) * sizeof(IA));
    fillIPHeader(packet, destIP, bytesToWrite);

    sendIPPacket(RTRouteSD, packet, (SA*) &tourSockAddr, sizeof(tourSockAddr), bytesToWrite);
    return bytesToWrite;
}

static void startTour(IA *List, int tourCount) {
    IPPacket packet;
    TourPayload *payload;

    bzero(&packet, sizeof(packet));
    printf("Initializing Tour ==>\n");

    generateDataPayload(&packet.payload, List, tourCount);
    forwardPacket(&packet, tourCount);
}

static void sendEndMulticast() {
    char msgBuf[MAX_BUF];
    struct sockaddr_in addr;

    /* set up destination address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = MulticastIP;
    addr.sin_port = htons(MulticastPort);

    sprintf(msgBuf, " <<<<< This is node VM%d . Tour has ended .    \
            Group members please identify yourselves. >>>>>\n",     
            getHostVmNodeNo());
    printf("Node VM%d. Sending: <<<<< This is node VM%d . Tour has ended .    \
            Group members please identify yourselves. >>>>>\n", getHostVmNodeNo(), getHostVmNodeNo());
    Sendto(MulticastSD, (void *)msgBuf, MAX_BUF, 0, 
                (SA *) &addr, sizeof(addr));
}

static void handleMulticast() {
    char msgBuf[MAX_BUF];
    fd_set fdSet, readFdSet;
    struct timeval timeout;
    int maxfd;
    uint32_t nbytes;


    if ((nbytes = recvfrom(MulticastSD, msgBuf, 
                    MAX_BUF, 0, NULL, NULL)) < 0) {
        perror("recvfrom");
        exit(1);
    }

    printf("%s", msgBuf);

    if (!haveSentMyMSG) {
        struct sockaddr_in addr;
        /* set up destination address */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr = MulticastIP;
        addr.sin_port = htons(MulticastPort);

        sprintf(msgBuf, "<<<<< Node vm%d . I am a member of the group.  >>>>>\n",getHostVmNodeNo());
        printf("Node VM%d. Sending: %s", getHostVmNodeNo(), msgBuf);
        if (sendto(MulticastSD, msgBuf, sizeof(msgBuf), 0, 
                    (struct sockaddr *) &addr, sizeof(addr)) < 0){
            perror("sendto");
            exit(1);
        }
        haveSentMyMSG = TRUE;
    }

    FD_ZERO(&fdSet);
    FD_SET(MulticastSD, &fdSet);
    while (1) {
    //    printf("\n");
        readFdSet = fdSet;
        timeout.tv_sec  = READ_TIMEOUT;
        timeout.tv_usec = 0;

        maxfd = MulticastSD + 1;

        nbytes = Select(maxfd, &readFdSet, NULL, NULL, &timeout);

        // Multicast Timeout
        if (nbytes == 0) {
            printf(" Terminating Tour Application. \n");
            printf("================================\n");
            exit(0);
        }
        // Received IP Packet on tour rt socket
        else if (FD_ISSET(MulticastSD, &readFdSet)) {
            if ((nbytes = recvfrom(MulticastSD, msgBuf, 
                            MAX_BUF, 0, NULL, NULL)) < 0) {
                perror("recvfrom");
                exit(1);
            }

            printf("Node VM%d. Received: %s", getHostVmNodeNo(), msgBuf);
        }
    }
}

static void readAllSockets() {
    fd_set fdSet, readFdSet;
    struct timeval timeout;
    bool pingStatus[MAX_NODES+1] = {FALSE};
    bool endOfTour;
    int maxfd, pingCountDown, n;

    FD_ZERO(&fdSet);
    FD_SET(RTRouteSD, &fdSet);
    FD_SET(PingReplySD, &fdSet);

    endOfTour = FALSE;
    pingCountDown = PING_COUNTDOWN;

    while (1) {
        readFdSet = fdSet;
        timeout.tv_sec  = PING_TIMEOUT;
        timeout.tv_usec = 0;
        
        maxfd = max(RTRouteSD, PingReplySD);

        if (joinedMulticast) {
            FD_SET(MulticastSD, &readFdSet);
            maxfd = max(maxfd, MulticastSD);
        }

        n = Select(maxfd + 1, &readFdSet, NULL, NULL, isPingEnable(pingStatus) ? &timeout : NULL);

        // PING Timeout
        if (n == 0) {
            assert(isPingEnable(pingStatus) && "Ping Status should be enable");
            if (endOfTour) {
                pingCountDown--;
            }
            if (pingCountDown == 0) {
                printf("<<<<< End of Tour >>>>>\n");
                disablePingStatus(pingStatus);
                endOfTour = FALSE;
                pingCountDown = PING_COUNTDOWN;
                // TODO: Send Multicast Msg to All
                sendEndMulticast();
            } else {
                sendPingRequests(pingStatus, -1);
            }
        }

        // Received IP Packet on tour rt socket
        else if (FD_ISSET(RTRouteSD, &readFdSet)) {
            IPPacket packet;
            int nbytes;

            if ((nbytes = recvIPPacket(RTRouteSD, &packet)) > 0) {
                int sourceNode = getVmNodeByIPAddr(packet.iphead.ip_src);

                printf("[%s] Received Source Routing Packet from VM%d\n", curTimeStr(), sourceNode);

                if (isLastTourNode(&packet, nbytes)) {
                    endOfTour = TRUE;
                } else {
                    forwardPacket(&packet, getTourNodeCntByPackSize(nbytes));
                }

                if (!pingStatus[sourceNode]) {
                    pingStatus[sourceNode] = TRUE;
                    sendPingRequests(pingStatus, sourceNode);
                }

                setMultiCast(packet.payload.multicastIP, packet.payload.multicastPort);
            }
            
        }

        // Received PING Reply IP Packet on pg socket
        else if (FD_ISSET(PingReplySD, &readFdSet)) {
            // TODO: Receive Ping Reply

        }

        // Received Multicast UDP message
        else if (FD_ISSET(MulticastSD, &readFdSet)) {
            // Handle message
            handleMulticast();            
            disablePingStatus(pingStatus);
            endOfTour = FALSE;
            pingCountDown = PING_COUNTDOWN;

        }
    }
}

static char* getHWAddrByIPAddr(IA s_ipaddr, char *s_haddr) {
    HWAddr hwAddr;
    struct sockaddr_in sockAddr;

    bzero(&sockAddr, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr   = s_ipaddr;
    sockAddr.sin_port   = 0;

    bzero(&hwAddr, sizeof(hwAddr));
    hwAddr.sll_ifindex = 2;
    hwAddr.sll_hatype  = ARPHRD_ETHER;
    hwAddr.sll_halen   = ETH_ALEN;

    if (areq((SA *) &sockAddr, sizeof(sockAddr), &hwAddr) == 0) {
        memcpy(s_haddr, hwAddr.sll_addr, ETH_ALEN);
    }
    return s_haddr;
}

int main(int argc, char* argv[]) {
    Eth0AddrPairs eth0AddrPairs[10] = {0};
    IA IPList[MAXHOPS] = {0};
    int nodeNo = 0;
    int i;

    // Get Host IP and MAC addresses
    HostIP = getIPAddrByVmNode(getHostVmNodeNo());
    if (getEth0IfaceAddrPairs(eth0AddrPairs) <= 0) {
        err_quit("No Eth0 interfaces found!");
    }
    memcpy(HostMAC, eth0AddrPairs[0].hwaddr, IF_HADDR);
    printf("Tour running on VM%d (%s)\n", getHostVmNodeNo(), getIPStrByIPAddr(HostIP));

    createSockets();

    if (argc == 1) {
        printf("No Tour specified. Running in Listening Mode ==>\n");

    } else {
        for (i = 1; i < argc; i++) {
            nodeNo = atoi(argv[i]+2);
#if DEBUG
            IP charIP;
            getIPStrByVmNode(charIP, nodeNo);
            printf("%d : VM%d ---> %s\n", i, nodeNo, charIP);
#endif
            IPList[i] = getIPAddrByVmNode(nodeNo);
        }
        IPList[0] = HostIP;
        getMulticastInfo();
        setMultiCast(MulticastIP, MulticastPort);
        startTour(IPList, argc);
    }
    readAllSockets();
}

