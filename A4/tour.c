#include "tour.h"

#define DEBUG 0

static IA HostIP;
static IA MulticastIP;
static uint16_t MulticastPort;
struct sockaddr_in GroupSock;
int RTRouteSD, MulticastRecvSD, MulticastSendSD, PingReplySD;
bool joinedMulticast = FALSE;

static void getMulticastInfo() {
    MulticastIP   = getIPAddrByIPStr(MULTICAST_IP);
    MulticastPort = MULTICAST_PORT;
}

static uint16_t csum(uint16_t *addr, int len) {
    long sum = 0;

    while (len > 1) {
        sum += *(addr++);
        len -= 2;
    }

    if (len > 0)
        sum += *addr;

    while (sum >> 16)
        sum = ((sum & 0xffff) + (sum >> 16));

    sum = ~sum;

    return ((uint16_t) sum);
}

static char* curTimeStr() {
    static char timeStr[100];
    time_t timestamp = time(NULL);

    strcpy(timeStr, asctime(localtime((const time_t *) &timestamp)));
    timeStr[strlen(timeStr)-1] = '\0';
    return timeStr;
}

static void createSockets() {
    int hdrincl=1;

    RTRouteSD       = socket(AF_INET, SOCK_RAW, IPPROTO_TOUR);
    MulticastRecvSD = socket(AF_INET, SOCK_DGRAM, 0);
    MulticastSendSD = socket(AF_INET, SOCK_DGRAM, 0);
    PingReplySD     = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (RTRouteSD < 0)
        err_quit("Opening RT Route socket error");
    else
        printf("Opening RT Route socket....OK.\n");

    if (setsockopt(RTRouteSD, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) < 0)
        err_quit("Error in setting Sock option for RT Socket\n");

    if (MulticastRecvSD < 0 || MulticastSendSD < 0)
        err_quit("Opening Multicast datagram socket error");
    else
        printf("Opening Multicast datagram socket....OK.\n");

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

/*
static void setMultiCast() {

    if(joinedMulticast == TRUE)
        return;

    else 
    {
        const int reuse = 1;
        struct ip_mreq group;
        char interface[] = "eth0";

        Setsockopt(MulticastRecvSD, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        memset((char *) &GroupSock, 0, sizeof(GroupSock));
        GroupSock.sin_family = AF_INET;
        GroupSock.sin_port = htons(MulticastPort);  
        group.imr_multiaddr.s_addr = inet_addr(MulticastIP);

        Bind(MulticastRecvSD, (SA *)&GroupSock, sizeof(GroupSock));
        Mcast_join(MulticastRecvSD,(SA*) &GroupSock, sizeof(GroupSock), interface, 0);// select the eth0 interface
        joinedMulticast = TRUE;
    }

}*/   

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
    iphdr->ip_sum = htons(csum((uint16_t *)packet, numBytes));
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

static void ListenOnSockets() {
    while (1) {
        // TODO: need select
        if (joinedMulticast) {

        } else {
            // Listen on all except the Multicast Socket
            IPPacket packet;
            int nbytes = recvIPPacket(RTRouteSD, &packet);
            
            printf("[%s] Received Source Routing Packet from %s\n", curTimeStr(),
                    getVmNameByIPAddr(packet.iphead.ip_src));

            if (isLastTourNode(&packet, nbytes)) {
                printf("End of Tour\n");
            } else {
                forwardPacket(&packet, getTourNodeCntByPackSize(nbytes));
            }
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

    IA IPList[MAXHOPS] = {0};
    int nodeNo = 0;
    int i;

    HostIP = getIPAddrByVmNode(getHostVmNodeNo());

    printf("Tour module running on VM%d (%s)\n", getHostVmNodeNo(), getIPStrByIPAddr(HostIP));
    createSockets();

    if (argc == 1) {
        printf("No Tour specified. Running in Listening Mode ==>\n");
        ListenOnSockets();

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
        //setMultiCast();
        startTour(IPList, argc);
        ListenOnSockets();
    }
}

