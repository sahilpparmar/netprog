#include "tour.h"
#include <netinet/ip.h>

static uint32_t HostIP;
static IP MulticastIP;
static uint16_t MulticastPort;
struct sockaddr_in GroupSock;
int RTRouteSD, MulticastRecvSD, MulticastSendSD, PingReplySD;
bool joinedMulticast = FALSE;

static void parseClientParams() {
    strncpy (MulticastIP, "226.1.2.3", sizeof("226.1.2.3"));
    MulticastPort = 5454;
}

unsigned short csum(unsigned short *buf, int nwords)
{       //
        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}
static void createSockets() {
    /* Create a datagram socket on which to receive. */
    int hdrincl=1;

    RTRouteSD   = socket(AF_INET, SOCK_RAW, IPPROTO_TOUR);
    MulticastRecvSD = socket(AF_INET, SOCK_DGRAM, 0);
    MulticastSendSD = socket(AF_INET, SOCK_DGRAM, 0);
    PingReplySD = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if(RTRouteSD < 0)
    {
        perror("Opening RT Route socket error");
        exit(1);
    }
    else
        printf("Opening RT Route socket....OK.\n");

    if (setsockopt(RTRouteSD, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) < 0) {
        perror("Error in setting Sock option for RT Socket\n");
    }

    if(MulticastRecvSD < 0 || MulticastSendSD < 0)
    {
        perror("Opening Multicast datagram socket error");
        exit(1);
    }
    else
        printf("Opening Multicast datagram socket....OK.\n");

    if(PingReplySD < 0)
    {
        perror("Opening Ping Reply socket error");
        exit(1);
    }
    else
        printf("Opening Ping Reply socket....OK.\n");
}
void generateDataPayload(TourPayload *data, uint32_t *IPList, int numNodes) {
    memcpy(data->multicastIP, MulticastIP, sizeof(MulticastIP));
    data->multicastPort = MulticastPort;
    data->curIndex = 0;
    memcpy(data->tourList, IPList, (sizeof(IP) * numNodes));
    return;
}
void incrementIndex(TourPayload *data) {
    data->curIndex++;
    return;
}
bool isLastTourNode(TourPayload *data, int payloadSize) {
    int totalNodes;
    totalNodes = (payloadSize - sizeof(IP) 
        + (2*sizeof(uint16_t)))
        /sizeof(IP); // MulicastIP + Port + curIndex
    totalNodes--;
    if(data->curIndex < totalNodes)
        return FALSE;
    else if(data->curIndex = totalNodes)
        return TRUE;
    else
        perror("Error in checking last node!\n");
    return;
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
static void prependHeader(uint32_t destIP, char *sendPacket, uint16_t userLen) {
    struct ip *iphdr;

    iphdr = (struct ip *) sendPacket;

    bzero(sendPacket, sizeof(*iphdr));
    iphdr->ip_hl = sizeof(struct ip) >> 2;
    iphdr->ip_v = IPVERSION;
    iphdr->ip_tos = 0;
#if defined(linux) || defined(__OpenBSD__)
    iphdr->ip_len = htons(userLen);	/* network byte order */
#else
    iphdr->ip_len = userLen;			/* host byte order */
#endif
    iphdr->ip_id = htons(UNIQ_ID);
    iphdr->ip_off = htons(0);			/* frag offset, MF and DF flags */
    iphdr->ip_ttl = TTL_OUT;
    iphdr->ip_p = IPPROTO_TOUR;

    iphdr->ip_src.s_addr = HostIP;
    iphdr->ip_dst.s_addr = destIP;
    iphdr->ip_sum = csum((unsigned short *)sendPacket, userLen); //TODO 
    return;
}



static int forwardPacket(TourPayload *data, int max) {

    char *sendPacket;
    uint16_t bytesToWrite;
    struct sockaddr_in tourSockAddr;
    uint32_t destIP;
    int headerLen = sizeof(struct ip);
    TourPayload *payload;

    bytesToWrite = headerLen + (sizeof(IP) + 2 *sizeof(uint16_t)) + max * sizeof(IP);
    sendPacket = malloc(bytesToWrite);
    memcpy((sendPacket + headerLen), data, (bytesToWrite - headerLen));

    payload = (TourPayload *) (sendPacket + headerLen);

    incrementIndex(payload);
    destIP = *(payload->tourList[payload->curIndex]);

    bzero(&tourSockAddr, sizeof(tourSockAddr));
    tourSockAddr.sin_family = AF_INET;
    tourSockAddr.sin_port = htons(IPPROTO_TOUR);
    tourSockAddr.sin_addr.s_addr = destIP;

    prependHeader(destIP, sendPacket, bytesToWrite);

    Sendto(RTRouteSD, sendPacket, bytesToWrite, 0, (const struct sockaddr *) &tourSockAddr, sizeof(socklen_t));

    free(sendPacket);
    
    return bytesToWrite;

}

static void startTour(uint32_t *List, int max) {
    printf("Initializing Tour\n");
    TourPayload data;
    generateDataPayload(&data, List, max);
    forwardPacket(&data, max);
}



static void ListenOnSockets() {
    if(joinedMulticast) {

    }
    else // Listen on all except the Multicast Socket
    {
        char *Packet;
        IP sourceIP;
        uint32_t source, readBytes;
        TourPayload *payload;


        Packet = malloc(sizeof(struct ip)+ MAXHOPS *sizeof(TourPayload));
        printf("Listening on all sockets!\n");
        readBytes = Recvfrom(RTRouteSD, Packet, sizeof(struct ip) + 
                MAXHOPS * sizeof(TourPayload), 0, NULL, NULL);
        printf("Bytes read: %d", readBytes);
        payload = (TourPayload *)(Packet +sizeof(struct ip));
        source = *(payload->tourList[(payload->curIndex)-1]);
        
    
        Inet_ntop(AF_INET, &source, sourceIP, sizeof(socklen_t));     
        printf("Packet received from VM%d\n", getVmNodeByIP(sourceIP));
    }
}


static void readIP() {


}

int main(int argc, char* argv[]) {

    uint32_t IPList[MAXHOPS] = {0};
    int nodeNo = 0;
    IP charIP;
    int i;

    getIPByVmNode(charIP, getHostVmNodeNo());
    Inet_pton(AF_INET, charIP, &HostIP);     

    printf("Tour module running on VM%d with IP:%s\n", getHostVmNodeNo(), charIP);
    createSockets();

    if (argc == 1) {
        printf("No Tour specified\n");
        createSockets();
        printf("Running in Listening Mode\n");
        ListenOnSockets();

    } 
    else {
        for (i = 1; i < argc; i++) {
            nodeNo = atoi(argv[i]+2);
            getIPByVmNode(charIP, nodeNo);
            printf("%d : VM%d ---> %s\n",i, nodeNo, charIP);
            Inet_pton(AF_INET, charIP, &IPList[i]);     
        }
        IPList[0] = HostIP;

        parseClientParams();
       // setMultiCast();
        startTour(IPList, i);
        ListenOnSockets();
    }
}
