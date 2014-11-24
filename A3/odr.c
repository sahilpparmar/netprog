#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include "common.h"
#include "hw_addrs.h"
#include "odr.h"

#define DEBUG  1
#define DEBUG2 0

char filePath[1024], hostNode, hostIP[100];
int staleness;

static void sig_int(int signo) {
    unlink(filePath);
    exit(0);
}

void printInterface(struct hwa_info *hwa) {
#if DEBUG2

    struct sockaddr     *sa;
    char   *ptr;
    int    i, prflag;

    printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");

    if ( (sa = hwa->ip_addr) != NULL)
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

#endif
}

char* ethAddrNtoP(char *MAC, char *tempMAC) {
    char buf[10];
    int i;

    tempMAC[0] = '\0';
    for (i = 0; i < MACLEN; i++) {
        sprintf(buf, "%.2x%s", MAC[i] & 0xff , i == 5 ? "" : ":");
        strcat(tempMAC, buf);
    }
    return tempMAC;
}

void printPacket(EthernetFrame *frame) {
#if DEBUG2

    ODRPacket *packet = &(frame->packet);
    char buffer[20];
    int i;

    printf ("\nEthernet frame header:\n");

    printf ("Destination MAC: %s\n", ethAddrNtoP(frame->destMAC, buffer));
    printf ("Source MAC: %s\n", ethAddrNtoP(frame->sourceMAC, buffer));

    printf("Ethernet Type Code: %x \n", frame->protocol);

    printf ("ODR packet header =>\n");
    printf("Packet Type: %u\n", packet->type);
    printf("Source IP: %s   Port no: %u \n", packet->sourceIP, packet->sourcePort);
    printf("Destination IP: %s   Port no: %u \n", packet->destIP, packet->destPort);
    printf("Hop count: %u \n", packet->hopCount);
    printf("Broadcast ID: %u \n", packet->broadID);

    if (packet->Asent)
        printf("Asent: True\n");
    else
        printf("Asent: False\n");

    if (packet->forceRedisc)
        printf("forceRedisc: True\n");
    else
        printf("forceRedisc: False\n");

    printf("Data: %s \n", packet->data);

#endif

    return;
}

void sendEthernetPacket(int sockfd, EthernetFrame *frame, SA *sockAddr, int saLen) {
    ODRPacket *packet;
    char buf[20];

    printPacket(frame);

    packet = &(frame->packet);
    printf("[ODR @ VM%d] Sending frame hdr =>  srcIP: VM%d  destMAC: %s\n",
                getVmNodeByIP(hostIP), getVmNodeByIP(hostIP), ethAddrNtoP(frame->destMAC, buf));
    printf("ODR MSG =>  TYPE: %d  SRC: VM%d  DST: VM%d\n",
                packet->type, getVmNodeByIP(packet->sourceIP), getVmNodeByIP(packet->destIP));

    if (sendto(sockfd, (void *)frame, sizeof(EthernetFrame), 0, sockAddr, saLen) == -1) {
        err_msg("Error in sending Ethernet packet");
    }
}

void recvEthernetPacket(int sockfd, EthernetFrame *frame) {
    bzero(frame, sizeof(EthernetFrame));
    if (recvfrom(sockfd, frame, sizeof(EthernetFrame), 0, NULL, NULL) < 0) {
        err_msg("Error in receiving Ethernet packet");
    }
    printPacket(frame);
}

int sendonIFace(ODRPacket *packet, uint8_t srcMAC[MACLEN], uint8_t destMAC[MACLEN],
                uint16_t outIfaceNum, int sockfd)
{
    int retVal;

    /*target address*/
    struct sockaddr_ll sockAddr;
    EthernetFrame frame;

    bzero(&sockAddr, sizeof(sockAddr));
    bzero(&frame, sizeof(frame));

    /*RAW communication*/
    sockAddr.sll_family   = PF_PACKET;
    sockAddr.sll_protocol = htons(PROTOCOL_NUMBER);

    /*ARP hardware identifier is ethernet*/
    sockAddr.sll_hatype   = ARPHRD_ETHER;

    /*target is another host*/
    sockAddr.sll_pkttype  = PACKET_OTHERHOST;

    /*address length*/
    sockAddr.sll_halen    = ETH_ALEN;

    memcpy(sockAddr.sll_addr, destMAC, MACLEN);
    sockAddr.sll_ifindex  = outIfaceNum;

    memcpy(frame.sourceMAC, srcMAC, MACLEN);
    memcpy(frame.destMAC, destMAC, MACLEN);
    memcpy(&(frame.packet), packet, sizeof(ODRPacket));
    frame.protocol = htons(PROTOCOL_NUMBER);

    // Increment Hop count in the packet
    packet->hopCount++;

    sendEthernetPacket(sockfd, &frame, (SA*) &sockAddr, sizeof(sockAddr));
}

// Function that would check and clear up waiting packets in the buffer
int sendWaitingPackets(int destIndex, RoutingTable *routes, IfaceInfo *ifaceList) {

    WaitingPacket *waitingPackets;
    WaitingPacket *freePacket;
    uint8_t srcMAC[MACLEN], dstMAC[MACLEN];
    uint16_t outIfaceInd, outIfaceNum;
    int outSocket;
    int packetSent = 0;

    assert(routes[destIndex].isValid && "Route Entry should be present");
    outIfaceInd = routes[destIndex].ifaceInd;
    outIfaceNum = ifaceList[outIfaceInd].ifaceNum;
    outSocket = ifaceList[outIfaceInd].ifaceSocket;

    waitingPackets = routes[destIndex].waitListHead;
    freePacket = routes[destIndex].waitListHead;
    memcpy(dstMAC, routes[destIndex].nextHopMAC, MACLEN);
    memcpy(srcMAC, ifaceList[outIfaceInd].ifaceMAC, MACLEN);

    while (waitingPackets != NULL) {
#if DEBUG2
        printf("Sent a waiting Packet of Type: %d\n", waitingPackets->packet.type);
#endif
        sendonIFace(&(waitingPackets->packet), srcMAC, dstMAC, outIfaceNum, outSocket);
        waitingPackets = waitingPackets->next;
        packetSent++;

        free(freePacket);
        freePacket = waitingPackets;
    }
    routes[destIndex].waitListHead = NULL;

    return packetSent;
}

void printTable(RoutingTable *routes, IfaceInfo *ifaceList, int specific) {
    char MACTemp[25];
    int i;

    printf("===================================================================================================================================\n");
    printf("Destination Node | isValid |   broadID   | ifaceNum |    nextHopMAC     | hopCount | waitListHead |        timestamp\n");
    printf("===================================================================================================================================\n");

    if (specific != 0) {
        printf("\tVM%-5d  | %8d | %10d | %8d | %17s | %8d | %8p | %24s",
                specific, routes[specific].isValid, routes[specific].broadID, ifaceList[routes[specific].ifaceInd].ifaceNum,
                ethAddrNtoP(routes[specific].nextHopMAC, MACTemp), routes[specific].hopCount,
                routes[specific].waitListHead, asctime(localtime((const time_t *)&routes[specific].timeStamp)));
    } else {

        for (i = 1; i <= TOTAL_VMS; i++) {
            if (routes[i].isValid)
                printf("\tVM%-5d  | %8d | %10d | %8d | %17s | %8d | %8p | %24s",
                        i, routes[i].isValid, routes[i].broadID, ifaceList[routes[i].ifaceInd].ifaceNum,
                        ethAddrNtoP(routes[i].nextHopMAC, MACTemp), routes[i].hopCount,
                        routes[i].waitListHead, asctime(localtime((const time_t *)&routes[i].timeStamp)));
        }
    }
    printf("===================================================================================================================================\n");

}

bool isRouteStale(RoutingTable *routeEntry) {
    double diff = difftime(time(NULL), routeEntry->timeStamp);
    return (diff >= (double)staleness) ? TRUE : FALSE;
}

bool checkIfTimeToLeave(ODRPacket *packet) {
    if (packet->hopCount == TTL_HOP_COUNT)
        return TRUE;
    return FALSE;
}

bool checkIfSrcNode(ODRPacket *packet) {
    if (strcmp(packet->sourceIP, hostIP) == 0)
        return TRUE;
    return FALSE;
}

bool checkIfDestNode(ODRPacket *packet) {
    if (strcmp(packet->destIP, hostIP) == 0)
        return TRUE;
    return FALSE;
}

bool isForceRediscover(ODRPacket *packet) {
    if (packet->forceRedisc)
        return TRUE;
    return FALSE;
}

typedef enum {
    NO_UPDATE   = 0,
    SAME_UPDATE = 1,
    NEW_UPDATE  = 2
} RouteUpdate;

RouteUpdate isBetterOrNewerRoute(RoutingTable *routeEntry, ODRPacket *packet) {
    uint32_t newBroadID  = packet->broadID;
    uint32_t newHopCount = packet->hopCount;

    // No Route present
    if (routeEntry->isValid == FALSE)
        return NEW_UPDATE;

    // Route is stale
    if (isRouteStale(routeEntry))
        return NEW_UPDATE;

    // Force rediscovery on, so force route update
    if (isForceRediscover(packet))
        return NEW_UPDATE;

    if (routeEntry->broadID != 0 && newBroadID != 0) {
        // Newer RREQ packet
        if (routeEntry->broadID < newBroadID)
            return NEW_UPDATE;
        // Older RREQ packet
        if (routeEntry->broadID > newBroadID)
            return NO_UPDATE;
    }

    // New path with better hop count
    if (routeEntry->hopCount > newHopCount)
        return NEW_UPDATE;
    // New path with same hop count
    else if (routeEntry->hopCount == newHopCount)
        return SAME_UPDATE;

    // Existing Route is better
    return NO_UPDATE;
}

RouteUpdate createUpdateRouteEntry(EthernetFrame *frame, int ifaceInd,
                                    RoutingTable *routes, IfaceInfo *ifaceList)
{
    ODRPacket *packet = &(frame->packet);
    int srcNode = getVmNodeByIP(packet->sourceIP);
    RoutingTable *routeEntry = &routes[srcNode];
    RouteUpdate routeUpdate;

    routeUpdate = isBetterOrNewerRoute(routeEntry, packet);
    if (routeUpdate != NO_UPDATE) {
        int packetsSent;

        routeEntry->isValid = TRUE;
        routeEntry->broadID = packet->broadID;
        routeEntry->ifaceInd = ifaceInd;
        memcpy(routeEntry->nextHopMAC, frame->sourceMAC, MACLEN);
        routeEntry->hopCount = packet->hopCount;
        routeEntry->timeStamp = time(NULL);

#if DEBUG
	printf("Route Table Updated for destination: VM%d\n", srcNode);
        printTable(routes, ifaceList, 0);
        if ((packetsSent = sendWaitingPackets(srcNode, routes, ifaceList)) > 0)
            printf("Cleared Waiting Queue for src Node: VM%d, Packets Sent: %d\n",
                    srcNode, packetsSent);
#endif 
    }
    return routeUpdate;
}

void fillODRPacket(ODRPacket *packet, packetType type, char *srcIP, char *dstIP,
                  uint32_t srcPort, uint32_t dstPort, int hopCount, int broadID,
                  bool Asent, bool forceRedisc, char* data, int length)
{
    packet->type = type;
    memcpy(packet->sourceIP, srcIP, IPLEN);
    memcpy(packet->destIP, dstIP, IPLEN);
    packet->sourcePort = srcPort;
    packet->destPort = dstPort;
    packet->hopCount = hopCount;
    packet->broadID = broadID;
    packet->Asent = Asent;
    packet->forceRedisc = forceRedisc;
    memcpy(packet->data, data, length);
}

void addToWaitList(ODRPacket *packet, RoutingTable *routes,int destNode) {
    WaitingPacket *newPacket = Malloc(sizeof(WaitingPacket));
    memcpy(&(newPacket->packet), packet, sizeof(ODRPacket));
    newPacket->next = routes[destNode].waitListHead;
    routes[destNode].waitListHead = newPacket;
}

bool isRoutePresent(ODRPacket *packet, RoutingTable *routes) {
    int destNode = getVmNodeByIP(packet->destIP);
    RoutingTable *routeEntry = &(routes[destNode]);

    if ((routeEntry->isValid == FALSE) ||   // Invalid Route Entry
        isRouteStale(routeEntry))           // Route expired
    {
#if DEBUG2
        printf("Route not present: %s %s\n", routeEntry->isValid ? "Valid" : "Invalid",
                isRouteStale(routeEntry) ? "Stale" : "NotStale");
#endif
        routeEntry->isValid = FALSE;
        if (packet->type != RREQ) {
            addToWaitList(packet, routes, destNode);
        }
        return FALSE;
    }
    return TRUE;
}

void floodPacket(ODRPacket *packet, IfaceInfo *ifaceList, int exceptInterface, int totalSockets) {

    int retVal;
    int index;
    uint8_t broadMAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /*target address*/
    struct sockaddr_ll sockAddr;
    EthernetFrame frame;

    bzero(&sockAddr, sizeof(sockAddr));
    bzero(&frame, sizeof(frame));

    /*RAW communication*/
    sockAddr.sll_family   = PF_PACKET;
    sockAddr.sll_protocol = htons(PROTOCOL_NUMBER);

    /*ARP hardware identifier is ethernet*/
    sockAddr.sll_hatype   = ARPHRD_ETHER;

    /*target is another host*/
    sockAddr.sll_pkttype  = PACKET_OTHERHOST;

    /*address length*/
    sockAddr.sll_halen    = ETH_ALEN;
    memcpy(sockAddr.sll_addr, broadMAC, MACLEN);

    memcpy(frame.destMAC, broadMAC, MACLEN);
    memcpy(&(frame.packet), packet, sizeof(ODRPacket));
    frame.protocol = htons(PROTOCOL_NUMBER);

    // Increment Hop count in the packet
    packet->hopCount++;

    for (index = 0; index < totalSockets; index++) {

        if (index != exceptInterface) {

            memcpy(frame.sourceMAC, ifaceList[index].ifaceMAC, MACLEN);
            sockAddr.sll_ifindex  = ifaceList[index].ifaceNum;
#if DEBUG
            printf("Flooding RREQ Packet%s on interface number: %d\n",
                packet->Asent ? " (with ASENT)" : "",
                ifaceList[index].ifaceNum);
#endif 
            sendEthernetPacket(ifaceList[index].ifaceSocket, &frame, (SA*) &sockAddr,
                                sizeof(sockAddr));
        }
    }
}

void handleRREQ(EthernetFrame *frame, RoutingTable *routes, IfaceInfo *ifaceList,
                int inSockIndex, int totalSockets)
{
    uint32_t  destIndex;
    ODRPacket *packet;
    int retval = -1;
    int nwdestNode;
    int nwsrcNode;
    RouteUpdate isSrcRouteUpdated;

    packet = Malloc(sizeof(ODRPacket));
    memcpy(packet, &(frame->packet), sizeof(ODRPacket));

    if (checkIfSrcNode(packet)) {
        // Do nothing when RREQ received from original source, stop flooding.
        return;
    }
    if (checkIfTimeToLeave(packet)) {
        // Throw away RREQ as Hop count is greater than TTL
        printf("Throwing away RREQ as hop count(%d) is equal to TTL\n", packet->hopCount);
        return;
    }

    isSrcRouteUpdated = createUpdateRouteEntry(frame, inSockIndex, routes, ifaceList);

    // Only send RREPs if Already Sent flag "Asent" is FALSE
    if (!packet->Asent) {
        if (checkIfDestNode(packet)) {
            if (isSrcRouteUpdated == NEW_UPDATE) {
                // Create RREPs and send them back only for better/fresher RREQ packets
                ODRPacket RREPPacket;
                nwdestNode = getVmNodeByIP(packet->sourceIP);

                fillODRPacket(&RREPPacket, RREP, packet->destIP, packet->sourceIP,
                        packet->destPort, packet->sourcePort, 1, 0, FALSE,
                        packet->forceRedisc, NULL, 0);
#if DEBUG2
                printf("Sent a RREP Packet\n");
#endif
                sendonIFace(&RREPPacket, ifaceList[inSockIndex].ifaceMAC, routes[nwdestNode].nextHopMAC,
                        ifaceList[inSockIndex].ifaceNum, ifaceList[inSockIndex].ifaceSocket);
            }
            return;
        }

        if (isForceRediscover(packet)) {
            // Invalidate route for destination entry
            int destNode = getVmNodeByIP(packet->destIP);
            routes[destNode].isValid = FALSE;

        } else if (isRoutePresent(packet, routes)) {
            // Create RREPs and send them back
            ODRPacket RREPPacket;
            nwdestNode = getVmNodeByIP(packet->sourceIP);
            nwsrcNode = getVmNodeByIP(packet->destIP);

            fillODRPacket(&RREPPacket, RREP, packet->destIP, packet->sourceIP,
                    packet->destPort, packet->sourcePort,
                    routes[nwsrcNode].hopCount + 1, 0, FALSE,
                    packet->forceRedisc, NULL, 0);

#if DEBUG2
            printf("Sent a RREP Packet\n");
#endif
            sendonIFace(&RREPPacket, ifaceList[inSockIndex].ifaceMAC, routes[nwdestNode].nextHopMAC,
                    ifaceList[inSockIndex].ifaceNum, ifaceList[inSockIndex].ifaceSocket); 

            // Flood RREQs with Asent flag (if needed)
            packet->Asent = TRUE;
        }
    }

    // Route not present or updated, so keep flooding RREQ
    if (isSrcRouteUpdated != NO_UPDATE) {
        packet->hopCount++;
        floodPacket(packet, ifaceList, inSockIndex, totalSockets);
    }
}

void handleRREP(EthernetFrame *frame, RoutingTable *routes, IfaceInfo *ifaceList,
                int inSockIndex, int totalSockets)
{
    uint32_t  outSockIndex;
    ODRPacket *packet;
    int nwdestNode;
    RouteUpdate isSrcRouteUpdated;
    
    packet = Malloc(sizeof(ODRPacket));
    memcpy(packet, &(frame->packet), sizeof(ODRPacket));

    isSrcRouteUpdated = createUpdateRouteEntry(frame, inSockIndex, routes, ifaceList);

    if ((isSrcRouteUpdated != NEW_UPDATE) || checkIfDestNode(packet)) {
        // RREP packet already Sent or Reached final destination
        return;
    }

    if (isRoutePresent(packet, routes)) {
        // Send RREP to source
        nwdestNode = getVmNodeByIP(packet->destIP);
        outSockIndex = routes[nwdestNode].ifaceInd;
        packet->hopCount++;
#if DEBUG2
        printf("Sent a RREP Packet\n");
#endif 
        sendonIFace(packet, ifaceList[outSockIndex].ifaceMAC,
                routes[nwdestNode].nextHopMAC,
                ifaceList[outSockIndex].ifaceNum,
                ifaceList[outSockIndex].ifaceSocket);
    } else {
#if DEBUG
        printf("Route is not present, generating RREQ\n");
#endif 
        ODRPacket RREQPacket;
        fillODRPacket(&RREQPacket, RREQ, hostIP, packet->destIP,
                0, packet->destPort, 1, getNextBroadCastID(), FALSE,
                packet->forceRedisc, NULL, 0);

        floodPacket(&RREQPacket, ifaceList, inSockIndex, totalSockets);
    }
}

void handleDATA(EthernetFrame *frame, RoutingTable *routes, int unixSockFd,
                IfaceInfo *ifaceList, int inSockIndex, int totalSockets)
{
    uint32_t  outSockIndex;
    ODRPacket *packet;
    int nwdestNode;
    
    packet = Malloc(sizeof(ODRPacket));
    memcpy(packet, &(frame->packet), sizeof(ODRPacket));

#if DEBUG2
    printf("DATA Packet received from Source Node: VM%d\n", getVmNodeByIP(packet->sourceIP));
#endif
    createUpdateRouteEntry(frame, inSockIndex, routes, ifaceList);

    if (checkIfDestNode(packet)) {
        // Send directly to destPort on local process
        printf("Sending DATA to %s:%d (local machine)\n", packet->destIP, packet->destPort);
        writeUnixSocket(unixSockFd, packet->sourceIP, packet->sourcePort,
                        packet->destPort, packet->data);
        return;
    }

    if (isRoutePresent(packet, routes)) {
        // Send data to destination
        nwdestNode = getVmNodeByIP(packet->destIP);
        outSockIndex = routes[nwdestNode].ifaceInd;
        packet->hopCount++;
#if DEBUG2
        printf("Sent a DATA Packet\n");
#endif 
        sendonIFace(packet, ifaceList[outSockIndex].ifaceMAC,
                routes[nwdestNode].nextHopMAC,
                ifaceList[outSockIndex].ifaceNum,
                ifaceList[outSockIndex].ifaceSocket);
    } else {
#if DEBUG
        printf("Route is not present, generating RREQ\n");
#endif 
        ODRPacket RREQPacket;
        fillODRPacket(&RREQPacket, RREQ, hostIP, packet->destIP,
                0, packet->destPort, 1, getNextBroadCastID(), FALSE,
                packet->forceRedisc, NULL, 0);

        floodPacket(&RREQPacket, ifaceList, inSockIndex, totalSockets);
    }
}

void processFrame(EthernetFrame *frame, RoutingTable *routes, int unixSockFd,
                    IfaceInfo *ifaceList, int inSockIndex, int totalSockets)
{
    ODRPacket *packet = &(frame->packet);

    switch (packet->type) {

        case RREQ: // RREQ packet
#if DEBUG
            printf("RREQ packet received!\n");
#endif 
            handleRREQ(frame, routes, ifaceList, inSockIndex, totalSockets);
            break;

        case RREP: // RREP packet
#if DEBUG
            printf("RREP packet received!\n");
#endif 
            handleRREP(frame, routes, ifaceList, inSockIndex, totalSockets);
            break;

        case DATA: // Data packet
#if DEBUG
            printf("Data packet received!\n");
#endif 
            handleDATA(frame, routes, unixSockFd, ifaceList, inSockIndex, totalSockets);
            break;

        default: // Error
            err_msg("Malformed packet received!");
    }
}

int startCommunication(ODRPacket *packet, RoutingTable *routes, IfaceInfo *ifaceList, int totalSockets) {
    uint8_t srcMAC[MACLEN], dstMAC[MACLEN];
    int destIndex, outIfaceInd, outIfaceNum, outSocket;

    if (isRoutePresent(packet, routes)) {
#if DEBUG
        printf("Route is present, sending DATA packet\n");
#endif
        destIndex = getVmNodeByIP(packet->destIP);
        outIfaceInd = routes[destIndex].ifaceInd;
        outIfaceNum = ifaceList[outIfaceInd].ifaceNum;
        outSocket = ifaceList[outIfaceInd].ifaceSocket;

        memcpy(dstMAC, routes[destIndex].nextHopMAC, MACLEN);
        memcpy(srcMAC, ifaceList[outIfaceInd].ifaceMAC, MACLEN);

        // Unable force rediscovery on DATA packet
        packet->forceRedisc = FALSE;

        sendonIFace(packet, srcMAC, dstMAC, outIfaceNum, outSocket);
        return 0;

    } else {
        // Create RREQ and Flood it out
#if DEBUG
        printf("Route is not present, generating RREQ\n");
#endif 
        ODRPacket RREQPacket;
        fillODRPacket(&RREQPacket, RREQ, packet->sourceIP, packet->destIP,
                packet->sourcePort, packet->destPort, 1, getNextBroadCastID(), FALSE, 
                packet->forceRedisc, NULL, 0);

        floodPacket(&RREQPacket, ifaceList, -1 /* Flood on all interfaces */, totalSockets);
        return 1;
    }
}

int readAllSockets(int unixSockFd, IfaceInfo *ifaceList, int totalIfaceSock, fd_set fdSet, RoutingTable* routes) {
    int maxfd, index;
    fd_set readFdSet;
    int i;

    printf("\nReading all incoming packets =>\n");
    maxfd = unixSockFd;
    for (i = 0; i < totalIfaceSock; i++) {
        maxfd = max(maxfd, ifaceList[i].ifaceSocket);
    }
    maxfd++;

    while (1) {
        printf("\n");
        readFdSet = fdSet;
        Select(maxfd, &readFdSet, NULL, NULL, NULL);

        // Check if got a packet on an unix domain socket
        if (FD_ISSET(unixSockFd, &readFdSet)) {
            ODRPacket packet;
            if (processUnixPacket(unixSockFd, &packet)) 
                startCommunication(&packet, routes, ifaceList, totalIfaceSock);
        }

        // Check if got a packet on an iface socket
        for (index = 0; index < totalIfaceSock; index++) {
            if (FD_ISSET(ifaceList[index].ifaceSocket, &readFdSet)) {
                EthernetFrame frame;

                recvEthernetPacket(ifaceList[index].ifaceSocket, &frame);

                // Process frame
                processFrame(&frame, routes, unixSockFd, ifaceList, index, totalIfaceSock);
            }
        }
    }
}

int createIfaceSockets(IfaceInfo **ifaceSockList, fd_set *fdSet) {
    struct hwa_info *hwa, *hwahead;
    int totalInterfaces = 0, index = 0;
    struct sockaddr_ll listenFilter;

    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next, totalInterfaces++);
#if DEBUG2
    printf("\nFollowing are %d HW Interfaces =>\n", totalInterfaces);
#endif
    *ifaceSockList = Malloc(totalInterfaces * sizeof(IfaceInfo));

    bzero(&listenFilter, sizeof(listenFilter));

    /*RAW communication*/
    listenFilter.sll_family   = PF_PACKET;    
    listenFilter.sll_protocol = htons(PROTOCOL_NUMBER);  

    /*ARP hardware identifier is ethernet*/
    listenFilter.sll_hatype   = ARPHRD_ETHER;

    /*target is another host*/
    listenFilter.sll_pkttype  = PACKET_OTHERHOST;

    /*address length*/
    listenFilter.sll_halen    = ETH_ALEN;

    for (hwa = hwahead; hwa != NULL; hwa = hwa->hwa_next) {
        printInterface(hwa);

        if ((strcmp(hwa->if_name, "lo") != 0) && (strcmp(hwa->if_name, "eth0") != 0)) {
            // if the interface number is greater than 2 then make sockets on each interfaces
            if ((((*ifaceSockList)[index]).ifaceSocket = socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL_NUMBER))) < 0) {
                err_quit("Error in creating PF_PACKET socket for interface: %d", index + 3);
            }
            listenFilter.sll_ifindex = hwa->if_index;
            memcpy(listenFilter.sll_addr, hwa->if_haddr, MACLEN);

            ((*ifaceSockList)[index]).ifaceNum = hwa->if_index;
            memcpy(((*ifaceSockList)[index]).ifaceMAC, hwa->if_haddr, MACLEN);
            FD_SET((*ifaceSockList)[index].ifaceSocket, fdSet);
            Bind((*ifaceSockList)[index].ifaceSocket, (SA *) &listenFilter, sizeof(listenFilter));
            index++;
        }
    }
    free_hwa_info(hwahead);

    printf("%d interfaces Bind\n", index);
    return index;
}


int main(int argc, char *argv[]) {
    RoutingTable routes[TOTAL_VMS + 1] = {0};
    IfaceInfo *ifaceSockList;
    int totalIfaceSock, unixSockFd, filePortMapCnt;
    fd_set fdSet;

    if (argc == 1) {
        printf("No given staleness parameter, ");
        staleness = 5;
    } else {
        staleness = atoi(argv[1]);
    }
    printf("Setting staleness = %d sec\n", staleness);

    hostNode = getHostVmNodeNo();
    getIPByVmNode(hostIP, hostNode);
    printf("ODR running on VM%d (%s)\n", hostNode, hostIP);

    Signal(SIGINT, sig_int);
    FD_ZERO(&fdSet);
    
    // Initialize filePath to Port Number Map
    initFilePortMap();

    // Create Unix domain socket
    getFullPath(filePath, ODR_FILE, sizeof(filePath), FALSE);
    unixSockFd = createAndBindUnixSocket(filePath);
    FD_SET(unixSockFd, &fdSet);

    // Create interface sockets
    totalIfaceSock = createIfaceSockets(&ifaceSockList, &fdSet);

    // Read incoming packets on all sockets
    readAllSockets(unixSockFd, ifaceSockList, totalIfaceSock, fdSet, routes);

    free(ifaceSockList);

    unlink(filePath);
    Close(unixSockFd);
}

