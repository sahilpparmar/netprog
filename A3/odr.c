#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include "common.h"
#include "hw_addrs.h"
#include "odr.h"

#define DEBUG 0 // 1 = TRUE
#define SLEEP_SEC 6 // Sleep parameter
char filePath[1024], hostNode, hostIP[100];

static void sig_int(int signo) {
    unlink(filePath);
    exit(0);
}

void printInterface(struct hwa_info *hwa) {
    struct sockaddr	*sa;
    char   *ptr;
    int    i, prflag;

    if (DEBUG != TRUE) 
        return;

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

void printMACAddrs(uint8_t srcMAC[MACLEN], uint8_t destMAC[MACLEN]) {
    char buffer[20];
    printf ("**Destination MAC: %s\n", ethAddrNtoP(destMAC, buffer));
    printf ("**Source MAC: %s\n", ethAddrNtoP(srcMAC, buffer));
}

void printPacket(EthernetFrame *frame) {

    char buffer[20];
    int i;
    ODRPacket *packet = &(frame->packet);

    if (DEBUG != TRUE) 
        return;

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

    return;
}

void sendEthernetPacket(int sockfd, EthernetFrame *frame, SA *sockAddr, int saLen) {
    ODRPacket *packet;
    int retVal;

    printPacket(frame);

    packet = &(frame->packet);
    packet->sourcePort = htonl(packet->sourcePort);
    packet->destPort   = htonl(packet->destPort);
    packet->hopCount   = htonl(packet->hopCount);
    packet->broadID    = htonl(packet->broadID);
    sleep(SLEEP_SEC);

    retVal = sendto(sockfd, (void *)frame, sizeof(EthernetFrame), 0, sockAddr, saLen);
    if (retVal == -1) {
        err_sys("Error in sending Ethernet packet");
    }
}

void receiveODRPacket(int sockfd, EthernetFrame *frame) {
    ODRPacket *packet;
    int len;

    bzero(frame, sizeof(EthernetFrame));
    len = Recvfrom(sockfd, frame, sizeof(EthernetFrame), 0, NULL, NULL);

    if (len < 0) {
        err_sys("Error in receiving Ethernet packet");
    }

    packet = &(frame->packet);
    packet->sourcePort = ntohl(packet->sourcePort);
    packet->destPort   = ntohl(packet->destPort);
    packet->hopCount   = ntohl(packet->hopCount);
    packet->broadID    = ntohl(packet->broadID);
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
    packet->hopCount = (packet->hopCount) + 1;

    sendEthernetPacket(sockfd, &frame, (SA*) &sockAddr, sizeof(sockAddr));
}

// Function that would check and clear up waiting packets in the buffer
int sendWaitingPackets(int destIndex, RoutingTable *routes, IfaceInfo *ifaceList) {

    uint8_t srcMAC[MACLEN], dstMAC[MACLEN];
    uint16_t outIfaceInd, outIfaceNum;
    int outSocket;
    int packetSent = 0;
    WaitingPacket *waitingPackets;
    WaitingPacket *freePacket;

    assert(routes[destIndex].isValid && "Route Entry should be present");
    outIfaceInd = routes[destIndex].ifaceInd;
    outIfaceNum = ifaceList[outIfaceInd].ifaceNum;
    outSocket = ifaceList[outIfaceInd].ifaceSocket;

    waitingPackets = routes[destIndex].waitListHead;
    freePacket = routes[destIndex].waitListHead;
    memcpy(dstMAC, routes[destIndex].nextHopMAC, MACLEN);
    memcpy(srcMAC, ifaceList[outIfaceInd].ifaceMAC, MACLEN);

    while (waitingPackets != NULL) {
        #ifdef DEBUG
        printf("Sent a waiting Packet of Type: %d", waitingPackets->packet.type);
        #endif /* MACRO */

        sendonIFace(&(waitingPackets->packet), srcMAC, dstMAC, outIfaceNum, outSocket);
        waitingPackets = waitingPackets->next;
        packetSent++;

        free(freePacket);
        freePacket = waitingPackets;

    }
    routes[destIndex].waitListHead = NULL;

    return packetSent;
}

void printTable(RoutingTable *routes, int specific) {
    int i = 0;
    char MACTemp[10];

    printf("===================================================================================================================================\n");
    printf("Destination Node |   isValid  |     broadID     |   ifaceInd |           nextHopMAC       | hopCount |  timestamp  | waitListHead |\n");
    printf("===================================================================================================================================\n");

    if (specific != 0) {
	    printf(" VM %10d \t | %10d | %10d\t| %10d | %15s\t  |%10d| %15s  | %12p |\n",
			    specific,   routes[specific].isValid, routes[specific].broadID, routes[specific].ifaceInd,
			    ethAddrNtoP(routes[specific].nextHopMAC, MACTemp), routes[specific].hopCount, asctime( localtime((const time_t *)&routes[specific].timeStamp)), routes[specific].waitListHead);
    }
    else {

	    for(i=1; i< (TOTAL_VMS + 1); i++) {
		    if(routes[i].isValid)
			    printf(" VM %10d \t | %10d | %10d\t| %10d | %15s\t  |%10d| %15s  | %12p |\n",
					    specific,   routes[specific].isValid, routes[specific].broadID, routes[specific].ifaceInd,
					    ethAddrNtoP(routes[specific].nextHopMAC, MACTemp), routes[specific].hopCount, asctime( localtime((const time_t *)&routes[specific].timeStamp)), routes[specific].waitListHead);
	    }
    }
    printf("===================================================================================================================================\n");

}

bool isRouteStale(RoutingTable *routeEntry) {
    return (((uint32_t)time(NULL) - routeEntry->timeStamp) > STALENESS) ? TRUE : FALSE;
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

void changePacketType(ODRPacket *packet, packetType type) {
    packet->type = type;
}

void incHopCount(ODRPacket *packet) {
    packet->hopCount = packet->hopCount + 1;
    return;
}

void setAsentFlag(ODRPacket *packet) {
    packet->Asent = TRUE;
    return;
}

bool createUpdateRouteEntry(EthernetFrame *frame, int ifaceInd, RoutingTable *routes, IfaceInfo *ifaceList) {
    int srcNode;

    ODRPacket *packet = &(frame->packet);
    srcNode = getVmNodeByIP(packet->sourceIP);

    RoutingTable *routeEntry = &routes[srcNode];
    if ((routeEntry->isValid == FALSE) ||
        ((routeEntry->broadID == packet->broadID) && (routeEntry->hopCount > packet->hopCount)) ||
        (routeEntry->broadID < packet->broadID) ||
        (packet->broadID == 0) ||
        (isRouteStale(routeEntry)))
    {
        routeEntry->isValid = TRUE;
        routeEntry->broadID = packet->broadID;
        routeEntry->ifaceInd = ifaceInd;
        memcpy(routeEntry->nextHopMAC, frame->sourceMAC, MACLEN);
        routeEntry->hopCount = packet->hopCount;
        routeEntry->timeStamp = (uint32_t) time(NULL);

        printTable(routes, srcNode);
        printf("Cleared Waiting Queue for src Node: VM%d, Packets Sent: %d\n",
                srcNode, sendWaitingPackets(srcNode, routes, ifaceList));

        return TRUE;
    }
    return FALSE;
}

int fillODRPacket(ODRPacket *packet, packetType type, char *srcIP, char *dstIP,
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

    return 1;
}

void addToWaitList(ODRPacket *packet, RoutingTable *routes,int destNode) {

    WaitingPacket *newPacket = Malloc(sizeof(WaitingPacket));

    memcpy(&(newPacket->packet), packet, sizeof(ODRPacket));
    newPacket->next = routes[destNode].waitListHead;

    routes[destNode].waitListHead = newPacket;

    return;
}

bool isRoutePresent(ODRPacket *packet, RoutingTable *routes) {
    int destNode;

    destNode = getVmNodeByIP(packet->destIP);  

    RoutingTable *routeEntry = &(routes[destNode]);
    if ((routeEntry->isValid == FALSE) ||   // Invalid Route Entry
        isRouteStale(routeEntry))           // Route expired
    {
        printf("Route Not present(%d) or Stale(%d)\n", routeEntry->isValid, isRouteStale(routeEntry));
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
    incHopCount(packet);

    for (index = 0; index < totalSockets; index++) {

        if (index != exceptInterface) {

            memcpy(frame.sourceMAC, ifaceList[index].ifaceMAC, MACLEN);
            sockAddr.sll_ifindex  = ifaceList[index].ifaceNum;
            printf("Flooding Packet on interface number: %d\n", ifaceList[index].ifaceNum);

            sendEthernetPacket(ifaceList[index].ifaceSocket, &frame, (SA*) &sockAddr,
                                sizeof(sockAddr));
        }
    }
    return;
}

void handleRREQ(EthernetFrame *frame, RoutingTable *routes, IfaceInfo *ifaceList,
                int inSockIndex, int totalSockets)
{
    uint32_t  destIndex;
    ODRPacket *packet;
    int retval = -1;
    int nwdestNode;
    int nwsrcNode;
    bool isSrcRouteUpdated;
    char buffer[20];

    packet = Malloc(sizeof(ODRPacket));
    memcpy(packet, &(frame->packet), sizeof(ODRPacket));
    
    printf("RREQ Packet received with destMAC: %s\n", ethAddrNtoP(frame->destMAC, buffer));
    
    if (checkIfSrcNode(packet)) {
        // Do nothing, RREQ received from original source, stop flooding.
        return;
    }

    isSrcRouteUpdated = createUpdateRouteEntry(frame, inSockIndex, routes, ifaceList);

    if (checkIfDestNode(packet)) {
        if (!packet->Asent) {
            // Create RREPs and send them back
            ODRPacket RREPPacket;
            nwdestNode = getVmNodeByIP(packet->sourceIP);

            fillODRPacket(&RREPPacket, RREP, packet->destIP, packet->sourceIP,
                    packet->destPort, packet->sourcePort, 0, 0, FALSE,
                    packet->forceRedisc/*TODO Check */, NULL, 0);

            sendonIFace(&RREPPacket, ifaceList[inSockIndex].ifaceMAC, routes[nwdestNode].nextHopMAC,
                    ifaceList[inSockIndex].ifaceNum, ifaceList[inSockIndex].ifaceSocket); 
        }
        return;
    }

    if (isRoutePresent(packet, routes)) { // Send RREP to source
        // Create RREPs and send them back
        ODRPacket RREPPacket;
        nwdestNode = getVmNodeByIP(packet->sourceIP); 
        nwsrcNode = getVmNodeByIP(packet->destIP);

        fillODRPacket(&RREPPacket, RREP, packet->destIP, packet->sourceIP,
                packet->destPort, packet->sourcePort, 
                routes[nwsrcNode].hopCount + 1/*HopCount*/, 0, FALSE,
                packet->forceRedisc/*TODO Check */, NULL, 0);

        sendonIFace(&RREPPacket, ifaceList[inSockIndex].ifaceMAC, routes[nwdestNode].nextHopMAC,
                ifaceList[inSockIndex].ifaceNum, ifaceList[inSockIndex].ifaceSocket); 

        // Flood RREQs with Asent flag (if needed)
        setAsentFlag(packet);
    }

    // Route not present or updated, so keep flooding RREQ
    if (isSrcRouteUpdated) {
        incHopCount(packet);
        floodPacket(packet, ifaceList, inSockIndex, totalSockets);
    }
}

void handleRREP(EthernetFrame *frame, RoutingTable *routes, IfaceInfo *ifaceList,
                int inSockIndex, int totalSockets)
{
    uint32_t  outSockIndex;
    ODRPacket *packet;
    int nwdestNode;
    
    packet = Malloc(sizeof(ODRPacket));

    memcpy(packet, &(frame->packet), sizeof(ODRPacket));
    createUpdateRouteEntry(frame, inSockIndex, routes, ifaceList);

    if (checkIfDestNode(packet)) {
        // Reached final destination. Data packet already Sent
        return;
    }

    if (isRoutePresent(packet, routes)) { // Send RREP to source
        nwdestNode = getVmNodeByIP(packet->destIP);
        outSockIndex = routes[nwdestNode].ifaceInd;
        incHopCount(packet);
        sendonIFace(packet, ifaceList[outSockIndex].ifaceMAC,
                routes[nwdestNode].nextHopMAC,
                ifaceList[outSockIndex].ifaceNum,
                ifaceList[outSockIndex].ifaceSocket);
    } else {
        printf("Route is not present, generating RREQ\n");
        ODRPacket RREQPacket;
        fillODRPacket(&RREQPacket, RREQ, hostIP, packet->destIP,
                0, packet->destPort, 0, getNextBroadCastID(), FALSE,
                packet->forceRedisc, NULL, 0);

        floodPacket(&RREQPacket, ifaceList, inSockIndex, totalSockets);
    }
    return;
}

void handleDATA(EthernetFrame *frame, RoutingTable *routes, int unixSockFd,
                IfaceInfo *ifaceList, int inSockIndex, int totalSockets)
{
    uint32_t  outSockIndex;
    ODRPacket *packet;
    int nwdestNode;
    
    packet = Malloc(sizeof(ODRPacket));
    memcpy(packet, &(frame->packet), sizeof(ODRPacket));

    createUpdateRouteEntry(frame, inSockIndex, routes, ifaceList);

    if (checkIfDestNode(packet)) {
        // Send directly to destPort on local process
        printf("Sending packet to %s:%d\n", packet->destIP, packet->destPort);
        writeUnixSocket(unixSockFd, packet->sourceIP, packet->sourcePort,
                        packet->destPort, packet->data);
        return;
    }

    if (isRoutePresent(packet, routes)) { // Send data to destination
        nwdestNode = getVmNodeByIP(packet->destIP);
        outSockIndex = routes[nwdestNode].ifaceInd;
        incHopCount(packet);
        sendonIFace(packet, ifaceList[outSockIndex].ifaceMAC,
                routes[nwdestNode].nextHopMAC,
                ifaceList[outSockIndex].ifaceNum,
                ifaceList[outSockIndex].ifaceSocket);
    } else {
        printf("Route is not present, generating RREQ\n");
        ODRPacket RREQPacket;
        fillODRPacket(&RREQPacket, RREQ, hostIP, packet->destIP,
                0, packet->destPort, 0, getNextBroadCastID(), FALSE,
                packet->forceRedisc, NULL, 0);

        floodPacket(&RREQPacket, ifaceList, inSockIndex, totalSockets);
    }

    return;
}

void processFrame(EthernetFrame *frame, RoutingTable *routes, int unixSockFd,
                    IfaceInfo *ifaceList, int inSockIndex, int totalSockets)
{
    ODRPacket *packet;
    packet = &(frame->packet);
    printPacket(frame); 

    switch (packet->type) {

        case RREQ: // RREQ packet
            printf("RREQ packet received!\n");
	    sleep(SLEEP_SEC);
            handleRREQ(frame, routes, ifaceList, inSockIndex, totalSockets);
            break;

        case RREP: // RREP packet
            printf("RREP packet received!\n");
	    sleep(SLEEP_SEC);
            handleRREP(frame, routes, ifaceList, inSockIndex, totalSockets);
            break;

        case DATA: // Data packet
            printf("Data packet received!\n");
	    sleep(SLEEP_SEC);
            handleDATA(frame, routes, unixSockFd, ifaceList, inSockIndex, totalSockets);
            break;

        default: // Error
            err_msg("Malformed packet received!");
    } // Switch

}

int startCommunication(ODRPacket *packet, RoutingTable *routes, IfaceInfo *ifaceList, int totalSockets) {
    uint8_t srcMAC[MACLEN], dstMAC[MACLEN];
    int destIndex, outIfaceInd, outIfaceNum, outSocket;

    if (isRoutePresent(packet, routes)) {
        printf("Route is present\n");
        destIndex = getVmNodeByIP(packet->destIP);
        outIfaceInd = routes[destIndex].ifaceInd;
        outIfaceNum = ifaceList[outIfaceInd].ifaceNum;
        outSocket = ifaceList[outIfaceInd].ifaceSocket;

        memcpy(dstMAC, routes[destIndex].nextHopMAC, MACLEN);
        memcpy(srcMAC, ifaceList[outIfaceInd].ifaceMAC, MACLEN);

        sendonIFace(packet, srcMAC, dstMAC, outIfaceNum, outSocket);
        return 0;

    } else {
        // Create RREQ and Flood it out
        printf("Route is not present, generating RREQ\n");
        ODRPacket RREQPacket;
        fillODRPacket(&RREQPacket, RREQ, packet->sourceIP, packet->destIP,
                packet->sourcePort, packet->destPort, 0, getNextBroadCastID(), FALSE, 
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

                receiveODRPacket(ifaceList[index].ifaceSocket, &frame);

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
    printf("\nFollowing are %d HW Interfaces =>\n", totalInterfaces);

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


int main() {
    RoutingTable routes[TOTAL_VMS + 1] = {0};
    IfaceInfo *ifaceSockList;
    int totalIfaceSock, unixSockFd, filePortMapCnt;
    fd_set fdSet;

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

